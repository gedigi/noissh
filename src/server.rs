//! Server runtime: a socket-free [`ServerCore`] (drivable by the resilience
//! harness) plus a [`Server`] UDP driver used by the `noisshd` binary.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use auth::AuthorizedKeys;
use nix::errno::Errno;
use noise_core::Keypair;
use proto::{authorize_client, ControlMsg, Handshaker, ServerShell};
use pty::{LocalLogin, LoginSession, PtyError, PtyHandle, SpawnRequest};
use transport::{Packet, Session, SessionId};
use wire::Frame;

use crate::RuntimeError;

struct ServerSession {
    session: Session,
    shell: Option<ServerShell>,
    pty: Option<PtyHandle>,
    rows: u16,
    cols: u16,
    exit_sent: bool,
}

/// Per-session, socket-free server logic. Consumes raw packets and returns raw
/// packets to send, so it can be driven directly by an in-memory shim.
pub struct ServerCore {
    keypair: Keypair,
    authorized: AuthorizedKeys,
    login: Box<dyn LoginSession + Send>,
    command: Option<Vec<String>>,
    user: Option<String>,
    pending: HashMap<SessionId, Handshaker>,
    sessions: HashMap<SessionId, ServerSession>,
    ever_active: bool,
}

impl ServerCore {
    /// Build a server core. `command` overrides the login shell (used by tests);
    /// `login` selects the login backend (`LocalLogin` for the portable path).
    pub fn new(
        keypair: Keypair,
        authorized: AuthorizedKeys,
        login: Box<dyn LoginSession + Send>,
        command: Option<Vec<String>>,
    ) -> Self {
        ServerCore {
            keypair,
            authorized,
            login,
            command,
            user: None,
            pending: HashMap::new(),
            sessions: HashMap::new(),
            ever_active: false,
        }
    }

    /// Set the target user for spawned sessions (privsep backend).
    pub fn with_user(mut self, user: Option<String>) -> Self {
        self.user = user;
        self
    }

    /// One-shot lifecycle: true once a session existed and all sessions have
    /// since reported their shell's exit.
    pub fn all_done(&self) -> bool {
        self.ever_active && self.sessions.values().all(|s| s.exit_sent)
    }

    /// Use the portable local-login backend running the current user's shell.
    pub fn local(keypair: Keypair, authorized: AuthorizedKeys) -> Self {
        ServerCore::new(keypair, authorized, Box::new(LocalLogin), None)
    }

    /// Force a fixed command instead of the login shell (deterministic tests).
    pub fn with_command(mut self, command: Vec<String>) -> Self {
        self.command = Some(command);
        self
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// The server's static public key (for clients to pin).
    pub fn public_key(&self) -> &[u8] {
        &self.keypair.public
    }

    /// Handle one inbound datagram from `src`; returns datagrams to send.
    pub fn handle_packet(&mut self, src: SocketAddr, buf: &[u8]) -> Vec<(SocketAddr, Vec<u8>)> {
        match self.try_handle_packet(src, buf) {
            Ok(out) => out,
            Err(_) => Vec::new(), // malformed/unauthorized: drop silently
        }
    }

    fn try_handle_packet(
        &mut self,
        src: SocketAddr,
        buf: &[u8],
    ) -> Result<Vec<(SocketAddr, Vec<u8>)>, RuntimeError> {
        match transport::parse_packet(buf)? {
            Packet::Handshake { session_id, body } => self.handle_handshake(src, session_id, body),
            Packet::Transport { session_id, .. } => self.handle_transport(src, session_id, buf),
        }
    }

    fn handle_handshake(
        &mut self,
        src: SocketAddr,
        sid: SessionId,
        body: &[u8],
    ) -> Result<Vec<(SocketAddr, Vec<u8>)>, RuntimeError> {
        if self.sessions.contains_key(&sid) {
            return Ok(Vec::new()); // already established
        }
        let hs = match self.pending.remove(&sid) {
            Some(hs) => hs,
            None => Handshaker::server(&self.keypair.private, sid)?,
        };
        let mut hs = hs;
        let outcome = hs.read(body)?;
        let mut out = Vec::new();
        if let Some(reply) = outcome.reply {
            out.push((src, reply));
        }
        if outcome.finished {
            // Authorize the authenticated client key BEFORE any session/pty work.
            let client_static = hs.remote_static().ok_or(RuntimeError::Handshake)?;
            if !authorize_client(&self.authorized, &client_static) {
                return Ok(out); // reject: no session created
            }
            let session = hs.into_session(Some(src))?;
            self.sessions.insert(
                sid,
                ServerSession { session, shell: None, pty: None, rows: 24, cols: 80, exit_sent: false },
            );
            self.ever_active = true;
        } else {
            self.pending.insert(sid, hs);
        }
        Ok(out)
    }

    fn handle_transport(
        &mut self,
        src: SocketAddr,
        sid: SessionId,
        buf: &[u8],
    ) -> Result<Vec<(SocketAddr, Vec<u8>)>, RuntimeError> {
        // Decrypt + decode while borrowing the session, then release the borrow
        // so per-frame handlers (e.g. OpenShell) can mutate the session map.
        let frames = {
            let Some(sess) = self.sessions.get_mut(&sid) else {
                return Ok(Vec::new());
            };
            sess.session.open(src, buf)? // roaming: peer_addr now = src
        };
        let mut reply_frames: Vec<Frame> = Vec::new();
        for frame in frames {
            match frame {
                Frame::Input { offset, data } => {
                    if let Some(sess) = self.sessions.get_mut(&sid)
                        && let Some(shell) = &mut sess.shell
                    {
                        let (fresh, ack) = shell.ingest_input(offset, &data);
                        if let Some(pty) = &sess.pty {
                            let _ = pty.write(&fresh);
                        }
                        reply_frames.push(ack);
                    }
                }
                Frame::Ack { seq } => {
                    if let Some(sess) = self.sessions.get_mut(&sid)
                        && let Some(shell) = &mut sess.shell
                    {
                        shell.on_state_ack(seq);
                    }
                }
                Frame::Control { data } => {
                    if let Ok(msg) = ControlMsg::decode(&data) {
                        self.handle_control(sid, msg);
                    }
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        if !reply_frames.is_empty()
            && let Some(sess) = self.sessions.get_mut(&sid)
            && let Some(addr) = sess.session.peer_addr()
        {
            out.push((addr, sess.session.seal(&reply_frames)?));
        }
        Ok(out)
    }

    fn handle_control(&mut self, sid: SessionId, msg: ControlMsg) {
        match msg {
            ControlMsg::OpenShell { cols, rows, term } => {
                let Some(sess) = self.sessions.get_mut(&sid) else { return };
                if sess.pty.is_some() {
                    return; // already open
                }
                let req = SpawnRequest {
                    user: self.user.clone(),
                    command: self.command.clone(),
                    env: Vec::new(),
                    term,
                    rows,
                    cols,
                };
                if let Ok(handle) = self.login.spawn(&req) {
                    let _ = handle.set_nonblocking(true);
                    sess.rows = rows;
                    sess.cols = cols;
                    sess.shell = Some(ServerShell::new(rows as usize, cols as usize));
                    sess.pty = Some(handle);
                }
            }
            ControlMsg::Resize { cols, rows } => {
                let Some(sess) = self.sessions.get_mut(&sid) else { return };
                sess.rows = rows;
                sess.cols = cols;
                if let Some(pty) = &sess.pty {
                    let _ = pty.set_winsize(rows, cols);
                }
                if let Some(shell) = &mut sess.shell {
                    shell.resize(rows as usize, cols as usize);
                }
            }
            _ => {}
        }
    }

    /// Pump PTYs into the emulators and emit state diffs / exit notices.
    pub fn tick(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut out = Vec::new();
        let mut finished: Vec<SessionId> = Vec::new();
        let sids: Vec<SessionId> = self.sessions.keys().copied().collect();
        for sid in sids {
            let Some(sess) = self.sessions.get_mut(&sid) else { continue };
            // Drain available PTY output.
            if let Some(pty) = &sess.pty {
                let mut buf = [0u8; 8192];
                loop {
                    match pty.read(&mut buf) {
                        Ok(0) => break, // EOF (child closed the pty)
                        Ok(n) => {
                            if let Some(shell) = &mut sess.shell {
                                shell.feed_output(&buf[..n]);
                            }
                        }
                        Err(PtyError::Sys(Errno::EAGAIN)) => break,
                        Err(_) => break,
                    }
                }
            }
            // Emit a state diff if the client is behind.
            let addr = sess.session.peer_addr();
            if let (Some(shell), Some(addr)) = (sess.shell.as_mut(), addr)
                && let Some(diff) = shell.poll_diff()
                && let Ok(pkt) = sess.session.seal(&[diff])
            {
                out.push((addr, pkt));
            }
            // Has the child exited? Notify once, then retire the session.
            if let Some(pty) = &mut sess.pty
                && let Ok(Some(status)) = pty.try_wait()
                && !sess.exit_sent
            {
                sess.exit_sent = true;
                let ctrl = ControlMsg::Exit { status }.encode();
                if let Some(addr) = sess.session.peer_addr()
                    && let Ok(pkt) = sess.session.seal(&[Frame::Control { data: ctrl }])
                {
                    out.push((addr, pkt));
                }
                finished.push(sid);
            }
        }
        // Give the exit notice a couple of ticks to flush before retiring; here
        // we keep the session until the next tick by deferring removal one round.
        for sid in finished {
            if let Some(sess) = self.sessions.get_mut(&sid) {
                sess.pty = None;
            }
        }
        out
    }
}

/// UDP driver around [`ServerCore`] for the `noisshd` binary.
pub struct Server {
    core: ServerCore,
    socket: UdpSocket,
}

impl Server {
    pub fn bind(addr: SocketAddr, core: ServerCore) -> Result<Self, RuntimeError> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(10)))?;
        Ok(Server { core, socket })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, RuntimeError> {
        Ok(self.socket.local_addr()?)
    }

    pub fn core(&self) -> &ServerCore {
        &self.core
    }

    /// One service iteration: drain ready packets, then tick. Returns false on
    /// fatal socket error (the loop should stop).
    pub fn poll_once(&mut self) -> bool {
        let mut buf = [0u8; 65536];
        match self.socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                for (addr, pkt) in self.core.handle_packet(src, &buf[..n]) {
                    let _ = self.socket.send_to(&pkt, addr);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return false,
        }
        for (addr, pkt) in self.core.tick() {
            let _ = self.socket.send_to(&pkt, addr);
        }
        true
    }

    /// Serve forever.
    pub fn run(&mut self) {
        while self.poll_once() {}
    }
}
