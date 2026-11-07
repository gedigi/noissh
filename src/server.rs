//! Server runtime: a socket-free [`ServerCore`] (drivable by in-memory tests)
//! plus a [`Server`] UDP driver used by the `noisshd` binary.
//!
//! Each client session is one QUIC connection (`quinn-proto`, Noise handshake
//! from `noise-quic`). A session's shell outlives its connection for a grace
//! period, so a client that reconnects (after sleep or a network change QUIC
//! migration couldn't cover, or a restart) gets the same running shell back.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth::AuthorizedKeys;
use bytes::BytesMut;
use noise_core::Keypair;
use proto::{ControlMsg, ServerShell, authorize_client};
use pty::{LocalLogin, LoginSession, PtyError, PtyHandle, SpawnRequest};
use quinn_proto::{
    Connection, ConnectionError, ConnectionHandle, DatagramEvent, Endpoint, Event, VarInt,
};
use wire::{Frame, StreamKind};

use crate::RuntimeError;
use crate::quic::{self, Streams};
pub use crate::quic::{SessionId, StreamEvent};

struct ServerSession {
    /// The session's QUIC connection; `None` once it has fully gone away.
    conn: Option<(ConnectionHandle, Connection)>,
    streams: Streams,
    /// The connection completed its handshake (the client is authenticated).
    established: bool,
    /// The connection has been lost or closed.
    lost: bool,
    /// The peer closed the connection deliberately (application close).
    closed_by_peer: bool,
    /// The authenticated client static key, used to reattach a returning client.
    client_key: Option<[u8; 32]>,
    shell: Option<ServerShell>,
    pty: Option<PtyHandle>,
    rows: u16,
    cols: u16,
    /// Set once the shell has exited (or the client said goodbye).
    exit_status: Option<i32>,
    exit_sent_at: Option<Instant>,
    /// Last time a datagram arrived on this session's connection.
    last_heard: Instant,
    /// When the connection was lost while a shell kept running.
    detached_at: Option<Instant>,
    /// Screen-state pacing: the last diff sent and when.
    diff_sent_seq: u64,
    diff_sent_at: Instant,
}

impl ServerSession {
    fn conn(&mut self) -> Option<&mut Connection> {
        self.conn.as_mut().map(|(_, c)| c)
    }

    fn shell_running(&self) -> bool {
        self.exit_status.is_none() && self.pty.is_some()
    }
}

/// How long a shell outlives a lost connection, waiting for its client to
/// reconnect.
pub const DETACH_GRACE: Duration = Duration::from_secs(15 * 60);

/// A new connection asking for a shell takes over a running shell of the same
/// client key once that shell's own connection has been silent this long
/// (its client is gone: restarted, or moved without telling us). Twice the
/// client's keep-alive interval plus margin.
pub const REATTACH_SILENCE: Duration = Duration::from_secs(8);

/// How long to wait, after sending a shell's exit status, for the client to
/// close the connection before closing it ourselves.
const EXIT_LINGER: Duration = Duration::from_secs(2);

/// Minimum interval between screen updates (coalesces bursts of output).
const DIFF_INTERVAL: Duration = Duration::from_millis(8);

/// Cap on sessions (connections in any state), bounding memory and processes
/// against a flood of handshakes.
const MAX_SESSIONS: usize = 512;

/// Control-stream backlog above which a large screen diff is held back (a
/// later, up-to-date diff replaces it).
const DIFF_BACKLOG: usize = 256 * 1024;

/// The per-user directory under which forwarded agent sockets live. Kept private
/// to the owning user (mode 0700) so no other local user can reach the sockets.
fn agent_socket_dir() -> std::path::PathBuf {
    let uid = nix::unistd::Uid::current().as_raw();
    std::env::temp_dir().join(format!("noissh-{uid}"))
}

/// Filesystem path for a session's forwarded SSH agent socket. Unique per
/// process and session so concurrent sessions never collide. The containing
/// directory (created and locked down by the driver at bind time) is what keeps
/// the socket private; see [`Server::ensure_agent_dir`].
fn agent_socket_path(sid: SessionId) -> String {
    agent_socket_dir()
        .join(format!("agent-{}-{sid:016x}.sock", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

/// Socket-free server logic: consumes datagrams, returns datagrams to send.
pub struct ServerCore {
    endpoint: Endpoint,
    crypto: Arc<noise_quic::ServerConfig>,
    public: Vec<u8>,
    login: Box<dyn LoginSession + Send>,
    command: Option<Vec<String>>,
    user: Option<String>,
    conns: HashMap<ConnectionHandle, SessionId>,
    sessions: HashMap<SessionId, ServerSession>,
    next_sid: SessionId,
    ever_active: bool,
    detach_grace: Duration,
    reattach_silence: Duration,
    /// Stream lifecycle events surfaced to the driver, tagged by session.
    stream_events: Vec<(SessionId, StreamEvent)>,
    /// Remote-forward (`-R`) listen requests surfaced to the driver:
    /// (session, bind_port, target).
    remote_forward_requests: Vec<(SessionId, u16, String)>,
    /// Agent-forwarding socket requests surfaced to the driver: (session, path).
    /// The driver binds a Unix listener at `path`; the spawned shell already has
    /// `SSH_AUTH_SOCK=path` in its environment.
    agent_socket_requests: Vec<(SessionId, String)>,
    /// Datagrams produced outside `handle_packet`/`tick` results.
    out: Vec<(SocketAddr, Vec<u8>)>,
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
        Self::build(keypair, authorized, login, command, quic::IDLE_TIMEOUT)
    }

    fn build(
        keypair: Keypair,
        authorized: AuthorizedKeys,
        login: Box<dyn LoginSession + Send>,
        command: Option<Vec<String>>,
        idle: Duration,
    ) -> Self {
        let private = quic::key32(&keypair.private).unwrap_or([0; 32]);
        let check: noise_quic::PeerCheck =
            Arc::new(move |key: &[u8; 32]| authorize_client(&authorized, key));
        let crypto = Arc::new(noise_quic::ServerConfig::new(private, check));
        let cfg = Self::server_config(crypto.clone(), idle);
        ServerCore {
            endpoint: Endpoint::new(quic::endpoint_config(), Some(cfg), true, None),
            crypto,
            public: keypair.public,
            login,
            command,
            user: None,
            conns: HashMap::new(),
            sessions: HashMap::new(),
            next_sid: 1,
            ever_active: false,
            detach_grace: DETACH_GRACE,
            reattach_silence: REATTACH_SILENCE,
            stream_events: Vec::new(),
            remote_forward_requests: Vec::new(),
            agent_socket_requests: Vec::new(),
            out: Vec::new(),
        }
    }

    fn server_config(
        crypto: Arc<noise_quic::ServerConfig>,
        idle: Duration,
    ) -> Arc<quinn_proto::ServerConfig> {
        let mut cfg =
            quinn_proto::ServerConfig::new(crypto, Arc::new(noise_quic::TokenKey::random()));
        cfg.transport_config(quic::transport_config(idle, None));
        cfg.max_incoming(MAX_SESSIONS);
        Arc::new(cfg)
    }

    /// Override the connection idle timeout, the detached-shell grace and the
    /// reattach silence (tests).
    pub fn with_timeouts(mut self, idle: Duration, grace: Duration, silence: Duration) -> Self {
        let cfg = Self::server_config(self.crypto.clone(), idle);
        self.endpoint.set_server_config(Some(cfg));
        self.detach_grace = grace;
        self.reattach_silence = silence;
        self
    }

    /// Set the target user for spawned sessions (privsep backend).
    pub fn with_user(mut self, user: Option<String>) -> Self {
        self.user = user;
        self
    }

    /// Whether a privsep target user is configured. When set, the shell drops to
    /// that user at exec (in the child), but the driver process does NOT — so it
    /// cannot safely perform file-transfer / agent I/O confined to that user.
    /// Those features are refused in this mode to avoid acting with the driver's
    /// (possibly root) privileges on the client's behalf. The supported
    /// multi-user model (SSH bootstrap, or a daemon already running as the target
    /// user) has process identity == session identity and is unaffected.
    pub fn privsep_active(&self) -> bool {
        self.user.is_some()
    }

    /// One-shot lifecycle: true once a session existed and every session has
    /// since ended.
    pub fn all_done(&self) -> bool {
        self.ever_active && self.sessions.values().all(|s| !s.established)
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

    /// Established sessions (connected, or detached with a running shell).
    pub fn session_count(&self) -> usize {
        self.sessions.values().filter(|s| s.established).count()
    }

    /// The server's static public key (for clients to pin).
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// Handle one inbound datagram from `src`; returns datagrams to send (for
    /// a connection still in its handshake; an established session's events
    /// and replies are processed by [`ServerCore::tick`]).
    pub fn handle_packet(&mut self, src: SocketAddr, buf: &[u8]) -> Vec<(SocketAddr, Vec<u8>)> {
        let now = Instant::now();
        let mut resp = Vec::new();
        let sid = match self
            .endpoint
            .handle(now, src, None, None, BytesMut::from(buf), &mut resp)
        {
            Some(DatagramEvent::NewConnection(incoming)) => {
                if self.sessions.len() >= MAX_SESSIONS {
                    let t = self.endpoint.refuse(incoming, &mut resp);
                    self.out.push((t.destination, resp[..t.size].to_vec()));
                    None
                } else {
                    let mut buf = Vec::new();
                    match self.endpoint.accept(incoming, now, &mut buf, None) {
                        Ok((ch, conn)) => Some(self.add_session(ch, conn, now)),
                        Err(e) => {
                            if let Some(t) = e.response {
                                self.out.push((t.destination, buf[..t.size].to_vec()));
                            }
                            None
                        }
                    }
                }
            }
            Some(DatagramEvent::ConnectionEvent(ch, ev)) => {
                let sid = self.conns.get(&ch).copied();
                match sid.and_then(|sid| self.sessions.get_mut(&sid)) {
                    Some(s) => {
                        if let Some(conn) = s.conn() {
                            conn.handle_event(ev);
                        }
                        s.last_heard = now;
                        // Established sessions are serviced once per batch of
                        // datagrams, in `tick`; handshakes answer at once.
                        if s.established { None } else { sid }
                    }
                    None => None,
                }
            }
            Some(DatagramEvent::Response(t)) => {
                self.out.push((t.destination, resp[..t.size].to_vec()));
                None
            }
            None => None,
        };
        if let Some(sid) = sid {
            self.service(sid, now);
        }
        std::mem::take(&mut self.out)
    }

    fn add_session(&mut self, ch: ConnectionHandle, conn: Connection, now: Instant) -> SessionId {
        let sid = self.next_sid;
        self.next_sid += 1;
        self.conns.insert(ch, sid);
        self.sessions.insert(
            sid,
            ServerSession {
                conn: Some((ch, conn)),
                streams: Streams::new(true),
                established: false,
                lost: false,
                closed_by_peer: false,
                client_key: None,
                shell: None,
                pty: None,
                rows: 24,
                cols: 80,
                exit_status: None,
                exit_sent_at: None,
                last_heard: now,
                detached_at: None,
                diff_sent_seq: 0,
                diff_sent_at: now,
            },
        );
        sid
    }

    /// Process a session's connection events and received frames, then queue
    /// its outgoing datagrams.
    fn service(&mut self, sid: SessionId, now: Instant) {
        let mut frames = Vec::new();
        {
            let Some(s) = self.sessions.get_mut(&sid) else {
                return;
            };
            let Some((ch, conn)) = s.conn.as_mut() else {
                return;
            };
            while let Some(ev) = conn.poll_endpoint_events() {
                if let Some(cev) = self.endpoint.handle_event(*ch, ev) {
                    conn.handle_event(cev);
                }
            }
            while let Some(ev) = conn.poll() {
                match ev {
                    Event::Connected => {
                        s.established = true;
                        s.client_key = quic::peer_key(conn);
                        self.ever_active = true;
                        let v = ControlMsg::ServerVersion(env!("CARGO_PKG_VERSION").to_string());
                        s.streams
                            .send_frame(conn, &Frame::Control { data: v.encode() });
                    }
                    Event::ConnectionLost { reason } => {
                        s.lost = true;
                        s.closed_by_peer = matches!(reason, ConnectionError::ApplicationClosed(_));
                        s.streams.fail_all();
                    }
                    Event::Stream(se) => s.streams.on_event(conn, se),
                    Event::DatagramReceived => s.streams.read_datagrams(conn),
                    _ => {}
                }
            }
            frames.extend(s.streams.take_frames());
            for ev in s.streams.take_events() {
                self.stream_events.push((sid, ev));
            }
        }
        for f in frames {
            self.handle_frame(sid, f, now);
        }
        if let Some(s) = self.sessions.get_mut(&sid)
            && let Some((_, conn)) = s.conn.as_mut()
        {
            s.streams.flush(conn);
            self.out.extend(quic::drain_transmits(conn, now));
        }
    }

    fn handle_frame(&mut self, sid: SessionId, frame: Frame, now: Instant) {
        match frame {
            Frame::Input { data, .. } => {
                if let Some(s) = self.sessions.get(&sid)
                    && let Some(pty) = &s.pty
                {
                    let _ = pty.write(&data);
                }
            }
            Frame::Ack { seq } => {
                if let Some(shell) = self.sessions.get_mut(&sid).and_then(|s| s.shell.as_mut()) {
                    shell.on_state_ack(seq);
                }
            }
            Frame::Control { data } => {
                if let Ok(msg) = ControlMsg::decode(&data) {
                    self.handle_control(sid, msg, now);
                }
            }
            _ => {}
        }
    }

    fn handle_control(&mut self, sid: SessionId, msg: ControlMsg, now: Instant) {
        match msg {
            ControlMsg::OpenShell {
                cols,
                rows,
                term,
                agent,
            } => {
                let Some(s) = self.sessions.get(&sid) else {
                    return;
                };
                if s.pty.is_some() {
                    return; // already open
                }
                let key = s.client_key;
                // Reattach: a running shell of the same client whose connection
                // is gone (or silent long enough that its client must be).
                let silence = self.reattach_silence;
                let old = self.sessions.iter().find_map(|(k, o)| {
                    (*k != sid
                        && key.is_some()
                        && o.client_key == key
                        && o.shell_running()
                        && (o.lost || now.duration_since(o.last_heard) >= silence))
                        .then_some(*k)
                });
                if let Some(old_sid) = old
                    && let Some(mut o) = self.sessions.remove(&old_sid)
                {
                    if let Some((ch, conn)) = o.conn.as_mut() {
                        conn.close(now, VarInt::from_u32(1), "reattached elsewhere".into());
                        self.out.extend(quic::drain_transmits(conn, now));
                        self.conns.remove(ch);
                    }
                    let Some(s) = self.sessions.get_mut(&sid) else {
                        return;
                    };
                    if let Some(shell) = &mut o.shell {
                        shell.rebind_to_new_client();
                        shell.resize(rows as usize, cols as usize);
                    }
                    if let Some(pty) = &o.pty {
                        let _ = pty.set_winsize(rows, cols);
                    }
                    s.shell = o.shell.take();
                    s.pty = o.pty.take();
                    s.rows = rows;
                    s.cols = cols;
                    s.diff_sent_seq = 0;
                    return;
                }
                // Agent forwarding: expose a Unix socket and point SSH_AUTH_SOCK
                // at it. The driver binds the actual listener (I/O); connections
                // to it are tunnelled back to the client's local agent. Refused
                // under privsep: the driver (not the dropped shell user) would
                // own the socket and accept its connections.
                let mut env = Vec::new();
                let agent_path = if agent && self.user.is_none() {
                    let path = agent_socket_path(sid);
                    env.push(("SSH_AUTH_SOCK".to_string(), path.clone()));
                    Some(path)
                } else {
                    None
                };
                let req = SpawnRequest {
                    user: self.user.clone(),
                    command: self.command.clone(),
                    env,
                    term,
                    rows,
                    cols,
                };
                if let Ok(handle) = self.login.spawn(&req)
                    && let Some(s) = self.sessions.get_mut(&sid)
                {
                    let _ = handle.set_nonblocking(true);
                    s.rows = rows;
                    s.cols = cols;
                    s.shell = Some(ServerShell::new(rows as usize, cols as usize));
                    s.pty = Some(handle);
                    if let Some(path) = agent_path {
                        self.agent_socket_requests.push((sid, path));
                    }
                }
            }
            ControlMsg::Resize { cols, rows } => {
                let Some(s) = self.sessions.get_mut(&sid) else {
                    return;
                };
                s.rows = rows;
                s.cols = cols;
                if let Some(pty) = &s.pty {
                    let _ = pty.set_winsize(rows, cols);
                }
                if let Some(shell) = &mut s.shell {
                    shell.resize(rows as usize, cols as usize);
                }
            }
            ControlMsg::RemoteForward { bind_port, target } => {
                self.remote_forward_requests.push((sid, bind_port, target));
            }
            ControlMsg::Bye => {
                if let Some(s) = self.sessions.get_mut(&sid) {
                    s.exit_status.get_or_insert(0);
                }
            }
            _ => {}
        }
    }

    /// Pump PTYs into the emulators, send screen updates and exit notices, run
    /// connection timers, and retire finished sessions.
    pub fn tick(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let now = Instant::now();
        let sids: Vec<SessionId> = self.sessions.keys().copied().collect();
        let mut finished = Vec::new();
        for sid in sids {
            let Some(s) = self.sessions.get_mut(&sid) else {
                continue;
            };
            if let Some(conn) = s.conn()
                && conn.poll_timeout().is_some_and(|t| t <= now)
            {
                conn.handle_timeout(now);
            }
            Self::pump_pty(s);
            // Detect child exit: record the status and release the PTY.
            if s.exit_status.is_none()
                && let Some(pty) = &mut s.pty
                && let Ok(Some(status)) = pty.try_wait()
            {
                // Drain whatever the shell printed last.
                Self::pump_pty(s);
                s.exit_status = Some(status);
                s.pty = None;
            }
            if !s.lost && s.streams.has_control() {
                Self::send_screen(s, now);
                if let Some(status) = s.exit_status
                    && let Some((_, conn)) = s.conn.as_mut()
                {
                    match s.exit_sent_at {
                        None => {
                            let msg = ControlMsg::Exit { status };
                            s.streams
                                .send_frame(conn, &Frame::Control { data: msg.encode() });
                            s.exit_sent_at = Some(now);
                        }
                        Some(t) if now.duration_since(t) >= EXIT_LINGER => {
                            conn.close(now, VarInt::from_u32(0), "exit".into());
                        }
                        Some(_) => {}
                    }
                }
            }
            if let Some((ch, conn)) = s.conn.as_mut()
                && conn.is_drained()
            {
                self.conns.remove(ch);
                s.conn = None;
                s.lost = true;
            }
            // Once the connection is gone, keep a running shell for the grace
            // period (unless the client said goodbye); otherwise stop it, and
            // retire the session when the connection has drained.
            if s.lost {
                let keep = s.shell_running() && !s.closed_by_peer && s.established;
                if keep {
                    let since = *s.detached_at.get_or_insert(now);
                    if now.duration_since(since) < self.detach_grace {
                        continue;
                    }
                }
                if let Some(pty) = &mut s.pty {
                    let _ = pty.kill();
                }
                s.pty = None;
                if s.conn.is_none() {
                    finished.push(sid);
                }
            }
        }
        for sid in self.sessions.keys().copied().collect::<Vec<_>>() {
            self.service(sid, now);
        }
        for sid in finished {
            self.sessions.remove(&sid);
        }
        std::mem::take(&mut self.out)
    }

    fn pump_pty(s: &mut ServerSession) {
        let Some(pty) = &mut s.pty else {
            return;
        };
        let mut buf = [0u8; 16384];
        loop {
            match pty.read(&mut buf) {
                Ok(0) => break, // EOF (child closed the pty)
                Ok(n) => {
                    if let Some(shell) = &mut s.shell {
                        shell.feed_output(&buf[..n]);
                        // Answer terminal queries (DSR/DA) the shell sent by
                        // writing the replies straight back to its input, so a
                        // line editor doesn't stall its first prompt.
                        let reply = shell.take_responses();
                        if !reply.is_empty() {
                            let _ = pty.write(&reply);
                        }
                    }
                }
                Err(PtyError::WouldBlock) => break,
                Err(_) => break,
            }
        }
    }

    /// Send the client the screen state it lacks: a new diff once the screen
    /// changed (at most every [`DIFF_INTERVAL`]), else a resend of the
    /// unacknowledged one after a retransmission timeout.
    fn send_screen(s: &mut ServerSession, now: Instant) {
        let Some((_, conn)) = s.conn.as_mut() else {
            return;
        };
        let Some(shell) = s.shell.as_mut() else {
            return;
        };
        if now.duration_since(s.diff_sent_at) < DIFF_INTERVAL {
            return;
        }
        let rto = (conn.rtt() * 3 / 2 + Duration::from_millis(10)).max(Duration::from_millis(30));
        let changed = shell.has_new_output();
        if !changed && (!shell.unacked() || now.duration_since(s.diff_sent_at) < rto) {
            return;
        }
        if s.streams.control_backlog() > DIFF_BACKLOG {
            return;
        }
        if let Some(diff) = shell.poll_diff() {
            if let Frame::StateDiff { seq, .. } = &diff {
                s.diff_sent_seq = *seq;
            }
            s.streams.send_datagram(conn, &diff);
            s.diff_sent_at = now;
        }
    }

    /// When the driver should call [`ServerCore::tick`] next, at the latest.
    pub fn next_wakeup(&mut self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let mut take = |t: Instant| next = Some(next.map_or(t, |n| n.min(t)));
        for s in self.sessions.values_mut() {
            if let Some(conn) = s.conn()
                && let Some(t) = conn.poll_timeout()
            {
                take(t);
            }
            if let (Some(shell), Some((_, conn))) = (s.shell.as_ref(), s.conn.as_ref()) {
                if shell.has_new_output() {
                    take(s.diff_sent_at + DIFF_INTERVAL);
                } else if shell.unacked() {
                    take(s.diff_sent_at + conn.rtt() * 3 / 2 + Duration::from_millis(30));
                }
            }
            if s.pty.is_some() && s.exit_status.is_none() {
                // Child exit has no fd to wait on.
                take(Instant::now() + Duration::from_millis(250));
            }
            if let Some(t) = s.exit_sent_at {
                take(t + EXIT_LINGER);
            }
            if let Some(t) = s.detached_at {
                take(t + self.detach_grace);
            }
        }
        next
    }

    /// PTY descriptors to wait on for shell output.
    pub fn poll_fds(&self) -> Vec<std::os::fd::BorrowedFd<'_>> {
        self.sessions
            .values()
            .filter_map(|s| s.pty.as_ref().map(|p| p.as_fd()))
            .collect()
    }

    // --- streams ---

    fn with_stream<R>(
        &mut self,
        sid: SessionId,
        f: impl FnOnce(&mut Streams, Option<&mut Connection>) -> R,
    ) -> Option<R> {
        let s = self.sessions.get_mut(&sid)?;
        let conn = if s.lost {
            None
        } else {
            s.conn.as_mut().map(|(_, c)| c)
        };
        let r = f(&mut s.streams, conn);
        // Surface events the call produced (e.g. a read reaching FIN).
        for ev in s.streams.take_events() {
            self.stream_events.push((sid, ev));
        }
        Some(r)
    }

    /// Drain stream lifecycle events (tagged by session).
    pub fn take_stream_events(&mut self) -> Vec<(SessionId, StreamEvent)> {
        std::mem::take(&mut self.stream_events)
    }

    /// Drain pending remote-forward (`-R`) listen requests for the driver to
    /// open TCP listeners for.
    pub fn take_remote_forward_requests(&mut self) -> Vec<(SessionId, u16, String)> {
        std::mem::take(&mut self.remote_forward_requests)
    }

    /// Drain pending agent-forwarding socket requests for the driver to bind
    /// Unix listeners for: (session, socket path).
    pub fn take_agent_socket_requests(&mut self) -> Vec<(SessionId, String)> {
        std::mem::take(&mut self.agent_socket_requests)
    }

    /// Open an agent-forwarding stream from the server side; returns its id.
    pub fn open_agent(&mut self, sid: SessionId) -> Option<u64> {
        self.with_stream(sid, |st, c| st.open(c, StreamKind::Agent, &[]))
    }

    /// Open an exec stream from the server side (used for a command's stderr);
    /// returns its id.
    pub fn open_exec(&mut self, sid: SessionId) -> Option<u64> {
        self.with_stream(sid, |st, c| st.open(c, StreamKind::Exec, &[]))
    }

    /// Report an exec's exit code (on the control stream), then finish its
    /// stdout stream.
    pub fn stream_close_status(&mut self, sid: SessionId, id: u64, status: i32) {
        self.with_stream(sid, |st, c| {
            if let Some(c) = c {
                let msg = ControlMsg::ExecExit { id, status };
                st.send_frame(c, &Frame::Control { data: msg.encode() });
                st.close(Some(c), id);
            }
        });
    }

    /// Read available bytes from a stream within a session.
    pub fn stream_read(&mut self, sid: SessionId, id: u64) -> Vec<u8> {
        self.with_stream(sid, |st, c| st.read(c, id))
            .unwrap_or_default()
    }

    /// Queue bytes to send on a stream within a session.
    pub fn stream_write(&mut self, sid: SessionId, id: u64, data: &[u8]) {
        self.with_stream(sid, |st, c| st.write(c, id, data));
    }

    /// Close our send half of a stream within a session.
    pub fn stream_close(&mut self, sid: SessionId, id: u64) {
        self.with_stream(sid, |st, c| st.close(c, id));
    }

    /// Abort a stream within a session (signals failure to the peer).
    pub fn stream_reset(&mut self, sid: SessionId, id: u64) {
        self.with_stream(sid, |st, c| st.reset(c, id));
    }

    /// Open a forward stream from the server side (used by remote `-R`
    /// forwarding); returns the new stream id.
    pub fn open_forward(&mut self, sid: SessionId, target: &str) -> Option<u64> {
        self.with_stream(sid, |st, c| {
            st.open(c, StreamKind::Forward, target.as_bytes())
        })
    }

    /// Whether a session's connection is still up (for the driver to prune
    /// listeners and connections tied to it).
    pub fn has_session(&self, sid: SessionId) -> bool {
        self.sessions.get(&sid).is_some_and(|s| !s.lost)
    }

    /// Bytes written to a stream but not yet taken by QUIC (backpressure).
    pub fn stream_in_flight(&self, sid: SessionId, id: u64) -> u64 {
        self.sessions
            .get(&sid)
            .map_or(0, |s| s.streams.in_flight(id))
    }

    /// True once the peer closed its send half and we've read every byte.
    pub fn stream_recv_finished(&self, sid: SessionId, id: u64) -> bool {
        self.sessions
            .get(&sid)
            .is_none_or(|s| s.streams.recv_finished(id))
    }
}

/// UDP driver around [`ServerCore`] for the `noisshd` binary.
pub struct Server {
    core: ServerCore,
    socket: UdpSocket,
    /// Forwarded TCP connections (both `-L` dial-outs and `-R` accepts), keyed
    /// by (session, stream id).
    forwards: HashMap<(SessionId, u64), crate::forward::ForwardConn>,
    /// Remote-forward (`-R`) listeners: (listener, session, target).
    remote_listeners: Vec<(std::net::TcpListener, SessionId, String)>,
    /// In-progress file transfers keyed by (session, stream id).
    xfers: HashMap<(SessionId, u64), XferState>,
    /// Agent-forwarding Unix listeners: (listener, session, socket path).
    agent_listeners: Vec<(
        std::os::unix::net::UnixListener,
        SessionId,
        std::path::PathBuf,
    )>,
    /// Live agent-forwarding connections (server side of the tunnel), keyed by
    /// (session, stream id).
    agent_conns:
        HashMap<(SessionId, u64), crate::forward::ForwardConn<std::os::unix::net::UnixStream>>,
    /// Running remote commands, keyed by (session, stdin/stdout stream id).
    execs: HashMap<(SessionId, u64), ExecState>,
    /// Receive buffer, reused for every datagram.
    rbuf: Vec<u8>,
}

/// Per-stream cap on bytes queued for QUIC but not yet taken by it.
const SEND_CAP: u64 = 1024 * 1024;

/// Server side of a file transfer: writing an upload, or reading a download.
enum XferState {
    Put(crate::xfer::FileSink),
    Get(crate::xfer::FileSource),
}

/// Server side of a running remote command. `err_id` is the separate stream
/// carrying the command's stderr to the client.
struct ExecState {
    proc: crate::exec::ExecProc,
    err_id: u64,
}

impl Server {
    pub fn bind(addr: SocketAddr, core: ServerCore) -> Result<Self, RuntimeError> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Ok(Server {
            core,
            socket,
            forwards: HashMap::new(),
            remote_listeners: Vec::new(),
            xfers: HashMap::new(),
            agent_listeners: Vec::new(),
            agent_conns: HashMap::new(),
            execs: HashMap::new(),
            rbuf: vec![0u8; 65536],
        })
    }

    /// Ensure the per-user agent-socket directory exists, is a real directory we
    /// own, and is private (mode 0700). Rejects a pre-existing path owned by
    /// another user or that is not a directory (symlink/replace defence).
    fn ensure_agent_dir() -> std::io::Result<std::path::PathBuf> {
        use std::io::{Error, ErrorKind};
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

        let dir = agent_socket_dir();
        let uid = nix::unistd::Uid::current().as_raw();
        match std::fs::symlink_metadata(&dir) {
            Ok(meta) => {
                if !meta.file_type().is_dir() {
                    return Err(Error::new(
                        ErrorKind::AlreadyExists,
                        "agent socket dir is not a directory",
                    ));
                }
                if meta.uid() != uid {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "agent socket dir not owned by current user",
                    ));
                }
                // Tighten in case a previous run (or umask) left it loose.
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
            }
            Err(e) => return Err(e),
        }
        Ok(dir)
    }

    /// Bind the per-session agent listener at `path`, locked down so only the
    /// owning user can connect: a 0700 parent directory plus a 0600 socket.
    fn bind_agent_socket(path: &str) -> std::io::Result<std::os::unix::net::UnixListener> {
        use nix::sys::stat::{Mode, umask};
        use std::os::unix::fs::PermissionsExt;

        Self::ensure_agent_dir()?;
        let p = std::path::Path::new(path);
        let _ = std::fs::remove_file(p); // clear a stale socket from a prior run
        // Bind under a restrictive umask so the socket is created 0600 from the
        // start — closing the window between bind and a path-based chmod where it
        // could briefly be reachable by another same-uid process.
        let prev = umask(Mode::from_bits_truncate(0o177));
        let bound = std::os::unix::net::UnixListener::bind(p);
        umask(prev); // restore promptly, even on bind failure
        let listener = bound?;
        // Belt and suspenders: tighten perms explicitly too.
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        Ok(listener)
    }

    /// Service forwarded TCP connections: dial out for new forward streams,
    /// move bytes between TCP and the session streams in both directions.
    fn pump_forwards(&mut self) {
        use crate::forward::ForwardConn;

        // Honour remote-forward (`-R`) requests: open a TCP listener per request.
        // Bind to loopback by default (do NOT expose the forwarded port to the
        // network — that would be an SSH "GatewayPorts yes" behaviour, which is
        // off by default). Skip duplicates for the same (session, port).
        for (sid, bind_port, target) in self.core.take_remote_forward_requests() {
            let already = self.remote_listeners.iter().any(|(l, s, _)| {
                *s == sid && l.local_addr().map(|a| a.port()).ok() == Some(bind_port)
            });
            if already {
                continue;
            }
            if let Ok(l) = std::net::TcpListener::bind(("127.0.0.1", bind_port)) {
                let _ = l.set_nonblocking(true);
                self.remote_listeners.push((l, sid, target));
            }
        }
        // Drop listeners whose session is gone (avoids port squatting + leak).
        self.remote_listeners
            .retain(|(_, sid, _)| self.core.has_session(*sid));

        // Accept on remote listeners: open a forward stream toward the client.
        let mut accepted: Vec<(SessionId, String, std::net::TcpStream)> = Vec::new();
        for (l, sid, target) in &self.remote_listeners {
            loop {
                match l.accept() {
                    Ok((s, _)) => accepted.push((*sid, target.clone(), s)),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        for (sid, target, s) in accepted {
            if let (Some(id), Ok(conn)) =
                (self.core.open_forward(sid, &target), ForwardConn::new(s))
            {
                self.forwards.insert((sid, id), conn);
            }
        }

        // Honour agent-forwarding requests: bind a Unix listener per request at
        // the path the shell's SSH_AUTH_SOCK points to. The socket carries the
        // user's live agent, so it must not be reachable by other local users:
        // it lives in a per-user 0700 directory and is itself chmod 0600.
        use std::os::unix::net::UnixStream;
        for (sid, path) in self.core.take_agent_socket_requests() {
            match Self::bind_agent_socket(&path) {
                Ok(l) => self
                    .agent_listeners
                    .push((l, sid, std::path::PathBuf::from(path))),
                Err(e) => eprintln!("noisshd: agent forwarding disabled for session: {e}"),
            }
        }
        // Drop agent listeners whose session is gone, unlinking the socket file.
        self.agent_listeners.retain(|(_, sid, path)| {
            if self.core.has_session(*sid) {
                true
            } else {
                let _ = std::fs::remove_file(path);
                false
            }
        });
        // Accept on agent listeners: each connection opens an Agent stream toward
        // the client, which bridges it to the client's own SSH agent.
        let mut agent_accepted: Vec<(SessionId, UnixStream)> = Vec::new();
        for (l, sid, _) in &self.agent_listeners {
            loop {
                match l.accept() {
                    Ok((s, _)) => agent_accepted.push((*sid, s)),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        for (sid, s) in agent_accepted {
            let Some(id) = self.core.open_agent(sid) else {
                continue;
            };
            match ForwardConn::new_unix(s) {
                Ok(conn) => {
                    self.agent_conns.insert((sid, id), conn);
                }
                // Couldn't wrap the accepted socket: reset the just-opened stream
                // so it isn't orphaned (retransmitting an open the client can
                // never satisfy) and stalling the session.
                Err(_) => self.core.stream_reset(sid, id),
            }
        }

        for (sid, ev) in self.core.take_stream_events() {
            match ev {
                StreamEvent::Opened {
                    id,
                    kind: StreamKind::Forward,
                    meta,
                } => {
                    match std::str::from_utf8(&meta)
                        .ok()
                        .and_then(|t| ForwardConn::connect(t).ok())
                    {
                        Some(conn) => {
                            self.forwards.insert((sid, id), conn);
                        }
                        None => self.core.stream_reset(sid, id), // unreachable target
                    }
                }
                StreamEvent::Opened {
                    id,
                    kind: StreamKind::FileTransfer,
                    ..
                } if self.core.privsep_active() => {
                    // The driver can't confine file I/O to the dropped session
                    // user, so refuse rather than read/write as the driver's
                    // (possibly root) identity. See ServerCore::privsep_active.
                    self.core.stream_reset(sid, id);
                }
                StreamEvent::Opened {
                    id,
                    kind: StreamKind::FileTransfer,
                    meta,
                } => match proto::XferRequest::parse(&meta) {
                    Some(proto::XferRequest::Put { path, .. }) => {
                        match crate::xfer::FileSink::create(&path) {
                            Ok(sink) => {
                                self.xfers.insert((sid, id), XferState::Put(sink));
                            }
                            // Can't create the destination: signal failure.
                            Err(_) => self.core.stream_reset(sid, id),
                        }
                    }
                    Some(proto::XferRequest::Get { path }) => {
                        match crate::xfer::FileSource::open(&path) {
                            Ok(src) => {
                                self.xfers.insert((sid, id), XferState::Get(src));
                            }
                            // No such file (or unreadable): signal failure.
                            Err(_) => self.core.stream_reset(sid, id),
                        }
                    }
                    None => self.core.stream_reset(sid, id),
                },
                // Exec under a privsep drop would run as the driver's (possibly
                // root) identity — refuse, like file transfer.
                StreamEvent::Opened {
                    id,
                    kind: StreamKind::Exec,
                    ..
                } if self.core.privsep_active() => {
                    self.core.stream_reset(sid, id);
                }
                StreamEvent::Opened {
                    id,
                    kind: StreamKind::Exec,
                    meta,
                } => {
                    let cmd = String::from_utf8_lossy(&meta).into_owned();
                    match crate::exec::ExecProc::spawn(&cmd) {
                        Ok(mut proc) => match self.core.open_exec(sid) {
                            Some(err_id) => {
                                self.execs.insert((sid, id), ExecState { proc, err_id });
                            }
                            // Session vanished between events: kill the child we
                            // just spawned so it isn't leaked, then reset.
                            None => {
                                proc.kill();
                                self.core.stream_reset(sid, id);
                            }
                        },
                        // Couldn't spawn the command: signal failure to the client.
                        Err(_) => self.core.stream_reset(sid, id),
                    }
                }
                // Draining happens in the bounded pump loop below.
                StreamEvent::Readable { .. } => {}
                StreamEvent::Closed { id } => {
                    if let Some(c) = self.forwards.get_mut(&(sid, id)) {
                        c.mark_peer_closed();
                    }
                    if let Some(c) = self.agent_conns.get_mut(&(sid, id)) {
                        c.mark_peer_closed();
                    }
                    // Client closed its stdin half: send EOF to the command.
                    if let Some(e) = self.execs.get_mut(&(sid, id)) {
                        e.proc.close_stdin();
                    }
                    // Upload completion is detected in the pump loop once every
                    // buffered byte has been drained into the sink (the Closed
                    // event can precede the final data segments).
                }
                StreamEvent::Reset { id } => {
                    // Forget the stream (the peer already aborted it).
                    self.core.stream_reset(sid, id);
                    self.forwards.remove(&(sid, id));
                    self.xfers.remove(&(sid, id));
                    self.agent_conns.remove(&(sid, id));
                    if let Some(mut e) = self.execs.remove(&(sid, id)) {
                        e.proc.kill();
                        self.core.stream_reset(sid, e.err_id);
                    }
                }
                _ => {}
            }
        }
        // Pump both directions, with caps, propagate half-close, reap.
        // Drop forwards/xfers whose session has gone away (e.g. idle-reaped or
        // replaced by a reattach): otherwise their TCP fds / file handles leak,
        // and an interrupted upload would be wrongly finalized as complete.
        let dead: Vec<(SessionId, u64)> = self
            .forwards
            .keys()
            .chain(self.xfers.keys())
            .copied()
            .filter(|(sid, _)| !self.core.has_session(*sid))
            .collect();
        for k in dead {
            self.forwards.remove(&k);
            self.xfers.remove(&k);
        }
        let keys: Vec<(SessionId, u64)> = self.forwards.keys().copied().collect();
        for k in keys {
            if let Some(c) = self.forwards.get_mut(&k) {
                // session → TCP, bounded so a stuck peer backpressures the session.
                c.flush();
                while c.out_len() < SEND_CAP as usize {
                    let d = self.core.stream_read(k.0, k.1);
                    if d.is_empty() {
                        break;
                    }
                    c.queue_to_tcp(&d);
                }
                // TCP → session, bounded by bytes QUIC hasn't taken yet.
                while self.core.stream_in_flight(k.0, k.1) < SEND_CAP {
                    let d = c.read_tcp();
                    if d.is_empty() {
                        break;
                    }
                    self.core.stream_write(k.0, k.1, &d);
                }
                if c.needs_fin() {
                    self.core.stream_close(k.0, k.1);
                }
                if c.is_finished() {
                    self.forwards.remove(&k);
                }
            }
        }

        // Pump file transfers: drain uploads into their sinks, feed downloads
        // from their sources, and finalize each when complete.
        let xkeys: Vec<(SessionId, u64)> = self.xfers.keys().copied().collect();
        for k in xkeys {
            // Whether the download stream has room for another chunk (bounded by
            // unacked in-flight bytes); computed before the borrow below.
            let get_has_window = self.core.stream_in_flight(k.0, k.1) < SEND_CAP;
            // `abort` distinguishes an I/O failure (reset → client sees an error)
            // from a clean end-of-transfer (graceful close → client sees success).
            let mut abort = false;
            let done = match self.xfers.get_mut(&k) {
                Some(XferState::Put(sink)) => {
                    loop {
                        let d = self.core.stream_read(k.0, k.1);
                        if d.is_empty() {
                            break;
                        }
                        if sink.write(&d).is_err() {
                            abort = true;
                            break;
                        }
                    }
                    // Finished once the client closed its half and all bytes are
                    // written; or aborted on a write error.
                    abort || self.core.stream_recv_finished(k.0, k.1)
                }
                Some(XferState::Get(src)) if get_has_window => match src.read_chunk(256 * 1024) {
                    Ok(d) if !d.is_empty() => {
                        self.core.stream_write(k.0, k.1, &d);
                        false
                    }
                    Ok(_) => true, // EOF: the whole file has been sent.
                    Err(_) => {
                        abort = true; // mid-file read error: fail the transfer.
                        true
                    }
                },
                // Window full (or no such transfer): wait for the next pump.
                Some(XferState::Get(_)) | None => false,
            };
            if done {
                if abort {
                    // Signal failure so the client doesn't treat a partial
                    // transfer as success.
                    self.core.stream_reset(k.0, k.1);
                    self.xfers.remove(&k); // drop sink → temp file discarded
                } else {
                    self.core.stream_close(k.0, k.1);
                    // On a successful upload, atomically move the temp file into
                    // place; on download there is no local sink to finalize.
                    if let Some(XferState::Put(sink)) = self.xfers.remove(&k)
                        && sink.finalize().is_err()
                    {
                        // Rename failed after the bytes arrived: tell the client
                        // the transfer didn't land.
                        self.core.stream_reset(k.0, k.1);
                    }
                }
            }
        }

        // Pump agent-forwarding connections (same model as port forwards).
        // Drop any whose session has gone away so their Unix fds don't leak.
        let dead_agents: Vec<(SessionId, u64)> = self
            .agent_conns
            .keys()
            .copied()
            .filter(|(sid, _)| !self.core.has_session(*sid))
            .collect();
        for k in dead_agents {
            self.agent_conns.remove(&k);
        }
        let akeys: Vec<(SessionId, u64)> = self.agent_conns.keys().copied().collect();
        for k in akeys {
            if let Some(c) = self.agent_conns.get_mut(&k) {
                c.flush();
                while c.out_len() < SEND_CAP as usize {
                    let d = self.core.stream_read(k.0, k.1);
                    if d.is_empty() {
                        break;
                    }
                    c.queue_to_tcp(&d);
                }
                while self.core.stream_in_flight(k.0, k.1) < SEND_CAP {
                    let d = c.read_tcp();
                    if d.is_empty() {
                        break;
                    }
                    self.core.stream_write(k.0, k.1, &d);
                }
                if c.needs_fin() {
                    self.core.stream_close(k.0, k.1);
                }
                if c.is_finished() {
                    self.agent_conns.remove(&k);
                }
            }
        }

        // Pump remote commands: command stdout → its stream, stderr → the
        // sibling stream, client stream → command stdin, exit code on close.
        // Drop any whose session has gone away (kill the child first).
        let ekeys: Vec<(SessionId, u64)> = self.execs.keys().copied().collect();
        for k in ekeys {
            if !self.core.has_session(k.0) {
                if let Some(mut e) = self.execs.remove(&k) {
                    e.proc.kill();
                }
                continue;
            }
            let Some(e) = self.execs.get_mut(&k) else {
                continue;
            };
            // Feed any client stdin into the command, but stop once the staging
            // buffer is large (the child isn't draining stdin) so a fast client
            // can't grow it without bound — the stream's flow control then
            // backpressures the client.
            while e.proc.stdin_buffered() < SEND_CAP as usize {
                let d = self.core.stream_read(k.0, k.1);
                if d.is_empty() {
                    break;
                }
                e.proc.write_stdin(&d);
            }
            e.proc.flush_stdin();
            // command stdout → the exec stream (bounded by unacked bytes).
            if self.core.stream_in_flight(k.0, k.1) < SEND_CAP {
                let out = e.proc.read_stdout();
                if !out.is_empty() {
                    self.core.stream_write(k.0, k.1, &out);
                }
            }
            // command stderr → the sibling stream.
            let err_id = e.err_id;
            if self.core.stream_in_flight(k.0, err_id) < SEND_CAP {
                let err = e.proc.read_stderr();
                if !err.is_empty() {
                    self.core.stream_write(k.0, err_id, &err);
                }
            }
            e.proc.poll_exit();
            // Finished once the process exited and both pipes drained; close the
            // streams, carrying the exit code on the stdout stream.
            if e.proc.finished() {
                let code = e.proc.exit_code();
                self.core.stream_close_status(k.0, k.1, code);
                self.core.stream_close(k.0, err_id);
                self.execs.remove(&k);
            }
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, RuntimeError> {
        Ok(self.socket.local_addr()?)
    }

    /// Wait until the socket, a shell, a forwarded connection or a timer
    /// needs attention (at most `max`).
    fn wait(&mut self, max: Duration) {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::os::fd::AsFd;

        let deadline = self.core.next_wakeup();
        let mut timeout = deadline.map_or(max, |t| {
            t.saturating_duration_since(Instant::now()).min(max)
        });
        // A running command's exit has no descriptor to wait on.
        if !self.execs.is_empty() {
            timeout = timeout.min(Duration::from_millis(20));
        }
        let mut fds = vec![PollFd::new(self.socket.as_fd(), PollFlags::POLLIN)];
        for fd in self.core.poll_fds() {
            fds.push(PollFd::new(fd, PollFlags::POLLIN));
        }
        let io = |c_in: bool, wants_write: bool| {
            let mut f = PollFlags::empty();
            if c_in {
                f |= PollFlags::POLLIN;
            }
            if wants_write {
                f |= PollFlags::POLLOUT;
            }
            f
        };
        for (k, c) in &self.forwards {
            let f = io(
                self.core.stream_in_flight(k.0, k.1) < SEND_CAP,
                c.wants_write(),
            );
            if !f.is_empty() {
                fds.push(PollFd::new(c.as_fd(), f));
            }
        }
        for (k, c) in &self.agent_conns {
            let f = io(
                self.core.stream_in_flight(k.0, k.1) < SEND_CAP,
                c.wants_write(),
            );
            if !f.is_empty() {
                fds.push(PollFd::new(c.as_fd(), f));
            }
        }
        for (l, _, _) in &self.remote_listeners {
            fds.push(PollFd::new(l.as_fd(), PollFlags::POLLIN));
        }
        for (l, _, _) in &self.agent_listeners {
            fds.push(PollFd::new(l.as_fd(), PollFlags::POLLIN));
        }
        for (k, e) in &self.execs {
            if self.core.stream_in_flight(k.0, k.1) < SEND_CAP {
                for fd in e.proc.output_fds() {
                    fds.push(PollFd::new(fd, PollFlags::POLLIN));
                }
            }
        }
        // Downloads with room in their window are ready to read the file now.
        let xfer_ready = self.xfers.iter().any(|(k, x)| {
            matches!(x, XferState::Get(_)) && self.core.stream_in_flight(k.0, k.1) < SEND_CAP
        });
        if xfer_ready {
            timeout = Duration::ZERO;
        }
        let ms = timeout.as_micros().div_ceil(1000).min(u16::MAX as u128) as u16;
        let _ = poll(&mut fds, PollTimeout::from(ms));
    }

    pub fn core(&self) -> &ServerCore {
        &self.core
    }

    /// One service iteration: wait for something to do (at most 100 ms),
    /// drain ready datagrams, move forwarded data, then tick. Returns false on
    /// a fatal socket error (the loop should stop).
    pub fn poll_once(&mut self) -> bool {
        self.wait(Duration::from_millis(100));
        // Bounded, so a flood can't starve the shells and forwards.
        for _ in 0..256 {
            match self.socket.recv_from(&mut self.rbuf) {
                Ok((n, src)) => {
                    for (addr, pkt) in self.core.handle_packet(src, &self.rbuf[..n]) {
                        let _ = self.socket.send_to(&pkt, addr);
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::Interrupted =>
                {
                    break;
                }
                // ICMP errors (port unreachable from a vanished client) surface
                // here on Linux; they concern one peer, not the socket.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => continue,
                Err(_) => return false,
            }
        }
        // Move bytes between forwarded connections and their session streams
        // before ticking, so freshly-read data ships out in this iteration.
        self.pump_forwards();
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
