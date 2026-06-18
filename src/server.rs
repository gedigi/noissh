//! Server runtime: a socket-free [`ServerCore`] (drivable by the resilience
//! harness) plus a [`Server`] UDP driver used by the `noisshd` binary.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use auth::AuthorizedKeys;
use noise_core::Keypair;
use proto::{ControlMsg, Handshaker, ServerShell, authorize_client};
use pty::{LocalLogin, LoginSession, PtyError, PtyHandle, SpawnRequest};
use transport::{Packet, Session, SessionId, StreamEvent, StreamMux};
use wire::{Frame, StreamKind};

use crate::RuntimeError;

struct ServerSession {
    session: Session,
    shell: Option<ServerShell>,
    pty: Option<PtyHandle>,
    rows: u16,
    cols: u16,
    /// The authenticated client static key, used to reattach a returning client.
    client_key: Vec<u8>,
    /// Ticks since we last received an authenticated packet from this client;
    /// resets to 0 on activity. Drives detached-session reaping.
    idle_ticks: u32,
    /// Set once the shell has exited; carries its status for retransmission.
    exit_status: Option<i32>,
    /// Ticks elapsed since exit, used to bound Exit retransmission before the
    /// session is reclaimed.
    exit_ticks: u32,
    /// Reliable stream multiplexer (port forwarding etc.) for this session.
    mux: StreamMux,
}

/// How many ticks to keep retransmitting the Exit notice before reclaiming a
/// finished session (the notice is best-effort; this bounds delivery + memory).
const EXIT_RETRANSMIT_TICKS: u32 = 50;

/// Reap a session whose client has been silent for this many ticks (no acks,
/// no keepalives). A live client sends keepalives well within this window; this
/// is also the grace during which a vanished client may reattach. At the
/// server's tick cadence (~tens of ms) this is on the order of minutes.
const IDLE_REAP_TICKS: u32 = 20_000;

/// Cap on simultaneously in-flight (incomplete) handshakes, bounding memory
/// against a flood of fresh session-ids from a spoofed source.
const MAX_PENDING_HANDSHAKES: usize = 512;

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
    /// Stream lifecycle events surfaced to the driver, tagged by session.
    stream_events: Vec<(SessionId, StreamEvent)>,
    /// Remote-forward (`-R`) listen requests surfaced to the driver:
    /// (session, bind_port, target).
    remote_forward_requests: Vec<(SessionId, u16, String)>,
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
            stream_events: Vec::new(),
            remote_forward_requests: Vec::new(),
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
        self.ever_active && self.sessions.values().all(|s| s.exit_status.is_some())
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
        // Malformed/unauthorized packets are silently dropped.
        self.try_handle_packet(src, buf).unwrap_or_default()
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
            None => {
                // New handshake: refuse if we're already tracking too many, to
                // bound memory against a session-id flood.
                if self.pending.len() >= MAX_PENDING_HANDSHAKES {
                    return Ok(Vec::new());
                }
                Handshaker::server(&self.keypair.private, sid)?
            }
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

            // Reattach: if this client key already has a live session (its
            // previous connection went silent but the shell is still running),
            // move that running shell/pty onto the new transport session and
            // resend the screen as a full snapshot.
            // Only reattach to a session that actually has a running shell/pty;
            // never steal another still-establishing session for the same key.
            let existing = self.sessions.iter().find_map(|(k, s)| {
                (s.client_key == client_static
                    && s.exit_status.is_none()
                    && (s.shell.is_some() || s.pty.is_some()))
                .then_some(*k)
            });

            let mut new_sess = ServerSession {
                session,
                shell: None,
                pty: None,
                rows: 24,
                cols: 80,
                client_key: client_static,
                idle_ticks: 0,
                exit_status: None,
                exit_ticks: 0,
                mux: StreamMux::new(false),
            };
            if let Some(old_sid) = existing
                && let Some(mut old) = self.sessions.remove(&old_sid)
            {
                if let Some(shell) = &mut old.shell {
                    shell.rebind_to_new_client();
                }
                new_sess.shell = old.shell.take();
                new_sess.pty = old.pty.take();
                new_sess.rows = old.rows;
                new_sess.cols = old.cols;
            }
            self.sessions.insert(sid, new_sess);
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
            let frames = sess.session.open(src, buf)?; // roaming: peer_addr now = src
            sess.idle_ticks = 0; // authenticated activity resets the idle timer
            frames
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
                Frame::Ping { stamp } => reply_frames.push(Frame::Pong { stamp }),
                f @ (Frame::StreamOpen { .. }
                | Frame::StreamData { .. }
                | Frame::StreamAck { .. }
                | Frame::StreamClose { .. }
                | Frame::StreamReset { .. }) => {
                    if let Some(sess) = self.sessions.get_mut(&sid) {
                        sess.mux.on_frame(f);
                    }
                }
                _ => {}
            }
        }
        let evs = self
            .sessions
            .get_mut(&sid)
            .map(|sess| sess.mux.take_events())
            .unwrap_or_default();
        for ev in evs {
            self.stream_events.push((sid, ev));
        }
        let mut out = Vec::new();
        if !reply_frames.is_empty()
            && let Some(sess) = self.sessions.get_mut(&sid)
            && let Some(addr) = sess.session.peer_addr()
        {
            for pkt in sess
                .session
                .seal_many(&reply_frames, transport::MAX_DATAGRAM_PLAINTEXT)?
            {
                out.push((addr, pkt));
            }
        }
        Ok(out)
    }

    fn handle_control(&mut self, sid: SessionId, msg: ControlMsg) {
        match msg {
            ControlMsg::OpenShell { cols, rows, term } => {
                let Some(sess) = self.sessions.get_mut(&sid) else {
                    return;
                };
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
                let Some(sess) = self.sessions.get_mut(&sid) else {
                    return;
                };
                sess.rows = rows;
                sess.cols = cols;
                if let Some(pty) = &sess.pty {
                    let _ = pty.set_winsize(rows, cols);
                }
                if let Some(shell) = &mut sess.shell {
                    shell.resize(rows as usize, cols as usize);
                }
            }
            ControlMsg::RemoteForward { bind_port, target } => {
                self.remote_forward_requests.push((sid, bind_port, target));
            }
            _ => {}
        }
    }

    /// Pump PTYs into the emulators and emit state diffs / exit notices.
    pub fn tick(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut out = Vec::new();
        let mut finished: Vec<SessionId> = Vec::new();
        let mut events_buf: Vec<(SessionId, StreamEvent)> = Vec::new();
        let sids: Vec<SessionId> = self.sessions.keys().copied().collect();
        for sid in sids {
            let Some(sess) = self.sessions.get_mut(&sid) else {
                continue;
            };
            // Reap a session whose client has been silent past the grace window
            // (detached and never reattached). Killing the PTY here lets the
            // child exit; the exit path below then retires the session.
            sess.idle_ticks = sess.idle_ticks.saturating_add(1);
            if sess.idle_ticks >= IDLE_REAP_TICKS && sess.exit_status.is_none() {
                if let Some(pty) = &mut sess.pty {
                    let _ = pty.kill();
                }
                finished.push(sid);
                continue;
            }
            // Drain available PTY output.
            if let Some(pty) = &mut sess.pty {
                let mut buf = [0u8; 8192];
                loop {
                    match pty.read(&mut buf) {
                        Ok(0) => break, // EOF (child closed the pty)
                        Ok(n) => {
                            if let Some(shell) = &mut sess.shell {
                                shell.feed_output(&buf[..n]);
                            }
                        }
                        Err(PtyError::WouldBlock) => break, // no data ready now
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
            // Emit reliable-stream frames (port forwarding) and surface events.
            let stream_frames = sess.mux.poll_transmit();
            for ev in sess.mux.take_events() {
                events_buf.push((sid, ev));
            }
            if !stream_frames.is_empty()
                && let Some(addr) = sess.session.peer_addr()
                && let Ok(pkts) = sess
                    .session
                    .seal_many(&stream_frames, transport::MAX_DATAGRAM_PLAINTEXT)
            {
                for pkt in pkts {
                    out.push((addr, pkt));
                }
            }
            // Detect child exit: record the status and release the PTY.
            if sess.exit_status.is_none()
                && let Some(pty) = &mut sess.pty
                && let Ok(Some(status)) = pty.try_wait()
            {
                sess.exit_status = Some(status);
                sess.pty = None;
            }
            // While exited, retransmit the Exit notice for a bounded number of
            // ticks, then reclaim the session.
            if let Some(status) = sess.exit_status {
                if let Some(addr) = sess.session.peer_addr()
                    && let Ok(pkt) = sess.session.seal(&[Frame::Control {
                        data: ControlMsg::Exit { status }.encode(),
                    }])
                {
                    out.push((addr, pkt));
                }
                sess.exit_ticks += 1;
                if sess.exit_ticks >= EXIT_RETRANSMIT_TICKS {
                    finished.push(sid);
                }
            }
        }
        // Reclaim fully-finished sessions so memory does not grow without bound.
        for sid in finished {
            self.sessions.remove(&sid);
        }
        self.stream_events.append(&mut events_buf);
        out
    }

    // --- reliable streams (port forwarding) ---

    /// Drain stream lifecycle events (tagged by session).
    pub fn take_stream_events(&mut self) -> Vec<(SessionId, StreamEvent)> {
        std::mem::take(&mut self.stream_events)
    }

    /// Drain pending remote-forward (`-R`) listen requests for the driver to
    /// open TCP listeners for.
    pub fn take_remote_forward_requests(&mut self) -> Vec<(SessionId, u16, String)> {
        std::mem::take(&mut self.remote_forward_requests)
    }

    /// Read available contiguous bytes from a stream within a session.
    pub fn stream_read(&mut self, sid: SessionId, id: u64) -> Vec<u8> {
        self.sessions
            .get_mut(&sid)
            .map(|s| s.mux.read(id))
            .unwrap_or_default()
    }

    /// Queue bytes to send on a stream within a session.
    pub fn stream_write(&mut self, sid: SessionId, id: u64, data: &[u8]) {
        if let Some(s) = self.sessions.get_mut(&sid) {
            s.mux.write(id, data);
        }
    }

    /// Close our send half of a stream within a session.
    pub fn stream_close(&mut self, sid: SessionId, id: u64) {
        if let Some(s) = self.sessions.get_mut(&sid) {
            s.mux.close(id, 0);
        }
    }

    /// Abort a stream within a session (signals failure to the peer).
    pub fn stream_reset(&mut self, sid: SessionId, id: u64) {
        if let Some(s) = self.sessions.get_mut(&sid) {
            s.mux.reset(id);
        }
    }

    /// Open a forward stream from the server side (used by remote `-R`
    /// forwarding); returns the new stream id.
    pub fn open_forward(&mut self, sid: SessionId, target: &str) -> Option<u64> {
        self.sessions
            .get_mut(&sid)
            .map(|s| s.mux.open(StreamKind::Forward, target.as_bytes().to_vec()))
    }

    /// Whether a session still exists (for the driver to prune `-R` listeners).
    pub fn has_session(&self, sid: SessionId) -> bool {
        self.sessions.contains_key(&sid)
    }

    /// Bytes written to a stream but not yet acked (driver backpressure).
    pub fn stream_in_flight(&self, sid: SessionId, id: u64) -> u64 {
        self.sessions
            .get(&sid)
            .map(|s| s.mux.in_flight(id))
            .unwrap_or(0)
    }

    /// True once the peer closed its send half and we've read every byte.
    pub fn stream_recv_finished(&self, sid: SessionId, id: u64) -> bool {
        self.sessions
            .get(&sid)
            .map(|s| s.mux.is_recv_finished(id))
            .unwrap_or(true)
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
}

/// Server side of a file transfer: writing an upload, or reading a download.
enum XferState {
    Put(crate::xfer::FileSink),
    Get(crate::xfer::FileSource),
}

impl Server {
    pub fn bind(addr: SocketAddr, core: ServerCore) -> Result<Self, RuntimeError> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(10)))?;
        Ok(Server {
            core,
            socket,
            forwards: HashMap::new(),
            remote_listeners: Vec::new(),
            xfers: HashMap::new(),
        })
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
                        None => self.core.stream_close(sid, id), // unreachable target
                    }
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
                // Draining happens in the bounded pump loop below.
                StreamEvent::Readable { .. } => {}
                StreamEvent::Closed { id, .. } => {
                    if let Some(c) = self.forwards.get_mut(&(sid, id)) {
                        c.mark_peer_closed();
                    }
                    // Upload completion is detected in the pump loop once every
                    // buffered byte has been drained into the sink (the Closed
                    // event can precede the final data segments).
                }
                StreamEvent::Reset { id } => {
                    self.forwards.remove(&(sid, id));
                    self.xfers.remove(&(sid, id));
                }
                _ => {}
            }
        }
        // Pump both directions, with caps, propagate half-close, reap.
        const SEND_CAP: u64 = 512 * 1024;
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
                // TCP → session, bounded by unacked in-flight bytes.
                if self.core.stream_in_flight(k.0, k.1) < SEND_CAP {
                    let d = c.read_tcp();
                    if !d.is_empty() {
                        self.core.stream_write(k.0, k.1, &d);
                    }
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
            let done = match self.xfers.get_mut(&k) {
                Some(XferState::Put(sink)) => {
                    let mut err = false;
                    loop {
                        let d = self.core.stream_read(k.0, k.1);
                        if d.is_empty() {
                            break;
                        }
                        if sink.write(&d).is_err() {
                            err = true;
                            break;
                        }
                    }
                    // Finished once the client closed its half and all bytes are
                    // written; or aborted on a write error.
                    err || self.core.stream_recv_finished(k.0, k.1)
                }
                Some(XferState::Get(src)) if get_has_window => match src.read_chunk(64 * 1024) {
                    Ok(d) if !d.is_empty() => {
                        self.core.stream_write(k.0, k.1, &d);
                        false
                    }
                    // EOF or read error: nothing more to send.
                    _ => true,
                },
                // Window full (or no such transfer): wait for the next pump.
                Some(XferState::Get(_)) | None => false,
            };
            if done {
                self.core.stream_close(k.0, k.1);
                self.xfers.remove(&k);
            }
        }
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
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return false,
        }
        // Move bytes between forwarded TCP connections and their session streams
        // before ticking, so freshly-read TCP data ships out in this iteration.
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
