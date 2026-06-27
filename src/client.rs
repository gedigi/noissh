//! Client runtime: a socket-free [`ClientCore`] (drivable by the resilience
//! harness) plus a [`Client`] UDP driver used by the `noissh` binary.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use auth::{KnownHosts, Tofu};
use noise_core::Keypair;
use predict::DisplayMode;
use proto::{ClientShell, ControlMsg, Handshaker, verify_server};
use term::Grid;
use transport::{Packet, Session, StreamEvent, StreamMux, random_session_id};
use wire::{Frame, StreamKind};

use crate::RuntimeError;

/// Socket-free client logic: consumes raw packets, produces raw packets.
pub struct ClientCore {
    hs: Option<Handshaker>,
    session: Option<Session>,
    shell: ClientShell,
    known: KnownHosts,
    host_label: String,
    server_addr: SocketAddr,
    rows: u16,
    cols: u16,
    term: String,
    established: bool,
    server_static: Option<Vec<u8>>,
    exited: Option<i32>,
    pending_control: Vec<Frame>,
    open_shell_pending: bool,
    open_shell_ticks: u32,
    /// A state-diff arrived since we last sent frames; re-ack so the server is
    /// not left retransmitting if a prior ack was lost.
    need_ack: bool,
    /// Reliable stream multiplexer (port forwarding etc.) over this session.
    mux: StreamMux,
    stream_events: Vec<StreamEvent>,
    /// Whether to request an interactive shell on connect (false for `-N`-style
    /// forward-only sessions).
    want_shell: bool,
    /// Whether to ask the server to forward our SSH agent (`-A`).
    want_agent: bool,
    /// Pending remote-forward (`-R`) requests, retransmitted for a bounded
    /// number of ticks (there is no ack, so we resend to survive packet loss).
    remote_forwards: Vec<(u16, String)>,
    remote_forward_ticks: u32,
    known_hosts_dirty: bool,
    /// The server's version, learned from its [`ControlMsg::ServerVersion`] after
    /// the session is established (a pre-v0.5.2 server never sends one).
    server_version: Option<String>,
}

/// Bound on OpenShell retransmissions, so a shell that produces no screen output
/// does not cause the request to be resent for the whole session.
const OPEN_SHELL_MAX_TICKS: u32 = 300;

/// Bound on RemoteForward retransmissions (best-effort reliability over UDP).
const REMOTE_FORWARD_MAX_TICKS: u32 = 300;

impl ClientCore {
    /// Begin a connection. Returns the core and the first handshake packet.
    pub fn new(
        keypair: &Keypair,
        known: KnownHosts,
        host_label: impl Into<String>,
        server_addr: SocketAddr,
        rows: u16,
        cols: u16,
        prediction: DisplayMode,
    ) -> Result<(Self, Vec<u8>), RuntimeError> {
        let sid = random_session_id();
        let (hs, first) = Handshaker::client(&keypair.private, sid)?;
        let core = ClientCore {
            hs: Some(hs),
            session: None,
            shell: ClientShell::new(rows as usize, cols as usize).with_prediction(prediction),
            known,
            host_label: host_label.into(),
            server_addr,
            rows,
            cols,
            // Advertise the user's actual terminal type so the remote shell and
            // programs render correctly (colours, key sequences), falling back to
            // a safe modern default when $TERM is unset.
            term: std::env::var("TERM")
                .ok()
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| "xterm-256color".to_string()),
            established: false,
            server_static: None,
            exited: None,
            pending_control: Vec::new(),
            open_shell_pending: false,
            open_shell_ticks: 0,
            need_ack: false,
            mux: StreamMux::new(true),
            stream_events: Vec::new(),
            want_shell: true,
            want_agent: false,
            remote_forwards: Vec::new(),
            remote_forward_ticks: 0,
            known_hosts_dirty: false,
            server_version: None,
        };
        Ok((core, first))
    }

    pub fn is_established(&self) -> bool {
        self.established
    }

    /// Disable the interactive-shell request (for forward-only sessions). Must
    /// be called before the handshake completes.
    pub fn set_want_shell(&mut self, want: bool) {
        self.want_shell = want;
    }

    /// Request SSH agent forwarding (`-A`). Must be set before the shell opens.
    pub fn set_want_agent(&mut self, want: bool) {
        self.want_agent = want;
    }

    pub fn exit_status(&self) -> Option<i32> {
        self.exited
    }

    pub fn server_static(&self) -> Option<&[u8]> {
        self.server_static.as_deref()
    }

    pub fn known_hosts(&self) -> &KnownHosts {
        &self.known
    }

    pub fn known_hosts_dirty(&self) -> bool {
        self.known_hosts_dirty
    }

    /// The server's announced version, if it sent one (pre-v0.5.2 servers don't).
    pub fn server_version(&self) -> Option<&str> {
        self.server_version.as_deref()
    }

    /// Queue locally-typed bytes.
    pub fn type_input(&mut self, bytes: &[u8]) {
        self.shell.type_input(bytes);
    }

    /// Queue a window resize to inform the server.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.rows = rows;
        self.cols = cols;
        self.pending_control.push(Frame::Control {
            data: ControlMsg::Resize { cols, rows }.encode(),
        });
    }

    /// Queue a `Bye` so the server tears the session down promptly (best-effort;
    /// the server's idle reap is the fallback if it's lost). Sent on clean
    /// completion of a one-shot task like a remote command or a file transfer.
    pub fn send_bye(&mut self) {
        self.pending_control.push(Frame::Control {
            data: ControlMsg::Bye.encode(),
        });
    }

    /// The authoritative screen.
    pub fn screen(&self) -> &Grid {
        self.shell.screen()
    }

    /// The screen as the user should see it (predictions painted on).
    pub fn overlay(&self) -> Grid {
        self.shell.overlay()
    }

    /// Handle an inbound datagram; returns datagrams to send.
    pub fn handle_packet(&mut self, buf: &[u8]) -> Result<Vec<Vec<u8>>, RuntimeError> {
        match transport::parse_packet(buf)? {
            Packet::Handshake { body, .. } => self.handle_handshake(body),
            Packet::Transport { .. } => {
                self.handle_transport(buf)?;
                Ok(Vec::new())
            }
        }
    }

    fn handle_handshake(&mut self, body: &[u8]) -> Result<Vec<Vec<u8>>, RuntimeError> {
        let hs = self.hs.as_mut().ok_or(RuntimeError::Handshake)?;
        let outcome = hs.read(body)?;
        let mut out = Vec::new();
        if let Some(reply) = outcome.reply {
            out.push(reply);
        }
        if outcome.finished {
            let server_static = self
                .hs
                .as_ref()
                .and_then(|h| h.remote_static())
                .ok_or(RuntimeError::Handshake)?;
            // TOFU known-hosts decision.
            match verify_server(&mut self.known, &self.host_label, &server_static) {
                Tofu::Mismatch => {
                    return Err(RuntimeError::HostKeyMismatch(self.host_label.clone()));
                }
                Tofu::New => self.known_hosts_dirty = true,
                Tofu::Match => {}
            }
            self.server_static = Some(server_static);
            let hs = self.hs.take().unwrap();
            self.session = Some(hs.into_session(Some(self.server_addr))?);
            self.established = true;
            // Request a shell with our geometry (unless this is a forward-only
            // session). Retransmitted every tick until the server starts sending
            // screen state (the request could be lost or reordered ahead of the
            // final handshake message).
            self.open_shell_pending = self.want_shell;
            out.extend(self.outgoing()?);
        }
        Ok(out)
    }

    fn handle_transport(&mut self, buf: &[u8]) -> Result<(), RuntimeError> {
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        // A transport packet that fails to authenticate/decrypt — forged, stale,
        // replayed, or arriving out of order while roaming — is dropped, never
        // fatal to the session.
        let Ok(frames) = session.open(self.server_addr, buf) else {
            return Ok(());
        };
        for frame in frames {
            match frame {
                Frame::StateDiff { seq, base, data } => {
                    self.shell.apply_state_diff(seq, base, &data);
                    // Re-ack on every diff (even stale ones) so a lost ack can't
                    // wedge the server into retransmitting an already-applied state.
                    self.need_ack = true;
                }
                Frame::Ack { seq } => self.shell.on_input_ack(seq),
                Frame::Control { data } => match ControlMsg::decode(&data) {
                    Ok(ControlMsg::Exit { status }) => self.exited = Some(status),
                    Ok(ControlMsg::ServerVersion(v)) => self.server_version = Some(v),
                    _ => {}
                },
                f @ (Frame::StreamOpen { .. }
                | Frame::StreamData { .. }
                | Frame::StreamAck { .. }
                | Frame::StreamClose { .. }
                | Frame::StreamReset { .. }) => self.mux.on_frame(f),
                _ => {} // Pong and others: liveness only
            }
        }
        self.stream_events.extend(self.mux.take_events());
        // Once the server is sending screen state, the shell is open.
        if self.shell.current_seq() > 0 {
            self.open_shell_pending = false;
        }
        Ok(())
    }

    /// Datagrams to send now: pending control + input + state ack.
    pub fn tick(&mut self) -> Vec<Vec<u8>> {
        self.outgoing().unwrap_or_default()
    }

    /// Whether there is anything worth sending right now (lets an event-driven
    /// driver avoid waking up just to send a redundant ack).
    pub fn has_outgoing(&self) -> bool {
        self.session.is_some()
            && (self.open_shell_pending
                || !self.pending_control.is_empty()
                || self.need_ack
                || self.shell.has_pending_input()
                || self.mux.has_traffic()
                || (!self.remote_forwards.is_empty()
                    && self.remote_forward_ticks < REMOTE_FORWARD_MAX_TICKS))
    }

    // --- reliable streams (port forwarding) ---

    /// Open a forwarded-connection stream toward `target` (e.g. "host:port").
    /// Returns the stream id.
    pub fn open_forward(&mut self, target: &str) -> u64 {
        self.mux
            .open(StreamKind::Forward, target.as_bytes().to_vec())
    }

    /// Open a file-transfer stream carrying `req`. Returns the stream id.
    pub fn open_xfer(&mut self, req: &proto::XferRequest) -> u64 {
        self.mux.open(StreamKind::FileTransfer, req.encode())
    }

    /// Open an exec stream running `cmd` on the server. Returns the stream id.
    pub fn open_exec(&mut self, cmd: &str) -> u64 {
        self.mux.open(StreamKind::Exec, cmd.as_bytes().to_vec())
    }

    /// Queue bytes to send on a stream.
    pub fn stream_write(&mut self, id: u64, data: &[u8]) {
        self.mux.write(id, data);
    }

    /// Read available contiguous bytes from a stream.
    pub fn stream_read(&mut self, id: u64) -> Vec<u8> {
        self.mux.read(id)
    }

    /// Close our send half of a stream.
    pub fn stream_close(&mut self, id: u64) {
        self.mux.close(id, 0);
    }

    /// Request a remote forward (`-R`): ask the server to listen on `bind_port`
    /// and tunnel accepted connections back to us for delivery to `target`. The
    /// request is retransmitted for a bounded window (no ack exists, so we resend
    /// to survive packet loss).
    pub fn request_remote_forward(&mut self, bind_port: u16, target: &str) {
        self.remote_forwards.push((bind_port, target.to_string()));
        self.remote_forward_ticks = 0;
    }

    /// Bytes written to a stream but not yet acked (for driver backpressure).
    pub fn stream_in_flight(&self, id: u64) -> u64 {
        self.mux.in_flight(id)
    }

    /// True once the peer closed its send half and we've read every byte.
    pub fn stream_recv_finished(&self, id: u64) -> bool {
        self.mux.is_recv_finished(id)
    }

    /// Drain stream lifecycle events (Opened/Readable/Closed/Reset).
    pub fn take_stream_events(&mut self) -> Vec<StreamEvent> {
        std::mem::take(&mut self.stream_events)
    }

    /// A keepalive datagram (Ping) to refresh NAT mappings and prove liveness
    /// while idle. `None` before the session is established.
    pub fn keepalive(&mut self) -> Option<Vec<u8>> {
        let session = self.session.as_mut()?;
        session.seal(&[Frame::Ping { stamp: 0 }]).ok()
    }

    fn outgoing(&mut self) -> Result<Vec<Vec<u8>>, RuntimeError> {
        let Some(session) = self.session.as_mut() else {
            return Ok(Vec::new());
        };
        let mut frames = Vec::new();
        if self.open_shell_pending {
            frames.push(Frame::Control {
                data: ControlMsg::OpenShell {
                    cols: self.cols,
                    rows: self.rows,
                    term: self.term.clone(),
                    agent: self.want_agent,
                }
                .encode(),
            });
            self.open_shell_ticks += 1;
            if self.open_shell_ticks >= OPEN_SHELL_MAX_TICKS {
                self.open_shell_pending = false;
            }
        }
        // Retransmit remote-forward (`-R`) requests for a bounded window.
        if !self.remote_forwards.is_empty() && self.remote_forward_ticks < REMOTE_FORWARD_MAX_TICKS
        {
            for (bind_port, target) in &self.remote_forwards {
                frames.push(Frame::Control {
                    data: ControlMsg::RemoteForward {
                        bind_port: *bind_port,
                        target: target.clone(),
                    }
                    .encode(),
                });
            }
            self.remote_forward_ticks += 1;
        }
        frames.append(&mut self.pending_control);
        frames.extend(self.shell.poll_frames());
        frames.extend(self.mux.poll_transmit());
        self.stream_events.extend(self.mux.take_events());
        if frames.is_empty() {
            return Ok(Vec::new());
        }
        let pkts = session.seal_many(&frames, transport::MAX_DATAGRAM_PLAINTEXT)?;
        self.need_ack = false; // only clear once the ack is actually sealed
        Ok(pkts)
    }
}

/// UDP driver around [`ClientCore`] for the `noissh` binary.
pub struct Client {
    core: ClientCore,
    socket: UdpSocket,
    server_addr: SocketAddr,
    /// Local SSH agent socket path (`$SSH_AUTH_SOCK`) to bridge forwarded agent
    /// streams to. `None` disables agent forwarding.
    agent_sock: Option<String>,
    /// Live agent-forwarding connections (client side), keyed by stream id.
    agent_conns:
        std::collections::HashMap<u64, crate::forward::ForwardConn<std::os::unix::net::UnixStream>>,
}

impl Client {
    /// Connect to `server_addr`, completing the handshake before returning.
    pub fn connect(
        keypair: &Keypair,
        known: KnownHosts,
        host_label: impl Into<String>,
        server_addr: SocketAddr,
        rows: u16,
        cols: u16,
        prediction: DisplayMode,
    ) -> Result<Self, RuntimeError> {
        Self::connect_with(
            keypair,
            known,
            host_label,
            server_addr,
            rows,
            cols,
            prediction,
            true,
            None,
            Duration::from_secs(5),
        )
    }

    /// Like [`Client::connect`], but `want_shell = false` opens a forward-only
    /// session (no interactive shell is requested).
    #[allow(clippy::too_many_arguments)]
    pub fn connect_with(
        keypair: &Keypair,
        known: KnownHosts,
        host_label: impl Into<String>,
        server_addr: SocketAddr,
        rows: u16,
        cols: u16,
        prediction: DisplayMode,
        want_shell: bool,
        agent_sock: Option<String>,
        connect_timeout: Duration,
    ) -> Result<Self, RuntimeError> {
        let bind: SocketAddr = if server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(Duration::from_millis(20)))?;
        let (mut core, first) = ClientCore::new(
            keypair,
            known,
            host_label,
            server_addr,
            rows,
            cols,
            prediction,
        )?;
        core.set_want_shell(want_shell);
        // Agent forwarding must be requested before the handshake completes, as
        // the OpenShell carrying the flag is sent the instant the session is up.
        core.set_want_agent(agent_sock.is_some());
        socket.send_to(&first, server_addr)?;
        let mut client = Client {
            core,
            socket,
            server_addr,
            agent_sock,
            agent_conns: std::collections::HashMap::new(),
        };
        // Drive the handshake to completion within the connect timeout.
        let deadline = std::time::Instant::now() + connect_timeout;
        while !client.core.is_established() {
            if std::time::Instant::now() > deadline {
                return Err(RuntimeError::Timeout);
            }
            client.pump_once()?;
        }
        Ok(client)
    }

    pub fn core(&self) -> &ClientCore {
        &self.core
    }

    pub fn core_mut(&mut self) -> &mut ClientCore {
        &mut self.core
    }

    /// Rebind the local socket to a new ephemeral port — simulates the client
    /// moving networks. The server must follow via session-id roaming.
    pub fn rebind(&mut self) -> Result<(), RuntimeError> {
        let bind: SocketAddr = if self.server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(Duration::from_millis(20)))?;
        self.socket = socket;
        Ok(())
    }

    /// Borrow the UDP socket (e.g. to register it with a poller).
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Whether agent forwarding is active (a local agent socket was provided).
    pub fn agent_enabled(&self) -> bool {
        self.agent_sock.is_some()
    }

    /// Borrowed fds of live agent-forwarding connections, for poll registration.
    pub fn agent_fds(&self) -> Vec<std::os::fd::BorrowedFd<'_>> {
        self.agent_conns.values().map(|c| c.as_fd()).collect()
    }

    /// Service agent forwarding: connect newly-opened Agent streams to the local
    /// agent socket, then move bytes both ways. Call once per loop iteration.
    pub fn pump_agent(&mut self) {
        use crate::forward::ForwardConn;
        const SEND_CAP: u64 = 512 * 1024;

        for ev in self.core.take_stream_events() {
            match ev {
                StreamEvent::Opened {
                    id,
                    kind: StreamKind::Agent,
                    ..
                } => {
                    match self
                        .agent_sock
                        .as_deref()
                        .and_then(|p| ForwardConn::connect_unix(p).ok())
                    {
                        Some(conn) => {
                            self.agent_conns.insert(id, conn);
                        }
                        // No local agent reachable: refuse the stream.
                        None => self.core.stream_close(id),
                    }
                }
                StreamEvent::Closed { id, .. } => {
                    if let Some(c) = self.agent_conns.get_mut(&id) {
                        c.mark_peer_closed();
                    }
                }
                StreamEvent::Reset { id } => {
                    self.agent_conns.remove(&id);
                }
                _ => {}
            }
        }

        let ids: Vec<u64> = self.agent_conns.keys().copied().collect();
        for id in ids {
            if let Some(c) = self.agent_conns.get_mut(&id) {
                c.flush();
                while c.out_len() < SEND_CAP as usize {
                    let d = self.core.stream_read(id);
                    if d.is_empty() {
                        break;
                    }
                    c.queue_to_tcp(&d);
                }
                if self.core.stream_in_flight(id) < SEND_CAP {
                    let d = c.read_tcp();
                    if !d.is_empty() {
                        self.core.stream_write(id, &d);
                    }
                }
                if c.needs_fin() {
                    self.core.stream_close(id);
                }
                if c.is_finished() {
                    self.agent_conns.remove(&id);
                }
            }
        }
    }

    /// Run port forwarding until interrupted.
    ///
    /// `local` are `-L` forwards `(local_port, "host:port")`: connections to
    /// `127.0.0.1:local_port` tunnel to `host:port` reachable from the server.
    /// `remote` are `-R` forwards `(remote_port, "host:port")`: the server
    /// listens on `remote_port` and tunnels accepted connections back here to be
    /// delivered to `host:port`.
    pub fn run_forwards(
        &mut self,
        local: &[(u16, String)],
        remote: &[(u16, String)],
        dynamic: &[(String, u16)],
    ) -> Result<(), RuntimeError> {
        use crate::forward::ForwardConn;
        use crate::socks::{Progress, SocksConn};
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::collections::HashMap;
        use std::net::TcpListener;
        use std::os::fd::AsFd;
        use std::time::Instant;

        // The loop waits via poll(); the UDP socket must be non-blocking so
        // recv drains to WouldBlock instead of blocking on each retransmit.
        self.socket.set_nonblocking(true)?;

        let mut listeners = Vec::new();
        for (port, target) in local {
            let l = TcpListener::bind(("127.0.0.1", *port))?;
            l.set_nonblocking(true)?;
            eprintln!("-L 127.0.0.1:{port} -> {target} (via {})", self.server_addr);
            listeners.push((l, target.clone()));
        }
        for (port, target) in remote {
            self.core.request_remote_forward(*port, target);
            eprintln!("-R {}:{port} -> {target}", self.server_addr.ip());
        }
        // SOCKS (`-D`) listeners: each accepts SOCKS clients and tunnels their
        // CONNECT targets dynamically.
        let mut socks_listeners = Vec::new();
        for (bind, port) in dynamic {
            let l = TcpListener::bind((bind.as_str(), *port))?;
            l.set_nonblocking(true)?;
            eprintln!("-D {bind}:{port} (SOCKS) -> via {}", self.server_addr);
            socks_listeners.push(l);
        }
        // SOCKS connections still negotiating (no forward stream opened yet).
        let mut pending_socks: Vec<SocksConn> = Vec::new();

        let mut conns: HashMap<u64, ForwardConn> = HashMap::new();
        let keepalive = Duration::from_secs(3);
        let mut next_keepalive = Instant::now() + keepalive;

        // Cap unacked per-stream bytes so a fast TCP producer can't grow the
        // mux send buffer without bound (the mux has receive-side flow control;
        // this is the matching send-side check).
        const SEND_CAP: u64 = 512 * 1024;

        loop {
            let timeout = if self.core.has_outgoing()
                || conns.values().any(|c| c.wants_write())
                || !pending_socks.is_empty()
            {
                Duration::from_millis(20)
            } else {
                next_keepalive
                    .saturating_duration_since(Instant::now())
                    .min(keepalive)
            };
            {
                let sock = self.socket.as_fd();
                let mut fds = vec![PollFd::new(sock, PollFlags::POLLIN)];
                for (l, _) in &listeners {
                    fds.push(PollFd::new(l.as_fd(), PollFlags::POLLIN));
                }
                for l in &socks_listeners {
                    fds.push(PollFd::new(l.as_fd(), PollFlags::POLLIN));
                }
                // Wait on each forwarded socket too (no busy-spin while connected).
                let conn_fds: Vec<_> = conns.values().map(|c| c.as_fd()).collect();
                for fd in &conn_fds {
                    fds.push(PollFd::new(*fd, PollFlags::POLLIN));
                }
                let socks_fds: Vec<_> = pending_socks.iter().map(|c| c.as_fd()).collect();
                for fd in &socks_fds {
                    fds.push(PollFd::new(*fd, PollFlags::POLLIN));
                }
                let ms = timeout.as_millis().min(u16::MAX as u128) as u16;
                let _ = poll(&mut fds, PollTimeout::from(ms));
            }

            // Accept new local (`-L`) connections and open a forward stream each.
            for (l, target) in &listeners {
                loop {
                    match l.accept() {
                        Ok((s, _)) => {
                            if let Ok(conn) = ForwardConn::new(s) {
                                let id = self.core.open_forward(target);
                                conns.insert(id, conn);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }

            // Accept new SOCKS (`-D`) connections; negotiation happens below.
            for l in &socks_listeners {
                loop {
                    match l.accept() {
                        Ok((s, _)) => {
                            if let Ok(sc) = SocksConn::new(s) {
                                pending_socks.push(sc);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }

            // Drive SOCKS negotiations; on CONNECT, open a forward and bridge.
            let mut still_pending = Vec::new();
            for sc in pending_socks.drain(..) {
                match sc.negotiate() {
                    (
                        Progress::Connected {
                            target,
                            socket,
                            leftover,
                        },
                        _,
                    ) => {
                        if let Ok(conn) = ForwardConn::new(socket) {
                            let id = self.core.open_forward(&target);
                            if !leftover.is_empty() {
                                self.core.stream_write(id, &leftover);
                            }
                            conns.insert(id, conn);
                        }
                    }
                    (Progress::Pending, Some(sc)) => still_pending.push(sc),
                    // Failed, or pending-without-handback: drop the connection.
                    _ => {}
                }
            }
            pending_socks = still_pending;

            // Inbound session packets.
            while self.recv_and_handle()? {}

            // React to stream events (incl. inbound `-R` opens → dial out).
            for ev in self.core.take_stream_events() {
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
                                conns.insert(id, conn);
                            }
                            None => self.core.stream_close(id),
                        }
                    }
                    // Session→TCP draining happens in the pump loop below, bounded
                    // by the out buffer; Readable just signals data is available.
                    StreamEvent::Readable { .. } => {}
                    // Peer closed its send half: keep flushing what we have, but
                    // stop expecting more session data. Reset aborts immediately.
                    StreamEvent::Closed { id, .. } => {
                        if let Some(c) = conns.get_mut(&id) {
                            c.mark_peer_closed();
                        }
                    }
                    StreamEvent::Reset { id } => {
                        conns.remove(&id);
                    }
                    _ => {}
                }
            }

            // Pump both directions, with caps, propagate half-close, reap.
            let ids: Vec<u64> = conns.keys().copied().collect();
            for id in ids {
                if let Some(c) = conns.get_mut(&id) {
                    // session → TCP, bounded so a stuck local peer backpressures
                    // the session (its mux recv window closes as we stop reading).
                    c.flush();
                    while c.out_len() < SEND_CAP as usize {
                        let d = self.core.stream_read(id);
                        if d.is_empty() {
                            break;
                        }
                        c.queue_to_tcp(&d);
                    }
                    // TCP → session, bounded by unacked in-flight bytes.
                    if self.core.stream_in_flight(id) < SEND_CAP {
                        let data = c.read_tcp();
                        if !data.is_empty() {
                            self.core.stream_write(id, &data);
                        }
                    }
                    if c.needs_fin() {
                        self.core.stream_close(id);
                    }
                    if c.is_finished() {
                        conns.remove(&id);
                    }
                }
            }

            self.flush()?;
            if Instant::now() >= next_keepalive {
                self.send_keepalive()?;
                next_keepalive = Instant::now() + keepalive;
            }
        }
    }

    /// Run a single file transfer to completion.
    ///
    /// For [`proto::XferRequest::Put`], `local` is the source file read and sent
    /// to the server's `path`. For [`proto::XferRequest::Get`], `local` is the
    /// destination file written from the bytes the server sends back. Returns an
    /// error if the server aborts the stream (e.g. missing/unwritable path).
    pub fn run_transfer(
        &mut self,
        req: &proto::XferRequest,
        local: &str,
    ) -> Result<(), RuntimeError> {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::os::fd::AsFd;
        use std::time::Instant;

        // poll()-driven loop, so the UDP socket must be non-blocking.
        self.socket.set_nonblocking(true)?;

        const SEND_CAP: u64 = 512 * 1024;
        const CHUNK: usize = 64 * 1024;

        let id = self.core.open_xfer(req);
        let mut source = match req {
            proto::XferRequest::Put { .. } => Some(crate::xfer::FileSource::open(local)?),
            proto::XferRequest::Get { .. } => None,
        };
        let mut sink = match req {
            proto::XferRequest::Get { .. } => Some(crate::xfer::FileSink::create(local)?),
            proto::XferRequest::Put { .. } => None,
        };
        let mut sent_fin = false;

        // Progress reporting (TTY-only; quiet in scripts/pipelines). On upload we
        // know the total from the request; on download the size is unknown, so we
        // report the running count.
        let (label, total) = match req {
            proto::XferRequest::Put { size, .. } => (format!("↑ {local}"), Some(*size)),
            proto::XferRequest::Get { path } => (format!("↓ {path}"), None),
        };
        let mut progress = crate::xfer::Progress::new(label, total);

        let keepalive = Duration::from_secs(3);
        let mut next_keepalive = Instant::now() + keepalive;

        loop {
            let timeout = if self.core.has_outgoing() {
                Duration::from_millis(20)
            } else {
                next_keepalive
                    .saturating_duration_since(Instant::now())
                    .min(keepalive)
            };
            {
                let sock = self.socket.as_fd();
                let mut fds = [PollFd::new(sock, PollFlags::POLLIN)];
                let ms = timeout.as_millis().min(u16::MAX as u128) as u16;
                let _ = poll(&mut fds, PollTimeout::from(ms));
            }

            while self.recv_and_handle()? {}

            // The server aborts the stream on a path error.
            for ev in self.core.take_stream_events() {
                if let StreamEvent::Reset { id: eid } = ev
                    && eid == id
                {
                    return Err(RuntimeError::Transfer(
                        "remote rejected the transfer (no such file or permission denied)".into(),
                    ));
                }
            }

            // Upload: stream the local file, then close to signal EOF.
            if let Some(src) = source.as_mut() {
                if !sent_fin && self.core.stream_in_flight(id) < SEND_CAP {
                    let chunk = src.read_chunk(CHUNK)?;
                    if chunk.is_empty() {
                        self.core.stream_close(id);
                        sent_fin = true;
                    } else {
                        let n = chunk.len() as u64;
                        self.core.stream_write(id, &chunk);
                        progress.add(n);
                    }
                }
                // Done once the server acknowledges by closing its half back.
                if sent_fin && self.core.stream_recv_finished(id) {
                    self.flush()?;
                    self.say_bye();
                    progress.finish();
                    return Ok(());
                }
            }

            // Download: drain stream bytes into the local file.
            if let Some(snk) = sink.as_mut() {
                loop {
                    let d = self.core.stream_read(id);
                    if d.is_empty() {
                        break;
                    }
                    progress.add(d.len() as u64);
                    snk.write(&d)?;
                }
                if self.core.stream_recv_finished(id) {
                    self.core.stream_close(id);
                    self.flush()?;
                    self.say_bye();
                    progress.finish();
                    // Atomically move the completed download into place. (On an
                    // error return below, the sink is dropped and the temp file
                    // is discarded — the destination is never clobbered.)
                    sink.take().unwrap().finalize()?;
                    return Ok(());
                }
            }

            self.flush()?;
            if Instant::now() >= next_keepalive {
                self.send_keepalive()?;
                next_keepalive = Instant::now() + keepalive;
            }
        }
    }

    /// Run a non-interactive remote command to completion, streaming its stdout
    /// and stderr to ours and returning its exit code. stdin is forwarded from
    /// our stdin until EOF.
    pub fn run_exec(&mut self, cmd: &str) -> Result<i32, RuntimeError> {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::io::Read;
        use std::os::fd::AsFd;
        use std::time::Instant;

        self.socket.set_nonblocking(true)?;
        let stdin = std::io::stdin();
        set_fd_nonblocking(stdin.as_fd());

        let e = self.core.open_exec(cmd);
        let mut err_id: Option<u64> = None;
        let mut exit_code: Option<i32> = None;
        let mut stdin_eof = false;

        let keepalive = Duration::from_secs(3);
        let mut next_keepalive = Instant::now() + keepalive;
        let mut inbuf = [0u8; 16384];

        loop {
            let timeout = if self.core.has_outgoing() {
                Duration::from_millis(20)
            } else {
                next_keepalive
                    .saturating_duration_since(Instant::now())
                    .min(keepalive)
            };
            {
                let sock = self.socket.as_fd();
                let inp = stdin.as_fd();
                let mut fds = vec![PollFd::new(sock, PollFlags::POLLIN)];
                if !stdin_eof {
                    fds.push(PollFd::new(inp, PollFlags::POLLIN));
                }
                let ms = timeout.as_millis().min(u16::MAX as u128) as u16;
                let _ = poll(&mut fds, PollTimeout::from(ms));
            }

            while self.recv_and_handle()? {}

            for ev in self.core.take_stream_events() {
                match ev {
                    // The server opens one Exec stream back to us: it's stderr.
                    StreamEvent::Opened {
                        id,
                        kind: StreamKind::Exec,
                        ..
                    } => err_id = Some(id),
                    // The server reset our exec stream: it couldn't run the
                    // command (spawn failure, or refused under a privsep drop).
                    StreamEvent::Reset { id } if id == e => {
                        return Err(RuntimeError::Exec(
                            "remote refused or could not start the command".into(),
                        ));
                    }
                    StreamEvent::Closed { id, status } if id == e => exit_code = Some(status),
                    _ => {}
                }
            }

            // command stdout / stderr → our stdout / stderr (blocking writes that
            // tolerate a non-blocking TTY, so no bytes are dropped).
            let out = self.core.stream_read(e);
            if !out.is_empty() {
                crate::tty::write_all_fd(std::io::stdout().as_fd(), &out)?;
            }
            if let Some(s) = err_id {
                let er = self.core.stream_read(s);
                if !er.is_empty() {
                    crate::tty::write_all_fd(std::io::stderr().as_fd(), &er)?;
                }
            }

            // our stdin → command stdin, until EOF.
            if !stdin_eof {
                match stdin.lock().read(&mut inbuf) {
                    Ok(0) => {
                        stdin_eof = true;
                        self.core.stream_close(e); // EOF to the command's stdin
                    }
                    Ok(n) => self.core.stream_write(e, &inbuf[..n]),
                    Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        stdin_eof = true;
                        self.core.stream_close(e);
                    }
                }
            }

            self.flush()?;
            if Instant::now() >= next_keepalive {
                self.send_keepalive()?;
                next_keepalive = Instant::now() + keepalive;
            }

            // Done once the command exited and all of stdout/stderr is drained.
            let stdout_done = self.core.stream_recv_finished(e);
            let stderr_done = err_id
                .map(|s| self.core.stream_recv_finished(s))
                .unwrap_or(true);
            if let Some(code) = exit_code
                && stdout_done
                && stderr_done
            {
                self.say_bye();
                return Ok(code);
            }
        }
    }

    /// Best-effort: tell the server we're done so a one-shot tears down promptly
    /// (the server's idle reap is the fallback if the packet is lost). Spends a
    /// few milliseconds pushing it out.
    fn say_bye(&mut self) {
        self.core.send_bye();
        for _ in 0..6 {
            let _ = self.flush();
            let _ = self.recv_and_handle();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Send a datagram. A send failure is NEVER fatal: a full send buffer
    /// (EWOULDBLOCK) or a transient network outage (no route / network down,
    /// e.g. while roaming between Wi-Fi and cellular) just drops the datagram —
    /// the reliability/latest-wins layers retransmit, and the session resumes
    /// (and roams to the new address) once connectivity returns.
    fn send_dgram(&self, pkt: &[u8]) -> Result<(), RuntimeError> {
        let _ = self.socket.send_to(pkt, self.server_addr);
        Ok(())
    }

    /// Drain a single ready datagram (non-blocking) and send any replies.
    /// Returns true if a datagram was processed. Receive errors are treated as
    /// "nothing right now" (transient) rather than fatal, so a network outage
    /// doesn't tear the session down.
    pub fn recv_and_handle(&mut self) -> Result<bool, RuntimeError> {
        let mut buf = [0u8; 65536];
        match self.socket.recv_from(&mut buf) {
            Ok((n, _src)) => {
                // `?` so a handshake-time failure (e.g. HOST KEY MISMATCH) still
                // aborts; transport-layer junk is dropped inside handle_packet.
                for pkt in self.core.handle_packet(&buf[..n])? {
                    self.send_dgram(&pkt)?;
                }
                Ok(true)
            }
            // Any receive error (would-block, timed out, or a transient
            // network-down/unreachable during roaming) means "no data now".
            Err(_) => Ok(false),
        }
    }

    /// Flush any pending outgoing frames (input, acks, control).
    pub fn flush(&mut self) -> Result<(), RuntimeError> {
        for pkt in self.core.tick() {
            self.send_dgram(&pkt)?;
        }
        Ok(())
    }

    /// Send a keepalive datagram (refreshes NAT, proves liveness while idle).
    pub fn send_keepalive(&mut self) -> Result<(), RuntimeError> {
        if let Some(pkt) = self.core.keepalive() {
            self.send_dgram(&pkt)?;
        }
        Ok(())
    }

    /// One I/O iteration: receive (if any) and flush outgoing frames. Used by
    /// the handshake drive loop and tests.
    pub fn pump_once(&mut self) -> Result<(), RuntimeError> {
        self.recv_and_handle()?;
        self.flush()
    }

    /// Pump the established session for up to `timeout`, returning as soon as the
    /// server announces its version (or the deadline passes). Lets a direct
    /// connection learn whether a standing daemon is outdated before entering the
    /// session. Returns `None` for a pre-v0.5.2 server (which never announces).
    pub fn wait_for_server_version(&mut self, timeout: Duration) -> Option<String> {
        let deadline = std::time::Instant::now() + timeout;
        while self.core.server_version().is_none() {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            // Block for at most a short slice per iteration, so this can never
            // become a busy-spin regardless of the socket's blocking mode. (The
            // caller enters the interactive loop next, which reconfigures the
            // socket, so we needn't restore the timeout.)
            let _ = self
                .socket
                .set_read_timeout(Some(remaining.min(Duration::from_millis(20))));
            if self.pump_once().is_err() {
                break;
            }
        }
        self.core.server_version().map(str::to_string)
    }
}

/// Put a file descriptor into non-blocking mode (safe `nix` fcntl).
fn set_fd_nonblocking<Fd: std::os::fd::AsFd>(fd: Fd) {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    if let Ok(cur) = fcntl(fd.as_fd(), FcntlArg::F_GETFL) {
        let mut flags = OFlag::from_bits_truncate(cur);
        flags.insert(OFlag::O_NONBLOCK);
        let _ = fcntl(fd.as_fd(), FcntlArg::F_SETFL(flags));
    }
}
