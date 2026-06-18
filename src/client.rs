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
    /// Pending remote-forward (`-R`) requests, retransmitted for a bounded
    /// number of ticks (there is no ack, so we resend to survive packet loss).
    remote_forwards: Vec<(u16, String)>,
    remote_forward_ticks: u32,
    known_hosts_dirty: bool,
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
            term: "xterm-256color".to_string(),
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
            remote_forwards: Vec::new(),
            remote_forward_ticks: 0,
            known_hosts_dirty: false,
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
        let frames = session.open(self.server_addr, buf)?;
        for frame in frames {
            match frame {
                Frame::StateDiff { seq, base, data } => {
                    self.shell.apply_state_diff(seq, base, &data);
                    // Re-ack on every diff (even stale ones) so a lost ack can't
                    // wedge the server into retransmitting an already-applied state.
                    self.need_ack = true;
                }
                Frame::Ack { seq } => self.shell.on_input_ack(seq),
                Frame::Control { data } => {
                    if let Ok(ControlMsg::Exit { status }) = ControlMsg::decode(&data) {
                        self.exited = Some(status);
                    }
                }
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
        let pkt = session.seal(&frames)?;
        self.need_ack = false; // only clear once the ack is actually sealed
        Ok(vec![pkt])
    }
}

/// UDP driver around [`ClientCore`] for the `noissh` binary.
pub struct Client {
    core: ClientCore,
    socket: UdpSocket,
    server_addr: SocketAddr,
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
        socket.send_to(&first, server_addr)?;
        let mut client = Client {
            core,
            socket,
            server_addr,
        };
        // Drive the handshake to completion.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
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
    ) -> Result<(), RuntimeError> {
        use crate::forward::ForwardConn;
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

        let mut conns: HashMap<u64, ForwardConn> = HashMap::new();
        let keepalive = Duration::from_secs(3);
        let mut next_keepalive = Instant::now() + keepalive;

        // Cap unacked per-stream bytes so a fast TCP producer can't grow the
        // mux send buffer without bound (the mux has receive-side flow control;
        // this is the matching send-side check).
        const SEND_CAP: u64 = 512 * 1024;

        loop {
            let timeout = if self.core.has_outgoing() || conns.values().any(|c| c.wants_write()) {
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
                // Wait on each forwarded socket too (no busy-spin while connected).
                let conn_fds: Vec<_> = conns.values().map(|c| c.as_fd()).collect();
                for fd in &conn_fds {
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
                    StreamEvent::Readable { id } => {
                        if let Some(c) = conns.get_mut(&id) {
                            loop {
                                let d = self.core.stream_read(id);
                                if d.is_empty() {
                                    break;
                                }
                                c.queue_to_tcp(&d);
                            }
                        }
                    }
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

            // TCP → session, flush, propagate half-close, and reap when finished.
            let ids: Vec<u64> = conns.keys().copied().collect();
            for id in ids {
                if let Some(c) = conns.get_mut(&id) {
                    if self.core.stream_in_flight(id) < SEND_CAP {
                        let data = c.read_tcp();
                        if !data.is_empty() {
                            self.core.stream_write(id, &data);
                        }
                    }
                    c.flush();
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

    /// Drain a single ready datagram (non-blocking) and send any replies.
    /// Returns true if a datagram was processed.
    pub fn recv_and_handle(&mut self) -> Result<bool, RuntimeError> {
        let mut buf = [0u8; 65536];
        match self.socket.recv_from(&mut buf) {
            Ok((n, _src)) => {
                for pkt in self.core.handle_packet(&buf[..n])? {
                    self.socket.send_to(&pkt, self.server_addr)?;
                }
                Ok(true)
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Flush any pending outgoing frames (input, acks, control).
    pub fn flush(&mut self) -> Result<(), RuntimeError> {
        for pkt in self.core.tick() {
            self.socket.send_to(&pkt, self.server_addr)?;
        }
        Ok(())
    }

    /// Send a keepalive datagram (refreshes NAT, proves liveness while idle).
    pub fn send_keepalive(&mut self) -> Result<(), RuntimeError> {
        if let Some(pkt) = self.core.keepalive() {
            self.socket.send_to(&pkt, self.server_addr)?;
        }
        Ok(())
    }

    /// One I/O iteration: receive (if any) and flush outgoing frames. Used by
    /// the handshake drive loop and tests.
    pub fn pump_once(&mut self) -> Result<(), RuntimeError> {
        self.recv_and_handle()?;
        self.flush()
    }
}
