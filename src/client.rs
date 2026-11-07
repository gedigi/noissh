//! Client runtime: a socket-free [`ClientCore`] (drivable by in-memory tests)
//! plus a [`Client`] UDP driver used by the `noissh` binary.
//!
//! The session is one QUIC connection (`quinn-proto`, with the Noise handshake
//! from `noise-quic`): the shell's screen state arrives as datagrams (or on the
//! control stream when too large), keystrokes and control messages go on the
//! control stream, and every forward, exec and file transfer is its own stream.

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use auth::{KnownHosts, Tofu};
use bytes::BytesMut;
use noise_core::Keypair;
use predict::DisplayMode;
use proto::{ClientShell, ControlMsg, verify_server};
use quinn_proto::{
    ClientConfig, Connection, ConnectionError, ConnectionHandle, DatagramEvent, Endpoint, Event,
    VarInt,
};
use term::Grid;
use wire::{Frame, StreamKind};

use crate::RuntimeError;
pub use crate::quic::StreamEvent;
use crate::quic::{self, Streams};

/// The server key check run inside the handshake (TOFU against known_hosts).
struct Trust {
    known: KnownHosts,
    label: String,
    new_key: bool,
    mismatch: bool,
}

/// Socket-free client logic: consumes raw datagrams, produces raw datagrams.
pub struct ClientCore {
    endpoint: Endpoint,
    config: ClientConfig,
    conn: Option<(ConnectionHandle, Connection)>,
    streams: Streams,
    shell: ClientShell,
    trust: Arc<Mutex<Trust>>,
    server_addr: SocketAddr,
    rows: u16,
    cols: u16,
    term: String,
    established: bool,
    /// The current connection has completed its handshake.
    connected: bool,
    server_static: Option<Vec<u8>>,
    exited: Option<i32>,
    /// Why the connection ended, once it has (the driver may reconnect).
    lost: Option<String>,
    /// A handshake-time failure to report to the caller.
    failure: Option<RuntimeError>,
    want_shell: bool,
    want_agent: bool,
    /// Remote-forward (`-R`) requests, sent on every (re)connection.
    remote_forwards: Vec<(u16, String)>,
    /// The server's version, from its first control message.
    server_version: Option<String>,
    /// Datagrams produced while handling input, returned by the next call.
    out: Vec<Vec<u8>>,
}

/// Validate a server-supplied version string before storing it — it is later
/// shown in the upgrade prompt, so require a short, version-ish token (leading
/// digit, version characters only) to keep a hostile server from injecting
/// control sequences. Mirrors the SSH-bootstrap version check.
fn sane_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.as_bytes()[0].is_ascii_digit()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

impl ClientCore {
    /// Begin a connection. Returns the core and the first datagram to send.
    pub fn new(
        keypair: &Keypair,
        known: KnownHosts,
        host_label: impl Into<String>,
        server_addr: SocketAddr,
        rows: u16,
        cols: u16,
        prediction: DisplayMode,
    ) -> Result<(Self, Vec<u8>), RuntimeError> {
        Self::with_idle_timeout(
            keypair,
            known,
            host_label,
            server_addr,
            rows,
            cols,
            prediction,
            quic::IDLE_TIMEOUT,
        )
    }

    /// [`ClientCore::new`] with a custom idle timeout (tests).
    #[allow(clippy::too_many_arguments)]
    pub fn with_idle_timeout(
        keypair: &Keypair,
        known: KnownHosts,
        host_label: impl Into<String>,
        server_addr: SocketAddr,
        rows: u16,
        cols: u16,
        prediction: DisplayMode,
        idle: Duration,
    ) -> Result<(Self, Vec<u8>), RuntimeError> {
        let private = quic::key32(&keypair.private).ok_or(RuntimeError::BadKeyFile)?;
        let trust = Arc::new(Mutex::new(Trust {
            known,
            label: host_label.into(),
            new_key: false,
            mismatch: false,
        }));
        let check = {
            let trust = trust.clone();
            Arc::new(move |key: &[u8; 32]| {
                let mut t = trust.lock().unwrap_or_else(|e| e.into_inner());
                let Trust {
                    known,
                    label,
                    new_key,
                    mismatch,
                } = &mut *t;
                match verify_server(known, label, key) {
                    Tofu::Mismatch => {
                        *mismatch = true;
                        false
                    }
                    Tofu::New => {
                        *new_key = true;
                        true
                    }
                    Tofu::Match => true,
                }
            })
        };
        let mut config = ClientConfig::new(Arc::new(noise_quic::ClientConfig::new(private, check)));
        config.version(noise_quic::VERSION);
        config.transport_config(quic::transport_config(idle, Some(quic::KEEP_ALIVE)));
        let mut core = ClientCore {
            endpoint: Endpoint::new(quic::endpoint_config(), None, true, None),
            config,
            conn: None,
            streams: Streams::new(false),
            shell: ClientShell::new(rows as usize, cols as usize).with_prediction(prediction),
            trust,
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
            connected: false,
            server_static: None,
            exited: None,
            lost: None,
            failure: None,
            want_shell: true,
            want_agent: false,
            remote_forwards: Vec::new(),
            server_version: None,
            out: Vec::new(),
        };
        core.start_connection()?;
        let mut first = core.transmits();
        let head = if first.is_empty() {
            Vec::new()
        } else {
            first.remove(0)
        };
        core.out = first;
        Ok((core, head))
    }

    fn start_connection(&mut self) -> Result<(), RuntimeError> {
        let (ch, conn) = self
            .endpoint
            .connect(
                Instant::now(),
                self.config.clone(),
                self.server_addr,
                "noissh",
            )
            .map_err(|e| RuntimeError::Quic(e.to_string()))?;
        self.conn = Some((ch, conn));
        self.streams = Streams::new(false);
        self.connected = false;
        self.lost = None;
        Ok(())
    }

    /// Start a new connection to the same server after the previous one was
    /// lost (sleep, a long outage). The screen is kept; the server reattaches
    /// the running shell and sends it in full. Returns the datagrams to send.
    pub fn reconnect(&mut self) -> Result<Vec<Vec<u8>>, RuntimeError> {
        self.start_connection()?;
        Ok(self.transmits())
    }

    /// Whether the session has been established (the first handshake
    /// completed and the server key was accepted).
    pub fn is_established(&self) -> bool {
        self.established
    }

    /// Whether the current connection is up (false while reconnecting).
    pub fn is_connected(&self) -> bool {
        self.connected && self.lost.is_none()
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

    /// The known-hosts store, including a key pinned by this connection.
    pub fn known_hosts(&self) -> KnownHosts {
        self.trust
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .known
            .clone()
    }

    pub fn known_hosts_dirty(&self) -> bool {
        self.trust.lock().unwrap_or_else(|e| e.into_inner()).new_key
    }

    /// The server's announced version.
    pub fn server_version(&self) -> Option<&str> {
        self.server_version.as_deref()
    }

    /// Why the connection was lost, if it was.
    pub fn lost_reason(&self) -> Option<&str> {
        self.lost.as_deref()
    }

    fn conn(&mut self) -> Option<&mut Connection> {
        self.conn.as_mut().map(|(_, c)| c)
    }

    /// Send a frame on the control stream (queued until it exists).
    fn send_frame(&mut self, f: Frame) {
        if let Some((_, conn)) = self.conn.as_mut() {
            self.streams.send_frame(conn, &f);
        }
    }

    /// Queue locally-typed bytes: predicted at once, sent on the control
    /// stream (reliable, ordered, highest priority).
    pub fn type_input(&mut self, bytes: &[u8]) {
        self.shell.predict_input(bytes);
        if self.is_connected() {
            self.send_frame(Frame::Input {
                data: bytes.to_vec(),
            });
        }
    }

    /// Queue a window resize to inform the server.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.rows = rows;
        self.cols = cols;
        if self.connected {
            self.send_frame(Frame::Control {
                data: ControlMsg::Resize { cols, rows }.encode(),
            });
        }
    }

    /// End the session: close the connection, which tells the server to tear
    /// the session down now (rather than keep the shell for a reattach).
    pub fn send_bye(&mut self) {
        if let Some((_, conn)) = self.conn.as_mut() {
            conn.close(Instant::now(), VarInt::from_u32(0), "bye".into());
        }
    }

    /// The authoritative screen.
    pub fn screen(&self) -> &Grid {
        self.shell.screen()
    }

    /// The screen as the user should see it (predictions painted on).
    pub fn overlay(&self) -> Grid {
        self.shell.overlay()
    }

    /// Handle an inbound datagram; returns datagrams to send while the
    /// handshake is in progress. Once established, events, application data
    /// and replies are processed by [`ClientCore::tick`], which the driver
    /// calls after draining the socket (once per batch of datagrams). A
    /// handshake failure (host key mismatch, rejected client key) is an error;
    /// a lost connection after that is reported by [`ClientCore::lost_reason`].
    pub fn handle_packet(&mut self, buf: &[u8]) -> Result<Vec<Vec<u8>>, RuntimeError> {
        let now = Instant::now();
        let mut resp = Vec::new();
        match self.endpoint.handle(
            now,
            self.server_addr,
            None,
            None,
            BytesMut::from(buf),
            &mut resp,
        ) {
            Some(DatagramEvent::ConnectionEvent(ch, ev)) => {
                if let Some((h, conn)) = self.conn.as_mut()
                    && *h == ch
                {
                    conn.handle_event(ev);
                }
            }
            Some(DatagramEvent::Response(t)) => self.out.push(resp[..t.size].to_vec()),
            _ => {}
        }
        if self.established {
            // The rest happens once per batch of datagrams, in `tick`.
            return Ok(Vec::new());
        }
        self.process(now);
        if let Some(e) = self.failure.take() {
            return Err(e);
        }
        Ok(self.transmits())
    }

    /// Run timers and the application logic; returns datagrams to send.
    pub fn tick(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        if let Some((_, conn)) = self.conn.as_mut()
            && conn.poll_timeout().is_some_and(|t| t <= now)
        {
            conn.handle_timeout(now);
        }
        self.process(now);
        self.transmits()
    }

    /// A handshake failure recorded by [`ClientCore::tick`], if any.
    pub fn take_failure(&mut self) -> Option<RuntimeError> {
        self.failure.take()
    }

    /// How long until the connection's next timer (loss recovery, delayed
    /// ack, keep-alive, idle timeout).
    pub fn timeout(&mut self) -> Option<Duration> {
        let t = self.conn()?.poll_timeout()?;
        Some(t.saturating_duration_since(Instant::now()))
    }

    /// Whether data is queued that QUIC hasn't taken yet (the driver keeps
    /// polling briefly in case it is waiting on local sockets only).
    pub fn has_outgoing(&self) -> bool {
        false
    }

    fn transmits(&mut self) -> Vec<Vec<u8>> {
        let mut out = std::mem::take(&mut self.out);
        if let Some((_, conn)) = self.conn.as_mut() {
            out.extend(
                quic::drain_transmits(conn, Instant::now())
                    .into_iter()
                    .map(|(_, d)| d),
            );
        }
        out
    }

    fn process(&mut self, _now: Instant) {
        let Some((ch, conn)) = self.conn.as_mut() else {
            return;
        };
        while let Some(ev) = conn.poll_endpoint_events() {
            if let Some(cev) = self.endpoint.handle_event(*ch, ev) {
                conn.handle_event(cev);
            }
        }
        let mut became_connected = false;
        while let Some(ev) = conn.poll() {
            match ev {
                Event::Connected => became_connected = true,
                Event::ConnectionLost { reason } => {
                    self.streams.fail_all();
                    let (mismatch, label) = {
                        let t = self.trust.lock().unwrap_or_else(|e| e.into_inner());
                        (t.mismatch, t.label.clone())
                    };
                    if mismatch {
                        self.failure = Some(RuntimeError::HostKeyMismatch(label));
                    } else if !self.established {
                        self.failure = Some(match reason {
                            ConnectionError::TimedOut => RuntimeError::Timeout,
                            _ => RuntimeError::Handshake,
                        });
                    }
                    self.lost = Some(reason.to_string());
                }
                Event::Stream(se) => self.streams.on_event(conn, se),
                Event::DatagramReceived => self.streams.read_datagrams(conn),
                _ => {}
            }
        }
        if became_connected {
            self.connected = true;
            if self.server_static.is_none() {
                self.server_static = quic::peer_key(conn).map(|k| k.to_vec());
            }
            self.established = true;
            self.streams.open_control(conn);
            if self.want_shell {
                let open = ControlMsg::OpenShell {
                    cols: self.cols,
                    rows: self.rows,
                    term: self.term.clone(),
                    agent: self.want_agent,
                };
                self.streams.send_frame(
                    conn,
                    &Frame::Control {
                        data: open.encode(),
                    },
                );
            }
            for (bind_port, target) in &self.remote_forwards {
                let msg = ControlMsg::RemoteForward {
                    bind_port: *bind_port,
                    target: target.clone(),
                };
                self.streams
                    .send_frame(conn, &Frame::Control { data: msg.encode() });
            }
        }
        for frame in self.streams.take_frames() {
            match frame {
                Frame::StateDiff { seq, base, data } => {
                    self.shell.apply_state_diff(seq, base, &data);
                }
                Frame::Control { data } => match ControlMsg::decode(&data) {
                    Ok(ControlMsg::Exit { status }) => self.exited = Some(status),
                    Ok(ControlMsg::ServerVersion(v))
                        if self.server_version.is_none() && sane_version(&v) =>
                    {
                        self.server_version = Some(v)
                    }
                    Ok(ControlMsg::ExecExit { id, status }) => {
                        self.streams.push_event(StreamEvent::Exited { id, status });
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        // Screen-state ack (after received diffs) on the control stream.
        if let Some(ack) = self.shell.poll_ack() {
            self.streams.send_frame(conn, &ack);
        }
        self.streams.flush(conn);
    }

    // --- streams ---

    /// Open a forwarded-connection stream toward `target` (e.g. "host:port").
    /// Returns the stream id.
    pub fn open_forward(&mut self, target: &str) -> u64 {
        let conn = self.conn.as_mut().map(|(_, c)| c);
        self.streams
            .open(conn, StreamKind::Forward, target.as_bytes())
    }

    /// Open a file-transfer stream carrying `req`. Returns the stream id.
    pub fn open_xfer(&mut self, req: &proto::XferRequest) -> u64 {
        let conn = self.conn.as_mut().map(|(_, c)| c);
        self.streams
            .open(conn, StreamKind::FileTransfer, &req.encode())
    }

    /// Open an exec stream running `cmd` on the server. Returns the stream id.
    pub fn open_exec(&mut self, cmd: &str) -> u64 {
        let conn = self.conn.as_mut().map(|(_, c)| c);
        self.streams.open(conn, StreamKind::Exec, cmd.as_bytes())
    }

    /// Queue bytes to send on a stream.
    pub fn stream_write(&mut self, id: u64, data: &[u8]) {
        let conn = self.conn.as_mut().map(|(_, c)| c);
        self.streams.write(conn, id, data);
    }

    /// Read available bytes from a stream.
    pub fn stream_read(&mut self, id: u64) -> Vec<u8> {
        let conn = self.conn.as_mut().map(|(_, c)| c);
        self.streams.read(conn, id)
    }

    /// Close our send half of a stream.
    pub fn stream_close(&mut self, id: u64) {
        let conn = self.conn.as_mut().map(|(_, c)| c);
        self.streams.close(conn, id);
    }

    /// Abort a stream.
    pub fn stream_reset(&mut self, id: u64) {
        let conn = self.conn.as_mut().map(|(_, c)| c);
        self.streams.reset(conn, id);
    }

    /// Request a remote forward (`-R`): ask the server to listen on
    /// `bind_port` and tunnel accepted connections back to us for delivery to
    /// `target`.
    pub fn request_remote_forward(&mut self, bind_port: u16, target: &str) {
        self.remote_forwards.push((bind_port, target.to_string()));
        if self.connected {
            self.send_frame(Frame::Control {
                data: ControlMsg::RemoteForward {
                    bind_port,
                    target: target.to_string(),
                }
                .encode(),
            });
        }
    }

    /// Bytes written to a stream but not yet taken by QUIC (backpressure).
    pub fn stream_in_flight(&self, id: u64) -> u64 {
        self.streams.in_flight(id)
    }

    /// True once the peer closed its send half and we've read every byte.
    pub fn stream_recv_finished(&self, id: u64) -> bool {
        self.streams.recv_finished(id)
    }

    /// Drain stream lifecycle events.
    pub fn take_stream_events(&mut self) -> Vec<StreamEvent> {
        self.streams.take_events()
    }

    /// Probe the path now (a PING), e.g. after moving to a new local address
    /// or while the link looks stale. Returns the datagrams to send.
    pub fn keepalive(&mut self) -> Vec<Vec<u8>> {
        if let Some(conn) = self.conn() {
            conn.ping();
        }
        self.transmits()
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
    /// Receive buffer, reused for every datagram.
    rbuf: Vec<u8>,
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
        let _ = socket.send_to(&first, server_addr);
        let mut client = Client {
            core,
            socket,
            server_addr,
            agent_sock,
            agent_conns: std::collections::HashMap::new(),
            rbuf: vec![0u8; 65536],
        };
        // Drive the handshake to completion within the connect timeout.
        let deadline = std::time::Instant::now() + connect_timeout;
        while !client.core.is_established() {
            if std::time::Instant::now() > deadline {
                return Err(RuntimeError::Timeout);
            }
            client.pump_once()?;
        }
        client.socket.set_nonblocking(true)?;
        Ok(client)
    }

    pub fn core(&self) -> &ClientCore {
        &self.core
    }

    pub fn core_mut(&mut self) -> &mut ClientCore {
        &mut self.core
    }

    /// Rebind the local socket to a new ephemeral port — simulates the client
    /// moving networks. The server follows through QUIC connection migration.
    pub fn rebind(&mut self) -> Result<(), RuntimeError> {
        let bind: SocketAddr = if self.server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(bind)?;
        socket.set_nonblocking(true)?;
        self.socket = socket;
        // Announce the new address at once: the server migrates the
        // connection to whatever address its latest packet came from, and an
        // idle client would otherwise stay silent until its next keep-alive.
        self.send_keepalive()
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
                        None => self.core.stream_reset(id),
                    }
                }
                StreamEvent::Closed { id } => {
                    if let Some(c) = self.agent_conns.get_mut(&id) {
                        c.mark_peer_closed();
                    }
                }
                StreamEvent::Reset { id } => {
                    self.agent_conns.remove(&id);
                    self.core.stream_reset(id);
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
        use nix::poll::{PollFd, PollFlags, poll};
        use std::os::fd::AsFd;

        // The loop waits via poll(); the UDP socket must be non-blocking so
        // recv drains to WouldBlock instead of blocking.
        self.socket.set_nonblocking(true)?;
        let mut fwd = Forwarder::bind(&mut self.core, self.server_addr, local, remote, dynamic)?;

        loop {
            let timeout = self.wait_time(fwd.is_busy());
            {
                let sock = self.socket.as_fd();
                let mut fds = vec![PollFd::new(sock, PollFlags::POLLIN)];
                for (fd, flags) in fwd.poll_fds(&self.core) {
                    fds.push(PollFd::new(fd, flags));
                }
                let _ = poll(&mut fds, poll_timeout(timeout));
            }

            fwd.accept(&mut self.core);

            // Inbound session packets.
            while self.recv_and_handle()? {}

            // React to stream events (incl. inbound `-R` opens → dial out).
            for ev in self.core.take_stream_events() {
                let _ = fwd.handle_event(&mut self.core, ev);
            }

            fwd.pump(&mut self.core);

            self.flush()?;
            self.check_connection()?;
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
        use nix::poll::{PollFd, PollFlags, poll};
        use std::os::fd::AsFd;

        // poll()-driven loop, so the UDP socket must be non-blocking.
        self.socket.set_nonblocking(true)?;

        const SEND_CAP: u64 = 4 * 1024 * 1024;
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

        loop {
            // An upload with room in its window has work to do right away.
            let busy = source.is_some() && !sent_fin && self.core.stream_in_flight(id) < SEND_CAP;
            let timeout = self.wait_time(busy);
            {
                let sock = self.socket.as_fd();
                let mut fds = [PollFd::new(sock, PollFlags::POLLIN)];
                let _ = poll(&mut fds, poll_timeout(timeout));
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
                while !sent_fin && self.core.stream_in_flight(id) < SEND_CAP {
                    let chunk = src.read_chunk(CHUNK)?;
                    if chunk.is_empty() {
                        self.core.stream_close(id);
                        sent_fin = true;
                        break;
                    } else {
                        let n = chunk.len() as u64;
                        self.core.stream_write(id, &chunk);
                        progress.add(n);
                    }
                }
                // Done once the server acknowledges by closing its half back
                // (reading is what observes the FIN; no data is expected).
                let _ = self.core.stream_read(id);
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
            self.check_connection()?;
        }
    }

    /// Run a non-interactive remote command to completion, streaming its stdout
    /// and stderr to ours and returning its exit code. stdin is forwarded from
    /// our stdin until EOF.
    pub fn run_exec(&mut self, cmd: &str) -> Result<i32, RuntimeError> {
        self.run_exec_with(cmd, &ExecOptions::default())
    }

    /// Like [`Client::run_exec`], but with port forwards (`-L`/`-R`/`-D`)
    /// serviced alongside the command for its whole lifetime, as `ssh -D 1080
    /// host cmd` does. Editors such as VS Code Remote-SSH rely on this: they
    /// feed a bootstrap script to the remote shell over stdin, then reach the
    /// server it starts through a forward on the same connection.
    pub fn run_exec_with(&mut self, cmd: &str, opts: &ExecOptions) -> Result<i32, RuntimeError> {
        use nix::poll::{PollFd, PollFlags, poll};
        use std::io::Read;
        use std::os::fd::AsFd;

        self.socket.set_nonblocking(true)?;
        let mut fwd = Forwarder::bind(
            &mut self.core,
            self.server_addr,
            &opts.local,
            &opts.remote,
            &opts.dynamic,
        )?;
        let stdin = std::io::stdin();
        if !opts.null_stdin {
            set_fd_nonblocking(stdin.as_fd());
        }

        let e = self.core.open_exec(cmd);
        let mut err_id: Option<u64> = None;
        let mut exit_code: Option<i32> = None;
        // `-n`: the command sees an immediate EOF on stdin.
        let mut stdin_eof = opts.null_stdin;
        if stdin_eof {
            self.core.stream_close(e);
        }

        let mut inbuf = [0u8; 65536];

        loop {
            let timeout = self.wait_time(fwd.is_busy());
            {
                let sock = self.socket.as_fd();
                let inp = stdin.as_fd();
                let mut fds = vec![PollFd::new(sock, PollFlags::POLLIN)];
                // Stop reading stdin while the stream is backed up.
                if !stdin_eof && self.core.stream_in_flight(e) < FORWARD_SEND_CAP {
                    fds.push(PollFd::new(inp, PollFlags::POLLIN));
                }
                for (fd, flags) in fwd.poll_fds(&self.core) {
                    fds.push(PollFd::new(fd, flags));
                }
                let _ = poll(&mut fds, poll_timeout(timeout));
            }

            fwd.accept(&mut self.core);

            while self.recv_and_handle()? {}

            for ev in self.core.take_stream_events() {
                // Forward-stream events (incl. inbound `-R` opens) go to the
                // forwarder; whatever it doesn't own concerns the command.
                let Some(ev) = fwd.handle_event(&mut self.core, ev) else {
                    continue;
                };
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
                    StreamEvent::Exited { id, status } if id == e => exit_code = Some(status),
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
            if !stdin_eof && self.core.stream_in_flight(e) < FORWARD_SEND_CAP {
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

            fwd.pump(&mut self.core);

            self.flush()?;
            if exit_code.is_none() {
                self.check_connection()?;
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

    /// Close the connection so the server tears the session down promptly.
    /// Spends a few milliseconds pushing the close out (it is retransmitted
    /// if the first one is lost).
    pub fn say_bye(&mut self) {
        let _ = self.flush();
        self.core.send_bye();
        for _ in 0..4 {
            let _ = self.flush();
            let _ = self.recv_and_handle();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// How long the event loop may sleep: until the connection's next timer,
    /// at most a second (`busy`: local work pending, 20 ms).
    fn wait_time(&mut self, busy: bool) -> Duration {
        let cap = if busy {
            Duration::from_millis(20)
        } else {
            Duration::from_secs(1)
        };
        self.core.timeout().map_or(cap, |t| t.min(cap))
    }

    /// An error once the connection is gone (forwards, exec and transfers do
    /// not survive it; the interactive shell reconnects instead).
    pub fn check_connection(&self) -> Result<(), RuntimeError> {
        match self.core.lost_reason() {
            Some(r) => Err(RuntimeError::ConnectionLost(r.to_string())),
            None => Ok(()),
        }
    }

    /// Start a new connection after the previous one was lost; the server
    /// reattaches the running shell.
    pub fn reconnect(&mut self) -> Result<(), RuntimeError> {
        for pkt in self.core.reconnect()? {
            self.send_dgram(&pkt)?;
        }
        Ok(())
    }

    /// Send a datagram. A send failure is NEVER fatal: a full send buffer
    /// (EWOULDBLOCK) or a transient network outage (no route / network down,
    /// e.g. while roaming between Wi-Fi and cellular) just drops the datagram —
    /// QUIC's loss recovery retransmits, and the connection migrates to the
    /// new address once connectivity returns.
    fn send_dgram(&self, pkt: &[u8]) -> Result<(), RuntimeError> {
        let _ = self.socket.send_to(pkt, self.server_addr);
        Ok(())
    }

    /// Drain a single ready datagram (non-blocking) and send any replies.
    /// Returns true if a datagram was processed. Receive errors are treated as
    /// "nothing right now" (transient) rather than fatal, so a network outage
    /// doesn't tear the session down.
    pub fn recv_and_handle(&mut self) -> Result<bool, RuntimeError> {
        match self.socket.recv_from(&mut self.rbuf) {
            Ok((n, _src)) => {
                // `?` so a handshake-time failure (e.g. HOST KEY MISMATCH) still
                // aborts; transport-layer junk is dropped inside handle_packet.
                for pkt in self.core.handle_packet(&self.rbuf[..n])? {
                    self.send_dgram(&pkt)?;
                }
                Ok(true)
            }
            // Any receive error (would-block, timed out, or a transient
            // network-down/unreachable during roaming) means "no data now".
            Err(_) => Ok(false),
        }
    }

    /// Run timers and send whatever the connection has queued.
    pub fn flush(&mut self) -> Result<(), RuntimeError> {
        for pkt in self.core.tick() {
            self.send_dgram(&pkt)?;
        }
        match self.core.take_failure() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Probe the path now (refreshes NAT, detects a recovered network).
    pub fn send_keepalive(&mut self) -> Result<(), RuntimeError> {
        for pkt in self.core.keepalive() {
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
            {
                use nix::poll::{PollFd, PollFlags, poll};
                use std::os::fd::AsFd;
                let mut fds = [PollFd::new(self.socket.as_fd(), PollFlags::POLLIN)];
                let _ = poll(
                    &mut fds,
                    poll_timeout(remaining.min(Duration::from_millis(20))),
                );
            }
            if self.pump_once().is_err() {
                break;
            }
        }
        self.core.server_version().map(str::to_string)
    }
}

/// A poll(2) timeout from a duration (rounded up to whole milliseconds, so a
/// sub-millisecond timer doesn't become a zero-timeout busy loop).
fn poll_timeout(d: Duration) -> nix::poll::PollTimeout {
    let ms = d.as_micros().div_ceil(1000).min(u16::MAX as u128) as u16;
    nix::poll::PollTimeout::from(ms)
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

/// Options for [`Client::run_exec_with`].
#[derive(Debug, Clone, Default)]
pub struct ExecOptions {
    /// `-L` forwards `(local_port, "host:port")`.
    pub local: Vec<(u16, String)>,
    /// `-R` forwards `(remote_port, "host:port")`.
    pub remote: Vec<(u16, String)>,
    /// `-D` SOCKS forwards `(bind_addr, port)`.
    pub dynamic: Vec<(String, u16)>,
    /// `-n`: give the command an empty stdin instead of forwarding ours.
    pub null_stdin: bool,
}

/// Per-stream cap on bytes queued for QUIC but not yet taken by it, so a fast
/// local producer can't grow the buffer without bound (QUIC's own send buffer
/// is bounded by its flow-control windows).
const FORWARD_SEND_CAP: u64 = 1024 * 1024;

/// Client-side port-forwarding state (`-L`/`-R`/`-D`), independent of the
/// session loop driving it, so forwards can run on their own (`ssh -N` style)
/// or alongside a remote command.
pub struct Forwarder {
    /// `-L` listeners and their fixed targets.
    listeners: Vec<(std::net::TcpListener, String)>,
    /// `-D` SOCKS listeners.
    socks_listeners: Vec<std::net::TcpListener>,
    /// SOCKS connections still negotiating (no forward stream opened yet).
    pending_socks: Vec<crate::socks::SocksConn>,
    /// Live forwarded connections, keyed by stream id.
    conns: std::collections::HashMap<u64, crate::forward::ForwardConn>,
}

impl Forwarder {
    /// Bind the local listeners and request the remote forwards.
    pub fn bind(
        core: &mut ClientCore,
        server_addr: SocketAddr,
        local: &[(u16, String)],
        remote: &[(u16, String)],
        dynamic: &[(String, u16)],
    ) -> Result<Self, RuntimeError> {
        use std::net::TcpListener;
        let mut listeners = Vec::new();
        for (port, target) in local {
            let l = TcpListener::bind(("127.0.0.1", *port))?;
            l.set_nonblocking(true)?;
            eprintln!("-L 127.0.0.1:{port} -> {target} (via {server_addr})");
            listeners.push((l, target.clone()));
        }
        for (port, target) in remote {
            core.request_remote_forward(*port, target);
            eprintln!("-R {}:{port} -> {target}", server_addr.ip());
        }
        let mut socks_listeners = Vec::new();
        for (bind, port) in dynamic {
            let l = TcpListener::bind((bind.as_str(), *port))?;
            l.set_nonblocking(true)?;
            eprintln!("-D {bind}:{port} (SOCKS) -> via {server_addr}");
            socks_listeners.push(l);
        }
        Ok(Forwarder {
            listeners,
            socks_listeners,
            pending_socks: Vec::new(),
            conns: std::collections::HashMap::new(),
        })
    }

    /// Whether there is local work in progress that warrants a short poll
    /// timeout (buffered output to flush, SOCKS handshakes to drive).
    pub fn is_busy(&self) -> bool {
        self.conns.values().any(|c| c.wants_write()) || !self.pending_socks.is_empty()
    }

    /// Every descriptor the session loop should wait on, with the events to
    /// wait for. A connection whose stream is backed up isn't polled for
    /// input (that would spin); one with buffered output waits to drain.
    pub fn poll_fds(
        &self,
        core: &ClientCore,
    ) -> Vec<(std::os::fd::BorrowedFd<'_>, nix::poll::PollFlags)> {
        use nix::poll::PollFlags;
        use std::os::fd::AsFd;
        let mut fds = Vec::new();
        fds.extend(
            self.listeners
                .iter()
                .map(|(l, _)| (l.as_fd(), PollFlags::POLLIN)),
        );
        fds.extend(
            self.socks_listeners
                .iter()
                .map(|l| (l.as_fd(), PollFlags::POLLIN)),
        );
        for (id, c) in &self.conns {
            let mut flags = PollFlags::empty();
            if c.wants_read() && core.stream_in_flight(*id) < FORWARD_SEND_CAP {
                flags |= PollFlags::POLLIN;
            }
            if c.wants_write() {
                flags |= PollFlags::POLLOUT;
            }
            if !flags.is_empty() {
                fds.push((c.as_fd(), flags));
            }
        }
        fds.extend(
            self.pending_socks
                .iter()
                .map(|c| (c.as_fd(), PollFlags::POLLIN)),
        );
        fds
    }

    /// Accept new local connections and advance SOCKS negotiations, opening a
    /// forward stream for each connection that is ready.
    pub fn accept(&mut self, core: &mut ClientCore) {
        use crate::forward::ForwardConn;
        use crate::socks::{Progress, SocksConn};

        // New `-L` connections: open a forward stream each.
        for (l, target) in &self.listeners {
            while let Ok((s, _)) = l.accept() {
                if let Ok(conn) = ForwardConn::new(s) {
                    let id = core.open_forward(target);
                    self.conns.insert(id, conn);
                }
            }
        }

        // New SOCKS (`-D`) connections; negotiation happens below.
        for l in &self.socks_listeners {
            while let Ok((s, _)) = l.accept() {
                if let Ok(sc) = SocksConn::new(s) {
                    self.pending_socks.push(sc);
                }
            }
        }

        // Drive SOCKS negotiations; on CONNECT, open a forward and bridge.
        let mut still_pending = Vec::new();
        for sc in self.pending_socks.drain(..) {
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
                        let id = core.open_forward(&target);
                        if !leftover.is_empty() {
                            core.stream_write(id, &leftover);
                        }
                        self.conns.insert(id, conn);
                    }
                }
                (Progress::Pending, Some(sc)) => still_pending.push(sc),
                // Failed, or pending-without-handback: drop the connection.
                _ => {}
            }
        }
        self.pending_socks = still_pending;
    }

    /// Handle a stream event if it concerns a forward; otherwise hand it back
    /// for the caller to process.
    pub fn handle_event(&mut self, core: &mut ClientCore, ev: StreamEvent) -> Option<StreamEvent> {
        use crate::forward::ForwardConn;
        match ev {
            // Inbound `-R` connection: dial the local target.
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
                        self.conns.insert(id, conn);
                    }
                    None => core.stream_reset(id),
                }
                None
            }
            // Session→TCP draining happens in `pump`, bounded by the out
            // buffer; Readable just signals data is available.
            StreamEvent::Readable { id } if self.conns.contains_key(&id) => None,
            // Peer closed its send half: keep flushing what we have, but stop
            // expecting more session data.
            StreamEvent::Closed { id } if self.conns.contains_key(&id) => {
                if let Some(c) = self.conns.get_mut(&id) {
                    c.mark_peer_closed();
                }
                None
            }
            // Reset aborts immediately.
            StreamEvent::Reset { id } if self.conns.contains_key(&id) => {
                self.conns.remove(&id);
                core.stream_reset(id);
                None
            }
            other => Some(other),
        }
    }

    /// Pump both directions of every forwarded connection (with backpressure
    /// caps), propagate half-close, and reap finished connections.
    pub fn pump(&mut self, core: &mut ClientCore) {
        let ids: Vec<u64> = self.conns.keys().copied().collect();
        for id in ids {
            let Some(c) = self.conns.get_mut(&id) else {
                continue;
            };
            // session → TCP, bounded so a stuck local peer backpressures the
            // session (its mux recv window closes as we stop reading).
            c.flush();
            while c.out_len() < FORWARD_SEND_CAP as usize {
                let d = core.stream_read(id);
                if d.is_empty() {
                    break;
                }
                c.queue_to_tcp(&d);
            }
            // TCP → session, bounded by bytes QUIC hasn't taken yet.
            while core.stream_in_flight(id) < FORWARD_SEND_CAP {
                let data = c.read_tcp();
                if data.is_empty() {
                    break;
                }
                core.stream_write(id, &data);
            }
            if c.needs_fin() {
                core.stream_close(id);
            }
            if c.is_finished() {
                self.conns.remove(&id);
            }
        }
    }
}
