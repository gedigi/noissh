//! Client runtime: a socket-free [`ClientCore`] (drivable by the resilience
//! harness) plus a [`Client`] UDP driver used by the `noissh` binary.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use auth::{KnownHosts, Tofu};
use noise_core::Keypair;
use predict::DisplayMode;
use proto::{ClientShell, ControlMsg, Handshaker, verify_server};
use term::Grid;
use transport::{Packet, Session, random_session_id};
use wire::Frame;

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
    known_hosts_dirty: bool,
}

/// Bound on OpenShell retransmissions, so a shell that produces no screen output
/// does not cause the request to be resent for the whole session.
const OPEN_SHELL_MAX_TICKS: u32 = 300;

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
            known_hosts_dirty: false,
        };
        Ok((core, first))
    }

    pub fn is_established(&self) -> bool {
        self.established
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
            // Request a shell with our geometry. Retransmitted every tick until
            // the server starts sending screen state (the request could be lost
            // or reordered ahead of the final handshake message).
            self.open_shell_pending = true;
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
                _ => {} // Pong and others: liveness only
            }
        }
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
                || self.shell.has_pending_input())
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
        frames.append(&mut self.pending_control);
        frames.extend(self.shell.poll_frames());
        self.need_ack = false;
        if frames.is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![session.seal(&frames)?])
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
        let bind: SocketAddr = if server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(Duration::from_millis(20)))?;
        let (core, first) = ClientCore::new(
            keypair,
            known,
            host_label,
            server_addr,
            rows,
            cols,
            prediction,
        )?;
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
