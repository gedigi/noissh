#![forbid(unsafe_code)]
//! noissh-bench: compares noissh with OpenSSH over a simulated network path.
//!
//! For each tool it starts a server on localhost behind a simulated link
//! (userspace delay/jitter/loss, see `link.rs`), opens a `-L` port forward
//! through it to a local data server, and measures through that forward:
//!
//! - **bulk**: throughput of a download of `--size` MB;
//! - **echo idle**: round trip of a 1-byte message (p50 / p95 over 50);
//! - **echo under load**: the same while a bulk download runs on another
//!   connection of the same session (how much a transfer delays typing);
//! - **idle pkts/s**: datagrams per second, each way, with the session idle
//!   (noissh only: OpenSSH's TCP path isn't counted by the TCP link).
//!
//! Loss is simulated only on UDP (noissh). TCP loss can't be simulated in
//! userspace, so the OpenSSH numbers are delay/jitter only unless the path is
//! impaired with `netem` instead (see `bench/README.md`).

mod link;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use link::{Impairment, TcpLink, UdpLink};

struct Args {
    rtt_ms: u64,
    jitter_ms: u64,
    loss_pct: f64,
    size_mb: u64,
    tools: Vec<String>,
    bin_dir: PathBuf,
    /// Run without the userspace link (the path is impaired outside, e.g. by
    /// `netem`, or not at all).
    no_link: bool,
    noissh_port: Option<u16>,
    ssh_port: Option<u16>,
    timeout: Duration,
}

/// How a tool is reached: through the userspace link with this impairment,
/// or directly; and on which server port (random if `None`).
#[derive(Clone, Copy)]
struct Path_ {
    link: Option<Impairment>,
    port: Option<u16>,
}

fn usage() -> ! {
    eprintln!(
        "usage: noissh-bench [--rtt MS] [--jitter MS] [--loss PCT] [--size MB]\n\
         \x20                   [--tools noissh,ssh] [--bin-dir DIR] [--timeout S]\n\
         \x20                   [--no-link] [--noissh-port N] [--ssh-port N]\n\
         defaults: --rtt 40 --jitter 0 --loss 0 --size 20 --tools noissh,ssh\n\
         \x20         --bin-dir target/release (noissh, noisshd, noissh-keygen)\n\
         \x20         --timeout 120 (per transfer); random server ports"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut a = Args {
        rtt_ms: 40,
        jitter_ms: 0,
        loss_pct: 0.0,
        size_mb: 20,
        tools: vec!["noissh".into(), "ssh".into()],
        bin_dir: PathBuf::from("target/release"),
        no_link: false,
        noissh_port: None,
        ssh_port: None,
        timeout: Duration::from_secs(120),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--rtt" => a.rtt_ms = val().parse().unwrap_or_else(|_| usage()),
            "--jitter" => a.jitter_ms = val().parse().unwrap_or_else(|_| usage()),
            "--loss" => a.loss_pct = val().parse().unwrap_or_else(|_| usage()),
            "--size" => a.size_mb = val().parse().unwrap_or_else(|_| usage()),
            "--tools" => a.tools = val().split(',').map(str::to_string).collect(),
            "--bin-dir" => a.bin_dir = PathBuf::from(val()),
            "--no-link" => a.no_link = true,
            "--noissh-port" => a.noissh_port = Some(val().parse().unwrap_or_else(|_| usage())),
            "--ssh-port" => a.ssh_port = Some(val().parse().unwrap_or_else(|_| usage())),
            "--timeout" => {
                a.timeout = Duration::from_secs(val().parse().unwrap_or_else(|_| usage()))
            }
            _ => usage(),
        }
    }
    a
}

// --- data server -------------------------------------------------------------

/// The far end of the forward: `B` + u64 size → that many bytes; `E` → echo.
fn start_data_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            thread::spawn(move || serve(s));
        }
    });
    addr
}

fn serve(mut s: TcpStream) {
    s.set_nodelay(true).ok();
    let mut cmd = [0u8; 1];
    if s.read_exact(&mut cmd).is_err() {
        return;
    }
    match cmd[0] {
        b'B' => {
            let mut n = [0u8; 8];
            if s.read_exact(&mut n).is_err() {
                return;
            }
            let mut left = u64::from_be_bytes(n);
            let chunk = vec![0x5au8; 64 * 1024];
            while left > 0 {
                let k = left.min(chunk.len() as u64) as usize;
                if s.write_all(&chunk[..k]).is_err() {
                    return;
                }
                left -= k as u64;
            }
        }
        b'E' => {
            let mut b = [0u8; 1];
            while s.read_exact(&mut b).is_ok() {
                if s.write_all(&b).is_err() {
                    return;
                }
            }
        }
        _ => {}
    }
}

// --- measurements --------------------------------------------------------------

fn bulk(port: u16, bytes: u64, deadline: Duration) -> Option<Duration> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let start = Instant::now();
    s.write_all(b"B").ok()?;
    s.write_all(&bytes.to_be_bytes()).ok()?;
    let mut got = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    while got < bytes {
        if start.elapsed() > deadline {
            return None;
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => got += n as u64,
        }
    }
    Some(start.elapsed())
}

/// Round trips of 1 byte, `n` times, 20 ms apart. Returns (p50, p95).
fn echo(port: u16, n: usize) -> Option<(Duration, Duration)> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_nodelay(true).ok();
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.write_all(b"E").ok()?;
    // Warm-up round trip (stream setup), not counted.
    let mut b = [0u8; 1];
    s.write_all(b"w").ok()?;
    s.read_exact(&mut b).ok()?;
    let mut rtts = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        s.write_all(b"x").ok()?;
        s.read_exact(&mut b).ok()?;
        rtts.push(t.elapsed());
        thread::sleep(Duration::from_millis(20));
    }
    rtts.sort();
    Some((rtts[n / 2], rtts[n * 95 / 100]))
}

/// Echo while bulk downloads run back to back on another connection.
fn echo_under_load(
    port: u16,
    n: usize,
    bulk_bytes: u64,
    timeout: Duration,
) -> Option<(Duration, Duration)> {
    let stop = Arc::new(AtomicBool::new(false));
    let loader = {
        let stop = stop.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if bulk(port, bulk_bytes, timeout).is_none() {
                    break;
                }
            }
        })
    };
    thread::sleep(Duration::from_millis(500)); // let the transfer ramp up
    let r = echo(port, n);
    stop.store(true, Ordering::Relaxed);
    let _ = loader.join();
    r
}

// --- tools -------------------------------------------------------------------

struct Running {
    children: Vec<Child>,
    forward_port: u16,
    udp: Option<UdpLink>,
    _tcp: Option<TcpLink>,
    _dir: TempDir,
}

impl Drop for Running {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut r = [0u8; 6];
        getrandom::fill(&mut r).unwrap();
        let name: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let p = std::env::temp_dir().join(format!("noissh-bench-{tag}-{name}"));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

fn start_noissh(bin: &Path, data: SocketAddr, path: Path_) -> Result<Running, String> {
    let dir = TempDir::new("noissh");
    let cfg = dir.0.join("cfg");
    let run = |name: &str| {
        let mut c = Command::new(bin.join(name));
        c.env("XDG_CONFIG_HOME", &cfg).stdin(Stdio::null());
        c
    };
    let out = run("noissh-keygen")
        .output()
        .map_err(|e| format!("noissh-keygen: {e}"))?;
    std::fs::write(cfg.join("noissh/authorized_keys"), &out.stdout).map_err(|e| e.to_string())?;
    let server_port = path.port.unwrap_or_else(free_udp_port);
    let daemon = run("noisshd")
        .args(["--listen", &format!("127.0.0.1:{server_port}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("noisshd: {e}"))?;
    let udp = match path.link {
        Some(imp) => Some(
            UdpLink::start(([127, 0, 0, 1], server_port).into(), imp).map_err(|e| e.to_string())?,
        ),
        None => None,
    };
    let connect_port = udp.as_ref().map_or(server_port, |u| u.front.port());
    let fwd = free_tcp_port();
    let client = run("noissh")
        .args([
            "--direct",
            "--port",
            &connect_port.to_string(),
            "-N",
            "-L",
            &format!("{fwd}:{data}"),
            "127.0.0.1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("noissh: {e}"))?;
    let running = Running {
        children: vec![client, daemon],
        forward_port: fwd,
        udp,
        _tcp: None,
        _dir: dir,
    };
    if !wait_for_port(fwd, Duration::from_secs(15)) {
        return Err("noissh forward never came up".into());
    }
    Ok(running)
}

fn start_ssh(data: SocketAddr, path: Path_) -> Result<Running, String> {
    let dir = TempDir::new("ssh");
    let d = &dir.0;
    for (key, path) in [("host", d.join("host")), ("client", d.join("client"))] {
        let st = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", key, "-f"])
            .arg(&path)
            .status()
            .map_err(|e| format!("ssh-keygen: {e}"))?;
        if !st.success() {
            return Err("ssh-keygen failed".into());
        }
    }
    std::fs::copy(d.join("client.pub"), d.join("authorized_keys")).map_err(|e| e.to_string())?;
    let port = path.port.unwrap_or_else(free_tcp_port);
    let config = format!(
        "Port {port}\nListenAddress 127.0.0.1\nHostKey {host}\nAuthorizedKeysFile {ak}\n\
         PidFile {pid}\nStrictModes no\nUsePAM no\nPermitRootLogin yes\n\
         PasswordAuthentication no\nKbdInteractiveAuthentication no\n",
        host = d.join("host").display(),
        ak = d.join("authorized_keys").display(),
        pid = d.join("sshd.pid").display(),
    );
    std::fs::write(d.join("sshd_config"), config).map_err(|e| e.to_string())?;
    let _ = std::fs::create_dir_all("/run/sshd"); // privilege-separation dir
    let sshd_bin = ["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .ok_or("sshd not found")?;
    let daemon = Command::new(sshd_bin)
        .args(["-D", "-e", "-f"])
        .arg(d.join("sshd_config"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("sshd: {e}"))?;
    if !wait_for_port(port, Duration::from_secs(10)) {
        return Err("sshd never listened".into());
    }
    let tcp = match path.link {
        Some(imp) => {
            Some(TcpLink::start(([127, 0, 0, 1], port).into(), imp).map_err(|e| e.to_string())?)
        }
        None => None,
    };
    let connect_port = tcp.as_ref().map_or(port, |t| t.front.port());
    let fwd = free_tcp_port();
    let client = Command::new("ssh")
        .args(["-N", "-L", &format!("{fwd}:{data}"), "-p"])
        .arg(connect_port.to_string())
        .arg("-i")
        .arg(d.join("client"))
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "LogLevel=ERROR",
            "127.0.0.1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("ssh: {e}"))?;
    let running = Running {
        children: vec![client, daemon],
        forward_port: fwd,
        udp: None,
        _tcp: tcp,
        _dir: dir,
    };
    if !wait_for_port(fwd, Duration::from_secs(15)) {
        return Err("ssh forward never came up".into());
    }
    Ok(running)
}

// --- main ----------------------------------------------------------------------

fn ms(d: Duration) -> String {
    format!("{:.1}", d.as_secs_f64() * 1000.0)
}

fn main() {
    let a = parse_args();
    let imp = Impairment {
        delay: Duration::from_millis(a.rtt_ms) / 2,
        jitter: Duration::from_millis(a.jitter_ms),
        loss: a.loss_pct / 100.0,
    };
    let data = start_data_server();
    let bytes = a.size_mb * 1_000_000;
    if a.no_link {
        println!("path: no userspace link (impaired outside the harness, if at all)");
    } else {
        println!(
            "path: RTT {} ms, jitter {} ms, loss {}% (loss applies to UDP only)",
            a.rtt_ms, a.jitter_ms, a.loss_pct
        );
    }
    let link = (!a.no_link).then_some(imp);
    println!(
        "{:<8} {:>12} {:>16} {:>18} {:>16}",
        "tool", "bulk MB/s", "echo p50/p95", "echo loaded p50/95", "idle pkts/s"
    );
    for tool in &a.tools {
        let started = match tool.as_str() {
            "noissh" => start_noissh(
                &a.bin_dir,
                data,
                Path_ {
                    link,
                    port: a.noissh_port,
                },
            ),
            "ssh" => start_ssh(
                data,
                Path_ {
                    link,
                    port: a.ssh_port,
                },
            ),
            other => Err(format!("unknown tool {other}")),
        };
        let r = match started {
            Ok(r) => r,
            Err(e) => {
                println!("{tool:<8} error: {e}");
                continue;
            }
        };
        let port = r.forward_port;
        let mbps = bulk(port, bytes, a.timeout)
            .map(|t| format!("{:.2}", bytes as f64 / 1e6 / t.as_secs_f64()))
            .unwrap_or_else(|| "timeout".into());
        let idle = echo(port, 50)
            .map(|(a, b)| format!("{}/{}", ms(a), ms(b)))
            .unwrap_or_else(|| "failed".into());
        let loaded = echo_under_load(port, 50, bytes, a.timeout)
            .map(|(a, b)| format!("{}/{}", ms(a), ms(b)))
            .unwrap_or_else(|| "failed".into());
        let pps = match &r.udp {
            Some(udp) => {
                thread::sleep(Duration::from_secs(2)); // settle
                let before = udp.counters.snapshot();
                thread::sleep(Duration::from_secs(5));
                let after = udp.counters.snapshot();
                format!(
                    "{:.1}↑ {:.1}↓",
                    (after[0] - before[0]) as f64 / 5.0,
                    (after[2] - before[2]) as f64 / 5.0
                )
            }
            None => "n/a".into(),
        };
        println!("{tool:<8} {mbps:>12} {idle:>16} {loaded:>18} {pps:>16}");
        drop(r);
    }
}
