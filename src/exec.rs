//! Server-side execution of a non-interactive remote command (`--exec`).
//!
//! Unlike the interactive shell (which allocates a PTY and syncs a terminal
//! screen), `--exec` runs the command under plain pipes so stdout stays byte-for
//! byte intact (no line-discipline `\n`→`\r\n` translation) — suitable for
//! piping output into a file. stdout and stderr are kept separate; the exit code
//! is reported when the command finishes.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsFd;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

/// Put a pipe end into non-blocking mode (safe `nix` fcntl, no `unsafe`).
fn set_nonblocking<Fd: AsFd>(fd: &Fd) {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    if let Ok(flags) = fcntl(fd.as_fd(), FcntlArg::F_GETFL) {
        let mut f = OFlag::from_bits_truncate(flags);
        f.insert(OFlag::O_NONBLOCK);
        let _ = fcntl(fd.as_fd(), FcntlArg::F_SETFL(f));
    }
}

/// Drain whatever is available from an optional pipe; clears the slot on EOF.
fn read_pipe<R: Read>(slot: &mut Option<R>) -> Vec<u8> {
    let mut out = Vec::new();
    let Some(r) = slot.as_mut() else {
        return out;
    };
    let mut buf = [0u8; 16384];
    loop {
        match r.read(&mut buf) {
            Ok(0) => {
                *slot = None; // EOF
                break;
            }
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                *slot = None;
                break;
            }
        }
    }
    out
}

/// Map an exit status to a conventional integer code (128 + signal if killed).
fn status_code(s: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))
}

/// A running `--exec` command with non-blocking pipe ends.
pub struct ExecProc {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    stdin_buf: Vec<u8>,
    exit: Option<i32>,
}

impl ExecProc {
    /// Spawn `cmd` via `/bin/sh -c` with piped, non-blocking stdio.
    pub fn spawn(cmd: &str) -> std::io::Result<Self> {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        if let Some(s) = &stdin {
            set_nonblocking(s);
        }
        if let Some(s) = &stdout {
            set_nonblocking(s);
        }
        if let Some(s) = &stderr {
            set_nonblocking(s);
        }
        Ok(ExecProc {
            child,
            stdin,
            stdout,
            stderr,
            stdin_buf: Vec::new(),
            exit: None,
        })
    }

    /// Drain available stdout bytes (empty once EOF).
    pub fn read_stdout(&mut self) -> Vec<u8> {
        read_pipe(&mut self.stdout)
    }

    /// Drain available stderr bytes (empty once EOF).
    pub fn read_stderr(&mut self) -> Vec<u8> {
        read_pipe(&mut self.stderr)
    }

    /// Queue bytes for the child's stdin and try to flush.
    pub fn write_stdin(&mut self, data: &[u8]) {
        if self.stdin.is_none() {
            return; // stdin already closed
        }
        self.stdin_buf.extend_from_slice(data);
        self.flush_stdin();
    }

    /// Flush buffered stdin (non-blocking).
    pub fn flush_stdin(&mut self) {
        let Some(si) = self.stdin.as_mut() else {
            self.stdin_buf.clear();
            return;
        };
        while !self.stdin_buf.is_empty() {
            match si.write(&self.stdin_buf) {
                Ok(0) => break,
                Ok(n) => {
                    self.stdin_buf.drain(0..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.stdin = None;
                    self.stdin_buf.clear();
                    break;
                }
            }
        }
    }

    /// Bytes staged for the child's stdin but not yet written to the pipe.
    pub fn stdin_buffered(&self) -> usize {
        self.stdin_buf.len()
    }

    /// Close the child's stdin (send EOF), flushing any remainder first.
    pub fn close_stdin(&mut self) {
        self.flush_stdin();
        self.stdin = None; // dropping the handle closes the pipe
    }

    /// Poll for process exit; returns the status code once it has exited.
    pub fn poll_exit(&mut self) -> Option<i32> {
        if self.exit.is_some() {
            return self.exit;
        }
        if let Ok(Some(status)) = self.child.try_wait() {
            self.exit = Some(status_code(status));
        }
        self.exit
    }

    /// True once the process has exited and both output pipes are drained to EOF.
    pub fn finished(&self) -> bool {
        self.exit.is_some() && self.stdout.is_none() && self.stderr.is_none()
    }

    /// The exit code (0 if not yet known).
    pub fn exit_code(&self) -> i32 {
        self.exit.unwrap_or(0)
    }

    /// Kill the child (used when the client aborts the exec stream).
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
