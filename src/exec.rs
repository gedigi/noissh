//! Server-side execution of a non-interactive remote command (the trailing
//! `noissh user@host <cmd>`).
//!
//! Unlike the interactive shell (which allocates a PTY and syncs a terminal
//! screen), a remote command runs under plain pipes so stdout stays byte-for
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

/// Most bytes taken from a pipe in one call.
const READ_PIPE_MAX: usize = 256 * 1024;

/// Read what is available from an optional pipe (up to [`READ_PIPE_MAX`]);
/// clears the slot on EOF.
fn read_pipe<R: Read>(slot: &mut Option<R>) -> Vec<u8> {
    let mut out = Vec::new();
    let Some(r) = slot.as_mut() else {
        return out;
    };
    let mut buf = [0u8; 16384];
    // Bounded per call: a command that writes faster than we read (`yes`)
    // would otherwise keep this loop, and the whole session loop, busy
    // forever while `out` grows without limit.
    while out.len() < READ_PIPE_MAX {
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

/// A running remote command with non-blocking pipe ends.
pub struct ExecProc {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    stdin_buf: Vec<u8>,
    exit: Option<i32>,
}

impl ExecProc {
    /// Spawn `cmd` with the user's login shell (`<shell> -c <cmd>`, as sshd
    /// does), with piped, non-blocking stdio, running in the user's home
    /// directory (like a login would) rather than the daemon's working
    /// directory.
    ///
    /// The login shell, not `/bin/sh`: an account whose shell is restricted
    /// (`rbash`, `git-shell`) or disabled (`nologin`) must not get an
    /// unrestricted shell through remote commands. `/bin/sh` is the fallback
    /// only when the account has no shell recorded.
    ///
    /// [`proto::LOGIN_SHELL_COMMAND`] (what `noissh -T host` sends to get a
    /// shell reading commands from stdin) is run as `<shell> -l` directly, so
    /// it works whatever the shell's syntax.
    pub fn spawn(cmd: &str) -> std::io::Result<Self> {
        let user = nix::unistd::User::from_uid(nix::unistd::getuid())
            .ok()
            .flatten();
        let shell = user
            .as_ref()
            .map(|u| u.shell.clone())
            .filter(|s| !s.as_os_str().is_empty())
            .unwrap_or_else(|| "/bin/sh".into());
        let mut command = Command::new(&shell);
        if cmd == proto::LOGIN_SHELL_COMMAND {
            command.arg("-l");
        } else {
            command.arg("-c").arg(cmd);
        }
        command
            .env("SHELL", &shell)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(user) = &user {
            command.current_dir(&user.dir);
        }
        let mut child = command.spawn()?;
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

    /// The open output pipes (stdout, stderr), for registering with `poll()`.
    pub fn output_fds(&self) -> Vec<std::os::fd::BorrowedFd<'_>> {
        let mut fds = Vec::new();
        if let Some(o) = &self.stdout {
            fds.push(o.as_fd());
        }
        if let Some(e) = &self.stderr {
            fds.push(e.as_fd());
        }
        fds
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
