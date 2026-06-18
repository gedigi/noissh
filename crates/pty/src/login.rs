//! Login backends behind a common trait.

use crate::{PtyError, PtyHandle, SpawnRequest, spawn_with};

/// Allocates a PTY and execs a login session for a [`SpawnRequest`].
pub trait LoginSession {
    fn spawn(&self, req: &SpawnRequest) -> Result<PtyHandle, PtyError>;
}

/// Portable backend: runs as the current user, no PAM, no privilege change.
/// This is the path used by tests and the local/dev daemon.
pub struct LocalLogin;

impl LoginSession for LocalLogin {
    fn spawn(&self, req: &SpawnRequest) -> Result<PtyHandle, PtyError> {
        spawn_with(req, || Ok(()))
    }
}

/// sshd-style privilege-separated backend (Linux): `setgid`/`initgroups`/
/// `setuid` to the target user before exec, with optional PAM `acct_mgmt` +
/// `open_session` (enable the `pam` cargo feature). Requires the daemon to run
/// as root.
#[cfg(target_os = "linux")]
pub struct PrivsepLogin {
    /// PAM service name (e.g. "noisshd"). Used only when the `pam` feature is
    /// enabled; a matching file must exist in `/etc/pam.d/`.
    pub service: String,
}

#[cfg(target_os = "linux")]
impl PrivsepLogin {
    pub fn new(service: impl Into<String>) -> Self {
        PrivsepLogin {
            service: service.into(),
        }
    }
}

#[cfg(target_os = "linux")]
impl LoginSession for PrivsepLogin {
    fn spawn(&self, req: &SpawnRequest) -> Result<PtyHandle, PtyError> {
        let user = req
            .user
            .clone()
            .ok_or_else(|| PtyError::UnknownUser("<none>".to_string()))?;

        // Account validity + session setup happen in the privileged parent.
        #[cfg(feature = "pam")]
        let mut _session = pam::PamSession::open(&self.service, &user)?;
        #[cfg(not(feature = "pam"))]
        let _ = &self.service;

        // Resolve credentials in the parent (heap/NSS work) so the post-fork
        // child uses only async-signal-safe raw libc calls.
        let creds = crate::Credentials::resolve(&user)?;
        let handle = spawn_with(req, move || creds.apply())?;

        #[cfg(feature = "pam")]
        _session.leak();
        Ok(handle)
    }
}

/// PAM session management (Linux, `pam` feature only).
#[cfg(all(target_os = "linux", feature = "pam"))]
mod pam {
    use crate::PtyError;
    use pam_client::conv_null::Conversation;
    use pam_client::{Context, Flag};

    pub struct PamSession {
        ctx: Context<Conversation>,
        open: bool,
    }

    impl PamSession {
        /// Run `acct_mgmt` then `open_session` for `user` under `service`.
        pub fn open(service: &str, user: &str) -> Result<Self, PtyError> {
            let mut ctx = Context::new(service, Some(user), Conversation::new())
                .map_err(|e| PtyError::Pam(format!("context: {e}")))?;
            ctx.acct_mgmt(Flag::NONE)
                .map_err(|e| PtyError::Pam(format!("acct_mgmt: {e}")))?;
            ctx.open_session(Flag::NONE)
                .map_err(|e| PtyError::Pam(format!("open_session: {e}")))?;
            Ok(PamSession { ctx, open: true })
        }

        /// Detach: let the session persist (closed best-effort on drop).
        pub fn leak(&mut self) {
            let _ = &self.ctx;
            self.open = true;
        }
    }
}
