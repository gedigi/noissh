//! Login backend behind a trait.

use crate::{PtyError, PtyHandle, SpawnRequest, spawn};

/// Allocates a PTY and execs a login session for a [`SpawnRequest`].
pub trait LoginSession {
    fn spawn(&self, req: &SpawnRequest) -> Result<PtyHandle, PtyError>;
}

/// Allocates a PTY and execs the login shell. Runs as the current user, or — if
/// `SpawnRequest::user` is set and the process is root — drops to that user's
/// uid/gid before exec. For full multi-user fidelity use the SSH-bootstrap model
/// (the server is launched as the authenticated user by SSH).
pub struct LocalLogin;

impl LoginSession for LocalLogin {
    fn spawn(&self, req: &SpawnRequest) -> Result<PtyHandle, PtyError> {
        spawn(req)
    }
}
