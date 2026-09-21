//! Pids the supervisor process spawns and reaps itself.
//!
//! The supervisor is a child subreaper and drains reparented orphans with
//! `waitpid(-1)` on every pass of its event loop. Credential capture commands
//! run on proxy threads inside that same process, so a blind drain can consume
//! a capture's exit status first and leave the waiting thread with `ECHILD`:
//! the capture is reported as `wait_failed` and the intercepted request fails
//! closed with 503 even though the command ran fine. Spawning through
//! [`spawn_owned`] registers the pid here, and the drain leaves those statuses
//! for the thread that is waiting on them.

use std::collections::HashSet;
use std::ops::{Deref, DerefMut};
use std::process::{Child, Command};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

static OWNED: LazyLock<Mutex<HashSet<u32>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

fn owned() -> MutexGuard<'static, HashSet<u32>> {
    OWNED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A spawned child whose exit status only its spawner may reap.
///
/// Derefs to [`Child`], so `try_wait`, `wait`, `kill`, and the stdio handles
/// are used exactly as on a plain child. Dropping it deregisters the pid.
pub(crate) struct OwnedChild(Child);

impl Deref for OwnedChild {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.0
    }
}

impl DerefMut for OwnedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        owned().remove(&self.0.id());
    }
}

/// Spawn `command` so the orphan drain cannot reap it.
///
/// The table stays locked across the spawn: a child that exits before the
/// insert would otherwise be reapable while still unregistered.
pub(crate) fn spawn_owned(command: &mut Command) -> std::io::Result<OwnedChild> {
    let mut table = owned();
    let child = command.spawn()?;
    table.insert(child.id());
    Ok(OwnedChild(child))
}

/// Run `drain` with the table locked, so no spawn can land mid-drain.
pub(crate) fn with_owned<T>(drain: impl FnOnce(&HashSet<u32>) -> T) -> T {
    let table = owned();
    drain(&table)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawned_child_is_registered_until_dropped() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        let Ok(mut child) = spawn_owned(&mut command) else {
            panic!("spawn failed");
        };
        let pid = child.id();
        assert!(with_owned(|owned| owned.contains(&pid)));
        let _ = child.wait();
        drop(child);
        assert!(!with_owned(|owned| owned.contains(&pid)));
    }
}
