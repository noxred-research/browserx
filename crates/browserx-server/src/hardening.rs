//! Process hardening of the worker itself.
//!
//! The worker holds the snapshot key, the lease-store and object-store
//! credentials (when they come from the environment rather than from files) and
//! every lease token in memory. [`harden_process`] marks the process
//! non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`), which on Linux
//!
//! * makes `/proc/<pid>/environ`, `/proc/<pid>/mem` and the other `/proc/<pid>`
//!   entries unreadable for other processes of the same user (without
//!   `CAP_SYS_PTRACE`), so the secrets the worker read from its environment
//!   cannot be taken from there, and
//! * refuses `ptrace` attach (and so `gdb -p`, `strace -p`) from other processes of
//!   the same user and disables core dumps of the worker.
//!
//! The setting is cleared by `execve`, so browsers started by the worker are
//! dumpable as usual (and keep their own, sandboxed, environment, see
//! `browserx-runtime`). It is not a boundary against root.

use browserx_core::{Error, Result};

/// Makes the current process non-dumpable. A no-op on platforms without
/// `PR_SET_DUMPABLE`.
///
/// # Errors
///
/// `Error::Internal` when the kernel refuses the setting.
pub fn harden_process() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        nix::sys::prctl::set_dumpable(false)
            .map_err(|e| Error::Internal(format!("cannot mark the worker non-dumpable: {e}")))?;
        // Read it back: the guarantee is the state, not the call.
        match nix::sys::prctl::get_dumpable() {
            Ok(false) => {}
            Ok(true) => return Err(Error::Internal("the worker is still dumpable".into())),
            Err(e) => {
                return Err(Error::Internal(format!(
                    "cannot read the dumpable flag: {e}"
                )));
            }
        }
    }
    Ok(())
}
