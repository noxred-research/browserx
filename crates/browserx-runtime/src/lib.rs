//! Local Chromium supervision.
//!
//! [`ChromiumRuntime`] implements [`browserx_core::BrowserRuntime`]: it launches
//! Chromium processes from named [`LaunchProfile`]s, discovers the DevTools
//! endpoint from the process's stderr, speaks CDP through `browserx-cdp`, creates
//! isolated browser contexts, captures and replays logical state (cookies and
//! `localStorage`), and shuts a browser down only after its process group is
//! confirmed gone.
//!
//! Launch profiles are the one extension point for alternative Chromium builds: an
//! `executable` and extra `args` are all a build needs. A small set of flags is
//! *managed* by the runtime (remote debugging, user-data-dir, proxy, headless) and
//! profiles that try to set them are rejected up front.
//!
//! Process supervision uses POSIX process groups and signals, so this crate
//! targets Unix hosts. A browser outlives a crashed worker (it runs in its own
//! process group), so every launch is recorded under the configured temp root and
//! [`ChromiumRuntime::sweep_orphans`] kills verified leftovers and removes stale
//! temporary directories at the next startup.

mod chromium;
mod config;
mod control;
mod discover;
mod lock;
mod orphans;
mod process;
mod state;

pub use chromium::ChromiumRuntime;
pub use config::{LaunchProfile, MAX_STARTUP_TIMEOUT, RuntimeConfig};
pub use discover::discover_chromium;
pub use lock::ProfileLock;
pub use orphans::SweepReport;
