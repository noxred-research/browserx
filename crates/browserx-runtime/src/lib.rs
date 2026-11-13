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
//! targets Unix hosts.

mod chromium;
mod config;
mod discover;
mod lock;
mod process;
mod state;

pub use chromium::ChromiumRuntime;
pub use config::{LaunchProfile, RuntimeConfig};
pub use discover::discover_chromium;
pub use lock::ProfileLock;
