//! Shared vocabulary for BrowserX.
//!
//! Everything that crosses a crate boundary lives here: identifiers, the session
//! specification a client asks for, the lease record the registry stores, the
//! explicit persistence and recovery contracts, typed errors, and the traits that
//! decouple the scheduler from browser runtimes and storage backends.
//!
//! Two rules shape these types:
//!
//! * **Say what persists.** A session never carries a bare `persistent: bool`.
//!   [`PersistenceMode`] names the exact mechanism, and every recovery reports a
//!   [`RecoveryOutcome`] that says whether the original browser process survived.
//! * **Ownership is fenced.** Every mutation of a lease is a compare-and-swap on
//!   its [`Generation`]. A worker or client holding an older generation can never
//!   overwrite newer state.

pub mod clock;
pub mod error;
pub mod ids;
pub mod lease;
pub mod runtime;
pub mod secret;
pub mod snapshot;
pub mod spec;
pub mod store;

pub use clock::{Clock, SystemClock};
pub use error::{Error, Result};
pub use ids::{BrowserId, ContextId, Generation, LeaseToken, ProfileId, SessionId, WorkerId};
pub use lease::{SessionLease, SessionStatus};
pub use runtime::{BrowserHandle, BrowserRuntime, LaunchRequest, RuntimeHealth, persona_seed};
pub use secret::Secret;
pub use snapshot::{Snapshot, SnapshotMeta, StateSnapshot};
pub use spec::{
    Isolation, PersistenceMode, ProxyRoute, RecoveryOutcome, RecoveryPolicy, SessionSpec,
};
pub use store::{LeaseStore, SnapshotStore};
