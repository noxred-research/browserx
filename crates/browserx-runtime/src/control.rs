//! The runtime's own DevTools connection to one browser, kept alive across
//! connection loss.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use browserx_cdp::{CdpClient, CdpError, CdpLimits};
use browserx_core::{Error, Result};

/// A [`CdpClient`] that is replaced when its connection ends.
///
/// A connection can end without the browser being at fault: a reply above the
/// size limit (the client cannot skip a frame, so it closes) or a transport
/// hiccup. The browser-level endpoint accepts any number of connections and
/// contexts are created with `disposeOnDetach: false`, so a new connection sees
/// exactly the same browser. [`Control::client`] hands out the live connection
/// and opens a fresh one when the current one is closed, instead of leaving the
/// browser permanently unmanageable.
pub(crate) struct Control {
    ws_url: String,
    limits: CdpLimits,
    current: Mutex<CdpClient>,
    /// Serializes reconnection so concurrent callers share one new connection.
    reconnecting: tokio::sync::Mutex<()>,
    /// Set by [`Control::close`]; no reconnect after an intentional close.
    shut: AtomicBool,
}

impl Control {
    pub(crate) fn new(ws_url: String, limits: CdpLimits, client: CdpClient) -> Self {
        Self {
            ws_url,
            limits,
            current: Mutex::new(client),
            reconnecting: tokio::sync::Mutex::new(()),
            shut: AtomicBool::new(false),
        }
    }

    fn current(&self) -> CdpClient {
        self.current
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The live connection, reconnecting first if the previous one ended.
    pub(crate) async fn client(&self) -> Result<CdpClient> {
        let client = self.current();
        if !client.is_closed() {
            return Ok(client);
        }
        let _turn = self.reconnecting.lock().await;
        let client = self.current();
        if !client.is_closed() {
            return Ok(client);
        }
        if self.shut.load(Ordering::Acquire) {
            return Err(CdpError::Closed("closed locally".into()).into());
        }
        let fresh = CdpClient::connect(&self.ws_url, self.limits.clone())
            .await
            .map_err(|e| Error::Browser(format!("cannot reconnect to the browser: {e}")))?;
        *self.current.lock().unwrap_or_else(PoisonError::into_inner) = fresh.clone();
        tracing::warn!("browser control connection was closed; reconnected");
        Ok(fresh)
    }

    /// Closes the connection for good.
    pub(crate) async fn close(&self) {
        self.shut.store(true, Ordering::Release);
        self.current().close().await;
    }
}
