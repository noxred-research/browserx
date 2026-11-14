//! Error responses: `{ "error": { "code", "message" } }` with a stable status mapping.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use browserx_core::Error;
use serde_json::json;

/// An [`Error`] on its way to an HTTP response.
#[derive(Debug)]
pub struct ApiError(pub Error);

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}

/// HTTP status for an error kind.
#[must_use]
pub fn status_of(error: &Error) -> StatusCode {
    match error {
        Error::InvalidRequest(_) => StatusCode::BAD_REQUEST,
        Error::Unauthorized => StatusCode::UNAUTHORIZED,
        Error::Forbidden(_) => StatusCode::FORBIDDEN,
        Error::NotFound(_) => StatusCode::NOT_FOUND,
        Error::StaleGeneration { .. } | Error::Conflict(_) | Error::ProfileLocked(_) => {
            StatusCode::CONFLICT
        }
        Error::Capacity(_) => StatusCode::TOO_MANY_REQUESTS,
        Error::Browser(_) | Error::Egress(_) => StatusCode::BAD_GATEWAY,
        Error::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        Error::ShuttingDown => StatusCode::SERVICE_UNAVAILABLE,
        Error::Storage(_) | Error::Crypto(_) | Error::Internal(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = status_of(&self.0);
        // Internal details stay in the logs; clients get the category only.
        let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self.0, "request failed with an internal error");
            "internal error".to_owned()
        } else {
            self.0.to_string()
        };
        let body = Json(json!({ "error": { "code": self.0.code(), "message": message } }));
        let mut response = (status, body).into_response();
        match self.0 {
            Error::Unauthorized => {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            }
            Error::Capacity(_) => {
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            }
            _ => {}
        }
        response
    }
}
