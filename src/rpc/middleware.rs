//! Axum middleware for RPC hardening.
//!
//! Layers applied (outermost → innermost, i.e. first to last in request flow):
//!   1. `request_id`      — inject X-Request-ID; add to tracing span
//!   2. `header_size`     — reject requests with oversized header blocks (8 KiB)
//!   3. `read_limit`      — rate-limit GET/HEAD requests per IP
//!   4. `concurrency`     — reject when MAX_CONCURRENT_REQUESTS is reached
//!   5. `body_limit`      — reject oversized bodies before deserialization (Content-Length)
//!   6. `json_depth`      — reject POST bodies with JSON nesting depth > MAX_JSON_DEPTH
//!
//! All middleware that needs the limiter extracts it via
//! `axum::extract::Extension<Arc<RpcLimiter>>`, which is inserted by
//! `.layer(Extension(limiter.clone()))` placed outer to these middleware.
//!
//! Router setup (iona-node.rs):
//! ```ignore
//! let limiter = Arc::new(RpcLimiter::new(config));
//! let router = Router::new()
//!     /* … routes … */
//!     .with_state(app.clone())
//!     .layer(middleware::from_fn(json_depth_middleware))
//!     .layer(middleware::from_fn(body_limit_middleware))
//!     .layer(middleware::from_fn(concurrency_middleware))
//!     .layer(middleware::from_fn(read_limit_middleware))
//!     .layer(Extension(limiter.clone()))
//!     .layer(middleware::from_fn(header_size_middleware))
//!     .layer(middleware::from_fn(request_id_middleware))
//!     .layer(CorsLayer::…);
//! ```

use axum::{
    body::Body,
    extract::{ConnectInfo, Extension, Request},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::warn;

use crate::rpc_limits::{new_request_id, RpcLimitResult, RpcLimiter, MAX_BODY_BYTES};

// -----------------------------------------------------------------------------
// Constants (can be overridden by config)
// -----------------------------------------------------------------------------

/// Maximum total byte size of all request headers combined.
pub const DEFAULT_MAX_HEADER_BYTES: usize = 8_192;

/// Maximum JSON object/array nesting depth accepted in POST bodies.
pub const DEFAULT_MAX_JSON_DEPTH: usize = 32;

/// Configuration for the middleware.
#[derive(Debug, Clone)]
pub struct RpcMiddlewareConfig {
    pub max_header_bytes: usize,
    pub max_json_depth: usize,
}

impl Default for RpcMiddlewareConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_json_depth: DEFAULT_MAX_JSON_DEPTH,
        }
    }
}

// -----------------------------------------------------------------------------
// X-Request-ID middleware
// -----------------------------------------------------------------------------

/// Middleware that injects a unique `X-Request-ID` into every request/response.
/// Also creates a tracing span so all log lines inside the handler carry the ID.
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let req_id = new_request_id();
    req.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&req_id).unwrap_or_else(|_| HeaderValue::from_static("bad-id")),
    );

    let span = tracing::info_span!("rpc_request", req_id = %req_id);
    let _guard = span.enter();

    let mut response = next.run(req).await;

    // Echo the request-ID back in the response so clients can correlate.
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&req_id).unwrap_or_else(|_| HeaderValue::from_static("bad-id")),
    );

    response
}

// -----------------------------------------------------------------------------
// Header-size guard middleware
// -----------------------------------------------------------------------------

/// Middleware that rejects requests whose combined header block exceeds the configured limit.
pub async fn header_size_middleware(
    Extension(config): Extension<Arc<RpcMiddlewareConfig>>,
    req: Request,
    next: Next,
) -> Response {
    let total: usize = req
        .headers()
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len() + 4) // name + ": " + value + "\r\n"
        .sum();

    if total > config.max_header_bytes {
        let req_id = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();
        warn!(
            req_id = %req_id,
            header_bytes = total,
            max = config.max_header_bytes,
            "rpc::middleware: header block too large"
        );

        // Increment metric
        if let Some(limiter) = req.extensions().get::<Arc<RpcLimiter>>() {
            limiter.metric_headers_too_large.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        return (
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            [("x-request-id", req_id.as_str())],
            r#"{"error":{"code":"HEADERS_TOO_LARGE","message":"request headers exceed size limit"}}"#,
        )
            .into_response();
    }

    next.run(req).await
}

// -----------------------------------------------------------------------------
// Read rate-limit middleware
// -----------------------------------------------------------------------------

/// Extract the client IP address from the request (X-Forwarded-For or ConnectInfo).
fn get_client_ip(req: &Request) -> Option<std::net::IpAddr> {
    // Try X-Forwarded-For (first IP in the list)
    if let Some(ips) = req.headers().get("x-forwarded-for") {
        if let Ok(ips_str) = ips.to_str() {
            if let Some(first) = ips_str.split(',').next() {
                if let Ok(ip) = first.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }

    // Fallback to ConnectInfo (axum's built-in)
    if let Some(ci) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return Some(ci.0.ip());
    }

    None
}

/// Middleware that applies `check_read()` to every GET/HEAD request.
pub async fn read_limit_middleware(
    limiter: Extension<Arc<RpcLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    if req.method() == Method::GET || req.method() == Method::HEAD {
        let req_id = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        if let Some(ip) = get_client_ip(&req) {
            match limiter.check_read(ip, &req_id) {
                RpcLimitResult::Allowed => {}
                _ => {
                    warn!(req_id = %req_id, %ip, "rpc::middleware: read rate limit exceeded");
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        [
                            ("x-request-id", req_id.as_str()),
                            ("retry-after", "1"),
                        ],
                        r#"{"error":{"code":"RATE_LIMITED","message":"read rate limit exceeded"}}"#,
                    )
                        .into_response();
                }
            }
        }
    }

    next.run(req).await
}

// -----------------------------------------------------------------------------
// Global concurrency cap middleware
// -----------------------------------------------------------------------------

/// Middleware that enforces the global concurrent-request cap.
pub async fn concurrency_middleware(
    limiter: Extension<Arc<RpcLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    let req_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let _ticket = match limiter.try_concurrency_slot(&req_id) {
        Some(t) => t,
        None => {
            warn!(req_id = %req_id, "rpc::middleware: concurrency limit reached");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [
                    ("x-request-id", req_id.as_str()),
                    ("retry-after", "1"),
                ],
                r#"{"error":{"code":"OVERLOADED","message":"server at capacity"}}"#,
            )
                .into_response();
        }
    };

    next.run(req).await
}

// -----------------------------------------------------------------------------
// Body-size guard middleware
// -----------------------------------------------------------------------------

/// Middleware that enforces MAX_BODY_BYTES via the Content-Length header.
pub async fn body_limit_middleware(
    limiter: Extension<Arc<RpcLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    let req_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    if let Some(cl) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    {
        if cl > MAX_BODY_BYTES {
            limiter
                .metric_payload_too_large
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            warn!(
                req_id = %req_id,
                content_length = cl,
                max = MAX_BODY_BYTES,
                "rpc::middleware: body too large (content-length check)"
            );
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                [("x-request-id", req_id.as_str())],
                r#"{"error":{"code":"PAYLOAD_TOO_LARGE","message":"request body exceeds limit"}}"#,
            )
                .into_response();
        }
    }

    next.run(req).await
}

// -----------------------------------------------------------------------------
// JSON nesting-depth guard middleware
// -----------------------------------------------------------------------------

/// Middleware that collects the request body (bounded by MAX_BODY_BYTES + 1)
/// and rejects it if the JSON nesting depth exceeds the configured limit.
pub async fn json_depth_middleware(
    Extension(config): Extension<Arc<RpcMiddlewareConfig>>,
    limiter: Extension<Arc<RpcLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    let is_json_post = {
        let method_ok = matches!(
            req.method(),
            &Method::POST | &Method::PUT | &Method::PATCH
        );
        let ct_ok = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("application/json"))
            .unwrap_or(false);
        method_ok && ct_ok
    };

    if !is_json_post {
        return next.run(req).await;
    }

    let req_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Collect body (bounded: MAX_BODY_BYTES + 1 so we detect over-limit here too).
    let (parts, body) = req.into_parts();
    let bytes: Bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES + 1).await {
        Ok(b) => b,
        Err(_) => {
            limiter.metric_payload_too_large.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                [("x-request-id", req_id.as_str())],
                r#"{"error":{"code":"PAYLOAD_TOO_LARGE","message":"body collection failed or too large"}}"#,
            )
                .into_response();
        }
    };

    let depth = json_nesting_depth(&bytes);
    if depth > config.max_json_depth {
        warn!(
            req_id = %req_id,
            json_depth = depth,
            max = config.max_json_depth,
            "rpc::middleware: JSON nesting depth exceeded"
        );
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            [("x-request-id", req_id.as_str())],
            r#"{"error":{"code":"JSON_TOO_DEEP","message":"JSON nesting depth exceeds limit"}}"#,
        )
            .into_response();
    }

    // Re-assemble request with collected body.
    let req = Request::from_parts(parts, Body::from(bytes));
    next.run(req).await
}

/// Count the maximum JSON nesting depth of a byte slice without full parsing.
/// Strings are skipped (including escaped braces/brackets inside them).
/// Returns 0 for empty or non-JSON input.
pub fn json_nesting_depth(bytes: &[u8]) -> usize {
    let mut depth: usize = 0;
    let mut max_depth: usize = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for &b in bytes {
        if escape_next {
            escape_next = false;
            continue;
        }
        if in_string {
            match b {
                b'\\' => escape_next = true,
                b'"' => in_string = false,
                _ => {}
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > max_depth {
                        max_depth = depth;
                    }
                }
                b'}' | b']' => {
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
    }

    max_depth
}

// -----------------------------------------------------------------------------
// Safe error response helper
// -----------------------------------------------------------------------------

/// Build a structured, opaque error response with no internal details.
pub fn error_response(status: StatusCode, code: &str, req_id: &str) -> Response {
    let body = format!(r#"{{"error":{{"code":"{code}","request_id":"{req_id}"}}}}"#);
    (
        status,
        [
            ("content-type", "application/json"),
            ("x-request-id", req_id),
        ],
        body,
    )
        .into_response()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get, Extension};
    use http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    // Dummy handler for testing.
    async fn dummy_handler() -> &'static str {
        "ok"
    }

    #[test]
    fn test_json_nesting_depth() {
        // Simple object
        let json = br#"{"a":1}"#;
        assert_eq!(json_nesting_depth(json), 1);

        // Nested object
        let json = br#"{"a":{"b":2}}"#;
        assert_eq!(json_nesting_depth(json), 2);

        // Array inside object
        let json = br#"{"a":[1,2,3]}"#;
        assert_eq!(json_nesting_depth(json), 2);

        // Deep nesting
        let json = br#"{"a":{"b":{"c":{"d":4}}}}"#;
        assert_eq!(json_nesting_depth(json), 4);

        // Strings with braces should be ignored
        let json = br#"{"a":"{\"b\":2}"}"#;
        assert_eq!(json_nesting_depth(json), 1);

        // Empty input
        assert_eq!(json_nesting_depth(b""), 0);

        // Non‑JSON
        assert_eq!(json_nesting_depth(b"hello"), 0);
    }

    #[tokio::test]
    async fn test_request_id_middleware() {
        let app = Router::new()
            .route("/", get(dummy_handler))
            .layer(axum::middleware::from_fn(request_id_middleware));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("x-request-id"));
    }

    #[tokio::test]
    async fn test_header_size_middleware() {
        let config = Arc::new(RpcMiddlewareConfig::default());
        let app = Router::new()
            .route("/", get(dummy_handler))
            .layer(axum::middleware::from_fn(header_size_middleware))
            .layer(Extension(config));

        // Create a request with oversized headers.
        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let large_header = "x".repeat(DEFAULT_MAX_HEADER_BYTES + 1);
        req.headers_mut().insert("x-large", HeaderValue::from_str(&large_header).unwrap());

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_json_depth_middleware() {
        let config = Arc::new(RpcMiddlewareConfig::default());
        let limiter = Arc::new(RpcLimiter::new()); // must be defined elsewhere
        let app = Router::new()
            .route("/", get(dummy_handler))
            .layer(axum::middleware::from_fn(json_depth_middleware))
            .layer(Extension(config))
            .layer(Extension(limiter));

        // Deep JSON (max depth 32, we send 33)
        let deep_json = format!("{}", "{\"a\":".repeat(33) + "1" + "}".repeat(33));
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(deep_json))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
