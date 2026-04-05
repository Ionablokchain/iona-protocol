//! HTTP and WebSocket router for the JSON-RPC server.

use axum::{
    extract::{State, WebSocketUpgrade},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use prometheus::Encoder;
use std::net::SocketAddr;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, limit::RequestBodyLimitLayer, trace::TraceLayer,
};
use tracing::info;

use crate::rpc::eth_rpc::{handle_rpc, EthRpcState};

/// Configuration for the RPC server.
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Address to bind to (e.g., "0.0.0.0:8545").
    pub listen_addr: SocketAddr,
    /// If true, CORS allows any origin (use only for development).
    pub cors_allow_all: bool,
    /// List of allowed origins when CORS is restricted.
    pub allowed_origins: Vec<String>,
    /// Optional API key for protected endpoints (e.g., /faucet).
    pub api_key: Option<String>,
    /// Maximum request body size in bytes (default 10 MiB).
    pub max_body_bytes: usize,
    /// Rate limit: requests per second per IP.
    pub requests_per_second: u64,
    /// Rate limit: burst size.
    pub burst_size: u32,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8545".parse().expect("valid socket addr literal"),
            cors_allow_all: false,
            allowed_origins: vec![],
            api_key: None,
            max_body_bytes: 10 * 1024 * 1024,
            requests_per_second: 50,
            burst_size: 100,
        }
    }
}

/// Build the Axum router with all middleware and routes.
pub fn build_router(state: EthRpcState, config: &RpcConfig) -> Router {
    let cors = if config.cors_allow_all {
        CorsLayer::permissive()
    } else {
        let mut cors = CorsLayer::new()
            .allow_methods([Method::POST, Method::GET])
            .allow_headers([header::CONTENT_TYPE]);

        if !config.allowed_origins.is_empty() {
            cors = cors.allow_origin(
                config
                    .allowed_origins
                    .iter()
                    .filter_map(|s| s.parse::<http::HeaderValue>().ok())
                    .collect::<Vec<_>>(),
            );
        }

        cors
    };

    let governor_conf = GovernorConfigBuilder::default()
        .per_second(config.requests_per_second)
        .burst_size(config.burst_size)
        .finish()
        .expect("invalid rate limit configuration");

    let governor_layer = GovernorLayer {
        config: std::sync::Arc::new(governor_conf),
    };

    let router = Router::new()
        .route("/rpc", post(handle_rpc))
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/ws", get(ws_handler))
        .with_state(state);

    let router = router
        .layer(cors)
        .layer(governor_layer)
        .layer(RequestBodyLimitLayer::new(config.max_body_bytes))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http());

    if config.api_key.is_some() {
        let auth = axum::middleware::from_fn(crate::rpc::middleware::auth_api_key);
        router.route("/faucet", post(faucet_handler).layer(auth))
    } else {
        router
    }
}

/// Health check handler.
async fn health_handler() -> &'static str {
    "ok"
}

/// Prometheus metrics handler.
async fn metrics_handler() -> String {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];

    encoder
        .encode(&metric_families, &mut buffer)
        .expect("prometheus encode failed");

    String::from_utf8(buffer).unwrap_or_else(|_| String::from("invalid utf8"))
}

/// WebSocket upgrade handler (for subscriptions).
async fn ws_handler(ws: WebSocketUpgrade, State(state): State<EthRpcState>) -> Response {
    ws.on_upgrade(|socket| handle_websocket(socket, state))
}

async fn handle_websocket(_socket: axum::extract::ws::WebSocket, _state: EthRpcState) {
    info!("WebSocket connection opened");
}

/// Faucet handler (example protected endpoint).
async fn faucet_handler() -> impl IntoResponse {
    (StatusCode::OK, "Faucet not implemented")
}

/// Run the RPC server with graceful shutdown.
pub async fn run_server(state: EthRpcState, config: RpcConfig) -> anyhow::Result<()> {
    let app = build_router(state, &config);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;

    info!("RPC server listening on {}", config.listen_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};

        let mut signal =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        signal.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutting down RPC server");
}

/// Simple compatibility wrapper used elsewhere in the codebase.
pub async fn serve(
    state: crate::rpc::eth_rpc::EthRpcState,
    addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/", post(crate::rpc::eth_rpc::handle_rpc))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_endpoint() {
        let state = EthRpcState::default();
        let config = RpcConfig::default();
        let app = build_router(state, &config);

        let mut req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .expect("RPC error");

        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:12345".parse::<SocketAddr>().expect("RPC error"),
        ));

        let response = app.oneshot(req).await.expect("RPC error");

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("RPC error");

        assert_eq!(body, "ok");
    }

    #[test]
    fn test_build_router_with_api_key() {
        let state = EthRpcState::default();
        let config = RpcConfig {
            api_key: Some("secret".into()),
            ..Default::default()
        };

        let _app = build_router(state, &config);
    }
}
