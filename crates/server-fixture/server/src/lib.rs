use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{Query, State},
    response::Html,
    routing::get,
};
use tower_http::trace::TraceLayer;

use futures::{AsyncRead, AsyncWrite, channel::oneshot};
use futures_rustls::{
    TlsAcceptor,
    pki_types::{CertificateDer, PrivateKeyDer},
    rustls::{
        ServerConfig,
        version::{TLS12, TLS13},
    },
};
use hyper::{
    Request, StatusCode,
    body::{Bytes, Incoming},
    server::conn::http1,
};
use hyper_util::rt::TokioIo;

use serde_json::Value;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tower_service::Service;

use axum::extract::FromRequest;
use hyper::header;

use tlsn_server_fixture_certs::*;
use tracing::info;

/// Re-exported so callers can name the type accepted by [`bind_with_versions`]
/// without depending on `futures-rustls` directly.
pub use futures_rustls::rustls::SupportedProtocolVersion;

pub const DEFAULT_FIXTURE_PORT: u16 = 3000;

struct AppState {
    shutdown: Option<oneshot::Sender<()>>,
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/bytes", get(bytes))
        .route("/formats/json", get(json))
        .route("/formats/html", get(html))
        .route("/protected", get(protected_route))
        .route("/elster", get(elster_route))
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::new(Mutex::new(state)))
}

/// TLS protocol versions the fixture server offers, in order of preference.
///
/// The negotiated version in proxy-mode e2e tests is driven by the *server*
/// (the proxy client offers both 1.3 and 1.2), so pinning these is how tests
/// keep both versions covered.
pub const BOTH_VERSIONS: &[&SupportedProtocolVersion] = &[&TLS13, &TLS12];
/// TLS 1.3 only — forces a 1.3 negotiation against a both-offering client.
pub const TLS13_ONLY: &[&SupportedProtocolVersion] = &[&TLS13];
/// TLS 1.2 only — forces a 1.2 negotiation against a both-offering client.
pub const TLS12_ONLY: &[&SupportedProtocolVersion] = &[&TLS12];

/// Bind the server to the given socket, offering **both** TLS 1.3 and 1.2.
///
/// Thin wrapper over [`bind_with_versions`] preserving the original behavior
/// for non-version-sensitive callers (the negotiated version is then driven by
/// the client's preference / the server's default).
pub async fn bind<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    socket: T,
) -> anyhow::Result<()> {
    bind_with_versions(socket, BOTH_VERSIONS).await
}

/// Bind the server to the given socket, pinning the offered TLS protocol
/// versions.
///
/// Use the [`BOTH_VERSIONS`] / [`TLS13_ONLY`] / [`TLS12_ONLY`] constants (or
/// any slice of [`futures_rustls::rustls::version`] constants) to control which
/// version is negotiated when the proxy client offers both (parent spec §2).
pub async fn bind_with_versions<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    socket: T,
    versions: &[&'static SupportedProtocolVersion],
) -> anyhow::Result<()> {
    let key = PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into());
    let cert = CertificateDer::from(SERVER_CERT_DER);

    // No TLS-layer client authentication. Previously this server installed an
    // optional (`allow_unauthenticated`) `WebPkiClientVerifier`, which makes a
    // TLS 1.3 server emit a `CertificateRequest`. tlsn proxy mode rejects
    // `CertificateRequest` in TLS 1.3 by design (parent spec §6.5 / non-goals:
    // in-handshake client authentication changes the Finished transcript and is
    // out of scope for v1), so an optional-client-auth server is not a valid
    // 1.3 target. No proxy/MPC test presents a client certificate, and rustls
    // clients only send one in response to a `CertificateRequest`, so dropping
    // it is behavior-preserving for the existing 1.2 callers and the MPC
    // example (whose configured client cert simply goes unused).
    let config = ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let conn = acceptor.accept(socket).await?;

    let io = TokioIo::new(conn.compat());

    let (sender, receiver) = oneshot::channel();
    let state = AppState {
        shutdown: Some(sender),
    };
    let tower_service = app(state);

    let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
        tower_service.clone().call(request)
    });

    tokio::select! {
        _ = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(io, hyper_service) => {},
        _ = receiver => {},
    }

    Ok(())
}

async fn bytes(
    State(state): State<Arc<Mutex<AppState>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Bytes, StatusCode> {
    info!("Handling /bytes with params: {:?}", params);

    let size = params
        .get("size")
        .and_then(|size| size.parse::<usize>().ok())
        .unwrap_or(1);

    if params.contains_key("shutdown") {
        _ = state.lock().unwrap().shutdown.take().unwrap().send(());
    }

    Ok(Bytes::from(vec![0x42u8; size]))
}

/// parse the JSON data from the file content
fn get_json_value(filecontent: &str) -> Result<Json<Value>, StatusCode> {
    Ok(Json(serde_json::from_str(filecontent).map_err(|e| {
        eprintln!("Failed to parse JSON data: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

async fn json(
    State(state): State<Arc<Mutex<AppState>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    info!("Handling /json with params: {:?}", params);

    let size = params
        .get("size")
        .and_then(|size| size.parse::<usize>().ok())
        .unwrap_or(1);

    if params.contains_key("shutdown") {
        _ = state.lock().unwrap().shutdown.take().unwrap().send(());
    }

    match size {
        1 => get_json_value(include_str!("data/1kb.json")),
        4 => get_json_value(include_str!("data/4kb.json")),
        8 => get_json_value(include_str!("data/8kb.json")),
        _ => Err(StatusCode::NOT_FOUND),
    }
}

async fn html(
    State(state): State<Arc<Mutex<AppState>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Html<&'static str> {
    info!("Handling /html with params: {:?}", params);

    if params.contains_key("shutdown") {
        _ = state.lock().unwrap().shutdown.take().unwrap().send(());
    }

    Html(include_str!("data/4kb.html"))
}

struct AuthenticatedUser;

impl<B> FromRequest<B> for AuthenticatedUser
where
    B: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(
        req: axum::extract::Request,
        _state: &B,
    ) -> Result<Self, Self::Rejection> {
        // Expected token (hardcoded for simplicity in the demo)
        let expected_token = "random_auth_token";

        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());

        if let Some(auth_token) = auth_header {
            let token = auth_token.trim_start_matches("Bearer ");
            if token == expected_token {
                return Ok(AuthenticatedUser);
            }
        }

        Err((StatusCode::UNAUTHORIZED, "Invalid or missing token"))
    }
}

async fn protected_route(_: AuthenticatedUser) -> Result<Json<Value>, StatusCode> {
    info!("Handling /protected");

    get_json_value(include_str!("data/protected_data.json"))
}

async fn elster_route(_: AuthenticatedUser) -> Result<Json<Value>, StatusCode> {
    info!("Handling /elster");

    get_json_value(include_str!("data/elster.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    fn get_app() -> Router {
        let (sender, _) = oneshot::channel();
        let state = AppState {
            shutdown: Some(sender),
        };
        app(state)
    }

    #[tokio::test]
    async fn hello_world() {
        let response = get_app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Hello, World!");
    }

    #[tokio::test]
    async fn json() {
        let response = get_app()
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/formats/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body.get("id").unwrap().as_number().unwrap().as_u64(),
            Some(1234567890)
        );
    }
}
