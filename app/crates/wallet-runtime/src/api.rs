use crate::runner::{Client, Command};
use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandBody {
    action: Command,
}
#[derive(Clone)]
pub struct ApiState {
    pub client: Client,
    pub token: String,
    pub authority: String,
    pub html: String,
}
pub fn router(state: ApiState) -> Router {
    let guard = LocalApiGuard {
        token: state.token.clone(),
        authority: state.authority.clone(),
    };
    protect_local_api(
        Router::new()
            .route("/", get(index))
            .route("/api/snapshot", get(snapshot))
            .route("/api/command", post(command))
            .route("/api/send", post(send))
            .route("/api/wallet", post(wallet))
            .route("/api/security", post(security))
            .route(
                "/api/privacy",
                post(privacy).layer(DefaultBodyLimit::max(16384)),
            )
            .route("/api/relationship", post(relationship))
            .route("/api/shutdown", post(shutdown))
            .layer(DefaultBodyLimit::max(1024))
            .with_state(state),
        guard,
    )
}
/// Shared loopback boundary for normal startup and the read-only failure screen.
#[derive(Clone)]
pub(crate) struct LocalApiGuard {
    pub token: String,
    pub authority: String,
}
pub(crate) fn protect_local_api(router: Router, guard: LocalApiGuard) -> Router {
    router.layer(middleware::from_fn_with_state(guard, local_guard))
}
async fn local_guard(State(state): State<LocalApiGuard>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    if headers.get(header::HOST).and_then(|v| v.to_str().ok()) != Some(state.authority.as_str())
        || headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v != format!("http://{}", state.authority))
        || headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("cross-site")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if request.uri().path().starts_with("/api/")
        && headers.get("x-lab-token").and_then(|v| v.to_str().ok()) != Some(state.token.as_str())
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("content-security-policy","default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'".parse().unwrap());
    response
}
async fn index(State(s): State<ApiState>) -> Html<String> {
    Html(s.html.replace("__LAB_TOKEN__", &s.token))
}
fn session(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-wallet-session")
        .and_then(|s| s.to_str().ok())
}
fn locked(error: &'static str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({"error":error}))).into_response()
}
async fn snapshot(State(s): State<ApiState>, headers: HeaderMap) -> Response {
    // Check access after taking the state snapshot: waiting for state must not
    // allow a session revoked in the meantime to expose wallet data.
    let mut snapshot = s.client.state.read().await.clone();
    let security = if let Some(security) = &s.client.security {
        Some(security.snapshot(session(&headers)).await)
    } else {
        None
    };
    if security.as_ref().is_some_and(|s| s.locked) {
        return Json(crate::runner::Snapshot {
            network: snapshot.network,
            phase: "Locked".into(),
            wallet_status: "Locked".into(),
            security,
            ..Default::default()
        })
        .into_response();
    }
    snapshot.security = security;
    snapshot.refresh_receive_status();
    Json(snapshot).into_response()
}
async fn command(
    State(s): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<CommandBody>,
) -> Response {
    let permit = match s.client.authorize(session(&headers)).await {
        Ok(p) => p,
        Err(e) => return locked(e),
    };
    match s.client.command_authorized(body.action, permit).await {
        Ok(()) => (StatusCode::ACCEPTED, Json(json!({"accepted":true}))).into_response(),
        Err(error) => (StatusCode::CONFLICT, Json(json!({"error":error}))).into_response(),
    }
}
async fn shutdown(State(s): State<ApiState>) -> Json<serde_json::Value> {
    s.client.shutdown.cancel();
    Json(json!({"stopping":true}))
}
async fn send(
    State(s): State<ApiState>,
    headers: HeaderMap,
    body: Result<Json<crate::send::SendCommand>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let permit = match s.client.authorize(session(&headers)).await {
        Ok(p) => p,
        Err(e) => return locked(e),
    };
    let Ok(Json(body)) = body else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Invalid payment request."})),
        )
            .into_response();
    };
    match s.client.send_authorized(body, permit).await {
        Ok(()) => (StatusCode::ACCEPTED, Json(json!({"accepted":true}))).into_response(),
        Err(error) => (StatusCode::CONFLICT, Json(json!({"error":error}))).into_response(),
    }
}
async fn wallet(
    State(s): State<ApiState>,
    headers: HeaderMap,
    body: Result<Json<crate::setup::SetupCommand>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let permit = match s.client.authorize(session(&headers)).await {
        Ok(p) => p,
        Err(e) => return locked(e),
    };
    let Ok(Json(command)) = body else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Invalid wallet setup request."})),
        )
            .into_response();
    };
    match s.client.setup_authorized(command, permit).await {
        Ok(reply) => Json(reply).into_response(),
        Err(error) => (StatusCode::CONFLICT, Json(json!({"error":error}))).into_response(),
    }
}
async fn security(
    State(s): State<ApiState>,
    headers: HeaderMap,
    body: Result<Json<crate::security::SecurityCommand>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(command)) = body else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Invalid security request."})),
        )
            .into_response();
    };
    match s.client.security_command(command, session(&headers)).await {
        Ok(reply) => Json(reply).into_response(),
        Err(error) => (StatusCode::CONFLICT, Json(json!({"error":error}))).into_response(),
    }
}
async fn privacy(
    State(s): State<ApiState>,
    headers: HeaderMap,
    body: Result<Json<crate::privacy::PrivacyCommand>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let permit = match s.client.authorize(session(&headers)).await {
        Ok(p) => p,
        Err(e) => return locked(e),
    };
    let Ok(Json(command)) = body else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Invalid privacy configuration."})),
        )
            .into_response();
    };
    match s.client.privacy_authorized(command, permit).await {
        Ok(reply) => Json(reply).into_response(),
        Err(error) => (StatusCode::CONFLICT, Json(json!({"error":error}))).into_response(),
    }
}
async fn relationship(
    State(s): State<ApiState>,
    headers: HeaderMap,
    body: Result<
        Json<crate::privacy::RelationshipCommand>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    let permit = match s.client.authorize(session(&headers)).await {
        Ok(p) => p,
        Err(e) => return locked(e),
    };
    let Ok(Json(command)) = body else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Enter a relationship name."})),
        )
            .into_response();
    };
    match s.client.relationship_authorized(command, permit).await {
        Ok(reply) => Json(reply).into_response(),
        Err(error) => (StatusCode::CONFLICT, Json(json!({"error":error}))).into_response(),
    }
}
