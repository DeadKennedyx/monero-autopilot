use crate::runner::{Client, Command};
use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
#[derive(Clone)]
pub struct ApiState {
    pub client: Client,
    pub token: String,
    pub authority: String,
    pub html: String,
}
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/snapshot", get(snapshot))
        .route("/api/command", post(command))
        .route("/api/shutdown", post(shutdown))
        .layer(DefaultBodyLimit::max(1024))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}
async fn guard(State(state): State<ApiState>, request: Request, next: Next) -> Response {
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
async fn snapshot(State(s): State<ApiState>) -> Response {
    Json(s.client.state.read().await.clone()).into_response()
}
async fn command(State(s): State<ApiState>, Json(command): Json<Command>) -> Response {
    match s.client.command(command) {
        Ok(()) => (StatusCode::ACCEPTED, Json(json!({"accepted":true}))).into_response(),
        Err(error) => (StatusCode::CONFLICT, Json(json!({"error":error}))).into_response(),
    }
}
async fn shutdown(State(s): State<ApiState>) -> Json<serde_json::Value> {
    s.client.shutdown.cancel();
    Json(json!({"stopping":true}))
}
