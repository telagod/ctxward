use axum::{
    http::header::{CACHE_CONTROL, HeaderValue},
    response::{Html, IntoResponse},
};

const ADMIN_CONSOLE_HTML: &str = include_str!("../assets/admin-console.html");

pub async fn admin_console() -> impl IntoResponse {
    (
        [(CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Html(ADMIN_CONSOLE_HTML),
    )
}
