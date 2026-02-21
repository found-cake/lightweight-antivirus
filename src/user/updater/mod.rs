use axum::Router;
use axum::routing::{delete, get, post};

mod handlers;
mod models;
mod state;
#[cfg(test)]
mod test;

pub use state::UpdaterState;

pub const USER_UPDATER_PATH: &str = "/user/updater";

/// Build user updater API routes.
/// Usage:
/// - GET /user/updater : 현재 규칙 목록 조회
/// - POST /user/updater: 새 규칙 추가
/// - DELETE /user/updater: idxs 배열 기반 규칙 삭제
///
/// Main 조립 예시:
/// ```
/// use crate::user::updater::{router, UpdaterState};
/// use crate::user::rule::init_rule_db_from_file;
/// use axum::Router;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let conn = init_rule_db_from_file("path/to/rules.db")?;
///     let updater_state = UpdaterState::new(conn);
///     let app = Router::new().merge(router(updater_state));
///     Ok(())
/// }
/// ```
pub fn router(state: UpdaterState) -> Router {
    Router::new()
        .route(
            USER_UPDATER_PATH,
            get(handlers::list_rules_handler)
                .post(handlers::add_rule_handler)
                .delete(handlers::delete_rule_handler),
        )
        .with_state(state)
}
