mod page;
mod handlers;
mod state;
mod models;
#[cfg(test)]
mod test;

use axum::Router;

pub use crate::user::rule::{init_rule_db, init_rule_db_from_file};
pub use crate::user::rule::{delete_rules, insert_rule, list_rules};
pub use crate::user::rule::{NewRule, PatternType, Rule};
pub use state::UpdaterState;

pub const USER_UPDATER_PATH: &str = "/user/updater";
pub const USER_UPDATER_PAGE_PATH: &str = "/user/updater/page";

/// Build user updater API routes.
/// Usage:
/// - GET /user/updater : 현재 규칙 목록 조회
/// - POST /user/updater: 새 규칙 추가
/// - DELETE /user/updater: idxs 배열 기반 규칙 삭제
/// - GET /user/updater/page : 정책 추가/삭제 프론트엔드 페이지
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
    use axum::routing::{delete, get, post};

    Router::new()
        .route(
            USER_UPDATER_PATH,
            get(handlers::list_rules_handler)
                .post(handlers::add_rule_handler)
                .delete(handlers::delete_rule_handler),
        )
        .route(
            USER_UPDATER_PAGE_PATH,
            get(handlers::policy_page_handler),
        )
        .with_state(state)
}
