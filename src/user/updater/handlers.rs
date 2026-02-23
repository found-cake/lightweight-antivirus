use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::Html;
use rusqlite::Error as SqliteError;

use crate::user::rule::{delete_rules, insert_rule, list_rules, NewRule, Rule};
use crate::user::updater::state::UpdaterState;

use super::models::{
    AddRuleResponse, DeleteRuleRequest, DeleteRuleResponse,
};
use super::page::POLICY_PAGE;

pub(super) async fn list_rules_handler(
    State(state): State<UpdaterState>,
) -> Result<Json<Vec<Rule>>, (StatusCode, String)> {
    let conn = state.conn.lock().await;
    let rules = list_rules(&conn).map_err(server_error)?;
    Ok(Json(rules))
}

pub(super) async fn add_rule_handler(
    State(state): State<UpdaterState>,
    Json(payload): Json<NewRule>,
) -> Result<Json<AddRuleResponse>, (StatusCode, String)> {
    let conn = state.conn.lock().await;
    let idx = insert_rule(&conn, &payload).map_err(server_error)?;

    Ok(Json(AddRuleResponse { idx }))
}

pub(super) async fn delete_rule_handler(
    State(state): State<UpdaterState>,
    Json(payload): Json<DeleteRuleRequest>,
) -> Result<Json<DeleteRuleResponse>, (StatusCode, String)> {
    if payload.idxs.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "idxs is required".to_string()));
    }

    let mut conn = state.conn.lock().await;
    let deleted = delete_rules(&mut conn, &payload.idxs).map_err(server_error)?;
    Ok(Json(DeleteRuleResponse { deleted }))
}

pub(super) async fn policy_page_handler() -> Html<&'static str> {
    Html(POLICY_PAGE)
}

fn server_error(err: SqliteError) -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("policy db error: {err}"),
    )
}
