use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rusqlite::{Connection, Error as SqliteError};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::user::rule::{
    delete_rules, init_rule_db_from_file, insert_rule, list_rules, NewRule, Rule,
};

#[derive(Clone)]
pub struct UpdaterState {
    pub conn: Arc<Mutex<Connection>>,
}

pub const USER_UPDATER_PATH: &str = "/user/updater";

#[derive(Deserialize)]
struct DeleteRuleRequest {
    idxs: Vec<i64>,
}

#[derive(Serialize)]
struct AddRuleResponse {
    idx: i64,
}

#[derive(Serialize)]
struct DeleteRuleResponse {
    deleted: usize,
}

pub fn router(state: UpdaterState) -> Router {
    Router::new()
        .route(
            USER_UPDATER_PATH,
            get(list_rules_handler)
                .post(add_rule_handler)
                .delete(delete_rule_handler),
        )
        .with_state(state)
}

impl UpdaterState {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    pub fn from_db_path(db_path: impl AsRef<str>) -> Result<Self, SqliteError> {
        let conn = init_rule_db_from_file(db_path.as_ref())?;
        Ok(Self::new(conn))
    }
}

async fn list_rules_handler(
    State(state): State<UpdaterState>,
) -> Result<Json<Vec<Rule>>, (StatusCode, String)> {
    let conn = state.conn.lock().await;
    let rules = list_rules(&conn).map_err(server_error)?;
    Ok(Json(rules))
}

async fn add_rule_handler(
    State(state): State<UpdaterState>,
    Json(payload): Json<NewRule>,
) -> Result<Json<AddRuleResponse>, (StatusCode, String)> {
    let conn = state.conn.lock().await;
    let idx = insert_rule(&conn, &payload).map_err(server_error)?;

    Ok(Json(AddRuleResponse { idx }))
}

async fn delete_rule_handler(
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

fn server_error(err: rusqlite::Error) -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("policy db error: {err}"),
    )
}
