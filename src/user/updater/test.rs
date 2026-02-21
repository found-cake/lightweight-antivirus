use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use rusqlite::Connection;

use crate::user::rule::{NewRule, PatternType, init_rule_db};

use super::handlers::{add_rule_handler, delete_rule_handler, list_rules_handler};
use super::models::{AddRuleResponse, DeleteRuleRequest, DeleteRuleResponse};
use super::state::UpdaterState;

fn build_state() -> UpdaterState {
    let conn = Connection::open_in_memory().unwrap();
    init_rule_db(&conn).unwrap();
    UpdaterState::new(conn)
}

fn sample_rule(name: &'static str, pattern: &'static str, pattern_type: PatternType) -> NewRule {
    NewRule {
        name: name.into(),
        pattern: pattern.into(),
        pattern_type,
        severity: 50,
    }
}

#[tokio::test]
async fn list_rules_handler_returns_empty_by_default() {
    let state = build_state();
    let Json(rules) = list_rules_handler(State(state)).await.unwrap();
    assert!(rules.is_empty());
}

#[tokio::test]
async fn add_rule_handler_inserts_and_returns_idx() {
    let state = build_state();

    let new_rule = sample_rule("scan", "abc", PatternType::Exact);
    let add_payload = Json(new_rule);

    let Json(added): Json<AddRuleResponse> = add_rule_handler(State(state.clone()), add_payload)
        .await
        .unwrap();
    assert_eq!(added.idx, 1);

    let Json(rules) = list_rules_handler(State(state)).await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "scan");
    assert_eq!(rules[0].pattern, "abc");
    assert_eq!(rules[0].pattern_type, PatternType::Exact);
}

#[tokio::test]
async fn delete_rule_handler_returns_bad_request_for_empty_idxs() {
    let state = build_state();
    let req = Json(DeleteRuleRequest { idxs: vec![] });

    let err = delete_rule_handler(State(state), req).await;
    match err {
        Ok(_) => panic!("should return bad request"),
        Err((status, msg)) => {
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(msg, "idxs is required");
        }
    }
}

#[tokio::test]
async fn delete_rule_handler_removes_existing_indices() {
    let state = build_state();

    let first = {
        let payload = Json(sample_rule("first", "a*", PatternType::Contains));
        let Json(res): Json<AddRuleResponse> = add_rule_handler(State(state.clone()), payload)
            .await
            .unwrap();
        res.idx
    };

    let second = {
        let payload = Json(sample_rule("second", "b*", PatternType::Contains));
        let Json(res): Json<AddRuleResponse> = add_rule_handler(State(state.clone()), payload)
            .await
            .unwrap();
        res.idx
    };

    let req = Json(DeleteRuleRequest { idxs: vec![first] });
    let Json(deleted): Json<DeleteRuleResponse> = delete_rule_handler(State(state.clone()), req)
        .await
        .unwrap();
    assert_eq!(deleted.deleted, 1);

    let Json(remaining) = list_rules_handler(State(state)).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].idx, second);
    assert_eq!(remaining[0].name, "second");
}
