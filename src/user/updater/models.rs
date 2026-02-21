use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(super) struct DeleteRuleRequest {
    pub idxs: Vec<i64>,
}

#[derive(Serialize)]
pub(super) struct AddRuleResponse {
    pub idx: i64,
}

#[derive(Serialize)]
pub(super) struct DeleteRuleResponse {
    pub deleted: usize,
}

