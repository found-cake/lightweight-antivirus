use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(crate) struct DeleteRuleRequest {
    pub idxs: Vec<i64>,
}

#[derive(Serialize, Debug)]
pub(crate) struct AddRuleResponse {
    pub idx: i64,
}

#[derive(Serialize, Debug)]
pub(crate) struct DeleteRuleResponse {
    pub deleted: usize,
}
