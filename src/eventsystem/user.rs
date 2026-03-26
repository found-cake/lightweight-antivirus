#[derive(Debug, Clone)]
pub struct UserVerdict {
    pub op_id: u64,
    pub verdict: Verdict,
    pub reason_code: u32,
    pub ttl_ms: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Allow = 0,
    Deny = 1,
    Defer = 2,
}
