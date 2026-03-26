use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub idx: i64,
    pub name: String,
    pub pattern: String,
    pub pattern_type: PatternType,
    pub severity: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewRule {
    pub name: String,
    pub pattern: String,
    pub pattern_type: PatternType,
    pub severity: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternType {
    Exact,
    Contains,
    Regex,
    Hash,
    FilePath,
}

impl PatternType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Contains => "contains",
            Self::Regex => "regex",
            Self::Hash => "hash",
            Self::FilePath => "file_path",
        }
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            "exact" => Some(Self::Exact),
            "contains" => Some(Self::Contains),
            "regex" => Some(Self::Regex),
            "hash" => Some(Self::Hash),
            "file_path" => Some(Self::FilePath),
            _ => None,
        }
    }
}
