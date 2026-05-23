use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum Clearance {
    Public,
    #[default]
    Internal,
    Confidential,
    Restricted,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAction {
    Allow,
    Redact,
    Review,
    Block,
}

impl DecisionAction {
    pub fn rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Redact => 1,
            Self::Review => 2,
            Self::Block => 3,
        }
    }

    pub fn combine(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MaskingStrategy {
    Placeholder,
    PartialEmail,
    PartialPhone,
    KeepLast4,
    Hash,
    Tokenize,
    Full,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Request,
    Response,
}
