use crate::error::DomainError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRequestState {
    Requested,
    PolicyEvaluating,
    AwaitingApproval,
    Approved,
    CapabilityIssued,
    Executing,
    Completed,
    Denied,
    Expired,
    Cancelled,
    Indeterminate,
    Revoked,
    Failed,
}

impl ActionRequestState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Denied
                | Self::Expired
                | Self::Cancelled
                | Self::Indeterminate
                | Self::Revoked
                | Self::Failed
        )
    }

    pub fn transition_to(
        &self,
        next: ActionRequestState,
    ) -> Result<ActionRequestState, DomainError> {
        if self.is_terminal() {
            return Err(DomainError::InvalidStateTransition {
                from: self.as_str(),
                to: next.as_str(),
            });
        }

        let valid = match (self, next) {
            (Self::Requested, Self::PolicyEvaluating) => true,
            (Self::PolicyEvaluating, Self::AwaitingApproval) => true,
            (Self::PolicyEvaluating, Self::Approved) => true,
            (Self::PolicyEvaluating, Self::Denied) => true,
            (Self::AwaitingApproval, Self::Approved) => true,
            (Self::AwaitingApproval, Self::Denied) => true,
            (Self::Approved, Self::CapabilityIssued) => true,
            (Self::CapabilityIssued, Self::Executing) => true,
            (Self::Executing, Self::Completed) => true,
            (Self::Executing, Self::Failed) => true,
            // Any active state can transition to Failed/Expired/Revoked
            (_, Self::Expired)
            | (_, Self::Cancelled)
            | (_, Self::Indeterminate)
            | (_, Self::Revoked)
            | (_, Self::Failed) => true,
            _ => false,
        };

        if valid {
            Ok(next)
        } else {
            Err(DomainError::InvalidStateTransition {
                from: self.as_str(),
                to: next.as_str(),
            })
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::PolicyEvaluating => "policy_evaluating",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Approved => "approved",
            Self::CapabilityIssued => "capability_issued",
            Self::Executing => "executing",
            Self::Completed => "completed",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Indeterminate => "indeterminate",
            Self::Revoked => "revoked",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Issued,
    Active,
    Consumed,
    Expired,
    Revoked,
}

impl CapabilityState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Consumed | Self::Expired | Self::Revoked)
    }

    pub fn transition_to(&self, next: CapabilityState) -> Result<CapabilityState, DomainError> {
        if self.is_terminal() {
            return Err(DomainError::InvalidStateTransition {
                from: self.as_str(),
                to: next.as_str(),
            });
        }

        let valid = match (self, next) {
            (Self::Issued, Self::Active) => true,
            (Self::Issued, Self::Consumed) => true,
            (Self::Active, Self::Consumed) => true,
            (_, Self::Expired) | (_, Self::Revoked) => true,
            _ => false,
        };

        if valid {
            Ok(next)
        } else {
            Err(DomainError::InvalidStateTransition {
                from: self.as_str(),
                to: next.as_str(),
            })
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserSessionState {
    Starting,
    Active,
    Stale,
    Terminated,
}

impl BrowserSessionState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminated)
    }

    pub fn transition_to(
        &self,
        next: BrowserSessionState,
    ) -> Result<BrowserSessionState, DomainError> {
        if self.is_terminal() {
            return Err(DomainError::InvalidStateTransition {
                from: self.as_str(),
                to: next.as_str(),
            });
        }

        let valid = match (self, next) {
            (Self::Starting, Self::Active) => true,
            (Self::Active, Self::Stale) => true,
            (Self::Stale, Self::Active) => true,
            (_, Self::Terminated) => true,
            _ => false,
        };

        if valid {
            Ok(next)
        } else {
            Err(DomainError::InvalidStateTransition {
                from: self.as_str(),
                to: next.as_str(),
            })
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Terminated => "terminated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Prepared,
    Consuming,
    Completed,
    Failed,
    Indeterminate,
}

impl ExecutionState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Indeterminate)
    }

    pub fn transition_to(&self, next: ExecutionState) -> Result<ExecutionState, DomainError> {
        if self.is_terminal() {
            return Err(DomainError::InvalidStateTransition {
                from: self.as_str(),
                to: next.as_str(),
            });
        }

        let valid = match (self, next) {
            (Self::Prepared, Self::Consuming) => true,
            (Self::Consuming, Self::Completed) => true,
            (Self::Consuming, Self::Failed) => true,
            (Self::Consuming, Self::Indeterminate) => true,
            (Self::Prepared, Self::Failed) => true,
            _ => false,
        };

        if valid {
            Ok(next)
        } else {
            Err(DomainError::InvalidStateTransition {
                from: self.as_str(),
                to: next.as_str(),
            })
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Consuming => "consuming",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_request_state_transitions() {
        let mut state = ActionRequestState::Requested;
        state = state
            .transition_to(ActionRequestState::PolicyEvaluating)
            .unwrap();
        state = state.transition_to(ActionRequestState::Approved).unwrap();
        state = state
            .transition_to(ActionRequestState::CapabilityIssued)
            .unwrap();
        state = state.transition_to(ActionRequestState::Executing).unwrap();
        state = state.transition_to(ActionRequestState::Completed).unwrap();
        assert!(state.is_terminal());

        // Cannot transition from terminal state
        assert!(state.transition_to(ActionRequestState::Requested).is_err());
    }

    #[test]
    fn test_capability_state_transitions() {
        let mut state = CapabilityState::Issued;
        state = state.transition_to(CapabilityState::Active).unwrap();
        state = state.transition_to(CapabilityState::Consumed).unwrap();
        assert!(state.is_terminal());

        assert!(state.transition_to(CapabilityState::Active).is_err());
    }
}
