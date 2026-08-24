pub mod chain;
pub mod error;
pub mod events;

pub use chain::{
    GENESIS_PREVIOUS_HASH, compute_event_hash, create_audit_event, verify_audit_chain,
};
pub use error::AuditError;
pub use events::{AuditContext, validate_audit_payload};
