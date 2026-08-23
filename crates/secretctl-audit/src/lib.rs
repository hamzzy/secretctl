pub mod chain;
pub mod error;
pub mod events;

pub use chain::{compute_event_hash, create_audit_event, verify_audit_chain, GENESIS_PREVIOUS_HASH};
pub use error::AuditError;
pub use events::{validate_audit_payload, AuditContext};
