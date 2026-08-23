use crate::model::PolicyDocument;
use sha2::{Digest, Sha256};

pub fn compute_policy_hash(doc: &PolicyDocument) -> Vec<u8> {
    let serialized = serde_json::to_vec(doc).expect("valid policy document serialization");
    let mut hasher = Sha256::new();
    hasher.update(&serialized);
    hasher.finalize().to_vec()
}
