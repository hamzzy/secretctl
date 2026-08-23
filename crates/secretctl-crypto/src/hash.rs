use sha2::{Digest, Sha256};

pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn compute_context_digest(components: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for item in components {
        hasher.update((item.len() as u64).to_be_bytes());
        hasher.update(item);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_digest() {
        let hash = sha256_digest(b"hello world");
        assert_eq!(hash.len(), 32);
    }
}
