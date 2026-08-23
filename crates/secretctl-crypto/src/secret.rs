use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret bytes buffer that zeroizes its memory upon drop.
/// Intentionally does NOT implement `Debug`, `Display`, `Serialize`, `Deserialize`, or `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    data: Vec<u8>,
}

impl SecretBytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED])")
    }
}

/// Secret string buffer that zeroizes its memory upon drop.
/// Intentionally does NOT implement `Debug`, `Display`, `Serialize`, `Deserialize`, or `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretString {
    data: String,
}

impl SecretString {
    pub fn new(data: String) -> Self {
        Self { data }
    }

    pub fn as_str(&self) -> &str {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_debug_redacted() {
        let secret = SecretBytes::new(b"sensitive_password_123".to_vec());
        let debug_str = format!("{:?}", secret);
        assert_eq!(debug_str, "SecretBytes([REDACTED])");
        assert!(!debug_str.contains("sensitive"));

        let secret_str = SecretString::new("super_secret_token".to_string());
        let debug_str = format!("{:?}", secret_str);
        assert_eq!(debug_str, "SecretString([REDACTED])");
        assert!(!debug_str.contains("super_secret"));
    }
}
