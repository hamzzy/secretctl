const PROHIBITED_KEYS: &[&str] = &[
    "password",
    "secret",
    "token",
    "cookie",
    "authorization",
    "totp_code",
    "seed",
    "value",
];

pub fn contains_prohibited_key_name(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    for prohibited in PROHIBITED_KEYS {
        if lower == *prohibited || lower.contains(prohibited) {
            // Exceptions: permitted non-secret suffixes/prefixes like "_id", "_hash", "_at", "_count"
            if lower.ends_with("_id")
                || lower.ends_with("_hash")
                || lower.ends_with("_digest")
                || lower.ends_with("_at")
                || lower.ends_with("_count")
                || lower.ends_with("_ms")
                || lower.ends_with("_seconds")
            {
                continue;
            }
            return true;
        }
    }
    false
}

pub fn sanitize_error_message(message: &str) -> String {
    // Redact any patterns resembling credentials or tokens
    let mut sanitized = message.to_string();
    for prohibited in PROHIBITED_KEYS {
        if sanitized.to_ascii_lowercase().contains(prohibited) {
            sanitized = format!("[REDACTED_SECURITY_ERROR]");
            break;
        }
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prohibited_keys() {
        assert!(contains_prohibited_key_name("password"));
        assert!(contains_prohibited_key_name("user_secret"));
        assert!(contains_prohibited_key_name("auth_token"));
        assert!(!contains_prohibited_key_name("token_hash"));
        assert!(!contains_prohibited_key_name("credential_id"));
    }
}
