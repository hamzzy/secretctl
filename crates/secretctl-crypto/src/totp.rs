use crate::error::CryptoError;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

pub struct TotpGenerator {
    period_seconds: u64,
    digits: u32,
}

impl TotpGenerator {
    pub fn new() -> Self {
        Self {
            period_seconds: 30,
            digits: 6,
        }
    }

    pub fn with_digits(digits: u32) -> Self {
        Self {
            period_seconds: 30,
            digits,
        }
    }

    pub fn with_period_seconds(mut self, period_seconds: u64) -> Self {
        self.period_seconds = period_seconds;
        self
    }

    pub fn compute_time_step(&self, unix_time_seconds: u64) -> (u64, u64) {
        let time_step = unix_time_seconds / self.period_seconds;
        let seconds_remaining = self.period_seconds - (unix_time_seconds % self.period_seconds);
        (time_step, seconds_remaining)
    }

    pub fn generate(
        &self,
        seed: &[u8],
        unix_time_seconds: u64,
    ) -> Result<(String, u64), CryptoError> {
        let (time_step, seconds_remaining) = self.compute_time_step(unix_time_seconds);

        // Security requirement: Must have at least 2 seconds remaining in the time step
        if seconds_remaining < 2 {
            return Err(CryptoError::SessionExpired);
        }

        let mut mac = HmacSha1::new_from_slice(seed)
            .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;

        mac.update(&time_step.to_be_bytes());
        let result = mac.finalize().into_bytes();

        let offset = (result[19] & 0x0f) as usize;
        let binary = ((result[offset] as u32 & 0x7f) << 24)
            | ((result[offset + 1] as u32 & 0xff) << 16)
            | ((result[offset + 2] as u32 & 0xff) << 8)
            | (result[offset + 3] as u32 & 0xff);

        let modulus = 10u32.pow(self.digits);
        let otp = binary % modulus;

        let formatted = format!("{:0width$}", otp, width = self.digits as usize);
        Ok((formatted, time_step))
    }
}

impl Default for TotpGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc6238_totp_generation() {
        let seed = b"12345678901234567890"; // Standard RFC test secret (20 bytes)
        let generator = TotpGenerator::new();

        // Test at t = 59s (time_step = 1, seconds_remaining = 1) -> should fail margin check
        assert!(generator.generate(seed, 59).is_err());

        // Test at t = 30s (time_step = 1, seconds_remaining = 30) -> should produce 6-digit code
        let (code, time_step) = generator.generate(seed, 30).unwrap();
        assert_eq!(time_step, 1);
        assert_eq!(code, "287082");
        assert!(code.chars().all(|c| c.is_ascii_digit()));

        // RFC 6238's next SHA-1 vector (T=59) is intentionally rejected by
        // the two-second safety margin, while the following step is valid.
        let (next_code, next_step) = generator.generate(seed, 60).unwrap();
        assert_eq!(next_step, 2);
        assert_eq!(next_code, "359152");
    }
}
