use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};

const TRANSCRIPT_LABEL: &str = "secretctl-extension-session-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionEnrollment {
    pub extension_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_pairing_code: Option<String>,
}

impl ExtensionEnrollment {
    pub fn new(extension_id: String) -> Self {
        let mut random = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let code = u32::from_be_bytes(random) % 1_000_000;
        Self {
            extension_id,
            public_key: None,
            pending_pairing_code: Some(format!("{code:06}")),
        }
    }

    pub fn challenge(&self) -> ExtensionChallenge {
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        ExtensionChallenge {
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            pairing_code: self.pending_pairing_code.clone(),
            paired: self.public_key.is_some(),
        }
    }

    pub fn verify_and_enroll(
        &mut self,
        expected_nonce: &str,
        proof: &ExtensionProof,
    ) -> anyhow::Result<String> {
        anyhow::ensure!(
            proof.challenge_nonce == expected_nonce,
            "extension challenge replay rejected"
        );
        let public_key = URL_SAFE_NO_PAD.decode(&proof.public_key)?;
        anyhow::ensure!(public_key.len() == 32, "extension public key rejected");
        if let Some(enrolled) = &self.public_key {
            anyhow::ensure!(enrolled == &public_key, "extension enrollment key changed");
        } else {
            anyhow::ensure!(
                self.pending_pairing_code.as_deref() == proof.pairing_code.as_deref(),
                "extension pairing code rejected"
            );
        }
        let transcript =
            extension_transcript(expected_nonce, &self.extension_id, &proof.public_key);
        let signature = URL_SAFE_NO_PAD.decode(&proof.signature)?;
        secretctl_crypto::verify_signature(&public_key, &transcript, &signature)
            .map_err(|_| anyhow::anyhow!("extension challenge signature rejected"))?;
        if self.public_key.is_none() {
            self.public_key = Some(public_key.clone());
            self.pending_pairing_code = None;
        }
        let digest = secretctl_crypto::sha256_digest(&public_key);
        Ok(format!("extkey_{}", URL_SAFE_NO_PAD.encode(&digest[..18])))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtensionChallenge {
    pub nonce: String,
    pub pairing_code: Option<String>,
    pub paired: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionProof {
    pub public_key: String,
    pub challenge_nonce: String,
    pub signature: String,
    #[serde(default)]
    pub pairing_code: Option<String>,
}

pub fn extension_transcript(nonce: &str, extension_id: &str, public_key: &str) -> Vec<u8> {
    secretctl_crypto::compute_context_digest(&[
        TRANSCRIPT_LABEL.as_bytes(),
        nonce.as_bytes(),
        extension_id.as_bytes(),
        public_key.as_bytes(),
    ])
    .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretctl_crypto::KeyPair;

    #[test]
    fn pairing_is_single_key_and_every_session_requires_a_fresh_signature() {
        let key = KeyPair::generate();
        let public_key = URL_SAFE_NO_PAD.encode(key.public_key_bytes());
        let mut enrollment = ExtensionEnrollment::new("extension-id".into());
        let challenge = enrollment.challenge();
        let signature = key.sign(&extension_transcript(
            &challenge.nonce,
            "extension-id",
            &public_key,
        ));
        let proof = ExtensionProof {
            public_key,
            challenge_nonce: challenge.nonce.clone(),
            signature: URL_SAFE_NO_PAD.encode(signature),
            pairing_code: challenge.pairing_code,
        };
        let key_id = enrollment
            .verify_and_enroll(&challenge.nonce, &proof)
            .expect("first pairing");
        assert!(key_id.starts_with("extkey_"));
        assert!(enrollment.pending_pairing_code.is_none());
        assert!(
            enrollment
                .verify_and_enroll("different-nonce", &proof)
                .is_err()
        );

        let replacement_key = KeyPair::generate();
        let replacement_public_key = URL_SAFE_NO_PAD.encode(replacement_key.public_key_bytes());
        let replacement_challenge = enrollment.challenge();
        let replacement_proof = ExtensionProof {
            public_key: replacement_public_key.clone(),
            challenge_nonce: replacement_challenge.nonce.clone(),
            signature: URL_SAFE_NO_PAD.encode(replacement_key.sign(&extension_transcript(
                &replacement_challenge.nonce,
                "extension-id",
                &replacement_public_key,
            ))),
            pairing_code: None,
        };
        assert!(
            enrollment
                .verify_and_enroll(&replacement_challenge.nonce, &replacement_proof)
                .is_err()
        );
    }

    #[test]
    fn first_pairing_rejects_a_valid_signature_with_the_wrong_code() {
        let key = KeyPair::generate();
        let public_key = URL_SAFE_NO_PAD.encode(key.public_key_bytes());
        let mut enrollment = ExtensionEnrollment::new("extension-id".into());
        let challenge = enrollment.challenge();
        let proof = ExtensionProof {
            public_key: public_key.clone(),
            challenge_nonce: challenge.nonce.clone(),
            signature: URL_SAFE_NO_PAD.encode(key.sign(&extension_transcript(
                &challenge.nonce,
                "extension-id",
                &public_key,
            ))),
            pairing_code: Some("000000".into()),
        };

        assert!(
            enrollment
                .verify_and_enroll(&challenge.nonce, &proof)
                .is_err()
        );
        assert!(enrollment.public_key.is_none());
    }
}
