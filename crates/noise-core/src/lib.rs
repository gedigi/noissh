#![forbid(unsafe_code)]
//! Static X25519 keys for noissh: generation (through `snow`, so the keys are
//! exactly what the Noise handshake expects) and public-key derivation.
//!
//! The handshake itself runs inside QUIC, in the `noise-quic` crate.

use thiserror::Error;

/// The Noise pattern noissh uses for all sessions (keys are generated for it).
pub const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Length of an X25519 public/private key in bytes.
pub const KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("snow error: {0}")]
    Snow(String),
}

impl From<snow::Error> for NoiseError {
    fn from(e: snow::Error) -> Self {
        NoiseError::Snow(format!("{e:?}"))
    }
}

/// A static X25519 keypair.
#[derive(Clone)]
pub struct Keypair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

/// Generate a fresh static keypair.
pub fn generate_keypair() -> Result<Keypair, NoiseError> {
    let params = PATTERN.parse().map_err(NoiseError::from)?;
    let builder = snow::Builder::new(params);
    let kp = builder.generate_keypair()?;
    Ok(Keypair {
        private: kp.private,
        public: kp.public,
    })
}

/// Derive the X25519 public key for `private` (a 32-byte static private key, as
/// produced by [`generate_keypair`]). Lets a key file store only the secret.
pub fn public_from_private(private: &[u8]) -> Option<Vec<u8>> {
    let bytes: [u8; KEY_LEN] = private.try_into().ok()?;
    Some(
        curve25519_dalek::MontgomeryPoint::mul_base_clamped(bytes)
            .to_bytes()
            .to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_derives_from_private_key() {
        // The derivation must agree with snow's own key generation, or a key
        // file holding only the private half would load a different identity.
        for _ in 0..16 {
            let kp = generate_keypair().unwrap();
            assert_eq!(public_from_private(&kp.private).unwrap(), kp.public);
        }
        assert!(public_from_private(&[0u8; 31]).is_none());
    }

    #[test]
    fn keypair_is_32_bytes() {
        let kp = generate_keypair().unwrap();
        assert_eq!(kp.public.len(), KEY_LEN);
        assert_eq!(kp.private.len(), KEY_LEN);
    }
}
