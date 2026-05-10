#![doc = "Independent FIPS 204 verification helpers."]

use core::marker::PhantomData;

use fips204::traits::{SerDes, Verifier};

use crate::{MlDsa44, MlDsa65, MlDsa87, MlDsaParams};

/// FIPS verification helper failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifyError {
    /// Public key length did not match the selected ML-DSA suite.
    PublicKeyLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
    /// Signature length did not match the selected ML-DSA suite.
    SignatureLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
    /// Public key deserialization failed.
    PublicKeyDecode(&'static str),
}

/// Independent FIPS verifier for one parameter set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fips204Verifier<P: MlDsaParams> {
    public_key: Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: MlDsaParams> Fips204Verifier<P> {
    /// Creates a verifier from serialized public-key bytes.
    pub fn new(public_key: Vec<u8>) -> Result<Self, VerifyError> {
        validate_public_key_len::<P>(&public_key)?;
        Ok(Self {
            public_key,
            _params: PhantomData,
        })
    }

    /// Returns the serialized public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Verifies a serialized FIPS ML-DSA signature.
    pub fn verify(&self, message: &[u8], signature: &[u8], context: &[u8]) -> bool {
        verify_fips204_signature::<P>(&self.public_key, message, signature, context)
            .unwrap_or(false)
    }
}

/// Verifies a serialized FIPS ML-DSA signature using the upstream `fips204`
/// public verifier.
pub fn verify_fips204_signature<P: MlDsaParams>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<bool, VerifyError> {
    validate_public_key_len::<P>(public_key)?;
    validate_signature_len::<P>(signature)?;

    match P::NAME {
        MlDsa44::NAME => {
            let pk = fips204::ml_dsa_44::PublicKey::try_from_bytes(
                public_key
                    .try_into()
                    .expect("validated ML-DSA-44 public key length"),
            )
            .map_err(VerifyError::PublicKeyDecode)?;
            let sig: &[u8; MlDsa44::SIG_LEN] = signature
                .try_into()
                .expect("validated ML-DSA-44 signature length");
            Ok(pk.verify(message, sig, context))
        }
        MlDsa65::NAME => {
            let pk = fips204::ml_dsa_65::PublicKey::try_from_bytes(
                public_key
                    .try_into()
                    .expect("validated ML-DSA-65 public key length"),
            )
            .map_err(VerifyError::PublicKeyDecode)?;
            let sig: &[u8; MlDsa65::SIG_LEN] = signature
                .try_into()
                .expect("validated ML-DSA-65 signature length");
            Ok(pk.verify(message, sig, context))
        }
        MlDsa87::NAME => {
            let pk = fips204::ml_dsa_87::PublicKey::try_from_bytes(
                public_key
                    .try_into()
                    .expect("validated ML-DSA-87 public key length"),
            )
            .map_err(VerifyError::PublicKeyDecode)?;
            let sig: &[u8; MlDsa87::SIG_LEN] = signature
                .try_into()
                .expect("validated ML-DSA-87 signature length");
            Ok(pk.verify(message, sig, context))
        }
        _ => unreachable!("unknown ML-DSA parameter set"),
    }
}

fn validate_public_key_len<P: MlDsaParams>(public_key: &[u8]) -> Result<(), VerifyError> {
    if public_key.len() != P::PK_LEN {
        return Err(VerifyError::PublicKeyLength {
            expected: P::PK_LEN,
            got: public_key.len(),
        });
    }
    Ok(())
}

fn validate_signature_len<P: MlDsaParams>(signature: &[u8]) -> Result<(), VerifyError> {
    if signature.len() != P::SIG_LEN {
        return Err(VerifyError::SignatureLength {
            expected: P::SIG_LEN,
            got: signature.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::traits::{KeyGen, SerDes, Signer};

    fn message() -> Vec<u8> {
        (0..64).map(|i| (i as u8).wrapping_mul(9)).collect()
    }

    fn check_valid_and_modified<P, const PK_LEN: usize, const SIG_LEN: usize>(
        pk: [u8; PK_LEN],
        signature: [u8; SIG_LEN],
    ) where
        P: MlDsaParams,
    {
        let message = message();
        assert_eq!(
            verify_fips204_signature::<P>(&pk, &message, &signature, b"ctx"),
            Ok(true)
        );

        let mut bad_signature = signature;
        bad_signature[0] ^= 1;
        assert_eq!(
            verify_fips204_signature::<P>(&pk, &message, &bad_signature, b"ctx"),
            Ok(false)
        );

        assert_eq!(
            verify_fips204_signature::<P>(&pk, b"wrong", &signature, b"ctx"),
            Ok(false)
        );
    }

    #[test]
    fn fips_verify_helper_accepts_and_rejects_all_parameter_sets() {
        let key_seed = [0x66; 32];
        let sign_seed = [0x77; 32];
        let message = message();

        {
            let (pk, sk) = fips204::ml_dsa_44::KG::keygen_from_seed(&key_seed);
            let sig = sk
                .try_sign_with_seed(&sign_seed, &message, b"ctx")
                .expect("ML-DSA-44 signs");
            check_valid_and_modified::<MlDsa44, { MlDsa44::PK_LEN }, { MlDsa44::SIG_LEN }>(
                pk.into_bytes(),
                sig,
            );
        }

        {
            let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&key_seed);
            let sig = sk
                .try_sign_with_seed(&sign_seed, &message, b"ctx")
                .expect("ML-DSA-65 signs");
            check_valid_and_modified::<MlDsa65, { MlDsa65::PK_LEN }, { MlDsa65::SIG_LEN }>(
                pk.into_bytes(),
                sig,
            );
        }

        {
            let (pk, sk) = fips204::ml_dsa_87::KG::keygen_from_seed(&key_seed);
            let sig = sk
                .try_sign_with_seed(&sign_seed, &message, b"ctx")
                .expect("ML-DSA-87 signs");
            check_valid_and_modified::<MlDsa87, { MlDsa87::PK_LEN }, { MlDsa87::SIG_LEN }>(
                pk.into_bytes(),
                sig,
            );
        }
    }

    #[test]
    fn fips_verifier_rejects_bad_lengths() {
        assert_eq!(
            verify_fips204_signature::<MlDsa65>(&[0u8; 31], b"m", &[0u8; MlDsa65::SIG_LEN], b""),
            Err(VerifyError::PublicKeyLength {
                expected: MlDsa65::PK_LEN,
                got: 31,
            })
        );

        assert_eq!(
            verify_fips204_signature::<MlDsa65>(&[0u8; MlDsa65::PK_LEN], b"m", &[0u8; 31], b""),
            Err(VerifyError::SignatureLength {
                expected: MlDsa65::SIG_LEN,
                got: 31,
            })
        );
    }

    #[test]
    fn fips204_verifier_wrapper_uses_public_key() {
        let key_seed = [0x12; 32];
        let sign_seed = [0x13; 32];
        let message = message();
        let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&key_seed);
        let sig = sk
            .try_sign_with_seed(&sign_seed, &message, b"ctx")
            .expect("ML-DSA-65 signs");

        let verifier = Fips204Verifier::<MlDsa65>::new(pk.into_bytes().to_vec()).expect("verifier");
        assert!(verifier.verify(&message, &sig, b"ctx"));
        assert!(!verifier.verify(b"wrong", &sig, b"ctx"));
    }
}
