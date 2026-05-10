#![cfg(feature = "tidecoin-local")]

use fips204::traits::{KeyGen, SerDes, Signer};
use tidecoin_consensus_core::{PqPublicKey, PqScheme, PqSignature};

fn message32() -> [u8; 32] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
}

fn message64() -> [u8; 64] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(9))
}

#[test]
fn fips204_signatures_verify_through_tidecoin_consensus_core() {
    let msg32 = message32();
    let msg64 = message64();
    let key_seed = [0x51u8; 32];
    let sign_seed = [0x52u8; 32];

    {
        let (pk, sk) = fips204::ml_dsa_44::KG::keygen_from_seed(&key_seed);
        let tide_pk = PqPublicKey::from_scheme_and_bytes(PqScheme::MlDsa44, &pk.into_bytes())
            .expect("Tidecoin accepts ML-DSA-44 public key bytes");
        let sig32 = sk
            .try_sign_with_seed(&sign_seed, &msg32, &[])
            .expect("ML-DSA-44 signs 32-byte Tidecoin parity message");
        let sig64 = sk
            .try_sign_with_seed(&sign_seed, &msg64, &[])
            .expect("ML-DSA-44 signs 64-byte Tidecoin parity message");
        PqSignature::from_slice(&sig32)
            .verify_msg32(&msg32, &tide_pk)
            .expect("Tidecoin verifies ML-DSA-44 msg32 signature");
        PqSignature::from_slice(&sig64)
            .verify_msg64(&msg64, &tide_pk)
            .expect("Tidecoin verifies ML-DSA-44 msg64 signature");
        assert!(PqSignature::from_slice(&sig64)
            .verify_msg32(&msg32, &tide_pk)
            .is_err());
    }

    {
        let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&key_seed);
        let tide_pk = PqPublicKey::from_scheme_and_bytes(PqScheme::MlDsa65, &pk.into_bytes())
            .expect("Tidecoin accepts ML-DSA-65 public key bytes");
        let sig32 = sk
            .try_sign_with_seed(&sign_seed, &msg32, &[])
            .expect("ML-DSA-65 signs 32-byte Tidecoin parity message");
        let sig64 = sk
            .try_sign_with_seed(&sign_seed, &msg64, &[])
            .expect("ML-DSA-65 signs 64-byte Tidecoin parity message");
        PqSignature::from_slice(&sig32)
            .verify_msg32(&msg32, &tide_pk)
            .expect("Tidecoin verifies ML-DSA-65 msg32 signature");
        PqSignature::from_slice(&sig64)
            .verify_msg64(&msg64, &tide_pk)
            .expect("Tidecoin verifies ML-DSA-65 msg64 signature");
        assert!(PqSignature::from_slice(&sig64)
            .verify_msg32(&msg32, &tide_pk)
            .is_err());
    }

    {
        let (pk, sk) = fips204::ml_dsa_87::KG::keygen_from_seed(&key_seed);
        let tide_pk = PqPublicKey::from_scheme_and_bytes(PqScheme::MlDsa87, &pk.into_bytes())
            .expect("Tidecoin accepts ML-DSA-87 public key bytes");
        let sig32 = sk
            .try_sign_with_seed(&sign_seed, &msg32, &[])
            .expect("ML-DSA-87 signs 32-byte Tidecoin parity message");
        let sig64 = sk
            .try_sign_with_seed(&sign_seed, &msg64, &[])
            .expect("ML-DSA-87 signs 64-byte Tidecoin parity message");
        PqSignature::from_slice(&sig32)
            .verify_msg32(&msg32, &tide_pk)
            .expect("Tidecoin verifies ML-DSA-87 msg32 signature");
        PqSignature::from_slice(&sig64)
            .verify_msg64(&msg64, &tide_pk)
            .expect("Tidecoin verifies ML-DSA-87 msg64 signature");
        assert!(PqSignature::from_slice(&sig64)
            .verify_msg32(&msg32, &tide_pk)
            .is_err());
    }
}
