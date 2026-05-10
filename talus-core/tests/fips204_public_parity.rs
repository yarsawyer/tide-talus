use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

fn message32() -> [u8; 32] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1))
}

fn message64() -> [u8; 64] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(7))
}

#[test]
fn fips204_adapter_matches_upstream_verify_all_params() {
    let msg32 = message32();
    let msg64 = message64();
    let seed = [0x42u8; 32];
    let sign_seed = [0x24u8; 32];

    {
        let (pk, sk) = fips204::ml_dsa_44::KG::keygen_from_seed(&seed);
        let sig32 = sk
            .try_sign_with_seed(&sign_seed, &msg32, &[])
            .expect("ML-DSA-44 signs 32-byte parity message");
        let sig64 = sk
            .try_sign_with_seed(&sign_seed, &msg64, &[])
            .expect("ML-DSA-44 signs 64-byte parity message");
        assert!(pk.verify(&msg32, &sig32, &[]));
        assert!(pk.verify(&msg64, &sig64, &[]));
        assert!(!pk.verify(&message32(), &sig64, &[]));
    }

    {
        let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&seed);
        let sig32 = sk
            .try_sign_with_seed(&sign_seed, &msg32, &[])
            .expect("ML-DSA-65 signs 32-byte parity message");
        let sig64 = sk
            .try_sign_with_seed(&sign_seed, &msg64, &[])
            .expect("ML-DSA-65 signs 64-byte parity message");
        assert!(pk.verify(&msg32, &sig32, &[]));
        assert!(pk.verify(&msg64, &sig64, &[]));
        assert!(!pk.verify(&message32(), &sig64, &[]));
    }

    {
        let (pk, sk) = fips204::ml_dsa_87::KG::keygen_from_seed(&seed);
        let sig32 = sk
            .try_sign_with_seed(&sign_seed, &msg32, &[])
            .expect("ML-DSA-87 signs 32-byte parity message");
        let sig64 = sk
            .try_sign_with_seed(&sign_seed, &msg64, &[])
            .expect("ML-DSA-87 signs 64-byte parity message");
        assert!(pk.verify(&msg32, &sig32, &[]));
        assert!(pk.verify(&msg64, &sig64, &[]));
        assert!(!pk.verify(&message32(), &sig64, &[]));
    }
}

#[test]
fn fips204_adapter_matches_upstream_signature_encoding_all_params() {
    let msg = message32();
    let seed = [0x11u8; 32];
    let sign_seed = [0x12u8; 32];

    {
        let (pk, sk) = fips204::ml_dsa_44::KG::keygen_from_seed(&seed);
        let pk_bytes = pk.clone().into_bytes();
        let sk_bytes = sk.clone().into_bytes();
        assert_eq!(pk_bytes.len(), 1_312);
        assert_eq!(sk_bytes.len(), 2_560);
        let pk2 = fips204::ml_dsa_44::PublicKey::try_from_bytes(pk_bytes)
            .expect("ML-DSA-44 public key round-trips");
        let sk2 = fips204::ml_dsa_44::PrivateKey::try_from_bytes(sk_bytes)
            .expect("ML-DSA-44 private key round-trips");
        let sig = sk2
            .try_sign_with_seed(&sign_seed, &msg, &[])
            .expect("ML-DSA-44 deserialized key signs");
        assert_eq!(sig.len(), 2_420);
        assert!(pk2.verify(&msg, &sig, &[]));
    }

    {
        let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&seed);
        let pk_bytes = pk.clone().into_bytes();
        let sk_bytes = sk.clone().into_bytes();
        assert_eq!(pk_bytes.len(), 1_952);
        assert_eq!(sk_bytes.len(), 4_032);
        let pk2 = fips204::ml_dsa_65::PublicKey::try_from_bytes(pk_bytes)
            .expect("ML-DSA-65 public key round-trips");
        let sk2 = fips204::ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes)
            .expect("ML-DSA-65 private key round-trips");
        let sig = sk2
            .try_sign_with_seed(&sign_seed, &msg, &[])
            .expect("ML-DSA-65 deserialized key signs");
        assert_eq!(sig.len(), 3_309);
        assert!(pk2.verify(&msg, &sig, &[]));
    }

    {
        let (pk, sk) = fips204::ml_dsa_87::KG::keygen_from_seed(&seed);
        let pk_bytes = pk.clone().into_bytes();
        let sk_bytes = sk.clone().into_bytes();
        assert_eq!(pk_bytes.len(), 2_592);
        assert_eq!(sk_bytes.len(), 4_896);
        let pk2 = fips204::ml_dsa_87::PublicKey::try_from_bytes(pk_bytes)
            .expect("ML-DSA-87 public key round-trips");
        let sk2 = fips204::ml_dsa_87::PrivateKey::try_from_bytes(sk_bytes)
            .expect("ML-DSA-87 private key round-trips");
        let sig = sk2
            .try_sign_with_seed(&sign_seed, &msg, &[])
            .expect("ML-DSA-87 deserialized key signs");
        assert_eq!(sig.len(), 4_627);
        assert!(pk2.verify(&msg, &sig, &[]));
    }
}
