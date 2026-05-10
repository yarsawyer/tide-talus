#![doc = "ML-DSA parameter metadata used by TALUS."]

/// Parameter set metadata needed by TALUS.
pub trait MlDsaParams: Clone + Copy + 'static {
    /// Human-readable suite name.
    const NAME: &'static str;

    /// Ring degree.
    const N: usize = 256;
    /// ML-DSA modulus.
    const Q: i32 = 8_380_417;
    /// Power2Round low-bit width.
    const D: usize = 13;

    /// Public matrix row count.
    const K: usize;
    /// Secret vector length.
    const L: usize;

    /// Secret coefficient bound.
    const ETA: i32;
    /// Challenge weight.
    const TAU: usize;
    /// FIPS 204 security strength in bits.
    const LAMBDA: usize;
    /// Rejection bound contribution.
    const BETA: i32;
    /// ML-DSA gamma1.
    const GAMMA1: i32;
    /// ML-DSA gamma2.
    const GAMMA2: i32;
    /// Hint weight bound.
    const OMEGA: usize;
    /// Challenge seed length, `lambda / 4`, in bytes.
    const CTILDE_LEN: usize;
    /// Serialized ML-DSA public key length in bytes.
    const PK_LEN: usize;
    /// Serialized ML-DSA signature length in bytes.
    const SIG_LEN: usize;
    /// Number of high-bit buckets.
    const HIGH_MOD: i32;

    /// Decomposition base alpha = 2 * gamma2.
    fn alpha() -> i32 {
        2 * Self::GAMMA2
    }

    /// Returns `(q - 1) / alpha`.
    fn computed_high_mod() -> i32 {
        (Self::Q - 1) / Self::alpha()
    }
}

/// ML-DSA-44 parameter set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MlDsa44;

impl MlDsaParams for MlDsa44 {
    const NAME: &'static str = "ML-DSA-44";
    const K: usize = 4;
    const L: usize = 4;
    const ETA: i32 = 2;
    const TAU: usize = 39;
    const LAMBDA: usize = 128;
    const BETA: i32 = 78;
    const GAMMA1: i32 = 1 << 17;
    const GAMMA2: i32 = (Self::Q - 1) / 88;
    const OMEGA: usize = 80;
    const CTILDE_LEN: usize = 32;
    const PK_LEN: usize = 1312;
    const SIG_LEN: usize = 2420;
    const HIGH_MOD: i32 = 44;
}

/// ML-DSA-65 parameter set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MlDsa65;

impl MlDsaParams for MlDsa65 {
    const NAME: &'static str = "ML-DSA-65";
    const K: usize = 6;
    const L: usize = 5;
    const ETA: i32 = 4;
    const TAU: usize = 49;
    const LAMBDA: usize = 192;
    const BETA: i32 = 196;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (Self::Q - 1) / 32;
    const OMEGA: usize = 55;
    const CTILDE_LEN: usize = 48;
    const PK_LEN: usize = 1952;
    const SIG_LEN: usize = 3309;
    const HIGH_MOD: i32 = 16;
}

/// ML-DSA-87 parameter set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MlDsa87;

impl MlDsaParams for MlDsa87 {
    const NAME: &'static str = "ML-DSA-87";
    const K: usize = 8;
    const L: usize = 7;
    const ETA: i32 = 2;
    const TAU: usize = 60;
    const LAMBDA: usize = 256;
    const BETA: i32 = 120;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (Self::Q - 1) / 32;
    const OMEGA: usize = 75;
    const CTILDE_LEN: usize = 64;
    const PK_LEN: usize = 2592;
    const SIG_LEN: usize = 4627;
    const HIGH_MOD: i32 = 16;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_params<P: MlDsaParams>() {
        assert_eq!(P::HIGH_MOD, P::computed_high_mod());
        assert_eq!(P::BETA, P::TAU as i32 * P::ETA);
        assert_eq!(P::alpha(), 2 * P::GAMMA2);
        assert_eq!(P::CTILDE_LEN, P::LAMBDA / 4);
    }

    #[test]
    fn params_match_fips_values() {
        check_params::<MlDsa44>();
        assert_eq!(MlDsa44::K, 4);
        assert_eq!(MlDsa44::L, 4);
        assert_eq!(MlDsa44::GAMMA2, 95_232);

        check_params::<MlDsa65>();
        assert_eq!(MlDsa65::K, 6);
        assert_eq!(MlDsa65::L, 5);
        assert_eq!(MlDsa65::GAMMA2, 261_888);

        check_params::<MlDsa87>();
        assert_eq!(MlDsa87::K, 8);
        assert_eq!(MlDsa87::L, 7);
        assert_eq!(MlDsa87::GAMMA2, 261_888);
    }
}
