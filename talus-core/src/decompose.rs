#![doc = "Public TALUS decomposition helpers."]

use crate::{fips204_adapter, params::MlDsaParams};

/// ML-DSA coefficient type.
pub type Coeff = fips204_adapter::Coeff;

/// Reduces an integer into `[0, q)`.
pub fn reduce_mod_q<P: MlDsaParams>(r: Coeff) -> Coeff {
    fips204_adapter::reduce_mod_q::<P>(r)
}

/// FIPS 204 Power2Round for a single coefficient.
pub fn power2round<P: MlDsaParams>(r: Coeff) -> (Coeff, Coeff) {
    fips204_adapter::power2round::<P>(r)
}

/// FIPS 204 Decompose for a single coefficient.
pub fn decompose<P: MlDsaParams>(r: Coeff) -> (Coeff, Coeff) {
    fips204_adapter::decompose::<P>(r)
}

/// FIPS 204 HighBits for a single coefficient.
pub fn high_bits<P: MlDsaParams>(r: Coeff) -> Coeff {
    fips204_adapter::high_bits::<P>(r)
}

/// FIPS 204 signed LowBits for a single coefficient.
pub fn low_bits_signed<P: MlDsaParams>(r: Coeff) -> Coeff {
    fips204_adapter::low_bits_signed::<P>(r)
}

/// TALUS unsigned low bits in `[0, alpha)`.
pub fn low_bits_unsigned<P: MlDsaParams>(r: Coeff) -> u32 {
    (reduce_mod_q::<P>(r) % P::alpha()) as u32
}

/// TALUS unsigned high bits in `[0, HIGH_MOD)`.
pub fn high_bits_unsigned<P: MlDsaParams>(r: Coeff) -> u32 {
    ((reduce_mod_q::<P>(r) / P::alpha()) % P::HIGH_MOD) as u32
}

/// FIPS 204 UseHint for a single coefficient.
pub fn use_hint<P: MlDsaParams>(hint: bool, r: Coeff) -> Coeff {
    fips204_adapter::use_hint::<P>(hint, r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{MlDsa44, MlDsa65, MlDsa87};

    const SAMPLE_COEFFS: &[Coeff] = &[
        0, 1, -1, 95_231, 95_232, 95_233, 190_463, 190_464, 261_887, 261_888, 261_889, 523_775,
        523_776, 523_777, 8_118_529, 8_285_185, 8_380_416, 8_380_417, -8_380_417,
    ];

    fn check_decompose<P: MlDsaParams>() {
        for &r in SAMPLE_COEFFS {
            let (high, low) = decompose::<P>(r);
            assert!((0..P::HIGH_MOD).contains(&high), "{} high={high}", P::NAME);
            assert!(
                (-P::GAMMA2..=P::GAMMA2).contains(&low),
                "{} low={low}",
                P::NAME
            );
            assert_eq!(
                reduce_mod_q::<P>(r),
                (high * P::alpha() + low).rem_euclid(P::Q),
                "{} r={r}",
                P::NAME
            );
        }
    }

    fn check_unsigned_ranges<P: MlDsaParams>() {
        for &r in SAMPLE_COEFFS {
            let high = high_bits_unsigned::<P>(r);
            let low = low_bits_unsigned::<P>(r);
            assert!(high < P::HIGH_MOD as u32, "{} high={high}", P::NAME);
            assert!(low < P::alpha() as u32, "{} low={low}", P::NAME);
        }
    }

    #[test]
    fn decompose_reconstructs_mod_q() {
        check_decompose::<MlDsa44>();
        check_decompose::<MlDsa65>();
        check_decompose::<MlDsa87>();
    }

    #[test]
    fn unsigned_decomposition_ranges() {
        check_unsigned_ranges::<MlDsa44>();
        check_unsigned_ranges::<MlDsa65>();
        check_unsigned_ranges::<MlDsa87>();
    }

    #[test]
    fn decompose_special_boundary_cases_from_fips204() {
        assert_eq!(decompose::<MlDsa44>(8_285_185), (0, -95_232));
        assert_eq!(decompose::<MlDsa65>(8_118_529), (0, -261_888));
        assert_eq!(decompose::<MlDsa87>(8_118_529), (0, -261_888));
    }

    #[test]
    fn high_and_low_bits_match_decompose() {
        for &r in SAMPLE_COEFFS {
            let (high, low) = decompose::<MlDsa65>(r);
            assert_eq!(high_bits::<MlDsa65>(r), high);
            assert_eq!(low_bits_signed::<MlDsa65>(r), low);
        }
    }

    #[test]
    fn use_hint_false_returns_high_bits() {
        for &r in SAMPLE_COEFFS {
            assert_eq!(use_hint::<MlDsa44>(false, r), high_bits::<MlDsa44>(r));
            assert_eq!(use_hint::<MlDsa65>(false, r), high_bits::<MlDsa65>(r));
            assert_eq!(use_hint::<MlDsa87>(false, r), high_bits::<MlDsa87>(r));
        }
    }

    #[test]
    fn use_hint_matches_make_hint_identity() {
        for &r in SAMPLE_COEFFS {
            for &z in &[-2, -1, 0, 1, 2, MlDsa65::GAMMA2 - 1, -MlDsa65::GAMMA2 + 1] {
                let hint = fips204_adapter::make_hint::<MlDsa65>(z, r);
                assert_eq!(use_hint::<MlDsa65>(hint, r), high_bits::<MlDsa65>(r + z));
            }
        }
    }

    #[test]
    fn power2round_reconstructs_mod_q() {
        for &r in SAMPLE_COEFFS {
            let (high, low) = power2round::<MlDsa65>(r);
            assert_eq!(reduce_mod_q::<MlDsa65>(r), high * (1 << MlDsa65::D) + low);
        }
    }
}
