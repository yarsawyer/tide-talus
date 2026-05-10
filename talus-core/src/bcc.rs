#![doc = "Boundary clearance and public TALUS hint helpers."]

use crate::decompose::{high_bits, low_bits_signed, use_hint, Coeff};
use crate::params::MlDsaParams;
use crate::PolyVec;

/// Public TALUS hint computation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HintError {
    /// Approximation vector length did not match ML-DSA `k`.
    RLength {
        /// Expected polynomial count.
        expected: usize,
        /// Actual polynomial count.
        got: usize,
    },
    /// Encoded `w1` coefficient count did not match `k * 256`.
    W1Length {
        /// Expected coefficient count.
        expected: usize,
        /// Actual coefficient count.
        got: usize,
    },
    /// `w1` coefficient outside `[0, HIGH_MOD)`.
    W1OutOfRange {
        /// Coefficient index.
        index: usize,
        /// Invalid value.
        value: u32,
    },
}

/// Returns whether one ML-DSA coefficient satisfies the TALUS boundary
/// clearance condition.
pub fn bcc_holds_coeff<P: MlDsaParams>(w: Coeff) -> bool {
    low_bits_signed::<P>(w).abs() < P::GAMMA2 - P::BETA
}

/// Returns whether every supplied coefficient satisfies boundary clearance.
pub fn bcc_holds_coeffs<P: MlDsaParams>(w: &[Coeff]) -> bool {
    w.iter().all(|&coeff| bcc_holds_coeff::<P>(coeff))
}

/// Computes the public TALUS hint bit for one coefficient.
pub fn talus_hint_coeff<P: MlDsaParams>(r: Coeff, w1: Coeff) -> bool {
    high_bits::<P>(r) != w1
}

/// Applies a TALUS hint with the FIPS 204 `UseHint` rule.
pub fn use_talus_hint_coeff<P: MlDsaParams>(hint: bool, r: Coeff) -> Coeff {
    use_hint::<P>(hint, r)
}

/// Writes public TALUS hint bits into `hints`.
///
/// Returns `false` if the input and output slices do not have identical length.
pub fn compute_talus_hints<P: MlDsaParams>(r: &[Coeff], w1: &[Coeff], hints: &mut [bool]) -> bool {
    if r.len() != w1.len() || r.len() != hints.len() {
        return false;
    }

    for ((hint, &r_coeff), &w1_coeff) in hints.iter_mut().zip(r).zip(w1) {
        *hint = talus_hint_coeff::<P>(r_coeff, w1_coeff);
    }
    true
}

/// Computes public TALUS hint bits over a typed `R^k` approximation vector.
pub fn compute_talus_hint_polyvec<P: MlDsaParams>(
    r: &PolyVec,
    w1: &[u32],
) -> Result<PolyVec, HintError> {
    if r.len() != P::K {
        return Err(HintError::RLength {
            expected: P::K,
            got: r.len(),
        });
    }
    if w1.len() != P::K * P::N {
        return Err(HintError::W1Length {
            expected: P::K * P::N,
            got: w1.len(),
        });
    }

    let mut hints = PolyVec::zero(P::K);
    for poly_index in 0..P::K {
        for coeff_index in 0..P::N {
            let flat_index = poly_index * P::N + coeff_index;
            let w1_coeff = w1[flat_index];
            if w1_coeff >= P::HIGH_MOD as u32 {
                return Err(HintError::W1OutOfRange {
                    index: flat_index,
                    value: w1_coeff,
                });
            }
            hints.polys_mut()[poly_index].coeffs_mut()[coeff_index] =
                i32::from(talus_hint_coeff::<P>(
                    r.polys()[poly_index].coeffs()[coeff_index],
                    w1_coeff as Coeff,
                ));
        }
    }

    Ok(hints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlDsa44, MlDsa65, MlDsa87};

    fn representative_lows<P: MlDsaParams>() -> [Coeff; 9] {
        let limit = P::GAMMA2 - P::BETA;
        [
            -limit - 1,
            -limit,
            -limit + 1,
            -1,
            0,
            1,
            limit - 1,
            limit,
            limit + 1,
        ]
    }

    fn coeff_from_high_low<P: MlDsaParams>(high: Coeff, low: Coeff) -> Coeff {
        (high * P::alpha() + low).rem_euclid(P::Q)
    }

    fn check_bcc_boundary<P: MlDsaParams>() {
        let limit = P::GAMMA2 - P::BETA;

        assert!(bcc_holds_coeff::<P>(limit - 1));
        assert!(bcc_holds_coeff::<P>(-limit + 1));
        assert!(!bcc_holds_coeff::<P>(limit));
        assert!(!bcc_holds_coeff::<P>(-limit));
    }

    fn check_bcc_safety<P: MlDsaParams>() {
        for high in 0..P::HIGH_MOD {
            for low in representative_lows::<P>() {
                let w = coeff_from_high_low::<P>(high, low);
                if !bcc_holds_coeff::<P>(w) {
                    continue;
                }

                let w1 = high_bits::<P>(w);
                for adjustment in [-P::BETA, -1, 0, 1, P::BETA] {
                    let shifted = w - adjustment;
                    assert_eq!(high_bits::<P>(shifted), w1);
                }
            }
        }
    }

    fn check_hint_identity<P: MlDsaParams>() {
        for high in 0..P::HIGH_MOD {
            for low in representative_lows::<P>() {
                let w = coeff_from_high_low::<P>(high, low);
                if !bcc_holds_coeff::<P>(w) {
                    continue;
                }

                let w1 = high_bits::<P>(w);
                for adjustment in [-P::BETA, -1, 0, 1, P::BETA] {
                    let r = w - adjustment;
                    let hint = talus_hint_coeff::<P>(r, w1);
                    assert_eq!(use_talus_hint_coeff::<P>(hint, r), w1);
                }
            }
        }
    }

    #[test]
    fn bcc_boundary_is_strict() {
        check_bcc_boundary::<MlDsa44>();
        check_bcc_boundary::<MlDsa65>();
        check_bcc_boundary::<MlDsa87>();
    }

    #[test]
    fn bcc_safety_representative_ml_dsa_44() {
        check_bcc_safety::<MlDsa44>();
    }

    #[test]
    fn bcc_safety_representative_ml_dsa_65() {
        check_bcc_safety::<MlDsa65>();
    }

    #[test]
    fn bcc_safety_representative_ml_dsa_87() {
        check_bcc_safety::<MlDsa87>();
    }

    #[test]
    fn hint_public_identity_representative() {
        check_hint_identity::<MlDsa44>();
        check_hint_identity::<MlDsa65>();
        check_hint_identity::<MlDsa87>();
    }

    #[test]
    fn compute_talus_hints_checks_lengths() {
        let r = [0, 1, 2];
        let w1 = [0, 0, 0];
        let mut hints = [false; 2];

        assert!(!compute_talus_hints::<MlDsa65>(&r, &w1, &mut hints));
    }

    #[test]
    fn compute_talus_hint_polyvec_checks_lengths_and_ranges() {
        assert_eq!(
            compute_talus_hint_polyvec::<MlDsa65>(&PolyVec::zero(MlDsa65::K - 1), &[]),
            Err(HintError::RLength {
                expected: MlDsa65::K,
                got: MlDsa65::K - 1,
            })
        );

        assert_eq!(
            compute_talus_hint_polyvec::<MlDsa65>(&PolyVec::zero(MlDsa65::K), &[0]),
            Err(HintError::W1Length {
                expected: MlDsa65::K * MlDsa65::N,
                got: 1,
            })
        );

        let mut w1 = vec![0u32; MlDsa65::K * MlDsa65::N];
        w1[3] = MlDsa65::HIGH_MOD as u32;
        assert_eq!(
            compute_talus_hint_polyvec::<MlDsa65>(&PolyVec::zero(MlDsa65::K), &w1),
            Err(HintError::W1OutOfRange {
                index: 3,
                value: MlDsa65::HIGH_MOD as u32,
            })
        );
    }

    #[test]
    fn compute_talus_hint_polyvec_matches_coefficient_identity() {
        let mut r = PolyVec::zero(MlDsa65::K);
        let mut w1 = vec![0u32; MlDsa65::K * MlDsa65::N];

        for poly_index in 0..MlDsa65::K {
            let high = (poly_index as i32) % MlDsa65::HIGH_MOD;
            let coeff = high * MlDsa65::alpha();
            r.polys_mut()[poly_index].coeffs_mut()[0] = coeff;
            w1[poly_index * MlDsa65::N] = high as u32;
        }

        let hints = compute_talus_hint_polyvec::<MlDsa65>(&r, &w1).expect("typed hints");
        for poly_index in 0..MlDsa65::K {
            let hint = hints.polys()[poly_index].coeffs()[0] != 0;
            let r_coeff = r.polys()[poly_index].coeffs()[0];
            assert_eq!(
                use_talus_hint_coeff::<MlDsa65>(hint, r_coeff),
                w1[poly_index * MlDsa65::N] as i32
            );
        }
    }
}
