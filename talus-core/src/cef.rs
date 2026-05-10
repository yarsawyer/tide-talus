#![doc = "Carry Elimination Framework helpers."]

use crate::params::MlDsaParams;

/// Computes clear `kappa` and `delta` for one coefficient.
///
/// TALUS range checks must ensure `sum(rho_i) < alpha`; otherwise the masked
/// low sum can contain more than one mask carry.
pub fn clear_kappa_delta<P: MlDsaParams>(masked_lows: &[u32], rhos: &[u32]) -> (bool, bool) {
    let alpha = P::alpha() as u64;
    let gamma2 = P::GAMMA2 as i64;

    let b = masked_lows.iter().map(|&x| u64::from(x)).sum::<u64>();
    let r = rhos.iter().map(|&x| u64::from(x)).sum::<u64>();
    debug_assert!(r < alpha);
    let t = b % alpha;

    let kappa = r > t;
    let delta_threshold = t as i64 - gamma2 + i64::from(kappa) * alpha as i64;
    let delta = (r as i64) < delta_threshold;

    (kappa, delta)
}

/// Reconstructs one `w1` coefficient from unmasked unsigned highs/lows.
pub fn cef_w1_clear_coeff<P: MlDsaParams>(highs: &[u32], lows: &[u32]) -> u32 {
    let alpha = P::alpha() as u64;
    let gamma2 = P::GAMMA2 as u64;
    let m = P::HIGH_MOD as u64;
    let sum_h = highs.iter().map(|&x| u64::from(x)).sum::<u64>() % m;
    let b = lows.iter().map(|&x| u64::from(x)).sum::<u64>();
    let delta = u64::from((b % alpha) > gamma2);

    ((sum_h + (b / alpha) + delta) % m) as u32
}

/// Reconstructs one `w1` coefficient from masked highs/lows and clear rhos.
///
/// This is the canonical CEF formula:
///
/// `w1 = (sum_Htilde + floor(B / alpha) - kappa + delta) mod m`.
pub fn cef_w1_coeff<P: MlDsaParams>(
    masked_highs: &[u32],
    masked_lows: &[u32],
    rhos: &[u32],
) -> u32 {
    debug_assert_eq!(masked_lows.len(), rhos.len());

    let alpha = P::alpha() as u64;
    let m = P::HIGH_MOD as u64;
    let sum_h = masked_highs.iter().map(|&x| u64::from(x)).sum::<u64>() % m;
    let b = masked_lows.iter().map(|&x| u64::from(x)).sum::<u64>();
    let (kappa, delta) = clear_kappa_delta::<P>(masked_lows, rhos);

    ((sum_h + (b / alpha) + u64::from(delta) + m - u64::from(kappa)) % m) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompose::{high_bits, high_bits_unsigned, low_bits_unsigned, Coeff};
    use crate::params::{MlDsa44, MlDsa65, MlDsa87};

    fn assert_delta_boundary_no_low_mask_carry<P: MlDsaParams>() {
        let base_high = 7u32 % P::HIGH_MOD as u32;
        let bsum = (P::GAMMA2 + 1) as u32;
        let got = cef_w1_coeff::<P>(&[base_high], &[bsum], &[0]);
        assert_eq!(got, (base_high + 1) % P::HIGH_MOD as u32);
        assert_eq!(clear_kappa_delta::<P>(&[bsum], &[0]), (false, true));
    }

    fn assert_delta_boundary_with_low_mask_carry<P: MlDsaParams>() {
        let base_high = 7u32 % P::HIGH_MOD as u32;
        let bsum = (P::alpha() - 500) as u32;
        let rho = 1_000u32;
        let btilde = bsum + rho;
        let got = cef_w1_coeff::<P>(&[base_high], &[btilde], &[rho]);
        assert_eq!(got, (base_high + 1) % P::HIGH_MOD as u32);
        assert_eq!(clear_kappa_delta::<P>(&[btilde], &[rho]), (true, true));
    }

    fn assert_delta_exact_boundary<P: MlDsaParams>() {
        let base_high = 7u32 % P::HIGH_MOD as u32;
        let bsum = P::GAMMA2 as u32;
        let got = cef_w1_coeff::<P>(&[base_high], &[bsum], &[0]);
        assert_eq!(got, base_high);
        assert_eq!(clear_kappa_delta::<P>(&[bsum], &[0]), (false, false));
    }

    fn assert_delta_upper_boundary<P: MlDsaParams>() {
        let base_high = 7u32 % P::HIGH_MOD as u32;
        let bsum = (P::alpha() - 1) as u32;
        let got = cef_w1_coeff::<P>(&[base_high], &[bsum], &[0]);
        assert_eq!(got, (base_high + 1) % P::HIGH_MOD as u32);
        assert_eq!(clear_kappa_delta::<P>(&[bsum], &[0]), (false, true));
    }

    fn cef_w1_coeff_wrong_minus_delta<P: MlDsaParams>(
        masked_highs: &[u32],
        masked_lows: &[u32],
        rhos: &[u32],
    ) -> u32 {
        let alpha = P::alpha() as u64;
        let m = P::HIGH_MOD as u64;
        let sum_h = masked_highs.iter().map(|&x| u64::from(x)).sum::<u64>() % m;
        let b = masked_lows.iter().map(|&x| u64::from(x)).sum::<u64>();
        let (kappa, delta) = clear_kappa_delta::<P>(masked_lows, rhos);
        ((sum_h + (b / alpha) + m - u64::from(kappa) + m - u64::from(delta)) % m) as u32
    }

    fn sample_coeff(seed: &mut u64) -> Coeff {
        *seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        ((*seed >> 16) as i32).rem_euclid(MlDsa44::Q)
    }

    fn assert_clear_identity<P: MlDsaParams>() {
        let mut seed = P::HIGH_MOD as u64;
        for party_count in 1..8 {
            for _ in 0..64 {
                let mut direct_sum = 0i64;
                let mut highs = [0u32; 8];
                let mut lows = [0u32; 8];

                for idx in 0..party_count {
                    let coeff = sample_coeff(&mut seed);
                    direct_sum += i64::from(coeff);
                    highs[idx] = high_bits_unsigned::<P>(coeff) as u32;
                    lows[idx] = low_bits_unsigned::<P>(coeff) as u32;
                }

                let direct = high_bits::<P>(direct_sum.rem_euclid(i64::from(P::Q)) as Coeff);
                let cef = cef_w1_clear_coeff::<P>(&highs[..party_count], &lows[..party_count]);
                assert_eq!(cef, direct as u32);
            }
        }
    }

    fn assert_masked_identity<P: MlDsaParams>() {
        let mut seed = (P::HIGH_MOD as u64) << 32;
        let m = P::HIGH_MOD as u32;

        for _ in 0..128 {
            let coeff0 = sample_coeff(&mut seed);
            let coeff1 = sample_coeff(&mut seed);
            let direct_sum = i64::from(coeff0) + i64::from(coeff1);
            let direct = high_bits::<P>(direct_sum.rem_euclid(i64::from(P::Q)) as Coeff);

            let high0 = high_bits_unsigned::<P>(coeff0) as u32;
            let high1 = high_bits_unsigned::<P>(coeff1) as u32;
            let low0 = low_bits_unsigned::<P>(coeff0) as u32;
            let low1 = low_bits_unsigned::<P>(coeff1) as u32;

            let mask_h = ((seed >> 8) as u32) % m;
            let rho_bound = (P::alpha() as u32) / 4;
            let rho0 = ((seed >> 17) as u32) % rho_bound;
            let rho1 = ((seed >> 29) as u32) % rho_bound;
            let masked_highs = [(high0 + mask_h) % m, (high1 + m - mask_h) % m];
            let masked_lows = [low0 + rho0, low1 + rho1];
            let rhos = [rho0, rho1];

            let cef = cef_w1_coeff::<P>(&masked_highs, &masked_lows, &rhos);
            assert_eq!(cef, direct as u32);
        }
    }

    #[test]
    fn cef_delta_boundary_no_low_mask_carry() {
        assert_delta_boundary_no_low_mask_carry::<MlDsa44>();
        assert_delta_boundary_no_low_mask_carry::<MlDsa65>();
        assert_delta_boundary_no_low_mask_carry::<MlDsa87>();
    }

    #[test]
    fn cef_delta_boundary_with_low_mask_carry() {
        assert_delta_boundary_with_low_mask_carry::<MlDsa44>();
        assert_delta_boundary_with_low_mask_carry::<MlDsa65>();
        assert_delta_boundary_with_low_mask_carry::<MlDsa87>();
    }

    #[test]
    fn cef_delta_exact_boundary() {
        assert_delta_exact_boundary::<MlDsa44>();
        assert_delta_exact_boundary::<MlDsa65>();
        assert_delta_exact_boundary::<MlDsa87>();
    }

    #[test]
    fn cef_delta_upper_boundary() {
        assert_delta_upper_boundary::<MlDsa44>();
        assert_delta_upper_boundary::<MlDsa65>();
        assert_delta_upper_boundary::<MlDsa87>();
    }

    #[test]
    fn cef_minus_delta_formula_fails_boundary_vectors() {
        let base_high = 7u32;
        let no_carry_bsum = (MlDsa65::GAMMA2 + 1) as u32;
        let with_carry_rho = 1_000u32;
        let with_carry_btilde = (MlDsa65::alpha() - 500) as u32 + with_carry_rho;

        assert_ne!(
            cef_w1_coeff::<MlDsa65>(&[base_high], &[no_carry_bsum], &[0]),
            cef_w1_coeff_wrong_minus_delta::<MlDsa65>(&[base_high], &[no_carry_bsum], &[0])
        );
        assert_ne!(
            cef_w1_coeff::<MlDsa65>(&[base_high], &[with_carry_btilde], &[with_carry_rho]),
            cef_w1_coeff_wrong_minus_delta::<MlDsa65>(
                &[base_high],
                &[with_carry_btilde],
                &[with_carry_rho]
            )
        );
    }

    #[test]
    fn cef_identity_clear_representative() {
        assert_clear_identity::<MlDsa44>();
        assert_clear_identity::<MlDsa65>();
        assert_clear_identity::<MlDsa87>();
    }

    #[test]
    fn cef_identity_masked_representative() {
        assert_masked_identity::<MlDsa44>();
        assert_masked_identity::<MlDsa65>();
        assert_masked_identity::<MlDsa87>();
    }
}
