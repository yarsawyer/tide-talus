#![doc = "Narrow vendored adapter for `fips204` internals needed by TALUS."]
//!
//! The published `fips204` crate keeps the high/low-bit helpers `pub(crate)`.
//! TALUS needs those helpers for BCC, public hint computation, and CEF tests.
//! This module carries a minimal, attributed adapter copied from
//! `fips204-0.4.6/src/high_low.rs`, with generic parameter metadata supplied by
//! `talus-core`.
//!
//! Keep this module small. If more internals are needed, copy only the required
//! helper and add parity/boundary tests at the TALUS API layer.

use crate::params::MlDsaParams;

/// ML-DSA coefficient type.
pub type Coeff = i32;

/// Reduces an integer into `[0, q)`.
pub fn reduce_mod_q<P: MlDsaParams>(r: Coeff) -> Coeff {
    r.rem_euclid(P::Q)
}

/// FIPS 204 Power2Round for a single coefficient.
pub fn power2round<P: MlDsaParams>(r: Coeff) -> (Coeff, Coeff) {
    let rp = reduce_mod_q::<P>(r);
    let high = (rp + (1i32 << (P::D - 1)) - 1) >> P::D;
    let low = rp - (high << P::D);
    (high, low)
}

/// FIPS 204 Decompose for a single coefficient.
pub fn decompose<P: MlDsaParams>(r: Coeff) -> (Coeff, Coeff) {
    let gamma2 = P::GAMMA2;
    let rp = reduce_mod_q::<P>(r);

    let mut high = (rp + 127) >> 7;
    if gamma2 & (1 << 17) == 0 {
        high = (high * 11_275 + (1 << 23)) >> 24;
        high ^= ((43 - high) >> 31) & high;
    } else {
        high = (high * 1_025 + (1 << 21)) >> 22;
        high &= 15;
    }

    let low = rp - high * 2 * gamma2;
    let low = low - ((((P::Q - 1) / 2 - low) >> 31) & P::Q);

    debug_assert_eq!(rp, (high * 2 * gamma2 + low).rem_euclid(P::Q));
    (high, low)
}

/// FIPS 204 HighBits for a single coefficient.
pub fn high_bits<P: MlDsaParams>(r: Coeff) -> Coeff {
    decompose::<P>(r).0
}

/// FIPS 204 signed LowBits for a single coefficient.
pub fn low_bits_signed<P: MlDsaParams>(r: Coeff) -> Coeff {
    decompose::<P>(r).1
}

/// FIPS 204 MakeHint for a single coefficient.
pub fn make_hint<P: MlDsaParams>(z: Coeff, r: Coeff) -> bool {
    high_bits::<P>(r) != high_bits::<P>(r + z)
}

/// FIPS 204 UseHint for a single coefficient.
pub fn use_hint<P: MlDsaParams>(hint: bool, r: Coeff) -> Coeff {
    let gamma2 = P::GAMMA2;
    let (high, low) = decompose::<P>(r);

    if !hint {
        return high;
    }

    if gamma2 & (1 << 17) == 0 {
        if low > 0 {
            if high == 43 {
                0
            } else {
                high + 1
            }
        } else if high == 0 {
            43
        } else {
            high - 1
        }
    } else if low > 0 {
        (high + 1) & 15
    } else {
        (high - 1) & 15
    }
}
