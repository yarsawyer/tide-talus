#![doc = "Narrow FIPS 204 NTT and `ExpandA` adapter."]
//!
//! This module vendors only the `fips204-0.4.6` internals needed to compute
//! verifier-side `A*z` for TALUS signature assembly.

use core::fmt;

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

use crate::{Coeff, MlDsaParams, Poly, PolyVec};

const Q: i32 = 8_380_417;
const ZETA: i32 = 1753;

/// NTT/ExpandA adapter failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NttError {
    /// Input vector length did not match ML-DSA `l`.
    ZLength {
        /// Expected polynomial count.
        expected: usize,
        /// Actual polynomial count.
        got: usize,
    },
    /// Matrix row count did not match ML-DSA `k`.
    MatrixRows {
        /// Expected row count.
        expected: usize,
        /// Actual row count.
        got: usize,
    },
    /// Matrix column count did not match ML-DSA `l`.
    MatrixCols {
        /// Row index.
        row: usize,
        /// Expected column count.
        expected: usize,
        /// Actual column count.
        got: usize,
    },
}

impl fmt::Display for NttError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ZLength { expected, got } => {
                write!(f, "bad z vector length: expected {expected}, got {got}")
            }
            Self::MatrixRows { expected, got } => {
                write!(f, "bad A matrix rows: expected {expected}, got {got}")
            }
            Self::MatrixCols { row, expected, got } => {
                write!(
                    f,
                    "bad A matrix cols at row {row}: expected {expected}, got {got}"
                )
            }
        }
    }
}

/// Expands the public ML-DSA matrix seed into an NTT-domain matrix `A`.
pub fn expand_a<P: MlDsaParams>(rho: &[u8; 32]) -> Vec<Vec<Poly>> {
    (0..P::K)
        .map(|row| {
            (0..P::L)
                .map(|col| rej_ntt_poly(&[&rho[..], &[col as u8], &[row as u8]]))
                .collect()
        })
        .collect()
}

/// Computes `A*z` using FIPS `ExpandA`, NTT, matrix multiplication, and inverse
/// NTT.
pub fn az_from_rho<P: MlDsaParams>(rho: &[u8; 32], z: &PolyVec) -> Result<PolyVec, NttError> {
    let a_hat = expand_a::<P>(rho);
    az_from_expanded_a::<P>(&a_hat, z)
}

/// Computes `A*z` from an already-expanded NTT-domain matrix.
pub fn az_from_expanded_a<P: MlDsaParams>(
    a_hat: &[Vec<Poly>],
    z: &PolyVec,
) -> Result<PolyVec, NttError> {
    validate_matrix::<P>(a_hat)?;
    if z.len() != P::L {
        return Err(NttError::ZLength {
            expected: P::L,
            got: z.len(),
        });
    }

    let z_hat: Vec<Poly> = z.polys().iter().map(ntt_poly).collect();
    let az_hat = mat_vec_mul::<P>(a_hat, &z_hat);
    Ok(PolyVec::new(az_hat.iter().map(inv_ntt_poly).collect()))
}

/// Computes FIPS NTT for one polynomial.
pub fn ntt_poly(poly: &Poly) -> Poly {
    let mut out = *poly.coeffs();
    let mut m = 0usize;
    let mut len = 128usize;

    while len >= 1 {
        let mut start = 0usize;
        while start < 256 {
            m += 1;
            let zeta = i64::from(ZETA_TABLE_MONT[m]);
            for j in start..(start + len) {
                let t = mont_reduce(zeta * i64::from(out[j + len]));
                out[j + len] = out[j] - t;
                out[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }

    Poly::from_coeffs(out)
}

/// Computes FIPS inverse NTT for one polynomial.
pub fn inv_ntt_poly(poly: &Poly) -> Poly {
    const F_MONT: i64 = 8_347_681_i128.wrapping_mul(1 << 32).rem_euclid(Q as i128) as i64;

    let mut out = *poly.coeffs();
    let mut m = 256usize;
    let mut len = 1usize;

    while len < 256 {
        let mut start = 0usize;
        while start < 256 {
            m -= 1;
            let zeta = -ZETA_TABLE_MONT[m];
            for j in start..(start + len) {
                let t = out[j];
                out[j] = t + out[j + len];
                out[j + len] = t - out[j + len];
                out[j + len] = mont_reduce(i64::from(zeta) * i64::from(out[j + len]));
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    for coeff in &mut out {
        *coeff = full_reduce32(mont_reduce(F_MONT * i64::from(*coeff)));
    }

    Poly::from_coeffs(out)
}

fn validate_matrix<P: MlDsaParams>(a_hat: &[Vec<Poly>]) -> Result<(), NttError> {
    if a_hat.len() != P::K {
        return Err(NttError::MatrixRows {
            expected: P::K,
            got: a_hat.len(),
        });
    }
    for (row, cols) in a_hat.iter().enumerate() {
        if cols.len() != P::L {
            return Err(NttError::MatrixCols {
                row,
                expected: P::L,
                got: cols.len(),
            });
        }
    }
    Ok(())
}

fn mat_vec_mul<P: MlDsaParams>(a_hat: &[Vec<Poly>], z_hat: &[Poly]) -> Vec<Poly> {
    let z_hat_mont = to_mont(z_hat);
    let mut out = vec![Poly::zero(); P::K];

    for (row, row_polys) in a_hat.iter().enumerate().take(P::K) {
        for col in 0..P::L {
            for coeff in 0..P::N {
                out[row].coeffs_mut()[coeff] += mont_reduce(
                    i64::from(row_polys[col].coeffs()[coeff])
                        * i64::from(z_hat_mont[col].coeffs()[coeff]),
                );
            }
        }
    }

    out
}

fn to_mont(polys: &[Poly]) -> Vec<Poly> {
    polys
        .iter()
        .map(|poly| {
            Poly::from_coeffs(core::array::from_fn(|i| {
                partial_reduce64(i64::from(poly.coeffs()[i]) << 32)
            }))
        })
        .collect()
}

fn rej_ntt_poly(rhos: &[&[u8]]) -> Poly {
    debug_assert_eq!(rhos.iter().map(|rho| rho.len()).sum::<usize>(), 272 / 8);
    let mut out = [0i32; 256];
    let mut j = 0usize;
    let mut xof = shake128_xof(rhos);

    while j < 256 {
        let mut bytes = [0u8; 3];
        xof.read(&mut bytes);
        if let Some(coeff) = coeff_from_three_bytes(bytes) {
            out[j] = coeff;
            j += 1;
        }
    }

    Poly::from_coeffs(out)
}

fn coeff_from_three_bytes(bytes: [u8; 3]) -> Option<Coeff> {
    let b2 = i32::from(bytes[2] & 0x7f);
    let coeff = (b2 << 16) | (i32::from(bytes[1]) << 8) | i32::from(bytes[0]);
    (coeff < Q).then_some(coeff)
}

fn shake128_xof(chunks: &[&[u8]]) -> impl XofReader {
    let mut hasher = Shake128::default();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize_xof()
}

const fn partial_reduce32(a: i32) -> i32 {
    let x = (a + (1 << 22)) >> 23;
    a - x * Q
}

const fn full_reduce32(a: i32) -> i32 {
    let x = partial_reduce32(a);
    x + ((x >> 31) & Q)
}

const fn partial_reduce64(a: i64) -> i32 {
    const M: i64 = (1 << 48) / (Q as i64);
    let x = a >> 23;
    let a = a - x * (Q as i64);
    let x = a >> 23;
    let a = a - x * (Q as i64);
    let q = (a * M) >> 48;
    (a - q * (Q as i64)) as i32
}

const fn mont_reduce(a: i64) -> i32 {
    const QINV: i32 = 58_728_449;
    let t = (a as i32).wrapping_mul(QINV);
    ((a - (t as i64).wrapping_mul(Q as i64)) >> 32) as i32
}

const fn gen_zeta_table_mont() -> [i32; 256] {
    let mut result = [0i32; 256];
    let mut x = 1i64;
    let mut i = 0u32;
    while i < 256 {
        result[(i as u8).reverse_bits() as usize] = ((x << 32) % (Q as i64)) as i32;
        x = (x * ZETA as i64) % (Q as i64);
        i += 1;
    }
    result
}

static ZETA_TABLE_MONT: [i32; 256] = gen_zeta_table_mont();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlDsa44, MlDsa65, MlDsa87};

    fn schoolbook_mul<P: MlDsaParams>(left: &Poly, right: &Poly) -> Poly {
        let mut out = [0i64; 256];
        for (i, &left_coeff) in left.coeffs().iter().enumerate() {
            for (j, &right_coeff) in right.coeffs().iter().enumerate() {
                let degree = i + j;
                let product = i64::from(left_coeff) * i64::from(right_coeff);
                if degree < 256 {
                    out[degree] += product;
                } else {
                    out[degree - 256] -= product;
                }
            }
        }
        Poly::from_coeffs(core::array::from_fn(|i| {
            out[i].rem_euclid(i64::from(P::Q)) as i32
        }))
    }

    fn check_ntt_roundtrip<P: MlDsaParams>() {
        let poly = Poly::from_coeffs(core::array::from_fn(|i| ((i * 17 + 3) as i32) % P::Q));
        assert_eq!(inv_ntt_poly(&ntt_poly(&poly)), poly);
    }

    #[test]
    fn ntt_roundtrip_all_parameter_sets() {
        check_ntt_roundtrip::<MlDsa44>();
        check_ntt_roundtrip::<MlDsa65>();
        check_ntt_roundtrip::<MlDsa87>();
    }

    #[test]
    fn expand_a_has_expected_shape_and_ranges() {
        let a = expand_a::<MlDsa65>(&[0x42; 32]);
        assert_eq!(a.len(), MlDsa65::K);
        assert_eq!(a[0].len(), MlDsa65::L);
        assert!(a
            .iter()
            .flatten()
            .flat_map(|poly| poly.coeffs())
            .all(|&coeff| (0..MlDsa65::Q).contains(&coeff)));
    }

    #[test]
    fn az_from_expanded_a_matches_schoolbook_for_one_hot_matrix() {
        let mut a = vec![vec![Poly::zero(); MlDsa65::L]; MlDsa65::K];
        let identity = Poly::from_coeffs(core::array::from_fn(|i| i32::from(i == 0)));
        a[0][0] = ntt_poly(&identity);

        let mut z = PolyVec::zero(MlDsa65::L);
        z.polys_mut()[0] = Poly::from_coeffs(core::array::from_fn(|i| i as i32));

        let az = az_from_expanded_a::<MlDsa65>(&a, &z).expect("az");
        assert_eq!(az.polys()[0], z.polys()[0]);
        assert!(az.polys()[1..].iter().all(|poly| *poly == Poly::zero()));
    }

    #[test]
    fn az_from_expanded_a_matches_schoolbook_for_representative_matrix() {
        let mut a = vec![vec![Poly::zero(); MlDsa65::L]; MlDsa65::K];
        let a00 = Poly::from_coeffs(core::array::from_fn(|i| ((i % 7) as i32) - 3));
        let a01 = Poly::from_coeffs(core::array::from_fn(|i| ((i % 5) as i32) - 2));
        a[0][0] = ntt_poly(&a00);
        a[0][1] = ntt_poly(&a01);

        let mut z = PolyVec::zero(MlDsa65::L);
        z.polys_mut()[0] = Poly::from_coeffs(core::array::from_fn(|i| ((i % 3) as i32) - 1));
        z.polys_mut()[1] = Poly::from_coeffs(core::array::from_fn(|i| ((i % 4) as i32) - 2));

        let az = az_from_expanded_a::<MlDsa65>(&a, &z).expect("az");
        let expected = schoolbook_mul::<MlDsa65>(&a00, &z.polys()[0])
            .add_mod_q::<MlDsa65>(&schoolbook_mul::<MlDsa65>(&a01, &z.polys()[1]));
        assert_eq!(az.polys()[0], expected);
    }

    #[test]
    fn az_from_expanded_a_rejects_bad_shapes() {
        assert_eq!(
            az_from_expanded_a::<MlDsa65>(&[], &PolyVec::zero(MlDsa65::L)),
            Err(NttError::MatrixRows {
                expected: MlDsa65::K,
                got: 0,
            })
        );

        let a = vec![vec![Poly::zero(); MlDsa65::L - 1]; MlDsa65::K];
        assert_eq!(
            az_from_expanded_a::<MlDsa65>(&a, &PolyVec::zero(MlDsa65::L)),
            Err(NttError::MatrixCols {
                row: 0,
                expected: MlDsa65::L,
                got: MlDsa65::L - 1,
            })
        );

        let a = vec![vec![Poly::zero(); MlDsa65::L]; MlDsa65::K];
        assert_eq!(
            az_from_expanded_a::<MlDsa65>(&a, &PolyVec::zero(MlDsa65::L - 1)),
            Err(NttError::ZLength {
                expected: MlDsa65::L,
                got: MlDsa65::L - 1,
            })
        );
    }
}
