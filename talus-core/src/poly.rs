#![doc = "Small FIPS-sized polynomial helpers for TALUS protocol assembly."]

use core::fmt;

use crate::{reduce_mod_q, sample_in_ball, Coeff, MlDsaParams};

/// Polynomial adapter failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolyError {
    /// Challenge seed length did not match the selected ML-DSA suite.
    ChallengeLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
    /// Polynomial vector length mismatch.
    PolyVecLength {
        /// Expected polynomial count.
        expected: usize,
        /// Actual polynomial count.
        got: usize,
    },
    /// No partial `z` shares were supplied for aggregation.
    EmptyPartialSet,
    /// Interpolation point count did not match the partial-share count.
    InterpolationPointCountMismatch {
        /// Number of interpolation points.
        points: usize,
        /// Number of polynomial shares.
        shares: usize,
    },
    /// Duplicate interpolation point.
    DuplicateInterpolationPoint(u32),
}

impl fmt::Display for PolyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ChallengeLength { expected, got } => {
                write!(f, "bad challenge length: expected {expected}, got {got}")
            }
            Self::PolyVecLength { expected, got } => {
                write!(
                    f,
                    "bad polynomial vector length: expected {expected}, got {got}"
                )
            }
            Self::EmptyPartialSet => write!(f, "empty partial z set"),
            Self::InterpolationPointCountMismatch { points, shares } => {
                write!(
                    f,
                    "interpolation point count mismatch: {points} points, {shares} shares"
                )
            }
            Self::DuplicateInterpolationPoint(point) => {
                write!(f, "duplicate interpolation point: {point}")
            }
        }
    }
}

/// One ML-DSA ring polynomial with 256 coefficients.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poly {
    coeffs: [Coeff; 256],
}

impl Poly {
    /// Returns the zero polynomial.
    pub const fn zero() -> Self {
        Self { coeffs: [0; 256] }
    }

    /// Creates a polynomial from raw coefficients.
    pub const fn from_coeffs(coeffs: [Coeff; 256]) -> Self {
        Self { coeffs }
    }

    /// Returns the coefficient slice.
    pub const fn coeffs(&self) -> &[Coeff; 256] {
        &self.coeffs
    }

    /// Returns the mutable coefficient slice.
    pub fn coeffs_mut(&mut self) -> &mut [Coeff; 256] {
        &mut self.coeffs
    }

    /// Adds two polynomials coefficient-wise modulo `q`.
    pub fn add_mod_q<P: MlDsaParams>(&self, rhs: &Self) -> Self {
        Self::from_coeffs(core::array::from_fn(|i| {
            reduce_mod_q::<P>(self.coeffs[i] + rhs.coeffs[i])
        }))
    }

    /// Subtracts two polynomials coefficient-wise modulo `q`.
    pub fn sub_mod_q<P: MlDsaParams>(&self, rhs: &Self) -> Self {
        Self::from_coeffs(core::array::from_fn(|i| {
            reduce_mod_q::<P>(self.coeffs[i] - rhs.coeffs[i])
        }))
    }

    /// Multiplies a polynomial by a scalar modulo `q`.
    pub fn mul_scalar_mod_q<P: MlDsaParams>(&self, scalar: Coeff) -> Self {
        let scalar = i64::from(reduce_mod_q::<P>(scalar));
        Self::from_coeffs(core::array::from_fn(|i| {
            reduce_i64_mod_q::<P>(i64::from(self.coeffs[i]) * scalar)
        }))
    }
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}

/// A dynamically sized vector of ML-DSA polynomials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolyVec {
    polys: Vec<Poly>,
}

impl PolyVec {
    /// Creates a polynomial vector.
    pub fn new(polys: Vec<Poly>) -> Self {
        Self { polys }
    }

    /// Returns a zero polynomial vector of `len` polynomials.
    pub fn zero(len: usize) -> Self {
        Self {
            polys: vec![Poly::zero(); len],
        }
    }

    /// Returns the polynomial slice.
    pub fn polys(&self) -> &[Poly] {
        &self.polys
    }

    /// Returns the mutable polynomial slice.
    pub fn polys_mut(&mut self) -> &mut [Poly] {
        &mut self.polys
    }

    /// Returns the vector length.
    pub fn len(&self) -> usize {
        self.polys.len()
    }

    /// Returns whether the vector is empty.
    pub fn is_empty(&self) -> bool {
        self.polys.is_empty()
    }

    /// Adds two polynomial vectors coefficient-wise modulo `q`.
    pub fn add_mod_q<P: MlDsaParams>(&self, rhs: &Self) -> Self {
        assert_eq!(self.len(), rhs.len(), "PolyVec add: length mismatch");
        Self::new(
            self.polys
                .iter()
                .zip(rhs.polys.iter())
                .map(|(left, right)| left.add_mod_q::<P>(right))
                .collect(),
        )
    }

    /// Subtracts two polynomial vectors coefficient-wise modulo `q`.
    pub fn sub_mod_q<P: MlDsaParams>(&self, rhs: &Self) -> Self {
        assert_eq!(self.len(), rhs.len(), "PolyVec sub: length mismatch");
        Self::new(
            self.polys
                .iter()
                .zip(rhs.polys.iter())
                .map(|(left, right)| left.sub_mod_q::<P>(right))
                .collect(),
        )
    }

    /// Multiplies a polynomial vector by a scalar modulo `q`.
    pub fn mul_scalar_mod_q<P: MlDsaParams>(&self, scalar: Coeff) -> Self {
        Self::new(
            self.polys
                .iter()
                .map(|poly| poly.mul_scalar_mod_q::<P>(scalar))
                .collect(),
        )
    }
}

/// Multiplies a polynomial by the sparse FIPS challenge polynomial in
/// `Z_q[x] / (x^256 + 1)`.
pub fn mul_challenge_poly<P: MlDsaParams>(challenge: &[Coeff; 256], poly: &Poly) -> Poly {
    let mut out = [0i64; 256];
    for (challenge_index, &challenge_coeff) in challenge.iter().enumerate() {
        if challenge_coeff == 0 {
            continue;
        }
        debug_assert!(matches!(challenge_coeff, -1 | 1));

        for (poly_index, &poly_coeff) in poly.coeffs.iter().enumerate() {
            let degree = challenge_index + poly_index;
            let signed_product = i64::from(challenge_coeff) * i64::from(poly_coeff);
            if degree < 256 {
                out[degree] += signed_product;
            } else {
                out[degree - 256] -= signed_product;
            }
        }
    }

    Poly::from_coeffs(core::array::from_fn(|i| reduce_i64_mod_q::<P>(out[i])))
}

/// Multiplies every polynomial in a vector by the sparse challenge polynomial.
pub fn mul_challenge_polyvec<P: MlDsaParams>(
    challenge: &[Coeff; 256],
    polyvec: &PolyVec,
) -> PolyVec {
    PolyVec::new(
        polyvec
            .polys()
            .iter()
            .map(|poly| mul_challenge_poly::<P>(challenge, poly))
            .collect(),
    )
}

/// Computes one additive partial ML-DSA response share:
/// `z_i = y_i + c * s1_i`.
pub fn partial_z_share<P: MlDsaParams>(
    ctilde: &[u8],
    y_share: &PolyVec,
    s1_share: &PolyVec,
) -> Result<PolyVec, PolyError> {
    if ctilde.len() != P::CTILDE_LEN {
        return Err(PolyError::ChallengeLength {
            expected: P::CTILDE_LEN,
            got: ctilde.len(),
        });
    }

    let challenge = sample_in_ball::<P>(ctilde);
    partial_z_share_with_challenge::<P>(&challenge, y_share, s1_share)
}

/// Computes one additive partial response share from an already-expanded
/// challenge polynomial.
pub fn partial_z_share_with_challenge<P: MlDsaParams>(
    challenge: &[Coeff; 256],
    y_share: &PolyVec,
    s1_share: &PolyVec,
) -> Result<PolyVec, PolyError> {
    validate_polyvec_len::<P>(y_share)?;
    validate_polyvec_len::<P>(s1_share)?;

    let cs1 = mul_challenge_polyvec::<P>(challenge, s1_share);
    Ok(y_share.add_mod_q::<P>(&cs1))
}

/// Aggregates additive partial response shares into one ML-DSA `z` vector.
pub fn aggregate_z_shares<P: MlDsaParams>(shares: &[PolyVec]) -> Result<PolyVec, PolyError> {
    let Some((first, rest)) = shares.split_first() else {
        return Err(PolyError::EmptyPartialSet);
    };
    validate_polyvec_len::<P>(first)?;

    let mut aggregate = first.clone();
    for share in rest {
        validate_polyvec_len::<P>(share)?;
        aggregate = aggregate.add_mod_q::<P>(share);
    }

    Ok(aggregate)
}

/// Computes Lagrange coefficients at zero for unique public interpolation
/// points modulo the ML-DSA field modulus `q`.
pub fn lagrange_coefficients_at_zero<P: MlDsaParams>(
    points: &[u32],
) -> Result<Vec<Coeff>, PolyError> {
    let q = i64::from(P::Q);
    let mut coefficients = Vec::with_capacity(points.len());

    for (i, &xi) in points.iter().enumerate() {
        let xi = i64::from(xi) % q;
        let mut numerator = 1i64;
        let mut denominator = 1i64;

        for (j, &xj) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = i64::from(xj) % q;
            if xi == xj {
                return Err(PolyError::DuplicateInterpolationPoint(points[i]));
            }

            numerator = (numerator * (-xj).rem_euclid(q)).rem_euclid(q);
            denominator = (denominator * (xi - xj).rem_euclid(q)).rem_euclid(q);
        }

        coefficients.push(reduce_i64_mod_q::<P>(
            numerator * mod_inverse_prime(denominator, q),
        ));
    }

    Ok(coefficients)
}

/// Aggregates Shamir-style partial response shares using Lagrange
/// interpolation at zero.
pub fn aggregate_z_shares_lagrange<P: MlDsaParams>(
    points: &[u32],
    shares: &[PolyVec],
) -> Result<PolyVec, PolyError> {
    if points.len() != shares.len() {
        return Err(PolyError::InterpolationPointCountMismatch {
            points: points.len(),
            shares: shares.len(),
        });
    }
    let Some((first, rest)) = shares.split_first() else {
        return Err(PolyError::EmptyPartialSet);
    };
    validate_polyvec_len::<P>(first)?;
    for share in rest {
        validate_polyvec_len::<P>(share)?;
    }

    let coefficients = lagrange_coefficients_at_zero::<P>(points)?;
    let mut aggregate = PolyVec::zero(P::L);
    for (coefficient, share) in coefficients.iter().zip(shares) {
        aggregate = aggregate.add_mod_q::<P>(&share.mul_scalar_mod_q::<P>(*coefficient));
    }

    Ok(aggregate)
}

/// Computes the FIPS-style infinity norm after centering coefficients modulo `q`.
pub fn infinity_norm<P: MlDsaParams>(polyvec: &PolyVec) -> Coeff {
    polyvec
        .polys()
        .iter()
        .flat_map(|poly| poly.coeffs())
        .map(|&coeff| center_mod_q::<P>(coeff).abs())
        .max()
        .unwrap_or(0)
}

/// Returns whether `z` satisfies the ML-DSA signing bound.
pub fn z_bound_holds<P: MlDsaParams>(z: &PolyVec) -> bool {
    infinity_norm::<P>(z) < P::GAMMA1 - P::BETA
}

fn validate_polyvec_len<P: MlDsaParams>(polyvec: &PolyVec) -> Result<(), PolyError> {
    if polyvec.len() != P::L {
        return Err(PolyError::PolyVecLength {
            expected: P::L,
            got: polyvec.len(),
        });
    }
    Ok(())
}

fn center_mod_q<P: MlDsaParams>(coeff: Coeff) -> Coeff {
    let reduced = reduce_mod_q::<P>(coeff);
    if reduced > P::Q / 2 {
        reduced - P::Q
    } else {
        reduced
    }
}

fn reduce_i64_mod_q<P: MlDsaParams>(value: i64) -> Coeff {
    value.rem_euclid(i64::from(P::Q)) as Coeff
}

fn mod_inverse_prime(value: i64, modulus: i64) -> i64 {
    debug_assert_ne!(value.rem_euclid(modulus), 0);
    mod_pow(value, modulus - 2, modulus)
}

fn mod_pow(mut base: i64, mut exponent: i64, modulus: i64) -> i64 {
    base = base.rem_euclid(modulus);
    let mut result = 1i64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = (result * base).rem_euclid(modulus);
        }
        base = (base * base).rem_euclid(modulus);
        exponent >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlDsa44, MlDsa65, MlDsa87};

    fn poly_with_coeffs(coeffs: &[(usize, Coeff)]) -> Poly {
        let mut poly = Poly::zero();
        for &(index, coeff) in coeffs {
            poly.coeffs_mut()[index] = coeff;
        }
        poly
    }

    #[test]
    fn poly_add_sub_roundtrip_mod_q() {
        let left = poly_with_coeffs(&[(0, MlDsa65::Q - 1), (1, 10)]);
        let right = poly_with_coeffs(&[(0, 2), (1, -20)]);
        let sum = left.add_mod_q::<MlDsa65>(&right);
        assert_eq!(sum.coeffs()[0], 1);
        assert_eq!(sum.coeffs()[1], MlDsa65::Q - 10);
        assert_eq!(sum.sub_mod_q::<MlDsa65>(&right), left);
    }

    #[test]
    fn scalar_multiplication_reduces_mod_q() {
        let poly = poly_with_coeffs(&[(0, MlDsa65::Q - 1), (1, 3)]);
        let product = poly.mul_scalar_mod_q::<MlDsa65>(2);
        assert_eq!(product.coeffs()[0], MlDsa65::Q - 2);
        assert_eq!(product.coeffs()[1], 6);
    }

    #[test]
    fn challenge_multiplication_identity_and_negacyclic_shift() {
        let poly = poly_with_coeffs(&[(0, 3), (254, 7), (255, 11)]);

        let mut one = [0i32; 256];
        one[0] = 1;
        assert_eq!(mul_challenge_poly::<MlDsa65>(&one, &poly), poly);

        let mut x = [0i32; 256];
        x[1] = 1;
        let shifted = mul_challenge_poly::<MlDsa65>(&x, &poly);
        assert_eq!(shifted.coeffs()[1], 3);
        assert_eq!(shifted.coeffs()[255], 7);
        assert_eq!(shifted.coeffs()[0], MlDsa65::Q - 11);
    }

    #[test]
    fn sampled_challenge_multiplication_stays_mod_q() {
        let challenge = sample_in_ball::<MlDsa65>(&[0x42; 48]);
        let poly = Poly::from_coeffs(core::array::from_fn(|i| i as i32 - 128));
        let product = mul_challenge_poly::<MlDsa65>(&challenge, &poly);
        assert!(product
            .coeffs()
            .iter()
            .all(|&coeff| (0..MlDsa65::Q).contains(&coeff)));
    }

    #[test]
    fn infinity_norm_and_z_bound_are_parameterized() {
        let z = PolyVec::new(vec![poly_with_coeffs(&[(
            0,
            MlDsa65::GAMMA1 - MlDsa65::BETA - 1,
        )])]);
        assert_eq!(
            infinity_norm::<MlDsa65>(&z),
            MlDsa65::GAMMA1 - MlDsa65::BETA - 1
        );
        assert!(z_bound_holds::<MlDsa65>(&z));

        let z = PolyVec::new(vec![poly_with_coeffs(&[(
            0,
            MlDsa65::GAMMA1 - MlDsa65::BETA,
        )])]);
        assert!(!z_bound_holds::<MlDsa65>(&z));
    }

    #[test]
    fn z_bound_checks_all_supported_suites() {
        assert!(z_bound_holds::<MlDsa44>(&PolyVec::zero(MlDsa44::L)));
        assert!(z_bound_holds::<MlDsa65>(&PolyVec::zero(MlDsa65::L)));
        assert!(z_bound_holds::<MlDsa87>(&PolyVec::zero(MlDsa87::L)));
    }

    #[test]
    fn partial_z_share_matches_explicit_challenge_multiplication() {
        let ctilde = [0x42; 48];
        let challenge = sample_in_ball::<MlDsa65>(&ctilde);
        let y = PolyVec::new(
            (0..MlDsa65::L)
                .map(|row| Poly::from_coeffs(core::array::from_fn(|i| row as i32 + i as i32)))
                .collect(),
        );
        let s1 = PolyVec::new(
            (0..MlDsa65::L)
                .map(|row| {
                    Poly::from_coeffs(core::array::from_fn(|i| {
                        ((row + 1) as i32) * ((i % 5) as i32 - 2)
                    }))
                })
                .collect(),
        );

        let z = partial_z_share::<MlDsa65>(&ctilde, &y, &s1).expect("partial z");
        let expected = y.add_mod_q::<MlDsa65>(&mul_challenge_polyvec::<MlDsa65>(&challenge, &s1));
        assert_eq!(z, expected);
    }

    #[test]
    fn aggregate_z_shares_adds_all_partials_mod_q() {
        let a = PolyVec::new(vec![poly_with_coeffs(&[(0, MlDsa65::Q - 1)]); MlDsa65::L]);
        let b = PolyVec::new(vec![poly_with_coeffs(&[(0, 2), (1, 5)]); MlDsa65::L]);

        let aggregate = aggregate_z_shares::<MlDsa65>(&[a, b]).expect("aggregate");
        for poly in aggregate.polys() {
            assert_eq!(poly.coeffs()[0], 1);
            assert_eq!(poly.coeffs()[1], 5);
        }
    }

    #[test]
    fn lagrange_coefficients_reconstruct_at_zero() {
        let coefficients = lagrange_coefficients_at_zero::<MlDsa65>(&[1, 2]).expect("coefficients");
        assert_eq!(coefficients, vec![2, MlDsa65::Q - 1]);

        let points = [1, 2, 4];
        let coefficients = lagrange_coefficients_at_zero::<MlDsa65>(&points).expect("coefficients");
        let values = [14i64, 17, 23];
        let reconstructed = coefficients
            .iter()
            .zip(values)
            .fold(0i64, |acc, (&lambda, value)| {
                (acc + i64::from(lambda) * value).rem_euclid(i64::from(MlDsa65::Q))
            });
        assert_eq!(reconstructed, 11);
    }

    #[test]
    fn aggregate_z_shares_lagrange_reconstructs_secret_share() {
        let points = [1, 2];
        let first = PolyVec::new(vec![poly_with_coeffs(&[(0, 14)]); MlDsa65::L]);
        let second = PolyVec::new(vec![poly_with_coeffs(&[(0, 17)]); MlDsa65::L]);

        let aggregate =
            aggregate_z_shares_lagrange::<MlDsa65>(&points, &[first, second]).expect("aggregate");

        for poly in aggregate.polys() {
            assert_eq!(poly.coeffs()[0], 11);
        }
    }

    #[test]
    fn partial_z_share_rejects_bad_lengths() {
        let ctilde = [0x42; 47];
        let y = PolyVec::zero(MlDsa65::L);
        let s1 = PolyVec::zero(MlDsa65::L);
        assert_eq!(
            partial_z_share::<MlDsa65>(&ctilde, &y, &s1),
            Err(PolyError::ChallengeLength {
                expected: MlDsa65::CTILDE_LEN,
                got: ctilde.len(),
            })
        );

        let ctilde = [0x42; 48];
        let bad_y = PolyVec::zero(MlDsa65::L - 1);
        assert_eq!(
            partial_z_share::<MlDsa65>(&ctilde, &bad_y, &s1),
            Err(PolyError::PolyVecLength {
                expected: MlDsa65::L,
                got: MlDsa65::L - 1,
            })
        );
    }

    #[test]
    fn aggregate_z_shares_rejects_empty_and_bad_lengths() {
        assert_eq!(
            aggregate_z_shares::<MlDsa65>(&[]),
            Err(PolyError::EmptyPartialSet)
        );

        let bad = PolyVec::zero(MlDsa65::L + 1);
        assert_eq!(
            aggregate_z_shares::<MlDsa65>(&[bad]),
            Err(PolyError::PolyVecLength {
                expected: MlDsa65::L,
                got: MlDsa65::L + 1,
            })
        );
    }

    #[test]
    fn aggregate_z_shares_lagrange_rejects_bad_inputs() {
        assert_eq!(
            aggregate_z_shares_lagrange::<MlDsa65>(&[1], &[]),
            Err(PolyError::InterpolationPointCountMismatch {
                points: 1,
                shares: 0,
            })
        );

        let share = PolyVec::zero(MlDsa65::L);
        assert_eq!(
            aggregate_z_shares_lagrange::<MlDsa65>(&[1, 1], &[share.clone(), share]),
            Err(PolyError::DuplicateInterpolationPoint(1))
        );
    }
}
