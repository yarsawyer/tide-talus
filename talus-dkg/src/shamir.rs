use super::*;

/// One scalar Shamir share over the ML-DSA field modulus `q`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShamirScalarShare {
    /// Non-zero public interpolation point.
    pub point: u32,
    /// Field value at `point`, reduced into `[0, q)`.
    pub value: Coeff,
}

/// Evaluates a scalar Shamir polynomial at `point` over the ML-DSA field.
///
/// `coefficients[0]` is the secret. Higher coefficients are supplied by the
/// caller so production randomness can come from the DKG sampler.
pub fn evaluate_shamir_polynomial<P: MlDsaParams>(
    coefficients: &[Coeff],
    point: u32,
) -> Result<Coeff, DkgError> {
    validate_interpolation_point::<P>(point)?;
    if coefficients.is_empty() {
        return Err(DkgError::EmptyShamirPolynomial);
    }

    let q = i64::from(P::Q);
    let x = i64::from(point);
    let mut acc = 0i64;
    for &coefficient in coefficients.iter().rev() {
        acc = (acc * x + i64::from(reduce_mod_q::<P>(coefficient))).rem_euclid(q);
    }
    Ok(acc as Coeff)
}

/// Creates scalar Shamir shares for caller-supplied non-zero points.
pub fn share_scalar_with_polynomial<P: MlDsaParams>(
    coefficients: &[Coeff],
    points: &[u32],
) -> Result<Vec<ShamirScalarShare>, DkgError> {
    validate_unique_points::<P>(points)?;
    points
        .iter()
        .map(|&point| {
            Ok(ShamirScalarShare {
                point,
                value: evaluate_shamir_polynomial::<P>(coefficients, point)?,
            })
        })
        .collect()
}

/// Reconstructs the scalar secret at zero from unique Shamir shares.
pub fn reconstruct_scalar_at_zero<P: MlDsaParams>(
    shares: &[ShamirScalarShare],
) -> Result<Coeff, DkgError> {
    if shares.is_empty() {
        return Err(DkgError::EmptyShamirShareSet);
    }
    let points: Vec<u32> = shares.iter().map(|share| share.point).collect();
    validate_unique_points::<P>(&points)?;

    let coefficients = lagrange_coefficients_at_zero::<P>(&points)
        .map_err(|_| DkgError::DuplicateInterpolationPoint)?;
    let q = i64::from(P::Q);
    let secret = coefficients
        .iter()
        .zip(shares)
        .fold(0i64, |acc, (&lambda, share)| {
            (acc + i64::from(lambda) * i64::from(share.value)).rem_euclid(q)
        });
    Ok(secret as Coeff)
}

/// Validates an ML-DSA `s1`/`s2`-shaped bounded secret vector.
pub fn validate_bounded_secret_vector<P: MlDsaParams>(
    coefficients: &[Coeff],
) -> Result<(), DkgError> {
    let expected = P::L * P::N;
    if coefficients.len() != expected {
        return Err(DkgError::InvalidBoundedSecretVectorLength {
            expected,
            got: coefficients.len(),
        });
    }
    for (index, &coefficient) in coefficients.iter().enumerate() {
        if !(-P::ETA..=P::ETA).contains(&coefficient) {
            return Err(DkgError::BoundedSecretCoefficientOutOfRange {
                index,
                coefficient,
                bound: P::ETA,
            });
        }
    }
    Ok(())
}
