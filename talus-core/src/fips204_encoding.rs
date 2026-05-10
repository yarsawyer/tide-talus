#![doc = "Narrow FIPS 204 encoding and challenge adapter surface."]

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{mul_challenge_polyvec, Coeff, MlDsaParams, Poly, PolyVec};

/// Decoded ML-DSA public-key components needed by verifier-side TALUS assembly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyParts {
    /// Public matrix seed.
    pub rho: [u8; 32],
    /// Public `t1` vector.
    pub t1: PolyVec,
}

/// FIPS public-key decoding failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicKeyDecodeError {
    /// Public key length did not match the selected ML-DSA suite.
    PublicKeyLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
    /// Decoded `t1` coefficient was outside the FIPS range.
    T1OutOfRange {
        /// Flat coefficient index.
        index: usize,
        /// Invalid value.
        value: Coeff,
    },
}

/// FIPS signature encoding failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureEncodingError {
    /// Challenge seed length did not match the selected ML-DSA suite.
    CtildeLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
    /// Response vector length did not match ML-DSA `l`.
    ZLength {
        /// Expected polynomial count.
        expected: usize,
        /// Actual polynomial count.
        got: usize,
    },
    /// Hint vector length did not match ML-DSA `k`.
    HintLength {
        /// Expected polynomial count.
        expected: usize,
        /// Actual polynomial count.
        got: usize,
    },
    /// Centered `z` coefficient is outside the FIPS signature encoding range.
    ZOutOfRange {
        /// Flat coefficient index.
        index: usize,
        /// Centered coefficient value.
        value: Coeff,
    },
    /// Hint coefficient is not binary.
    HintCoeffOutOfRange {
        /// Flat coefficient index.
        index: usize,
        /// Invalid value.
        value: Coeff,
    },
    /// Hint weight exceeds ML-DSA `omega`.
    HintWeight {
        /// Maximum allowed weight.
        omega: usize,
        /// Actual weight.
        got: usize,
    },
}

/// Returns the FIPS 204 bit length of a positive integer.
pub const fn bit_length(x: i32) -> usize {
    x.ilog2() as usize + 1
}

/// Returns the FIPS Algorithm 28 `w1Encode(w1)` output length in bytes.
pub fn w1_encoded_len<P: MlDsaParams>() -> usize {
    32 * P::K * bit_length(P::HIGH_MOD - 1)
}

/// Returns the FIPS ML-DSA signature length in bytes.
pub fn signature_encoded_len<P: MlDsaParams>() -> usize {
    P::CTILDE_LEN + P::L * 32 * (1 + bit_length(P::GAMMA1 - 1)) + P::OMEGA + P::K
}

/// Returns the FIPS ML-DSA public key length in bytes.
pub fn public_key_encoded_len<P: MlDsaParams>() -> usize {
    32 + 32 * P::K * (bit_length(P::Q - 1) - P::D)
}

/// Computes the FIPS public-key transcript hash `tr = H(pk, 64)`.
pub fn compute_tr(public_key: &[u8]) -> [u8; 64] {
    let mut reader = shake256_xof(&[public_key]);
    let mut tr = [0u8; 64];
    reader.read(&mut tr);
    tr
}

/// Encodes a flat `R^k` high-bit vector with FIPS Algorithm 28.
///
/// This is a narrow, attributed adapter copied from the `fips204-0.4.6`
/// `encodings::w1_encode`/`conversion::simple_bit_pack` behavior. It exists so
/// TALUS can share verifier-compatible challenge material without depending on
/// broad private internals.
pub fn w1_encode<P: MlDsaParams>(w1: &[u32]) -> Vec<u8> {
    assert_eq!(w1.len(), P::K * P::N, "FIPS w1Encode: bad w1 length");
    let max = (P::HIGH_MOD - 1) as u32;
    assert!(
        w1.iter().all(|&coeff| coeff <= max),
        "FIPS w1Encode: coefficient out of range"
    );

    let coeff_bits = bit_length(P::HIGH_MOD - 1);
    let step = 32 * coeff_bits;
    let mut out = vec![0u8; w1_encoded_len::<P>()];
    for poly_index in 0..P::K {
        let start = poly_index * P::N;
        simple_bit_pack(
            &w1[start..start + P::N],
            coeff_bits,
            &mut out[poly_index * step..(poly_index + 1) * step],
        );
    }
    out
}

/// Computes the FIPS message representative `mu = H(tr || M', 64)`.
pub fn compute_mu(tr: &[u8; 64], context: &[u8], message: &[u8]) -> [u8; 64] {
    assert!(
        context.len() <= u8::MAX as usize,
        "FIPS mu: context too long"
    );

    let mut reader = shake256_xof(&[tr, &[0u8], &[context.len() as u8], context, message]);
    let mut mu = [0u8; 64];
    reader.read(&mut mu);
    mu
}

/// Computes the FIPS commitment hash `ctilde = H(mu || w1Encode(w1), lambda/4)`.
pub fn compute_ctilde<P: MlDsaParams>(mu: &[u8; 64], encoded_w1: &[u8]) -> Vec<u8> {
    assert_eq!(
        encoded_w1.len(),
        w1_encoded_len::<P>(),
        "FIPS ctilde: bad encoded w1 length"
    );

    let mut reader = shake256_xof(&[mu, encoded_w1]);
    let mut ctilde = vec![0u8; P::CTILDE_LEN];
    reader.read(&mut ctilde);
    ctilde
}

/// Samples the sparse FIPS challenge polynomial with Algorithm 29.
pub fn sample_in_ball<P: MlDsaParams>(rho: &[u8]) -> [i32; 256] {
    let mut c = [0i32; 256];
    let mut reader = shake256_xof(&[rho]);

    let mut signs = [0u8; 8];
    reader.read(&mut signs);

    for i in (256 - P::TAU)..=255 {
        let mut j = [0u8; 1];
        reader.read(&mut j);
        while usize::from(j[0]) > i {
            reader.read(&mut j);
        }

        c[i] = c[usize::from(j[0])];
        let index = i + P::TAU - 256;
        let bit = (signs[index / 8] >> (index & 0x07)) & 1;
        c[usize::from(j[0])] = 1 - 2 * i32::from(bit);
    }

    c
}

/// Encodes a FIPS ML-DSA signature with Algorithm 26.
pub fn signature_encode<P: MlDsaParams>(
    ctilde: &[u8],
    z: &PolyVec,
    h: &PolyVec,
) -> Result<Vec<u8>, SignatureEncodingError> {
    validate_signature_inputs::<P>(ctilde, z, h)?;

    let mut signature = vec![0u8; signature_encoded_len::<P>()];
    signature[..P::CTILDE_LEN].copy_from_slice(ctilde);

    let z_start = P::CTILDE_LEN;
    let z_step = 32 * (1 + bit_length(P::GAMMA1 - 1));
    for poly_index in 0..P::L {
        let encoded =
            &mut signature[z_start + poly_index * z_step..z_start + (poly_index + 1) * z_step];
        bit_pack_z::<P>(z.polys()[poly_index].coeffs(), encoded);
    }

    let h_start = z_start + P::L * z_step;
    hint_bit_pack::<P>(h, &mut signature[h_start..]);
    Ok(signature)
}

/// Decodes a FIPS ML-DSA public key into `(rho, t1)`.
pub fn public_key_decode<P: MlDsaParams>(
    pk: &[u8],
) -> Result<PublicKeyParts, PublicKeyDecodeError> {
    if pk.len() != public_key_encoded_len::<P>() {
        return Err(PublicKeyDecodeError::PublicKeyLength {
            expected: public_key_encoded_len::<P>(),
            got: pk.len(),
        });
    }

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[..32]);

    let bitlen = bit_length(P::Q - 1) - P::D;
    let max = (1 << bitlen) - 1;
    let step = 32 * bitlen;
    let mut polys = Vec::with_capacity(P::K);
    for poly_index in 0..P::K {
        let start = 32 + poly_index * step;
        let coeffs = simple_bit_unpack(&pk[start..start + step], bitlen);
        for (coeff_index, &coeff) in coeffs.iter().enumerate() {
            if !(0..=max).contains(&coeff) {
                return Err(PublicKeyDecodeError::T1OutOfRange {
                    index: poly_index * P::N + coeff_index,
                    value: coeff,
                });
            }
        }
        polys.push(Poly::from_coeffs(coeffs));
    }

    Ok(PublicKeyParts {
        rho,
        t1: PolyVec::new(polys),
    })
}

/// Computes `t1 * 2^d` from decoded public-key material.
pub fn t1_times_2d<P: MlDsaParams>(t1: &PolyVec) -> PolyVec {
    assert_eq!(t1.len(), P::K, "t1 vector length mismatch");
    PolyVec::new(
        t1.polys()
            .iter()
            .map(|poly| {
                Poly::from_coeffs(core::array::from_fn(|i| {
                    (i64::from(poly.coeffs()[i]) << P::D).rem_euclid(i64::from(P::Q)) as Coeff
                }))
            })
            .collect(),
    )
}

/// Computes `c * t1 * 2^d` from the FIPS challenge seed and decoded public key.
pub fn challenge_times_t1_2d<P: MlDsaParams>(
    ctilde: &[u8],
    t1: &PolyVec,
) -> Result<PolyVec, SignatureEncodingError> {
    if ctilde.len() != P::CTILDE_LEN {
        return Err(SignatureEncodingError::CtildeLength {
            expected: P::CTILDE_LEN,
            got: ctilde.len(),
        });
    }
    let challenge = sample_in_ball::<P>(ctilde);
    Ok(mul_challenge_polyvec::<P>(
        &challenge,
        &t1_times_2d::<P>(t1),
    ))
}

/// Combines an externally computed `A*z` with `c*t1*2^d` to produce
/// verifier-side `w'_approx = A*z - c*t1*2^d`.
pub fn public_approx_from_az<P: MlDsaParams>(
    az: &PolyVec,
    ctilde: &[u8],
    t1: &PolyVec,
) -> Result<PolyVec, SignatureEncodingError> {
    assert_eq!(az.len(), P::K, "A*z vector length mismatch");
    let ct1 = challenge_times_t1_2d::<P>(ctilde, t1)?;
    Ok(az.sub_mod_q::<P>(&ct1))
}

/// Counts nonzero hint coefficients.
pub fn hint_weight(h: &PolyVec) -> usize {
    h.polys()
        .iter()
        .flat_map(|poly| poly.coeffs())
        .filter(|&&coeff| coeff != 0)
        .count()
}

fn simple_bit_pack(coeffs: &[u32], coeff_bits: usize, bytes_out: &mut [u8]) {
    debug_assert_eq!(coeffs.len(), 256);
    debug_assert_eq!(bytes_out.len() * 8, coeffs.len() * coeff_bits);

    let mut temp = 0u32;
    let mut byte_index = 0usize;
    let mut bit_index = 0usize;

    for &coeff in coeffs {
        temp |= coeff << bit_index;
        bit_index += coeff_bits;
        while bit_index > 7 {
            bytes_out[byte_index] = temp.to_le_bytes()[0];
            temp >>= 8;
            byte_index += 1;
            bit_index -= 8;
        }
    }
}

fn simple_bit_unpack(bytes: &[u8], coeff_bits: usize) -> [Coeff; 256] {
    let mask = (1u32 << coeff_bits) - 1;
    let mut out = [0i32; 256];
    let mut temp = 0u32;
    let mut byte_index = 0usize;
    let mut bit_index = 0usize;

    for coeff in &mut out {
        while bit_index < coeff_bits {
            temp |= u32::from(bytes[byte_index]) << bit_index;
            byte_index += 1;
            bit_index += 8;
        }
        *coeff = (temp & mask) as Coeff;
        temp >>= coeff_bits;
        bit_index -= coeff_bits;
    }

    out
}

fn validate_signature_inputs<P: MlDsaParams>(
    ctilde: &[u8],
    z: &PolyVec,
    h: &PolyVec,
) -> Result<(), SignatureEncodingError> {
    if ctilde.len() != P::CTILDE_LEN {
        return Err(SignatureEncodingError::CtildeLength {
            expected: P::CTILDE_LEN,
            got: ctilde.len(),
        });
    }
    if z.len() != P::L {
        return Err(SignatureEncodingError::ZLength {
            expected: P::L,
            got: z.len(),
        });
    }
    if h.len() != P::K {
        return Err(SignatureEncodingError::HintLength {
            expected: P::K,
            got: h.len(),
        });
    }

    for (poly_index, poly) in z.polys().iter().enumerate() {
        for (coeff_index, &coeff) in poly.coeffs().iter().enumerate() {
            let centered = center_mod_q::<P>(coeff);
            if !(-P::GAMMA1 + 1..=P::GAMMA1).contains(&centered) {
                return Err(SignatureEncodingError::ZOutOfRange {
                    index: poly_index * P::N + coeff_index,
                    value: centered,
                });
            }
        }
    }

    for (poly_index, poly) in h.polys().iter().enumerate() {
        for (coeff_index, &coeff) in poly.coeffs().iter().enumerate() {
            if !matches!(coeff, 0 | 1) {
                return Err(SignatureEncodingError::HintCoeffOutOfRange {
                    index: poly_index * P::N + coeff_index,
                    value: coeff,
                });
            }
        }
    }

    let weight = hint_weight(h);
    if weight > P::OMEGA {
        return Err(SignatureEncodingError::HintWeight {
            omega: P::OMEGA,
            got: weight,
        });
    }

    Ok(())
}

fn bit_pack_z<P: MlDsaParams>(coeffs: &[Coeff; 256], bytes_out: &mut [u8]) {
    let bitlen = 1 + bit_length(P::GAMMA1 - 1);
    let mut temp = 0u32;
    let mut byte_index = 0usize;
    let mut bit_index = 0usize;

    for &coeff in coeffs {
        let centered = center_mod_q::<P>(coeff);
        temp |= P::GAMMA1.abs_diff(centered) << bit_index;
        bit_index += bitlen;
        while bit_index > 7 {
            bytes_out[byte_index] = temp.to_le_bytes()[0];
            temp >>= 8;
            byte_index += 1;
            bit_index -= 8;
        }
    }
}

fn hint_bit_pack<P: MlDsaParams>(h: &PolyVec, bytes_out: &mut [u8]) {
    debug_assert_eq!(bytes_out.len(), P::OMEGA + P::K);
    bytes_out.fill(0);

    let mut index = 0usize;
    for poly_index in 0..P::K {
        for coeff_index in 0..P::N {
            if h.polys()[poly_index].coeffs()[coeff_index] != 0 {
                bytes_out[index] = coeff_index as u8;
                index += 1;
            }
        }
        bytes_out[P::OMEGA + poly_index] = index as u8;
    }
}

fn center_mod_q<P: MlDsaParams>(coeff: Coeff) -> Coeff {
    let reduced = coeff.rem_euclid(P::Q);
    if reduced > P::Q / 2 {
        reduced - P::Q
    } else {
        reduced
    }
}

fn shake256_xof(chunks: &[&[u8]]) -> impl XofReader {
    let mut hasher = Shake256::default();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize_xof()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlDsa44, MlDsa65, MlDsa87, PolyVec};

    fn check_w1_zero_and_max<P: MlDsaParams>(expected_len: usize) {
        assert_eq!(w1_encoded_len::<P>(), expected_len);

        let zero = vec![0u32; P::K * P::N];
        assert_eq!(w1_encode::<P>(&zero), vec![0u8; expected_len]);

        let max = vec![(P::HIGH_MOD - 1) as u32; P::K * P::N];
        let encoded = w1_encode::<P>(&max);
        assert_eq!(encoded.len(), expected_len);
        assert!(encoded.iter().any(|&byte| byte != 0));
    }

    fn check_challenge_shape<P: MlDsaParams>() {
        let mu = [0x42u8; 64];
        let w1 = vec![0u32; P::K * P::N];
        let encoded = w1_encode::<P>(&w1);
        let ctilde = compute_ctilde::<P>(&mu, &encoded);
        assert_eq!(ctilde.len(), P::CTILDE_LEN);

        let c = sample_in_ball::<P>(&ctilde);
        assert_eq!(c.iter().filter(|&&coeff| coeff != 0).count(), P::TAU);
        assert!(c.iter().all(|&coeff| (-1..=1).contains(&coeff)));
    }

    #[test]
    fn w1_encode_lengths_match_fips_parameters() {
        check_w1_zero_and_max::<MlDsa44>(768);
        check_w1_zero_and_max::<MlDsa65>(768);
        check_w1_zero_and_max::<MlDsa87>(1024);
    }

    #[test]
    fn signature_encode_lengths_match_fips_parameters() {
        assert_eq!(signature_encoded_len::<MlDsa44>(), MlDsa44::SIG_LEN);
        assert_eq!(signature_encoded_len::<MlDsa65>(), MlDsa65::SIG_LEN);
        assert_eq!(signature_encoded_len::<MlDsa87>(), MlDsa87::SIG_LEN);
    }

    #[test]
    fn public_key_decode_lengths_match_fips_parameters() {
        assert_eq!(public_key_encoded_len::<MlDsa44>(), MlDsa44::PK_LEN);
        assert_eq!(public_key_encoded_len::<MlDsa65>(), MlDsa65::PK_LEN);
        assert_eq!(public_key_encoded_len::<MlDsa87>(), MlDsa87::PK_LEN);
    }

    #[test]
    fn ctilde_and_sample_in_ball_match_parameter_shapes() {
        check_challenge_shape::<MlDsa44>();
        check_challenge_shape::<MlDsa65>();
        check_challenge_shape::<MlDsa87>();
    }

    #[test]
    fn compute_mu_is_context_and_message_bound() {
        let tr = [0x11; 64];
        let first = compute_mu(&tr, b"ctx", b"message");
        assert_eq!(first, compute_mu(&tr, b"ctx", b"message"));
        assert_ne!(first, compute_mu(&tr, b"ctx2", b"message"));
        assert_ne!(first, compute_mu(&tr, b"ctx", b"message2"));
    }

    #[test]
    fn signature_encode_packs_shape_and_hint_trailer() {
        let ctilde = vec![0x42; MlDsa65::CTILDE_LEN];
        let z = PolyVec::zero(MlDsa65::L);
        let mut h = PolyVec::zero(MlDsa65::K);
        h.polys_mut()[0].coeffs_mut()[3] = 1;
        h.polys_mut()[2].coeffs_mut()[9] = 1;

        let signature = signature_encode::<MlDsa65>(&ctilde, &z, &h).expect("signature encoding");
        assert_eq!(signature.len(), MlDsa65::SIG_LEN);
        assert_eq!(&signature[..MlDsa65::CTILDE_LEN], ctilde.as_slice());

        let hint_start =
            MlDsa65::CTILDE_LEN + MlDsa65::L * 32 * (1 + bit_length(MlDsa65::GAMMA1 - 1));
        let hint = &signature[hint_start..];
        assert_eq!(hint[0], 3);
        assert_eq!(hint[1], 9);
        assert_eq!(
            &hint[MlDsa65::OMEGA..MlDsa65::OMEGA + MlDsa65::K],
            &[1, 1, 2, 2, 2, 2]
        );
    }

    #[test]
    fn signature_encode_rejects_bad_inputs() {
        let ctilde = vec![0u8; MlDsa65::CTILDE_LEN - 1];
        assert_eq!(
            signature_encode::<MlDsa65>(
                &ctilde,
                &PolyVec::zero(MlDsa65::L),
                &PolyVec::zero(MlDsa65::K)
            ),
            Err(SignatureEncodingError::CtildeLength {
                expected: MlDsa65::CTILDE_LEN,
                got: MlDsa65::CTILDE_LEN - 1,
            })
        );

        let ctilde = vec![0u8; MlDsa65::CTILDE_LEN];
        assert_eq!(
            signature_encode::<MlDsa65>(
                &ctilde,
                &PolyVec::zero(MlDsa65::L - 1),
                &PolyVec::zero(MlDsa65::K)
            ),
            Err(SignatureEncodingError::ZLength {
                expected: MlDsa65::L,
                got: MlDsa65::L - 1,
            })
        );

        let mut h = PolyVec::zero(MlDsa65::K);
        h.polys_mut()[0].coeffs_mut()[0] = 2;
        assert_eq!(
            signature_encode::<MlDsa65>(&ctilde, &PolyVec::zero(MlDsa65::L), &h),
            Err(SignatureEncodingError::HintCoeffOutOfRange { index: 0, value: 2 })
        );
    }

    #[test]
    fn signature_encode_rejects_hint_weight_over_omega() {
        let ctilde = vec![0u8; MlDsa65::CTILDE_LEN];
        let mut h = PolyVec::zero(MlDsa65::K);
        for index in 0..=MlDsa65::OMEGA {
            h.polys_mut()[0].coeffs_mut()[index] = 1;
        }

        assert_eq!(
            signature_encode::<MlDsa65>(&ctilde, &PolyVec::zero(MlDsa65::L), &h),
            Err(SignatureEncodingError::HintWeight {
                omega: MlDsa65::OMEGA,
                got: MlDsa65::OMEGA + 1,
            })
        );
    }

    #[test]
    fn public_key_decode_unpacks_zero_key_shape() {
        let pk = vec![0u8; MlDsa65::PK_LEN];
        let parts = public_key_decode::<MlDsa65>(&pk).expect("decode zero public key shape");
        assert_eq!(parts.rho, [0u8; 32]);
        assert_eq!(parts.t1.len(), MlDsa65::K);
        assert!(parts
            .t1
            .polys()
            .iter()
            .flat_map(|poly| poly.coeffs())
            .all(|&coeff| coeff == 0));
    }

    #[test]
    fn public_key_decode_rejects_bad_length() {
        assert_eq!(
            public_key_decode::<MlDsa65>(&[0u8; 31]),
            Err(PublicKeyDecodeError::PublicKeyLength {
                expected: MlDsa65::PK_LEN,
                got: 31,
            })
        );
    }

    #[test]
    fn public_approx_from_az_subtracts_challenge_t1_2d() {
        let ctilde = vec![0x42; MlDsa65::CTILDE_LEN];
        let mut t1 = PolyVec::zero(MlDsa65::K);
        t1.polys_mut()[0].coeffs_mut()[0] = 1;
        let ct1 = challenge_times_t1_2d::<MlDsa65>(&ctilde, &t1).expect("ct1");
        let approx = public_approx_from_az::<MlDsa65>(&ct1, &ctilde, &t1).expect("approx");
        assert_eq!(approx, PolyVec::zero(MlDsa65::K));
    }
}
