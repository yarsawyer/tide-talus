#![forbid(unsafe_code)]
#![doc = "Core TALUS arithmetic and fips204 adapter surface."]
//!
//! This crate contains standard-compatible ML-DSA/TALUS arithmetic helpers and
//! the narrow `fips204` adapter surface used by higher-level TALUS protocols.
//! It does not define a separate signing mode and does not provide paper-fast,
//! scaffold, or transport APIs.

pub mod bcc;
pub mod cef;
pub mod decompose;
pub mod fips204_adapter;
pub mod fips204_encoding;
pub mod fips204_ntt;
pub mod fips204_verify;
pub mod params;
pub mod performance;
pub mod poly;

pub use bcc::{
    bcc_holds_coeff, bcc_holds_coeffs, compute_talus_hint_polyvec, compute_talus_hints,
    talus_hint_coeff, use_talus_hint_coeff, HintError,
};
pub use cef::{cef_w1_clear_coeff, cef_w1_coeff, clear_kappa_delta};
pub use decompose::{
    decompose, high_bits, high_bits_unsigned, low_bits_signed, low_bits_unsigned, power2round,
    reduce_mod_q, use_hint, Coeff,
};
pub use fips204_encoding::{
    challenge_times_t1_2d, compute_ctilde, compute_mu, compute_tr, hint_weight,
    public_approx_from_az, public_key_decode, public_key_encoded_len, sample_in_ball,
    signature_encode, signature_encoded_len, t1_times_2d, w1_encode, w1_encoded_len,
    PublicKeyDecodeError, PublicKeyParts, SignatureEncodingError,
};
pub use fips204_ntt::{
    az_from_expanded_a, az_from_rho, expand_a, inv_ntt_poly, ntt_poly, NttError,
};
pub use fips204_verify::{verify_fips204_signature, Fips204Verifier, VerifyError};
pub use params::{MlDsa44, MlDsa65, MlDsa87, MlDsaParams};
pub use performance::{
    ensure_performance_counters_within_envelope, PerformanceGateError, ProductionBatchSizingPolicy,
    StrictTokenBatchSizingDecision, TalusPerformanceCounters, TalusPerformanceEnvelope,
    TokenPassProbabilityEstimate,
};
pub use poly::{
    aggregate_z_shares, aggregate_z_shares_lagrange, infinity_norm, lagrange_coefficients_at_zero,
    mul_challenge_poly, mul_challenge_polyvec, partial_z_share, partial_z_share_with_challenge,
    z_bound_holds, Poly, PolyError, PolyVec,
};
