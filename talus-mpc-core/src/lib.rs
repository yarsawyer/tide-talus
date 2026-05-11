#![forbid(unsafe_code)]
#![doc = "Malicious-secure MPC primitives for TALUS."]
//!
//! This crate contains low-level authenticated-share, Beaver multiplication,
//! bit, and CarryCompare primitives. Test dealers and local certification
//! helpers are not production setup protocols; production TALUS uses higher
//! level honest-majority IT-MPC/VSS runtime evidence before release.

#[cfg(all(feature = "test-dealer", not(debug_assertions)))]
compile_error!("the `test-dealer` feature is test-only and must not be enabled in release builds");

pub mod auth;
pub mod beaver;
pub mod bit;
pub mod carry;
pub mod gf128;

pub use auth::{open_checked, open_many_checked, AuthShare, MacKeyShare, OpenError, PartyId};
#[cfg(any(test, feature = "test-dealer"))]
pub use beaver::certify_triple_bundle_for_test;
pub use beaver::{
    beaver_multiply_checked, beaver_multiply_tracked_checked, BeaverError,
    CertifiedBeaverTripleShare, InMemoryTripleProvider, TripleCertificate, TripleId,
    TripleProvider, TripleProviderError, TripleUseTracker, UncheckedBeaverTripleShare,
};
pub use bit::{
    and_bits_checked, full_adder_checked, half_adder_checked, not_bits, open_bit_checked,
    public_bit, xor_bits, AuthBit, AuthBitError, FullAdder, HalfAdder,
};
pub use carry::{
    carry_compare, check_bits_are_bits, gt_public_checked, lt_public_checked, sum_u19_checked,
    AuthU19, CarryCompare, CarryError, TripleCursor, AUTH_U19_WIDTH,
};
pub use gf128::Gf128;

/// Placeholder exported so the crate compiles before MPC primitives land.
pub const CRATE_STATUS: &str = "scaffold";
