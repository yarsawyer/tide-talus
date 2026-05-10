#![doc = "Authenticated Boolean shares and gates."]

use core::fmt;

use crate::auth::{open_checked, AuthShare, MacKeyShare, OpenError, PartyId};
use crate::beaver::{
    beaver_multiply_tracked_checked, BeaverError, CertifiedBeaverTripleShare, TripleUseTracker,
};
use crate::Gf128;

/// One party's authenticated Boolean share.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthBit {
    /// Underlying authenticated field share.
    pub share: AuthShare,
}

impl fmt::Debug for AuthBit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthBit")
            .field("party", &self.share.party)
            .field("share", &"<redacted>")
            .finish()
    }
}

/// Boolean gate failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthBitError {
    /// Checked opening failed.
    Open(OpenError),
    /// Beaver multiplication failed.
    Beaver(BeaverError),
    /// Missing MAC-key share for a public operation.
    MissingMacKey(PartyId),
    /// A local gate was given shares from different parties.
    PartyMismatch(PartyId),
    /// Input share vectors had different lengths.
    LengthMismatch {
        /// Left-hand input length.
        lhs: usize,
        /// Right-hand input length.
        rhs: usize,
    },
    /// Opened field value was not a bit.
    NotBit(Gf128),
}

impl fmt::Display for AuthBitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Open(err) => write!(f, "authenticated bit opening failed: {err}"),
            Self::Beaver(err) => write!(f, "authenticated bit AND failed: {err}"),
            Self::MissingMacKey(party) => write!(f, "missing MAC key for party {}", party.0),
            Self::PartyMismatch(party) => {
                write!(f, "bit share party mismatch for party {}", party.0)
            }
            Self::LengthMismatch { lhs, rhs } => {
                write!(f, "bit share length mismatch: lhs {lhs}, rhs {rhs}")
            }
            Self::NotBit(value) => write!(f, "opened value is not a bit: {value:?}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AuthBitError {}

impl From<OpenError> for AuthBitError {
    fn from(value: OpenError) -> Self {
        Self::Open(value)
    }
}

impl From<BeaverError> for AuthBitError {
    fn from(value: BeaverError) -> Self {
        Self::Beaver(value)
    }
}

impl AuthBit {
    /// Wraps an authenticated share without opening it.
    pub const fn from_share_unchecked(share: AuthShare) -> Self {
        Self { share }
    }

    /// XORs two local bit shares owned by the same party.
    pub fn xor_same_party(self, rhs: Self) -> Result<Self, AuthBitError> {
        Ok(Self {
            share: self
                .share
                .add_same_party(rhs.share)
                .ok_or(AuthBitError::PartyMismatch(self.share.party))?,
        })
    }

    /// NOTs one local bit share using public addition of one.
    pub fn not(self, mac_key: MacKeyShare, public_party: PartyId) -> Result<Self, AuthBitError> {
        Ok(Self {
            share: self
                .share
                .add_public(Gf128::ONE, mac_key, public_party)
                .ok_or(AuthBitError::MissingMacKey(self.share.party))?,
        })
    }
}

/// Builds authenticated shares of a public bit.
pub fn public_bit(bit: bool, mac_keys: &[MacKeyShare], public_party: PartyId) -> Vec<AuthBit> {
    let value = if bit { Gf128::ONE } else { Gf128::ZERO };

    mac_keys
        .iter()
        .map(|mac_key| {
            let value_share = if mac_key.party == public_party {
                value
            } else {
                Gf128::ZERO
            };
            AuthBit {
                share: AuthShare {
                    party: mac_key.party,
                    value: value_share,
                    mac: mac_key.alpha * value,
                },
            }
        })
        .collect()
}

/// Opens an authenticated bit and checks that the opened value is in `{0, 1}`.
pub fn open_bit_checked(bits: &[AuthBit], mac_keys: &[MacKeyShare]) -> Result<bool, AuthBitError> {
    let shares: Vec<_> = bits.iter().map(|bit| bit.share).collect();
    let value = open_checked(&shares, mac_keys)?;

    if value == Gf128::ZERO {
        return Ok(false);
    }
    if value == Gf128::ONE {
        return Ok(true);
    }

    Err(AuthBitError::NotBit(value))
}

/// XORs two authenticated shared bits.
pub fn xor_bits(lhs: &[AuthBit], rhs: &[AuthBit]) -> Result<Vec<AuthBit>, AuthBitError> {
    if lhs.len() != rhs.len() {
        return Err(AuthBitError::LengthMismatch {
            lhs: lhs.len(),
            rhs: rhs.len(),
        });
    }

    lhs.iter()
        .zip(rhs)
        .map(|(&lhs_bit, &rhs_bit)| lhs_bit.xor_same_party(rhs_bit))
        .collect()
}

/// NOTs an authenticated shared bit.
pub fn not_bits(
    bits: &[AuthBit],
    mac_keys: &[MacKeyShare],
    public_party: PartyId,
) -> Result<Vec<AuthBit>, AuthBitError> {
    bits.iter()
        .map(|bit| {
            let mac_key = mac_keys
                .iter()
                .copied()
                .find(|candidate| candidate.party == bit.share.party)
                .ok_or(AuthBitError::MissingMacKey(bit.share.party))?;
            bit.not(mac_key, public_party)
        })
        .collect()
}

/// ANDs two authenticated shared bits using a tracked Beaver triple.
pub fn and_bits_checked(
    lhs: &[AuthBit],
    rhs: &[AuthBit],
    triples: &[CertifiedBeaverTripleShare],
    mac_keys: &[MacKeyShare],
    tracker: &mut TripleUseTracker,
) -> Result<Vec<AuthBit>, AuthBitError> {
    if lhs.len() != rhs.len() {
        return Err(AuthBitError::LengthMismatch {
            lhs: lhs.len(),
            rhs: rhs.len(),
        });
    }

    let lhs_shares: Vec<_> = lhs.iter().map(|bit| bit.share).collect();
    let rhs_shares: Vec<_> = rhs.iter().map(|bit| bit.share).collect();
    let product =
        beaver_multiply_tracked_checked(&lhs_shares, &rhs_shares, triples, mac_keys, tracker)?;
    Ok(product
        .into_iter()
        .map(AuthBit::from_share_unchecked)
        .collect())
}

/// Half-adder result.
#[derive(Clone, Eq, PartialEq)]
pub struct HalfAdder {
    /// Sum bit, `lhs XOR rhs`.
    pub sum: Vec<AuthBit>,
    /// Carry bit, `lhs AND rhs`.
    pub carry: Vec<AuthBit>,
}

impl fmt::Debug for HalfAdder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HalfAdder")
            .field("sum_len", &self.sum.len())
            .field("carry_len", &self.carry.len())
            .finish()
    }
}

/// Full-adder result.
#[derive(Clone, Eq, PartialEq)]
pub struct FullAdder {
    /// Sum bit, `lhs XOR rhs XOR carry_in`.
    pub sum: Vec<AuthBit>,
    /// Carry bit.
    pub carry: Vec<AuthBit>,
}

impl fmt::Debug for FullAdder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FullAdder")
            .field("sum_len", &self.sum.len())
            .field("carry_len", &self.carry.len())
            .finish()
    }
}

/// Computes a one-bit half adder.
pub fn half_adder_checked(
    lhs: &[AuthBit],
    rhs: &[AuthBit],
    and_triples: &[CertifiedBeaverTripleShare],
    mac_keys: &[MacKeyShare],
    tracker: &mut TripleUseTracker,
) -> Result<HalfAdder, AuthBitError> {
    let sum = xor_bits(lhs, rhs)?;
    let carry = and_bits_checked(lhs, rhs, and_triples, mac_keys, tracker)?;
    Ok(HalfAdder { sum, carry })
}

/// Computes a one-bit full adder.
pub fn full_adder_checked(
    lhs: &[AuthBit],
    rhs: &[AuthBit],
    carry_in: &[AuthBit],
    lhs_rhs_triples: &[CertifiedBeaverTripleShare],
    carry_triples: &[CertifiedBeaverTripleShare],
    mac_keys: &[MacKeyShare],
    tracker: &mut TripleUseTracker,
) -> Result<FullAdder, AuthBitError> {
    let lhs_xor_rhs = xor_bits(lhs, rhs)?;
    let sum = xor_bits(&lhs_xor_rhs, carry_in)?;
    let lhs_and_rhs = and_bits_checked(lhs, rhs, lhs_rhs_triples, mac_keys, tracker)?;
    let carry_and_xor = and_bits_checked(carry_in, &lhs_xor_rhs, carry_triples, mac_keys, tracker)?;
    let carry = xor_bits(&lhs_and_rhs, &carry_and_xor)?;

    Ok(FullAdder { sum, carry })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::test_dealer::deal_authenticated;
    use crate::beaver::{
        certify_triple_bundle_for_test, CertifiedBeaverTripleShare, TripleId,
        UncheckedBeaverTripleShare,
    };

    fn deal_bit(bit: bool, alpha: Gf128, party_count: u16) -> (Vec<AuthBit>, Vec<MacKeyShare>) {
        let value = if bit { Gf128::ONE } else { Gf128::ZERO };
        let deal = deal_authenticated(value, alpha, party_count);
        (
            deal.shares
                .into_iter()
                .map(AuthBit::from_share_unchecked)
                .collect(),
            deal.mac_keys,
        )
    }

    fn deal_triple(
        id: TripleId,
        a: bool,
        b: bool,
        alpha: Gf128,
        party_count: u16,
    ) -> Vec<CertifiedBeaverTripleShare> {
        let a_value = if a { Gf128::ONE } else { Gf128::ZERO };
        let b_value = if b { Gf128::ONE } else { Gf128::ZERO };
        let a_deal = deal_authenticated(a_value, alpha, party_count);
        let b_deal = deal_authenticated(b_value, alpha, party_count);
        let c_deal = deal_authenticated(a_value * b_value, alpha, party_count);

        let unchecked = a_deal
            .shares
            .iter()
            .zip(&b_deal.shares)
            .zip(&c_deal.shares)
            .map(|((a_share, b_share), c_share)| UncheckedBeaverTripleShare {
                id,
                party: a_share.party,
                a: *a_share,
                b: *b_share,
                c: *c_share,
            })
            .collect::<Vec<_>>();
        let mac_keys = deal_authenticated(Gf128::ZERO, alpha, party_count).mac_keys;
        certify_triple_bundle_for_test(&unchecked, &mac_keys).expect("test triple certifies")
    }

    #[test]
    fn xor_not_truth_tables() {
        let alpha = Gf128::from_u128(0x3456);

        for lhs in [false, true] {
            for rhs in [false, true] {
                let (lhs_bits, mac_keys) = deal_bit(lhs, alpha, 3);
                let (rhs_bits, _) = deal_bit(rhs, alpha, 3);
                let xor = xor_bits(&lhs_bits, &rhs_bits).expect("aligned bit shares XOR");
                assert_eq!(open_bit_checked(&xor, &mac_keys), Ok(lhs ^ rhs));
            }

            let (bits, mac_keys) = deal_bit(lhs, alpha, 3);
            let not = not_bits(&bits, &mac_keys, PartyId(0)).expect("NOT uses local MAC keys");
            assert_eq!(open_bit_checked(&not, &mac_keys), Ok(!lhs));
        }
    }

    #[test]
    fn and_truth_table() {
        let alpha = Gf128::from_u128(0x4567);
        let mut triple_id = 1;

        for lhs in [false, true] {
            for rhs in [false, true] {
                let (lhs_bits, mac_keys) = deal_bit(lhs, alpha, 3);
                let (rhs_bits, _) = deal_bit(rhs, alpha, 3);
                let triples = deal_triple(TripleId(triple_id), true, true, alpha, 3);
                let mut tracker = TripleUseTracker::new();
                let and = and_bits_checked(&lhs_bits, &rhs_bits, &triples, &mac_keys, &mut tracker)
                    .expect("AND uses one valid Beaver triple");
                assert_eq!(open_bit_checked(&and, &mac_keys), Ok(lhs & rhs));
                triple_id += 1;
            }
        }
    }

    #[test]
    fn public_bit_round_trips() {
        let (_, mac_keys) = deal_bit(false, Gf128::from_u128(0x9999), 3);
        let zero = public_bit(false, &mac_keys, PartyId(0));
        let one = public_bit(true, &mac_keys, PartyId(0));

        assert_eq!(open_bit_checked(&zero, &mac_keys), Ok(false));
        assert_eq!(open_bit_checked(&one, &mac_keys), Ok(true));
    }

    #[test]
    fn half_adder_truth_table() {
        let alpha = Gf128::from_u128(0x123456);
        let mut triple_id = 100;

        for lhs in [false, true] {
            for rhs in [false, true] {
                let (lhs_bits, mac_keys) = deal_bit(lhs, alpha, 3);
                let (rhs_bits, _) = deal_bit(rhs, alpha, 3);
                let triples = deal_triple(TripleId(triple_id), true, true, alpha, 3);
                let mut tracker = TripleUseTracker::new();
                let out =
                    half_adder_checked(&lhs_bits, &rhs_bits, &triples, &mac_keys, &mut tracker)
                        .expect("half adder uses one valid AND triple");

                assert_eq!(open_bit_checked(&out.sum, &mac_keys), Ok(lhs ^ rhs));
                assert_eq!(open_bit_checked(&out.carry, &mac_keys), Ok(lhs & rhs));
                triple_id += 1;
            }
        }
    }

    #[test]
    fn full_adder_truth_table() {
        let alpha = Gf128::from_u128(0x654321);
        let mut triple_id = 200;

        for lhs in [false, true] {
            for rhs in [false, true] {
                for carry_in in [false, true] {
                    let (lhs_bits, mac_keys) = deal_bit(lhs, alpha, 3);
                    let (rhs_bits, _) = deal_bit(rhs, alpha, 3);
                    let (carry_bits, _) = deal_bit(carry_in, alpha, 3);
                    let lhs_rhs_triples = deal_triple(TripleId(triple_id), true, true, alpha, 3);
                    let carry_triples = deal_triple(TripleId(triple_id + 1), true, true, alpha, 3);
                    let mut tracker = TripleUseTracker::new();
                    let out = full_adder_checked(
                        &lhs_bits,
                        &rhs_bits,
                        &carry_bits,
                        &lhs_rhs_triples,
                        &carry_triples,
                        &mac_keys,
                        &mut tracker,
                    )
                    .expect("full adder uses two valid AND triples");

                    let clear_sum = lhs ^ rhs ^ carry_in;
                    let clear_carry = (lhs & rhs) | (carry_in & (lhs ^ rhs));
                    assert_eq!(open_bit_checked(&out.sum, &mac_keys), Ok(clear_sum));
                    assert_eq!(open_bit_checked(&out.carry, &mac_keys), Ok(clear_carry));
                    triple_id += 2;
                }
            }
        }
    }

    #[test]
    fn debug_redacts_authenticated_bit_material() {
        let (bits, _) = deal_bit(true, Gf128::from_u128(0x9999), 2);
        assert_eq!(
            format!("{:?}", bits[0]),
            "AuthBit { party: PartyId(0), share: \"<redacted>\" }"
        );

        let half = HalfAdder {
            sum: bits.clone(),
            carry: bits.clone(),
        };
        assert_eq!(
            format!("{half:?}"),
            "HalfAdder { sum_len: 2, carry_len: 2 }"
        );
    }
}
