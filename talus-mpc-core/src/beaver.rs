#![doc = "Authenticated Beaver multiplication."]

use core::fmt;

use crate::auth::{open_many_checked, AuthShare, MacKeyShare, OpenError, PartyId};

/// Identifies one Beaver triple for single-use tracking.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TripleId(pub u64);

/// One party's unchecked share of an authenticated Beaver triple candidate.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct UncheckedBeaverTripleShare {
    /// Single-use triple identifier.
    pub id: TripleId,
    /// Party that owns this triple share.
    pub party: PartyId,
    /// Authenticated share of `a`.
    pub a: AuthShare,
    /// Authenticated share of `b`.
    pub b: AuthShare,
    /// Authenticated share of `c = a*b`.
    pub c: AuthShare,
}

impl fmt::Debug for UncheckedBeaverTripleShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UncheckedBeaverTripleShare")
            .field("id", &self.id)
            .field("party", &self.party)
            .field("a", &"<redacted>")
            .field("b", &"<redacted>")
            .field("c", &"<redacted>")
            .finish()
    }
}

/// Certificate that a triple provider has checked the triple relation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TripleCertificate {
    /// Backend-specific transcript binding for certification.
    pub transcript_hash: [u8; 32],
}

/// One party's certified share of an authenticated Beaver triple `(a, b, c = a*b)`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CertifiedBeaverTripleShare {
    /// Single-use triple identifier.
    id: TripleId,
    /// Party that owns this triple share.
    party: PartyId,
    /// Authenticated share of `a`.
    a: AuthShare,
    /// Authenticated share of `b`.
    b: AuthShare,
    /// Authenticated share of `c = a*b`.
    c: AuthShare,
    /// Certification transcript.
    certificate: TripleCertificate,
}

impl fmt::Debug for CertifiedBeaverTripleShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertifiedBeaverTripleShare")
            .field("id", &self.id)
            .field("party", &self.party)
            .field("a", &"<redacted>")
            .field("b", &"<redacted>")
            .field("c", &"<redacted>")
            .field("certificate", &self.certificate)
            .finish()
    }
}

impl CertifiedBeaverTripleShare {
    /// Returns the single-use triple identifier.
    pub const fn id(&self) -> TripleId {
        self.id
    }

    /// Returns the owning party.
    pub const fn party(&self) -> PartyId {
        self.party
    }

    /// Returns the certification transcript.
    pub const fn certificate(&self) -> TripleCertificate {
        self.certificate
    }
}

/// Beaver multiplication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeaverError {
    /// Input opening failed.
    Open(OpenError),
    /// The input share set was empty.
    Empty,
    /// A matching RHS share was not present.
    MissingRhs(PartyId),
    /// A matching triple share was not present.
    MissingTriple(PartyId),
    /// A matching MAC-key share was not present.
    MissingMacKey(PartyId),
    /// A triple entry contained inconsistent party identifiers.
    TriplePartyMismatch(PartyId),
    /// Triple shares did not all carry the same identifier.
    TripleIdMismatch {
        /// Expected triple identifier.
        expected: TripleId,
        /// Actual triple identifier.
        got: TripleId,
    },
    /// The triple identifier has already been consumed.
    TripleAlreadyUsed(TripleId),
    /// Triple candidate failed relation certification.
    TripleRelationInvalid(TripleId),
    /// A local share operation found different party identifiers.
    PartyMismatch(PartyId),
}

impl fmt::Display for BeaverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Open(err) => write!(f, "Beaver opening failed: {err}"),
            Self::Empty => write!(f, "no shares supplied for Beaver multiplication"),
            Self::MissingRhs(party) => write!(f, "missing RHS share for party {}", party.0),
            Self::MissingTriple(party) => write!(f, "missing Beaver triple for party {}", party.0),
            Self::MissingMacKey(party) => write!(f, "missing MAC key for party {}", party.0),
            Self::TriplePartyMismatch(party) => {
                write!(f, "Beaver triple party mismatch for party {}", party.0)
            }
            Self::TripleIdMismatch { expected, got } => {
                write!(
                    f,
                    "Beaver triple id mismatch: expected {}, got {}",
                    expected.0, got.0
                )
            }
            Self::TripleAlreadyUsed(id) => write!(f, "Beaver triple {} already used", id.0),
            Self::TripleRelationInvalid(id) => {
                write!(f, "Beaver triple {} failed relation certification", id.0)
            }
            Self::PartyMismatch(party) => {
                write!(f, "local share party mismatch for party {}", party.0)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BeaverError {}

impl From<OpenError> for BeaverError {
    fn from(value: OpenError) -> Self {
        Self::Open(value)
    }
}

/// Tracks consumed Beaver triples.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TripleUseTracker {
    used: Vec<TripleId>,
}

impl TripleUseTracker {
    /// Creates an empty tracker.
    pub const fn new() -> Self {
        Self { used: Vec::new() }
    }

    /// Returns whether `id` has already been marked used.
    pub fn contains(&self, id: TripleId) -> bool {
        self.used.contains(&id)
    }

    /// Marks `id` as used.
    pub fn mark_used(&mut self, id: TripleId) -> Result<(), BeaverError> {
        if self.contains(id) {
            return Err(BeaverError::TripleAlreadyUsed(id));
        }

        self.used.push(id);
        Ok(())
    }
}

/// Certifies an unchecked triple bundle by opening `a`, `b`, and `c`.
///
/// This helper is for deterministic tests and trusted-dealer scaffolding only.
/// Production providers must use a malicious-secure preprocessing/sacrifice
/// protocol that certifies `c = a*b` without exposing triple secrets.
#[cfg(any(test, feature = "test-dealer"))]
pub fn certify_triple_bundle_for_test(
    triples: &[UncheckedBeaverTripleShare],
    mac_keys: &[MacKeyShare],
) -> Result<Vec<CertifiedBeaverTripleShare>, BeaverError> {
    let id = unchecked_triple_id(triples)?;
    let mut a_shares = Vec::with_capacity(triples.len());
    let mut b_shares = Vec::with_capacity(triples.len());
    let mut c_shares = Vec::with_capacity(triples.len());
    for triple in triples {
        validate_unchecked_triple_party(*triple)?;
        a_shares.push(triple.a);
        b_shares.push(triple.b);
        c_shares.push(triple.c);
    }

    let openings = [
        a_shares.as_slice(),
        b_shares.as_slice(),
        c_shares.as_slice(),
    ];
    let opened = open_many_checked(&openings, mac_keys)?;
    if opened[2] != opened[0] * opened[1] {
        return Err(BeaverError::TripleRelationInvalid(id));
    }

    Ok(triples
        .iter()
        .map(|triple| CertifiedBeaverTripleShare {
            id: triple.id,
            party: triple.party,
            a: triple.a,
            b: triple.b,
            c: triple.c,
            certificate: TripleCertificate {
                transcript_hash: test_triple_certificate_hash(triple),
            },
        })
        .collect())
}

/// Triple-provider failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TripleProviderError {
    /// Provider did not have enough triple bundles available.
    Exhausted {
        /// Number of bundles requested.
        requested: usize,
        /// Number of bundles remaining.
        remaining: usize,
    },
}

impl fmt::Display for TripleProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Exhausted {
                requested,
                remaining,
            } => {
                write!(
                    f,
                    "triple provider exhausted: requested {requested}, remaining {remaining}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TripleProviderError {}

/// Production-facing source of authenticated Beaver triple bundles.
///
/// Implementations may be backed by MASCOT/OT-extension, an external MPC
/// service, persistent preprocessing, or a test-only source. Protocol code
/// should depend on this trait instead of directly invoking a dealer.
pub trait TripleProvider {
    /// Returns one authenticated triple bundle, one share per party.
    fn take_triple_bundle(
        &mut self,
    ) -> Result<Vec<CertifiedBeaverTripleShare>, TripleProviderError>;

    /// Returns `count` triple bundles in circuit order.
    fn take_triple_bundles(
        &mut self,
        count: usize,
    ) -> Result<Vec<Vec<CertifiedBeaverTripleShare>>, TripleProviderError> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.take_triple_bundle()?);
        }
        Ok(out)
    }
}

/// In-memory triple provider for deterministic tests and adapter wiring.
#[derive(Clone, Eq, PartialEq)]
pub struct InMemoryTripleProvider {
    bundles: Vec<Vec<CertifiedBeaverTripleShare>>,
    next: usize,
}

impl fmt::Debug for InMemoryTripleProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryTripleProvider")
            .field("bundle_count", &self.bundles.len())
            .field("next", &self.next)
            .field("bundles", &"<redacted>")
            .finish()
    }
}

impl InMemoryTripleProvider {
    /// Creates a provider from precomputed authenticated triple bundles.
    pub fn new(bundles: Vec<Vec<CertifiedBeaverTripleShare>>) -> Self {
        Self { bundles, next: 0 }
    }

    /// Returns the number of bundles already handed out.
    pub const fn consumed(&self) -> usize {
        self.next
    }

    /// Returns the number of bundles still available.
    pub fn remaining(&self) -> usize {
        self.bundles.len().saturating_sub(self.next)
    }
}

impl TripleProvider for InMemoryTripleProvider {
    fn take_triple_bundle(
        &mut self,
    ) -> Result<Vec<CertifiedBeaverTripleShare>, TripleProviderError> {
        let Some(bundle) = self.bundles.get(self.next) else {
            return Err(TripleProviderError::Exhausted {
                requested: 1,
                remaining: 0,
            });
        };

        self.next += 1;
        Ok(bundle.clone())
    }

    fn take_triple_bundles(
        &mut self,
        count: usize,
    ) -> Result<Vec<Vec<CertifiedBeaverTripleShare>>, TripleProviderError> {
        let remaining = self.remaining();
        if count > remaining {
            return Err(TripleProviderError::Exhausted {
                requested: count,
                remaining,
            });
        }

        let out = self.bundles[self.next..self.next + count].to_vec();
        self.next += count;
        Ok(out)
    }
}

/// Multiplies two authenticated shared values using one authenticated Beaver
/// triple.
pub fn beaver_multiply_checked(
    lhs: &[AuthShare],
    rhs: &[AuthShare],
    triples: &[CertifiedBeaverTripleShare],
    mac_keys: &[MacKeyShare],
) -> Result<Vec<AuthShare>, BeaverError> {
    if lhs.is_empty() {
        return Err(BeaverError::Empty);
    }

    let mut d_shares = Vec::with_capacity(lhs.len());
    let mut e_shares = Vec::with_capacity(lhs.len());

    for lhs_share in lhs {
        let rhs_share =
            find_share(rhs, lhs_share.party).ok_or(BeaverError::MissingRhs(lhs_share.party))?;
        let triple = find_triple(triples, lhs_share.party)
            .ok_or(BeaverError::MissingTriple(lhs_share.party))?;
        validate_triple_party(triple)?;

        d_shares.push(
            lhs_share
                .sub_same_party(triple.a)
                .ok_or(BeaverError::PartyMismatch(lhs_share.party))?,
        );
        e_shares.push(
            rhs_share
                .sub_same_party(triple.b)
                .ok_or(BeaverError::PartyMismatch(lhs_share.party))?,
        );
    }

    let openings = [d_shares.as_slice(), e_shares.as_slice()];
    let opened = open_many_checked(&openings, mac_keys)?;
    let d = opened[0];
    let e = opened[1];
    let public_term = d * e;
    let public_party = lhs[0].party;
    let mut out = Vec::with_capacity(lhs.len());

    for lhs_share in lhs {
        let triple = find_triple(triples, lhs_share.party)
            .ok_or(BeaverError::MissingTriple(lhs_share.party))?;
        let mac_key = find_mac_key(mac_keys, lhs_share.party)
            .ok_or(BeaverError::MissingMacKey(lhs_share.party))?;
        let mut product = triple
            .c
            .add_same_party(triple.b.mul_public(d))
            .ok_or(BeaverError::PartyMismatch(lhs_share.party))?
            .add_same_party(triple.a.mul_public(e))
            .ok_or(BeaverError::PartyMismatch(lhs_share.party))?;

        product.mac += mac_key.alpha * public_term;
        if product.party == public_party {
            product.value += public_term;
        }

        out.push(product);
    }

    Ok(out)
}

/// Multiplies with single-use triple tracking.
pub fn beaver_multiply_tracked_checked(
    lhs: &[AuthShare],
    rhs: &[AuthShare],
    triples: &[CertifiedBeaverTripleShare],
    mac_keys: &[MacKeyShare],
    tracker: &mut TripleUseTracker,
) -> Result<Vec<AuthShare>, BeaverError> {
    let triple_id = triple_id_for_lhs(lhs, triples)?;
    tracker.mark_used(triple_id)?;
    beaver_multiply_checked(lhs, rhs, triples, mac_keys)
}

fn find_share(shares: &[AuthShare], party: PartyId) -> Option<AuthShare> {
    shares.iter().copied().find(|share| share.party == party)
}

fn find_triple(
    triples: &[CertifiedBeaverTripleShare],
    party: PartyId,
) -> Option<CertifiedBeaverTripleShare> {
    triples.iter().copied().find(|triple| triple.party == party)
}

fn find_mac_key(mac_keys: &[MacKeyShare], party: PartyId) -> Option<MacKeyShare> {
    mac_keys
        .iter()
        .copied()
        .find(|mac_key| mac_key.party == party)
}

fn validate_triple_party(triple: CertifiedBeaverTripleShare) -> Result<(), BeaverError> {
    if triple.a.party != triple.party
        || triple.b.party != triple.party
        || triple.c.party != triple.party
    {
        return Err(BeaverError::TriplePartyMismatch(triple.party));
    }

    Ok(())
}

#[cfg(any(test, feature = "test-dealer"))]
fn validate_unchecked_triple_party(triple: UncheckedBeaverTripleShare) -> Result<(), BeaverError> {
    if triple.a.party != triple.party
        || triple.b.party != triple.party
        || triple.c.party != triple.party
    {
        return Err(BeaverError::TriplePartyMismatch(triple.party));
    }

    Ok(())
}

fn triple_id_for_lhs(
    lhs: &[AuthShare],
    triples: &[CertifiedBeaverTripleShare],
) -> Result<TripleId, BeaverError> {
    let first = lhs.first().ok_or(BeaverError::Empty)?;
    let first_triple =
        find_triple(triples, first.party).ok_or(BeaverError::MissingTriple(first.party))?;
    let expected = first_triple.id;

    for lhs_share in lhs {
        let triple = find_triple(triples, lhs_share.party)
            .ok_or(BeaverError::MissingTriple(lhs_share.party))?;
        if triple.id != expected {
            return Err(BeaverError::TripleIdMismatch {
                expected,
                got: triple.id,
            });
        }
    }

    Ok(expected)
}

#[cfg(any(test, feature = "test-dealer"))]
fn unchecked_triple_id(triples: &[UncheckedBeaverTripleShare]) -> Result<TripleId, BeaverError> {
    let first = triples.first().ok_or(BeaverError::Empty)?;
    let expected = first.id;
    for triple in triples {
        if triple.id != expected {
            return Err(BeaverError::TripleIdMismatch {
                expected,
                got: triple.id,
            });
        }
    }
    Ok(expected)
}

#[cfg(any(test, feature = "test-dealer"))]
fn test_triple_certificate_hash(triple: &UncheckedBeaverTripleShare) -> [u8; 32] {
    let mut seed = triple.id.0.to_le_bytes().to_vec();
    seed.extend_from_slice(&triple.party.0.to_le_bytes());
    seed.extend_from_slice(&triple.a.value.to_u128().to_le_bytes());
    seed.extend_from_slice(&triple.b.value.to_u128().to_le_bytes());
    seed.extend_from_slice(&triple.c.value.to_u128().to_le_bytes());
    let mut out = [0u8; 32];
    for (idx, byte) in seed.iter().enumerate() {
        out[idx % 32] ^= *byte;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::open_checked;
    use crate::auth::test_dealer::deal_authenticated;
    use crate::Gf128;

    fn deal_triple(
        id: TripleId,
        a: Gf128,
        b: Gf128,
        alpha: Gf128,
        party_count: u16,
    ) -> Vec<CertifiedBeaverTripleShare> {
        let unchecked = deal_unchecked_triple(id, a, b, alpha, party_count);
        let mac_keys = deal_authenticated(Gf128::ZERO, alpha, party_count).mac_keys;
        certify_triple_bundle_for_test(&unchecked, &mac_keys).expect("test triple certifies")
    }

    fn deal_unchecked_triple(
        id: TripleId,
        a: Gf128,
        b: Gf128,
        alpha: Gf128,
        party_count: u16,
    ) -> Vec<UncheckedBeaverTripleShare> {
        let a_deal = deal_authenticated(a, alpha, party_count);
        let b_deal = deal_authenticated(b, alpha, party_count);
        let c_deal = deal_authenticated(a * b, alpha, party_count);

        a_deal
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
            .collect()
    }

    #[test]
    fn beaver_multiplication_matches_clear_multiplication() {
        let alpha = Gf128::from_u128(0x9876);
        let x = Gf128::from_u128(0x1234);
        let y = Gf128::from_u128(0x5678);
        let x_deal = deal_authenticated(x, alpha, 4);
        let y_deal = deal_authenticated(y, alpha, 4);
        let triples = deal_triple(
            TripleId(1),
            Gf128::from_u128(0x1111),
            Gf128::from_u128(0x2222),
            alpha,
            4,
        );

        let product =
            beaver_multiply_checked(&x_deal.shares, &y_deal.shares, &triples, &x_deal.mac_keys)
                .expect("valid Beaver multiplication succeeds");

        assert_eq!(open_checked(&product, &x_deal.mac_keys), Ok(x * y));
    }

    #[test]
    fn bad_input_mac_fails_before_product_is_returned() {
        let alpha = Gf128::from_u128(0x9876);
        let x = Gf128::from_u128(0x1234);
        let y = Gf128::from_u128(0x5678);
        let mut x_deal = deal_authenticated(x, alpha, 4);
        let y_deal = deal_authenticated(y, alpha, 4);
        let triples = deal_triple(
            TripleId(2),
            Gf128::from_u128(0x1111),
            Gf128::from_u128(0x2222),
            alpha,
            4,
        );
        x_deal.shares[0].mac += Gf128::ONE;

        assert_eq!(
            beaver_multiply_checked(&x_deal.shares, &y_deal.shares, &triples, &x_deal.mac_keys),
            Err(BeaverError::Open(OpenError::MacCheckFailed))
        );
    }

    #[test]
    fn bad_triple_c_share_fails_when_product_is_opened() {
        let alpha = Gf128::from_u128(0x9876);
        let x = Gf128::from_u128(0x1234);
        let y = Gf128::from_u128(0x5678);
        let x_deal = deal_authenticated(x, alpha, 4);
        let y_deal = deal_authenticated(y, alpha, 4);
        let mut triples = deal_triple(
            TripleId(3),
            Gf128::from_u128(0x1111),
            Gf128::from_u128(0x2222),
            alpha,
            4,
        );
        triples[0].c.value += Gf128::ONE;

        let product =
            beaver_multiply_checked(&x_deal.shares, &y_deal.shares, &triples, &x_deal.mac_keys)
                .expect("tampered output is not released until checked opening");

        assert_eq!(
            open_checked(&product, &x_deal.mac_keys),
            Err(OpenError::MacCheckFailed)
        );
    }

    #[test]
    fn mac_valid_but_relation_invalid_triple_fails_certification() {
        let alpha = Gf128::from_u128(0x9876);
        let a = Gf128::from_u128(0x1111);
        let b = Gf128::from_u128(0x2222);
        let mut unchecked = deal_unchecked_triple(TripleId(31), a, b, alpha, 4);
        let bad_c = deal_authenticated((a * b) + Gf128::ONE, alpha, 4);
        for (triple, c_share) in unchecked.iter_mut().zip(&bad_c.shares) {
            triple.c = *c_share;
        }

        let mac_keys = deal_authenticated(Gf128::ZERO, alpha, 4).mac_keys;
        assert_eq!(
            certify_triple_bundle_for_test(&unchecked, &mac_keys),
            Err(BeaverError::TripleRelationInvalid(TripleId(31)))
        );
    }

    #[test]
    fn triple_reuse_is_rejected() {
        let alpha = Gf128::from_u128(0x9876);
        let x = Gf128::from_u128(0x1234);
        let y = Gf128::from_u128(0x5678);
        let x_deal = deal_authenticated(x, alpha, 4);
        let y_deal = deal_authenticated(y, alpha, 4);
        let triples = deal_triple(
            TripleId(4),
            Gf128::from_u128(0x1111),
            Gf128::from_u128(0x2222),
            alpha,
            4,
        );
        let mut tracker = TripleUseTracker::new();

        let product = beaver_multiply_tracked_checked(
            &x_deal.shares,
            &y_deal.shares,
            &triples,
            &x_deal.mac_keys,
            &mut tracker,
        )
        .expect("first tracked Beaver multiplication succeeds");
        assert_eq!(open_checked(&product, &x_deal.mac_keys), Ok(x * y));

        assert_eq!(
            beaver_multiply_tracked_checked(
                &x_deal.shares,
                &y_deal.shares,
                &triples,
                &x_deal.mac_keys,
                &mut tracker,
            ),
            Err(BeaverError::TripleAlreadyUsed(TripleId(4)))
        );
    }

    #[test]
    fn mixed_triple_ids_are_rejected() {
        let alpha = Gf128::from_u128(0x9876);
        let x_deal = deal_authenticated(Gf128::from_u128(0x1234), alpha, 4);
        let y_deal = deal_authenticated(Gf128::from_u128(0x5678), alpha, 4);
        let mut triples = deal_triple(
            TripleId(5),
            Gf128::from_u128(0x1111),
            Gf128::from_u128(0x2222),
            alpha,
            4,
        );
        triples[2].id = TripleId(6);
        let mut tracker = TripleUseTracker::new();

        assert_eq!(
            beaver_multiply_tracked_checked(
                &x_deal.shares,
                &y_deal.shares,
                &triples,
                &x_deal.mac_keys,
                &mut tracker,
            ),
            Err(BeaverError::TripleIdMismatch {
                expected: TripleId(5),
                got: TripleId(6),
            })
        );
    }

    #[test]
    fn in_memory_triple_provider_returns_bundles_in_order() {
        let alpha = Gf128::from_u128(0x9876);
        let first = deal_triple(
            TripleId(10),
            Gf128::from_u128(0x1111),
            Gf128::from_u128(0x2222),
            alpha,
            2,
        );
        let second = deal_triple(
            TripleId(11),
            Gf128::from_u128(0x3333),
            Gf128::from_u128(0x4444),
            alpha,
            2,
        );
        let mut provider = InMemoryTripleProvider::new(vec![first.clone(), second.clone()]);

        assert_eq!(provider.remaining(), 2);
        assert_eq!(provider.take_triple_bundle(), Ok(first));
        assert_eq!(provider.consumed(), 1);
        assert_eq!(provider.take_triple_bundles(1), Ok(vec![second]));
        assert_eq!(provider.remaining(), 0);
    }

    #[test]
    fn in_memory_triple_provider_rejects_exhaustion_without_advancing() {
        let alpha = Gf128::from_u128(0x9876);
        let bundle = deal_triple(
            TripleId(12),
            Gf128::from_u128(0x1111),
            Gf128::from_u128(0x2222),
            alpha,
            2,
        );
        let mut provider = InMemoryTripleProvider::new(vec![bundle]);

        assert_eq!(
            provider.take_triple_bundles(2),
            Err(TripleProviderError::Exhausted {
                requested: 2,
                remaining: 1,
            })
        );
        assert_eq!(provider.consumed(), 0);
        assert_eq!(provider.remaining(), 1);
    }

    #[test]
    fn in_memory_triple_provider_debug_redacts_bundles() {
        let alpha = Gf128::from_u128(0x9876);
        let bundle = deal_triple(
            TripleId(13),
            Gf128::from_u128(0x1111),
            Gf128::from_u128(0x2222),
            alpha,
            2,
        );
        let provider = InMemoryTripleProvider::new(vec![bundle]);

        assert_eq!(
            format!("{provider:?}"),
            "InMemoryTripleProvider { bundle_count: 1, next: 0, bundles: \"<redacted>\" }"
        );
    }

    #[test]
    fn debug_redacts_beaver_triple_material() {
        let alpha = Gf128::from_u128(0x9876);
        let triples = deal_triple(
            TripleId(7),
            Gf128::from_u128(0x1111),
            Gf128::from_u128(0x2222),
            alpha,
            2,
        );

        let debug = format!("{:?}", triples[0]);
        assert!(debug.contains("CertifiedBeaverTripleShare"));
        assert!(debug.contains("a: \"<redacted>\""));
        assert!(debug.contains("b: \"<redacted>\""));
        assert!(debug.contains("c: \"<redacted>\""));
    }
}
