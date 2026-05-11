use crate::{MpcAdversarialCase, MpcAdversarialOutcome};
use talus_core::MlDsa65;
use talus_mpc_core::{
    beaver_multiply_checked, beaver_multiply_tracked_checked, carry_compare,
    certify_triple_bundle_for_test, open_checked, AuthBit, AuthBitError, AuthShare, AuthU19,
    BeaverError, CarryError, CertifiedBeaverTripleShare, Gf128, InMemoryTripleProvider,
    MacKeyShare, OpenError, PartyId, TripleCursor, TripleId, TripleProvider, TripleProviderError,
    TripleUseTracker, UncheckedBeaverTripleShare, AUTH_U19_WIDTH,
};

/// Runs deterministic malicious MPC-core mutations.
pub fn run_mpc_adversarial_cases() -> Vec<MpcAdversarialCase> {
    let mut cases = Vec::new();

    cases.push(mpc_case(
        "bad_mac_open_rejects_without_value",
        {
            let mut deal = deal_authenticated(Gf128::from_u128(0x1234), Gf128::from_u128(0x55), 3);
            deal.shares[0].mac += Gf128::ONE;
            MpcAdversarialOutcome::Open(
                open_checked(&deal.shares, &deal.mac_keys).expect_err("bad MAC rejects"),
            )
        },
        MpcAdversarialOutcome::Open(OpenError::MacCheckFailed),
    ));

    cases.push(mpc_case(
        "bad_input_mac_rejects_before_product",
        {
            let alpha = Gf128::from_u128(0x9876);
            let mut lhs = deal_authenticated(Gf128::from_u128(0x12), alpha, 3);
            let rhs = deal_authenticated(Gf128::from_u128(0x34), alpha, 3);
            lhs.shares[0].mac += Gf128::ONE;
            let triples = deal_triple(
                TripleId(100),
                Gf128::from_u128(0x56),
                Gf128::from_u128(0x78),
                alpha,
                3,
            );
            MpcAdversarialOutcome::Beaver(
                beaver_multiply_checked(&lhs.shares, &rhs.shares, &triples, &lhs.mac_keys)
                    .expect_err("bad input MAC rejects before product"),
            )
        },
        MpcAdversarialOutcome::Beaver(BeaverError::Open(OpenError::MacCheckFailed)),
    ));

    cases.push(mpc_case(
        "relation_invalid_triple_rejects_certification",
        {
            let alpha = Gf128::from_u128(0x9876);
            let a = Gf128::from_u128(0x56);
            let b = Gf128::from_u128(0x78);
            let mut unchecked = deal_unchecked_triple(TripleId(101), a, b, alpha, 3);
            let bad_c = deal_authenticated((a * b) + Gf128::ONE, alpha, 3);
            for (triple, c_share) in unchecked.iter_mut().zip(&bad_c.shares) {
                triple.c = *c_share;
            }
            let mac_keys = deal_authenticated(Gf128::ZERO, alpha, 3).mac_keys;
            MpcAdversarialOutcome::Beaver(
                certify_triple_bundle_for_test(&unchecked, &mac_keys)
                    .expect_err("relation-invalid triple rejects certification"),
            )
        },
        MpcAdversarialOutcome::Beaver(BeaverError::TripleRelationInvalid(TripleId(101))),
    ));

    cases.push(mpc_case(
        "reused_triple_rejects_before_second_product",
        {
            let alpha = Gf128::from_u128(0x1111);
            let lhs = deal_authenticated(Gf128::from_u128(0x12), alpha, 3);
            let rhs = deal_authenticated(Gf128::from_u128(0x34), alpha, 3);
            let triples = deal_triple(
                TripleId(102),
                Gf128::from_u128(0x56),
                Gf128::from_u128(0x78),
                alpha,
                3,
            );
            let mut tracker = TripleUseTracker::new();
            let first = beaver_multiply_tracked_checked(
                &lhs.shares,
                &rhs.shares,
                &triples,
                &lhs.mac_keys,
                &mut tracker,
            )
            .expect("first tracked multiplication succeeds");
            open_checked(&first, &lhs.mac_keys).expect("first product opens");
            MpcAdversarialOutcome::Beaver(
                beaver_multiply_tracked_checked(
                    &lhs.shares,
                    &rhs.shares,
                    &triples,
                    &lhs.mac_keys,
                    &mut tracker,
                )
                .expect_err("second use rejects before product"),
            )
        },
        MpcAdversarialOutcome::Beaver(BeaverError::TripleAlreadyUsed(TripleId(102))),
    ));

    cases.push(mpc_case(
        "non_bit_carry_input_rejects_without_bits",
        {
            let alpha = Gf128::from_u128(0x2222);
            let mut bits = Vec::new();
            let bad = deal_authenticated(Gf128::from_u128(2), alpha, 3);
            bits.push(bits_from_shares(&bad.shares));
            for _ in 1..AUTH_U19_WIDTH {
                bits.push(public_bit_shares(false, &bad.mac_keys, PartyId(0)));
            }
            let r_sum = AuthU19::from_bits_le(bits).expect("valid U19 shape");
            let mut provider = InMemoryTripleProvider::new(triple_bundles(256, alpha, 3));
            let bundles = provider
                .take_triple_bundles(256)
                .expect("provider has enough bundles");
            let mut cursor = TripleCursor::new(&bundles);
            let mut tracker = TripleUseTracker::new();
            MpcAdversarialOutcome::Carry(
                carry_compare::<MlDsa65>(
                    &r_sum,
                    0,
                    &bad.mac_keys,
                    PartyId(0),
                    &mut cursor,
                    &mut tracker,
                )
                .expect_err("non-bit carry input rejects"),
            )
        },
        MpcAdversarialOutcome::Carry(CarryError::Bit(AuthBitError::NotBit(Gf128::from_u128(2)))),
    ));

    cases.push(mpc_case(
        "triple_provider_exhaustion_rejects_before_circuit",
        {
            let mut provider = InMemoryTripleProvider::new(Vec::new());
            MpcAdversarialOutcome::TripleProvider(
                provider
                    .take_triple_bundles(1)
                    .expect_err("empty provider rejects"),
            )
        },
        MpcAdversarialOutcome::TripleProvider(TripleProviderError::Exhausted {
            requested: 1,
            remaining: 0,
        }),
    ));

    cases
}

fn mpc_case(
    name: &'static str,
    got: MpcAdversarialOutcome,
    expected: MpcAdversarialOutcome,
) -> MpcAdversarialCase {
    MpcAdversarialCase {
        name,
        got,
        expected,
    }
}

struct AuthDeal {
    shares: Vec<AuthShare>,
    mac_keys: Vec<MacKeyShare>,
}

fn deal_authenticated(secret: Gf128, alpha: Gf128, party_count: u16) -> AuthDeal {
    let mut shares = Vec::with_capacity(party_count as usize);
    let mut mac_keys = Vec::with_capacity(party_count as usize);

    for party in 0..party_count {
        let party_id = PartyId(party);
        let value = if party == 0 { secret } else { Gf128::ZERO };
        let mac = if party == 0 {
            alpha * secret
        } else {
            Gf128::ZERO
        };
        let alpha_share = if party == 0 { alpha } else { Gf128::ZERO };
        shares.push(AuthShare {
            party: party_id,
            value,
            mac,
        });
        mac_keys.push(MacKeyShare {
            party: party_id,
            alpha: alpha_share,
        });
    }

    AuthDeal { shares, mac_keys }
}

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

fn bits_from_shares(shares: &[AuthShare]) -> Vec<AuthBit> {
    shares
        .iter()
        .copied()
        .map(AuthBit::from_share_unchecked)
        .collect()
}

fn public_bit_shares(bit: bool, mac_keys: &[MacKeyShare], public_party: PartyId) -> Vec<AuthBit> {
    let value = if bit { Gf128::ONE } else { Gf128::ZERO };
    mac_keys
        .iter()
        .map(|mac_key| {
            let value_share = if mac_key.party == public_party {
                value
            } else {
                Gf128::ZERO
            };
            AuthBit::from_share_unchecked(AuthShare {
                party: mac_key.party,
                value: value_share,
                mac: mac_key.alpha * value,
            })
        })
        .collect()
}

fn triple_bundles(
    count: usize,
    alpha: Gf128,
    party_count: u16,
) -> Vec<Vec<CertifiedBeaverTripleShare>> {
    (0..count)
        .map(|idx| {
            deal_triple(
                TripleId(idx as u64 + 20_000),
                Gf128::ONE,
                Gf128::ONE,
                alpha,
                party_count,
            )
        })
        .collect()
}
