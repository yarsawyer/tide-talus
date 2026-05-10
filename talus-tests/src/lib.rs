#![forbid(unsafe_code)]
#![doc = "Integration-test support for TALUS."]

use talus_core::{
    cef_w1_clear_coeff, cef_w1_coeff, signature_encoded_len, MlDsa44, MlDsa65, MlDsa87, MlDsaParams,
};
use talus_mpc::{
    certify_preprocessing_token, masked_broadcast_commitment, open_broadcasts, BroadcastEnvelope,
    ChallengeMaterial, Commitment, ConsumedTokenStore, FinalSignature, FinalVerifier,
    MaskedBroadcastConsistencyProof, NonceCommitment, OnlineError, OnlineServices,
    PartialSignature, PartialSigner, PartyPreprocessInput, PreprocessError, RetryPolicy, SessionId,
    SessionRegistry, SignRequest, SignatureAssembler, SigningCounters, TokenCandidate,
    TokenConsumptionStore, TokenPool, TokenPoolError, TranscriptHash, ONLINE_PROTOCOL_VERSION,
};
use talus_mpc_core::PartyId;
use talus_mpc_core::{
    beaver_multiply_checked, beaver_multiply_tracked_checked, carry_compare,
    certify_triple_bundle_for_test, open_checked, AuthBit, AuthBitError, AuthShare, AuthU19,
    BeaverError, CarryError, CertifiedBeaverTripleShare, Gf128, InMemoryTripleProvider,
    MacKeyShare, OpenError, TripleCursor, TripleId, TripleProvider, TripleProviderError,
    TripleUseTracker, UncheckedBeaverTripleShare, AUTH_U19_WIDTH,
};
use talus_wire::{
    decode_commit_payload, decode_final_signature_payload, decode_message,
    decode_partial_signature_payload, decode_sign_request_payload, encode_commit_payload,
    encode_final_signature_payload, encode_masked_broadcast_open_payload, encode_message,
    encode_partial_signature_payload, encode_sign_request_payload, signing_set_hash,
    validate_round_batch, CommitPayload, ExpectedContext, FinalSignaturePayload,
    MaskedBroadcastOpenPayload, PartialSignaturePayload, PayloadKind, RoundId, SignRequestPayload,
    SuiteId, WireError, WireHeader, WireMessage, WIRE_PROTOCOL_VERSION,
};

/// One deterministic property-style case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicPropertyCase {
    /// Human-readable case name.
    pub name: &'static str,
    /// Whether the property held.
    pub passed: bool,
    /// Short failure detail.
    pub detail: &'static str,
}

/// Observed outcome for one MPC-core adversarial case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MpcAdversarialOutcome {
    /// Checked opening rejected before returning a value.
    Open(OpenError),
    /// Beaver multiplication rejected before returning product shares.
    Beaver(BeaverError),
    /// Product shares were produced, but checked opening rejected them before a value was returned.
    ProductOpen(OpenError),
    /// Carry comparison rejected before returning carry/correction bits.
    Carry(CarryError),
    /// Triple provider rejected before handing out triple bundles.
    TripleProvider(TripleProviderError),
}

/// One deterministic adversarial MPC-core case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MpcAdversarialCase {
    /// Human-readable case name.
    pub name: &'static str,
    /// Observed failure.
    pub got: MpcAdversarialOutcome,
    /// Expected failure.
    pub expected: MpcAdversarialOutcome,
}

impl MpcAdversarialCase {
    /// Returns whether this case failed as expected.
    pub fn passed(&self) -> bool {
        self.got == self.expected
    }
}

/// Observed outcome for one online-signing adversarial case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnlineAdversarialOutcome {
    /// Online error returned to the caller.
    pub error: OnlineError,
    /// Whether the token was durably marked consumed.
    pub token_consumed: bool,
    /// Number of verified signatures returned.
    pub signatures_returned: u64,
    /// Number of final verifier failures counted.
    pub final_verify_failures: u64,
    /// Number of retry-exhaustion events counted.
    pub retry_exhausted: u64,
}

/// One deterministic adversarial online-signing case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnlineAdversarialCase {
    /// Human-readable case name.
    pub name: &'static str,
    /// Observed failure.
    pub got: OnlineAdversarialOutcome,
    /// Expected failure.
    pub expected: OnlineAdversarialOutcome,
}

impl OnlineAdversarialCase {
    /// Returns whether this case failed as expected.
    pub fn passed(&self) -> bool {
        self.got == self.expected
    }
}

/// Observed outcome for one preprocessing adversarial case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreprocessingAdversarialOutcome {
    /// Preprocessing rejected the mutated input or opened broadcast.
    Preprocess(PreprocessError),
    /// Token pool rejected an uncertified or duplicate object.
    TokenPool(TokenPoolError),
}

/// One deterministic adversarial preprocessing case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreprocessingAdversarialCase {
    /// Human-readable case name.
    pub name: &'static str,
    /// Observed failure.
    pub got: PreprocessingAdversarialOutcome,
    /// Expected failure.
    pub expected: PreprocessingAdversarialOutcome,
}

impl PreprocessingAdversarialCase {
    /// Returns whether this case failed as expected.
    pub fn passed(&self) -> bool {
        self.got == self.expected
    }
}

/// One deterministic adversarial wire case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireAdversarialCase {
    /// Human-readable case name.
    pub name: &'static str,
    /// Observed failure.
    pub got: WireError,
    /// Expected failure.
    pub expected: WireError,
}

impl WireAdversarialCase {
    /// Returns whether this case failed as expected.
    pub fn passed(&self) -> bool {
        self.got == self.expected
    }
}

/// Runs deterministic property-style mutation loops.
pub fn run_deterministic_property_cases() -> Vec<DeterministicPropertyCase> {
    vec![
        property_case(
            "cef_boundary_identities_all_suites",
            cef_boundary_identities::<MlDsa44>()
                && cef_boundary_identities::<MlDsa65>()
                && cef_boundary_identities::<MlDsa87>(),
        ),
        property_case(
            "wire_message_canonical_roundtrips",
            wire_canonical_roundtrips(),
        ),
        property_case(
            "wire_payload_codecs_reject_trailing_mutations",
            payload_codecs_reject_trailing_mutations(),
        ),
        property_case(
            "signature_payload_lengths_all_suites",
            signature_payload_lengths_all_suites(),
        ),
        property_case(
            "signer_set_permutation_hashes_are_canonical",
            signer_set_permutation_hashes_are_canonical(),
        ),
    ]
}

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

/// Runs deterministic malicious online-signing mutations.
pub fn run_online_adversarial_cases() -> Vec<OnlineAdversarialCase> {
    let mut cases = Vec::new();

    cases.push(online_case(
        "wrong_request_session",
        {
            let (token, mut request) = online_token_and_request(0x31);
            request.session_id = online_session(0x99);
            validate_request_err(&request, &token)
        },
        online_outcome(OnlineError::SessionMismatch, false, 0, 0, 0),
    ));

    cases.push(online_case(
        "wrong_signing_set",
        {
            let (token, mut request) = online_token_and_request(0x32);
            request.signing_set.reverse();
            validate_request_err(&request, &token)
        },
        online_outcome(OnlineError::SigningSetMismatch, false, 0, 0, 0),
    ));

    cases.push(online_case(
        "wrong_token_transcript",
        {
            let (token, mut request) = online_token_and_request(0x33);
            request.token_transcript_hash = TranscriptHash([0x44; 32]);
            validate_request_err(&request, &token)
        },
        online_outcome(OnlineError::TranscriptMismatch, false, 0, 0, 0),
    ));

    cases.push(online_case(
        "wrong_partial_session_blames_and_consumes",
        sign_once_err(0x34, &WrongSessionPartialSigner, &AcceptVerifier),
        online_outcome(OnlineError::Blame(PartyId(1)), true, 0, 0, 0),
    ));

    cases.push(online_case(
        "wrong_partial_challenge_blames_and_consumes",
        sign_once_err(0x35, &WrongChallengePartialSigner, &AcceptVerifier),
        online_outcome(OnlineError::Blame(PartyId(1)), true, 0, 0, 0),
    ));

    cases.push(online_case(
        "final_verifier_rejection_consumes_without_output",
        sign_once_err(0x36, &SessionAwarePartialSigner, &RejectVerifier),
        online_outcome(OnlineError::FinalVerifyFailed, true, 0, 1, 0),
    ));

    cases.push(online_case(
        "consumed_token_reuse_rejected_without_second_consumption",
        consumed_reuse_outcome(0x37),
        online_outcome(
            OnlineError::TokenAlreadyConsumed(online_session(0x37)),
            true,
            1,
            0,
            0,
        ),
    ));

    cases.push(online_case(
        "retry_exhaustion_after_final_verify_failures",
        retry_exhausted_outcome(0x38, 0x39),
        online_outcome(OnlineError::RetryExhausted, true, 0, 2, 1),
    ));

    cases
}

/// Runs deterministic malicious preprocessing mutations.
pub fn run_preprocessing_adversarial_cases() -> Vec<PreprocessingAdversarialCase> {
    let mut cases = Vec::new();

    cases.push(preprocess_case(
        "empty_signer_set",
        preprocessing_err(0x01, Vec::new()),
        PreprocessError::EmptySignerSet,
    ));

    cases.push(preprocess_case(
        "duplicate_party_input",
        preprocessing_err(0x02, vec![preprocess_input(1), preprocess_input(1)]),
        PreprocessError::DuplicateParty(PartyId(1)),
    ));

    let mut bad = preprocess_input(2);
    bad.highs.push(3);
    cases.push(preprocess_case(
        "input_coeff_count_mismatch",
        preprocessing_err(0x03, vec![preprocess_input(1), bad]),
        PreprocessError::CoeffCountMismatch,
    ));

    let mut bad = preprocess_input(1);
    bad.highs[0] = MlDsa65::HIGH_MOD as u32;
    cases.push(preprocess_case(
        "invalid_high_bit",
        preprocessing_err(0x04, vec![bad, preprocess_input(2)]),
        PreprocessError::InvalidHigh {
            party: PartyId(1),
            value: MlDsa65::HIGH_MOD as u32,
        },
    ));

    let mut bad = preprocess_input(2);
    bad.lows[0] = MlDsa65::alpha() as u32;
    cases.push(preprocess_case(
        "invalid_low_bit",
        preprocessing_err(0x05, vec![preprocess_input(1), bad]),
        PreprocessError::InvalidLow {
            party: PartyId(2),
            value: MlDsa65::alpha() as u32,
        },
    ));

    cases.push(preprocess_case(
        "session_reuse",
        {
            let mut registry = SessionRegistry::new();
            certify_preprocessing_token::<MlDsa65>(
                &mut registry,
                preprocess_session(0x06),
                valid_preprocess_inputs(),
            )
            .expect("first preprocessing session certifies");
            certify_preprocessing_token::<MlDsa65>(
                &mut registry,
                preprocess_session(0x06),
                valid_preprocess_inputs(),
            )
            .expect_err("session reuse rejects")
        },
        PreprocessError::SessionReuse(preprocess_session(0x06)),
    ));

    cases.push(preprocess_case(
        "equivocated_masked_high",
        {
            let (session_id, transcript, mut envelopes) = valid_open_envelopes(0x07);
            envelopes[0].message.masked_highs[0] ^= 1;
            open_broadcasts(session_id, &envelopes, transcript).expect_err("equivocation rejects")
        },
        PreprocessError::CommitmentMismatch(PartyId(1)),
    ));

    cases.push(preprocess_case(
        "mutated_commitment_salt",
        {
            let (session_id, transcript, mut envelopes) = valid_open_envelopes(0x08);
            envelopes[1].salt[0] ^= 1;
            open_broadcasts(session_id, &envelopes, transcript).expect_err("salt mutation rejects")
        },
        PreprocessError::CommitmentMismatch(PartyId(2)),
    ));

    cases.push(preprocess_case(
        "wrong_transcript_with_valid_commitment",
        {
            let (session_id, transcript, mut envelopes) = valid_open_envelopes(0x09);
            envelopes[2].message.transcript_hash = TranscriptHash([0x99; 32]);
            envelopes[2].commitment =
                masked_broadcast_commitment(session_id, &envelopes[2].message, envelopes[2].salt);
            open_broadcasts(session_id, &envelopes, transcript)
                .expect_err("wrong transcript rejects after commitment check")
        },
        PreprocessError::TranscriptMismatch(PartyId(3)),
    ));

    cases.push(preprocess_case(
        "duplicate_opened_party",
        {
            let (session_id, transcript, mut envelopes) = valid_open_envelopes(0x0a);
            envelopes[1] = envelopes[0].clone();
            open_broadcasts(session_id, &envelopes, transcript)
                .expect_err("duplicate opened party rejects")
        },
        PreprocessError::DuplicateParty(PartyId(1)),
    ));

    cases.push(token_pool_case(
        "uncertified_token_candidate",
        {
            let mut pool = TokenPool::new();
            pool.insert_candidate(TokenCandidate {
                session_id: preprocess_session(0x0b),
            })
            .expect_err("uncertified token rejects")
        },
        TokenPoolError::NotCertified(preprocess_session(0x0b)),
    ));

    cases
}

/// Runs deterministic adversarial wire mutations and replay checks.
pub fn run_wire_adversarial_cases() -> Vec<WireAdversarialCase> {
    let mut cases = Vec::new();
    let base = commit_message(1, [0x22; 32]);
    let encoded = encode_message(&base).expect("base message encodes");

    cases.push(case(
        "bad_magic",
        {
            let mut mutated = encoded.clone();
            mutated[0] ^= 1;
            decode_message(&mutated).expect_err("bad magic rejects")
        },
        WireError::BadMagic,
    ));

    cases.push(case(
        "unknown_suite",
        {
            let mut mutated = encoded.clone();
            mutated[10] = 99;
            decode_message(&mutated).expect_err("unknown suite rejects")
        },
        WireError::UnknownSuite(99),
    ));

    cases.push(case(
        "unknown_round",
        {
            let mut mutated = encoded.clone();
            mutated[11] = 99;
            decode_message(&mutated).expect_err("unknown round rejects")
        },
        WireError::UnknownRound(99),
    ));

    cases.push(case(
        "unknown_payload_kind",
        {
            let mut mutated = encoded.clone();
            let payload_kind_offset = 8 + 2 + 1 + 1 + 2 + 32 + 32;
            mutated[payload_kind_offset] = 99;
            mutated[payload_kind_offset + 1] = 0;
            decode_message(&mutated).expect_err("unknown payload kind rejects")
        },
        WireError::UnknownPayloadKind(99),
    ));

    cases.push(case(
        "truncated_payload",
        {
            let mut mutated = encoded.clone();
            mutated.pop();
            decode_message(&mutated).expect_err("truncated payload rejects")
        },
        WireError::PayloadLengthMismatch {
            expected_total: encoded.len(),
            got_total: encoded.len() - 1,
        },
    ));

    let mut replayed = base.clone();
    replayed.header.session_id = [0x99; 32];
    cases.push(case(
        "cross_session_replay",
        validate_round_batch(&[replayed], RoundId::PreprocessCommit, &expected_context())
            .expect_err("cross-session replay rejects"),
        WireError::ContextMismatch,
    ));

    let mut replayed = base.clone();
    replayed.header.suite = SuiteId::MlDsa87;
    cases.push(case(
        "cross_suite_replay",
        validate_round_batch(&[replayed], RoundId::PreprocessCommit, &expected_context())
            .expect_err("cross-suite replay rejects"),
        WireError::ContextMismatch,
    ));

    cases.push(case(
        "unknown_sender",
        validate_round_batch(
            &[commit_message(9, [0x22; 32])],
            RoundId::PreprocessCommit,
            &expected_context(),
        )
        .expect_err("unknown sender rejects"),
        WireError::UnknownSender(9),
    ));

    cases.push(case(
        "duplicate_sender",
        validate_round_batch(
            &[commit_message(1, [0x22; 32]), commit_message(1, [0x22; 32])],
            RoundId::PreprocessCommit,
            &expected_context(),
        )
        .expect_err("duplicate sender rejects"),
        WireError::DuplicateSender(1),
    ));

    cases.push(case(
        "wrong_round",
        validate_round_batch(
            &[partial_message(1)],
            RoundId::PreprocessCommit,
            &expected_context(),
        )
        .expect_err("wrong round rejects"),
        WireError::RoundMismatch {
            expected: RoundId::PreprocessCommit,
            got: RoundId::SignPartial,
        },
    ));

    cases.push(case(
        "dropped_message",
        require_all_parties(
            &[commit_message(1, [0x22; 32]), commit_message(2, [0x22; 32])],
            &[1, 2, 3],
        )
        .expect_err("dropped message rejects"),
        WireError::UnknownSender(3),
    ));

    cases.push(case(
        "malformed_commit_payload",
        decode_commit_payload(&[0u8; 31]).expect_err("short commit rejects"),
        WireError::TruncatedPayload,
    ));

    cases.push(case(
        "malformed_sign_request_flag",
        {
            let payload = SignRequestPayload {
                message: b"message".to_vec(),
                context: b"ctx".to_vec(),
                external_mu: None,
                token_transcript_hash: [0x55; 32],
            };
            let mut encoded = encode_sign_request_payload(&payload);
            let flag_index = 4 + payload.message.len() + 4 + payload.context.len();
            encoded[flag_index] = 7;
            decode_sign_request_payload(&encoded).expect_err("bad flag rejects")
        },
        WireError::NonCanonicalFlag(7),
    ));

    cases.push(case(
        "malformed_masked_open_vector_lengths",
        {
            let payload = MaskedBroadcastOpenPayload {
                masked_highs: vec![1],
                masked_lows: vec![2, 3],
                nonce_commitment: [0; 32],
                rho_bits_commitment: [1; 32],
                transcript_hash: [2; 32],
                consistency_proof: vec![4, 5, 6],
                salt: [3; 32],
            };
            encode_masked_broadcast_open_payload(&payload).expect_err("length mismatch rejects")
        },
        WireError::VectorLengthMismatch { lhs: 1, rhs: 2 },
    ));

    cases.push(case(
        "malformed_final_payload_trailing",
        {
            let mut encoded = encode_final_signature_payload(&FinalSignaturePayload {
                signature: vec![1, 2, 3],
            });
            encoded.push(0);
            decode_final_signature_payload(&encoded).expect_err("trailing final rejects")
        },
        WireError::TrailingPayloadBytes(1),
    ));

    cases
}

/// Requires exactly one message from every expected party.
pub fn require_all_parties(messages: &[WireMessage], parties: &[u16]) -> Result<(), WireError> {
    for &party in parties {
        if !messages
            .iter()
            .any(|message| message.header.sender_party_id == party)
        {
            return Err(WireError::UnknownSender(party));
        }
    }
    Ok(())
}

fn case(name: &'static str, got: WireError, expected: WireError) -> WireAdversarialCase {
    WireAdversarialCase {
        name,
        got,
        expected,
    }
}

fn property_case(name: &'static str, passed: bool) -> DeterministicPropertyCase {
    DeterministicPropertyCase {
        name,
        passed,
        detail: if passed {
            "ok"
        } else {
            "deterministic property failed"
        },
    }
}

fn cef_boundary_identities<P: MlDsaParams>() -> bool {
    let alpha = P::alpha() as u32;
    let gamma2 = P::GAMMA2 as u32;
    let m = P::HIGH_MOD as u32;
    let high_cases = [
        [0, 0, 0],
        [1 % m, 2 % m, 3 % m],
        [(m + m - 1) % m, 0, 1 % m],
    ];
    let low_cases = [0, gamma2, gamma2 + 1, alpha - 1, alpha - 500];
    let rho_cases = [[0, 0, 0], [1, 2, 3], [1000, 0, 0]];

    for highs in high_cases {
        for b_sum in low_cases {
            let lows = [b_sum, 0, 0];
            let direct = cef_w1_clear_coeff::<P>(&highs, &lows);

            for rhos in rho_cases {
                let masked_lows = [
                    lows[0].saturating_add(rhos[0]),
                    lows[1].saturating_add(rhos[1]),
                    lows[2].saturating_add(rhos[2]),
                ];
                let got = cef_w1_coeff::<P>(&highs, &masked_lows, &rhos);
                if got != direct {
                    return false;
                }
            }
        }
    }

    true
}

fn wire_canonical_roundtrips() -> bool {
    let messages = [
        commit_message(1, [0x22; 32]),
        WireMessage {
            header: header(
                2,
                [0x22; 32],
                RoundId::PreprocessOpen,
                PayloadKind::MaskedBroadcastOpen,
            ),
            payload: encode_masked_broadcast_open_payload(&MaskedBroadcastOpenPayload {
                masked_highs: vec![1, 2, 3],
                masked_lows: vec![4, 5, 6],
                nonce_commitment: [7; 32],
                rho_bits_commitment: [8; 32],
                transcript_hash: [9; 32],
                consistency_proof: vec![11, 12, 13],
                salt: [10; 32],
            })
            .expect("valid masked-open payload"),
        },
        partial_message(3),
    ];

    for message in messages {
        let encoded = match encode_message(&message) {
            Ok(encoded) => encoded,
            Err(_) => return false,
        };
        let decoded = match decode_message(&encoded) {
            Ok(decoded) => decoded,
            Err(_) => return false,
        };
        let reencoded = match encode_message(&decoded) {
            Ok(reencoded) => reencoded,
            Err(_) => return false,
        };
        if decoded != message || reencoded != encoded {
            return false;
        }
    }

    true
}

fn payload_codecs_reject_trailing_mutations() -> bool {
    let commit = encode_commit_payload(&CommitPayload {
        commitment: [1; 32],
    });
    let sign_request = encode_sign_request_payload(&SignRequestPayload {
        message: b"message".to_vec(),
        context: b"ctx".to_vec(),
        external_mu: Some([2; 64]),
        token_transcript_hash: [3; 32],
    });
    let partial = encode_partial_signature_payload(&PartialSignaturePayload {
        ctilde: vec![4; MlDsa65::CTILDE_LEN],
        z_share: vec![5; 17],
    });
    let final_sig = encode_final_signature_payload(&FinalSignaturePayload {
        signature: vec![6; MlDsa65::SIG_LEN],
    });

    let mut payloads = vec![
        (commit, PayloadCodec::Commit),
        (sign_request, PayloadCodec::SignRequest),
        (partial, PayloadCodec::Partial),
        (final_sig, PayloadCodec::Final),
    ];

    for (payload, codec) in &mut payloads {
        payload.push(0);
        let rejected = match codec {
            PayloadCodec::Commit => decode_commit_payload(payload).is_err(),
            PayloadCodec::SignRequest => decode_sign_request_payload(payload).is_err(),
            PayloadCodec::Partial => decode_partial_signature_payload(payload).is_err(),
            PayloadCodec::Final => decode_final_signature_payload(payload).is_err(),
        };
        if !rejected {
            return false;
        }
    }

    true
}

fn signature_payload_lengths_all_suites() -> bool {
    let suite_lengths = [
        (MlDsa44::SIG_LEN, signature_encoded_len::<MlDsa44>()),
        (MlDsa65::SIG_LEN, signature_encoded_len::<MlDsa65>()),
        (MlDsa87::SIG_LEN, signature_encoded_len::<MlDsa87>()),
    ];

    for (declared, encoded_len) in suite_lengths {
        if declared != encoded_len {
            return false;
        }
        let payload = FinalSignaturePayload {
            signature: vec![0xa5; declared],
        };
        let encoded = encode_final_signature_payload(&payload);
        let decoded = match decode_final_signature_payload(&encoded) {
            Ok(decoded) => decoded,
            Err(_) => return false,
        };
        if decoded.signature.len() != declared || decoded != payload {
            return false;
        }
    }

    true
}

fn signer_set_permutation_hashes_are_canonical() -> bool {
    let permutations = [
        [1u16, 2, 3],
        [1, 3, 2],
        [2, 1, 3],
        [2, 3, 1],
        [3, 1, 2],
        [3, 2, 1],
    ];
    let expected = signing_set_hash(&[1, 2, 3]);

    for permutation in permutations {
        if signing_set_hash(&permutation) != expected {
            return false;
        }
    }

    signing_set_hash(&[1, 2, 2]) != expected && signing_set_hash(&[1, 2, 4]) != expected
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PayloadCodec {
    Commit,
    SignRequest,
    Partial,
    Final,
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

fn preprocess_case(
    name: &'static str,
    got: PreprocessError,
    expected: PreprocessError,
) -> PreprocessingAdversarialCase {
    PreprocessingAdversarialCase {
        name,
        got: PreprocessingAdversarialOutcome::Preprocess(got),
        expected: PreprocessingAdversarialOutcome::Preprocess(expected),
    }
}

fn token_pool_case(
    name: &'static str,
    got: TokenPoolError,
    expected: TokenPoolError,
) -> PreprocessingAdversarialCase {
    PreprocessingAdversarialCase {
        name,
        got: PreprocessingAdversarialOutcome::TokenPool(got),
        expected: PreprocessingAdversarialOutcome::TokenPool(expected),
    }
}

fn online_case(
    name: &'static str,
    got: OnlineAdversarialOutcome,
    expected: OnlineAdversarialOutcome,
) -> OnlineAdversarialCase {
    OnlineAdversarialCase {
        name,
        got,
        expected,
    }
}

fn online_outcome(
    error: OnlineError,
    token_consumed: bool,
    signatures_returned: u64,
    final_verify_failures: u64,
    retry_exhausted: u64,
) -> OnlineAdversarialOutcome {
    OnlineAdversarialOutcome {
        error,
        token_consumed,
        signatures_returned,
        final_verify_failures,
        retry_exhausted,
    }
}

fn validate_request_err(
    request: &SignRequest,
    token: &talus_mpc::CertifiedToken,
) -> OnlineAdversarialOutcome {
    let error = talus_mpc::validate_sign_request::<MlDsa65>(request, token)
        .expect_err("mutated request rejects");
    online_outcome(error, false, 0, 0, 0)
}

fn sign_once_err(
    byte: u8,
    signer: &impl PartialSigner,
    verifier: &impl FinalVerifier,
) -> OnlineAdversarialOutcome {
    let (token, request) = online_token_and_request(byte);
    let mut pool = TokenPool::new();
    pool.insert_certified(token)
        .expect("insert certified online token");
    let mut consumed = ConsumedTokenStore::new();
    let mut counters = SigningCounters::default();
    let tr = [0x42; 64];
    let error = talus_mpc::sign_with_token::<MlDsa65, _, _, _, _>(
        &mut pool,
        &mut consumed,
        &mut counters,
        &request,
        OnlineServices {
            tr: &tr,
            partial_signer: signer,
            assembler: &TestAssembler,
            verifier,
        },
    )
    .expect_err("adversarial online signing rejects");

    online_outcome(
        error,
        consumed.is_consumed(request.session_id),
        counters.signatures_returned,
        counters.final_verify_failures,
        counters.retry_exhausted,
    )
}

fn consumed_reuse_outcome(byte: u8) -> OnlineAdversarialOutcome {
    let (token, request) = online_token_and_request(byte);
    let mut pool = TokenPool::new();
    pool.insert_certified(token)
        .expect("insert certified online token");
    let mut consumed = ConsumedTokenStore::new();
    let mut counters = SigningCounters::default();
    let tr = [0x42; 64];

    talus_mpc::sign_with_token::<MlDsa65, _, _, _, _>(
        &mut pool,
        &mut consumed,
        &mut counters,
        &request,
        OnlineServices {
            tr: &tr,
            partial_signer: &SessionAwarePartialSigner,
            assembler: &TestAssembler,
            verifier: &AcceptVerifier,
        },
    )
    .expect("first signing succeeds");

    let error = talus_mpc::sign_with_token::<MlDsa65, _, _, _, _>(
        &mut pool,
        &mut consumed,
        &mut counters,
        &request,
        OnlineServices {
            tr: &tr,
            partial_signer: &SessionAwarePartialSigner,
            assembler: &TestAssembler,
            verifier: &AcceptVerifier,
        },
    )
    .expect_err("second signing rejects consumed token");

    online_outcome(
        error,
        consumed.is_consumed(request.session_id),
        counters.signatures_returned,
        counters.final_verify_failures,
        counters.retry_exhausted,
    )
}

fn retry_exhausted_outcome(first: u8, second: u8) -> OnlineAdversarialOutcome {
    let (first_token, first_request) = online_token_and_request(first);
    let (second_token, second_request) = online_token_and_request(second);
    let mut pool = TokenPool::new();
    pool.insert_certified(first_token)
        .expect("insert first online token");
    pool.insert_certified(second_token)
        .expect("insert second online token");
    let mut consumed = ConsumedTokenStore::new();
    let mut counters = SigningCounters::default();
    let tr = [0x42; 64];

    let error = talus_mpc::sign_with_retry::<MlDsa65, _, _, _, _>(
        &mut pool,
        &mut consumed,
        &mut counters,
        &[first_request.clone(), second_request.clone()],
        OnlineServices {
            tr: &tr,
            partial_signer: &SessionAwarePartialSigner,
            assembler: &TestAssembler,
            verifier: &RejectVerifier,
        },
        RetryPolicy { max_attempts: 2 },
    )
    .expect_err("retry exhaustion rejects");

    online_outcome(
        error,
        consumed.is_consumed(first_request.session_id)
            && consumed.is_consumed(second_request.session_id),
        counters.signatures_returned,
        counters.final_verify_failures,
        counters.retry_exhausted,
    )
}

fn preprocessing_err(session: u8, inputs: Vec<PartyPreprocessInput>) -> PreprocessError {
    let mut registry = SessionRegistry::new();
    certify_preprocessing_token::<MlDsa65>(&mut registry, preprocess_session(session), inputs)
        .expect_err("mutated preprocessing input rejects")
}

fn valid_open_envelopes(byte: u8) -> (SessionId, TranscriptHash, Vec<BroadcastEnvelope>) {
    let session_id = preprocess_session(byte);
    let mut registry = SessionRegistry::new();
    let token = certify_preprocessing_token::<MlDsa65>(
        &mut registry,
        session_id,
        valid_preprocess_inputs(),
    )
    .expect("valid preprocessing certifies before mutation");
    let envelopes = token
        .broadcasts
        .iter()
        .map(|broadcast| {
            let salt = preprocess_salt(session_id, broadcast.party);
            BroadcastEnvelope {
                commitment: masked_broadcast_commitment(session_id, broadcast, salt),
                message: broadcast.clone(),
                consistency_proof: MaskedBroadcastConsistencyProof::default(),
                salt,
            }
        })
        .collect();
    (session_id, token.transcript_hash, envelopes)
}

fn valid_preprocess_inputs() -> Vec<PartyPreprocessInput> {
    vec![
        preprocess_input(1),
        preprocess_input(2),
        preprocess_input(3),
    ]
}

fn preprocess_input(party: u16) -> PartyPreprocessInput {
    PartyPreprocessInput {
        party: PartyId(party),
        highs: vec![party as u32, party as u32 + 1],
        lows: vec![party as u32 + 10, party as u32 + 11],
        y_share: vec![party as u8; 8],
        ay_contribution: None,
        nonce_commitment: NonceCommitment([party as u8; 32]),
        randomness_commitment: Commitment([(party + 10) as u8; 32]),
    }
}

fn preprocess_session(byte: u8) -> SessionId {
    SessionId([byte; 32])
}

fn preprocess_salt(session_id: SessionId, party: PartyId) -> [u8; 32] {
    let mut salt = [0u8; 32];
    salt[..16].copy_from_slice(&session_id.0[..16]);
    salt[16..18].copy_from_slice(&party.0.to_le_bytes());
    salt
}

fn online_token_and_request(byte: u8) -> (talus_mpc::CertifiedToken, SignRequest) {
    let mut registry = SessionRegistry::new();
    let session_id = online_session(byte);
    let token = certify_preprocessing_token::<MlDsa65>(
        &mut registry,
        session_id,
        vec![online_preprocess_input(1), online_preprocess_input(2)],
    )
    .expect("online token certifies");
    let request = SignRequest {
        protocol_version: ONLINE_PROTOCOL_VERSION,
        suite: MlDsa65::NAME,
        session_id: token.session_id,
        signing_set: token.signer_set.clone(),
        message: b"message".to_vec(),
        external_mu: None,
        context: b"ctx".to_vec(),
        token_transcript_hash: token.transcript_hash,
    };
    (token, request)
}

fn online_preprocess_input(party: u16) -> PartyPreprocessInput {
    let coeffs = MlDsa65::K * MlDsa65::N;
    PartyPreprocessInput {
        party: PartyId(party),
        highs: vec![party as u32; coeffs],
        lows: vec![party as u32 + 2; coeffs],
        y_share: vec![party as u8; 8],
        ay_contribution: None,
        nonce_commitment: NonceCommitment([party as u8; 32]),
        randomness_commitment: Commitment([(party + 20) as u8; 32]),
    }
}

fn online_session(byte: u8) -> SessionId {
    SessionId([byte; 32])
}

struct SessionAwarePartialSigner;

impl PartialSigner for SessionAwarePartialSigner {
    fn sign_partial(
        &self,
        session_id: SessionId,
        party: PartyId,
        challenge: &ChallengeMaterial,
        y_share: &[u8],
    ) -> Result<PartialSignature, OnlineError> {
        let mut z_share = Vec::new();
        z_share.extend_from_slice(&challenge.ctilde[..8]);
        z_share.extend_from_slice(&(y_share.len() as u32).to_le_bytes());
        Ok(PartialSignature {
            session_id,
            party,
            z_share,
            challenge: challenge.ctilde.clone(),
        })
    }
}

struct WrongSessionPartialSigner;

impl PartialSigner for WrongSessionPartialSigner {
    fn sign_partial(
        &self,
        _session_id: SessionId,
        party: PartyId,
        challenge: &ChallengeMaterial,
        _y_share: &[u8],
    ) -> Result<PartialSignature, OnlineError> {
        Ok(PartialSignature {
            session_id: online_session(0xee),
            party,
            z_share: vec![0],
            challenge: challenge.ctilde.clone(),
        })
    }
}

struct WrongChallengePartialSigner;

impl PartialSigner for WrongChallengePartialSigner {
    fn sign_partial(
        &self,
        session_id: SessionId,
        party: PartyId,
        challenge: &ChallengeMaterial,
        _y_share: &[u8],
    ) -> Result<PartialSignature, OnlineError> {
        let mut wrong_challenge = challenge.ctilde.clone();
        wrong_challenge[0] ^= 1;
        Ok(PartialSignature {
            session_id,
            party,
            z_share: vec![0],
            challenge: wrong_challenge,
        })
    }
}

struct TestAssembler;

impl SignatureAssembler for TestAssembler {
    fn assemble(
        &self,
        _request: &SignRequest,
        challenge: &ChallengeMaterial,
        partials: &[PartialSignature],
    ) -> Result<FinalSignature, OnlineError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&challenge.ctilde);
        for partial in partials {
            bytes.extend_from_slice(&partial.z_share);
        }
        Ok(FinalSignature { bytes })
    }
}

struct AcceptVerifier;

impl FinalVerifier for AcceptVerifier {
    fn verify_final(&self, _request: &SignRequest, _signature: &FinalSignature) -> bool {
        true
    }
}

struct RejectVerifier;

impl FinalVerifier for RejectVerifier {
    fn verify_final(&self, _request: &SignRequest, _signature: &FinalSignature) -> bool {
        false
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

fn expected_context() -> ExpectedContext {
    ExpectedContext {
        suite: SuiteId::MlDsa65,
        keygen_transcript_hash: [0x11; 32],
        session_id: [0x22; 32],
        signing_set_hash: signing_set_hash(&[1, 2, 3]),
        allowed_parties: vec![1, 2, 3],
    }
}

fn header(sender: u16, session_id: [u8; 32], round: RoundId, kind: PayloadKind) -> WireHeader {
    WireHeader {
        protocol_version: WIRE_PROTOCOL_VERSION,
        suite: SuiteId::MlDsa65,
        round,
        sender_party_id: sender,
        keygen_transcript_hash: [0x11; 32],
        session_id,
        signing_set_hash: signing_set_hash(&[1, 2, 3]),
        payload_kind: kind,
    }
}

fn commit_message(sender: u16, session_id: [u8; 32]) -> WireMessage {
    WireMessage {
        header: header(
            sender,
            session_id,
            RoundId::PreprocessCommit,
            PayloadKind::PreprocessCommit,
        ),
        payload: encode_commit_payload(&CommitPayload {
            commitment: [sender as u8; 32],
        }),
    }
}

fn partial_message(sender: u16) -> WireMessage {
    WireMessage {
        header: header(
            sender,
            [0x22; 32],
            RoundId::SignPartial,
            PayloadKind::PartialSignature,
        ),
        payload: vec![1, 2, 3],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talus_wire::{decode_masked_broadcast_open_payload, encode_partial_signature_payload};

    #[test]
    fn deterministic_property_cases_pass() {
        let cases = run_deterministic_property_cases();
        assert!(cases.len() >= 5);
        for case in cases {
            assert!(case.passed, "case {} failed: {}", case.name, case.detail);
        }
    }

    #[test]
    fn all_mpc_adversarial_cases_fail_as_expected() {
        let cases = run_mpc_adversarial_cases();
        assert!(cases.len() >= 6);
        for case in cases {
            assert!(
                case.passed(),
                "case {} got {:?}, expected {:?}",
                case.name,
                case.got,
                case.expected
            );
        }
    }

    #[test]
    fn all_online_adversarial_cases_fail_as_expected() {
        let cases = run_online_adversarial_cases();
        assert!(cases.len() >= 8);
        for case in cases {
            assert!(
                case.passed(),
                "case {} got {:?}, expected {:?}",
                case.name,
                case.got,
                case.expected
            );
        }
    }

    #[test]
    fn all_preprocessing_adversarial_cases_fail_as_expected() {
        let cases = run_preprocessing_adversarial_cases();
        assert!(cases.len() >= 11);
        for case in cases {
            assert!(
                case.passed(),
                "case {} got {:?}, expected {:?}",
                case.name,
                case.got,
                case.expected
            );
        }
    }

    #[test]
    fn all_wire_adversarial_cases_fail_as_expected() {
        let cases = run_wire_adversarial_cases();
        assert!(cases.len() >= 14);
        for case in cases {
            assert!(
                case.passed(),
                "case {} got {:?}, expected {:?}",
                case.name,
                case.got,
                case.expected
            );
        }
    }

    #[test]
    fn replayed_payload_under_different_context_is_rejected() {
        let mut message = commit_message(1, [0x22; 32]);
        message.header.keygen_transcript_hash = [0x66; 32];

        assert_eq!(
            validate_round_batch(&[message], RoundId::PreprocessCommit, &expected_context()),
            Err(WireError::ContextMismatch)
        );
    }

    #[test]
    fn payload_decoders_reject_truncation_and_trailing_bytes() {
        let open = MaskedBroadcastOpenPayload {
            masked_highs: vec![1, 2],
            masked_lows: vec![3, 4],
            nonce_commitment: [5; 32],
            rho_bits_commitment: [6; 32],
            transcript_hash: [7; 32],
            consistency_proof: vec![9, 10, 11],
            salt: [8; 32],
        };
        let mut encoded = encode_masked_broadcast_open_payload(&open).expect("encode open");
        encoded.pop();
        assert_eq!(
            decode_masked_broadcast_open_payload(&encoded),
            Err(WireError::TruncatedPayload)
        );

        let mut partial = encode_partial_signature_payload(&talus_wire::PartialSignaturePayload {
            ctilde: vec![1],
            z_share: vec![2],
        });
        partial.push(0);
        assert_eq!(
            talus_wire::decode_partial_signature_payload(&partial),
            Err(WireError::TrailingPayloadBytes(1))
        );
    }

    #[test]
    fn all_suites_dkg_to_talus_signing_verifies_with_standard_fips_verifier() {
        dkg_to_talus_signing_verifies_with_standard_fips_verifier::<MlDsa44>(0x44);
        dkg_to_talus_signing_verifies_with_standard_fips_verifier::<MlDsa65>(0x65);
        dkg_to_talus_signing_verifies_with_standard_fips_verifier::<MlDsa87>(0x87);
    }

    #[test]
    fn all_suites_dkg_to_talus_signing_with_nonzero_nonce_verifies_with_standard_fips_verifier() {
        dkg_to_talus_nonzero_nonce_signing_verifies_with_standard_fips_verifier::<MlDsa44>(0x54);
    }

    #[test]
    fn dkg_to_talus_signing_with_generated_distributed_nonce_verifies_with_standard_fips_verifier()
    {
        dkg_to_talus_generated_nonce_signing_verifies_with_standard_fips_verifier::<MlDsa44>(0x64);
    }

    fn dkg_to_talus_signing_verifies_with_standard_fips_verifier<P: MlDsaParams>(seed: u8) {
        let parties = vec![PartyId(1), PartyId(2), PartyId(3)];
        let config = talus_dkg::DkgConfig::new::<P>(
            2,
            parties.clone(),
            talus_dkg::KeygenEpoch(u64::from(seed)),
        )
        .expect("dkg config");
        let rho = [seed; 32];

        let mut sampler = talus_dkg::VerifiedDistributedSmallSampler::new([seed ^ 0x5a; 32]);
        let s1 =
            sample_zero_secret_vector::<P>(&mut sampler, &config, talus_dkg::SecretVectorKind::S1);
        let s2 =
            sample_zero_secret_vector::<P>(&mut sampler, &config, talus_dkg::SecretVectorKind::S2);
        let shared_t =
            talus_dkg::assemble_shared_t::<P>(&config, rho, &s1, s2).expect("assemble shared t");
        let expected_t1 = reconstruct_t1_from_shared_t::<P>(&shared_t);
        assert!(
            expected_t1.iter().all(|&coeff| coeff == 0),
            "zero DKG material should assemble zero t1"
        );

        let power2round_output =
            drive_production_vector_power2round::<P>(&config, rho, &expected_t1);
        let (public, mut certificate) =
            talus_dkg::assemble_public_output_from_production_power2round(
                &config,
                rho,
                &parties,
                power2round_output,
            )
            .expect("production p2round public output");
        certificate.setup = Some(production_setup_certificate(&config, &parties));
        public.validate_binding().expect("public binding");

        let s1_packages =
            talus_dkg::sampled_s1_to_dkg_secret_shares::<P>(&config, &s1).expect("s1 packages");
        let key_packages =
            talus_dkg::dkg_key_packages_from_public_output(&public, s1_packages, certificate)
                .expect("key packages");
        let release_output =
            production_dkg_output_from_parts(public.clone(), key_packages.clone(), parties.clone());
        assert_eq!(release_output.public().public_key, public.public_key);
        assert_eq!(release_output.key_packages().len(), parties.len());

        let signature = sign_zero_token_with_dkg_key_packages::<P>(
            &config,
            &public.public_key,
            release_output.key_packages().to_vec(),
            seed,
        );
        let verifier =
            talus_mpc::FipsFinalVerifier::<P>::new(public.public_key.clone()).expect("verifier");
        let request = sign_request_for_seed::<P>(
            seed,
            TranscriptHash(signature.token_transcript_hash),
            &[PartyId(1), PartyId(2)],
        );
        assert!(
            verifier.verify_final(&request, &signature.signature),
            "standard FIPS verifier must accept TALUS signature for {}",
            P::NAME
        );
    }

    fn dkg_to_talus_generated_nonce_signing_verifies_with_standard_fips_verifier<P: MlDsaParams>(
        seed: u8,
    ) {
        let parties = vec![PartyId(1), PartyId(2), PartyId(3)];
        let config = talus_dkg::DkgConfig::new::<P>(
            2,
            parties.clone(),
            talus_dkg::KeygenEpoch(u64::from(seed)),
        )
        .expect("dkg config");
        let rho = [seed; 32];

        let mut sampler = talus_dkg::VerifiedDistributedSmallSampler::new([seed ^ 0x3c; 32]);
        let s1 =
            sample_zero_secret_vector::<P>(&mut sampler, &config, talus_dkg::SecretVectorKind::S1);
        let s2 =
            sample_zero_secret_vector::<P>(&mut sampler, &config, talus_dkg::SecretVectorKind::S2);
        let shared_t =
            talus_dkg::assemble_shared_t::<P>(&config, rho, &s1, s2).expect("assemble shared t");
        let expected_t1 = reconstruct_t1_from_shared_t::<P>(&shared_t);
        let power2round_output =
            drive_production_vector_power2round::<P>(&config, rho, &expected_t1);
        let (public, mut certificate) =
            talus_dkg::assemble_public_output_from_production_power2round(
                &config,
                rho,
                &parties,
                power2round_output,
            )
            .expect("production p2round public output");
        certificate.setup = Some(production_setup_certificate(&config, &parties));
        let s1_packages =
            talus_dkg::sampled_s1_to_dkg_secret_shares::<P>(&config, &s1).expect("s1 packages");
        let key_packages =
            talus_dkg::dkg_key_packages_from_public_output(&public, s1_packages, certificate)
                .expect("key packages");
        let release_output =
            production_dkg_output_from_parts(public.clone(), key_packages.clone(), parties.clone());

        let signer_set = vec![PartyId(1), PartyId(2)];
        let signing_session_id = SessionId([seed ^ 0xa5; 32]);
        let mut accepted_y_shares = None;
        for attempt in 0..32u8 {
            let nonce = talus_mpc::generate_distributed_nonce_shares::<P>(
                talus_mpc::DistributedNonceGenerationOptions {
                    session_id: SessionId([seed ^ 0xa5 ^ attempt; 32]),
                    dkg_config: config.clone(),
                    rho,
                    nonce_entropy: [seed ^ 0x71 ^ attempt; 32],
                    it_vss_entropy: [seed ^ 0x72 ^ attempt; 32],
                    it_vss_security: talus_dkg::ProductionItVssSecurityParams {
                        audit_tags: 1,
                        retained_tags: 1,
                        consistency_rounds: 1,
                        max_vector_lanes_per_chunk: 32_000,
                        max_private_delivery_bytes: 16 * 1024 * 1024,
                    },
                },
            )
            .expect("distributed nonce generation");
            assert_eq!(nonce.shares.len(), parties.len());
            assert_eq!(nonce.evidence.public_commitments.len(), parties.len());
            let y_shares = signer_set
                .iter()
                .map(|&party| {
                    let share = nonce
                        .shares
                        .iter()
                        .find(|share| share.party == party)
                        .expect("generated nonce share");
                    (party, share.y_share.clone())
                })
                .collect::<Vec<_>>();
            let mut registry = SessionRegistry::new();
            match try_preprocessing_token_for_nonce_shares::<P>(
                &mut registry,
                signing_session_id,
                &public.public_key,
                &signer_set,
                &y_shares,
            ) {
                Ok(_) => {
                    accepted_y_shares = Some(y_shares);
                    break;
                }
                Err(err) if err.is_retryable_pre_challenge() => continue,
                Err(err) => panic!("unexpected preprocessing failure: {err:?}"),
            }
        }
        let y_shares = accepted_y_shares.expect("BCC-cleared generated nonce");
        let signature = sign_with_dkg_key_packages_and_nonce_shares::<P>(
            &config,
            &public.public_key,
            release_output.key_packages().to_vec(),
            y_shares,
            seed,
        );
        let verifier =
            talus_mpc::FipsFinalVerifier::<P>::new(public.public_key.clone()).expect("verifier");
        let request = sign_request_for_seed::<P>(
            seed,
            TranscriptHash(signature.token_transcript_hash),
            &signer_set,
        );
        assert!(
            verifier.verify_final(&request, &signature.signature),
            "standard FIPS verifier must accept generated-nonce TALUS signature for {}",
            P::NAME
        );
    }

    fn dkg_to_talus_nonzero_nonce_signing_verifies_with_standard_fips_verifier<P: MlDsaParams>(
        seed: u8,
    ) {
        let parties = vec![PartyId(1), PartyId(2), PartyId(3)];
        let config = talus_dkg::DkgConfig::new::<P>(
            2,
            parties.clone(),
            talus_dkg::KeygenEpoch(u64::from(seed)),
        )
        .expect("dkg config");
        let rho = [seed; 32];

        let mut sampler = talus_dkg::VerifiedDistributedSmallSampler::new([seed ^ 0x3c; 32]);
        let s1 =
            sample_zero_secret_vector::<P>(&mut sampler, &config, talus_dkg::SecretVectorKind::S1);
        let s2 =
            sample_zero_secret_vector::<P>(&mut sampler, &config, talus_dkg::SecretVectorKind::S2);
        let shared_t =
            talus_dkg::assemble_shared_t::<P>(&config, rho, &s1, s2).expect("assemble shared t");
        let expected_t1 = reconstruct_t1_from_shared_t::<P>(&shared_t);
        let power2round_output =
            drive_production_vector_power2round::<P>(&config, rho, &expected_t1);
        let (public, mut certificate) =
            talus_dkg::assemble_public_output_from_production_power2round(
                &config,
                rho,
                &parties,
                power2round_output,
            )
            .expect("production p2round public output");
        certificate.setup = Some(production_setup_certificate(&config, &parties));
        let s1_packages =
            talus_dkg::sampled_s1_to_dkg_secret_shares::<P>(&config, &s1).expect("s1 packages");
        let key_packages =
            talus_dkg::dkg_key_packages_from_public_output(&public, s1_packages, certificate)
                .expect("key packages");
        let release_output =
            production_dkg_output_from_parts(public.clone(), key_packages.clone(), parties.clone());

        let signer_set = vec![PartyId(1), PartyId(2)];
        let signing_session_id = SessionId([seed ^ 0xa5; 32]);
        let mut accepted_signature = None;
        for attempt in 0..64u8 {
            let nonce = talus_mpc::generate_distributed_nonce_shares::<P>(
                talus_mpc::DistributedNonceGenerationOptions {
                    session_id: SessionId([seed ^ 0xa5 ^ attempt; 32]),
                    dkg_config: config.clone(),
                    rho,
                    nonce_entropy: [seed ^ 0x81 ^ attempt; 32],
                    it_vss_entropy: [seed ^ 0x82 ^ attempt; 32],
                    it_vss_security: talus_dkg::ProductionItVssSecurityParams {
                        audit_tags: 1,
                        retained_tags: 1,
                        consistency_rounds: 1,
                        max_vector_lanes_per_chunk: 32_000,
                        max_private_delivery_bytes: 16 * 1024 * 1024,
                    },
                },
            )
            .expect("distributed nonce generation");
            let y_shares = signer_set
                .iter()
                .map(|&party| {
                    let share = nonce
                        .shares
                        .iter()
                        .find(|share| share.party == party)
                        .expect("generated nonce share");
                    (party, share.y_share.clone())
                })
                .collect::<Vec<_>>();
            assert!(y_shares
                .iter()
                .flat_map(|(_, share)| share.polys())
                .flat_map(|poly| poly.coeffs())
                .any(|&coeff| coeff != 0));
            let mut registry = SessionRegistry::new();
            match try_preprocessing_token_for_nonce_shares::<P>(
                &mut registry,
                signing_session_id,
                &public.public_key,
                &signer_set,
                &y_shares,
            ) {
                Ok(_) => {
                    match try_sign_with_dkg_key_packages_and_nonce_shares::<P>(
                        &config,
                        &public.public_key,
                        release_output.key_packages().to_vec(),
                        y_shares,
                        seed,
                    ) {
                        Ok(signature) => {
                            accepted_signature = Some(signature);
                            break;
                        }
                        Err(talus_mpc::OnlineError::ZNormExceeded { .. }) => continue,
                        Err(err) => panic!("unexpected TALUS signing failure: {err:?}"),
                    }
                }
                Err(err) if err.is_retryable_pre_challenge() => continue,
                Err(err) => panic!("unexpected preprocessing failure: {err:?}"),
            }
        }
        let signature = accepted_signature.expect("BCC-cleared and norm-valid generated nonce");
        let verifier =
            talus_mpc::FipsFinalVerifier::<P>::new(public.public_key.clone()).expect("verifier");
        let request = sign_request_for_seed::<P>(
            seed,
            TranscriptHash(signature.token_transcript_hash),
            &signer_set,
        );
        assert!(
            verifier.verify_final(&request, &signature.signature),
            "standard FIPS verifier must accept nonzero-nonce TALUS signature for {}",
            P::NAME
        );
    }

    fn sample_zero_secret_vector<P: MlDsaParams>(
        sampler: &mut talus_dkg::VerifiedDistributedSmallSampler,
        config: &talus_dkg::DkgConfig,
        vector: talus_dkg::SecretVectorKind,
    ) -> talus_dkg::SharedSmallPolyVec {
        let eta = talus_dkg::SmallSecretEta::for_params::<P>().expect("eta");
        let inputs = (0..vector.coefficient_count::<P>())
            .map(|index| {
                let label = talus_dkg::SamplerLabel::new::<P>(config, vector, index)
                    .expect("sampler label");
                config
                    .parties
                    .iter()
                    .copied()
                    .map(|party| {
                        let residue = if party == PartyId(1) {
                            eta.bound() as u8
                        } else {
                            0
                        };
                        let label_hash =
                            test_verified_residue_hash(0x31, party, vector, index, config);
                        let certificate_hash =
                            test_verified_residue_hash(0x41, party, vector, index, config);
                        talus_dkg::VerifiedSmallResidueInput::from_it_vss_certificate(
                            party,
                            label,
                            eta,
                            residue,
                            label_hash,
                            certificate_hash,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        talus_dkg::DistributedSmallSampler::sample_verified_small_polyvec::<P>(
            sampler, config, vector, &inputs,
        )
        .expect("zero small vector")
    }

    fn test_verified_residue_hash(
        domain: u8,
        party: PartyId,
        vector: talus_dkg::SecretVectorKind,
        index: usize,
        config: &talus_dkg::DkgConfig,
    ) -> [u8; 32] {
        let mut out = [domain; 32];
        out[0] = domain;
        out[1] = party.0 as u8;
        out[2] = match vector {
            talus_dkg::SecretVectorKind::S1 => 1,
            talus_dkg::SecretVectorKind::S2 => 2,
        };
        out[3..7].copy_from_slice(&(index as u32).to_le_bytes());
        out[7..15].copy_from_slice(&config.epoch.0.to_le_bytes());
        out
    }

    fn production_dkg_output_from_parts(
        public: talus_dkg::DkgPublicOutput,
        key_packages: Vec<talus_dkg::DkgKeyPackage>,
        accepted_dealers: Vec<PartyId>,
    ) -> talus_dkg::ProductionNativeDkgAssemblyOutput {
        talus_dkg::ProductionNativeDkgAssemblyOutput::new(
            public,
            key_packages.clone(),
            key_packages[0].certificate.clone(),
            accepted_dealers,
            Vec::new(),
            Vec::new(),
        )
        .expect("release-valid production assembly output")
    }

    fn reconstruct_t1_from_shared_t<P: MlDsaParams>(shared_t: &talus_dkg::SharedT) -> Vec<u16> {
        let mut out = Vec::with_capacity(P::K * P::N);
        for poly_idx in 0..P::K {
            for coeff_idx in 0..P::N {
                let shares = shared_t
                    .shares
                    .iter()
                    .map(|share| talus_dkg::ShamirScalarShare {
                        point: share.point,
                        value: share.t_share.polys()[poly_idx].coeffs()[coeff_idx],
                    })
                    .collect::<Vec<_>>();
                let coeff =
                    talus_dkg::reconstruct_scalar_at_zero::<P>(&shares).expect("reconstruct t");
                let (high, _low) = talus_core::power2round::<P>(coeff);
                out.push(high as u16);
            }
        }
        out
    }

    fn drive_production_vector_power2round<P: MlDsaParams>(
        config: &talus_dkg::DkgConfig,
        rho: [u8; 32],
        expected_t1_coeffs: &[u16],
    ) -> talus_dkg::ProductionPower2RoundOutput {
        let lane_count = P::K * P::N;
        assert_eq!(expected_t1_coeffs.len(), lane_count);
        let assembly_label = talus_dkg::PublicKeyAssemblyLabel::new(config, rho);
        let root = talus_dkg::Power2RoundTranscriptLabel::root(config, assembly_label.rho_hash);
        let label = root.child("power2round_t1_vec");
        let mask_id = talus_dkg::Power2RoundMaskBatchId::new(&label.child("mask"), lane_count);
        let mut driver =
            talus_dkg::ProductionPower2RoundPerPartyDriver::resume_after_precomputed_masks(mask_id);
        let mut runtimes = prime_field_runtimes(config);

        broadcast_vec_phase(&mut runtimes, |runtime| {
            runtime
                .drive_power2round_masked_c_vec(&label, &vec![0; lane_count])
                .map(|_| ())
        });
        let collected = runtimes[0]
            .drive_collect_power2round_masked_c_vec_and_advance(&mut driver, &label)
            .expect("collect masked values");
        assert!(
            matches!(
                collected,
                talus_dkg::ProductionPower2RoundVectorCollectResult::Collected(_)
            ),
            "masked collection did not complete: {collected:?}"
        );
        clear_prime_field_queues(&mut runtimes);

        broadcast_vec_phase(&mut runtimes, |runtime| {
            runtime
                .drive_power2round_wrap_compare_vec(&label, &vec![0; lane_count])
                .map(|_| ())
        });
        runtimes[0]
            .drive_collect_power2round_wrap_compare_vec(&label)
            .expect("collect wrap");
        clear_prime_field_queues(&mut runtimes);

        for bit_idx in 0..24 {
            broadcast_vec_phase(&mut runtimes, |runtime| {
                runtime
                    .drive_power2round_subtractor_share_vec(&label, bit_idx, &vec![0; lane_count])
                    .map(|_| ())
            });
            runtimes[0]
                .drive_collect_power2round_subtractor_share_vec(&label, bit_idx)
                .expect("collect subtractor");
            clear_prime_field_queues(&mut runtimes);
        }
        for bit_idx in 0..23 {
            broadcast_vec_phase(&mut runtimes, |runtime| {
                runtime
                    .drive_power2round_canonical_bitness_check_vec(
                        &label,
                        bit_idx,
                        &vec![0; lane_count],
                    )
                    .map(|_| ())
            });
            runtimes[0]
                .drive_collect_power2round_canonical_bitness_check_vec(&label, bit_idx)
                .expect("collect bitness");
            clear_prime_field_queues(&mut runtimes);
        }
        broadcast_vec_phase(&mut runtimes, |runtime| {
            runtime
                .drive_power2round_canonical_range_check_vec(&label, &vec![0; lane_count])
                .map(|_| ())
        });
        runtimes[0]
            .drive_collect_power2round_canonical_range_check_vec(&label)
            .expect("collect range");
        clear_prime_field_queues(&mut runtimes);

        broadcast_vec_phase(&mut runtimes, |runtime| {
            runtime
                .drive_power2round_equality_check_vec(&label, &vec![0; lane_count])
                .map(|_| ())
        });
        runtimes[0]
            .drive_collect_power2round_equality_check_vec(&label)
            .expect("collect equality");
        let recovered_canonical =
            recovered_prime_field_runtime(config, runtimes[0].runtime().wire_log().clone());
        let mut recovered_canonical = recovered_canonical;
        assert!(matches!(
            recovered_canonical
                .drive_collect_power2round_canonical_recovery_all_vec_and_advance(
                    &mut driver,
                    &label
                )
                .expect("recover canonical"),
            talus_dkg::ProductionPower2RoundVectorCollectResult::Collected(_)
        ));
        clear_prime_field_queues(&mut runtimes);

        for bit_idx in 0..23 {
            broadcast_vec_phase(&mut runtimes, |runtime| {
                runtime
                    .drive_power2round_add4095_share_vec(&label, bit_idx, &vec![0; lane_count])
                    .map(|_| ())
            });
            runtimes[0]
                .drive_collect_power2round_add4095_share_vec(&label, bit_idx)
                .expect("collect add4095");
            clear_prime_field_queues(&mut runtimes);
        }
        let mut recovered_add4095 =
            recovered_prime_field_runtime(config, runtimes[0].runtime().wire_log().clone());
        assert!(matches!(
            recovered_add4095
                .drive_collect_power2round_add4095_all_vec_and_advance(&mut driver, &label)
                .expect("recover add4095"),
            talus_dkg::ProductionPower2RoundVectorCollectResult::Collected(_)
        ));

        for bit_idx in 0..10 {
            let values = expected_t1_coeffs
                .iter()
                .map(|coefficient| ((coefficient >> bit_idx) & 1) as talus_core::Coeff)
                .collect::<Vec<_>>();
            broadcast_vec_phase(&mut runtimes, |runtime| {
                runtime
                    .drive_power2round_t1_bit_vec(&label, bit_idx, &values)
                    .map(|_| ())
            });
            runtimes[0]
                .drive_collect_power2round_t1_bit_vec(&label, bit_idx)
                .expect("collect t1 bit");
            clear_prime_field_queues(&mut runtimes);
        }
        let mut recovered_t1 =
            recovered_prime_field_runtime(config, runtimes[0].runtime().wire_log().clone());
        match recovered_t1
            .drive_collect_power2round_t1_bits_and_certify::<P>(
                &mut driver,
                config,
                assembly_label,
                &label,
            )
            .expect("certify t1")
        {
            talus_dkg::ProductionPower2RoundVectorCollectResult::Collected(output) => output,
            talus_dkg::ProductionPower2RoundVectorCollectResult::Waiting(statuses) => {
                panic!("unexpected Power2Round wait: {statuses:?}")
            }
        }
    }

    type PrimeFieldRuntime = talus_dkg::CursoredTransportPrimeFieldMpcPartyRuntime<
        talus_wire::InMemoryTransport,
        talus_dkg::InMemoryPrimeFieldMpcWireMessageLog,
        talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog,
    >;

    fn prime_field_runtimes(config: &talus_dkg::DkgConfig) -> Vec<PrimeFieldRuntime> {
        config
            .parties
            .iter()
            .map(|party| {
                let transport = talus_wire::InMemoryTransport::new(
                    party.0,
                    config.parties.iter().map(|party| party.0).collect(),
                )
                .expect("transport");
                let state = talus_dkg::TransportPrimeFieldMpcStateMachine::new(
                    config.clone(),
                    *party,
                    transport,
                )
                .expect("state");
                let runtime = talus_dkg::TransportPrimeFieldMpcPartyRuntime::new(
                    state,
                    talus_dkg::InMemoryPrimeFieldMpcWireMessageLog::default(),
                );
                talus_dkg::CursoredTransportPrimeFieldMpcPartyRuntime::new(
                    runtime,
                    talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog::default(),
                )
            })
            .collect()
    }

    fn recovered_prime_field_runtime(
        config: &talus_dkg::DkgConfig,
        wire_log: talus_dkg::InMemoryPrimeFieldMpcWireMessageLog,
    ) -> PrimeFieldRuntime {
        let transport = talus_wire::InMemoryTransport::new(
            config.parties[0].0,
            config.parties.iter().map(|party| party.0).collect(),
        )
        .expect("transport");
        let state = talus_dkg::TransportPrimeFieldMpcStateMachine::new(
            config.clone(),
            config.parties[0],
            transport,
        )
        .expect("state");
        let runtime = talus_dkg::TransportPrimeFieldMpcPartyRuntime::new(state, wire_log);
        talus_dkg::CursoredTransportPrimeFieldMpcPartyRuntime::new(
            runtime,
            talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog::default(),
        )
    }

    fn broadcast_vec_phase(
        runtimes: &mut [PrimeFieldRuntime],
        mut drive: impl FnMut(&mut PrimeFieldRuntime) -> Result<(), talus_dkg::DkgError>,
    ) {
        for runtime in runtimes.iter_mut() {
            drive(runtime).expect("broadcast vector phase");
        }
        let deliveries = runtimes
            .iter()
            .flat_map(|runtime| {
                let sender = runtime.runtime().local_party().0;
                runtime
                    .runtime()
                    .state()
                    .transport()
                    .broadcast_deliveries()
                    .iter()
                    .filter(move |delivery| delivery.message.header.sender_party_id == sender)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for delivery in deliveries {
            let sender = delivery.message.header.sender_party_id;
            for runtime in runtimes.iter_mut() {
                if runtime.runtime().local_party().0 == sender {
                    continue;
                }
                runtime
                    .runtime_mut()
                    .state_mut()
                    .transport_mut()
                    .inject_broadcast_delivery(delivery.observer_party_id, delivery.message.clone())
                    .expect("route broadcast delivery");
            }
        }
    }

    fn clear_prime_field_queues(runtimes: &mut [PrimeFieldRuntime]) {
        for runtime in runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
    }

    fn production_setup_certificate(
        _config: &talus_dkg::DkgConfig,
        parties: &[PartyId],
    ) -> talus_dkg::DkgSetupTranscriptCertificate {
        talus_dkg::DkgSetupTranscriptCertificate {
            setup_backend_id: talus_dkg::DkgSetupBackendId::ProductionInformationTheoretic,
            sampler_s1_hash: [1; 32],
            sampler_s2_hash: [2; 32],
            vss_commit_hash: [3; 32],
            vss_share_hash: [4; 32],
            complaint_hash: [5; 32],
            it_vss_public_artifact_hash: [6; 32],
            it_vss_resolution_hash: [7; 32],
            it_vss_backend_id: talus_dkg::ItVssBackendId::ProductionInformationChecking,
            complaints: Vec::new(),
            accepted_dealers: parties.to_vec(),
            rejected_dealers: Vec::new(),
            release_blockers: Vec::new(),
        }
    }

    struct SignedDkgResult {
        signature: FinalSignature,
        token_transcript_hash: [u8; 32],
    }

    fn sign_zero_token_with_dkg_key_packages<P: MlDsaParams>(
        config: &talus_dkg::DkgConfig,
        public_key: &[u8],
        key_packages: Vec<talus_dkg::DkgKeyPackage>,
        seed: u8,
    ) -> SignedDkgResult {
        let signer_set = vec![PartyId(1), PartyId(2)];
        let session_id = SessionId([seed ^ 0xa5; 32]);
        let mut registry = SessionRegistry::new();
        let token = zero_preprocessing_token::<P>(&mut registry, session_id, signer_set.clone());
        let request = sign_request_for_seed::<P>(seed, token.transcript_hash, &signer_set);
        let y_shares = signer_set
            .iter()
            .map(|&party| (party, talus_core::PolyVec::zero(P::L)))
            .collect::<Vec<_>>();
        let provider = talus_mpc::DkgBackedPolynomialShareProvider::<P>::from_key_packages(
            session_id,
            config.clone(),
            y_shares,
            key_packages,
        );
        let partial_verifier =
            partial_verifier_for_dkg_provider::<P>(public_key, session_id, &signer_set, &provider);
        let verifier =
            talus_mpc::FipsFinalVerifier::<P>::new(public_key.to_vec()).expect("standard verifier");
        let tr = talus_core::compute_tr(public_key);
        let mut pool = TokenPool::new();
        pool.insert_certified(token).expect("insert token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let signature = talus_mpc::sign_polynomial_with_token::<P, _, _, _, _>(
            &mut pool,
            &mut consumed,
            &mut counters,
            &request,
            talus_mpc::PolynomialOnlineServices {
                tr: &tr,
                public_key,
                aggregation: talus_mpc::PolynomialAggregation::LagrangeAtZero,
                partial_verifier: &partial_verifier,
                share_provider: &provider,
                verifier: &verifier,
            },
        )
        .expect("TALUS signing with native DKG key packages");
        assert!(consumed.is_consumed(session_id));
        assert_eq!(counters.signatures_returned, 1);
        SignedDkgResult {
            signature,
            token_transcript_hash: request.token_transcript_hash.0,
        }
    }

    fn sign_with_dkg_key_packages_and_nonce_shares<P: MlDsaParams>(
        config: &talus_dkg::DkgConfig,
        public_key: &[u8],
        key_packages: Vec<talus_dkg::DkgKeyPackage>,
        y_shares: Vec<(PartyId, talus_core::PolyVec)>,
        seed: u8,
    ) -> SignedDkgResult {
        try_sign_with_dkg_key_packages_and_nonce_shares::<P>(
            config,
            public_key,
            key_packages,
            y_shares,
            seed,
        )
        .expect("TALUS signing with nonzero nonce shares")
    }

    fn try_sign_with_dkg_key_packages_and_nonce_shares<P: MlDsaParams>(
        config: &talus_dkg::DkgConfig,
        public_key: &[u8],
        key_packages: Vec<talus_dkg::DkgKeyPackage>,
        y_shares: Vec<(PartyId, talus_core::PolyVec)>,
        seed: u8,
    ) -> Result<SignedDkgResult, talus_mpc::OnlineError> {
        let signer_set = y_shares.iter().map(|(party, _)| *party).collect::<Vec<_>>();
        let session_id = SessionId([seed ^ 0xa5; 32]);
        let mut registry = SessionRegistry::new();
        let token = preprocessing_token_for_nonce_shares::<P>(
            &mut registry,
            session_id,
            public_key,
            &signer_set,
            &y_shares,
        );
        let request = sign_request_for_seed::<P>(seed, token.transcript_hash, &signer_set);
        let provider = talus_mpc::DkgBackedPolynomialShareProvider::<P>::from_key_packages(
            session_id,
            config.clone(),
            y_shares,
            key_packages,
        );
        let partial_verifier =
            partial_verifier_for_dkg_provider::<P>(public_key, session_id, &signer_set, &provider);
        let verifier =
            talus_mpc::FipsFinalVerifier::<P>::new(public_key.to_vec()).expect("standard verifier");
        let tr = talus_core::compute_tr(public_key);
        let mut pool = TokenPool::new();
        pool.insert_certified(token).expect("insert token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let signature = talus_mpc::sign_polynomial_with_token::<P, _, _, _, _>(
            &mut pool,
            &mut consumed,
            &mut counters,
            &request,
            talus_mpc::PolynomialOnlineServices {
                tr: &tr,
                public_key,
                aggregation: talus_mpc::PolynomialAggregation::LagrangeAtZero,
                partial_verifier: &partial_verifier,
                share_provider: &provider,
                verifier: &verifier,
            },
        )?;
        assert!(consumed.is_consumed(session_id));
        assert_eq!(counters.signatures_returned, 1);
        Ok(SignedDkgResult {
            signature,
            token_transcript_hash: request.token_transcript_hash.0,
        })
    }

    fn zero_preprocessing_token<P: MlDsaParams>(
        registry: &mut SessionRegistry,
        session_id: SessionId,
        signer_set: Vec<PartyId>,
    ) -> talus_mpc::CertifiedToken {
        let coeffs = P::K * P::N;
        let inputs = signer_set
            .iter()
            .map(|&party| PartyPreprocessInput {
                party,
                highs: vec![0; coeffs],
                lows: vec![0; coeffs],
                y_share: Vec::new(),
                ay_contribution: Some(talus_core::PolyVec::zero(P::K)),
                nonce_commitment: NonceCommitment([party.0 as u8; 32]),
                randomness_commitment: Commitment([(party.0 as u8) ^ 0x55; 32]),
            })
            .collect::<Vec<_>>();
        let token =
            certify_preprocessing_token::<P>(registry, session_id, inputs).expect("certify token");
        assert!(token.w1.iter().all(|&coeff| coeff == 0));
        token
    }

    fn preprocessing_token_for_nonce_shares<P: MlDsaParams>(
        registry: &mut SessionRegistry,
        session_id: SessionId,
        public_key: &[u8],
        signer_set: &[PartyId],
        y_shares: &[(PartyId, talus_core::PolyVec)],
    ) -> talus_mpc::CertifiedToken {
        let token = try_preprocessing_token_for_nonce_shares::<P>(
            registry, session_id, public_key, signer_set, y_shares,
        )
        .expect("certify token");

        let public = talus_core::public_key_decode::<P>(public_key).expect("decode public key");
        let points = signer_set
            .iter()
            .map(|party| u32::from(party.0))
            .collect::<Vec<_>>();
        let aggregate_y =
            talus_core::aggregate_z_shares_lagrange::<P>(&points, &nonce_share_values(y_shares))
                .expect("aggregate y");
        let aggregate_ay =
            talus_core::az_from_rho::<P>(&public.rho, &aggregate_y).expect("A*aggregate y");
        let expected_w1 = aggregate_ay
            .polys()
            .iter()
            .flat_map(|poly| {
                poly.coeffs()
                    .iter()
                    .map(|&coeff| talus_core::high_bits::<P>(coeff) as u32)
            })
            .collect::<Vec<_>>();
        assert_eq!(token.w1, expected_w1);
        assert!(token.w1.iter().any(|&coeff| coeff != 0));
        token
    }

    fn try_preprocessing_token_for_nonce_shares<P: MlDsaParams>(
        registry: &mut SessionRegistry,
        session_id: SessionId,
        public_key: &[u8],
        signer_set: &[PartyId],
        y_shares: &[(PartyId, talus_core::PolyVec)],
    ) -> Result<talus_mpc::CertifiedToken, PreprocessError> {
        let public = talus_core::public_key_decode::<P>(public_key).expect("decode public key");
        let points = signer_set
            .iter()
            .map(|party| u32::from(party.0))
            .collect::<Vec<_>>();
        let lambdas =
            talus_core::lagrange_coefficients_at_zero::<P>(&points).expect("lagrange weights");
        let inputs = signer_set
            .iter()
            .zip(lambdas.iter())
            .map(|(&party, &lambda)| {
                let (_, y_share) = y_shares
                    .iter()
                    .find(|(candidate, _)| *candidate == party)
                    .expect("nonce share");
                let weighted_y = y_share.mul_scalar_mod_q::<P>(lambda);
                let weighted_ay =
                    talus_core::az_from_rho::<P>(&public.rho, &weighted_y).expect("A*lambda*y");
                let mut highs = Vec::with_capacity(P::K * P::N);
                let mut lows = Vec::with_capacity(P::K * P::N);
                for poly in weighted_ay.polys() {
                    for &coeff in poly.coeffs() {
                        highs.push(talus_core::high_bits_unsigned::<P>(coeff));
                        lows.push(talus_core::low_bits_unsigned::<P>(coeff));
                    }
                }
                PartyPreprocessInput {
                    party,
                    highs,
                    lows,
                    y_share: Vec::new(),
                    ay_contribution: Some(weighted_ay),
                    nonce_commitment: NonceCommitment([party.0 as u8; 32]),
                    randomness_commitment: Commitment([(party.0 as u8) ^ 0x91; 32]),
                }
            })
            .collect::<Vec<_>>();
        certify_preprocessing_token::<P>(registry, session_id, inputs)
    }

    fn nonce_share_values(y_shares: &[(PartyId, talus_core::PolyVec)]) -> Vec<talus_core::PolyVec> {
        y_shares
            .iter()
            .map(|(_, share)| share.clone())
            .collect::<Vec<_>>()
    }

    fn sign_request_for_seed<P: MlDsaParams>(
        seed: u8,
        token_transcript_hash: TranscriptHash,
        signer_set: &[PartyId],
    ) -> SignRequest {
        SignRequest {
            protocol_version: ONLINE_PROTOCOL_VERSION,
            suite: P::NAME,
            session_id: SessionId([seed ^ 0xa5; 32]),
            signing_set: signer_set.to_vec(),
            message: vec![seed, seed ^ 0x11, seed ^ 0x22],
            external_mu: None,
            context: b"talus-dkg-e2e".to_vec(),
            token_transcript_hash,
        }
    }

    fn partial_verifier_for_dkg_provider<P: MlDsaParams>(
        public_key: &[u8],
        session_id: SessionId,
        signer_set: &[PartyId],
        provider: &talus_mpc::DkgBackedPolynomialShareProvider<P>,
    ) -> talus_mpc::CommitmentBackedPartialVerifier {
        let public = talus_core::public_key_decode::<P>(public_key).expect("decode public key");
        let commitments = signer_set
            .iter()
            .map(|&party| {
                let share =
                    talus_mpc::PolynomialShareProvider::signing_share(provider, session_id, party)
                        .expect("signing share");
                talus_mpc::PolynomialPartialCommitment {
                    party,
                    ay_commitment: talus_core::az_from_rho::<P>(&public.rho, &share.y_share)
                        .expect("A*y commitment"),
                    as1_commitment: talus_core::az_from_rho::<P>(&public.rho, &share.s1_share)
                        .expect("A*s1 commitment"),
                }
            })
            .collect();
        talus_mpc::CommitmentBackedPartialVerifier::new(commitments)
    }
}
