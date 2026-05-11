use crate::{PreprocessingAdversarialCase, PreprocessingAdversarialOutcome};
use talus_core::{MlDsa65, MlDsaParams};
use talus_mpc::{
    certify_preprocessing_token, masked_broadcast_commitment, open_broadcasts, BroadcastEnvelope,
    Commitment, MaskedBroadcastConsistencyProof, NonceCommitment, PartyPreprocessInput,
    PreprocessError, SessionId, SessionRegistry, TokenCandidate, TokenPool, TokenPoolError,
    TranscriptHash,
};
use talus_mpc_core::PartyId;

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
