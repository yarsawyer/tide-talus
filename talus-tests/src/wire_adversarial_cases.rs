use crate::WireAdversarialCase;
use talus_wire::{
    decode_commit_payload, decode_final_signature_payload, decode_message,
    decode_sign_request_payload, encode_commit_payload, encode_final_signature_payload,
    encode_masked_broadcast_open_payload, encode_message, encode_sign_request_payload,
    signing_set_hash, validate_round_batch, CommitPayload, ExpectedContext, FinalSignaturePayload,
    MaskedBroadcastOpenPayload, PayloadKind, RoundId, SignRequestPayload, SuiteId, WireError,
    WireHeader, WireMessage, WIRE_PROTOCOL_VERSION,
};

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

pub(crate) fn expected_context() -> ExpectedContext {
    ExpectedContext {
        suite: SuiteId::MlDsa65,
        keygen_transcript_hash: [0x11; 32],
        session_id: [0x22; 32],
        signing_set_hash: signing_set_hash(&[1, 2, 3]),
        allowed_parties: vec![1, 2, 3],
    }
}

pub(crate) fn header(
    sender: u16,
    session_id: [u8; 32],
    round: RoundId,
    kind: PayloadKind,
) -> WireHeader {
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

pub(crate) fn commit_message(sender: u16, session_id: [u8; 32]) -> WireMessage {
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

pub(crate) fn partial_message(sender: u16) -> WireMessage {
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
