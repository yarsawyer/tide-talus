use crate::commit_message;
use crate::wire_adversarial_cases::expected_context;
use talus_wire::dev_backends::{
    decode_partial_signature_payload, encode_partial_signature_payload, PartialSignaturePayload,
};
use talus_wire::{
    decode_masked_broadcast_open_payload, encode_masked_broadcast_open_payload,
    validate_round_batch, MaskedBroadcastOpenPayload, RoundId, WireError,
};

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

    let mut partial = encode_partial_signature_payload(&PartialSignaturePayload {
        ctilde: vec![1],
        z_share: vec![2],
    });
    partial.push(0);
    assert_eq!(
        decode_partial_signature_payload(&partial),
        Err(WireError::TrailingPayloadBytes(1))
    );
}
