use crate::{commit_message, header, partial_message, DeterministicPropertyCase};
use talus_core::{
    cef_w1_clear_coeff, cef_w1_coeff, signature_encoded_len, MlDsa44, MlDsa65, MlDsa87, MlDsaParams,
};
use talus_wire::dev_backends::{
    decode_partial_signature_payload, encode_partial_signature_payload, PartialSignaturePayload,
};
use talus_wire::{
    decode_commit_payload, decode_final_signature_payload, decode_message,
    decode_sign_request_payload, encode_commit_payload, encode_final_signature_payload,
    encode_masked_broadcast_open_payload, encode_message, encode_sign_request_payload,
    signing_set_hash, CommitPayload, FinalSignaturePayload, MaskedBroadcastOpenPayload,
    PayloadKind, RoundId, SignRequestPayload, WireMessage,
};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PayloadCodec {
    Commit,
    SignRequest,
    Partial,
    Final,
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
