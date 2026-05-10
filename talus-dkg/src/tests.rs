use super::dev_backends::*;
use super::*;
use talus_core::{MlDsa44, MlDsa65, MlDsa87};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TinyMlDsa44;

impl MlDsaParams for TinyMlDsa44 {
    const NAME: &'static str = "ML-DSA-44";
    const N: usize = 2;
    const K: usize = 1;
    const L: usize = 1;
    const ETA: i32 = <MlDsa44 as MlDsaParams>::ETA;
    const TAU: usize = <MlDsa44 as MlDsaParams>::TAU;
    const LAMBDA: usize = <MlDsa44 as MlDsaParams>::LAMBDA;
    const BETA: i32 = <MlDsa44 as MlDsaParams>::BETA;
    const GAMMA1: i32 = <MlDsa44 as MlDsaParams>::GAMMA1;
    const GAMMA2: i32 = <MlDsa44 as MlDsaParams>::GAMMA2;
    const OMEGA: usize = <MlDsa44 as MlDsaParams>::OMEGA;
    const CTILDE_LEN: usize = <MlDsa44 as MlDsaParams>::CTILDE_LEN;
    const PK_LEN: usize = <MlDsa44 as MlDsaParams>::PK_LEN;
    const SIG_LEN: usize = <MlDsa44 as MlDsaParams>::SIG_LEN;
    const HIGH_MOD: i32 = <MlDsa44 as MlDsaParams>::HIGH_MOD;
}

fn parties(values: &[u16]) -> Vec<PartyId> {
    values.iter().copied().map(PartyId).collect()
}

fn config() -> DkgConfig {
    DkgConfig::new::<MlDsa65>(2, parties(&[1, 2, 3]), KeygenEpoch(7))
        .expect("valid DKG test config")
}

fn config_for<P: MlDsaParams>() -> DkgConfig {
    DkgConfig::new::<P>(2, parties(&[1, 2, 3]), KeygenEpoch(7)).expect("valid DKG test config")
}

fn config4_for<P: MlDsaParams>() -> DkgConfig {
    DkgConfig::new::<P>(2, parties(&[1, 2, 3, 4]), KeygenEpoch(7))
        .expect("valid 4-party DKG test config")
}

type TestPartyRuntime = TransportPrimeFieldMpcPartyRuntime<
    talus_wire::InMemoryTransport,
    InMemoryPrimeFieldMpcWireMessageLog,
>;
type TestCursoredPrimeFieldRuntime = CursoredTransportPrimeFieldMpcPartyRuntime<
    talus_wire::InMemoryTransport,
    InMemoryPrimeFieldMpcWireMessageLog,
    InMemoryPrimeFieldMpcPhaseCursorLog,
>;

fn test_party_runtimes(config: &DkgConfig) -> Vec<TestPartyRuntime> {
    let party_ids = config
        .parties
        .iter()
        .map(|party| party.0)
        .collect::<Vec<_>>();
    config
        .parties
        .iter()
        .map(|&party| {
            let transport = talus_wire::InMemoryTransport::new(party.0, party_ids.clone())
                .expect("in-memory transport");
            let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), party, transport)
                .expect("state machine");
            TransportPrimeFieldMpcPartyRuntime::new(
                state,
                InMemoryPrimeFieldMpcWireMessageLog::default(),
            )
        })
        .collect()
}

fn route_private_messages(
    runtimes: &mut [TestPartyRuntime],
    source_indices: impl IntoIterator<Item = usize>,
    reverse: bool,
    duplicate_first: bool,
) {
    let mut deliveries = Vec::new();
    for source_idx in source_indices {
        let local_party = runtimes[source_idx].local_party().0;
        deliveries.extend(
            runtimes[source_idx]
                .state()
                .transport()
                .private_messages()
                .iter()
                .filter(|delivery| delivery.sender_party_id == local_party)
                .cloned(),
        );
    }
    if reverse {
        deliveries.reverse();
    }
    if duplicate_first {
        if let Some(first) = deliveries.first().cloned() {
            deliveries.push(first);
        }
    }
    for delivery in deliveries {
        let receiver_idx = runtimes
            .iter()
            .position(|runtime| runtime.local_party().0 == delivery.receiver_party_id)
            .expect("receiver runtime");
        if runtimes[receiver_idx].local_party().0 == delivery.sender_party_id {
            continue;
        }
        runtimes[receiver_idx]
            .state_mut()
            .transport_mut()
            .inject_private(
                delivery.sender_party_id,
                delivery.receiver_party_id,
                delivery.message,
            )
            .expect("route private message");
    }
}

fn route_broadcast_messages(
    runtimes: &mut [TestPartyRuntime],
    source_indices: impl IntoIterator<Item = usize>,
    omit_last_delivery: bool,
    equivocate_sender: Option<u16>,
) {
    let mut deliveries = Vec::new();
    for source_idx in source_indices {
        let local_party = runtimes[source_idx].local_party().0;
        deliveries.extend(
            runtimes[source_idx]
                .state()
                .transport()
                .broadcast_deliveries()
                .iter()
                .filter(|delivery| delivery.message.header.sender_party_id == local_party)
                .cloned(),
        );
    }
    if omit_last_delivery {
        deliveries.pop();
    }
    for mut delivery in deliveries {
        if Some(delivery.message.header.sender_party_id) == equivocate_sender
            && delivery.observer_party_id == 3
        {
            let mut payload =
                decode_dkg_prime_field_mpc_payload(&delivery.message.payload).expect("mpc payload");
            payload.value = payload.value.wrapping_add(1);
            delivery.message.payload = encode_dkg_prime_field_mpc_payload(&payload);
        }
        for runtime in runtimes.iter_mut() {
            if runtime.local_party().0 == delivery.message.header.sender_party_id {
                continue;
            }
            runtime
                .state_mut()
                .transport_mut()
                .inject_broadcast_delivery(delivery.observer_party_id, delivery.message.clone())
                .expect("route broadcast message");
        }
    }
}

fn route_cursored_prime_field_broadcast_messages(
    runtimes: &mut [TestCursoredPrimeFieldRuntime],
    source_indices: impl IntoIterator<Item = usize>,
    routed_count: &mut usize,
) {
    let mut deliveries = Vec::new();
    for source_idx in source_indices {
        let local_party = runtimes[source_idx].runtime().local_party().0;
        deliveries.extend(
            runtimes[source_idx]
                .runtime()
                .state()
                .transport()
                .broadcast_deliveries()
                .iter()
                .filter(|delivery| delivery.message.header.sender_party_id == local_party)
                .cloned(),
        );
    }
    for delivery in deliveries.into_iter().skip(*routed_count) {
        *routed_count += 1;
        for runtime in runtimes.iter_mut() {
            if runtime.runtime().local_party().0 == delivery.message.header.sender_party_id {
                continue;
            }
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .inject_broadcast_delivery(delivery.observer_party_id, delivery.message.clone())
                .expect("route cursored prime-field broadcast message");
        }
    }
}

type TestDkgTransportRuntime = DkgTransportPartyRuntime<talus_wire::InMemoryTransport>;
type TestLoggedDkgTransportRuntime =
    LoggedDkgTransportPartyRuntime<talus_wire::InMemoryTransport, InMemoryDkgWireMessageLog>;
type TestCursoredLoggedDkgTransportRuntime = CursoredLoggedDkgTransportPartyRuntime<
    talus_wire::InMemoryTransport,
    InMemoryDkgWireMessageLog,
    InMemoryDkgSetupPhaseCursorLog,
>;

fn test_dkg_transport_runtimes(config: &DkgConfig) -> Vec<TestDkgTransportRuntime> {
    let party_ids = config
        .parties
        .iter()
        .map(|party| party.0)
        .collect::<Vec<_>>();
    config
        .parties
        .iter()
        .map(|&party| {
            let transport = talus_wire::InMemoryTransport::new(party.0, party_ids.clone())
                .expect("in-memory transport");
            let state = DkgTransportStateMachine::new(config.clone(), party, transport)
                .expect("dkg transport state");
            DkgTransportPartyRuntime::new(state)
        })
        .collect()
}

fn test_logged_dkg_transport_runtimes(config: &DkgConfig) -> Vec<TestLoggedDkgTransportRuntime> {
    let party_ids = config
        .parties
        .iter()
        .map(|party| party.0)
        .collect::<Vec<_>>();
    config
        .parties
        .iter()
        .map(|&party| {
            let transport = talus_wire::InMemoryTransport::new(party.0, party_ids.clone())
                .expect("in-memory transport");
            let state = DkgTransportStateMachine::new(config.clone(), party, transport)
                .expect("dkg transport state");
            LoggedDkgTransportPartyRuntime::new(state, InMemoryDkgWireMessageLog::default())
        })
        .collect()
}

fn test_cursored_logged_dkg_transport_runtimes(
    config: &DkgConfig,
) -> Vec<TestCursoredLoggedDkgTransportRuntime> {
    test_logged_dkg_transport_runtimes(config)
        .into_iter()
        .map(|runtime| {
            CursoredLoggedDkgTransportPartyRuntime::new(
                runtime,
                InMemoryDkgSetupPhaseCursorLog::default(),
            )
        })
        .collect()
}

fn tamper_it_vss_batch_delivery_message(
    config: &DkgConfig,
    mut message: WireMessage,
    dealer: PartyId,
    receiver: PartyId,
    vector: SecretVectorKind,
) -> WireMessage {
    let wire_payload =
        wire_decode_dkg_share_payload(&message.payload).expect("decode dkg share wire payload");
    let dkg_payload = DkgSharePayload {
        dealer,
        receiver: PartyId(wire_payload.receiver_party_id),
        encrypted_share: wire_payload.encrypted_share,
        encrypted_seed_share: wire_payload.encrypted_seed_share,
        proof: wire_payload.proof,
    };
    let mut private_deliveries =
        it_vss_private_deliveries_from_dkg_share(&dkg_payload).expect("decode batch");
    let label = ItVssSharingLabel::new(
        config,
        dealer,
        ItVssSharingDomain::for_secret_vector(vector),
        None,
    )
    .expect("tamper label");
    let delivery = private_deliveries
        .iter_mut()
        .find(|delivery| delivery.receiver == receiver && delivery.label_hash == label.label_hash)
        .expect("delivery to tamper");
    delivery.share[0] ^= 1;
    let tampered = dkg_share_payload_from_it_vss_private_delivery_batch(&private_deliveries)
        .expect("tampered batch payload");
    message.payload = wire_encode_dkg_share_payload(&WireDkgSharePayload {
        receiver_party_id: tampered.receiver.0,
        encrypted_share: tampered.encrypted_share,
        encrypted_seed_share: tampered.encrypted_seed_share,
        proof: tampered.proof,
    });
    message
}

fn route_dkg_private_messages(
    runtimes: &mut [TestDkgTransportRuntime],
    source_indices: impl IntoIterator<Item = usize>,
) {
    let mut deliveries = Vec::new();
    for source_idx in source_indices {
        let local_party = runtimes[source_idx].local_party().0;
        deliveries.extend(
            runtimes[source_idx]
                .state()
                .transport()
                .private_messages()
                .iter()
                .filter(|delivery| delivery.sender_party_id == local_party)
                .cloned(),
        );
    }
    for delivery in deliveries {
        let receiver_idx = runtimes
            .iter()
            .position(|runtime| runtime.local_party().0 == delivery.receiver_party_id)
            .expect("receiver runtime");
        if runtimes[receiver_idx].local_party().0 == delivery.sender_party_id {
            continue;
        }
        runtimes[receiver_idx]
            .state_mut()
            .transport_mut()
            .inject_private(
                delivery.sender_party_id,
                delivery.receiver_party_id,
                delivery.message,
            )
            .expect("route dkg private message");
    }
}

fn route_logged_dkg_private_messages(
    runtimes: &mut [TestLoggedDkgTransportRuntime],
    source_indices: impl IntoIterator<Item = usize>,
) {
    let mut deliveries = Vec::new();
    for source_idx in source_indices {
        let local_party = runtimes[source_idx].local_party().0;
        deliveries.extend(
            runtimes[source_idx]
                .state()
                .transport()
                .private_messages()
                .iter()
                .filter(|delivery| delivery.sender_party_id == local_party)
                .cloned(),
        );
    }
    for delivery in deliveries {
        let receiver_idx = runtimes
            .iter()
            .position(|runtime| runtime.local_party().0 == delivery.receiver_party_id)
            .expect("receiver runtime");
        if runtimes[receiver_idx].local_party().0 == delivery.sender_party_id {
            continue;
        }
        runtimes[receiver_idx]
            .state_mut()
            .transport_mut()
            .inject_private(
                delivery.sender_party_id,
                delivery.receiver_party_id,
                delivery.message,
            )
            .expect("route logged dkg private message");
    }
}

fn route_cursored_logged_dkg_private_messages(
    runtimes: &mut [TestCursoredLoggedDkgTransportRuntime],
    source_indices: impl IntoIterator<Item = usize>,
) {
    let mut deliveries = Vec::new();
    for source_idx in source_indices {
        let local_party = runtimes[source_idx].local_party().0;
        deliveries.extend(
            runtimes[source_idx]
                .runtime()
                .state()
                .transport()
                .private_messages()
                .iter()
                .filter(|delivery| delivery.sender_party_id == local_party)
                .cloned(),
        );
    }
    for delivery in deliveries {
        let receiver_idx = runtimes
            .iter()
            .position(|runtime| runtime.local_party().0 == delivery.receiver_party_id)
            .expect("receiver runtime");
        if runtimes[receiver_idx].local_party().0 == delivery.sender_party_id {
            continue;
        }
        runtimes[receiver_idx]
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .inject_private(
                delivery.sender_party_id,
                delivery.receiver_party_id,
                delivery.message,
            )
            .expect("route cursored logged dkg private message");
    }
}

fn route_cursored_logged_dkg_new_private_messages(
    runtimes: &mut [TestCursoredLoggedDkgTransportRuntime],
    source_indices: impl IntoIterator<Item = usize>,
    offsets: &mut [usize],
) {
    let mut deliveries = Vec::new();
    for source_idx in source_indices {
        let local_party = runtimes[source_idx].local_party().0;
        deliveries.extend(
            runtimes[source_idx]
                .runtime()
                .state()
                .transport()
                .private_messages()[offsets[source_idx]..]
                .iter()
                .filter(|delivery| delivery.sender_party_id == local_party)
                .cloned(),
        );
        offsets[source_idx] = runtimes[source_idx]
            .runtime()
            .state()
            .transport()
            .private_messages()
            .len();
    }
    for delivery in deliveries {
        let receiver_idx = runtimes
            .iter()
            .position(|runtime| runtime.local_party().0 == delivery.receiver_party_id)
            .expect("receiver runtime");
        if runtimes[receiver_idx].local_party().0 == delivery.sender_party_id {
            continue;
        }
        runtimes[receiver_idx]
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .inject_private(
                delivery.sender_party_id,
                delivery.receiver_party_id,
                delivery.message,
            )
            .expect("route new cursored logged dkg private message");
    }
}

fn route_dkg_broadcast_messages(
    runtimes: &mut [TestDkgTransportRuntime],
    source_indices: impl IntoIterator<Item = usize>,
) {
    let mut deliveries = Vec::new();
    for source_idx in source_indices {
        let local_party = runtimes[source_idx].local_party().0;
        deliveries.extend(
            runtimes[source_idx]
                .state()
                .transport()
                .broadcast_deliveries()
                .iter()
                .filter(|delivery| delivery.message.header.sender_party_id == local_party)
                .cloned(),
        );
    }
    for delivery in deliveries {
        for runtime in runtimes.iter_mut() {
            if runtime.local_party().0 == delivery.message.header.sender_party_id {
                continue;
            }
            runtime
                .state_mut()
                .transport_mut()
                .inject_broadcast_delivery(delivery.observer_party_id, delivery.message.clone())
                .expect("route dkg broadcast message");
        }
    }
}

fn route_logged_dkg_broadcast_messages(
    runtimes: &mut [TestLoggedDkgTransportRuntime],
    source_indices: impl IntoIterator<Item = usize>,
) {
    let mut deliveries = Vec::new();
    for source_idx in source_indices {
        let local_party = runtimes[source_idx].local_party().0;
        deliveries.extend(
            runtimes[source_idx]
                .state()
                .transport()
                .broadcast_deliveries()
                .iter()
                .filter(|delivery| delivery.message.header.sender_party_id == local_party)
                .cloned(),
        );
    }
    for delivery in deliveries {
        for runtime in runtimes.iter_mut() {
            if runtime.local_party().0 == delivery.message.header.sender_party_id {
                continue;
            }
            runtime
                .state_mut()
                .transport_mut()
                .inject_broadcast_delivery(delivery.observer_party_id, delivery.message.clone())
                .expect("route logged dkg broadcast message");
        }
    }
}

fn route_cursored_logged_dkg_broadcast_messages(
    runtimes: &mut [TestCursoredLoggedDkgTransportRuntime],
    source_indices: impl IntoIterator<Item = usize>,
) {
    let mut deliveries = Vec::new();
    for source_idx in source_indices {
        let local_party = runtimes[source_idx].local_party().0;
        deliveries.extend(
            runtimes[source_idx]
                .runtime()
                .state()
                .transport()
                .broadcast_deliveries()
                .iter()
                .filter(|delivery| delivery.message.header.sender_party_id == local_party)
                .cloned(),
        );
    }
    for delivery in deliveries {
        for runtime in runtimes.iter_mut() {
            if runtime.local_party().0 == delivery.message.header.sender_party_id {
                continue;
            }
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .inject_broadcast_delivery(delivery.observer_party_id, delivery.message.clone())
                .expect("route cursored logged dkg broadcast message");
        }
    }
}

fn route_cursored_logged_dkg_new_broadcast_messages(
    runtimes: &mut [TestCursoredLoggedDkgTransportRuntime],
    source_indices: impl IntoIterator<Item = usize>,
    offsets: &mut [usize],
) {
    let mut deliveries = Vec::new();
    for source_idx in source_indices {
        let local_party = runtimes[source_idx].local_party().0;
        deliveries.extend(
            runtimes[source_idx]
                .runtime()
                .state()
                .transport()
                .broadcast_deliveries()[offsets[source_idx]..]
                .iter()
                .filter(|delivery| delivery.message.header.sender_party_id == local_party)
                .cloned(),
        );
        offsets[source_idx] = runtimes[source_idx]
            .runtime()
            .state()
            .transport()
            .broadcast_deliveries()
            .len();
    }
    for delivery in deliveries {
        for runtime in runtimes.iter_mut() {
            if runtime.local_party().0 == delivery.message.header.sender_party_id {
                continue;
            }
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .inject_broadcast_delivery(delivery.observer_party_id, delivery.message.clone())
                .expect("route new cursored logged dkg broadcast message");
        }
    }
}

fn output_with_hash(hash: KeygenTranscriptHash) -> DkgPublicOutput {
    let config = config();
    DkgPublicOutput {
        public_key: vec![1; config.suite.public_key_len()],
        t1: vec![4; config.suite.t1_len()],
        as1_commitments: config
            .parties
            .iter()
            .map(|&party| As1Commitment {
                party,
                bytes: vec![party.0 as u8, 10],
            })
            .collect(),
        pairwise_seed_commitments: config
            .parties
            .iter()
            .map(|&party| PairwiseSeedCommitment {
                party,
                commitment: [party.0 as u8; 32],
            })
            .collect(),
        config,
        keygen_transcript_hash: hash,
        rho: [9; 32],
        vss_commitments: vec![VssCommitment {
            bytes: vec![6, 7, 8],
        }],
    }
}

fn bound_output() -> DkgPublicOutput {
    let mut output = output_with_hash(KeygenTranscriptHash([0; 32]));
    output.keygen_transcript_hash = output.transcript_binding();
    output
}

fn commit_payload(party: PartyId) -> DkgCommitPayload {
    DkgCommitPayload {
        dealer: party,
        vss_commitments: vec![VssCommitment {
            bytes: vec![party.0 as u8, 1],
        }],
        as1_commitment: As1Commitment {
            party,
            bytes: vec![party.0 as u8, 2],
        },
        pairwise_seed_commitment: PairwiseSeedCommitment {
            party,
            commitment: [party.0 as u8; 32],
        },
    }
}

fn commit_round() -> Vec<DkgCommitPayload> {
    parties(&[1, 2, 3])
        .into_iter()
        .map(commit_payload)
        .collect()
}

fn share_round() -> Vec<DkgSharePayload> {
    let mut shares = Vec::new();
    for dealer in parties(&[1, 2, 3]) {
        for receiver in parties(&[1, 2, 3]) {
            if dealer == receiver {
                continue;
            }
            shares.push(DkgSharePayload {
                dealer,
                receiver,
                encrypted_share: vec![dealer.0 as u8, receiver.0 as u8],
                encrypted_seed_share: vec![receiver.0 as u8, dealer.0 as u8],
                proof: vec![dealer.0 as u8 ^ receiver.0 as u8],
            });
        }
    }
    shares
}

fn finalize_round(output: DkgPublicOutput) -> Vec<DkgFinalizePayload> {
    parties(&[1, 2, 3])
        .into_iter()
        .map(|sender| DkgFinalizePayload {
            sender,
            output: output.clone(),
        })
        .collect()
}

#[test]
fn config_accepts_sorted_threshold_shape() {
    let got = DkgConfig::new::<MlDsa44>(2, parties(&[2, 4, 9]), KeygenEpoch(1))
        .expect("sorted threshold shape is valid");

    assert_eq!(got.suite, DkgSuite::MlDsa44);
    assert_eq!(got.threshold, 2);
    assert_eq!(got.parties, parties(&[2, 4, 9]));
}

#[test]
fn config_rejects_invalid_thresholds() {
    assert_eq!(
        DkgConfig::new::<MlDsa44>(0, parties(&[1, 2, 3]), KeygenEpoch(1)),
        Err(DkgError::InvalidThreshold {
            threshold: 0,
            parties: 3
        })
    );
    assert_eq!(
        DkgConfig::new::<MlDsa44>(4, parties(&[1, 2, 3]), KeygenEpoch(1)),
        Err(DkgError::InvalidThreshold {
            threshold: 4,
            parties: 3
        })
    );
}

#[test]
fn config_rejects_unsorted_or_duplicate_parties() {
    assert_eq!(
        DkgConfig::new::<MlDsa44>(1, parties(&[2, 1]), KeygenEpoch(1)),
        Err(DkgError::UnsortedParties)
    );
    assert_eq!(
        DkgConfig::new::<MlDsa44>(1, parties(&[1, 1]), KeygenEpoch(1)),
        Err(DkgError::DuplicateParty(PartyId(1)))
    );
}

#[test]
fn config_rejects_insufficient_honest_majority_shape() {
    assert_eq!(
        DkgConfig::new::<MlDsa65>(3, parties(&[1, 2, 3, 4]), KeygenEpoch(1)),
        Err(DkgError::InsufficientPartiesForThreshold {
            threshold: 3,
            parties: 4,
            required: 5
        })
    );
}

#[test]
fn transcript_hash_changes_with_suite_epoch_threshold_and_party_set() {
    let base = config().transcript_hash();

    assert_ne!(
        base,
        DkgConfig::new::<MlDsa44>(2, parties(&[1, 2, 3]), KeygenEpoch(7))
            .expect("valid changed suite config")
            .transcript_hash()
    );
    assert_ne!(
        base,
        DkgConfig::new::<MlDsa65>(2, parties(&[1, 2, 3]), KeygenEpoch(8))
            .expect("valid changed epoch config")
            .transcript_hash()
    );
    assert_ne!(
        base,
        DkgConfig::new::<MlDsa65>(1, parties(&[1, 2, 3]), KeygenEpoch(7))
            .expect("valid changed threshold config")
            .transcript_hash()
    );
    assert_ne!(
        base,
        DkgConfig::new::<MlDsa65>(2, parties(&[1, 2, 4]), KeygenEpoch(7))
            .expect("valid changed party-set config")
            .transcript_hash()
    );
}

#[test]
fn config_exposes_canonical_interpolation_points() {
    let config = config();
    assert_eq!(
        config.interpolation_points::<MlDsa65>(),
        Ok(vec![(PartyId(1), 1), (PartyId(2), 2), (PartyId(3), 3)])
    );
    assert_eq!(
        config.interpolation_point::<MlDsa65>(PartyId(9)),
        Err(DkgError::UnknownParty(PartyId(9)))
    );

    let zero_config =
        DkgConfig::new::<MlDsa65>(1, parties(&[0]), KeygenEpoch(9)).expect("config shape");
    assert_eq!(
        zero_config.interpolation_point::<MlDsa65>(PartyId(0)),
        Err(DkgError::InvalidSharePoint {
            party: PartyId(0),
            expected: 0,
            got: 0,
        })
    );
}

#[test]
fn public_output_validates_transcript_binding() {
    let mut output = output_with_hash(KeygenTranscriptHash([0; 32]));
    output.keygen_transcript_hash = output.transcript_binding();

    assert_eq!(output.validate_binding(), Ok(()));

    output.rho[0] ^= 1;
    assert!(matches!(
        output.validate_binding(),
        Err(DkgError::TranscriptMismatch { .. })
    ));
}

#[test]
fn production_dkg_entrypoint_requires_readiness_for_product_start() {
    let config = config();
    assert_eq!(
        ProductionDkg::start(config.clone()),
        Ok(DkgState::Waiting(DkgRound::Commit))
    );
    assert_eq!(
        ProductionDkg::start_with_readiness(
            config,
            ProductionNativeDkgCoordinatorReadiness::default(),
        ),
        Err(DkgError::InsecureNativeDkgCoordinator)
    );
}

#[test]
fn secret_share_debug_redacts_material() {
    let share = DkgSecretShare {
        party: PartyId(3),
        s1_share: vec![1, 2, 3],
        s2_share: vec![4, 5, 6],
        t0_share: vec![7, 8, 9],
        pairwise_seed_shares: vec![vec![10, 11]],
    };

    assert_eq!(
        format!("{share:?}"),
        "DkgSecretShare { party: PartyId(3), s1_share: \"<redacted>\", s2_share: \"<redacted>\", t0_share: \"<redacted>\", pairwise_seed_shares: \"<redacted>\" }"
    );
}

fn secret_share(party: PartyId) -> DkgSecretShare {
    let config = config();
    let point = config
        .interpolation_point::<MlDsa65>(party)
        .expect("test party point");
    let s1_share = BoundedSecretVectorShare::new::<MlDsa65>(
        &config,
        party,
        point,
        vec![0; MlDsa65::L * MlDsa65::N],
    )
    .expect("typed s1 share")
    .encode::<MlDsa65>(&config)
    .expect("encoded s1 share");
    DkgSecretShare {
        party,
        s1_share,
        s2_share: vec![party.0 as u8, 2],
        t0_share: vec![party.0 as u8, 3],
        pairwise_seed_shares: vec![vec![party.0 as u8, 4]],
    }
}

fn provisioned_packages(output: DkgPublicOutput) -> Vec<ProvisionedKeyShare> {
    parties(&[1, 2, 3])
        .into_iter()
        .map(|party| ProvisionedKeyShare {
            party,
            public: output.clone(),
            secret: secret_share(party),
            ceremony_transcript_hash: [0x42; 32],
        })
        .collect()
}

#[test]
fn public_output_shape_rejects_wrong_lengths_and_commitment_sets() {
    let mut output = bound_output();
    output.public_key.pop();
    assert_eq!(
        output.validate_binding(),
        Err(DkgError::InvalidPublicKeyLength {
            expected: DkgSuite::MlDsa65.public_key_len(),
            got: DkgSuite::MlDsa65.public_key_len() - 1,
        })
    );

    let mut output = bound_output();
    output.as1_commitments.pop();
    assert_eq!(
        output.validate_binding(),
        Err(DkgError::InvalidCommitmentPartySet {
            set: CommitmentSet::As1,
            expected: 3,
            got: 2,
        })
    );
}

#[test]
fn provisioning_import_accepts_complete_transcript_bound_packages() {
    let output = bound_output();
    let imported = import_provisioned_key_shares(&config(), provisioned_packages(output.clone()))
        .expect("provisioning import");

    assert_eq!(imported.len(), 3);
    for (item, expected_party) in imported.iter().zip(parties(&[1, 2, 3])) {
        assert_eq!(item.public, output);
        assert_eq!(item.secret.party, expected_party);
    }
}

#[test]
fn provisioning_import_rejects_silent_or_inconsistent_dealer_shapes() {
    let output = bound_output();
    let mut packages = provisioned_packages(output.clone());
    packages.pop();
    assert_eq!(
        import_provisioned_key_shares(&config(), packages),
        Err(DkgError::MissingRoundMessages {
            round: DkgRound::Finalize,
            expected: 3,
            got: 2,
        })
    );

    let mut packages = provisioned_packages(output.clone());
    packages[1].public.rho[0] ^= 1;
    packages[1].public.keygen_transcript_hash = packages[1].public.transcript_binding();
    assert_eq!(
        import_provisioned_key_shares(&config(), packages),
        Err(DkgError::ProvisionedPublicOutputDisagreement)
    );

    let mut packages = provisioned_packages(output.clone());
    packages[2].secret.s1_share.clear();
    assert_eq!(
        import_provisioned_key_shares(&config(), packages),
        Err(DkgError::EmptySecretShareField {
            party: PartyId(3),
            field: "s1_share",
        })
    );

    let mut packages = provisioned_packages(output);
    packages[1].secret.s1_share[0] ^= 1;
    assert_eq!(
        import_provisioned_key_shares(&config(), packages),
        Err(DkgError::InvalidSecretShareEncoding(
            "bounded vector share magic mismatch"
        ))
    );
}

#[test]
fn shamir_scalar_shares_reconstruct_secret_at_zero() {
    let shares =
        share_scalar_with_polynomial::<MlDsa65>(&[1234, 10, -3], &[1, 2, 5]).expect("shares");

    assert_eq!(
        evaluate_shamir_polynomial::<MlDsa65>(&[1234, 10, -3], 2).expect("eval"),
        shares[1].value
    );
    assert_eq!(
        reconstruct_scalar_at_zero::<MlDsa65>(&shares).expect("reconstruct"),
        1234
    );
    assert_eq!(
        reconstruct_scalar_at_zero::<MlDsa65>(&shares[..2]).expect("degree-1 projection"),
        1240
    );
}

#[test]
fn shamir_scalar_rejects_empty_duplicate_and_zero_points() {
    assert_eq!(
        evaluate_shamir_polynomial::<MlDsa65>(&[], 1),
        Err(DkgError::EmptyShamirPolynomial)
    );
    assert_eq!(
        share_scalar_with_polynomial::<MlDsa65>(&[1, 2], &[0]),
        Err(DkgError::InvalidInterpolationPoint(0))
    );
    assert_eq!(
        share_scalar_with_polynomial::<MlDsa65>(&[1, 2], &[1, 1]),
        Err(DkgError::DuplicateInterpolationPoint)
    );
    assert_eq!(
        reconstruct_scalar_at_zero::<MlDsa65>(&[]),
        Err(DkgError::EmptyShamirShareSet)
    );
}

#[test]
fn test_only_scalar_vss_accepts_valid_shares_and_reports_complaints() {
    let deal = test_only_deal_scalar_vss::<MlDsa65>(
        PartyId(1),
        &[77, -5, 9],
        &[(PartyId(1), 1), (PartyId(2), 2), (PartyId(3), 3)],
    )
    .expect("test vss deal");

    assert_eq!(deal.commitments.len(), 3);
    for share in &deal.shares {
        assert_eq!(
            test_only_verify_scalar_vss_share::<MlDsa65>(&deal, share),
            Ok(())
        );
    }

    let mut bad_share = deal.shares[1];
    bad_share.value += 1;
    let complaint = test_only_verify_scalar_vss_share::<MlDsa65>(&deal, &bad_share)
        .expect_err("tampered share is rejected");
    assert_eq!(complaint.dealer, PartyId(1));
    assert_eq!(complaint.receiver, PartyId(2));
    assert_eq!(complaint.point, 2);
    assert_eq!(complaint.got, reduce_mod_q::<MlDsa65>(bad_share.value));
    assert_eq!(
        complaint.expected,
        evaluate_shamir_polynomial::<MlDsa65>(&[77, -5, 9], 2).expect("expected")
    );

    let payload = DkgComplaintPayload {
        complainant: complaint.receiver,
        dealer: complaint.dealer,
        receiver: complaint.receiver,
        reason: DkgComplaintReason::InvalidVssShare,
        evidence: complaint.to_canonical_bytes(),
    };
    assert_eq!(payload.reason, DkgComplaintReason::InvalidVssShare);
    assert_eq!(payload.evidence.len(), 48);
}

#[test]
fn test_only_scalar_vss_rejects_bad_deal_shape() {
    assert_eq!(
        test_only_deal_scalar_vss::<MlDsa65>(PartyId(1), &[], &[(PartyId(1), 1)]),
        Err(DkgError::EmptyShamirPolynomial)
    );
    assert_eq!(
        test_only_deal_scalar_vss::<MlDsa65>(PartyId(1), &[1], &[]),
        Err(DkgError::EmptyShamirShareSet)
    );
    assert_eq!(
        test_only_deal_scalar_vss::<MlDsa65>(PartyId(1), &[1], &[(PartyId(1), 1), (PartyId(2), 1)]),
        Err(DkgError::DuplicateInterpolationPoint)
    );
}

#[test]
fn test_only_scalar_vss_round_uses_configured_points_and_complaints() {
    let config = config();
    let deal = test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(1), &[77, -5, 9])
        .expect("test vss deal");

    assert_eq!(
        deal.shares
            .iter()
            .map(|share| (share.receiver, share.point))
            .collect::<Vec<_>>(),
        vec![(PartyId(1), 1), (PartyId(2), 2), (PartyId(3), 3)]
    );
    assert_eq!(
        test_only_verify_scalar_vss_round::<MlDsa65>(&config, &deal, &deal.shares),
        Ok(Vec::new())
    );

    let mut shares = deal.shares.clone();
    shares[2].value += 1;
    let complaints =
        test_only_verify_scalar_vss_round::<MlDsa65>(&config, &deal, &shares).expect("complaints");
    assert_eq!(complaints.len(), 1);
    assert_eq!(complaints[0].complainant, PartyId(3));
    assert_eq!(complaints[0].dealer, PartyId(1));
    assert_eq!(complaints[0].reason, DkgComplaintReason::InvalidVssShare);

    let mut bad_point = deal.shares.clone();
    bad_point[0].point = 9;
    assert_eq!(
        test_only_verify_scalar_vss_round::<MlDsa65>(&config, &deal, &bad_point),
        Err(DkgError::InvalidSharePoint {
            party: PartyId(1),
            expected: 1,
            got: 9,
        })
    );
}

#[test]
fn in_process_scalar_it_vss_accepts_valid_deal() {
    let config = config();
    let mut backend = InProcessScalarItVssBackend::new([0x21; 32]);
    let deal = backend
        .deal::<MlDsa65>(&config, PartyId(1), 77)
        .expect("in-process deal");

    assert_eq!(deal.public_check.dealer, PartyId(1));
    assert_eq!(deal.public_check.threshold, config.threshold);
    assert_eq!(deal.public_check.config_hash, config.transcript_hash());
    assert_eq!(
        deal.public_check.commitments.len(),
        usize::from(config.threshold)
    );
    assert_eq!(deal.public_check.share_bindings.len(), config.parties.len());
    assert_eq!(
        verify_in_process_scalar_vss_round::<MlDsa65>(&config, &deal),
        Ok(Vec::new())
    );
    for share in &deal.shares {
        backend
            .verify_scalar_share::<MlDsa65>(&config, &deal.public_check, share)
            .expect("share verifies");
    }
}

#[test]
fn in_process_scalar_it_vss_complaint_evidence_round_trips() {
    let evidence = InProcessScalarVssComplaintEvidence {
        dealer: PartyId(1),
        receiver: PartyId(2),
        point: 2,
        got: 10,
        expected_binding: [0x11; 32],
        got_binding: [0x22; 32],
        public_check_binding: [0x33; 32],
    };

    let encoded = evidence.to_canonical_bytes();
    assert_eq!(encoded.len(), 108);
    assert_eq!(
        InProcessScalarVssComplaintEvidence::from_canonical_bytes(&encoded),
        Ok(evidence)
    );
    assert_eq!(
        InProcessScalarVssComplaintEvidence::from_canonical_bytes(&encoded[..107]),
        Err(DkgError::InvalidComplaintEvidenceLength {
            expected: 108,
            got: 107,
        })
    );
}

#[test]
fn in_process_scalar_it_vss_rejects_tampered_share_and_combines_accepted_dealers() {
    let config = config();
    let mut backend = InProcessScalarItVssBackend::new([0x31; 32]);
    let first = backend
        .deal::<MlDsa65>(&config, PartyId(1), 10)
        .expect("deal 1");
    let mut second = backend
        .deal::<MlDsa65>(&config, PartyId(2), 20)
        .expect("deal 2");
    let third = backend
        .deal::<MlDsa65>(&config, PartyId(3), 30)
        .expect("deal 3");
    second.shares[1].share.value += 1;

    let complaints =
        verify_in_process_scalar_vss_round::<MlDsa65>(&config, &second).expect("complaints");
    assert_eq!(complaints.len(), 1);
    assert_eq!(complaints[0].complainant, PartyId(2));
    assert_eq!(complaints[0].dealer, PartyId(2));
    assert_eq!(complaints[0].reason, DkgComplaintReason::InvalidVssShare);

    let deals = vec![first, second, third];
    let public_checks = deals
        .iter()
        .map(|deal| deal.public_check.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        resolve_in_process_scalar_vss_complaints::<MlDsa65>(&config, &public_checks, &complaints,)
            .expect("resolve"),
        ScalarVssResolution {
            accepted_dealers: parties(&[1, 3]),
            rejected_dealers: parties(&[2]),
        }
    );

    let output =
        combine_accepted_in_process_scalar_vss_deals::<MlDsa65>(&config, &deals, &complaints)
            .expect("combine accepted");
    assert_eq!(output.accepted_dealers, parties(&[1, 3]));
    assert_eq!(output.rejected_dealers, parties(&[2]));
    assert_eq!(output.shares.len(), config.parties.len());
    let reconstructed = reconstruct_scalar_at_zero::<MlDsa65>(
        &output
            .shares
            .iter()
            .take(2)
            .map(|share| ShamirScalarShare {
                point: share.point,
                value: share.value,
            })
            .collect::<Vec<_>>(),
    )
    .expect("reconstruct accepted scalar");
    assert_eq!(reconstructed, 40);
}

#[test]
fn in_process_scalar_it_vss_rejects_tampered_complaint_evidence() {
    let config = config();
    let mut backend = InProcessScalarItVssBackend::new([0x41; 32]);
    let mut deals = [
        backend
            .deal::<MlDsa65>(&config, PartyId(1), 10)
            .expect("deal 1"),
        backend
            .deal::<MlDsa65>(&config, PartyId(2), 20)
            .expect("deal 2"),
        backend
            .deal::<MlDsa65>(&config, PartyId(3), 30)
            .expect("deal 3"),
    ];
    deals[0].shares[2].share.value += 1;
    let mut complaints =
        verify_in_process_scalar_vss_round::<MlDsa65>(&config, &deals[0]).expect("complaints");
    complaints[0].evidence[20] ^= 1;
    let public_checks = deals
        .iter()
        .map(|deal| deal.public_check.clone())
        .collect::<Vec<_>>();

    assert_eq!(
        resolve_in_process_scalar_vss_complaints::<MlDsa65>(&config, &public_checks, &complaints,),
        Err(DkgError::ComplaintEvidenceMismatch)
    );
}

#[test]
fn in_process_scalar_it_vss_rejects_insufficient_accepted_dealers() {
    let config = config();
    let mut backend = InProcessScalarItVssBackend::new([0x51; 32]);
    let mut first = backend
        .deal::<MlDsa65>(&config, PartyId(1), 10)
        .expect("deal 1");
    let mut second = backend
        .deal::<MlDsa65>(&config, PartyId(2), 20)
        .expect("deal 2");
    let third = backend
        .deal::<MlDsa65>(&config, PartyId(3), 30)
        .expect("deal 3");
    first.shares[0].share.value += 1;
    second.shares[1].share.value += 1;
    let mut complaints =
        verify_in_process_scalar_vss_round::<MlDsa65>(&config, &first).expect("complaints");
    complaints.extend(
        verify_in_process_scalar_vss_round::<MlDsa65>(&config, &second).expect("complaints"),
    );

    assert_eq!(
        combine_accepted_in_process_scalar_vss_deals::<MlDsa65>(
            &config,
            &[first, second, third],
            &complaints,
        ),
        Err(DkgError::InsufficientAcceptedDealers {
            threshold: 2,
            accepted: 1,
        })
    );
}

#[test]
fn in_process_vector_vss_policy_rejects_whole_dealer_on_valid_complaint() {
    let config = config();
    let mut backend = InProcessScalarItVssBackend::new([0x52; 32]);
    let first = vec![
        backend
            .deal::<MlDsa65>(&config, PartyId(1), 10)
            .expect("deal 1 coeff 0"),
        backend
            .deal::<MlDsa65>(&config, PartyId(1), 11)
            .expect("deal 1 coeff 1"),
    ];
    let mut second = vec![
        backend
            .deal::<MlDsa65>(&config, PartyId(2), 20)
            .expect("deal 2 coeff 0"),
        backend
            .deal::<MlDsa65>(&config, PartyId(2), 21)
            .expect("deal 2 coeff 1"),
    ];
    let third = vec![
        backend
            .deal::<MlDsa65>(&config, PartyId(3), 30)
            .expect("deal 3 coeff 0"),
        backend
            .deal::<MlDsa65>(&config, PartyId(3), 31)
            .expect("deal 3 coeff 1"),
    ];
    second[1].shares[1].share.value += 1;
    let complaints =
        verify_in_process_scalar_vss_round::<MlDsa65>(&config, &second[1]).expect("complaint");
    let public_check_vectors = [first, second, third]
        .iter()
        .map(|vector| {
            vector
                .iter()
                .map(|deal| deal.public_check.clone())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let resolution = resolve_in_process_scalar_vss_vector_complaints::<MlDsa65>(
        &config,
        &public_check_vectors,
        &complaints,
    )
    .expect("resolve vector complaints");

    assert_eq!(resolution.accepted_dealers, parties(&[1, 3]));
    assert_eq!(resolution.rejected_dealers, parties(&[2]));

    let (public_commitments, it_vss_resolution) =
        scaffold_it_vss_resolution_from_in_process_scalar_vss_vector_resolution(
            &config,
            &public_check_vectors,
            &complaints,
            &resolution,
        )
        .expect("production-shaped it-vss resolution");
    validate_it_vss_complaint_resolution_for_backend(
        &config,
        &public_commitments,
        &it_vss_resolution,
        ItVssBackendId::InProcessHashBindingScaffold,
    )
    .expect("validated it-vss resolution");
    assert_eq!(it_vss_resolution.accepted_dealers, parties(&[1, 3]));
    assert_eq!(it_vss_resolution.rejected_dealers, parties(&[2]));
    assert_eq!(it_vss_resolution.certificates.len(), 2);
    assert!(it_vss_resolution
        .certificates
        .iter()
        .all(|certificate| certificate.backend_id == ItVssBackendId::InProcessHashBindingScaffold));
}

#[test]
fn in_process_vector_vss_policy_rejects_bad_duplicate_and_insufficient_complaints() {
    let config = config();
    let mut backend = InProcessScalarItVssBackend::new([0x53; 32]);
    let mut dealer_vectors = [
        vec![
            backend
                .deal::<MlDsa65>(&config, PartyId(1), 10)
                .expect("deal 1 coeff 0"),
            backend
                .deal::<MlDsa65>(&config, PartyId(1), 11)
                .expect("deal 1 coeff 1"),
        ],
        vec![
            backend
                .deal::<MlDsa65>(&config, PartyId(2), 20)
                .expect("deal 2 coeff 0"),
            backend
                .deal::<MlDsa65>(&config, PartyId(2), 21)
                .expect("deal 2 coeff 1"),
        ],
        vec![
            backend
                .deal::<MlDsa65>(&config, PartyId(3), 30)
                .expect("deal 3 coeff 0"),
            backend
                .deal::<MlDsa65>(&config, PartyId(3), 31)
                .expect("deal 3 coeff 1"),
        ],
    ];
    dealer_vectors[0][0].shares[0].share.value += 1;
    dealer_vectors[1][1].shares[1].share.value += 1;
    let public_check_vectors = dealer_vectors
        .iter()
        .map(|vector| {
            vector
                .iter()
                .map(|deal| deal.public_check.clone())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let first_complaints =
        verify_in_process_scalar_vss_round::<MlDsa65>(&config, &dealer_vectors[0][0])
            .expect("first complaints");

    let mut duplicate = first_complaints.clone();
    duplicate.push(first_complaints[0].clone());
    assert_eq!(
        resolve_in_process_scalar_vss_vector_complaints::<MlDsa65>(
            &config,
            &public_check_vectors,
            &duplicate,
        ),
        Err(DkgError::DuplicateComplaint {
            complainant: PartyId(1),
            dealer: PartyId(1),
            receiver: PartyId(1),
        })
    );

    let mut tampered = first_complaints.clone();
    tampered[0].evidence[20] ^= 1;
    assert_eq!(
        resolve_in_process_scalar_vss_vector_complaints::<MlDsa65>(
            &config,
            &public_check_vectors,
            &tampered,
        ),
        Err(DkgError::ComplaintEvidenceMismatch)
    );

    let mut insufficient = first_complaints;
    insufficient.extend(
        verify_in_process_scalar_vss_round::<MlDsa65>(&config, &dealer_vectors[1][1])
            .expect("second complaints"),
    );
    assert_eq!(
        resolve_in_process_scalar_vss_vector_complaints::<MlDsa65>(
            &config,
            &public_check_vectors,
            &insufficient,
        ),
        Err(DkgError::InsufficientAcceptedDealers {
            threshold: 2,
            accepted: 1,
        })
    );
}

#[test]
fn small_sampler_exact_distribution_for_fixed_corrupted_contributions() {
    for eta in [SmallSecretEta::Two, SmallSecretEta::Four] {
        let config = config();
        let label = SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 0).expect("label");
        let m = eta.modulus();
        for first_corrupt in 0..m {
            for second_corrupt in 0..m {
                let mut seen = vec![0u8; usize::from(m)];
                for honest in 0..m {
                    let contributions = [
                        SmallResidueContribution::new(PartyId(1), label, eta, first_corrupt),
                        SmallResidueContribution::new(PartyId(2), label, eta, second_corrupt),
                        SmallResidueContribution::new(PartyId(3), label, eta, honest),
                    ];
                    let residue = sum_small_residues_mod(&config, label, eta, &contributions)
                        .expect("sum residues");
                    seen[usize::from(residue)] += 1;
                }
                assert!(seen.iter().all(|&count| count == 1));
            }
        }
    }
}

#[test]
fn small_sampler_outputs_bounded_coefficients_for_all_parameter_sets() {
    fn check<P: MlDsaParams>() {
        let config = config_for::<P>();
        let mut sampler = InProcessDistributedSmallSampler::new([0x61; 32]);
        for vector in [SecretVectorKind::S1, SecretVectorKind::S2] {
            for index in 0..vector.coefficient_count::<P>() {
                let contributions = small_contributions::<P>(&config, vector, index, &[0, 1, 2]);
                let label = SamplerLabel::new::<P>(&config, vector, index).expect("label");
                let coeff = sampler
                    .sample_small_coeff::<P>(&config, label, &contributions)
                    .expect("sample coefficient");
                let reconstructed =
                    reconstruct_small_coeff::<P>(&coeff, usize::from(config.threshold));
                let signed = signed_field_coeff::<P>(reconstructed);
                assert!((-P::ETA..=P::ETA).contains(&signed));
            }
        }
    }

    check::<MlDsa44>();
    check::<MlDsa65>();
    check::<MlDsa87>();
}

#[test]
fn small_sampler_no_single_dealer_controls_output() {
    let config = config();
    let eta = SmallSecretEta::for_params::<MlDsa65>().expect("eta");
    let label = SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 0).expect("label");
    let m = eta.modulus();
    let mut seen = vec![false; usize::from(m)];

    for honest in 0..m {
        let contributions = [
            SmallResidueContribution::new(PartyId(1), label, eta, 3),
            SmallResidueContribution::new(PartyId(2), label, eta, 6),
            SmallResidueContribution::new(PartyId(3), label, eta, honest),
        ];
        let residue = sum_small_residues_mod(&config, label, eta, &contributions).expect("sum");
        seen[usize::from(residue)] = true;
    }

    assert!(seen.into_iter().all(|item| item));
}

#[test]
fn small_sampler_rejects_malformed_contributions() {
    let config = config();
    let eta = SmallSecretEta::for_params::<MlDsa65>().expect("eta");
    let label = SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 0).expect("label");
    let valid = small_contributions::<MlDsa65>(&config, SecretVectorKind::S1, 0, &[0, 1, 2]);

    let mut bad_residue = valid.clone();
    bad_residue[1] = SmallResidueContribution::new(PartyId(2), label, eta, eta.modulus());
    assert_eq!(
        sum_small_residues_mod(&config, label, eta, &bad_residue),
        Err(DkgError::InvalidSmallResidue {
            dealer: PartyId(2),
            modulus: eta.modulus(),
            got: eta.modulus(),
        })
    );

    let mut bad_bit = valid.clone();
    bad_bit[0].bits[1] = 2;
    assert_eq!(
        sum_small_residues_mod(&config, label, eta, &bad_bit),
        Err(DkgError::InvalidSmallResidueBit {
            dealer: PartyId(1),
            bit_index: 1,
            bit: 2,
        })
    );

    let mut wrong_label = valid.clone();
    wrong_label[2].label =
        SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 1).expect("label");
    assert_eq!(
        sum_small_residues_mod(&config, label, eta, &wrong_label),
        Err(DkgError::SmallSamplerLabelMismatch)
    );

    let mut duplicate = valid.clone();
    duplicate[2].dealer = PartyId(2);
    assert_eq!(
        sum_small_residues_mod(&config, label, eta, &duplicate),
        Err(DkgError::DuplicateRoundSender {
            round: DkgRound::Share,
            sender: PartyId(2),
        })
    );

    assert_eq!(
        sum_small_residues_mod(&config, label, eta, &valid[..2]),
        Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: 3,
            got: 2,
        })
    );
}

#[test]
fn small_sampler_core_consumes_verified_inputs_and_rejects_unverified_inputs() {
    let config = config();
    let eta = SmallSecretEta::for_params::<MlDsa65>().expect("eta");
    let label = SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 0).expect("label");
    let contributions =
        small_contributions::<MlDsa65>(&config, SecretVectorKind::S1, 0, &[1, 2, 3]);
    let verified =
        verified_small_residue_inputs_from_scaffold_contributions(label, eta, &contributions)
            .expect("verified scaffold inputs");

    assert_eq!(
        sum_verified_small_residues_mod(&config, label, eta, &verified),
        sum_small_residues_mod(&config, label, eta, &contributions)
    );

    let mut sampler = InProcessDistributedSmallSampler::new([0x61; 32]);
    let via_verified = sampler
        .sample_verified_small_coeff::<MlDsa65>(&config, label, &verified)
        .expect("sample verified");
    let mut sampler = InProcessDistributedSmallSampler::new([0x61; 32]);
    let via_scaffold = sampler
        .sample_small_coeff::<MlDsa65>(&config, label, &contributions)
        .expect("sample scaffold");
    assert_eq!(via_verified, via_scaffold);

    let unverified = config
        .parties
        .iter()
        .copied()
        .zip([1u8, 2, 3])
        .map(|(dealer, residue)| {
            VerifiedSmallResidueInput::unverified_for_test(dealer, label, eta, residue)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        sum_verified_small_residues_mod(&config, label, eta, &unverified),
        Err(DkgError::UnverifiedSmallResidueInput { dealer: PartyId(1) })
    );

    let zero_certificate = vec![
        VerifiedSmallResidueInput::from_it_vss_certificate(
            PartyId(1),
            label,
            eta,
            1,
            [0u8; 32],
            [0x11; 32],
        ),
        VerifiedSmallResidueInput::from_it_vss_certificate(
            PartyId(2),
            label,
            eta,
            2,
            [0x12; 32],
            [0x13; 32],
        ),
        VerifiedSmallResidueInput::from_it_vss_certificate(
            PartyId(3),
            label,
            eta,
            3,
            [0x14; 32],
            [0x15; 32],
        ),
    ];
    assert_eq!(
        sum_verified_small_residues_mod(&config, label, eta, &zero_certificate),
        Err(DkgError::UnverifiedSmallResidueInput { dealer: PartyId(1) })
    );
}

#[test]
fn small_sampler_scaffold_it_vss_certificates_feed_verified_path() {
    let config = config();
    let eta = SmallSecretEta::for_params::<MlDsa65>().expect("eta");
    let label = SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 2).expect("label");
    let contributions =
        small_contributions::<MlDsa65>(&config, SecretVectorKind::S1, 2, &[4, 5, 6]);
    let certified = scaffold_it_vss_certified_small_residue_inputs::<MlDsa65>(
        &config,
        label,
        eta,
        &contributions,
    )
    .expect("certified inputs");
    assert_eq!(certified.public_commitments.len(), config.parties.len());
    assert_eq!(certified.resolution.accepted_dealers, config.parties);
    assert!(certified.inputs.iter().all(|input| matches!(
        input.verification,
        SmallResidueInputVerification::ItVssCertificate { .. }
    )));

    let mut sampler = InProcessDistributedSmallSampler::new([0x64; 32]);
    let via_cert = sampler
        .sample_verified_small_coeff::<MlDsa65>(&config, label, &certified.inputs)
        .expect("sample verified certs");
    let mut sampler = InProcessDistributedSmallSampler::new([0x64; 32]);
    let via_scaffold = sampler
        .sample_small_coeff::<MlDsa65>(&config, label, &contributions)
        .expect("sample scaffold");
    assert_eq!(via_cert, via_scaffold);
}

#[test]
fn it_vss_artifacts_encode_and_persist_through_dkg_log() {
    let config = config();
    let eta = SmallSecretEta::for_params::<MlDsa65>().expect("eta");
    let label = SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S2, 1).expect("label");
    let contributions =
        small_contributions::<MlDsa65>(&config, SecretVectorKind::S2, 1, &[1, 2, 3]);
    let certified = scaffold_it_vss_certified_small_residue_inputs::<MlDsa65>(
        &config,
        label,
        eta,
        &contributions,
    )
    .expect("certified inputs");

    let commitment_bytes =
        encode_it_vss_public_commitment_artifact(&certified.public_commitments[0]);
    assert_eq!(
        decode_it_vss_public_commitment_artifact(&commitment_bytes),
        Ok(certified.public_commitments[0].clone())
    );
    let resolution_bytes = encode_it_vss_complaint_resolution_artifact(&certified.resolution);
    assert_eq!(
        decode_it_vss_complaint_resolution_artifact(&resolution_bytes),
        Ok(certified.resolution.clone())
    );

    let mut runtimes = test_logged_dkg_transport_runtimes(&config);
    runtimes[1]
        .persist_it_vss_artifacts_logged(&certified.public_commitments, &certified.resolution)
        .expect("persist artifacts");
    let (recovered_commitments, recovered_resolution) = runtimes[1]
        .recover_it_vss_artifacts_from_log()
        .expect("recover artifacts");
    assert_eq!(recovered_commitments, certified.public_commitments);
    assert_eq!(recovered_resolution, Some(certified.resolution.clone()));
    validate_it_vss_complaint_resolution_for_backend(
        &config,
        &recovered_commitments,
        recovered_resolution.as_ref().expect("resolution"),
        ItVssBackendId::InProcessHashBindingScaffold,
    )
    .expect("recovered artifacts validate");
    assert_eq!(
        ensure_it_vss_artifact_log_allowed_for_release(runtimes[1].wire_log()),
        Err(DkgError::ItVssCertificateBackendMismatch)
    );
}

#[test]
fn small_residue_it_vss_sharing_uses_backend_boundary() {
    let config = config();
    let eta = SmallSecretEta::for_params::<MlDsa65>().expect("eta");
    let label = SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 3).expect("label");
    let contribution = SmallResidueContribution::new(PartyId(1), label, eta, 4);
    let contributions =
        small_contributions::<MlDsa65>(&config, SecretVectorKind::S1, 3, &[4, 1, 2]);

    let mut deterministic = DeterministicItVssTestBackend::new([0xb1; 32]);
    let output = it_vss_share_small_residue_contribution::<MlDsa65, _>(
        &mut deterministic,
        &config,
        label,
        eta,
        &contribution,
    )
    .expect("share residue through deterministic backend");
    assert_eq!(
        output.public_commitment.backend_id,
        deterministic.backend_id()
    );
    assert_eq!(output.public_commitment.dealer, contribution.dealer);
    assert_eq!(output.deliveries.len(), config.parties.len());
    for delivery in &output.deliveries {
        deterministic
            .verify_private_delivery::<MlDsa65>(&config, &output.public_commitment, delivery)
            .expect("deterministic delivery verifies");
    }

    let certified = scaffold_it_vss_certified_small_residue_inputs::<MlDsa65>(
        &config,
        label,
        eta,
        &contributions,
    )
    .expect("certify residue");
    assert_eq!(certified.public_commitments.len(), config.parties.len());
    let certified_party1 = certified
        .public_commitments
        .iter()
        .find(|commitment| commitment.dealer == PartyId(1))
        .expect("party 1 commitment");
    assert_eq!(
        certified_party1.public_metadata_hash,
        output.public_commitment.public_metadata_hash
    );

    let mut production = TestInformationCheckingVssBackend;
    let production_output = it_vss_share_small_residue_contribution::<MlDsa65, _>(
        &mut production,
        &config,
        label,
        eta,
        &contribution,
    )
    .expect("share residue through production information-checking backend");
    assert_eq!(
        production_output.public_commitment.backend_id,
        ItVssBackendId::ProductionInformationChecking
    );
    for delivery in &production_output.deliveries {
        production
            .verify_private_delivery::<MlDsa65>(
                &config,
                &production_output.public_commitment,
                delivery,
            )
            .expect("production delivery verifies");
    }
}

#[cfg(feature = "std")]
#[test]
fn file_dkg_wire_log_recovers_it_vss_artifacts_after_reopen() {
    let config = config();
    let eta = SmallSecretEta::for_params::<MlDsa65>().expect("eta");
    let label = SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 5).expect("label");
    let contributions =
        small_contributions::<MlDsa65>(&config, SecretVectorKind::S1, 5, &[2, 3, 4]);
    let certified = scaffold_it_vss_certified_small_residue_inputs::<MlDsa65>(
        &config,
        label,
        eta,
        &contributions,
    )
    .expect("certified inputs");
    let path = std::env::temp_dir().join(format!(
        "talus-it-vss-artifacts-{}-{}.log",
        std::process::id(),
        config.epoch.0
    ));
    let _ = std::fs::remove_file(&path);
    let party_ids = config
        .parties
        .iter()
        .map(|party| party.0)
        .collect::<Vec<_>>();
    let transport = talus_wire::InMemoryTransport::new(1, party_ids.clone()).expect("transport");
    let state =
        DkgTransportStateMachine::new(config.clone(), PartyId(1), transport).expect("state");
    let log = FileDkgWireMessageLog::open(&path).expect("open log");
    let mut runtime = LoggedDkgTransportPartyRuntime::new(state, log);
    runtime
        .persist_it_vss_artifacts_logged(&certified.public_commitments, &certified.resolution)
        .expect("persist artifacts");

    let transport = talus_wire::InMemoryTransport::new(1, party_ids).expect("transport");
    let state =
        DkgTransportStateMachine::new(config.clone(), PartyId(1), transport).expect("state");
    let reopened_log = FileDkgWireMessageLog::open(&path).expect("reopen log");
    let reopened = LoggedDkgTransportPartyRuntime::new(state, reopened_log);
    let (recovered_commitments, recovered_resolution) = reopened
        .recover_it_vss_artifacts_from_log()
        .expect("recover artifacts");
    assert_eq!(recovered_commitments, certified.public_commitments);
    assert_eq!(recovered_resolution, Some(certified.resolution));
    assert_eq!(
        ensure_it_vss_artifact_log_allowed_for_release(reopened.wire_log()),
        Err(DkgError::ItVssCertificateBackendMismatch)
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn it_vss_information_check_complaint_evidence_is_public_shape_only() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::PrimeFieldMpcAux,
        None,
    )
    .expect("label");
    let commitment = ItVssPublicCommitment {
        backend_id: ItVssBackendId::ProductionInformationChecking,
        dealer: PartyId(1),
        label_hash: label.label_hash,
        public_metadata_hash: [0x81; 32],
    };
    let evidence = ItVssInformationCheckComplaintEvidence {
        dealer: PartyId(1),
        receiver: PartyId(2),
        tagger: PartyId(3),
        label_hash: label.label_hash,
        expected_tag_hash: [0x82; 32],
        received_share_hash: [0x83; 32],
        delivery_transcript_hash: [0x84; 32],
        transcript_hash: transcript_hash_it_vss_information_check_complaint(
            [0x82; 32], [0x83; 32], [0x84; 32],
        ),
    };
    validate_it_vss_information_check_complaint_evidence(&config, &commitment, &evidence)
        .expect("valid evidence shape");

    let mut zero_hash = evidence.clone();
    zero_hash.received_share_hash = [0u8; 32];
    assert_eq!(
        validate_it_vss_information_check_complaint_evidence(&config, &commitment, &zero_hash,),
        Err(DkgError::ComplaintEvidenceMismatch)
    );

    let mut wrong_label = evidence;
    wrong_label.label_hash = [0x99; 32];
    assert_eq!(
        validate_it_vss_information_check_complaint_evidence(&config, &commitment, &wrong_label,),
        Err(DkgError::ComplaintEvidenceMismatch)
    );
}

#[test]
fn deterministic_information_checking_backend_verifies_and_complains() {
    let config = config();
    let mut backend = DeterministicItVssTestBackend::new([0x91; 32]);
    let outputs = config
        .parties
        .iter()
        .copied()
        .map(|dealer| {
            let label =
                ItVssSharingLabel::new(&config, dealer, ItVssSharingDomain::PrimeFieldMpcAux, None)
                    .expect("label");
            backend
                .share_secret::<MlDsa65>(&config, label, &[dealer.0 as u8, 7])
                .expect("share")
        })
        .collect::<Vec<_>>();

    for output in &outputs {
        for delivery in &output.deliveries {
            backend
                .verify_private_delivery::<MlDsa65>(&config, &output.public_commitment, delivery)
                .expect("valid delivery");
        }
    }

    let mut bad_share = outputs[0].deliveries[1].clone();
    bad_share.share[0] ^= 1;
    assert_eq!(
        backend.verify_private_delivery::<MlDsa65>(
            &config,
            &outputs[0].public_commitment,
            &bad_share,
        ),
        Err(DkgError::ComplaintEvidenceMismatch)
    );
    let complaint = backend
        .complaint_for_invalid_delivery::<MlDsa65>(
            &config,
            &outputs[0].public_commitment,
            &bad_share,
        )
        .expect("complaint");
    let evidence = decode_it_vss_information_check_complaint_evidence(&complaint.evidence)
        .expect("decode evidence");
    validate_it_vss_information_check_complaint_evidence(
        &config,
        &outputs[0].public_commitment,
        &evidence,
    )
    .expect("valid complaint evidence");

    let public_commitments = outputs
        .iter()
        .map(|output| output.public_commitment.clone())
        .collect::<Vec<_>>();
    let resolution = backend
        .resolve_complaints::<MlDsa65>(&config, &public_commitments, &[complaint])
        .expect("resolve complaints");
    assert_eq!(resolution.accepted_dealers, parties(&[2, 3]));
    assert_eq!(resolution.rejected_dealers, parties(&[1]));

    let mut bad_tag = outputs[1].deliveries[2].clone();
    bad_tag.information_tags[0].tag[0] ^= 1;
    assert_eq!(
        backend.verify_private_delivery::<MlDsa65>(
            &config,
            &outputs[1].public_commitment,
            &bad_tag,
        ),
        Err(DkgError::ComplaintEvidenceMismatch)
    );
}

#[test]
fn deterministic_it_vss_phase_driver_binds_deliveries_and_complaints() {
    let config = config();
    let mut backend = DeterministicItVssTestBackend::new([0xa1; 32]);
    let mut outputs = config
        .parties
        .iter()
        .copied()
        .map(|dealer| {
            let label = ItVssSharingLabel::new(
                &config,
                dealer,
                ItVssSharingDomain::PrimeFieldMpcAux,
                Some(7),
            )
            .expect("label");
            backend
                .share_secret::<MlDsa65>(&config, label, &[dealer.0 as u8, 9])
                .expect("share")
        })
        .collect::<Vec<_>>();
    outputs[0]
        .deliveries
        .iter_mut()
        .find(|delivery| delivery.receiver == PartyId(2))
        .expect("delivery")
        .share[0] ^= 1;

    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);
    for (runtime, output) in runtimes.iter_mut().zip(&outputs) {
        runtime
            .drive_broadcast_it_vss_public_commitment(&output.public_commitment)
            .expect("broadcast it-vss public commitment");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (status, public_commitments) = runtimes[1]
        .drive_collect_it_vss_public_commitments()
        .expect("collect it-vss commitments");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::Collected {
            phase: DkgTransportPhase::ItVssArtifact,
            ..
        }
    ));
    assert_eq!(public_commitments.len(), config.parties.len());

    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }
    for (runtime, output) in runtimes.iter_mut().zip(&outputs) {
        if runtime.local_party() == PartyId(2) {
            continue;
        }
        let delivery = output
            .deliveries
            .iter()
            .find(|delivery| delivery.receiver == PartyId(2))
            .expect("receiver delivery");
        runtime
            .drive_send_it_vss_private_delivery(delivery)
            .expect("send it-vss private delivery");
    }
    route_cursored_logged_dkg_private_messages(&mut runtimes, [0usize, 2]);
    let (status, deliveries) = runtimes[1]
        .drive_collect_it_vss_private_delivery_round(PartyId(2))
        .expect("collect it-vss deliveries");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::Collected {
            phase: DkgTransportPhase::VssShare,
            receiver: Some(PartyId(2)),
            ..
        }
    ));
    assert_eq!(deliveries.len(), 2);
    assert_eq!(
        runtimes[1]
            .runtime()
            .recover_it_vss_private_delivery_round_from_log(PartyId(2))
            .expect("recover deliveries"),
        deliveries
    );

    let complaints = verify_it_vss_private_deliveries_for_receiver::<MlDsa65, _>(
        &backend,
        &config,
        PartyId(2),
        &public_commitments,
        &deliveries,
    )
    .expect("verify receiver deliveries");
    assert_eq!(complaints.len(), 1);
    let complaint = complaints[0].clone();
    let bad_delivery = deliveries
        .iter()
        .find(|delivery| delivery.dealer == complaint.dealer)
        .expect("bad delivery");
    let commitment = public_commitments
        .iter()
        .find(|commitment| commitment.dealer == complaint.dealer)
        .expect("bad commitment");
    let evidence = decode_it_vss_information_check_complaint_evidence(&complaint.evidence)
        .expect("decode evidence");
    validate_it_vss_information_check_complaint_evidence_for_delivery(
        &config,
        commitment,
        bad_delivery,
        &evidence,
    )
    .expect("evidence binds delivery");
    validate_it_vss_complaints_against_private_deliveries(
        &config,
        &public_commitments,
        &deliveries,
        core::slice::from_ref(&complaint),
    )
    .expect("complaint binds accepted delivery");

    let resolution = backend
        .resolve_complaints::<MlDsa65>(
            &config,
            &public_commitments,
            core::slice::from_ref(&complaint),
        )
        .expect("resolve complaint");
    assert_eq!(resolution.rejected_dealers, parties(&[1]));
    runtimes[1]
        .runtime_mut()
        .persist_it_vss_resolution_logged(&resolution)
        .expect("persist resolution");
    let (recovered_commitments, recovered_resolution) = runtimes[1]
        .runtime()
        .recover_it_vss_artifacts_from_log()
        .expect("recover it-vss artifacts");
    assert_eq!(recovered_commitments, public_commitments);
    assert_eq!(recovered_resolution, Some(resolution));
}

#[test]
fn it_vss_small_residue_driver_runs_public_private_verify_and_complaint_phases() {
    let config = config();
    let label = SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 9).expect("label");
    let contributions =
        small_contributions::<MlDsa65>(&config, SecretVectorKind::S1, 9, &[1, 2, 3]);
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);
    let mut backend = DeterministicItVssTestBackend::new([0xc1; 32]);

    for (runtime, contribution) in runtimes.iter_mut().zip(&contributions) {
        runtime
            .drive_share_small_residue_it_vss::<MlDsa65, _>(&mut backend, &config, contribution)
            .expect("drive it-vss residue sharing");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (_, public_commitments) = runtimes[1]
        .drive_collect_it_vss_public_commitments()
        .expect("collect public commitments");
    assert_eq!(public_commitments.len(), config.parties.len());

    route_cursored_logged_dkg_private_messages(&mut runtimes, [0usize, 2]);
    let complaints = runtimes[1]
        .drive_verify_it_vss_private_deliveries::<MlDsa65, _>(
            &backend,
            &config,
            &public_commitments,
        )
        .expect("verify private deliveries");
    assert!(complaints.is_empty());
    assert_eq!(
        runtimes[1]
            .cursor_log()
            .latest_setup_phase_cursor()
            .expect("latest cursor")
            .it_vss_phase,
        Some(ProductionItVssComplaintPhase::BroadcastComplaints)
    );

    let (persisted_commitments, resolution) =
        persist_logged_sampler_it_vss_artifacts_for_labels_from_phase_logs::<MlDsa65, _, _, _>(
            &config,
            runtimes[1].runtime_mut(),
            &backend,
            &[label],
        )
        .expect("persist sampler it-vss phase artifacts");
    assert_eq!(persisted_commitments, public_commitments);
    assert_eq!(resolution.accepted_dealers, config.parties);
    validate_it_vss_complaint_resolution_for_backend(
        &config,
        &public_commitments,
        &resolution,
        backend.backend_id(),
    )
    .expect("valid resolution");
    let (_, recovered_resolution) = runtimes[1]
        .runtime()
        .recover_it_vss_artifacts_from_log()
        .expect("recover persisted sampler resolution");
    assert_eq!(recovered_resolution, Some(resolution));

    let inputs = verified_small_residue_inputs_from_recovered_it_vss_artifacts::<MlDsa65>(
        &config,
        label,
        &contributions,
        &public_commitments,
    )
    .expect("verified inputs from artifacts");
    let mut sampler = InProcessDistributedSmallSampler::new([0xc2; 32]);
    let coeff = sampler
        .sample_verified_small_coeff::<MlDsa65>(&config, label, &inputs)
        .expect("sample verified coefficient");
    assert_eq!(coeff.label.coefficient_index, label.coefficient_index);
    assert_eq!(
        classify_dkg_setup_restart(runtimes[1].cursor_log().latest_setup_phase_cursor()),
        DkgSetupRestartDecision::ReplaySentThenResume
    );
}

#[test]
fn it_vss_small_residue_vector_driver_certifies_full_sampler_vectors() {
    let config = config_for::<MlDsa44>();
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);
    let mut backend = DeterministicItVssTestBackend::new([0xc3; 32]);
    let mut public_commitments = Vec::new();
    let mut private_offsets = runtimes
        .iter()
        .map(|runtime| {
            runtime
                .runtime()
                .state()
                .transport()
                .private_messages()
                .len()
        })
        .collect::<Vec<_>>();
    let mut broadcast_offsets = runtimes
        .iter()
        .map(|runtime| {
            runtime
                .runtime()
                .state()
                .transport()
                .broadcast_deliveries()
                .len()
        })
        .collect::<Vec<_>>();

    for vector in [SecretVectorKind::S1, SecretVectorKind::S2] {
        let rounds = constant_small_polyvec_contributions::<MlDsa44>(&config, vector, &[1, 2, 3]);

        for round in &rounds {
            for (runtime, contribution) in runtimes.iter_mut().zip(round) {
                runtime
                    .drive_broadcast_small_residue(contribution)
                    .expect("broadcast raw sampler residue");
            }
            route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
            runtimes[1]
                .drive_collect_small_residue_round(
                    round[0].label,
                    SmallSecretEta::for_params::<MlDsa44>().expect("eta"),
                )
                .expect("collect raw sampler residue");
            for runtime in &mut runtimes {
                runtime
                    .runtime_mut()
                    .state_mut()
                    .transport_mut()
                    .clear_queued_messages();
            }
        }

        for runtime in &mut runtimes {
            let dealer_contributions =
                dealer_small_polyvec_contributions(&rounds, runtime.local_party());
            runtime
                .drive_share_small_residue_vector_it_vss::<MlDsa44, _>(
                    &mut backend,
                    &config,
                    vector,
                    &dealer_contributions,
                )
                .expect("drive vector sampler it-vss");
        }

        route_cursored_logged_dkg_new_broadcast_messages(
            &mut runtimes,
            [0usize, 1, 2],
            &mut broadcast_offsets,
        );
        let (_, vector_commitments) = runtimes[1]
            .drive_collect_it_vss_public_commitments()
            .expect("collect vector-domain public commitments");
        let expected_keys =
            expected_sampler_vector_it_vss_keys(&config, core::slice::from_ref(&vector))
                .expect("expected vector keys");
        let vector_commitments =
            select_expected_it_vss_public_commitments(&vector_commitments, &expected_keys)
                .expect("selected vector commitments");
        assert_eq!(vector_commitments.len(), config.parties.len());
        public_commitments.extend(vector_commitments.clone());

        route_cursored_logged_dkg_new_private_messages(
            &mut runtimes,
            [0usize, 1, 2],
            &mut private_offsets,
        );
        let receiver = runtimes[1].local_party();
        let (_, deliveries) = runtimes[1]
            .drive_collect_it_vss_private_delivery_round(receiver)
            .expect("collect vector-domain private deliveries");
        for delivery in &deliveries {
            assert!(
                vector_commitments.iter().any(|commitment| {
                    commitment.dealer == delivery.dealer
                        && commitment.label_hash == delivery.label_hash
                }),
                "missing commitment for vector {:?} {:?} {:?}",
                vector,
                delivery.dealer,
                delivery.label_hash
            );
        }
        let complaints = verify_it_vss_private_deliveries_for_receiver::<MlDsa44, _>(
            &backend,
            &config,
            receiver,
            &vector_commitments,
            &deliveries,
        )
        .expect("verify vector-domain private deliveries");
        assert!(complaints.is_empty());
        runtimes[1]
            .persist_it_vss_complaint_phase_cursor(
                ProductionItVssComplaintPhase::BroadcastComplaints,
                DkgSetupPhaseCursorState::Sent,
                complaints.len(),
                complaints.len(),
            )
            .expect("persist complaint phase cursor");

        for runtime in &mut runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
        for (idx, runtime) in runtimes.iter().enumerate() {
            private_offsets[idx] = runtime
                .runtime()
                .state()
                .transport()
                .private_messages()
                .len();
            broadcast_offsets[idx] = runtime
                .runtime()
                .state()
                .transport()
                .broadcast_deliveries()
                .len();
        }
    }
    assert_eq!(public_commitments.len(), config.parties.len() * 2);
    for vector in [SecretVectorKind::S1, SecretVectorKind::S2] {
        for &dealer in &config.parties {
            let label = ItVssSharingLabel::new(
                &config,
                dealer,
                ItVssSharingDomain::for_secret_vector(vector),
                None,
            )
            .expect("vector-domain label");
            assert!(public_commitments.iter().any(|commitment| {
                commitment.dealer == dealer && commitment.label_hash == label.label_hash
            }));
        }
    }

    let (persisted_commitments, resolution) =
        persist_logged_sampler_it_vss_artifacts_from_phase_logs::<MlDsa44, _, _, _>(
            &config,
            runtimes[1].runtime_mut(),
            &backend,
        )
        .expect("persist vector-domain sampler artifacts");
    assert_eq!(persisted_commitments, public_commitments);
    assert_eq!(resolution.accepted_dealers, config.parties);

    let mut sampler = InProcessDistributedSmallSampler::new([0xc4; 32]);
    let s1 = sample_logged_small_polyvec_from_certified_log::<MlDsa44, _, _>(
        &mut sampler,
        &config,
        runtimes[1].runtime(),
        SecretVectorKind::S1,
    )
    .expect("sample certified s1");
    let s2 = sample_logged_small_polyvec_from_certified_log::<MlDsa44, _, _>(
        &mut sampler,
        &config,
        runtimes[1].runtime(),
        SecretVectorKind::S2,
    )
    .expect("sample certified s2");
    assert_eq!(s1.coefficients.len(), MlDsa44::L * MlDsa44::N);
    assert_eq!(s2.coefficients.len(), MlDsa44::K * MlDsa44::N);
    assert_eq!(
        runtimes[1]
            .cursor_log()
            .latest_setup_phase_cursor()
            .expect("latest cursor")
            .it_vss_phase,
        Some(ProductionItVssComplaintPhase::BroadcastComplaints)
    );
}

#[test]
fn in_memory_native_dkg_scaffold_coordinator_drives_setup_and_assembly() {
    let config = config_for::<MlDsa44>();
    let mut coordinator =
        InMemoryNativeDkgScaffoldCoordinator::new(config.clone()).expect("coordinator");
    let mut power2round = ClearSimPower2RoundBackend;
    let assembled = coordinator
        .drive_setup_and_assemble::<MlDsa44, _>(
            PartyId(2),
            [0xd1; 32],
            [0xd2; 32],
            [0xd3; 32],
            [0xd4; 32],
            &mut power2round,
        )
        .expect("coordinated setup and assembly");

    assembled
        .public
        .validate_binding()
        .expect("valid coordinated output");
    assert_eq!(assembled.key_packages.len(), config.parties.len());
    assert_eq!(assembled.accepted_dealers, config.parties);
    assert!(assembled.rejected_dealers.is_empty());
    assert!(assembled.complaints.is_empty());
    assert_eq!(
        ensure_native_dkg_assembly_output_allowed_for_release(&assembled),
        Err(DkgError::InsecurePower2RoundBackend)
    );
    assert_eq!(
        assembled.certificate.power2round.backend_id,
        Power2RoundBackendId::InsecureClearSimulator
    );
    let receiver_runtime = coordinator.runtime(PartyId(2)).expect("receiver runtime");
    ensure_logged_dkg_setup_matches_certificate::<MlDsa44, _, _>(
        &config,
        receiver_runtime.runtime(),
        &assembled.certificate,
    )
    .expect("coordinated setup log matches certificate");
    let (public_commitments, resolution) = receiver_runtime
        .runtime()
        .recover_it_vss_artifacts_from_log()
        .expect("recover coordinator artifacts");
    assert_eq!(public_commitments.len(), config.parties.len() * 2);
    assert_eq!(
        resolution.expect("resolution").accepted_dealers,
        config.parties
    );
    assert_eq!(
        classify_dkg_setup_restart(receiver_runtime.cursor_log().latest_setup_phase_cursor()),
        DkgSetupRestartDecision::Complete
    );
}

#[cfg(feature = "std")]
#[test]
fn file_it_vss_phase_driver_resumes_resolution_artifact_after_reopen() {
    let config = config();
    let mut backend = DeterministicItVssTestBackend::new([0xa2; 32]);
    let outputs = config
        .parties
        .iter()
        .copied()
        .map(|dealer| {
            let label = ItVssSharingLabel::new(
                &config,
                dealer,
                ItVssSharingDomain::PrimeFieldMpcAux,
                Some(8),
            )
            .expect("label");
            backend
                .share_secret::<MlDsa65>(&config, label, &[dealer.0 as u8, 10])
                .expect("share")
        })
        .collect::<Vec<_>>();
    let public_commitments = outputs
        .iter()
        .map(|output| output.public_commitment.clone())
        .collect::<Vec<_>>();
    let resolution = backend
        .resolve_complaints::<MlDsa65>(&config, &public_commitments, &[])
        .expect("resolve");
    let path = std::env::temp_dir().join(format!(
        "talus-it-vss-phase-driver-{}-{}.log",
        std::process::id(),
        config.epoch.0
    ));
    let _ = std::fs::remove_file(&path);
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state =
        DkgTransportStateMachine::new(config.clone(), PartyId(1), transport).expect("state");
    let log = FileDkgWireMessageLog::open(&path).expect("open log");
    let mut runtime = LoggedDkgTransportPartyRuntime::new(state, log);
    runtime
        .persist_it_vss_artifacts_logged(&public_commitments, &resolution)
        .expect("persist artifacts");

    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state =
        DkgTransportStateMachine::new(config.clone(), PartyId(1), transport).expect("state");
    let reopened_log = FileDkgWireMessageLog::open(&path).expect("reopen log");
    let reopened = LoggedDkgTransportPartyRuntime::new(state, reopened_log);
    let (recovered_commitments, recovered_resolution) = reopened
        .recover_it_vss_artifacts_from_log()
        .expect("recover artifacts");
    assert_eq!(recovered_commitments, public_commitments);
    assert_eq!(recovered_resolution, Some(resolution));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn small_sampler_polyvec_shapes_match_all_parameter_sets() {
    fn check<P: MlDsaParams>(expected_s1: usize, expected_s2: usize) {
        let config = config_for::<P>();
        let mut sampler = InProcessDistributedSmallSampler::new([0x71; 32]);
        let s1 = sampler
            .sample_small_polyvec::<P>(
                &config,
                SecretVectorKind::S1,
                &small_polyvec_contributions::<P>(&config, SecretVectorKind::S1),
            )
            .expect("sample s1");
        let s2 = sampler
            .sample_small_polyvec::<P>(
                &config,
                SecretVectorKind::S2,
                &small_polyvec_contributions::<P>(&config, SecretVectorKind::S2),
            )
            .expect("sample s2");

        assert_eq!(s1.coefficients.len(), expected_s1);
        assert_eq!(s2.coefficients.len(), expected_s2);
        assert_eq!(s1.eta, SmallSecretEta::for_params::<P>().expect("eta"));
        assert_eq!(s2.eta, SmallSecretEta::for_params::<P>().expect("eta"));
    }

    check::<MlDsa44>(4 * 256, 4 * 256);
    check::<MlDsa65>(5 * 256, 6 * 256);
    check::<MlDsa87>(7 * 256, 8 * 256);
}

#[test]
fn small_sampler_transcript_label_binds_vector_and_coefficient() {
    let config = config();
    let eta = SmallSecretEta::for_params::<MlDsa65>().expect("eta");
    let s1_label = SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 0).expect("label");
    let s2_label = SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S2, 0).expect("label");
    let index_label =
        SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 1).expect("label");
    assert_ne!(s1_label, s2_label);
    assert_ne!(s1_label, index_label);

    let contributions = [
        SmallResidueContribution::new(PartyId(1), s2_label, eta, 0),
        SmallResidueContribution::new(PartyId(2), s2_label, eta, 1),
        SmallResidueContribution::new(PartyId(3), s2_label, eta, 2),
    ];
    assert_eq!(
        sum_small_residues_mod(&config, s1_label, eta, &contributions),
        Err(DkgError::SmallSamplerLabelMismatch)
    );
}

#[test]
fn sampled_s1_wires_to_dkg_secret_share_packages() {
    let config = config();
    let material = sampled_material::<MlDsa65>(&config).expect("sample material");
    let secret_shares =
        sampled_s1_to_dkg_secret_shares::<MlDsa65>(&config, &material.s1).expect("s1 packages");
    assert_eq!(secret_shares.len(), config.parties.len());
    for secret in secret_shares {
        let decoded = BoundedSecretVectorShare::decode::<MlDsa65>(&config, &secret.s1_share)
            .expect("decode sampled s1");
        assert_eq!(decoded.party, secret.party);
        assert_eq!(decoded.coeffs.len(), MlDsa65::L * MlDsa65::N);
    }

    let s2_party_shares = shared_small_polyvec_party_shares::<MlDsa65>(&config, &material.s2)
        .expect("temporary s2 shares");
    assert_eq!(s2_party_shares.len(), config.parties.len());
    assert!(s2_party_shares
        .iter()
        .all(|share| share.coeffs.len() == MlDsa65::K * MlDsa65::N));
}

#[test]
fn public_key_assembly_scaffold_opens_t1_only_shape() {
    let config = config();
    let material = sampled_material::<MlDsa65>(&config).expect("sample material");
    let rho = [0x91; 32];
    let mut power2round = ClearSimPower2RoundBackend;
    let (output, certificate) = assemble_public_output_scaffold::<MlDsa65, _>(
        &config,
        rho,
        material,
        &config.parties,
        &mut power2round,
    )
    .expect("assemble public output scaffold");

    assert_eq!(output.rho, rho);
    assert_eq!(output.t1.len(), config.suite.t1_len());
    assert_eq!(output.public_key.len(), config.suite.public_key_len());
    assert_eq!(&output.public_key[..32], &rho);
    assert_eq!(&output.public_key[32..], output.t1.as_slice());
    assert_eq!(
        certificate.power2round.backend_id,
        Power2RoundBackendId::InsecureClearSimulator
    );
    assert_eq!(certificate.power2round.suite, config.suite);
    output.validate_binding().expect("bound output");
}

#[test]
fn clear_sim_power2round_matches_clear_reference() {
    let config = config();
    let material = sampled_material::<MlDsa65>(&config).expect("sample material");
    let rho = [0x93; 32];
    let shared_t = assemble_shared_t::<MlDsa65>(&config, rho, &material.s1, material.s2.clone())
        .expect("shared t");
    let clear_t = reconstruct_shared_t::<MlDsa65>(&config, &shared_t).expect("reconstruct t");
    let expected = clear_t
        .polys()
        .iter()
        .flat_map(|poly| {
            poly.coeffs()
                .iter()
                .map(|&coeff| talus_core::power2round::<MlDsa65>(coeff).0 as u16)
        })
        .collect::<Vec<_>>();
    let mut backend = ClearSimPower2RoundBackend;
    let (public_t1, evidence) = backend
        .power2round_t1::<MlDsa65>(&config, shared_t)
        .expect("power2round");

    assert_eq!(public_t1.coeffs, expected);
    assert_eq!(public_t1.bytes.len(), config.suite.t1_len());
    assert_eq!(
        evidence.backend_id,
        Power2RoundBackendId::InsecureClearSimulator
    );
    assert_eq!(
        evidence.output_t1_hash,
        hash_bytes32(b"TALUS-DKG-v1/power2round-t1", &public_t1.bytes)
    );
}

#[test]
fn power2round_boundary_coefficients_match_fips_shape() {
    let cases = [
        (0, 0, 0),
        (4095, 0, 4095),
        (4096, 0, 4096),
        (4097, 1, -4095),
        (8191, 1, -1),
        (8192, 1, 0),
        (MlDsa65::Q - 4096, 1023, -4095),
        (MlDsa65::Q - 1, 1023, 0),
    ];

    for (input, expected_high, expected_low) in cases {
        assert_eq!(
            talus_core::power2round::<MlDsa65>(input),
            (expected_high, expected_low),
            "input {input}"
        );
    }
}

#[test]
fn prime_field_mpc_power2round_coeff_boundaries_match_reference() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x44; 32]);
    let cases = [
        0,
        4095,
        4096,
        4097,
        8191,
        8192,
        MlDsa65::Q - 4096,
        MlDsa65::Q - 1,
    ];

    for input in cases {
        let mut backend = LocalPrimeFieldMpcBackend::new([input as u8; 32]);
        let share = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
            &backend, input,
        );
        let got = power2round_t1_coeff::<MlDsa65, _>(
            &mut backend,
            share,
            root.child(format!("boundary_{input}")),
        )
        .expect("mpc power2round coeff");
        let expected = talus_core::power2round::<MlDsa65>(input).0 as u16;
        assert_eq!(got, expected, "input {input}");
        assert!(backend
            .opened_labels()
            .iter()
            .any(|label| label.ends_with("open_t1_bits")));
        assert!(!backend
            .opened_labels()
            .iter()
            .any(|label| label.contains("lower") || label.contains("t0")));
    }
}

#[test]
fn in_process_shamir_prime_field_mpc_power2round_coeff_boundaries() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x49; 32]);
    let cases = [0, 4097, 8192, MlDsa65::Q - 4096, MlDsa65::Q - 1];

    for input in cases {
        let mut backend =
            InProcessShamirPrimeFieldMpcBackend::new(config.clone(), [input as u8; 32]);
        let share =
            <InProcessShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                &backend, input,
            );
        let got = power2round_t1_coeff::<MlDsa65, _>(
            &mut backend,
            share,
            root.child(format!("shamir_boundary_{input}")),
        )
        .expect("shamir mpc power2round coeff");
        let expected = talus_core::power2round::<MlDsa65>(input).0 as u16;
        assert_eq!(got, expected, "input {input}");
        assert!(!backend.gate_labels().is_empty());
        assert!(backend
            .opened_labels()
            .iter()
            .all(|label| label.contains("open_mask_lt_q")
                || label.contains("open_masked_c")
                || label.contains("open_t1_bits")));
        assert!(!backend
            .opened_labels()
            .iter()
            .any(|label| label.contains("lower") || label.contains("t0")));
    }
}

#[test]
fn networked_shamir_prime_field_mpc_power2round_coeff_boundaries() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x4a; 32]);
    let cases = [0, 4097, 8192, MlDsa65::Q - 4096, MlDsa65::Q - 1];

    for input in cases {
        let mut backend =
            NetworkedShamirPrimeFieldMpcBackend::new(config.clone(), [input as u8; 32]);
        let share =
            <NetworkedShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                &backend, input,
            );
        let got = power2round_t1_coeff::<MlDsa65, _>(
            &mut backend,
            share,
            root.child(format!("networked_shamir_boundary_{input}")),
        )
        .expect("networked shamir mpc power2round coeff");
        let expected = talus_core::power2round::<MlDsa65>(input).0 as u16;
        assert_eq!(got, expected, "input {input}");

        let messages = backend.network().messages();
        assert!(messages
            .iter()
            .any(|message| message.kind == PrimeFieldMpcRoundKind::MulDegreeReduce));
        assert!(messages
            .iter()
            .any(|message| message.kind == PrimeFieldMpcRoundKind::Open));
        assert!(messages
            .iter()
            .any(|message| message.kind == PrimeFieldMpcRoundKind::AssertZero));
        assert!(messages
            .iter()
            .any(|message| message.kind == PrimeFieldMpcRoundKind::RandomBit));
        assert!(!backend.gate_labels().is_empty());
        assert!(backend
            .opened_labels()
            .iter()
            .all(|label| label.contains("open_mask_lt_q")
                || label.contains("open_masked_c")
                || label.contains("open_t1_bits")));
        assert!(!backend
            .opened_labels()
            .iter()
            .any(|label| label.contains("lower") || label.contains("t0")));
    }
}

#[test]
fn transport_backed_shamir_prime_field_mpc_power2round_coeff_boundaries() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x60; 32]);
    let cases = [0, 4097, 8192, MlDsa65::Q - 4096, MlDsa65::Q - 1];

    for input in cases {
        let mut backend =
            TransportBackedShamirPrimeFieldMpcBackend::new(config.clone(), [input as u8; 32]);
        let share = <TransportBackedShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<
            MlDsa65,
        >>::secret_share(&backend, input);
        let got = power2round_t1_coeff::<MlDsa65, _>(
            &mut backend,
            share,
            root.child(format!("transport_shamir_boundary_{input}")),
        )
        .expect("transport-backed shamir mpc power2round coeff");
        let expected = talus_core::power2round::<MlDsa65>(input).0 as u16;
        assert_eq!(got, expected, "input {input}");

        assert!(!backend.gate_labels().is_empty());
        assert!(backend.accepted_rounds().iter().any(|round| {
            round.kind == PrimeFieldMpcRoundKind::MulDegreeReduce
                && round.phase == PrimeFieldMpcPhase::MulDegreeReductionShare
        }));
        assert!(backend.accepted_rounds().iter().any(|round| {
            round.kind == PrimeFieldMpcRoundKind::Open
                && round.phase == PrimeFieldMpcPhase::OpenShare
        }));
        assert!(backend.accepted_rounds().iter().any(|round| {
            round.kind == PrimeFieldMpcRoundKind::Open
                && round.phase == PrimeFieldMpcPhase::T1BitOpening
        }));
        assert!(backend.accepted_rounds().iter().any(|round| {
            round.kind == PrimeFieldMpcRoundKind::AssertZero
                && round.phase == PrimeFieldMpcPhase::AssertZeroShare
        }));
        assert!(backend.accepted_rounds().iter().any(|round| {
            round.kind == PrimeFieldMpcRoundKind::RandomBit
                && round.phase == PrimeFieldMpcPhase::RandomBitShare
        }));
        assert!(backend
            .opened_labels()
            .iter()
            .all(|label| label.contains("open_mask_lt_q")
                || label.contains("open_masked_c")
                || label.contains("open_t1_bits")));
        assert!(!backend
            .opened_labels()
            .iter()
            .any(|label| label.contains("lower") || label.contains("t0")));
    }
}

#[test]
fn networked_prime_field_mpc_rejects_replayed_message_label() {
    let mut network = InMemoryPrimeFieldMpcNetwork::default();
    let message = PrimeFieldMpcMessage {
        sender: PartyId(1),
        receiver: Some(PartyId(2)),
        kind: PrimeFieldMpcRoundKind::Open,
        label_hash: [0x51; 32],
        value: 7,
    };

    assert_eq!(network.send(message.clone()), Ok(()));
    assert_eq!(
        network.send(message),
        Err(DkgError::PrimeFieldMpcReplayDetected)
    );
}

#[test]
fn transport_prime_field_mpc_state_machine_sends_and_collects_directed_rounds() {
    let config = config();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let label = Power2RoundTranscriptLabel::root(&config, [0x52; 32]).child("directed_open");

    state
        .send_directed_value(PartyId(2), PrimeFieldMpcRoundKind::Open, &label, 99)
        .expect("send directed value");
    let values = state
        .collect_directed_values(PartyId(2), PrimeFieldMpcRoundKind::Open, &label)
        .expect("collect directed values");

    assert_eq!(values, vec![(PartyId(1), 99)]);
    assert_eq!(state.accepted_rounds().len(), 1);
    assert_eq!(
        state.accepted_rounds()[0].kind,
        PrimeFieldMpcRoundKind::Open
    );
    assert_eq!(
        state.accepted_rounds()[0].phase,
        PrimeFieldMpcPhase::OpenShare
    );
    let mut log = InMemoryPrimeFieldMpcRoundLog::default();
    state
        .persist_accepted_rounds(&mut log)
        .expect("persist public round metadata");
    assert_eq!(log.accepted(), state.accepted_rounds());
    assert_eq!(
        state.persist_accepted_rounds(&mut log),
        Err(DkgError::PrimeFieldMpcReplayDetected)
    );
    assert_eq!(
        state.collect_directed_values(PartyId(2), PrimeFieldMpcRoundKind::Open, &label),
        Err(DkgError::PrimeFieldMpcReplayDetected)
    );

    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let random_label = Power2RoundTranscriptLabel::root(&config, [0x56; 32]).child("random_bit");
    state
        .send_random_bit_share(PartyId(2), &random_label, 1)
        .expect("send random-bit share");
    let values = state
        .collect_random_bit_shares(PartyId(2), &random_label)
        .expect("collect random-bit shares");
    assert_eq!(values, vec![(PartyId(1), 1)]);
}

#[test]
fn transport_prime_field_mpc_state_machine_sends_and_collects_vector_rounds() {
    let config = config();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let label = Power2RoundTranscriptLabel::root(&config, [0x7e; 32]).child("directed_vec");

    state
        .send_directed_phase_vec(
            PartyId(2),
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            &label,
            &[10, 20, 30],
        )
        .expect("send directed vector");
    let values = state
        .collect_directed_phase_vec(
            PartyId(2),
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            &label,
        )
        .expect("collect directed vector");
    assert_eq!(values, vec![(PartyId(1), vec![10, 20, 30])]);
    assert_eq!(state.accepted_rounds().len(), 1);
    assert_eq!(
        state.collect_directed_phase_vec(
            PartyId(2),
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            &label,
        ),
        Err(DkgError::PrimeFieldMpcReplayDetected)
    );

    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let label = Power2RoundTranscriptLabel::root(&config, [0x7f; 32]).child("broadcast_vec");
    for sender in [1u16, 2, 3] {
        let mut message = state
            .wire_message_vec(
                PrimeFieldMpcRoundKind::AssertZero,
                PrimeFieldMpcPhase::AssertZeroShare,
                &label,
                None,
                &[sender as Coeff, sender as Coeff + 10],
            )
            .expect("wire vector broadcast");
        message.header.sender_party_id = sender;
        for observer in [1u16, 2, 3] {
            state
                .transport_mut()
                .inject_broadcast_delivery(observer, message.clone())
                .expect("inject vector broadcast observer delivery");
        }
    }
    let values = state
        .collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::AssertZeroShare,
            &label,
        )
        .expect("collect broadcast vector");
    assert_eq!(
        values,
        vec![
            (PartyId(1), vec![1, 11]),
            (PartyId(2), vec![2, 12]),
            (PartyId(3), vec![3, 13]),
        ]
    );
}

#[test]
fn transport_prime_field_mpc_state_machine_accepts_pq_bound_context() {
    let config = config();
    let binding = talus_wire::PqTransportSessionBinding::new(
        wire_suite(config.suite),
        config.transcript_hash().0,
        &[3, 1, 2],
        [0x12; 32],
        [0x34; 32],
    )
    .expect("pq binding");
    assert_ne!(binding.session_id, prime_field_mpc_session_id(&config));

    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new_with_expected_context(
        config.clone(),
        PartyId(1),
        transport,
        binding.expected_context(),
    )
    .expect("state machine with app-supplied context");
    let label = Power2RoundTranscriptLabel::root(&config, [0x65; 32]).child("pq_context");

    state
        .send_directed_value(PartyId(2), PrimeFieldMpcRoundKind::Open, &label, 77)
        .expect("send directed value");
    let sent = &state.transport().private_messages()[0].message;
    assert_eq!(sent.header.session_id, binding.session_id);
    assert_eq!(
        sent.header.signing_set_hash,
        binding.expected_context().signing_set_hash
    );

    let values = state
        .collect_directed_values(PartyId(2), PrimeFieldMpcRoundKind::Open, &label)
        .expect("collect directed values under pq context");
    assert_eq!(values, vec![(PartyId(1), 77)]);

    let mut wrong_context = binding.expected_context();
    wrong_context.allowed_parties = vec![1, 2];
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    assert_eq!(
        TransportPrimeFieldMpcStateMachine::new_with_expected_context(
            config,
            PartyId(1),
            transport,
            wrong_context,
        )
        .map(|_| ()),
        Err(DkgError::PrimeFieldMpcContextMismatch)
    );
}

#[test]
fn single_party_phase_driver_handles_private_wait_reorder_duplicate_and_resume() {
    let config = config();
    let label = Power2RoundTranscriptLabel::root(&config, [0x66; 32]).child("driver_private");
    let mut runtimes = test_party_runtimes(&config);
    let mut cursor_log = InMemoryPrimeFieldMpcPhaseCursorLog::default();

    for (idx, runtime) in runtimes.iter_mut().enumerate() {
        let status = runtime
            .drive_send_directed_phase(
                PartyId(2),
                PrimeFieldMpcRoundKind::RandomBit,
                PrimeFieldMpcPhase::RandomBitShare,
                &label,
                (idx + 10) as Coeff,
            )
            .expect("send directed phase");
        assert!(matches!(
            status,
            PrimeFieldMpcPhaseDriverStatus::SentPrivate {
                receiver: PartyId(2),
                kind: PrimeFieldMpcRoundKind::RandomBit,
                phase: PrimeFieldMpcPhase::RandomBitShare,
                ..
            }
        ));
        cursor_log
            .persist_phase_cursor(&PrimeFieldMpcPhaseCursor::from_driver_status(&status))
            .expect("persist sent cursor");
    }
    assert_eq!(cursor_log.cursors().len(), 3);
    assert_eq!(
        cursor_log.latest_phase_cursor().expect("latest sent").state,
        PrimeFieldMpcPhaseCursorState::SentPrivate
    );

    route_private_messages(&mut runtimes, [0usize], false, false);
    let (status, values) = runtimes[1]
        .drive_collect_directed_phase(
            PartyId(2),
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::RandomBitShare,
            &label,
        )
        .expect("waiting private phase");
    assert_eq!(values, Vec::new());
    assert_eq!(
        status,
        PrimeFieldMpcPhaseDriverStatus::WaitingPrivate {
            receiver: PartyId(2),
            kind: PrimeFieldMpcRoundKind::RandomBit,
            phase: PrimeFieldMpcPhase::RandomBitShare,
            label_hash: power2round_label_hash(&label),
            expected: 3,
            got: 2,
        }
    );
    cursor_log
        .persist_phase_cursor(&PrimeFieldMpcPhaseCursor::from_driver_status(&status))
        .expect("persist waiting cursor");
    let latest = cursor_log.latest_phase_cursor().expect("latest waiting");
    assert_eq!(latest.receiver, Some(PartyId(2)));
    assert_eq!(latest.state, PrimeFieldMpcPhaseCursorState::WaitingPrivate);
    assert_eq!((latest.expected, latest.got), (3, 2));

    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let mut resumed =
        TransportPrimeFieldMpcPartyRuntime::new(state, runtimes[0].wire_log().clone());
    resumed
        .resume_sent_messages()
        .expect("resume sent messages");
    assert_eq!(resumed.state().transport().private_messages().len(), 1);
    assert_eq!(
        decode_dkg_prime_field_mpc_payload(
            &resumed.state().transport().private_messages()[0]
                .message
                .payload
        )
        .expect("payload")
        .value,
        10
    );

    route_private_messages(&mut runtimes, [1usize, 2], true, false);
    let (status, mut values) = runtimes[1]
        .drive_collect_directed_phase(
            PartyId(2),
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::RandomBitShare,
            &label,
        )
        .expect("collect private phase");
    values.sort_by_key(|(party, _)| party.0);
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::Collected {
            kind: PrimeFieldMpcRoundKind::RandomBit,
            phase: PrimeFieldMpcPhase::RandomBitShare,
            ..
        }
    ));
    cursor_log
        .persist_phase_cursor(&PrimeFieldMpcPhaseCursor::from_driver_status(&status))
        .expect("persist collected cursor");
    let latest = cursor_log.latest_phase_cursor().expect("latest collected");
    assert_eq!(latest.receiver, Some(PartyId(2)));
    assert_eq!(latest.state, PrimeFieldMpcPhaseCursorState::Collected);
    assert_eq!((latest.expected, latest.got), (3, 3));
    assert_eq!(
        values,
        vec![(PartyId(1), 10), (PartyId(2), 11), (PartyId(3), 12)]
    );

    let transport = talus_wire::InMemoryTransport::new(2, vec![1, 2, 3]).expect("transport");
    let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(2), transport)
        .expect("state machine");
    let mut recovered =
        TransportPrimeFieldMpcPartyRuntime::new(state, runtimes[1].wire_log().clone());
    let mut recovered_values = recovered
        .recover_random_bit_shares(PartyId(2), &label)
        .expect("recover accepted values");
    recovered_values.sort_by_key(|(party, _)| party.0);
    assert_eq!(recovered_values, values);

    let mut duplicated = test_party_runtimes(&config);
    for (idx, runtime) in duplicated.iter_mut().enumerate() {
        runtime
            .drive_send_directed_phase(
                PartyId(2),
                PrimeFieldMpcRoundKind::RandomBit,
                PrimeFieldMpcPhase::RandomBitShare,
                &label.child("duplicate"),
                idx as Coeff,
            )
            .expect("send duplicate test");
    }
    route_private_messages(&mut duplicated, [0usize, 1, 2], false, true);
    assert_eq!(
        duplicated[1]
            .drive_collect_directed_phase(
                PartyId(2),
                PrimeFieldMpcRoundKind::RandomBit,
                PrimeFieldMpcPhase::RandomBitShare,
                &label.child("duplicate"),
            )
            .map(|_| ()),
        Err(DkgError::PrimeFieldMpcTransport)
    );
}

#[test]
fn single_party_phase_driver_handles_broadcast_wait_and_equivocation() {
    let config = config();
    let label = Power2RoundTranscriptLabel::root(&config, [0x67; 32]).child("driver_broadcast");
    let mut runtimes = test_party_runtimes(&config);
    for (idx, runtime) in runtimes.iter_mut().enumerate() {
        runtime
            .drive_broadcast_phase(
                PrimeFieldMpcRoundKind::Open,
                PrimeFieldMpcPhase::OpenShare,
                &label,
                (idx + 20) as Coeff,
            )
            .expect("broadcast phase");
    }

    route_broadcast_messages(&mut runtimes, [0usize], true, None);
    let (status, values) = runtimes[0]
        .drive_collect_broadcast_phase(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            &label,
        )
        .expect("waiting broadcast phase");
    assert_eq!(values, Vec::new());
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
            kind: PrimeFieldMpcRoundKind::Open,
            phase: PrimeFieldMpcPhase::OpenShare,
            expected: 3,
            ..
        }
    ));

    route_broadcast_messages(&mut runtimes, [0usize, 1, 2], false, None);
    let (status, mut values) = runtimes[0]
        .drive_collect_broadcast_phase(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            &label,
        )
        .expect("collect broadcast phase");
    values.sort_by_key(|(party, _)| party.0);
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::Collected {
            kind: PrimeFieldMpcRoundKind::Open,
            phase: PrimeFieldMpcPhase::OpenShare,
            ..
        }
    ));
    assert_eq!(
        values,
        vec![(PartyId(1), 20), (PartyId(2), 21), (PartyId(3), 22)]
    );

    let mut equivocated = test_party_runtimes(&config);
    let eq_label = label.child("equivocation");
    for (idx, runtime) in equivocated.iter_mut().enumerate() {
        runtime
            .drive_broadcast_phase(
                PrimeFieldMpcRoundKind::Open,
                PrimeFieldMpcPhase::OpenShare,
                &eq_label,
                (idx + 30) as Coeff,
            )
            .expect("broadcast equivocation test");
    }
    route_broadcast_messages(&mut equivocated, [0usize, 1, 2], false, Some(PartyId(2).0));
    assert_eq!(
        equivocated[0]
            .drive_collect_broadcast_phase(
                PrimeFieldMpcRoundKind::Open,
                PrimeFieldMpcPhase::OpenShare,
                &eq_label,
            )
            .map(|_| ()),
        Err(DkgError::PrimeFieldMpcTransport)
    );
}

#[test]
fn single_party_phase_driver_handles_masked_opening_vector_broadcast() {
    let config = config();
    let label = Power2RoundTranscriptLabel::root(&config, [0x87; 32]).child("power2round_t1_vec");
    let mut runtimes = test_party_runtimes(&config);
    for (idx, runtime) in runtimes.iter_mut().enumerate() {
        runtime
            .drive_power2round_masked_c_vec(
                &label,
                &[(idx + 1) as Coeff, (idx + 11) as Coeff, (idx + 21) as Coeff],
            )
            .expect("broadcast masked opening vector");
    }

    route_broadcast_messages(&mut runtimes, [0usize], true, None);
    let (status, values) = runtimes[0]
        .drive_collect_power2round_masked_c_vec(&label)
        .expect("waiting masked opening vector");
    assert_eq!(values, Vec::new());
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
            kind: PrimeFieldMpcRoundKind::Open,
            phase: PrimeFieldMpcPhase::Power2RoundMaskedOpenC,
            expected: 3,
            ..
        }
    ));

    route_broadcast_messages(&mut runtimes, [0usize, 1, 2], false, None);
    let (status, mut values) = runtimes[0]
        .drive_collect_power2round_masked_c_vec(&label)
        .expect("collect masked opening vector");
    values.sort_by_key(|(party, _)| party.0);
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::Collected {
            kind: PrimeFieldMpcRoundKind::Open,
            phase: PrimeFieldMpcPhase::Power2RoundMaskedOpenC,
            ..
        }
    ));
    assert_eq!(
        values,
        vec![
            (PartyId(1), vec![1, 11, 21]),
            (PartyId(2), vec![2, 12, 22]),
            (PartyId(3), vec![3, 13, 23]),
        ]
    );
    assert!(runtimes[0]
        .wire_log()
        .records()
        .iter()
        .any(|record| record.direction == PrimeFieldMpcWireDirection::AcceptedBroadcast));

    let saved_log = runtimes[0].wire_log().clone();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state =
        TransportPrimeFieldMpcStateMachine::new(config, PartyId(1), transport).expect("state");
    let mut recovered = TransportPrimeFieldMpcPartyRuntime::new(state, saved_log.clone());
    let mut recovered_values = recovered
        .state_mut()
        .collect_broadcast_phase_vec_from_wire_log(
            &saved_log,
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::Power2RoundMaskedOpenC,
            &label.child("open_masked_c"),
        )
        .expect("recover masked opening vector from wire log");
    recovered_values.sort_by_key(|(party, _)| party.0);
    assert_eq!(recovered_values, values);
}

#[test]
fn single_party_phase_driver_handles_wrap_compare_vector_broadcast() {
    let config = config();
    let label = Power2RoundTranscriptLabel::root(&config, [0x89; 32]).child("power2round_t1_vec");
    let mut runtimes = test_party_runtimes(&config);
    for (idx, runtime) in runtimes.iter_mut().enumerate() {
        runtime
            .drive_power2round_wrap_compare_vec(
                &label,
                &[(idx % 2) as Coeff, ((idx + 1) % 2) as Coeff, 1],
            )
            .expect("broadcast wrap comparison vector");
    }

    route_broadcast_messages(&mut runtimes, [0usize], true, None);
    let (status, values) = runtimes[0]
        .drive_collect_power2round_wrap_compare_vec(&label)
        .expect("waiting wrap comparison vector");
    assert_eq!(values, Vec::new());
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
            kind: PrimeFieldMpcRoundKind::AssertZero,
            phase: PrimeFieldMpcPhase::Power2RoundWrapCompare,
            expected: 3,
            ..
        }
    ));

    route_broadcast_messages(&mut runtimes, [0usize, 1, 2], false, None);
    let (status, mut values) = runtimes[0]
        .drive_collect_power2round_wrap_compare_vec(&label)
        .expect("collect wrap comparison vector");
    values.sort_by_key(|(party, _)| party.0);
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::Collected {
            kind: PrimeFieldMpcRoundKind::AssertZero,
            phase: PrimeFieldMpcPhase::Power2RoundWrapCompare,
            ..
        }
    ));
    assert_eq!(
        values,
        vec![
            (PartyId(1), vec![0, 1, 1]),
            (PartyId(2), vec![1, 0, 1]),
            (PartyId(3), vec![0, 1, 1]),
        ]
    );

    let saved_log = runtimes[0].wire_log().clone();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state =
        TransportPrimeFieldMpcStateMachine::new(config, PartyId(1), transport).expect("state");
    let mut recovered = TransportPrimeFieldMpcPartyRuntime::new(state, saved_log.clone());
    let mut recovered_values = recovered
        .state_mut()
        .collect_broadcast_phase_vec_from_wire_log(
            &saved_log,
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundWrapCompare,
            &label.child("a_gt_c"),
        )
        .expect("recover wrap comparison vector from wire log");
    recovered_values.sort_by_key(|(party, _)| party.0);
    assert_eq!(recovered_values, values);
}

#[test]
fn single_party_phase_driver_handles_subtractor_vector_broadcast() {
    let config = config();
    let label = Power2RoundTranscriptLabel::root(&config, [0x8b; 32]).child("power2round_t1_vec");
    let mut runtimes = test_party_runtimes(&config);
    for (idx, runtime) in runtimes.iter_mut().enumerate() {
        runtime
            .drive_power2round_subtractor_share_vec(
                &label,
                7,
                &[(idx + 3) as Coeff, (idx + 13) as Coeff, (idx + 23) as Coeff],
            )
            .expect("broadcast subtractor vector");
    }

    route_broadcast_messages(&mut runtimes, [0usize], true, None);
    let (status, values) = runtimes[0]
        .drive_collect_power2round_subtractor_share_vec(&label, 7)
        .expect("waiting subtractor vector");
    assert_eq!(values, Vec::new());
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
            kind: PrimeFieldMpcRoundKind::AssertZero,
            phase: PrimeFieldMpcPhase::SubtractorShare,
            expected: 3,
            ..
        }
    ));

    route_broadcast_messages(&mut runtimes, [0usize, 1, 2], false, None);
    let (status, mut values) = runtimes[0]
        .drive_collect_power2round_subtractor_share_vec(&label, 7)
        .expect("collect subtractor vector");
    values.sort_by_key(|(party, _)| party.0);
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::Collected {
            kind: PrimeFieldMpcRoundKind::AssertZero,
            phase: PrimeFieldMpcPhase::SubtractorShare,
            ..
        }
    ));
    assert_eq!(
        values,
        vec![
            (PartyId(1), vec![3, 13, 23]),
            (PartyId(2), vec![4, 14, 24]),
            (PartyId(3), vec![5, 15, 25]),
        ]
    );

    let saved_log = runtimes[0].wire_log().clone();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state =
        TransportPrimeFieldMpcStateMachine::new(config, PartyId(1), transport).expect("state");
    let mut recovered = TransportPrimeFieldMpcPartyRuntime::new(state, saved_log.clone());
    let mut recovered_values = recovered
        .state_mut()
        .collect_broadcast_phase_vec_from_wire_log(
            &saved_log,
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::SubtractorShare,
            &label.child("recover_r_bits/subtract_bit_7"),
        )
        .expect("recover subtractor vector from wire log");
    recovered_values.sort_by_key(|(party, _)| party.0);
    assert_eq!(recovered_values, values);
}

#[test]
fn single_party_phase_driver_handles_canonical_check_vector_broadcasts() {
    let config = config();
    let label = Power2RoundTranscriptLabel::root(&config, [0x8d; 32]).child("power2round_t1_vec");

    let mut bitness_runtimes = test_party_runtimes(&config);
    for (idx, runtime) in bitness_runtimes.iter_mut().enumerate() {
        runtime
            .drive_power2round_canonical_bitness_check_vec(
                &label,
                4,
                &[(idx + 2) as Coeff, (idx + 12) as Coeff],
            )
            .expect("broadcast canonical bitness vector");
    }
    route_broadcast_messages(&mut bitness_runtimes, [0usize], true, None);
    let (status, values) = bitness_runtimes[0]
        .drive_collect_power2round_canonical_bitness_check_vec(&label, 4)
        .expect("waiting canonical bitness vector");
    assert_eq!(values, Vec::new());
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
            kind: PrimeFieldMpcRoundKind::AssertZero,
            phase: PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck,
            expected: 3,
            ..
        }
    ));
    route_broadcast_messages(&mut bitness_runtimes, [0usize, 1, 2], false, None);
    let (status, mut values) = bitness_runtimes[0]
        .drive_collect_power2round_canonical_bitness_check_vec(&label, 4)
        .expect("collect canonical bitness vector");
    values.sort_by_key(|(party, _)| party.0);
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::Collected {
            kind: PrimeFieldMpcRoundKind::AssertZero,
            phase: PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck,
            ..
        }
    ));
    assert_eq!(
        values,
        vec![
            (PartyId(1), vec![2, 12]),
            (PartyId(2), vec![3, 13]),
            (PartyId(3), vec![4, 14]),
        ]
    );
    let saved_log = bitness_runtimes[0].wire_log().clone();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state");
    let mut recovered = TransportPrimeFieldMpcPartyRuntime::new(state, saved_log.clone());
    let mut recovered_values = recovered
        .state_mut()
        .collect_broadcast_phase_vec_from_wire_log(
            &saved_log,
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck,
            &label.child("r_bits_boolean/bit_4/assert_zero"),
        )
        .expect("recover canonical bitness vector from wire log");
    recovered_values.sort_by_key(|(party, _)| party.0);
    assert_eq!(recovered_values, values);

    let mut range_runtimes = test_party_runtimes(&config);
    for (idx, runtime) in range_runtimes.iter_mut().enumerate() {
        runtime
            .drive_power2round_canonical_range_check_vec(
                &label,
                &[(idx + 5) as Coeff, (idx + 15) as Coeff],
            )
            .expect("broadcast canonical range vector");
    }
    route_broadcast_messages(&mut range_runtimes, [0usize], true, None);
    let (status, values) = range_runtimes[0]
        .drive_collect_power2round_canonical_range_check_vec(&label)
        .expect("waiting canonical range vector");
    assert_eq!(values, Vec::new());
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
            kind: PrimeFieldMpcRoundKind::AssertZero,
            phase: PrimeFieldMpcPhase::Power2RoundCanonicalRangeCheck,
            expected: 3,
            ..
        }
    ));
    route_broadcast_messages(&mut range_runtimes, [0usize, 1, 2], false, None);
    let (status, mut values) = range_runtimes[0]
        .drive_collect_power2round_canonical_range_check_vec(&label)
        .expect("collect canonical range vector");
    values.sort_by_key(|(party, _)| party.0);
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::Collected {
            kind: PrimeFieldMpcRoundKind::AssertZero,
            phase: PrimeFieldMpcPhase::Power2RoundCanonicalRangeCheck,
            ..
        }
    ));
    assert_eq!(
        values,
        vec![
            (PartyId(1), vec![5, 15]),
            (PartyId(2), vec![6, 16]),
            (PartyId(3), vec![7, 17]),
        ]
    );
    let saved_log = range_runtimes[0].wire_log().clone();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state");
    let mut recovered = TransportPrimeFieldMpcPartyRuntime::new(state, saved_log.clone());
    let mut recovered_values = recovered
        .state_mut()
        .collect_broadcast_phase_vec_from_wire_log(
            &saved_log,
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundCanonicalRangeCheck,
            &label.child("r_lt_q"),
        )
        .expect("recover canonical range vector from wire log");
    recovered_values.sort_by_key(|(party, _)| party.0);
    assert_eq!(recovered_values, values);

    let mut equality_runtimes = test_party_runtimes(&config);
    for (idx, runtime) in equality_runtimes.iter_mut().enumerate() {
        runtime
            .drive_power2round_equality_check_vec(
                &label,
                &[(idx + 25) as Coeff, (idx + 35) as Coeff],
            )
            .expect("broadcast equality vector");
    }
    route_broadcast_messages(&mut equality_runtimes, [0usize, 1, 2], false, None);
    let (status, mut values) = equality_runtimes[0]
        .drive_collect_power2round_equality_check_vec(&label)
        .expect("collect equality vector");
    values.sort_by_key(|(party, _)| party.0);
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::Collected {
            kind: PrimeFieldMpcRoundKind::AssertZero,
            phase: PrimeFieldMpcPhase::Power2RoundEqualityCheck,
            ..
        }
    ));
    assert_eq!(
        values,
        vec![
            (PartyId(1), vec![25, 35]),
            (PartyId(2), vec![26, 36]),
            (PartyId(3), vec![27, 37]),
        ]
    );
}

#[test]
fn single_party_phase_driver_handles_add4095_vector_broadcast() {
    let config = config();
    let label = Power2RoundTranscriptLabel::root(&config, [0x8f; 32]).child("power2round_t1_vec");
    let mut runtimes = test_party_runtimes(&config);
    for (idx, runtime) in runtimes.iter_mut().enumerate() {
        runtime
            .drive_power2round_add4095_share_vec(
                &label,
                11,
                &[(idx + 45) as Coeff, (idx + 55) as Coeff],
            )
            .expect("broadcast add4095 vector");
    }

    route_broadcast_messages(&mut runtimes, [0usize], true, None);
    let (status, values) = runtimes[0]
        .drive_collect_power2round_add4095_share_vec(&label, 11)
        .expect("waiting add4095 vector");
    assert_eq!(values, Vec::new());
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
            kind: PrimeFieldMpcRoundKind::AssertZero,
            phase: PrimeFieldMpcPhase::Power2RoundAdd4095,
            expected: 3,
            ..
        }
    ));

    route_broadcast_messages(&mut runtimes, [0usize, 1, 2], false, None);
    let (status, mut values) = runtimes[0]
        .drive_collect_power2round_add4095_share_vec(&label, 11)
        .expect("collect add4095 vector");
    values.sort_by_key(|(party, _)| party.0);
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::Collected {
            kind: PrimeFieldMpcRoundKind::AssertZero,
            phase: PrimeFieldMpcPhase::Power2RoundAdd4095,
            ..
        }
    ));
    assert_eq!(
        values,
        vec![
            (PartyId(1), vec![45, 55]),
            (PartyId(2), vec![46, 56]),
            (PartyId(3), vec![47, 57]),
        ]
    );

    let saved_log = runtimes[0].wire_log().clone();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state =
        TransportPrimeFieldMpcStateMachine::new(config, PartyId(1), transport).expect("state");
    let mut recovered = TransportPrimeFieldMpcPartyRuntime::new(state, saved_log.clone());
    let mut recovered_values = recovered
        .state_mut()
        .collect_broadcast_phase_vec_from_wire_log(
            &saved_log,
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundAdd4095,
            &label.child("add_4095/carry_11"),
        )
        .expect("recover add4095 vector from wire log");
    recovered_values.sort_by_key(|(party, _)| party.0);
    assert_eq!(recovered_values, values);
}

#[test]
fn single_party_phase_driver_handles_t1_bit_vector_broadcast() {
    let config = config();
    let label = Power2RoundTranscriptLabel::root(&config, [0x90; 32]).child("power2round_t1_vec");
    let mut runtimes = test_party_runtimes(&config);
    for (idx, runtime) in runtimes.iter_mut().enumerate() {
        runtime
            .drive_power2round_t1_bit_vec(
                &label,
                9,
                &[(idx % 2) as Coeff, ((idx + 1) % 2) as Coeff],
            )
            .expect("broadcast t1 bit vector");
    }

    route_broadcast_messages(&mut runtimes, [0usize], true, None);
    let (status, values) = runtimes[0]
        .drive_collect_power2round_t1_bit_vec(&label, 9)
        .expect("waiting t1 bit vector");
    assert_eq!(values, Vec::new());
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
            kind: PrimeFieldMpcRoundKind::Open,
            phase: PrimeFieldMpcPhase::T1BitOpening,
            expected: 3,
            ..
        }
    ));

    route_broadcast_messages(&mut runtimes, [0usize, 1, 2], false, None);
    let (status, mut values) = runtimes[0]
        .drive_collect_power2round_t1_bit_vec(&label, 9)
        .expect("collect t1 bit vector");
    values.sort_by_key(|(party, _)| party.0);
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::Collected {
            kind: PrimeFieldMpcRoundKind::Open,
            phase: PrimeFieldMpcPhase::T1BitOpening,
            ..
        }
    ));
    assert_eq!(
        values,
        vec![
            (PartyId(1), vec![0, 1]),
            (PartyId(2), vec![1, 0]),
            (PartyId(3), vec![0, 1]),
        ]
    );

    let saved_log = runtimes[0].wire_log().clone();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state =
        TransportPrimeFieldMpcStateMachine::new(config, PartyId(1), transport).expect("state");
    let mut recovered = TransportPrimeFieldMpcPartyRuntime::new(state, saved_log.clone());
    let mut recovered_values = recovered
        .state_mut()
        .collect_broadcast_phase_vec_from_wire_log(
            &saved_log,
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::T1BitOpening,
            &label.child("open_t1_bits/bit_9"),
        )
        .expect("recover t1 bit vector from wire log");
    recovered_values.sort_by_key(|(party, _)| party.0);
    assert_eq!(recovered_values, values);
}

#[test]
fn cursored_phase_runtime_persists_current_phase_and_resumes_sent_messages() {
    let config = config();
    let party_ids = vec![1, 2, 3];
    let transport = talus_wire::InMemoryTransport::new(1, party_ids).expect("transport");
    let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state");
    let runtime = TransportPrimeFieldMpcPartyRuntime::new(
        state,
        InMemoryPrimeFieldMpcWireMessageLog::default(),
    );
    let mut runtime = CursoredTransportPrimeFieldMpcPartyRuntime::new(
        runtime,
        InMemoryPrimeFieldMpcPhaseCursorLog::default(),
    );
    let label = Power2RoundTranscriptLabel::root(&config, [0x68; 32]).child("cursored_runtime");

    runtime
        .drive_send_directed_phase(
            PartyId(2),
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::RandomBitShare,
            &label,
            7,
        )
        .expect("send with cursor");
    assert_eq!(
        runtime
            .cursor_log()
            .latest_phase_cursor()
            .expect("sent cursor")
            .state,
        PrimeFieldMpcPhaseCursorState::SentPrivate
    );

    let (status, values) = runtime
        .drive_collect_directed_phase(
            PartyId(2),
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::RandomBitShare,
            &label,
        )
        .expect("waiting with cursor");
    assert_eq!(values, Vec::new());
    assert!(matches!(
        status,
        PrimeFieldMpcPhaseDriverStatus::WaitingPrivate {
            receiver: PartyId(2),
            expected: 3,
            got: 1,
            ..
        }
    ));

    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state =
        TransportPrimeFieldMpcStateMachine::new(config, PartyId(1), transport).expect("state");
    let restored_runtime =
        TransportPrimeFieldMpcPartyRuntime::new(state, runtime.runtime().wire_log().clone());
    let mut restored = CursoredTransportPrimeFieldMpcPartyRuntime::new(
        restored_runtime,
        runtime.cursor_log().clone(),
    );
    let latest = restored.resume().expect("resume").expect("latest cursor");
    assert_eq!(latest.state, PrimeFieldMpcPhaseCursorState::WaitingPrivate);
    assert_eq!(
        restored
            .runtime()
            .state()
            .transport()
            .private_messages()
            .len(),
        1
    );
}

#[test]
fn dkg_transport_driver_handles_small_sampler_and_vss_phases() {
    let config = config();
    let mut runtimes = test_dkg_transport_runtimes(&config);
    let eta = SmallSecretEta::for_params::<MlDsa65>().expect("eta");
    let label = SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 0).expect("label");

    for (idx, runtime) in runtimes.iter_mut().enumerate() {
        let contribution =
            SmallResidueContribution::new(runtime.local_party(), label, eta, idx as u8);
        assert_eq!(
            runtime
                .drive_broadcast_small_residue(&contribution)
                .expect("broadcast residue"),
            DkgTransportPhaseDriverStatus::SentBroadcast {
                phase: DkgTransportPhase::SmallResidue
            }
        );
    }
    route_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (status, mut contributions) = runtimes[0]
        .drive_collect_small_residue_round(label, eta)
        .expect("collect residues");
    contributions.sort_by_key(|item| item.dealer.0);
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::Collected {
            phase: DkgTransportPhase::SmallResidue,
            ..
        }
    ));
    assert_eq!(
        contributions
            .iter()
            .map(|item| (item.dealer, item.residue))
            .collect::<Vec<_>>(),
        vec![(PartyId(1), 0), (PartyId(2), 1), (PartyId(3), 2)]
    );
    for runtime in &mut runtimes {
        runtime.state_mut().transport_mut().clear_queued_messages();
    }

    for runtime in &mut runtimes {
        runtime
            .drive_broadcast_vss_commit(&commit_payload(runtime.local_party()))
            .expect("broadcast commit");
    }
    route_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (_status, commits) = runtimes[1]
        .drive_collect_vss_commit_round()
        .expect("collect commits");
    assert_eq!(commits.len(), 3);
    for runtime in &mut runtimes {
        runtime.state_mut().transport_mut().clear_queued_messages();
    }

    let shares = share_round();
    for runtime in &mut runtimes {
        let local = runtime.local_party();
        for share in shares.iter().filter(|share| share.dealer == local) {
            runtime
                .drive_send_vss_share(share.receiver, share)
                .expect("send vss share");
        }
    }
    route_dkg_private_messages(&mut runtimes, [0usize, 1, 2]);
    let (status, mut received) = runtimes[1]
        .drive_collect_vss_share_round(PartyId(2))
        .expect("collect vss shares");
    received.sort_by_key(|share| share.dealer.0);
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::Collected {
            phase: DkgTransportPhase::VssShare,
            receiver: Some(PartyId(2)),
            ..
        }
    ));
    assert_eq!(
        received
            .iter()
            .map(|share| (share.dealer, share.receiver))
            .collect::<Vec<_>>(),
        vec![(PartyId(1), PartyId(2)), (PartyId(3), PartyId(2))]
    );
    for runtime in &mut runtimes {
        runtime.state_mut().transport_mut().clear_queued_messages();
    }

    let complaints_to_send = vec![
        DkgComplaintPayload {
            complainant: PartyId(1),
            dealer: PartyId(2),
            receiver: PartyId(1),
            reason: DkgComplaintReason::InvalidVssShare,
            evidence: vec![1],
        },
        DkgComplaintPayload {
            complainant: PartyId(2),
            dealer: PartyId(1),
            receiver: PartyId(2),
            reason: DkgComplaintReason::InvalidVssShare,
            evidence: vec![9, 9],
        },
        DkgComplaintPayload {
            complainant: PartyId(3),
            dealer: PartyId(1),
            receiver: PartyId(3),
            reason: DkgComplaintReason::InvalidVssShare,
            evidence: vec![3],
        },
    ];
    for (runtime, complaint) in runtimes.iter_mut().zip(&complaints_to_send) {
        runtime
            .drive_broadcast_vss_complaint(complaint)
            .expect("broadcast complaint");
    }
    route_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (_status, complaints) = runtimes[0]
        .drive_collect_vss_complaint_round()
        .expect("collect complaints");
    assert_eq!(complaints, complaints_to_send);
}

#[test]
fn logged_dkg_transport_wire_log_replays_sent_and_recovers_accepted_shares() {
    let config = config();
    let party_ids = vec![1, 2, 3];
    let share12 = DkgSharePayload {
        dealer: PartyId(1),
        receiver: PartyId(2),
        encrypted_share: vec![1, 2],
        encrypted_seed_share: vec![2, 1],
        proof: vec![3],
    };
    let share32 = DkgSharePayload {
        dealer: PartyId(3),
        receiver: PartyId(2),
        encrypted_share: vec![3, 2],
        encrypted_seed_share: vec![2, 3],
        proof: vec![1],
    };

    let transport = talus_wire::InMemoryTransport::new(1, party_ids.clone()).expect("transport");
    let state =
        DkgTransportStateMachine::new(config.clone(), PartyId(1), transport).expect("state");
    let mut sender =
        LoggedDkgTransportPartyRuntime::new(state, InMemoryDkgWireMessageLog::default());
    sender
        .send_vss_share_logged(PartyId(2), &share12)
        .expect("logged send");
    assert_eq!(sender.wire_log().dkg_wire_records().len(), 1);

    let changed = DkgSharePayload {
        encrypted_share: vec![9, 9],
        ..share12.clone()
    };
    sender
        .send_vss_share_logged(PartyId(2), &changed)
        .expect("replay exact sent bytes");
    let sent_payload = wire_decode_dkg_share_payload(
        &sender
            .state()
            .transport()
            .private_messages()
            .last()
            .expect("replayed sent message")
            .message
            .payload,
    )
    .expect("decode sent payload");
    assert_eq!(sent_payload.encrypted_share, share12.encrypted_share);

    let transport = talus_wire::InMemoryTransport::new(1, party_ids.clone()).expect("transport");
    let state =
        DkgTransportStateMachine::new(config.clone(), PartyId(1), transport).expect("state");
    let mut restored = LoggedDkgTransportPartyRuntime::new(state, sender.wire_log().clone());
    restored.resume_sent_messages().expect("resume sent");
    assert_eq!(restored.state().transport().private_messages().len(), 1);

    let mut receiver = LoggedDkgTransportPartyRuntime::new(
        DkgTransportStateMachine::new(
            config.clone(),
            PartyId(2),
            talus_wire::InMemoryTransport::new(2, party_ids.clone()).expect("transport"),
        )
        .expect("receiver state"),
        InMemoryDkgWireMessageLog::default(),
    );
    receiver
        .state_mut()
        .transport_mut()
        .inject_private(
            1,
            2,
            sender
                .state()
                .transport()
                .private_messages()
                .first()
                .expect("sender message")
                .message
                .clone(),
        )
        .expect("route first share");

    let mut sender3 = LoggedDkgTransportPartyRuntime::new(
        DkgTransportStateMachine::new(
            config,
            PartyId(3),
            talus_wire::InMemoryTransport::new(3, party_ids).expect("transport"),
        )
        .expect("sender3 state"),
        InMemoryDkgWireMessageLog::default(),
    );
    sender3
        .send_vss_share_logged(PartyId(2), &share32)
        .expect("sender3 logged send");
    receiver
        .state_mut()
        .transport_mut()
        .inject_private(
            3,
            2,
            sender3
                .state()
                .transport()
                .private_messages()
                .first()
                .expect("sender3 message")
                .message
                .clone(),
        )
        .expect("route second share");

    let mut accepted = receiver
        .collect_vss_share_round_logged(PartyId(2))
        .expect("collect accepted shares");
    accepted.sort_by_key(|share| share.dealer.0);
    assert_eq!(accepted, vec![share12, share32]);
    let recovered = receiver
        .recover_vss_share_round_from_log(PartyId(2))
        .expect("recover accepted shares");
    assert_eq!(recovered.len(), 2);
}

#[test]
fn logged_bounded_sampler_collects_samples_and_recovers_from_log() {
    let config = config();
    let label =
        SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 0).expect("sampler label");
    let contributions =
        small_contributions::<MlDsa65>(&config, SecretVectorKind::S1, 0, &[1, 2, 3]);
    let mut runtimes = test_logged_dkg_transport_runtimes(&config);

    for (runtime, contribution) in runtimes.iter_mut().zip(&contributions) {
        runtime
            .broadcast_small_residue_logged(contribution)
            .expect("broadcast logged residue");
    }
    route_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);

    let mut sampler = InProcessDistributedSmallSampler::new([0x91; 32]);
    let sampled =
        sample_logged_small_coeff::<MlDsa65, _, _>(&mut sampler, &config, &mut runtimes[1], label)
            .expect("sample from logged residues");
    assert_eq!(
        signed_field_coeff::<MlDsa65>(reconstruct_small_coeff::<MlDsa65>(
            &sampled,
            usize::from(config.threshold),
        )),
        2
    );

    let recovered = runtimes[1]
        .recover_small_residue_round_from_log(
            label,
            SmallSecretEta::for_params::<MlDsa65>().expect("eta"),
        )
        .expect("recover logged residues");
    assert_eq!(recovered, contributions);

    let mut recovered_sampler = InProcessDistributedSmallSampler::new([0x91; 32]);
    let recovered_sampled = sample_logged_small_coeff_from_log::<MlDsa65, _, _>(
        &mut recovered_sampler,
        &config,
        &runtimes[1],
        label,
    )
    .expect("sample from recovered logged residues");
    assert_eq!(recovered_sampled, sampled);
}

#[test]
fn dkg_setup_phase_cursors_resume_logged_sampler_and_vss_phases() {
    let config = config();
    let label =
        SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 0).expect("sampler label");
    let contributions =
        small_contributions::<MlDsa65>(&config, SecretVectorKind::S1, 0, &[1, 2, 3]);
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);

    for (runtime, contribution) in runtimes.iter_mut().zip(&contributions) {
        runtime
            .drive_broadcast_small_residue(contribution)
            .expect("broadcast residue with cursor");
    }
    assert_eq!(
        runtimes[0]
            .cursor_log()
            .latest_setup_phase_cursor()
            .expect("sent cursor")
            .state,
        DkgSetupPhaseCursorState::Sent
    );
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (status, values) = runtimes[1]
        .drive_collect_small_residue_round(
            label,
            SmallSecretEta::for_params::<MlDsa65>().expect("eta"),
        )
        .expect("collect residue with cursor");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::Collected {
            phase: DkgTransportPhase::SmallResidue,
            ..
        }
    ));
    assert_eq!(values.len(), 3);
    let latest = runtimes[1]
        .cursor_log()
        .latest_setup_phase_cursor()
        .expect("collected cursor");
    assert_eq!(latest.state, DkgSetupPhaseCursorState::Collected);
    assert_eq!(latest.vector, Some(SecretVectorKind::S1));
    assert_eq!(latest.coefficient_index, Some(0));

    let mut restored = CursoredLoggedDkgTransportPartyRuntime::new(
        LoggedDkgTransportPartyRuntime::new(
            DkgTransportStateMachine::new(
                config.clone(),
                PartyId(1),
                talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport"),
            )
            .expect("state"),
            runtimes[0].runtime().wire_log().clone(),
        ),
        runtimes[0].cursor_log().clone(),
    );
    let resumed = restored.resume().expect("resume").expect("latest cursor");
    assert_eq!(resumed.state, DkgSetupPhaseCursorState::Sent);
    assert_eq!(
        restored
            .runtime()
            .state()
            .transport()
            .broadcast_deliveries()
            .len(),
        3
    );

    let commit = DkgCommitPayload {
        dealer: PartyId(1),
        vss_commitments: vec![VssCommitment { bytes: vec![1] }],
        as1_commitment: As1Commitment {
            party: PartyId(1),
            bytes: Vec::new(),
        },
        pairwise_seed_commitment: PairwiseSeedCommitment {
            party: PartyId(1),
            commitment: [0u8; 32],
        },
    };
    runtimes[0]
        .drive_broadcast_vss_commit(&commit)
        .expect("vss commit cursor");
    assert_eq!(
        runtimes[0]
            .cursor_log()
            .latest_setup_phase_cursor()
            .expect("commit cursor")
            .phase,
        DkgTransportPhase::VssCommit
    );
}

#[test]
fn native_dkg_application_setup_driver_is_transport_and_log_boundary() {
    fn app_broadcast_residue<D: NativeDkgApplicationSetupDriver>(
        driver: &mut D,
        contribution: &SmallResidueContribution,
    ) -> DkgTransportPhaseDriverStatus {
        driver
            .drive_broadcast_small_residue(contribution)
            .expect("application broadcasts residue")
    }

    fn app_collect_residue<D: NativeDkgApplicationSetupDriver>(
        driver: &mut D,
        label: SamplerLabel,
        eta: SmallSecretEta,
    ) -> (DkgTransportPhaseDriverStatus, Vec<SmallResidueContribution>) {
        driver
            .drive_collect_small_residue_round(label, eta)
            .expect("application collects residue")
    }

    fn app_resume<D: NativeDkgApplicationSetupDriver>(
        driver: &mut D,
    ) -> Option<DkgSetupPhaseCursor> {
        driver.resume_setup().expect("application resumes setup")
    }

    let config = config();
    let label =
        SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 2).expect("sampler label");
    let eta = SmallSecretEta::for_params::<MlDsa65>().expect("eta");
    let contributions =
        small_contributions::<MlDsa65>(&config, SecretVectorKind::S1, 2, &[1, 2, 3]);
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);

    for (runtime, contribution) in runtimes.iter_mut().zip(&contributions) {
        let status = app_broadcast_residue(runtime, contribution);
        assert_eq!(
            status,
            DkgTransportPhaseDriverStatus::SentBroadcast {
                phase: DkgTransportPhase::SmallResidue
            }
        );
    }

    assert_eq!(
        <TestCursoredLoggedDkgTransportRuntime as NativeDkgApplicationSetupDriver>::wire_log(
            &runtimes[0]
        )
        .dkg_wire_records()
        .len(),
        1
    );
    assert_eq!(
        <TestCursoredLoggedDkgTransportRuntime as NativeDkgApplicationSetupDriver>::cursor_log(
            &runtimes[0]
        )
        .latest_setup_phase_cursor()
        .expect("latest cursor")
        .vector,
        Some(SecretVectorKind::S1)
    );

    let mut restored = CursoredLoggedDkgTransportPartyRuntime::new(
        LoggedDkgTransportPartyRuntime::new(
            DkgTransportStateMachine::new(
                config.clone(),
                PartyId(1),
                talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport"),
            )
            .expect("state"),
            runtimes[0].runtime().wire_log().clone(),
        ),
        runtimes[0].cursor_log().clone(),
    );
    let resumed = app_resume(&mut restored).expect("resume cursor");
    assert_eq!(resumed.phase, DkgTransportPhase::SmallResidue);
    assert_eq!(resumed.coefficient_index, Some(2));
    assert_eq!(
        restored
            .runtime()
            .state()
            .transport()
            .broadcast_deliveries()
            .len(),
        config.parties.len()
    );

    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (status, values) = app_collect_residue(&mut runtimes[1], label, eta);
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::Collected {
            phase: DkgTransportPhase::SmallResidue,
            ..
        }
    ));
    assert_eq!(values, contributions);
}

#[test]
fn native_dkg_application_setup_driver_drives_scaffold_setup_to_assembly() {
    fn app_broadcast_residue<D: NativeDkgApplicationSetupDriver>(
        driver: &mut D,
        contribution: &SmallResidueContribution,
    ) {
        driver
            .drive_broadcast_small_residue(contribution)
            .expect("app driver broadcasts residue");
    }

    fn app_collect_residue<D: NativeDkgApplicationSetupDriver>(
        driver: &mut D,
        label: SamplerLabel,
        eta: SmallSecretEta,
    ) {
        let (status, values) = driver
            .drive_collect_small_residue_round(label, eta)
            .expect("app driver collects residue");
        assert!(matches!(
            status,
            DkgTransportPhaseDriverStatus::Collected {
                phase: DkgTransportPhase::SmallResidue,
                ..
            }
        ));
        assert_eq!(values.len(), 3);
    }

    fn app_share_vector_it_vss<D, B>(
        driver: &mut D,
        backend: &mut B,
        config: &DkgConfig,
        vector: SecretVectorKind,
        contributions: &[SmallResidueContribution],
    ) where
        D: NativeDkgApplicationSetupDriver,
        B: ProductionItVssBackend,
    {
        driver
            .drive_share_small_residue_vector_it_vss::<MlDsa44, B>(
                backend,
                config,
                vector,
                contributions,
            )
            .expect("app driver shares vector it-vss");
    }

    fn app_collect_it_vss_public<D: NativeDkgApplicationSetupDriver>(
        driver: &mut D,
    ) -> Vec<ItVssPublicCommitment> {
        let (status, commitments) = driver
            .drive_collect_it_vss_public_commitments()
            .expect("app driver collects it-vss public commitments");
        assert!(
            matches!(
                status,
                DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::ItVssArtifact,
                    ..
                }
            ),
            "unexpected public IT-VSS status: {status:?}"
        );
        commitments
    }

    fn app_verify_it_vss_private<D, B>(
        driver: &mut D,
        backend: &B,
        config: &DkgConfig,
        public_commitments: &[ItVssPublicCommitment],
    ) where
        D: NativeDkgApplicationSetupDriver,
        B: ProductionItVssBackend,
    {
        let complaints = driver
            .drive_verify_it_vss_private_deliveries::<MlDsa44, B>(
                backend,
                config,
                public_commitments,
            )
            .expect("app driver verifies it-vss private deliveries");
        assert!(complaints.is_empty());
    }

    fn app_broadcast_vss_commit<D: NativeDkgApplicationSetupDriver>(
        driver: &mut D,
        commit: &DkgCommitPayload,
    ) {
        driver
            .drive_broadcast_vss_commit(commit)
            .expect("app driver broadcasts scalar vss commit");
    }

    fn app_collect_vss_commit<D: NativeDkgApplicationSetupDriver>(driver: &mut D) {
        let (status, commits) = driver
            .drive_collect_vss_commit_round()
            .expect("app driver collects scalar vss commits");
        assert!(matches!(
            status,
            DkgTransportPhaseDriverStatus::Collected {
                phase: DkgTransportPhase::VssCommit,
                ..
            }
        ));
        assert_eq!(commits.len(), 3);
    }

    fn app_send_vss_share<D: NativeDkgApplicationSetupDriver>(
        driver: &mut D,
        receiver: PartyId,
        share: &DkgSharePayload,
    ) {
        driver
            .drive_send_vss_share(receiver, share)
            .expect("app driver sends scalar vss share");
    }

    fn app_collect_vss_share<D: NativeDkgApplicationSetupDriver>(
        driver: &mut D,
        receiver: PartyId,
    ) {
        let (status, shares) = driver
            .drive_collect_vss_share_round(receiver)
            .expect("app driver collects scalar vss shares");
        assert!(matches!(
            status,
            DkgTransportPhaseDriverStatus::Collected {
                phase: DkgTransportPhase::VssShare,
                receiver: Some(_),
                ..
            }
        ));
        assert_eq!(shares.len(), 3);
    }

    let config = config_for::<MlDsa44>();
    let receiver = PartyId(2);
    let receiver_idx = 1usize;
    let eta = SmallSecretEta::for_params::<MlDsa44>().expect("eta");
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);

    for vector in [SecretVectorKind::S1, SecretVectorKind::S2] {
        for round in small_polyvec_contributions::<MlDsa44>(&config, vector) {
            let label = round[0].label;
            for (runtime, contribution) in runtimes.iter_mut().zip(&round) {
                app_broadcast_residue(runtime, contribution);
            }
            route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
            app_collect_residue(&mut runtimes[receiver_idx], label, eta);
            for runtime in &mut runtimes {
                runtime
                    .runtime_mut()
                    .state_mut()
                    .transport_mut()
                    .clear_queued_messages();
            }
        }
    }

    let mut sampler_it_vss = DeterministicItVssTestBackend::new([0xd1; 32]);
    let mut private_offsets = vec![0usize; runtimes.len()];
    let mut broadcast_offsets = vec![0usize; runtimes.len()];
    for vector in [SecretVectorKind::S1, SecretVectorKind::S2] {
        let rounds = small_polyvec_contributions::<MlDsa44>(&config, vector);
        for runtime in &mut runtimes {
            let dealer_contributions =
                dealer_small_polyvec_contributions(&rounds, runtime.local_party());
            app_share_vector_it_vss(
                runtime,
                &mut sampler_it_vss,
                &config,
                vector,
                &dealer_contributions,
            );
        }
        route_cursored_logged_dkg_new_broadcast_messages(
            &mut runtimes,
            [0usize, 1, 2],
            &mut broadcast_offsets,
        );
        let commitments = app_collect_it_vss_public(&mut runtimes[receiver_idx]);
        let expected_keys =
            expected_sampler_vector_it_vss_keys(&config, core::slice::from_ref(&vector))
                .expect("expected vector keys");
        let commitments = select_expected_it_vss_public_commitments(&commitments, &expected_keys)
            .expect("selected vector commitments");
        route_cursored_logged_dkg_new_private_messages(
            &mut runtimes,
            [0usize, 1, 2],
            &mut private_offsets,
        );
        app_verify_it_vss_private(
            &mut runtimes[receiver_idx],
            &sampler_it_vss,
            &config,
            &commitments,
        );
        for runtime in &mut runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
        private_offsets.fill(0);
        broadcast_offsets.fill(0);
    }
    persist_logged_sampler_it_vss_artifacts_from_phase_logs::<MlDsa44, _, _, _>(
        &config,
        runtimes[receiver_idx].runtime_mut(),
        &sampler_it_vss,
    )
    .expect("persist app-driver sampler it-vss artifacts");

    let mut scalar_vss = InProcessScalarItVssBackend::new([0xd2; 32]);
    let dealer_vectors = config
        .parties
        .iter()
        .map(|&dealer| {
            vec![
                scalar_vss
                    .deal::<MlDsa44>(&config, dealer, Coeff::from(dealer.0))
                    .expect("scalar deal 0"),
                scalar_vss
                    .deal::<MlDsa44>(&config, dealer, Coeff::from(dealer.0) + 10)
                    .expect("scalar deal 1"),
            ]
        })
        .collect::<Vec<_>>();
    let commits = dealer_vectors
        .iter()
        .map(|vector| {
            dkg_commit_from_in_process_scalar_vss_public_checks(
                &vector
                    .iter()
                    .map(|deal| deal.public_check.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    for (runtime, commit) in runtimes.iter_mut().zip(&commits) {
        app_broadcast_vss_commit(runtime, commit);
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    app_collect_vss_commit(&mut runtimes[receiver_idx]);
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }

    for (runtime, vector) in runtimes.iter_mut().zip(&dealer_vectors) {
        let receiver_shares = vector
            .iter()
            .map(|deal| {
                *deal
                    .shares
                    .iter()
                    .find(|share| share.share.receiver == receiver)
                    .expect("receiver scalar share")
            })
            .collect::<Vec<_>>();
        app_send_vss_share(
            runtime,
            receiver,
            &dkg_share_from_in_process_scalar_vss_private_shares(&receiver_shares),
        );
    }
    route_cursored_logged_dkg_private_messages(&mut runtimes, [0usize, 1, 2]);
    app_collect_vss_share(&mut runtimes[receiver_idx], receiver);

    let mut sampler = InProcessDistributedSmallSampler::new([0xd3; 32]);
    let mut power2round = ClearSimPower2RoundBackend;
    let assembled = assemble_logged_native_dkg_scaffold_from_logs::<MlDsa44, _, _, _>(
        &config,
        [0xd4; 32],
        runtimes[receiver_idx].runtime_mut(),
        &mut sampler,
        &mut power2round,
    )
    .expect("assemble app-driver native dkg logs");
    assembled.public.validate_binding().expect("valid output");
    assert_eq!(assembled.accepted_dealers, config.parties);
    assert!(assembled.rejected_dealers.is_empty());
    assert_eq!(assembled.key_packages.len(), config.parties.len());
    assert_eq!(
        runtimes[receiver_idx]
            .cursor_log()
            .latest_setup_phase_cursor()
            .expect("latest app-driver cursor")
            .phase,
        DkgTransportPhase::VssShare
    );
}

#[test]
fn native_dkg_application_driver_uses_production_it_vss_batch_path_to_assembly() {
    let config = config_for::<MlDsa44>();
    let receiver = PartyId(2);
    let receiver_idx = 1usize;
    let eta = SmallSecretEta::for_params::<MlDsa44>().expect("eta");
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);

    for vector in [SecretVectorKind::S1, SecretVectorKind::S2] {
        for round in small_polyvec_contributions::<MlDsa44>(&config, vector) {
            let label = round[0].label;
            for (runtime, contribution) in runtimes.iter_mut().zip(&round) {
                runtime
                    .drive_broadcast_small_residue(contribution)
                    .expect("broadcast sampler residue");
            }
            route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
            let (status, values) = runtimes[receiver_idx]
                .drive_collect_small_residue_round(label, eta)
                .expect("collect sampler residue");
            assert!(matches!(
                status,
                DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::SmallResidue,
                    ..
                }
            ));
            assert_eq!(values.len(), config.parties.len());
            for runtime in &mut runtimes {
                runtime
                    .runtime_mut()
                    .state_mut()
                    .transport_mut()
                    .clear_queued_messages();
            }
        }
    }

    let s1_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S1);
    let s2_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S2);
    let params = ProductionItVssSecurityParams {
        audit_tags: 1,
        retained_tags: 1,
        consistency_rounds: 2,
        ..ProductionItVssSecurityParams::default()
    };
    let mut prepared_by_dealer = Vec::new();
    for runtime in &mut runtimes {
        let dealer = runtime.local_party();
        let mut backend =
            ProductionInformationCheckingVssBackend::with_params([dealer.0 as u8; 32], params)
                .expect("production it-vss backend");
        let mut prepared = Vec::new();
        for (vector, rounds) in [
            (SecretVectorKind::S1, &s1_rounds),
            (SecretVectorKind::S2, &s2_rounds),
        ] {
            let label = ItVssSharingLabel::new(
                &config,
                dealer,
                ItVssSharingDomain::for_secret_vector(vector),
                None,
            )
            .expect("vector sharing label");
            let eta = SmallSecretEta::for_params::<MlDsa44>().expect("eta");
            let secret = encode_small_residue_vector_it_vss_secret::<MlDsa44>(
                &config,
                vector,
                eta,
                dealer,
                &dealer_small_polyvec_contributions(rounds, dealer),
            )
            .expect("encoded residue vector secret");
            let output = backend
                .prepare_secret::<MlDsa44>(&config, label, &secret)
                .expect("prepared production it-vss secret");
            prepared.push((label, output));
        }
        prepared_by_dealer.push((dealer, prepared));
    }
    for vector in [SecretVectorKind::S1, SecretVectorKind::S2] {
        for runtime in &mut runtimes {
            let dealer = runtime.local_party();
            let prepared = prepared_by_dealer
                .iter()
                .find(|(prepared_dealer, _)| *prepared_dealer == dealer)
                .expect("dealer prepared output")
                .1
                .iter()
                .find(|(label, _)| label.domain == ItVssSharingDomain::for_secret_vector(vector))
                .expect("vector prepared output");
            runtime
                .drive_broadcast_it_vss_public_precommitment(&prepared.1.public_precommitment)
                .expect("broadcast production it-vss precommitment");
        }
        route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
        let (_, precommitments) = runtimes[receiver_idx]
            .drive_collect_it_vss_public_precommitments()
            .expect("collect production it-vss precommitments");
        assert_eq!(precommitments.len(), config.parties.len());
        for runtime in &mut runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
    }

    let labels = sampler_vector_it_vss_sharing_labels(
        &config,
        &[SecretVectorKind::S1, SecretVectorKind::S2],
    )
    .expect("sampler vector labels");
    let mut public_coin_transcripts = Vec::new();
    for label in &labels {
        for runtime in &mut runtimes {
            let party = runtime.local_party();
            let mut coin = [0x77; 32];
            coin[0..2].copy_from_slice(&party.0.to_le_bytes());
            coin[2..4].copy_from_slice(&label.dealer.0.to_le_bytes());
            coin[4] = match label.domain {
                ItVssSharingDomain::MldsaS1 => 1,
                ItVssSharingDomain::MldsaS2 => 2,
                _ => 0,
            };
            let share = production_it_vss_public_coin_share(&config, label.label_hash, party, coin)
                .expect("production it-vss public coin share");
            runtime
                .drive_broadcast_it_vss_public_coin_share(&share)
                .expect("broadcast production it-vss public coin share");
        }
        route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
        let (_, transcript) = runtimes[receiver_idx]
            .drive_collect_it_vss_public_coin_transcript(&config, label.label_hash)
            .expect("collect production it-vss public coin transcript");
        public_coin_transcripts.push((label.label_hash, transcript));
        for runtime in &mut runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
    }

    let finalize_backend = ProductionInformationCheckingVssBackend::with_params([0x78; 32], params)
        .expect("finalize production it-vss backend");
    let mut outputs_by_dealer = Vec::new();
    for (dealer, prepared) in prepared_by_dealer {
        let mut outputs = Vec::new();
        for (label, prepared_output) in prepared {
            let transcript = public_coin_transcripts
                .iter()
                .find(|(label_hash, _)| *label_hash == label.label_hash)
                .map(|(_, transcript)| *transcript)
                .expect("public coin transcript");
            outputs.push(
                finalize_backend
                    .finalize_prepared_secret(&config, prepared_output, transcript)
                    .expect("finalize production it-vss secret"),
            );
        }
        outputs_by_dealer.push((dealer, outputs));
    }

    for runtime in &mut runtimes {
        let dealer = runtime.local_party();
        let commitments = outputs_by_dealer
            .iter()
            .find(|(output_dealer, _)| *output_dealer == dealer)
            .expect("dealer outputs")
            .1
            .iter()
            .map(|output| output.public_commitment.clone())
            .collect::<Vec<_>>();
        runtime
            .runtime_mut()
            .broadcast_it_vss_public_commitment_batch_logged(&commitments)
            .expect("broadcast final production it-vss commitment batch");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (_, all_commitments) = runtimes[receiver_idx]
        .drive_collect_it_vss_public_commitments()
        .expect("collect production it-vss commitments");
    let expected_keys =
        expected_sampler_vector_it_vss_keys(&config, &[SecretVectorKind::S1, SecretVectorKind::S2])
            .expect("expected vector keys");
    let public_commitments =
        select_expected_it_vss_public_commitments(&all_commitments, &expected_keys)
            .expect("selected production commitments");
    assert_eq!(public_commitments.len(), config.parties.len() * 2);
    assert!(public_commitments.iter().all(|commitment| {
        commitment.backend_id == ItVssBackendId::ProductionInformationChecking
    }));

    for runtime in &mut runtimes {
        let dealer = runtime.local_party();
        if dealer == receiver {
            continue;
        }
        let receiver_deliveries = outputs_by_dealer
            .iter()
            .find(|(output_dealer, _)| *output_dealer == dealer)
            .expect("dealer outputs")
            .1
            .iter()
            .flat_map(|output| output.deliveries.iter())
            .filter(|delivery| delivery.receiver == receiver)
            .cloned()
            .collect::<Vec<_>>();
        runtime
            .runtime_mut()
            .send_it_vss_private_delivery_batch_logged(receiver, &receiver_deliveries)
            .expect("send production it-vss private delivery batch");
    }
    route_cursored_logged_dkg_private_messages(&mut runtimes, [0usize, 2]);
    let complaints = runtimes[receiver_idx]
        .drive_verify_it_vss_private_deliveries::<MlDsa44, _>(
            &finalize_backend,
            &config,
            &public_commitments,
        )
        .expect("verify production it-vss private deliveries");
    assert!(complaints.is_empty());
    persist_logged_sampler_it_vss_artifacts_from_phase_logs::<MlDsa44, _, _, _>(
        &config,
        runtimes[receiver_idx].runtime_mut(),
        &finalize_backend,
    )
    .expect("persist production it-vss artifacts");
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }

    assert!(runtimes[receiver_idx]
        .runtime()
        .recover_vss_commit_round_from_log()
        .expect("no scalar vss commits before production assembly")
        .is_empty());
    assert!(runtimes[receiver_idx]
        .runtime()
        .recover_vss_share_round_from_log(receiver)
        .expect("recover production private deliveries")
        .iter()
        .all(|payload| !is_in_process_scalar_vss_private_share_payload(payload)));

    let rho = [0x74; 32];
    let mut sampler_for_t1 = InProcessDistributedSmallSampler::new([0x75; 32]);
    let s1 = sample_logged_small_polyvec_from_certified_log_for_backend::<MlDsa44, _, _>(
        &mut sampler_for_t1,
        &config,
        runtimes[receiver_idx].runtime_mut(),
        SecretVectorKind::S1,
        ItVssBackendId::ProductionInformationChecking,
    )
    .expect("recover production-it-vss s1");
    let s2 = sample_logged_small_polyvec_from_certified_log_for_backend::<MlDsa44, _, _>(
        &mut sampler_for_t1,
        &config,
        runtimes[receiver_idx].runtime_mut(),
        SecretVectorKind::S2,
        ItVssBackendId::ProductionInformationChecking,
    )
    .expect("recover production-it-vss s2");
    let material = SharedMldsaSecretMaterial { s1, s2 };
    let mut clear_power2round = ClearSimPower2RoundBackend;
    let (scaffold_public, _) = assemble_public_output_scaffold::<MlDsa44, _>(
        &config,
        rho,
        material,
        &config.parties,
        &mut clear_power2round,
    )
    .expect("derive reference t1");
    let production_t1 = PublicT1 {
        bytes: scaffold_public.t1.clone(),
        coeffs: Vec::new(),
    };
    let assembly_label = PublicKeyAssemblyLabel::new(&config, rho);
    let production_evidence = power2round_certify_public_t1_evidence(
        Power2RoundBackendId::ProductionItMpc,
        &config,
        assembly_label,
        &production_t1,
    );
    let production_power2round = ProductionPower2RoundOutput::new(
        &config,
        assembly_label,
        production_t1,
        production_evidence,
    )
    .expect("typed production power2round output");
    let mut sampler_for_production = InProcessDistributedSmallSampler::new([0x76; 32]);
    let production = assemble_logged_native_dkg_production_from_logs::<MlDsa44, _, _>(
        &config,
        rho,
        runtimes[receiver_idx].runtime_mut(),
        &mut sampler_for_production,
        production_power2round,
    )
    .expect("assemble production native dkg logs with typed power2round");
    assert_eq!(production.public().t1, scaffold_public.t1);
    assert_eq!(production.accepted_dealers(), config.parties.as_slice());
    assert_eq!(
        production.certificate().power2round.backend_id,
        Power2RoundBackendId::ProductionItMpc
    );

    let mut scalar_vss = InProcessScalarItVssBackend::new([0x71; 32]);
    let dealer_vectors = config
        .parties
        .iter()
        .map(|&dealer| {
            vec![
                scalar_vss
                    .deal::<MlDsa44>(&config, dealer, Coeff::from(dealer.0))
                    .expect("scalar deal 0"),
                scalar_vss
                    .deal::<MlDsa44>(&config, dealer, Coeff::from(dealer.0) + 10)
                    .expect("scalar deal 1"),
            ]
        })
        .collect::<Vec<_>>();
    let commits = dealer_vectors
        .iter()
        .map(|vector| {
            dkg_commit_from_in_process_scalar_vss_public_checks(
                &vector
                    .iter()
                    .map(|deal| deal.public_check.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    for (runtime, commit) in runtimes.iter_mut().zip(&commits) {
        runtime
            .drive_broadcast_vss_commit(commit)
            .expect("broadcast scalar vss commit");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (status, commits) = runtimes[receiver_idx]
        .drive_collect_vss_commit_round()
        .expect("collect scalar vss commits");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::Collected {
            phase: DkgTransportPhase::VssCommit,
            ..
        }
    ));
    assert_eq!(commits.len(), config.parties.len());
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }

    for (runtime, vector) in runtimes.iter_mut().zip(&dealer_vectors) {
        let receiver_shares = vector
            .iter()
            .map(|deal| {
                *deal
                    .shares
                    .iter()
                    .find(|share| share.share.receiver == receiver)
                    .expect("receiver scalar share")
            })
            .collect::<Vec<_>>();
        runtime
            .drive_send_vss_share(
                receiver,
                &dkg_share_from_in_process_scalar_vss_private_shares(&receiver_shares),
            )
            .expect("send scalar vss share");
    }
    route_cursored_logged_dkg_private_messages(&mut runtimes, [0usize, 1, 2]);
    runtimes[receiver_idx]
        .drive_collect_vss_share_round(receiver)
        .expect("collect scalar vss shares");

    let mut sampler = InProcessDistributedSmallSampler::new([0x72; 32]);
    let mut power2round = ClearSimPower2RoundBackend;
    let assembled =
        assemble_logged_native_dkg_with_production_it_vss_from_logs::<MlDsa44, _, _, _>(
            &config,
            [0x73; 32],
            runtimes[receiver_idx].runtime_mut(),
            &mut sampler,
            &mut power2round,
        )
        .expect("assemble production-it-vss native dkg logs");
    let setup = assembled
        .certificate
        .setup
        .as_ref()
        .expect("setup certificate");
    assert_eq!(
        assembled.certificate.power2round.backend_id,
        Power2RoundBackendId::InsecureClearSimulator
    );
    assert_eq!(
        setup.it_vss_backend_id,
        ItVssBackendId::ProductionInformationChecking
    );
    assert!(!setup
        .release_blockers
        .contains(&DkgReleaseBlocker::ScaffoldItVssAdapters));
    assert!(!setup
        .release_blockers
        .contains(&DkgReleaseBlocker::ProductionItVss));
    assert_eq!(assembled.accepted_dealers, config.parties);
    assert!(assembled.rejected_dealers.is_empty());
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&assembled.key_packages),
        Err(DkgError::InsecurePower2RoundBackend)
    );
}

#[test]
fn native_dkg_session_facade_drives_setup_without_scaffold_choices() {
    type Session =
        NativeDkgSession<TinyMlDsa44, InMemoryDkgWireMessageLog, InMemoryDkgSetupPhaseCursorLog>;

    let config = DkgConfig::new::<TinyMlDsa44>(2, parties(&[1, 2, 3]), KeygenEpoch(91))
        .expect("tiny config");
    let params = ProductionItVssSecurityParams {
        audit_tags: 1,
        retained_tags: 1,
        consistency_rounds: 1,
        max_vector_lanes_per_chunk: 512,
        ..ProductionItVssSecurityParams::default()
    };
    let mut sessions = config
        .parties
        .iter()
        .copied()
        .map(|party| {
            let mut sampler_entropy = [0x11; 32];
            sampler_entropy[0..2].copy_from_slice(&party.0.to_le_bytes());
            let mut it_vss_entropy = [0x22; 32];
            it_vss_entropy[0..2].copy_from_slice(&party.0.to_le_bytes());
            let mut public_coin_entropy = [0x33; 32];
            public_coin_entropy[0..2].copy_from_slice(&party.0.to_le_bytes());
            Session::start(
                config.clone(),
                party,
                InMemoryDkgWireMessageLog::default(),
                InMemoryDkgSetupPhaseCursorLog::default(),
                NativeDkgSessionOptions {
                    rho: [0x44; 32],
                    sampler_entropy,
                    it_vss_entropy,
                    public_coin_entropy,
                    it_vss_security: params,
                },
            )
            .expect("start native dkg session")
        })
        .collect::<Vec<_>>();

    for _ in 0..1_000 {
        let mut batch = Vec::new();
        for index in 0..sessions.len() {
            while let Some(outbound) = sessions[index].next_outbound() {
                let sender = sessions[index].local_party();
                batch.push((sender, outbound));
            }
        }
        let routed = !batch.is_empty();
        for (sender, outbound) in batch {
            match outbound {
                NativeDkgOutbound::Private { receiver, message } => {
                    let receiver_index = sessions
                        .iter()
                        .position(|session| session.local_party() == receiver)
                        .expect("receiver session");
                    sessions[receiver_index]
                        .handle_private(sender, message)
                        .expect("deliver private message");
                }
                NativeDkgOutbound::Broadcast { message } => {
                    for session in &mut sessions {
                        if let Err(err) = session.handle_broadcast(message.clone()) {
                            panic!(
                                "deliver broadcast message from {:?} to {:?}, round {:?}, payload {:?}: {:?}",
                                sender,
                                session.local_party(),
                                message.header.round,
                                message.header.payload_kind,
                                err
                            );
                        }
                    }
                }
            }
        }
        if sessions.iter().all(NativeDkgSession::setup_complete) {
            break;
        }
        assert!(
            routed,
            "native DKG session made no progress: {:?}",
            sessions
                .iter()
                .map(|session| session.cursor_log().latest_setup_phase_cursor().cloned())
                .collect::<Vec<_>>()
        );
    }

    assert!(sessions.iter().all(NativeDkgSession::setup_complete));
    for session in &sessions {
        assert!(session.wire_log().records().iter().any(|record| {
            record.message.header.round == talus_wire::RoundId::DkgItVssArtifact
        }));
        assert!(session.cursor_log().cursors().iter().any(|cursor| {
            cursor.it_vss_phase == Some(ProductionItVssComplaintPhase::BroadcastPublicCoins)
        }));
        assert!(session
            .wire_log()
            .records()
            .iter()
            .all(|record| { record.message.header.round != talus_wire::RoundId::DkgCommit }));
    }
}

#[test]
fn native_dkg_application_setup_driver_handles_delays_and_restart_cursors() {
    let config = config_for::<MlDsa44>();
    let receiver = PartyId(2);
    let receiver_idx = 1usize;
    let eta = SmallSecretEta::for_params::<MlDsa44>().expect("eta");

    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);
    let label = SamplerLabel::new::<MlDsa44>(&config, SecretVectorKind::S1, 0).expect("label");
    let contributions =
        small_contributions::<MlDsa44>(&config, SecretVectorKind::S1, 0, &[1, 2, 3]);
    for (runtime, contribution) in runtimes.iter_mut().zip(&contributions) {
        runtime
            .drive_broadcast_small_residue(contribution)
            .expect("broadcast delayed residue");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize]);
    let (status, values) = runtimes[receiver_idx]
        .drive_collect_small_residue_round(label, eta)
        .expect("waiting residue collect");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::WaitingBroadcast {
            phase: DkgTransportPhase::SmallResidue,
            ..
        }
    ));
    assert!(values.is_empty());
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [1usize, 2]);
    let (status, values) = runtimes[receiver_idx]
        .drive_collect_small_residue_round(label, eta)
        .expect("complete residue collect");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::Collected {
            phase: DkgTransportPhase::SmallResidue,
            ..
        }
    ));
    assert_eq!(values, contributions);

    let mut vector_runtimes = test_cursored_logged_dkg_transport_runtimes(&config);
    let mut backend = DeterministicItVssTestBackend::new([0xe1; 32]);
    let vector = SecretVectorKind::S1;
    let rounds = small_polyvec_contributions::<MlDsa44>(&config, vector);
    for runtime in &mut vector_runtimes {
        let dealer_contributions =
            dealer_small_polyvec_contributions(&rounds, runtime.local_party());
        runtime
            .drive_share_small_residue_vector_it_vss::<MlDsa44, _>(
                &mut backend,
                &config,
                vector,
                &dealer_contributions,
            )
            .expect("share delayed vector it-vss");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut vector_runtimes, [0usize, 1, 2]);
    let (_, public_commitments) = vector_runtimes[receiver_idx]
        .drive_collect_it_vss_public_commitments()
        .expect("collect vector commitments");
    let expected_keys =
        expected_sampler_vector_it_vss_keys(&config, core::slice::from_ref(&vector))
            .expect("expected vector keys");
    let public_commitments =
        select_expected_it_vss_public_commitments(&public_commitments, &expected_keys)
            .expect("selected commitments");

    route_cursored_logged_dkg_private_messages(&mut vector_runtimes, [0usize]);
    let (status, deliveries) = vector_runtimes[receiver_idx]
        .drive_collect_it_vss_private_delivery_round(receiver)
        .expect("waiting vector private deliveries");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::WaitingPrivate {
            phase: DkgTransportPhase::VssShare,
            receiver: PartyId(2),
            expected: 2,
            got: 1,
        }
    ));
    assert!(deliveries.is_empty());

    let mut restored_receiver = CursoredLoggedDkgTransportPartyRuntime::new(
        LoggedDkgTransportPartyRuntime::new(
            DkgTransportStateMachine::new(
                config.clone(),
                receiver,
                talus_wire::InMemoryTransport::new(2, vec![1, 2, 3]).expect("transport"),
            )
            .expect("state"),
            vector_runtimes[receiver_idx].runtime().wire_log().clone(),
        ),
        vector_runtimes[receiver_idx].cursor_log().clone(),
    );
    let latest = restored_receiver
        .resume()
        .expect("resume waiting vector it-vss")
        .expect("waiting cursor");
    assert_eq!(latest.phase, DkgTransportPhase::VssShare);
    assert_eq!(latest.state, DkgSetupPhaseCursorState::Waiting);
    assert_eq!(latest.receiver, Some(receiver));

    route_cursored_logged_dkg_private_messages(&mut vector_runtimes, [2usize]);
    let (status, deliveries) = vector_runtimes[receiver_idx]
        .drive_collect_it_vss_private_delivery_round(receiver)
        .expect("complete vector private deliveries");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::Collected {
            phase: DkgTransportPhase::VssShare,
            receiver: Some(PartyId(2)),
            ..
        }
    ));
    let deliveries =
        select_expected_it_vss_private_deliveries(&config, receiver, &deliveries, &expected_keys)
            .expect("selected private deliveries");
    assert_eq!(deliveries.len(), 2);
    let complaints = verify_it_vss_private_deliveries_for_receiver::<MlDsa44, _>(
        &backend,
        &config,
        receiver,
        &public_commitments,
        &deliveries,
    )
    .expect("verify completed private deliveries");
    assert!(complaints.is_empty());

    let mut complaint_runtimes = test_cursored_logged_dkg_transport_runtimes(&config);
    let complaints_to_send = vec![
        DkgComplaintPayload {
            complainant: PartyId(1),
            dealer: PartyId(3),
            receiver,
            reason: DkgComplaintReason::Backend,
            evidence: vec![1],
        },
        DkgComplaintPayload {
            complainant: PartyId(2),
            dealer: PartyId(3),
            receiver,
            reason: DkgComplaintReason::Backend,
            evidence: vec![2],
        },
        DkgComplaintPayload {
            complainant: PartyId(3),
            dealer: PartyId(3),
            receiver,
            reason: DkgComplaintReason::Backend,
            evidence: vec![3],
        },
    ];
    for (runtime, complaint) in complaint_runtimes.iter_mut().zip(&complaints_to_send) {
        runtime
            .drive_broadcast_vss_complaint(complaint)
            .expect("broadcast delayed complaint");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut complaint_runtimes, [0usize]);
    let (status, collected) = complaint_runtimes[receiver_idx]
        .drive_collect_vss_complaint_round()
        .expect("waiting complaint collect");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::WaitingBroadcast {
            phase: DkgTransportPhase::VssComplaint,
            ..
        }
    ));
    assert!(collected.is_empty());
    let mut restored_complaints = CursoredLoggedDkgTransportPartyRuntime::new(
        LoggedDkgTransportPartyRuntime::new(
            DkgTransportStateMachine::new(
                config,
                receiver,
                talus_wire::InMemoryTransport::new(2, vec![1, 2, 3]).expect("transport"),
            )
            .expect("state"),
            complaint_runtimes[receiver_idx]
                .runtime()
                .wire_log()
                .clone(),
        ),
        complaint_runtimes[receiver_idx].cursor_log().clone(),
    );
    let latest = restored_complaints
        .resume()
        .expect("resume waiting complaint")
        .expect("complaint cursor");
    assert_eq!(latest.phase, DkgTransportPhase::VssComplaint);
    assert_eq!(latest.state, DkgSetupPhaseCursorState::Waiting);

    route_cursored_logged_dkg_broadcast_messages(&mut complaint_runtimes, [1usize, 2]);
    let (status, mut collected) = complaint_runtimes[receiver_idx]
        .drive_collect_vss_complaint_round()
        .expect("complete complaint collect");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::Collected {
            phase: DkgTransportPhase::VssComplaint,
            ..
        }
    ));
    collected.sort_by_key(|complaint| complaint.complainant.0);
    assert_eq!(collected, complaints_to_send);
}

#[test]
fn logged_bounded_sampler_samples_full_s1_vector_from_recovered_rounds() {
    let config = config_for::<MlDsa44>();
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);
    for index in 0..SecretVectorKind::S1.coefficient_count::<MlDsa44>() {
        let contributions =
            small_contributions::<MlDsa44>(&config, SecretVectorKind::S1, index, &[1, 2, 3]);
        for (runtime, contribution) in runtimes.iter_mut().zip(&contributions) {
            runtime
                .drive_broadcast_small_residue(contribution)
                .expect("broadcast vector residue");
        }
        route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
        let label =
            SamplerLabel::new::<MlDsa44>(&config, SecretVectorKind::S1, index).expect("label");
        runtimes[1]
            .drive_collect_small_residue_round(
                label,
                SmallSecretEta::for_params::<MlDsa44>().expect("eta"),
            )
            .expect("collect vector residue");
        for runtime in &mut runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
    }

    let mut sampler = InProcessDistributedSmallSampler::new([0x93; 32]);
    let sampled = sample_logged_small_polyvec_from_log::<MlDsa44, _, _>(
        &mut sampler,
        &config,
        runtimes[1].runtime(),
        SecretVectorKind::S1,
    )
    .expect("sample full s1 from log");
    assert_eq!(
        sampled.coefficients.len(),
        SecretVectorKind::S1.coefficient_count::<MlDsa44>()
    );
    assert_eq!(
        signed_field_coeff::<MlDsa44>(reconstruct_small_coeff::<MlDsa44>(
            &sampled.coefficients[0],
            usize::from(config.threshold),
        )),
        -1
    );
    let party_shares =
        shared_small_polyvec_party_shares::<MlDsa44>(&config, &sampled).expect("party shares");
    assert_eq!(party_shares.len(), config.parties.len());
    assert_eq!(
        party_shares[0].coeffs.len(),
        SecretVectorKind::S1.coefficient_count::<MlDsa44>()
    );
}

#[test]
fn logged_scalar_vss_collects_verifies_recovers_and_broadcasts_complaints() {
    let config = config();
    let mut backend = InProcessScalarItVssBackend::new([0x92; 32]);
    let deals = vec![
        backend
            .deal::<MlDsa65>(&config, PartyId(1), 10)
            .expect("deal 1"),
        backend
            .deal::<MlDsa65>(&config, PartyId(2), 20)
            .expect("deal 2"),
        backend
            .deal::<MlDsa65>(&config, PartyId(3), 30)
            .expect("deal 3"),
    ];
    let commits = deals
        .iter()
        .map(|deal| dkg_commit_from_in_process_scalar_vss_public_check(&deal.public_check))
        .collect::<Vec<_>>();
    let mut runtimes = test_logged_dkg_transport_runtimes(&config);

    for (runtime, commit) in runtimes.iter_mut().zip(&commits) {
        runtime
            .broadcast_vss_commit_logged(commit)
            .expect("broadcast logged public check");
    }
    route_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);

    let mut public_checks = collect_logged_in_process_scalar_vss_public_checks(&mut runtimes[1])
        .expect("collect logged checks");
    public_checks.sort_by_key(|check| check.dealer.0);
    assert_eq!(
        public_checks
            .iter()
            .map(|check| check.dealer)
            .collect::<Vec<_>>(),
        parties(&[1, 2, 3])
    );
    let mut recovered_checks = recover_logged_in_process_scalar_vss_public_checks(&runtimes[1])
        .expect("recover logged checks");
    recovered_checks.sort_by_key(|check| check.dealer.0);
    assert_eq!(recovered_checks, public_checks);

    for runtime in &mut runtimes {
        runtime.state_mut().transport_mut().clear_queued_messages();
    }
    for (runtime, deal) in runtimes.iter_mut().zip(&deals) {
        let share = deal
            .shares
            .iter()
            .find(|share| share.share.receiver == PartyId(2))
            .expect("receiver share");
        runtime
            .send_vss_share_logged(
                PartyId(2),
                &dkg_share_from_in_process_scalar_vss_private_share(share),
            )
            .expect("send logged share");
    }
    route_logged_dkg_private_messages(&mut runtimes, [0usize, 1, 2]);

    let complaints = verify_logged_in_process_scalar_vss_receiver_shares::<MlDsa65, _, _>(
        &config,
        &mut runtimes[1],
        &public_checks,
    )
    .expect("verify logged private shares");
    assert!(complaints.is_empty());
    assert_eq!(
        verify_logged_in_process_scalar_vss_receiver_shares_from_log::<MlDsa65, _, _>(
            &config,
            &runtimes[1],
            &public_checks,
        ),
        Ok(Vec::new())
    );

    let combined =
        combine_accepted_in_process_scalar_vss_deals::<MlDsa65>(&config, &deals, &complaints)
            .expect("combine logged accepted deals");
    let reconstructed = reconstruct_scalar_at_zero::<MlDsa65>(
        &combined
            .shares
            .iter()
            .take(usize::from(config.threshold))
            .map(|share| ShamirScalarShare {
                point: share.point,
                value: share.value,
            })
            .collect::<Vec<_>>(),
    )
    .expect("reconstruct combined scalar");
    assert_eq!(reconstructed, 60);

    let mut bad_runtimes = test_logged_dkg_transport_runtimes(&config);
    for (runtime, commit) in bad_runtimes.iter_mut().zip(&commits) {
        runtime
            .broadcast_vss_commit_logged(commit)
            .expect("broadcast logged public check");
    }
    route_logged_dkg_broadcast_messages(&mut bad_runtimes, [0usize, 1, 2]);
    let bad_public_checks =
        collect_logged_in_process_scalar_vss_public_checks(&mut bad_runtimes[1])
            .expect("collect bad public checks");
    for runtime in &mut bad_runtimes {
        runtime.state_mut().transport_mut().clear_queued_messages();
    }
    let mut bad_share = *deals[0]
        .shares
        .iter()
        .find(|share| share.share.receiver == PartyId(2))
        .expect("bad receiver share");
    bad_share.share.value = reduce_mod_q::<MlDsa65>(bad_share.share.value + 1);
    bad_runtimes[0]
        .send_vss_share_logged(
            PartyId(2),
            &dkg_share_from_in_process_scalar_vss_private_share(&bad_share),
        )
        .expect("send bad share");
    route_logged_dkg_private_messages(&mut bad_runtimes, [0usize]);

    let bad_complaints = verify_logged_in_process_scalar_vss_receiver_shares::<MlDsa65, _, _>(
        &config,
        &mut bad_runtimes[1],
        &bad_public_checks,
    )
    .expect("verify bad logged share");
    assert_eq!(bad_complaints.len(), 1);
    assert_eq!(bad_complaints[0].complainant, PartyId(2));
    assert_eq!(bad_complaints[0].dealer, PartyId(1));

    let complaints_to_broadcast = vec![
        DkgComplaintPayload {
            complainant: PartyId(1),
            dealer: PartyId(3),
            receiver: PartyId(1),
            reason: DkgComplaintReason::Backend,
            evidence: vec![1],
        },
        bad_complaints[0].clone(),
        DkgComplaintPayload {
            complainant: PartyId(3),
            dealer: PartyId(1),
            receiver: PartyId(3),
            reason: DkgComplaintReason::Backend,
            evidence: vec![3],
        },
    ];
    for (runtime, complaint) in bad_runtimes.iter_mut().zip(&complaints_to_broadcast) {
        runtime
            .broadcast_vss_complaint_logged(complaint)
            .expect("broadcast complaint");
    }
    route_logged_dkg_broadcast_messages(&mut bad_runtimes, [0usize, 1, 2]);
    let collected = bad_runtimes[0]
        .collect_vss_complaint_round_logged()
        .expect("collect logged complaint");
    assert_eq!(collected, complaints_to_broadcast);
    let recovered = bad_runtimes[0]
        .recover_vss_complaint_round_from_log()
        .expect("recover logged complaint");
    assert_eq!(recovered, complaints_to_broadcast);
}

#[test]
fn logged_scalar_vss_vectors_verify_and_combine_coefficient_material() {
    let config = config();
    let mut backend = InProcessScalarItVssBackend::new([0x94; 32]);
    let dealer_vectors = vec![
        vec![
            backend
                .deal::<MlDsa65>(&config, PartyId(1), 1)
                .expect("deal 1 coeff 0"),
            backend
                .deal::<MlDsa65>(&config, PartyId(1), 2)
                .expect("deal 1 coeff 1"),
        ],
        vec![
            backend
                .deal::<MlDsa65>(&config, PartyId(2), 10)
                .expect("deal 2 coeff 0"),
            backend
                .deal::<MlDsa65>(&config, PartyId(2), 20)
                .expect("deal 2 coeff 1"),
        ],
        vec![
            backend
                .deal::<MlDsa65>(&config, PartyId(3), 100)
                .expect("deal 3 coeff 0"),
            backend
                .deal::<MlDsa65>(&config, PartyId(3), 200)
                .expect("deal 3 coeff 1"),
        ],
    ];
    let commits = dealer_vectors
        .iter()
        .map(|vector| {
            dkg_commit_from_in_process_scalar_vss_public_checks(
                &vector
                    .iter()
                    .map(|deal| deal.public_check.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);

    for (runtime, commit) in runtimes.iter_mut().zip(&commits) {
        runtime
            .drive_broadcast_vss_commit(commit)
            .expect("broadcast vector commit");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (_status, _commits) = runtimes[1]
        .drive_collect_vss_commit_round()
        .expect("collect vector commits with cursor");
    let mut public_check_vectors =
        recover_logged_in_process_scalar_vss_public_check_vectors(runtimes[1].runtime())
            .expect("recover vector public checks");
    public_check_vectors.sort_by_key(|checks| checks[0].dealer.0);
    assert_eq!(public_check_vectors.len(), 3);
    assert!(public_check_vectors.iter().all(|checks| checks.len() == 2));

    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }
    for (runtime, vector) in runtimes.iter_mut().zip(&dealer_vectors) {
        let receiver_shares = vector
            .iter()
            .map(|deal| {
                *deal
                    .shares
                    .iter()
                    .find(|share| share.share.receiver == PartyId(2))
                    .expect("receiver vector share")
            })
            .collect::<Vec<_>>();
        runtime
            .drive_send_vss_share(
                PartyId(2),
                &dkg_share_from_in_process_scalar_vss_private_shares(&receiver_shares),
            )
            .expect("send vector share payload");
    }
    route_cursored_logged_dkg_private_messages(&mut runtimes, [0usize, 1, 2]);

    let complaints = verify_logged_in_process_scalar_vss_receiver_vector_shares::<MlDsa65, _, _>(
        &config,
        runtimes[1].runtime_mut(),
        &public_check_vectors,
    )
    .expect("verify vector shares");
    assert!(complaints.is_empty());
    assert_eq!(
        verify_logged_in_process_scalar_vss_receiver_vector_shares_from_log::<MlDsa65, _, _>(
            &config,
            runtimes[1].runtime(),
            &public_check_vectors,
        ),
        Ok(Vec::new())
    );

    let combined = combine_accepted_in_process_scalar_vss_vector_deals::<MlDsa65>(
        &config,
        &dealer_vectors,
        &complaints,
    )
    .expect("combine vector deals");
    assert_eq!(combined.len(), 2);
    let reconstructed = combined
        .iter()
        .map(|output| {
            reconstruct_scalar_at_zero::<MlDsa65>(
                &output
                    .shares
                    .iter()
                    .take(usize::from(config.threshold))
                    .map(|share| ShamirScalarShare {
                        point: share.point,
                        value: share.value,
                    })
                    .collect::<Vec<_>>(),
            )
            .expect("reconstruct vector coefficient")
        })
        .collect::<Vec<_>>();
    assert_eq!(reconstructed, vec![111, 222]);
}

#[test]
fn logged_native_dkg_scaffold_assembles_output_packages_and_certificate() {
    let config = config_for::<MlDsa44>();
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);

    for vector in [SecretVectorKind::S1, SecretVectorKind::S2] {
        for index in 0..vector.coefficient_count::<MlDsa44>() {
            let contributions = small_contributions::<MlDsa44>(&config, vector, index, &[1, 2, 3]);
            for (runtime, contribution) in runtimes.iter_mut().zip(&contributions) {
                runtime
                    .drive_broadcast_small_residue(contribution)
                    .expect("broadcast dkg residue");
            }
            route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
            let label = SamplerLabel::new::<MlDsa44>(&config, vector, index).expect("label");
            runtimes[1]
                .drive_collect_small_residue_round(
                    label,
                    SmallSecretEta::for_params::<MlDsa44>().expect("eta"),
                )
                .expect("collect dkg residue");
            for runtime in &mut runtimes {
                runtime
                    .runtime_mut()
                    .state_mut()
                    .transport_mut()
                    .clear_queued_messages();
            }
        }
    }

    let mut vss = InProcessScalarItVssBackend::new([0x95; 32]);
    let dealer_vectors = vec![
        vec![
            vss.deal::<MlDsa44>(&config, PartyId(1), 1).expect("deal"),
            vss.deal::<MlDsa44>(&config, PartyId(1), 2).expect("deal"),
        ],
        vec![
            vss.deal::<MlDsa44>(&config, PartyId(2), 3).expect("deal"),
            vss.deal::<MlDsa44>(&config, PartyId(2), 4).expect("deal"),
        ],
        vec![
            vss.deal::<MlDsa44>(&config, PartyId(3), 5).expect("deal"),
            vss.deal::<MlDsa44>(&config, PartyId(3), 6).expect("deal"),
        ],
    ];
    let commits = dealer_vectors
        .iter()
        .map(|vector| {
            dkg_commit_from_in_process_scalar_vss_public_checks(
                &vector
                    .iter()
                    .map(|deal| deal.public_check.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    for (runtime, commit) in runtimes.iter_mut().zip(&commits) {
        runtime
            .drive_broadcast_vss_commit(commit)
            .expect("broadcast native dkg vss commit");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    runtimes[1]
        .drive_collect_vss_commit_round()
        .expect("collect native dkg vss commits");
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }
    for (runtime, vector) in runtimes.iter_mut().zip(&dealer_vectors) {
        let receiver_shares = vector
            .iter()
            .map(|deal| {
                *deal
                    .shares
                    .iter()
                    .find(|share| share.share.receiver == PartyId(2))
                    .expect("receiver share")
            })
            .collect::<Vec<_>>();
        runtime
            .drive_send_vss_share(
                PartyId(2),
                &dkg_share_from_in_process_scalar_vss_private_shares(&receiver_shares),
            )
            .expect("send native dkg vss shares");
    }
    route_cursored_logged_dkg_private_messages(&mut runtimes, [0usize, 1, 2]);
    runtimes[1]
        .drive_collect_vss_share_round(PartyId(2))
        .expect("collect native dkg vss shares");
    persist_logged_scaffold_it_vss_artifacts_from_logs::<MlDsa44, _, _>(
        &config,
        runtimes[1].runtime_mut(),
    )
    .expect("persist it-vss artifacts");

    let mut sampler = InProcessDistributedSmallSampler::new([0x96; 32]);
    let mut power2round = ClearSimPower2RoundBackend;
    let assembled = assemble_logged_native_dkg_scaffold_from_logs::<MlDsa44, _, _, _>(
        &config,
        [0x97; 32],
        runtimes[1].runtime_mut(),
        &mut sampler,
        &mut power2round,
    )
    .expect("assemble logged native dkg scaffold");

    assembled
        .public
        .validate_binding()
        .expect("valid public output");
    assert_eq!(assembled.key_packages.len(), config.parties.len());
    assert_eq!(assembled.accepted_dealers, config.parties);
    assert!(assembled.rejected_dealers.is_empty());
    assert!(assembled.complaints.is_empty());
    assert_eq!(
        assembled.certificate.power2round.backend_id,
        Power2RoundBackendId::InsecureClearSimulator
    );
    let setup = assembled
        .certificate
        .setup
        .as_ref()
        .expect("setup certificate");
    ensure_logged_dkg_setup_matches_certificate::<MlDsa44, _, _>(
        &config,
        runtimes[1].runtime(),
        &assembled.certificate,
    )
    .expect("local setup log matches certificate");
    assert_eq!(setup.setup_backend_id, DkgSetupBackendId::InProcessScaffold);
    assert!(setup.complaints.is_empty());
    assert_eq!(setup.accepted_dealers, config.parties);
    assert_eq!(
        setup.release_blockers,
        vec![
            DkgReleaseBlocker::ScaffoldItVssAdapters,
            DkgReleaseBlocker::ProductionItVss,
            DkgReleaseBlocker::ProductionItMpc,
            DkgReleaseBlocker::TransportConformance,
        ]
    );
    for package in &assembled.key_packages {
        assert!(!package.s1_share.s1_share.is_empty());
        assert!(package.certificate.setup.is_some());
        assert!(format!("{:?}", package.s1_share).contains("<redacted>"));
    }
}

#[test]
fn logged_native_dkg_scaffold_rejects_missing_and_disagreeing_it_vss_artifacts() {
    let config = config_for::<MlDsa44>();
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);

    for vector in [SecretVectorKind::S1, SecretVectorKind::S2] {
        for index in 0..vector.coefficient_count::<MlDsa44>() {
            let contributions = small_contributions::<MlDsa44>(&config, vector, index, &[1, 2, 3]);
            for (runtime, contribution) in runtimes.iter_mut().zip(&contributions) {
                runtime
                    .drive_broadcast_small_residue(contribution)
                    .expect("broadcast dkg residue");
            }
            route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
            let label = SamplerLabel::new::<MlDsa44>(&config, vector, index).expect("label");
            runtimes[1]
                .drive_collect_small_residue_round(
                    label,
                    SmallSecretEta::for_params::<MlDsa44>().expect("eta"),
                )
                .expect("collect dkg residue");
            for runtime in &mut runtimes {
                runtime
                    .runtime_mut()
                    .state_mut()
                    .transport_mut()
                    .clear_queued_messages();
            }
        }
    }

    let mut vss = InProcessScalarItVssBackend::new([0xa3; 32]);
    let dealer_vectors = vec![
        vec![
            vss.deal::<MlDsa44>(&config, PartyId(1), 1).expect("deal"),
            vss.deal::<MlDsa44>(&config, PartyId(1), 2).expect("deal"),
        ],
        vec![
            vss.deal::<MlDsa44>(&config, PartyId(2), 3).expect("deal"),
            vss.deal::<MlDsa44>(&config, PartyId(2), 4).expect("deal"),
        ],
        vec![
            vss.deal::<MlDsa44>(&config, PartyId(3), 5).expect("deal"),
            vss.deal::<MlDsa44>(&config, PartyId(3), 6).expect("deal"),
        ],
    ];
    let commits = dealer_vectors
        .iter()
        .map(|vector| {
            dkg_commit_from_in_process_scalar_vss_public_checks(
                &vector
                    .iter()
                    .map(|deal| deal.public_check.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    for (runtime, commit) in runtimes.iter_mut().zip(&commits) {
        runtime
            .drive_broadcast_vss_commit(commit)
            .expect("broadcast native dkg vss commit");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    runtimes[1]
        .drive_collect_vss_commit_round()
        .expect("collect native dkg vss commits");
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }
    for (runtime, vector) in runtimes.iter_mut().zip(&dealer_vectors) {
        let receiver_shares = vector
            .iter()
            .map(|deal| {
                *deal
                    .shares
                    .iter()
                    .find(|share| share.share.receiver == PartyId(2))
                    .expect("receiver share")
            })
            .collect::<Vec<_>>();
        runtime
            .drive_send_vss_share(
                PartyId(2),
                &dkg_share_from_in_process_scalar_vss_private_shares(&receiver_shares),
            )
            .expect("send native dkg vss shares");
    }
    route_cursored_logged_dkg_private_messages(&mut runtimes, [0usize, 1, 2]);
    runtimes[1]
        .drive_collect_vss_share_round(PartyId(2))
        .expect("collect native dkg vss shares");

    let base_runtime = runtimes[1].runtime().clone();
    let mut sampler = InProcessDistributedSmallSampler::new([0xa4; 32]);
    let mut power2round = ClearSimPower2RoundBackend;
    let mut missing_artifacts = base_runtime.clone();
    assert!(matches!(
        assemble_logged_native_dkg_scaffold_from_logs::<MlDsa44, _, _, _>(
            &config,
            [0xa5; 32],
            &mut missing_artifacts,
            &mut sampler,
            &mut power2round,
        )
        .map(|_| ()),
        Err(DkgError::ItVssCertificateMissingCommitment { .. })
            | Err(DkgError::MissingDkgSetupCertificate)
    ));

    let public_check_vectors =
        recover_logged_in_process_scalar_vss_public_check_vectors(&base_runtime)
            .expect("recover checks");
    let complaints = verify_logged_in_process_scalar_vss_receiver_vector_shares_from_log::<
        MlDsa44,
        _,
        _,
    >(&config, &base_runtime, &public_check_vectors)
    .expect("verify shares");
    let scalar_resolution = resolve_in_process_scalar_vss_vector_complaints::<MlDsa44>(
        &config,
        &public_check_vectors,
        &complaints,
    )
    .expect("scalar resolution");
    let (public_commitments, resolution) =
        scaffold_it_vss_resolution_from_in_process_scalar_vss_vector_resolution(
            &config,
            &public_check_vectors,
            &complaints,
            &scalar_resolution,
        )
        .expect("it-vss artifacts");

    let mut missing_commitment_runtime = base_runtime.clone();
    missing_commitment_runtime
        .persist_it_vss_artifacts_logged(&public_commitments[1..], &resolution)
        .expect("persist missing commitment artifacts");
    let mut sampler = InProcessDistributedSmallSampler::new([0xa6; 32]);
    let mut power2round = ClearSimPower2RoundBackend;
    assert!(matches!(
        assemble_logged_native_dkg_scaffold_from_logs::<MlDsa44, _, _, _>(
            &config,
            [0xa7; 32],
            &mut missing_commitment_runtime,
            &mut sampler,
            &mut power2round,
        ),
        Err(DkgError::ItVssCertificateMissingCommitment { .. })
    ));

    let mut disagreeing_resolution = resolution.clone();
    disagreeing_resolution.rejected_dealers.push(PartyId(3));
    disagreeing_resolution
        .accepted_dealers
        .retain(|party| *party != PartyId(3));
    let mut disagreeing_runtime = base_runtime;
    disagreeing_runtime
        .persist_it_vss_artifacts_logged(&public_commitments, &disagreeing_resolution)
        .expect("persist disagreeing artifacts");
    let mut sampler = InProcessDistributedSmallSampler::new([0xa8; 32]);
    let mut power2round = ClearSimPower2RoundBackend;
    assert!(matches!(
        assemble_logged_native_dkg_scaffold_from_logs::<MlDsa44, _, _, _>(
            &config,
            [0xa9; 32],
            &mut disagreeing_runtime,
            &mut sampler,
            &mut power2round,
        ),
        Err(DkgError::ItVssResolutionUnexpectedCertificate { .. })
            | Err(DkgError::ComplaintEvidenceMismatch)
    ));
}

#[test]
fn logged_public_output_keeps_signing_parties_when_contribution_dealer_rejected() {
    let config = config_for::<MlDsa44>();
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);
    let mut vss = InProcessScalarItVssBackend::new([0x98; 32]);
    let dealer_vectors = [
        vec![
            vss.deal::<MlDsa44>(&config, PartyId(1), 1)
                .expect("deal 1 coeff 0"),
            vss.deal::<MlDsa44>(&config, PartyId(1), 2)
                .expect("deal 1 coeff 1"),
        ],
        vec![
            vss.deal::<MlDsa44>(&config, PartyId(2), 3)
                .expect("deal 2 coeff 0"),
            vss.deal::<MlDsa44>(&config, PartyId(2), 4)
                .expect("deal 2 coeff 1"),
        ],
        vec![
            vss.deal::<MlDsa44>(&config, PartyId(3), 5)
                .expect("deal 3 coeff 0"),
            vss.deal::<MlDsa44>(&config, PartyId(3), 6)
                .expect("deal 3 coeff 1"),
        ],
    ];
    let commits = dealer_vectors
        .iter()
        .map(|vector| {
            dkg_commit_from_in_process_scalar_vss_public_checks(
                &vector
                    .iter()
                    .map(|deal| deal.public_check.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    for (runtime, commit) in runtimes.iter_mut().zip(&commits) {
        runtime
            .drive_broadcast_vss_commit(commit)
            .expect("broadcast native dkg vss commit");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    runtimes[1]
        .drive_collect_vss_commit_round()
        .expect("collect native dkg vss commits");

    let accepted_dealers = parties(&[1, 3]);
    let mut power2round = ClearSimPower2RoundBackend;
    let (mut public, _certificate) = assemble_public_output_scaffold::<MlDsa44, _>(
        &config,
        [0x99; 32],
        sampled_material::<MlDsa44>(&config).expect("sample material"),
        &accepted_dealers,
        &mut power2round,
    )
    .expect("assemble public output scaffold");

    apply_logged_vss_commitments_to_public_output(
        &mut public,
        runtimes[1].runtime(),
        &accepted_dealers,
    )
    .expect("apply logged commitments");

    public.validate_binding().expect("valid public output");
    assert_eq!(
        public
            .as1_commitments
            .iter()
            .map(|commitment| commitment.party)
            .collect::<Vec<_>>(),
        config.parties
    );
    assert_eq!(
        public
            .pairwise_seed_commitments
            .iter()
            .map(|commitment| commitment.party)
            .collect::<Vec<_>>(),
        config.parties
    );
    assert_eq!(
        public.vss_commitments,
        commits[0]
            .vss_commitments
            .iter()
            .chain(commits[2].vss_commitments.iter())
            .cloned()
            .collect::<Vec<_>>()
    );
}

#[test]
fn logged_native_dkg_scaffold_assembles_with_complaint_rejected_dealer() {
    let config = config_for::<MlDsa44>();
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);
    drive_full_logged_small_sampler::<MlDsa44>(&config, &mut runtimes);

    let mut vss = InProcessScalarItVssBackend::new([0x9a; 32]);
    let dealer_vectors = [
        vec![
            vss.deal::<MlDsa44>(&config, PartyId(1), 1)
                .expect("deal 1 coeff 0"),
            vss.deal::<MlDsa44>(&config, PartyId(1), 2)
                .expect("deal 1 coeff 1"),
        ],
        vec![
            vss.deal::<MlDsa44>(&config, PartyId(2), 3)
                .expect("deal 2 coeff 0"),
            vss.deal::<MlDsa44>(&config, PartyId(2), 4)
                .expect("deal 2 coeff 1"),
        ],
        vec![
            vss.deal::<MlDsa44>(&config, PartyId(3), 5)
                .expect("deal 3 coeff 0"),
            vss.deal::<MlDsa44>(&config, PartyId(3), 6)
                .expect("deal 3 coeff 1"),
        ],
    ];
    let commits = dealer_vectors
        .iter()
        .map(|vector| {
            dkg_commit_from_in_process_scalar_vss_public_checks(
                &vector
                    .iter()
                    .map(|deal| deal.public_check.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    for (runtime, commit) in runtimes.iter_mut().zip(&commits) {
        runtime
            .drive_broadcast_vss_commit(commit)
            .expect("broadcast complaint-test vss commit");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    for runtime in &mut runtimes {
        runtime
            .drive_collect_vss_commit_round()
            .expect("collect complaint-test vss commits");
    }
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }

    for receiver in config.parties.clone() {
        for (runtime, vector) in runtimes.iter_mut().zip(dealer_vectors.iter()) {
            let mut receiver_shares = vector
                .iter()
                .map(|deal| {
                    *deal
                        .shares
                        .iter()
                        .find(|share| share.share.receiver == receiver)
                        .expect("receiver vector share")
                })
                .collect::<Vec<_>>();
            if runtime.local_party() == PartyId(2) {
                receiver_shares[0].share.value =
                    reduce_mod_q::<MlDsa44>(receiver_shares[0].share.value + 1);
            }
            runtime
                .drive_send_vss_share(
                    receiver,
                    &dkg_share_from_in_process_scalar_vss_private_shares(&receiver_shares),
                )
                .expect("send complaint-test vss shares");
        }
        route_cursored_logged_dkg_private_messages(&mut runtimes, [0usize, 1, 2]);
        let receiver_idx = runtimes
            .iter()
            .position(|runtime| runtime.local_party() == receiver)
            .expect("receiver runtime");
        runtimes[receiver_idx]
            .drive_collect_vss_share_round(receiver)
            .expect("collect complaint-test vss shares");
        for runtime in &mut runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
    }

    let mut complaints_to_broadcast = Vec::new();
    for runtime in &runtimes {
        let public_checks =
            recover_logged_in_process_scalar_vss_public_check_vectors(runtime.runtime())
                .expect("recover public checks");
        let complaints = verify_logged_in_process_scalar_vss_receiver_vector_shares_from_log::<
            MlDsa44,
            _,
            _,
        >(&config, runtime.runtime(), &public_checks)
        .expect("verify tampered vector shares");
        assert_eq!(complaints.len(), 1);
        assert_eq!(complaints[0].complainant, runtime.local_party());
        assert_eq!(complaints[0].dealer, PartyId(2));
        assert_eq!(complaints[0].receiver, runtime.local_party());
        complaints_to_broadcast.push(complaints[0].clone());
    }

    for (runtime, complaint) in runtimes.iter_mut().zip(&complaints_to_broadcast) {
        runtime
            .drive_broadcast_vss_complaint(complaint)
            .expect("broadcast valid vss complaint");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let mut expected_complaints = complaints_to_broadcast.clone();
    expected_complaints.sort_by_key(|complaint| complaint.complainant.0);
    for runtime in &mut runtimes {
        let (_status, collected) = runtime
            .drive_collect_vss_complaint_round()
            .expect("collect valid vss complaints");
        let mut collected = collected;
        collected.sort_by_key(|complaint| complaint.complainant.0);
        assert_eq!(collected, expected_complaints);
    }
    let mut recovered_complaints = runtimes[1]
        .runtime()
        .recover_vss_complaint_round_from_log()
        .expect("recover accepted complaints");
    recovered_complaints.sort_by_key(|complaint| complaint.complainant.0);
    assert_eq!(recovered_complaints, expected_complaints);

    let mut restored_receiver = CursoredLoggedDkgTransportPartyRuntime::new(
        LoggedDkgTransportPartyRuntime::new(
            DkgTransportStateMachine::new(
                config.clone(),
                PartyId(2),
                talus_wire::InMemoryTransport::new(2, vec![1, 2, 3]).expect("transport"),
            )
            .expect("state"),
            runtimes[1].runtime().wire_log().clone(),
        ),
        runtimes[1].cursor_log().clone(),
    );
    let latest = restored_receiver
        .resume()
        .expect("resume complaint receiver")
        .expect("latest complaint cursor");
    assert_eq!(latest.phase, DkgTransportPhase::VssComplaint);
    assert_eq!(latest.state, DkgSetupPhaseCursorState::Collected);
    let mut recovered_after_restart = restored_receiver
        .runtime()
        .recover_vss_complaint_round_from_log()
        .expect("recover complaints after restart");
    recovered_after_restart.sort_by_key(|complaint| complaint.complainant.0);
    assert_eq!(recovered_after_restart, expected_complaints);

    let mut sampler = InProcessDistributedSmallSampler::new([0x9b; 32]);
    let mut power2round = ClearSimPower2RoundBackend;
    persist_logged_scaffold_it_vss_artifacts_from_logs::<MlDsa44, _, _>(
        &config,
        restored_receiver.runtime_mut(),
    )
    .expect("persist complaint-test it-vss artifacts");
    let assembled = assemble_logged_native_dkg_scaffold_from_logs::<MlDsa44, _, _, _>(
        &config,
        [0x9c; 32],
        restored_receiver.runtime_mut(),
        &mut sampler,
        &mut power2round,
    )
    .expect("assemble with complaint-rejected dealer");

    assembled
        .public
        .validate_binding()
        .expect("valid complaint assembly output");
    assert_eq!(assembled.accepted_dealers, parties(&[1, 3]));
    assert_eq!(assembled.rejected_dealers, parties(&[2]));
    let mut assembled_complaints = assembled.complaints.clone();
    assembled_complaints.sort_by_key(|complaint| complaint.complainant.0);
    assert_eq!(assembled_complaints, expected_complaints);
    assert_eq!(assembled.key_packages.len(), config.parties.len());
    assert_eq!(
        assembled
            .public
            .as1_commitments
            .iter()
            .map(|commitment| commitment.party)
            .collect::<Vec<_>>(),
        config.parties
    );
    assert_eq!(
        assembled
            .public
            .pairwise_seed_commitments
            .iter()
            .map(|commitment| commitment.party)
            .collect::<Vec<_>>(),
        config.parties
    );
    assert_eq!(
        assembled.public.vss_commitments,
        commits[0]
            .vss_commitments
            .iter()
            .chain(commits[2].vss_commitments.iter())
            .cloned()
            .collect::<Vec<_>>()
    );

    let setup = assembled
        .certificate
        .setup
        .as_ref()
        .expect("setup certificate");
    let mut setup_complaints = setup.complaints.clone();
    setup_complaints.sort_by_key(|complaint| complaint.complainant.0);
    assert_eq!(setup_complaints, expected_complaints);
    assert_eq!(setup.accepted_dealers, parties(&[1, 3]));
    assert_eq!(setup.rejected_dealers, parties(&[2]));
    assert_eq!(
        setup.complaint_hash,
        hash_dkg_complaint_payloads(&assembled.complaints)
    );
    for package in &assembled.key_packages {
        assert!(!package.s1_share.s1_share.is_empty());
        assert!(package.certificate.setup.is_some());
        let debug = format!("{package:?}");
        assert!(!debug.contains("s2_share"));
        assert!(!debug.contains("t0_share"));
        assert!(!debug.contains("SharedT"));
    }
}

#[test]
fn logged_native_dkg_scaffold_resumes_from_setup_logs_and_cursors() {
    let config = config_for::<MlDsa44>();
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);

    let first_label =
        SamplerLabel::new::<MlDsa44>(&config, SecretVectorKind::S1, 0).expect("label");
    let first_contributions =
        small_contributions::<MlDsa44>(&config, SecretVectorKind::S1, 0, &[1, 2, 3]);
    for (runtime, contribution) in runtimes.iter_mut().zip(&first_contributions) {
        runtime
            .drive_broadcast_small_residue(contribution)
            .expect("broadcast first residue");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    runtimes[1]
        .drive_collect_small_residue_round(
            first_label,
            SmallSecretEta::for_params::<MlDsa44>().expect("eta"),
        )
        .expect("collect first residue");
    let recovered_before_restart = runtimes[1]
        .runtime()
        .recover_small_residue_round_from_log(
            first_label,
            SmallSecretEta::for_params::<MlDsa44>().expect("eta"),
        )
        .expect("recover before restart");
    assert_eq!(recovered_before_restart, first_contributions);

    let mut restored_receiver = CursoredLoggedDkgTransportPartyRuntime::new(
        LoggedDkgTransportPartyRuntime::new(
            DkgTransportStateMachine::new(
                config.clone(),
                PartyId(2),
                talus_wire::InMemoryTransport::new(2, vec![1, 2, 3]).expect("transport"),
            )
            .expect("state"),
            runtimes[1].runtime().wire_log().clone(),
        ),
        runtimes[1].cursor_log().clone(),
    );
    let latest = restored_receiver
        .resume()
        .expect("resume receiver")
        .expect("latest cursor");
    assert_eq!(latest.state, DkgSetupPhaseCursorState::Collected);
    assert_eq!(latest.vector, Some(SecretVectorKind::S1));
    assert_eq!(latest.coefficient_index, Some(0));
    runtimes[1] = restored_receiver;
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }

    for vector in [SecretVectorKind::S1, SecretVectorKind::S2] {
        let start = if vector == SecretVectorKind::S1 { 1 } else { 0 };
        for index in start..vector.coefficient_count::<MlDsa44>() {
            let contributions = small_contributions::<MlDsa44>(&config, vector, index, &[1, 2, 3]);
            for (runtime, contribution) in runtimes.iter_mut().zip(&contributions) {
                runtime
                    .drive_broadcast_small_residue(contribution)
                    .expect("broadcast resumed residue");
            }
            route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
            let label = SamplerLabel::new::<MlDsa44>(&config, vector, index).expect("label");
            runtimes[1]
                .drive_collect_small_residue_round(
                    label,
                    SmallSecretEta::for_params::<MlDsa44>().expect("eta"),
                )
                .expect("collect resumed residue");
            for runtime in &mut runtimes {
                runtime
                    .runtime_mut()
                    .state_mut()
                    .transport_mut()
                    .clear_queued_messages();
            }
        }
    }
    assert_eq!(
        runtimes[1]
            .runtime()
            .recover_small_residue_round_from_log(
                first_label,
                SmallSecretEta::for_params::<MlDsa44>().expect("eta"),
            )
            .expect("recover first after restart"),
        first_contributions
    );

    let mut vss = InProcessScalarItVssBackend::new([0x98; 32]);
    let dealer_vectors = config
        .parties
        .iter()
        .map(|&party| {
            vec![
                vss.deal::<MlDsa44>(&config, party, Coeff::from(party.0))
                    .expect("deal coeff 0"),
                vss.deal::<MlDsa44>(&config, party, Coeff::from(party.0 + 10))
                    .expect("deal coeff 1"),
            ]
        })
        .collect::<Vec<_>>();
    let commits = dealer_vectors
        .iter()
        .map(|vector| {
            dkg_commit_from_in_process_scalar_vss_public_checks(
                &vector
                    .iter()
                    .map(|deal| deal.public_check.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    for (runtime, commit) in runtimes.iter_mut().zip(&commits) {
        runtime
            .drive_broadcast_vss_commit(commit)
            .expect("broadcast resumed vss commit");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    runtimes[1]
        .drive_collect_vss_commit_round()
        .expect("collect resumed vss commits");
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }
    for (runtime, vector) in runtimes.iter_mut().zip(&dealer_vectors) {
        let receiver_shares = vector
            .iter()
            .map(|deal| {
                *deal
                    .shares
                    .iter()
                    .find(|share| share.share.receiver == PartyId(2))
                    .expect("receiver share")
            })
            .collect::<Vec<_>>();
        runtime
            .drive_send_vss_share(
                PartyId(2),
                &dkg_share_from_in_process_scalar_vss_private_shares(&receiver_shares),
            )
            .expect("send resumed vss share");
    }
    route_cursored_logged_dkg_private_messages(&mut runtimes, [0usize, 1, 2]);
    runtimes[1]
        .drive_collect_vss_share_round(PartyId(2))
        .expect("collect resumed vss shares");

    let mut sampler = InProcessDistributedSmallSampler::new([0x99; 32]);
    let mut power2round = ClearSimPower2RoundBackend;
    persist_logged_scaffold_it_vss_artifacts_from_logs::<MlDsa44, _, _>(
        &config,
        runtimes[1].runtime_mut(),
    )
    .expect("persist resumed it-vss artifacts");
    let assembled = assemble_logged_native_dkg_scaffold_from_logs::<MlDsa44, _, _, _>(
        &config,
        [0x9a; 32],
        runtimes[1].runtime_mut(),
        &mut sampler,
        &mut power2round,
    )
    .expect("assemble after restart");
    assembled.public.validate_binding().expect("valid output");
    assert_eq!(assembled.key_packages.len(), config.parties.len());
    assert_eq!(
        assembled
            .certificate
            .setup
            .as_ref()
            .expect("setup certificate")
            .accepted_dealers,
        config.parties
    );
}

#[cfg(feature = "std")]
#[test]
fn file_dkg_wire_log_survives_reopen_and_rejects_corrupt_log() {
    let path = std::env::temp_dir().join(format!("talus-dkg-wire-log-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let config = config();
    let mut runtime = LoggedDkgTransportPartyRuntime::new(
        DkgTransportStateMachine::new(
            config,
            PartyId(1),
            talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport"),
        )
        .expect("state"),
        FileDkgWireMessageLog::open(&path).expect("open dkg wire log"),
    );
    let share = DkgSharePayload {
        dealer: PartyId(1),
        receiver: PartyId(2),
        encrypted_share: vec![1],
        encrypted_seed_share: vec![2],
        proof: vec![3],
    };
    runtime
        .send_vss_share_logged(PartyId(2), &share)
        .expect("logged send");
    assert_eq!(runtime.wire_log().dkg_wire_records().len(), 1);

    let reopened = FileDkgWireMessageLog::open(&path).expect("reopen dkg wire log");
    assert_eq!(reopened.records().len(), 1);

    std::fs::write(&path, b"not a valid dkg wire log\n").expect("write corrupt");
    assert_eq!(
        FileDkgWireMessageLog::open(&path),
        Err(DkgError::DkgWireLogCorrupt { line: 1 })
    );
    let _ = std::fs::remove_file(&path);
}

#[cfg(feature = "std")]
#[test]
fn file_dkg_setup_phase_cursor_log_survives_reopen_and_rejects_corrupt_log() {
    let path = std::env::temp_dir().join(format!(
        "talus-dkg-setup-phase-cursor-log-{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let cursor = DkgSetupPhaseCursor {
        phase: DkgTransportPhase::SmallResidue,
        state: DkgSetupPhaseCursorState::Collected,
        receiver: None,
        vector: Some(SecretVectorKind::S1),
        coefficient_index: Some(17),
        it_vss_phase: None,
        expected: 3,
        got: 3,
    };
    {
        let mut log = FileDkgSetupPhaseCursorLog::open(&path).expect("open cursor log");
        log.persist_setup_phase_cursor(&cursor)
            .expect("persist cursor");
    }
    let reopened = FileDkgSetupPhaseCursorLog::open(&path).expect("reopen cursor log");
    assert_eq!(reopened.cursors(), std::slice::from_ref(&cursor));

    std::fs::write(&path, b"not a valid setup cursor\n").expect("write corrupt cursor log");
    assert_eq!(
        FileDkgSetupPhaseCursorLog::open(&path),
        Err(DkgError::DkgSetupPhaseCursorLogCorrupt { line: 1 })
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn transport_power2round_coefficient_phase_helpers_are_transcript_bound() {
    let config = config();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let coeff_label = Power2RoundTranscriptLabel::root(&config, [0x5d; 32]).child("poly_0/coeff_7");

    state
        .send_power2round_mask_bit(PartyId(2), &coeff_label, 3, 1)
        .expect("send mask bit");
    assert_eq!(
        state
            .collect_power2round_mask_bits(PartyId(2), &coeff_label, 3)
            .expect("collect mask bit"),
        vec![(PartyId(1), 1)]
    );

    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    for sender in [1u16, 2, 3] {
        let mut message = state
            .wire_message(
                PrimeFieldMpcRoundKind::Open,
                PrimeFieldMpcPhase::Power2RoundMaskedOpenC,
                &coeff_label.child("open_masked_c"),
                None,
                i32::from(sender),
            )
            .expect("wire message");
        message.header.sender_party_id = sender;
        for observer in [1u16, 2, 3] {
            state
                .transport_mut()
                .inject_broadcast_delivery(observer, message.clone())
                .expect("inject masked c");
        }
    }
    assert_eq!(
        state
            .collect_power2round_masked_c(&coeff_label)
            .expect("collect masked c"),
        vec![(PartyId(1), 1), (PartyId(2), 2), (PartyId(3), 3)]
    );

    let completion = Power2RoundCoefficientCompletion {
        poly_idx: 0,
        coeff_idx: 7,
        t1: 42,
        label_hash: power2round_label_hash(&coeff_label),
    };
    let mut log = InMemoryPrimeFieldMpcRoundLog::default();
    state
        .persist_completed_coefficient(&mut log, &completion)
        .expect("persist completion");
    assert_eq!(
        log.completed_coefficients(),
        std::slice::from_ref(&completion)
    );
    assert_eq!(
        state.persist_completed_coefficient(&mut log, &completion),
        Err(DkgError::PrimeFieldMpcReplayDetected)
    );
}

#[test]
fn transport_prime_field_mpc_state_machine_collects_equivocation_checked_broadcasts() {
    let config = config();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let label =
        Power2RoundTranscriptLabel::root(&config, [0x53; 32]).child("assert_zero_broadcast");

    for sender in [1u16, 2, 3] {
        let mut message = state
            .wire_message(
                PrimeFieldMpcRoundKind::AssertZero,
                PrimeFieldMpcPhase::AssertZeroShare,
                &label,
                None,
                i32::from(sender),
            )
            .expect("wire message");
        message.header.sender_party_id = sender;
        for observer in [1u16, 2, 3] {
            state
                .transport_mut()
                .inject_broadcast_delivery(observer, message.clone())
                .expect("inject broadcast");
        }
    }

    let values = state
        .collect_broadcast_values(PrimeFieldMpcRoundKind::AssertZero, &label)
        .expect("collect broadcast values");
    assert_eq!(
        values,
        vec![(PartyId(1), 1), (PartyId(2), 2), (PartyId(3), 3)]
    );
    assert_eq!(state.accepted_rounds().len(), 1);
}

#[test]
fn transport_prime_field_mpc_state_machine_rejects_context_and_replay_failures() {
    let config = config();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let label = Power2RoundTranscriptLabel::root(&config, [0x54; 32]).child("bad_context");

    let mut wrong_suite = state
        .wire_message(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            &label,
            Some(PartyId(2)),
            1,
        )
        .expect("wire message");
    wrong_suite.header.suite = talus_wire::SuiteId::MlDsa44;
    state
        .transport_mut()
        .inject_private(1, 2, wrong_suite)
        .expect("inject wrong suite");
    assert_eq!(
        state.collect_directed_values(PartyId(2), PrimeFieldMpcRoundKind::Open, &label),
        Err(DkgError::PrimeFieldMpcTransport)
    );

    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let replay_label = Power2RoundTranscriptLabel::root(&config, [0x55; 32]).child("replay");
    state
        .send_directed_value(PartyId(2), PrimeFieldMpcRoundKind::Open, &replay_label, 1)
        .expect("send first");
    state
        .send_directed_value(PartyId(2), PrimeFieldMpcRoundKind::Open, &replay_label, 2)
        .expect("send duplicate");
    assert_eq!(
        state.collect_directed_values(PartyId(2), PrimeFieldMpcRoundKind::Open, &replay_label),
        Err(DkgError::PrimeFieldMpcTransport)
    );
}

#[test]
fn transport_prime_field_mpc_state_machine_rejects_wrong_phase_receiver_and_label() {
    let config = config();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let label = Power2RoundTranscriptLabel::root(&config, [0x57; 32]).child("wrong_phase");
    state
        .send_directed_phase(
            PartyId(2),
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::T1BitOpening,
            &label,
            1,
        )
        .expect("send wrong phase");
    assert_eq!(
        state.collect_directed_phase(
            PartyId(2),
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            &label,
        ),
        Err(DkgError::PrimeFieldMpcTransport)
    );

    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let label = Power2RoundTranscriptLabel::root(&config, [0x58; 32]).child("wrong_receiver");
    state
        .send_directed_value(PartyId(3), PrimeFieldMpcRoundKind::Open, &label, 1)
        .expect("send wrong receiver");
    assert_eq!(
        state.collect_directed_values(PartyId(2), PrimeFieldMpcRoundKind::Open, &label),
        Ok(Vec::new())
    );

    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let label = Power2RoundTranscriptLabel::root(&config, [0x59; 32]).child("wrong_label");
    let other_label = Power2RoundTranscriptLabel::root(&config, [0x5a; 32]).child("wrong_label");
    state
        .send_directed_value(PartyId(2), PrimeFieldMpcRoundKind::Open, &label, 1)
        .expect("send wrong label");
    assert_eq!(
        state.collect_directed_values(PartyId(2), PrimeFieldMpcRoundKind::Open, &other_label),
        Err(DkgError::PrimeFieldMpcTransport)
    );
}

#[test]
fn transport_prime_field_mpc_state_machine_rejects_broadcast_equivocation() {
    let config = config();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let label = Power2RoundTranscriptLabel::root(&config, [0x5b; 32]).child("equivocation");
    let honest = state
        .wire_message(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            &label,
            None,
            1,
        )
        .expect("wire message");
    let equivocated = state
        .wire_message(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            &label,
            None,
            2,
        )
        .expect("wire message");

    state
        .transport_mut()
        .inject_broadcast_delivery(1, honest.clone())
        .expect("inject observer 1");
    state
        .transport_mut()
        .inject_broadcast_delivery(2, equivocated)
        .expect("inject observer 2");
    state
        .transport_mut()
        .inject_broadcast_delivery(3, honest)
        .expect("inject observer 3");

    assert_eq!(
        state.collect_open_shares(&label),
        Err(DkgError::PrimeFieldMpcTransport)
    );
}

#[test]
fn logged_prime_field_mpc_send_replays_without_regenerating_message() {
    let config = config();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state");
    let mut log = InMemoryPrimeFieldMpcWireMessageLog::default();
    let label = Power2RoundTranscriptLabel::root(&config, [0x61; 32]).child("logged_directed");

    state
        .send_directed_phase_logged(
            &mut log,
            PartyId(2),
            PrimeFieldMpcRoundKind::MulDegreeReduce,
            PrimeFieldMpcPhase::MulDegreeReductionShare,
            &label,
            77,
        )
        .expect("logged send");
    assert_eq!(log.records().len(), 1);
    assert_eq!(
        log.records()[0].direction,
        PrimeFieldMpcWireDirection::SentPrivate
    );

    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut resumed =
        TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
            .expect("resumed state");
    resumed
        .send_directed_phase_logged(
            &mut log,
            PartyId(2),
            PrimeFieldMpcRoundKind::MulDegreeReduce,
            PrimeFieldMpcPhase::MulDegreeReductionShare,
            &label,
            999,
        )
        .expect("replay logged send ignores regenerated value");
    assert_eq!(log.records().len(), 1);

    let values = resumed
        .collect_directed_phase_logged(
            &mut log,
            PartyId(2),
            PrimeFieldMpcRoundKind::MulDegreeReduce,
            PrimeFieldMpcPhase::MulDegreeReductionShare,
            &label,
        )
        .expect("collect replayed value");
    assert_eq!(values, vec![(PartyId(1), 77)]);
    assert!(log
        .records()
        .iter()
        .any(|record| record.direction == PrimeFieldMpcWireDirection::AcceptedPrivate));
}

#[test]
fn party_runtime_resumes_logged_single_party_phase() {
    let config = config();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state");
    let mut runtime = TransportPrimeFieldMpcPartyRuntime::new(
        state,
        InMemoryPrimeFieldMpcWireMessageLog::default(),
    );
    let label = Power2RoundTranscriptLabel::root(&config, [0x62; 32]).child("runtime_mul");

    runtime
        .send_mul_degree_reduction_share(PartyId(2), &label, 11)
        .expect("runtime send");
    let saved_log = runtime.wire_log().clone();

    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state");
    let mut resumed = TransportPrimeFieldMpcPartyRuntime::new(state, saved_log);
    resumed
        .resume_sent_messages()
        .expect("resume sent messages");
    let values = resumed
        .collect_mul_degree_reduction_shares(PartyId(2), &label)
        .expect("collect resumed phase");
    assert_eq!(values, vec![(PartyId(1), 11)]);
    assert!(resumed
        .wire_log()
        .wire_records()
        .iter()
        .any(|record| record.direction == PrimeFieldMpcWireDirection::AcceptedPrivate));
}

#[cfg(feature = "std")]
#[test]
fn file_prime_field_mpc_round_log_survives_reopen_and_rejects_corrupt_log() {
    let path = std::env::temp_dir().join(format!(
        "talus-prime-field-round-log-{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    let round = AcceptedPrimeFieldMpcRound {
        kind: PrimeFieldMpcRoundKind::Open,
        phase: PrimeFieldMpcPhase::T1BitOpening,
        label_hash: [0x5c; 32],
        senders: vec![PartyId(1), PartyId(2)],
    };
    let completion = Power2RoundCoefficientCompletion {
        poly_idx: 1,
        coeff_idx: 9,
        t1: 88,
        label_hash: [0x5d; 32],
    };
    {
        let mut log = FilePrimeFieldMpcRoundLog::open(&path).expect("open log");
        log.persist_round(&round).expect("persist round");
        log.persist_coefficient(&completion)
            .expect("persist coefficient");
    }
    let reopened = FilePrimeFieldMpcRoundLog::open(&path).expect("reopen log");
    assert_eq!(reopened.accepted(), &[round]);
    assert_eq!(reopened.completed_coefficients(), &[completion]);

    std::fs::write(&path, b"not a valid mpc round\n").expect("write corrupt");
    assert_eq!(
        FilePrimeFieldMpcRoundLog::open(&path),
        Err(DkgError::PrimeFieldMpcRoundLogCorrupt { line: 1 })
    );
    let _ = std::fs::remove_file(&path);
}

#[cfg(feature = "std")]
#[test]
fn file_prime_field_mpc_phase_cursor_log_survives_reopen_and_rejects_corrupt_log() {
    let path = std::env::temp_dir().join(format!(
        "talus-prime-field-phase-cursor-log-{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    let waiting = PrimeFieldMpcPhaseCursor {
        kind: PrimeFieldMpcRoundKind::RandomBit,
        phase: PrimeFieldMpcPhase::RandomBitShare,
        receiver: Some(PartyId(2)),
        label_hash: [0x42; 32],
        state: PrimeFieldMpcPhaseCursorState::WaitingPrivate,
        expected: 3,
        got: 1,
    };
    let collected = PrimeFieldMpcPhaseCursor {
        kind: PrimeFieldMpcRoundKind::RandomBit,
        phase: PrimeFieldMpcPhase::RandomBitShare,
        receiver: Some(PartyId(2)),
        label_hash: [0x43; 32],
        state: PrimeFieldMpcPhaseCursorState::Collected,
        expected: 3,
        got: 3,
    };
    {
        let mut log = FilePrimeFieldMpcPhaseCursorLog::open(&path).expect("open cursor log");
        log.persist_phase_cursor(&waiting)
            .expect("persist waiting cursor");
        log.persist_phase_cursor(&collected)
            .expect("persist collected cursor");
    }

    let reopened = FilePrimeFieldMpcPhaseCursorLog::open(&path).expect("reopen cursor log");
    assert_eq!(reopened.cursors(), &[waiting, collected.clone()]);
    assert_eq!(reopened.latest_phase_cursor(), Some(&collected));

    std::fs::write(&path, b"not a valid phase cursor\n").expect("write corrupt cursor log");
    assert_eq!(
        FilePrimeFieldMpcPhaseCursorLog::open(&path),
        Err(DkgError::PrimeFieldMpcPhaseCursorLogCorrupt { line: 1 })
    );
    let _ = std::fs::remove_file(&path);
}

#[cfg(feature = "std")]
#[test]
fn file_prime_field_mpc_wire_log_survives_reopen_and_replays_sent_messages() {
    let path = std::env::temp_dir().join(format!(
        "talus-prime-field-wire-log-{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    let config = config();
    let label = Power2RoundTranscriptLabel::root(&config, [0x63; 32]).child("file_wire_log");
    {
        let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
        let mut state =
            TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
                .expect("state");
        let mut log = FilePrimeFieldMpcWireMessageLog::open(&path).expect("open wire log");
        state
            .send_directed_phase_logged(
                &mut log,
                PartyId(2),
                PrimeFieldMpcRoundKind::RandomBit,
                PrimeFieldMpcPhase::RandomBitShare,
                &label,
                1,
            )
            .expect("logged send");
        assert_eq!(log.records().len(), 1);
    }

    let mut reopened = FilePrimeFieldMpcWireMessageLog::open(&path).expect("reopen wire log");
    assert_eq!(reopened.records().len(), 1);
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state");
    state
        .replay_logged_sent_messages(&reopened)
        .expect("replay sent");
    let values = state
        .collect_directed_phase_logged(
            &mut reopened,
            PartyId(2),
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::RandomBitShare,
            &label,
        )
        .expect("collect replayed");
    assert_eq!(values, vec![(PartyId(1), 1)]);
    assert_eq!(reopened.records().len(), 2);

    let reopened_again =
        FilePrimeFieldMpcWireMessageLog::open(&path).expect("reopen accepted wire log");
    assert_eq!(reopened_again.records().len(), 2);
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let mut recovered =
        TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
            .expect("recovered state");
    let recovered_values = recovered
        .collect_directed_phase_from_wire_log(
            &reopened_again,
            PartyId(2),
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::RandomBitShare,
            &label,
        )
        .expect("recover accepted values without network");
    assert_eq!(recovered_values, vec![(PartyId(1), 1)]);

    std::fs::write(&path, b"not a valid wire log\n").expect("write corrupt");
    assert_eq!(
        FilePrimeFieldMpcWireMessageLog::open(&path),
        Err(DkgError::PrimeFieldMpcWireLogCorrupt { line: 1 })
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn production_it_mpc_readiness_gate_requires_implemented_components() {
    assert_eq!(
        ensure_production_it_mpc_readiness(
            Power2RoundBackendId::NetworkedShamirSimulator,
            ProductionItMpcReadiness {
                per_party_power2round: true,
                pq_authenticated_transport: true,
                durable_round_log: true,
                blame_abort_policy: true,
                external_review: true,
            },
        ),
        Err(DkgError::InsecurePower2RoundBackend)
    );
    assert_eq!(
        ensure_production_it_mpc_readiness(
            Power2RoundBackendId::TransportBackedPerPartyDriver,
            ProductionItMpcReadiness {
                per_party_power2round: true,
                pq_authenticated_transport: true,
                durable_round_log: true,
                blame_abort_policy: true,
                external_review: true,
            },
        ),
        Err(DkgError::InsecurePower2RoundBackend)
    );
    assert_eq!(
        ensure_production_it_mpc_readiness(
            Power2RoundBackendId::ProductionItMpc,
            ProductionItMpcReadiness {
                per_party_power2round: true,
                pq_authenticated_transport: true,
                durable_round_log: true,
                blame_abort_policy: true,
                external_review: false,
            },
        ),
        Ok(())
    );
    assert_eq!(
        ensure_production_it_mpc_readiness(
            Power2RoundBackendId::ProductionItMpc,
            ProductionItMpcReadiness {
                per_party_power2round: false,
                pq_authenticated_transport: true,
                durable_round_log: true,
                blame_abort_policy: true,
                external_review: true,
            },
        ),
        Err(DkgError::BlockedPendingReview)
    );
    assert_eq!(
        ensure_production_it_mpc_readiness(
            Power2RoundBackendId::ProductionItMpc,
            ProductionItMpcReadiness {
                per_party_power2round: true,
                pq_authenticated_transport: true,
                durable_round_log: true,
                blame_abort_policy: true,
                external_review: true,
            },
        ),
        Ok(())
    );
}

#[test]
fn production_it_vss_readiness_gate_requires_implemented_components() {
    assert_eq!(
        ensure_production_it_vss_readiness(
            ItVssBackendId::InProcessHashBindingScaffold,
            ProductionItVssReadiness {
                information_checking_protocol: true,
                pq_private_channels: true,
                equivocation_resistant_broadcast: true,
                complaint_resolution_policy: true,
                external_review: true,
                ..ProductionItVssReadiness::default()
            },
        ),
        Err(DkgError::ItVssCertificateBackendMismatch)
    );
    assert_eq!(
        ensure_production_it_vss_readiness(
            ItVssBackendId::ProductionInformationChecking,
            ProductionItVssReadiness {
                information_checking_protocol: true,
                pq_private_channels: true,
                equivocation_resistant_broadcast: true,
                complaint_resolution_policy: true,
                external_review: false,
                ..ProductionItVssReadiness::default()
            },
        ),
        Ok(())
    );
    assert_eq!(
        ensure_production_it_vss_readiness(
            ItVssBackendId::ProductionInformationChecking,
            ProductionItVssReadiness {
                information_checking_protocol: false,
                pq_private_channels: true,
                equivocation_resistant_broadcast: true,
                complaint_resolution_policy: true,
                external_review: true,
                ..ProductionItVssReadiness::default()
            },
        ),
        Err(DkgError::BlockedPendingReview)
    );
    assert_eq!(
        ensure_production_it_vss_readiness(
            ItVssBackendId::ProductionInformationChecking,
            ProductionItVssReadiness {
                information_checking_protocol: true,
                pq_private_channels: true,
                equivocation_resistant_broadcast: true,
                complaint_resolution_policy: true,
                external_review: true,
                ..ProductionItVssReadiness::default()
            },
        ),
        Ok(())
    );
    assert_eq!(
        ensure_production_it_vss_readiness(
            ItVssBackendId::ProductionInformationChecking,
            ProductionItVssReadiness {
                release_policy: ItVssV1ReleasePolicy {
                    dkg_mode: ItVssProductionDkgMode::ScalarPerCoefficient,
                    ..ItVssV1ReleasePolicy::default()
                },
                information_checking_protocol: true,
                pq_private_channels: true,
                equivocation_resistant_broadcast: true,
                complaint_resolution_policy: true,
                external_review: true,
            },
        ),
        Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked)
    );
}

#[test]
fn production_native_dkg_coordinator_readiness_requires_application_transport_and_components() {
    let it_vss_ready = ProductionItVssReadiness {
        information_checking_protocol: true,
        pq_private_channels: true,
        equivocation_resistant_broadcast: true,
        complaint_resolution_policy: true,
        external_review: true,
        ..ProductionItVssReadiness::default()
    };
    let it_mpc_ready = ProductionItMpcReadiness {
        per_party_power2round: true,
        pq_authenticated_transport: true,
        durable_round_log: true,
        blame_abort_policy: true,
        external_review: true,
    };
    let ready = ProductionNativeDkgCoordinatorReadiness {
        coordinator: NativeDkgCoordinatorKind::ApplicationSuppliedTransport,
        setup_backend_id: DkgSetupBackendId::ProductionInformationTheoretic,
        it_vss_backend_id: ItVssBackendId::ProductionInformationChecking,
        power2round_backend_id: Power2RoundBackendId::ProductionItMpc,
        it_vss_readiness: it_vss_ready,
        it_mpc_readiness: it_mpc_ready,
        application_transport_contract: true,
        reliable_broadcast_conformance: true,
        ml_kem_private_channels: true,
        ml_dsa_operational_identities: true,
        durable_restart_policy: true,
        no_scaffold_backends: true,
        external_review: true,
    };

    assert_eq!(
        ensure_production_native_dkg_coordinator_readiness(
            ProductionNativeDkgCoordinatorReadiness {
                coordinator: NativeDkgCoordinatorKind::InMemoryScaffold,
                ..ready
            }
        ),
        Err(DkgError::InsecureNativeDkgCoordinator)
    );
    assert_eq!(
        ensure_production_native_dkg_coordinator_readiness(
            ProductionNativeDkgCoordinatorReadiness {
                setup_backend_id: DkgSetupBackendId::InProcessScaffold,
                ..ready
            }
        ),
        Err(DkgError::InsecureDkgSetupBackend)
    );
    assert_eq!(
        ensure_production_native_dkg_coordinator_readiness(
            ProductionNativeDkgCoordinatorReadiness {
                application_transport_contract: false,
                ..ready
            }
        ),
        Err(DkgError::BlockedPendingReview)
    );
    assert_eq!(
        ensure_production_native_dkg_coordinator_readiness(ready),
        Ok(())
    );
    assert_eq!(
        ensure_production_native_dkg_coordinator_readiness(
            ProductionNativeDkgCoordinatorReadiness {
                external_review: false,
                ..ready
            }
        ),
        Ok(())
    );
}

#[test]
fn in_memory_native_dkg_scaffold_coordinator_advertises_non_release_profile() {
    let coordinator =
        InMemoryNativeDkgScaffoldCoordinator::new(config_for::<MlDsa44>()).expect("coordinator");
    assert_eq!(
        coordinator.coordinator_kind(),
        NativeDkgCoordinatorKind::InMemoryScaffold
    );
    assert!(coordinator.coordinator_kind().is_scaffold());
    assert_eq!(
        coordinator.coordinator_kind().release_label(),
        "in-memory-scaffold"
    );
    assert!(!InMemoryNativeDkgScaffoldCoordinator::PRODUCTION_ALLOWED);

    let profile = coordinator.production_readiness_profile();
    assert_eq!(
        profile.coordinator,
        NativeDkgCoordinatorKind::InMemoryScaffold
    );
    assert_eq!(
        profile.setup_backend_id,
        DkgSetupBackendId::InProcessScaffold
    );
    assert_eq!(
        profile.it_vss_backend_id,
        ItVssBackendId::InProcessHashBindingScaffold
    );
    assert_eq!(
        profile.power2round_backend_id,
        Power2RoundBackendId::InsecureClearSimulator
    );
    assert_eq!(
        coordinator.ensure_allowed_for_production_release(),
        Err(DkgError::InsecureNativeDkgCoordinator)
    );
}

#[test]
fn scalar_it_vss_state_machine_enforces_order_and_replay_checks() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::SmallResidue,
        Some(7),
    )
    .expect("label");
    let mut machine = ScalarItVssStateMachine::new(&config, label).expect("machine");

    assert_eq!(machine.next_phase(), Some(ScalarItVssPhase::Context));
    assert_eq!(
        machine.record_message(
            ScalarItVssPhase::PrivatePayload,
            PartyId(1),
            Some(PartyId(2)),
            0
        ),
        Err(DkgError::ItVssScalarPhaseOutOfOrder)
    );

    let context_hash = machine
        .record_message(ScalarItVssPhase::Context, PartyId(1), None, 0)
        .expect("context message");
    assert_ne!(context_hash, [0u8; 32]);
    assert_eq!(
        machine.record_message(ScalarItVssPhase::Context, PartyId(1), None, 0),
        Err(DkgError::ItVssScalarReplayDetected)
    );
    machine
        .accept_phase(ScalarItVssPhase::Context)
        .expect("accept context");

    let directed_hash = machine
        .record_message(
            ScalarItVssPhase::PrivatePayload,
            PartyId(1),
            Some(PartyId(2)),
            0,
        )
        .expect("private payload");
    assert_ne!(directed_hash, context_hash);
    assert_eq!(
        machine.record_message(
            ScalarItVssPhase::PrivatePayload,
            PartyId(1),
            Some(PartyId(2)),
            0,
        ),
        Err(DkgError::ItVssScalarReplayDetected)
    );
    assert_eq!(
        machine.record_message(
            ScalarItVssPhase::PrivatePayload,
            PartyId(9),
            Some(PartyId(2)),
            1,
        ),
        Err(DkgError::UnknownParty(PartyId(9)))
    );
    assert_eq!(
        machine.record_message(
            ScalarItVssPhase::PrivatePayload,
            PartyId(1),
            Some(PartyId(9)),
            1,
        ),
        Err(DkgError::UnknownParty(PartyId(9)))
    );
}

#[test]
fn scalar_it_vss_state_machine_completes_ordered_phases() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::SmallResidue,
        Some(8),
    )
    .expect("label");
    let mut machine = ScalarItVssStateMachine::new(&config, label).expect("machine");
    assert_eq!(machine.context().dealer, PartyId(1));
    assert_eq!(machine.context().threshold_f, config.threshold - 1);
    assert_ne!(machine.context().transcript_hash(), [0u8; 32]);

    assert_eq!(
        machine.accept_phase(ScalarItVssPhase::IcAudit),
        Err(DkgError::ItVssScalarPhaseOutOfOrder)
    );
    for phase in SCALAR_IT_VSS_PHASES {
        machine.accept_phase(*phase).expect("accept phase");
    }
    assert!(machine.is_complete());
    assert_eq!(machine.next_phase(), None);
    assert_eq!(
        machine.accept_phase(ScalarItVssPhase::Accepted),
        Err(DkgError::ItVssScalarPhaseOutOfOrder)
    );
}

#[test]
fn scalar_it_vss_state_machine_context_is_label_bound() {
    let config = config();
    let other_config =
        DkgConfig::new_for_suite(DkgSuite::MlDsa65, 2, parties(&[1, 2, 4]), KeygenEpoch(7))
            .expect("other config");
    let label = ItVssSharingLabel::new(
        &other_config,
        PartyId(1),
        ItVssSharingDomain::SmallResidue,
        Some(9),
    )
    .expect("label");
    assert_eq!(
        ScalarItVssStateMachine::new(&config, label),
        Err(DkgError::ItVssCertificateLabelMismatch)
    );
}

#[test]
fn scalar_it_vss_state_machine_terminal_abort_and_blame_policy() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(2),
        ItVssSharingDomain::SmallResidue,
        Some(10),
    )
    .expect("label");
    let mut machine = ScalarItVssStateMachine::new(&config, label).expect("machine");
    let failure = machine
        .abort_no_blame(ScalarItVssAbortReason::IcAuditDispute)
        .expect("abort");
    match failure {
        ScalarItVssFailure::AbortNoBlame {
            reason,
            transcript_hash,
        } => {
            assert_eq!(reason, ScalarItVssAbortReason::IcAuditDispute);
            assert_ne!(transcript_hash, [0u8; 32]);
        }
        _ => panic!("expected abort without blame"),
    }
    assert_eq!(machine.terminal_failure(), Some(&failure));
    assert_eq!(machine.next_phase(), None);
    assert_eq!(
        machine.accept_phase(ScalarItVssPhase::Context),
        Err(DkgError::ItVssScalarSessionTerminal)
    );
    assert_eq!(
        machine.record_message(ScalarItVssPhase::Context, PartyId(1), None, 0),
        Err(DkgError::ItVssScalarSessionTerminal)
    );

    let label = ItVssSharingLabel::new(
        &config,
        PartyId(2),
        ItVssSharingDomain::SmallResidue,
        Some(11),
    )
    .expect("label");
    let mut machine = ScalarItVssStateMachine::new(&config, label).expect("machine");
    assert_eq!(
        machine.blame_party(PartyId(1), [0u8; 32]),
        Err(DkgError::ComplaintEvidenceMismatch)
    );
    assert_eq!(
        machine.blame_party(PartyId(9), [0x44; 32]),
        Err(DkgError::UnknownParty(PartyId(9)))
    );
    assert_eq!(
        machine.blame_dealer([0x55; 32]),
        Ok(ScalarItVssFailure::BlameDealer {
            dealer: PartyId(2),
            evidence_hash: [0x55; 32],
        })
    );
    assert_eq!(
        machine.blame_party(PartyId(1), [0x66; 32]),
        Err(DkgError::ItVssScalarSessionTerminal)
    );
}

#[test]
fn scalar_it_vss_honest_path_accepts_and_binds_commitments() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::SmallResidue,
        Some(12),
    )
    .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 2,
        ic_audit_tags: 2,
        poly_consistency_rounds: 3,
    };
    let deal = scalar_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[123, 7],
        &[vec![9, 1], vec![10, 2], vec![11, 3]],
        params,
        [0x12; 32],
    )
    .expect("honest deal");

    assert_eq!(deal.private_payloads.len(), config.parties.len());
    assert_eq!(deal.payload_commitments.len(), config.parties.len());
    assert_eq!(deal.consistency_rounds.len(), 3);
    assert_ne!(deal.transcript_hash, [0u8; 32]);
    for payload in &deal.private_payloads {
        assert_eq!(payload.holder_audit_tags.len(), 6);
        assert_eq!(payload.holder_retained_tags.len(), 6);
        assert_eq!(payload.audited_receiver_tags.len(), 6);
        assert_eq!(payload.retained_receiver_tags.len(), 6);
        assert_eq!(payload.gamma_shares.len(), 3);
    }

    let accepted = accept_scalar_it_vss_honest_deal::<MlDsa65>(&config, &deal).expect("accepted");
    assert_eq!(accepted.context, deal.context);
    assert_eq!(accepted.accepted_receivers, config.parties);
    assert_eq!(accepted.transcript_hash, deal.transcript_hash);
    assert_eq!(accepted.payload_commitments, deal.payload_commitments);
}

#[test]
fn scalar_it_vss_honest_path_rejects_tampered_audit_tag() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::SmallResidue,
        Some(13),
    )
    .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 1,
        ic_audit_tags: 1,
        poly_consistency_rounds: 2,
    };
    let mut deal = scalar_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[50, 4],
        &[vec![2, 1], vec![3, 1]],
        params,
        [0x13; 32],
    )
    .expect("honest deal");
    deal.private_payloads[0].holder_audit_tags[0].y =
        ItVssFq::new(deal.private_payloads[0].holder_audit_tags[0].y.value() + 1)
            .expect("tampered y");

    assert_eq!(
        accept_scalar_it_vss_honest_deal::<MlDsa65>(&config, &deal),
        Err(DkgError::ComplaintEvidenceMismatch)
    );
}

#[test]
fn scalar_it_vss_honest_path_rejects_tampered_commitment_and_consistency() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(2),
        ItVssSharingDomain::SmallResidue,
        Some(14),
    )
    .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 1,
        ic_audit_tags: 1,
        poly_consistency_rounds: 2,
    };
    let deal = scalar_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[70, -3],
        &[vec![5, 1], vec![6, 1]],
        params,
        [0x14; 32],
    )
    .expect("honest deal");

    let mut bad_commitment = deal.clone();
    bad_commitment.payload_commitments[1].commitment_hash[0] ^= 1;
    assert_eq!(
        accept_scalar_it_vss_honest_deal::<MlDsa65>(&config, &bad_commitment),
        Err(DkgError::ComplaintEvidenceMismatch)
    );

    let mut bad_consistency = deal;
    bad_consistency.consistency_rounds[0].h_coefficients[0] =
        bad_consistency.consistency_rounds[0].h_coefficients[0].add_mod(ItVssFq::one());
    bad_consistency.transcript_hash = hash_scalar_it_vss_honest_deal(
        &bad_consistency.context,
        &bad_consistency.payload_commitments,
        &bad_consistency.consistency_rounds,
    );
    assert_eq!(
        accept_scalar_it_vss_honest_deal::<MlDsa65>(&config, &bad_consistency),
        Err(DkgError::ComplaintEvidenceMismatch)
    );
}

#[test]
fn scalar_it_vss_honest_path_rejects_bad_shapes_and_config() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::SmallResidue,
        Some(15),
    )
    .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 1,
        ic_audit_tags: 1,
        poly_consistency_rounds: 1,
    };
    assert_eq!(
        scalar_it_vss_deal_honest_path::<MlDsa65>(
            &config,
            label,
            &[1, 2, 3],
            &[vec![1, 2]],
            params,
            [0x15; 32],
        ),
        Err(DkgError::Backend("bad scalar IT-VSS polynomial degree"))
    );
    assert_eq!(
        scalar_it_vss_deal_honest_path::<MlDsa65>(
            &config,
            label,
            &[1, 2],
            &[vec![1, 2, 3]],
            params,
            [0x15; 32],
        ),
        Err(DkgError::Backend("bad scalar IT-VSS mask polynomial shape"))
    );
}

#[test]
fn vector_it_vss_honest_path_accepts_and_binds_commitments() {
    let config = config();
    let label = ItVssSharingLabel::new(&config, PartyId(1), ItVssSharingDomain::MldsaS1, None)
        .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 2,
        ic_audit_tags: 2,
        poly_consistency_rounds: 2,
    };
    let deal = vector_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[vec![1, 2, 3], vec![10, 20, 30]],
        &[
            vec![vec![5, 6, 7], vec![1, 1, 1]],
            vec![vec![8, 9, 10], vec![2, 2, 2]],
        ],
        params,
        [0x31; 32],
    )
    .expect("vector deal");

    assert_eq!(deal.vector_len, 3);
    assert_eq!(deal.private_payloads.len(), config.parties.len());
    assert_eq!(deal.payload_commitments.len(), config.parties.len());
    assert_eq!(deal.consistency_rounds.len(), 2);
    assert_ne!(deal.transcript_hash, [0u8; 32]);
    for payload in &deal.private_payloads {
        assert_eq!(payload.beta.len(), 3);
        assert_eq!(payload.gamma_shares.len(), 2);
        assert!(payload.gamma_shares.iter().all(|gamma| gamma.len() == 3));
        assert_eq!(payload.holder_audit_tags.len(), 6);
        assert_eq!(payload.holder_retained_tags.len(), 6);
        assert_eq!(payload.audited_receiver_tags.len(), 6);
        assert_eq!(payload.retained_receiver_tags.len(), 6);
    }

    let accepted = accept_vector_it_vss_honest_deal::<MlDsa65>(&config, &deal).expect("accepted");
    assert_eq!(accepted.context, deal.context);
    assert_eq!(accepted.vector_len, 3);
    assert_eq!(accepted.accepted_receivers, config.parties);
    assert_eq!(accepted.transcript_hash, deal.transcript_hash);
    assert_eq!(accepted.payload_commitments, deal.payload_commitments);
}

#[test]
fn vector_it_vss_honest_path_rejects_tampering_and_bad_shapes() {
    let config = config();
    let label = ItVssSharingLabel::new(&config, PartyId(2), ItVssSharingDomain::MldsaS2, None)
        .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 1,
        ic_audit_tags: 1,
        poly_consistency_rounds: 2,
    };
    let deal = vector_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[vec![70, 71], vec![-3, 4]],
        &[vec![vec![5, 6], vec![1, 2]], vec![vec![8, 9], vec![3, 4]]],
        params,
        [0x32; 32],
    )
    .expect("vector deal");

    let mut bad_audit = deal.clone();
    bad_audit.private_payloads[0].holder_audit_tags[0].y[0] =
        bad_audit.private_payloads[0].holder_audit_tags[0].y[0].add_mod(ItVssFq::one());
    assert_eq!(
        accept_vector_it_vss_honest_deal::<MlDsa65>(&config, &bad_audit),
        Err(DkgError::ComplaintEvidenceMismatch)
    );

    let mut bad_commitment = deal.clone();
    bad_commitment.payload_commitments[1].commitment_hash[0] ^= 1;
    assert_eq!(
        accept_vector_it_vss_honest_deal::<MlDsa65>(&config, &bad_commitment),
        Err(DkgError::ComplaintEvidenceMismatch)
    );

    let mut bad_consistency = deal;
    bad_consistency.consistency_rounds[0].h_coefficients[0][0] =
        bad_consistency.consistency_rounds[0].h_coefficients[0][0].add_mod(ItVssFq::one());
    bad_consistency.transcript_hash = hash_vector_it_vss_honest_deal(
        &bad_consistency.context,
        &bad_consistency.payload_commitments,
        &bad_consistency.consistency_rounds,
    );
    assert_eq!(
        accept_vector_it_vss_honest_deal::<MlDsa65>(&config, &bad_consistency),
        Err(DkgError::ComplaintEvidenceMismatch)
    );

    assert_eq!(
        vector_it_vss_deal_honest_path::<MlDsa65>(
            &config,
            label,
            &[vec![1, 2], vec![3]],
            &[vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8],]],
            params,
            [0x33; 32],
        ),
        Err(DkgError::ItVssVectorLengthMismatch {
            expected: 2,
            got: 1,
        })
    );
}

#[test]
fn vector_it_vss_reconstruction_opens_honest_vector() {
    let config = config();
    let label = ItVssSharingLabel::new(&config, PartyId(1), ItVssSharingDomain::MldsaS1, Some(34))
        .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 2,
        ic_audit_tags: 1,
        poly_consistency_rounds: 2,
    };
    let deal = vector_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[vec![101, 202, 303], vec![7, 8, 9]],
        &[
            vec![vec![5, 6, 7], vec![1, 1, 1]],
            vec![vec![8, 9, 10], vec![2, 2, 2]],
        ],
        params,
        [0x34; 32],
    )
    .expect("vector deal");
    let accepted = accept_vector_it_vss_honest_deal::<MlDsa65>(&config, &deal).expect("accepted");
    let shares = vector_it_vss_reconstruction_shares(&deal);
    let opened = reconstruct_vector_it_vss_opening::<MlDsa65>(
        &config,
        &accepted,
        &deal.private_payloads,
        &shares,
    )
    .expect("open vector");

    assert_eq!(
        opened.secret,
        vec![
            ItVssFq::new(101).expect("secret"),
            ItVssFq::new(202).expect("secret"),
            ItVssFq::new(303).expect("secret"),
        ]
    );
    assert_eq!(opened.accepted_points_by_coordinate.len(), 3);
    assert!(opened
        .accepted_points_by_coordinate
        .iter()
        .all(|points| points.len() == config.parties.len()));
    assert_eq!(
        opened.votes.len(),
        config.parties.len() * config.parties.len()
    );
    assert!(opened.votes.iter().all(|vote| vote.accepted));
    assert_ne!(opened.transcript_hash, [0u8; 32]);
}

#[test]
fn vector_it_vss_reconstruction_rejects_forged_beta_or_y() {
    let config = config();
    let label = ItVssSharingLabel::new(&config, PartyId(2), ItVssSharingDomain::MldsaS2, Some(35))
        .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 1,
        ic_audit_tags: 1,
        poly_consistency_rounds: 2,
    };
    let deal = vector_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[vec![11, 22], vec![3, 4]],
        &[vec![vec![1, 2], vec![5, 6]], vec![vec![7, 8], vec![9, 10]]],
        params,
        [0x35; 32],
    )
    .expect("vector deal");
    let accepted = accept_vector_it_vss_honest_deal::<MlDsa65>(&config, &deal).expect("accepted");
    let shares = vector_it_vss_reconstruction_shares(&deal);

    let mut one_bad = shares.clone();
    one_bad[0].beta[0] = one_bad[0].beta[0].add_mod(ItVssFq::one());
    let opened = reconstruct_vector_it_vss_opening::<MlDsa65>(
        &config,
        &accepted,
        &deal.private_payloads,
        &one_bad,
    )
    .expect("one bad holder is excluded");
    assert_eq!(
        opened.secret,
        vec![
            ItVssFq::new(11).expect("secret"),
            ItVssFq::new(22).expect("secret"),
        ]
    );
    assert!(opened.votes.iter().any(|vote| !vote.accepted));

    let mut too_many_bad = shares.clone();
    too_many_bad[0].beta[0] = too_many_bad[0].beta[0].add_mod(ItVssFq::one());
    too_many_bad[1].beta[1] = too_many_bad[1].beta[1].add_mod(ItVssFq::one());
    assert_eq!(
        reconstruct_vector_it_vss_opening::<MlDsa65>(
            &config,
            &accepted,
            &deal.private_payloads,
            &too_many_bad,
        ),
        Err(DkgError::InsufficientAcceptedReconstructionPoints {
            threshold: config.threshold,
            accepted: 1,
        })
    );

    let mut bad_shape = shares;
    bad_shape[0].beta.pop();
    assert_eq!(
        reconstruct_vector_it_vss_opening::<MlDsa65>(
            &config,
            &accepted,
            &deal.private_payloads,
            &bad_shape,
        ),
        Err(DkgError::ItVssVectorLengthMismatch {
            expected: 2,
            got: 1,
        })
    );
}

#[test]
fn vector_it_vss_hardening_rejects_label_retained_tag_and_shape_faults() {
    let config = config();
    let label = ItVssSharingLabel::new(&config, PartyId(1), ItVssSharingDomain::MldsaS1, Some(36))
        .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 1,
        ic_audit_tags: 1,
        poly_consistency_rounds: 2,
    };
    let deal = vector_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[vec![31, 32, 33], vec![4, 5, 6]],
        &[
            vec![vec![1, 2, 3], vec![7, 8, 9]],
            vec![vec![4, 5, 6], vec![10, 11, 12]],
        ],
        params,
        [0x36; 32],
    )
    .expect("vector deal");
    let accepted = accept_vector_it_vss_honest_deal::<MlDsa65>(&config, &deal).expect("accepted");
    let shares = vector_it_vss_reconstruction_shares(&deal);

    let mut leaked_public_payload = Vec::from(b"public-prefix".as_slice());
    leaked_public_payload.extend_from_slice(RETAINED_RECEIVER_TAG_PUBLIC_ARTIFACT_MAGIC);
    leaked_public_payload.extend_from_slice(b"public-suffix");
    assert_eq!(
        ensure_public_payload_excludes_retained_receiver_tags(&leaked_public_payload),
        Err(DkgError::DkgReleaseArtifactContainsPrivateSetupPayload)
    );

    let mut wrong_label = accepted.clone();
    wrong_label.context.label_hash = [0x77; 32];
    assert_eq!(
        reconstruct_vector_it_vss_opening::<MlDsa65>(
            &config,
            &wrong_label,
            &deal.private_payloads,
            &shares,
        ),
        Err(DkgError::ComplaintEvidenceMismatch)
    );

    let mut wrong_domain = accepted.clone();
    wrong_domain.context.label_hash =
        ItVssSharingLabel::new(&config, PartyId(1), ItVssSharingDomain::MldsaS2, Some(36))
            .expect("wrong domain label")
            .label_hash;
    assert_eq!(
        reconstruct_vector_it_vss_opening::<MlDsa65>(
            &config,
            &wrong_domain,
            &deal.private_payloads,
            &shares,
        ),
        Err(DkgError::ComplaintEvidenceMismatch)
    );

    let mut malformed_y = shares.clone();
    malformed_y[0].retained_y_tags[0]
        .y
        .push(ItVssFq::new(99).expect("fq"));
    assert_eq!(
        reconstruct_vector_it_vss_opening::<MlDsa65>(
            &config,
            &accepted,
            &deal.private_payloads,
            &malformed_y,
        ),
        Err(DkgError::ItVssVectorLengthMismatch {
            expected: 3,
            got: 4,
        })
    );

    let mut missing_tags = shares;
    missing_tags[0].retained_y_tags.clear();
    assert_eq!(
        reconstruct_vector_it_vss_opening::<MlDsa65>(
            &config,
            &accepted,
            &deal.private_payloads,
            &missing_tags,
        ),
        Err(DkgError::MissingScalarItVssRetainedTag {
            holder: PartyId(1),
            receiver: PartyId(1),
        })
    );
}

#[test]
fn vector_it_vss_openings_feed_verified_small_sampler_inputs() {
    let config = config_for::<MlDsa44>();
    let vector = SecretVectorKind::S1;
    let count = vector.coefficient_count::<MlDsa44>();
    let eta = SmallSecretEta::for_params::<MlDsa44>().expect("eta");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 1,
        ic_audit_tags: 1,
        poly_consistency_rounds: 1,
    };
    let mut by_coefficient = vec![Vec::<VerifiedSmallResidueInput>::new(); count];
    let mut expected_residues = vec![0u16; count];

    for (dealer_index, &dealer) in config.parties.iter().enumerate() {
        let residues = (0..count)
            .map(|index| ((index + dealer_index) % usize::from(eta.modulus())) as Coeff)
            .collect::<Vec<_>>();
        let slope = vec![dealer_index as Coeff + 1; count];
        let mask_const = vec![2 + dealer_index as Coeff; count];
        let mask_slope = vec![1; count];
        let label = ItVssSharingLabel::new(
            &config,
            dealer,
            ItVssSharingDomain::for_secret_vector(vector),
            None,
        )
        .expect("vector label");
        let deal = vector_it_vss_deal_honest_path::<MlDsa44>(
            &config,
            label,
            &[residues.clone(), slope],
            &[vec![mask_const, mask_slope]],
            params,
            [dealer.0 as u8; 32],
        )
        .expect("vector deal");
        let accepted =
            accept_vector_it_vss_honest_deal::<MlDsa44>(&config, &deal).expect("accepted");
        let shares = vector_it_vss_reconstruction_shares(&deal);
        let opening = reconstruct_vector_it_vss_opening::<MlDsa44>(
            &config,
            &accepted,
            &deal.private_payloads,
            &shares,
        )
        .expect("opening");
        let inputs = VerifiedSmallResidueInput::from_vector_it_vss_opening::<MlDsa44>(
            &config, vector, &accepted, &opening,
        )
        .expect("verified inputs");
        assert_eq!(inputs.len(), count);
        for (index, input) in inputs.into_iter().enumerate() {
            expected_residues[index] += residues[index] as u16;
            assert_eq!(input.dealer, dealer);
            assert!(matches!(
                input.verification,
                SmallResidueInputVerification::ItVssCertificate { .. }
            ));
            by_coefficient[index].push(input);
        }
    }

    let mut sampler = InProcessDistributedSmallSampler::new([0xd1; 32]);
    let sampled = sampler
        .sample_verified_small_polyvec::<MlDsa44>(&config, vector, &by_coefficient)
        .expect("sample vector from vector IT-VSS inputs");
    assert_eq!(sampled.coefficients.len(), count);
    for (index, coefficient) in sampled.coefficients.iter().enumerate() {
        let expected_residue = (expected_residues[index] % u16::from(eta.modulus())) as i32;
        let expected_coeff = expected_residue - i32::from(eta.bound());
        let expected_encoded = expected_coeff.rem_euclid(MlDsa44::Q) as Coeff;
        let points = coefficient
            .shares
            .iter()
            .take(usize::from(config.threshold))
            .map(|share| ShamirScalarShare {
                point: share.point,
                value: share.value,
            })
            .collect::<Vec<_>>();
        let opened = reconstruct_scalar_at_zero::<MlDsa44>(&points)
            .expect("reconstruct sampled coefficient");
        assert_eq!(opened, expected_encoded, "coefficient {index}");
    }
}

#[test]
fn vector_it_vss_opening_adapter_rejects_wrong_domain_and_residue_range() {
    let config = config_for::<MlDsa44>();
    let vector = SecretVectorKind::S1;
    let count = vector.coefficient_count::<MlDsa44>();
    let eta = SmallSecretEta::for_params::<MlDsa44>().expect("eta");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 1,
        ic_audit_tags: 1,
        poly_consistency_rounds: 1,
    };
    let bad_residues = vec![Coeff::from(eta.modulus()); count];
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::for_secret_vector(vector),
        None,
    )
    .expect("vector label");
    let deal = vector_it_vss_deal_honest_path::<MlDsa44>(
        &config,
        label,
        &[bad_residues, vec![1; count]],
        &[vec![vec![2; count], vec![1; count]]],
        params,
        [0xd2; 32],
    )
    .expect("vector deal");
    let accepted = accept_vector_it_vss_honest_deal::<MlDsa44>(&config, &deal).expect("accepted");
    let shares = vector_it_vss_reconstruction_shares(&deal);
    let opening = reconstruct_vector_it_vss_opening::<MlDsa44>(
        &config,
        &accepted,
        &deal.private_payloads,
        &shares,
    )
    .expect("opening");
    assert_eq!(
        VerifiedSmallResidueInput::from_vector_it_vss_opening::<MlDsa44>(
            &config, vector, &accepted, &opening,
        ),
        Err(DkgError::InvalidSmallResidue {
            dealer: PartyId(1),
            modulus: eta.modulus(),
            got: eta.modulus(),
        })
    );

    let wrong_label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S2),
        None,
    )
    .expect("wrong label");
    let mut wrong_context = accepted.clone();
    wrong_context.context.label_hash = wrong_label.label_hash;
    assert_eq!(
        VerifiedSmallResidueInput::from_vector_it_vss_opening::<MlDsa44>(
            &config,
            vector,
            &wrong_context,
            &opening,
        ),
        Err(DkgError::ItVssCertificateLabelMismatch)
    );
}

#[test]
fn scalar_it_vss_reconstruction_opens_honest_secret() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::SmallResidue,
        Some(16),
    )
    .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 2,
        ic_audit_tags: 1,
        poly_consistency_rounds: 2,
    };
    let deal = scalar_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[123, 7],
        &[vec![9, 1], vec![10, 2]],
        params,
        [0x16; 32],
    )
    .expect("honest deal");
    let accepted = accept_scalar_it_vss_honest_deal::<MlDsa65>(&config, &deal).expect("accepted");
    let shares = scalar_it_vss_reconstruction_shares(&deal);
    let opened = reconstruct_scalar_it_vss_opening::<MlDsa65>(
        &config,
        &accepted,
        &deal.private_payloads,
        &shares,
    )
    .expect("open");

    assert_eq!(opened.secret, ItVssFq::new(123).expect("secret"));
    assert_eq!(opened.accepted_points.len(), config.parties.len());
    assert_eq!(
        opened.votes.len(),
        config.parties.len() * config.parties.len()
    );
    assert!(opened.votes.iter().all(|vote| vote.accepted));
    assert_ne!(opened.transcript_hash, [0u8; 32]);
}

#[test]
fn scalar_it_vss_reconstruction_rejects_forged_beta_or_y() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::SmallResidue,
        Some(17),
    )
    .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 2,
        ic_audit_tags: 1,
        poly_consistency_rounds: 2,
    };
    let deal = scalar_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[80, 3],
        &[vec![1, 1], vec![2, 1]],
        params,
        [0x17; 32],
    )
    .expect("honest deal");
    let accepted = accept_scalar_it_vss_honest_deal::<MlDsa65>(&config, &deal).expect("accepted");

    let mut bad_beta = scalar_it_vss_reconstruction_shares(&deal);
    bad_beta[0].beta = bad_beta[0].beta.add_mod(ItVssFq::one());
    let opened = reconstruct_scalar_it_vss_opening::<MlDsa65>(
        &config,
        &accepted,
        &deal.private_payloads,
        &bad_beta,
    )
    .expect("one forged point is excluded");
    assert_eq!(opened.secret, ItVssFq::new(80).expect("secret"));
    assert_eq!(opened.accepted_points.len(), 2);

    bad_beta[1].beta = bad_beta[1].beta.add_mod(ItVssFq::one());
    assert_eq!(
        reconstruct_scalar_it_vss_opening::<MlDsa65>(
            &config,
            &accepted,
            &deal.private_payloads,
            &bad_beta,
        ),
        Err(DkgError::InsufficientAcceptedReconstructionPoints {
            threshold: 2,
            accepted: 1,
        })
    );

    let mut bad_y = scalar_it_vss_reconstruction_shares(&deal);
    for share in bad_y.iter_mut().take(2) {
        for tag in &mut share.retained_y_tags {
            tag.y = tag.y.add_mod(ItVssFq::one());
        }
    }
    assert_eq!(
        reconstruct_scalar_it_vss_opening::<MlDsa65>(
            &config,
            &accepted,
            &deal.private_payloads,
            &bad_y,
        ),
        Err(DkgError::InsufficientAcceptedReconstructionPoints {
            threshold: 2,
            accepted: 1,
        })
    );
}

#[test]
fn scalar_it_vss_reconstruction_rejects_missing_or_tampered_private_payload() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(2),
        ItVssSharingDomain::SmallResidue,
        Some(18),
    )
    .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 1,
        ic_audit_tags: 1,
        poly_consistency_rounds: 2,
    };
    let deal = scalar_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[44, 5],
        &[vec![3, 1], vec![4, 1]],
        params,
        [0x18; 32],
    )
    .expect("honest deal");
    let accepted = accept_scalar_it_vss_honest_deal::<MlDsa65>(&config, &deal).expect("accepted");
    let shares = scalar_it_vss_reconstruction_shares(&deal);

    assert_eq!(
        reconstruct_scalar_it_vss_opening::<MlDsa65>(
            &config,
            &accepted,
            &deal.private_payloads[..2],
            &shares,
        ),
        Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: 3,
            got: 2,
        })
    );

    let mut tampered_payloads = deal.private_payloads.clone();
    tampered_payloads[0].payload_salt[0] ^= 1;
    assert_eq!(
        reconstruct_scalar_it_vss_opening::<MlDsa65>(
            &config,
            &accepted,
            &tampered_payloads,
            &shares,
        ),
        Err(DkgError::ComplaintEvidenceMismatch)
    );
}

#[test]
fn scalar_it_vss_reconstruction_rejects_duplicate_holder_broadcast() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::SmallResidue,
        Some(19),
    )
    .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 1,
        ic_audit_tags: 1,
        poly_consistency_rounds: 2,
    };
    let deal = scalar_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[91, 6],
        &[vec![7, 1], vec![8, 1]],
        params,
        [0x19; 32],
    )
    .expect("honest deal");
    let accepted = accept_scalar_it_vss_honest_deal::<MlDsa65>(&config, &deal).expect("accepted");
    let mut shares = scalar_it_vss_reconstruction_shares(&deal);
    shares[1] = shares[0].clone();

    assert_eq!(
        reconstruct_scalar_it_vss_opening::<MlDsa65>(
            &config,
            &accepted,
            &deal.private_payloads,
            &shares,
        ),
        Err(DkgError::DuplicateRoundSender {
            round: DkgRound::Finalize,
            sender: PartyId(1),
        })
    );
}

#[test]
fn scalar_it_vss_reconstruction_rejects_malformed_retained_tag_sets() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::SmallResidue,
        Some(20),
    )
    .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 1,
        ic_audit_tags: 1,
        poly_consistency_rounds: 2,
    };
    let deal = scalar_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[92, 6],
        &[vec![7, 1], vec![8, 1]],
        params,
        [0x20; 32],
    )
    .expect("honest deal");
    let accepted = accept_scalar_it_vss_honest_deal::<MlDsa65>(&config, &deal).expect("accepted");

    let mut missing = scalar_it_vss_reconstruction_shares(&deal);
    missing[0]
        .retained_y_tags
        .retain(|tag| tag.receiver != PartyId(2));
    assert_eq!(
        reconstruct_scalar_it_vss_opening::<MlDsa65>(
            &config,
            &accepted,
            &deal.private_payloads,
            &missing,
        ),
        Err(DkgError::MissingScalarItVssRetainedTag {
            holder: PartyId(1),
            receiver: PartyId(2),
        })
    );

    let mut duplicated = scalar_it_vss_reconstruction_shares(&deal);
    let duplicate = duplicated[0].retained_y_tags[0];
    duplicated[0].retained_y_tags.push(duplicate);
    assert_eq!(
        reconstruct_scalar_it_vss_opening::<MlDsa65>(
            &config,
            &accepted,
            &deal.private_payloads,
            &duplicated,
        ),
        Err(DkgError::DuplicateScalarItVssRetainedTag {
            holder: PartyId(1),
            receiver: duplicate.receiver,
            tag_index: duplicate.tag_index,
        })
    );

    let mut wrong_holder = scalar_it_vss_reconstruction_shares(&deal);
    wrong_holder[0].retained_y_tags[0].holder = PartyId(3);
    assert_eq!(
        reconstruct_scalar_it_vss_opening::<MlDsa65>(
            &config,
            &accepted,
            &deal.private_payloads,
            &wrong_holder,
        ),
        Err(DkgError::ComplaintEvidenceMismatch)
    );
}

#[test]
fn scalar_it_vss_false_dispute_aborts_without_false_dealer_blame() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(2),
        ItVssSharingDomain::SmallResidue,
        Some(21),
    )
    .expect("label");
    let mut machine = ScalarItVssStateMachine::new(&config, label).expect("machine");
    machine
        .accept_phase(ScalarItVssPhase::Context)
        .expect("context");
    machine
        .accept_phase(ScalarItVssPhase::PrivatePayload)
        .expect("payload");
    let failure = machine
        .abort_no_blame(ScalarItVssAbortReason::IcAuditDispute)
        .expect("abort no blame");
    assert!(matches!(
        failure,
        ScalarItVssFailure::AbortNoBlame {
            reason: ScalarItVssAbortReason::IcAuditDispute,
            ..
        }
    ));
    assert!(!matches!(
        machine.terminal_failure(),
        Some(ScalarItVssFailure::BlameDealer { .. })
    ));
}

#[test]
fn release_scan_rejects_public_retained_receiver_tag_artifact() {
    assert_eq!(
        ensure_public_payload_excludes_retained_receiver_tags(
            RETAINED_RECEIVER_TAG_PUBLIC_ARTIFACT_MAGIC
        ),
        Err(DkgError::DkgReleaseArtifactContainsPrivateSetupPayload)
    );
    let mut embedded = b"public-prefix".to_vec();
    embedded.extend_from_slice(RETAINED_RECEIVER_TAG_PUBLIC_ARTIFACT_MAGIC);
    embedded.extend_from_slice(b"public-suffix");
    assert_eq!(
        ensure_public_payload_excludes_retained_receiver_tags(&embedded),
        Err(DkgError::DkgReleaseArtifactContainsPrivateSetupPayload)
    );
    assert_eq!(
        ensure_public_payload_excludes_retained_receiver_tags(b"ordinary public artifact"),
        Ok(())
    );
}

#[test]
fn it_vss_v1_release_policy_rejects_forbidden_modes() {
    assert_eq!(
        ensure_it_vss_v1_release_policy_allowed(ItVssV1ReleasePolicy::default()),
        Ok(())
    );

    assert_eq!(
        ensure_it_vss_v1_release_policy_allowed(ItVssV1ReleasePolicy {
            dkg_mode: ItVssProductionDkgMode::ScalarPerCoefficient,
            ..ItVssV1ReleasePolicy::default()
        }),
        Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked)
    );

    assert_eq!(
        ensure_it_vss_v1_release_policy_allowed(ItVssV1ReleasePolicy {
            public_beta_reveal: true,
            ..ItVssV1ReleasePolicy::default()
        }),
        Err(DkgError::ItVssPublicBetaRevealReleaseBlocked)
    );

    assert_eq!(
        ensure_it_vss_v1_release_policy_allowed(ItVssV1ReleasePolicy {
            retained_receiver_tags_public: true,
            ..ItVssV1ReleasePolicy::default()
        }),
        Err(DkgError::ItVssRetainedTagPublicArtifactReleaseBlocked)
    );
}

#[test]
fn scalar_it_vss_persistence_allows_only_complete_accepted_restart() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::SmallResidue,
        Some(22),
    )
    .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 1,
        ic_audit_tags: 1,
        poly_consistency_rounds: 1,
    };
    let deal = scalar_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[77, 2],
        &[vec![4, 1]],
        params,
        [0x22; 32],
    )
    .expect("deal");
    let context = deal.context;

    let mut incomplete = InMemoryScalarItVssPersistenceLog::default();
    let machine = ScalarItVssStateMachine::new(&config, label).expect("machine");
    machine
        .persist_cursor(&mut incomplete)
        .expect("persist incomplete");
    assert_eq!(
        ensure_scalar_it_vss_restart_allows_accepted(&context, &incomplete),
        Err(DkgError::ScalarItVssIncompleteAfterRestart)
    );
    assert_eq!(
        ensure_scalar_it_vss_release_state_allows_accepted(&context, &incomplete),
        Err(DkgError::ScalarItVssIncompleteAfterRestart)
    );

    let mut accepted_log = InMemoryScalarItVssPersistenceLog::default();
    let mut complete_machine = ScalarItVssStateMachine::new(&config, label).expect("machine");
    for phase in SCALAR_IT_VSS_PHASES {
        complete_machine.accept_phase(*phase).expect("phase");
    }
    complete_machine
        .persist_cursor(&mut accepted_log)
        .expect("persist accepted");
    persist_scalar_it_vss_private_state(&mut accepted_log, &context, &deal.private_payloads[0])
        .expect("persist private state");
    assert_eq!(
        ensure_scalar_it_vss_restart_allows_accepted(&context, &accepted_log),
        Ok(())
    );
    assert_eq!(
        ensure_scalar_it_vss_release_state_allows_accepted(&context, &accepted_log),
        Ok(())
    );
    assert_eq!(accepted_log.cursors().len(), 1);
    assert_eq!(accepted_log.private_state().len(), 1);
}

#[test]
fn scalar_it_vss_persistence_aborted_restart_cannot_accept() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(2),
        ItVssSharingDomain::SmallResidue,
        Some(23),
    )
    .expect("label");
    let mut machine = ScalarItVssStateMachine::new(&config, label).expect("machine");
    let context = machine.context();
    machine
        .abort_no_blame(ScalarItVssAbortReason::PolynomialConsistencyDispute)
        .expect("abort");
    let mut log = InMemoryScalarItVssPersistenceLog::default();
    machine.persist_cursor(&mut log).expect("persist abort");
    assert_eq!(
        ensure_scalar_it_vss_restart_allows_accepted(&context, &log),
        Err(DkgError::ScalarItVssAbortedAfterRestart)
    );
    assert_eq!(
        ensure_scalar_it_vss_release_state_allows_accepted(&context, &log),
        Err(DkgError::ScalarItVssAbortedAfterRestart)
    );
    assert!(matches!(
        log.latest_scalar_it_vss_cursor()
            .expect("cursor")
            .terminal_failure,
        Some(ScalarItVssFailure::AbortNoBlame {
            reason: ScalarItVssAbortReason::PolynomialConsistencyDispute,
            ..
        })
    ));
}

#[test]
fn scalar_it_vss_persistence_rejects_wrong_context_or_bad_private_state() {
    let config = config();
    let label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::SmallResidue,
        Some(24),
    )
    .expect("label");
    let params = ScalarItVssSecurityParams {
        ic_retained_tags: 1,
        ic_audit_tags: 1,
        poly_consistency_rounds: 1,
    };
    let deal = scalar_it_vss_deal_honest_path::<MlDsa65>(
        &config,
        label,
        &[77, 2],
        &[vec![4, 1]],
        params,
        [0x24; 32],
    )
    .expect("deal");
    let mut log = InMemoryScalarItVssPersistenceLog::default();
    let mut machine = ScalarItVssStateMachine::new(&config, label).expect("machine");
    for phase in SCALAR_IT_VSS_PHASES {
        machine.accept_phase(*phase).expect("phase");
    }
    machine.persist_cursor(&mut log).expect("persist accepted");
    persist_scalar_it_vss_private_state(&mut log, &deal.context, &deal.private_payloads[0])
        .expect("persist private state");

    let other_label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::SmallResidue,
        Some(25),
    )
    .expect("other label");
    let other_context = ScalarItVssContext::new(&config, other_label).expect("context");
    assert_eq!(
        ensure_scalar_it_vss_restart_allows_accepted(&other_context, &log),
        Err(DkgError::ComplaintEvidenceMismatch)
    );

    let mut bad_log = log.clone();
    bad_log.private_state[0].retained_receiver_tag_state_hash = [0u8; 32];
    assert_eq!(
        ensure_scalar_it_vss_restart_allows_accepted(&deal.context, &bad_log),
        Err(DkgError::ComplaintEvidenceMismatch)
    );
}

#[test]
fn it_vss_ic_tag_accepts_correct_value_and_rejects_mutations() {
    let value = ItVssFq::new(123_456).expect("value");
    let b = ItVssFq::nonzero(77).expect("b");
    let y = ItVssFq::new(987).expect("y");
    let (holder_tag, audited) =
        it_vss_audited_ic_tag_pair(PartyId(1), PartyId(2), 9, value, b, y).expect("audited tag");
    assert!(audited.verify(value, holder_tag));

    let wrong_value = ItVssFq::new(value.value() + 1).expect("wrong value");
    assert!(!audited.verify(wrong_value, holder_tag));

    let wrong_y = ItVssHolderSideTag {
        y: ItVssFq::new(y.value() + 1).expect("wrong y"),
        ..holder_tag
    };
    assert!(!audited.verify(value, wrong_y));

    let wrong_receiver = ItVssHolderSideTag {
        receiver: PartyId(3),
        ..holder_tag
    };
    assert!(!audited.verify(value, wrong_receiver));
}

#[test]
fn it_vss_retained_receiver_tag_verifies_privately_and_redacts_debug() {
    let value = ItVssFq::new(55).expect("value");
    let b = ItVssFq::nonzero(13).expect("b");
    let y = ItVssFq::new(21).expect("y");
    let (holder_tag, retained) =
        it_vss_retained_ic_tag_pair(PartyId(1), PartyId(3), 2, value, b, y).expect("retained tag");

    assert_eq!(retained.holder(), PartyId(1));
    assert_eq!(retained.receiver(), PartyId(3));
    assert_eq!(retained.tag_index(), 2);
    assert!(retained.verify_private(value, holder_tag));

    let wrong_value = ItVssFq::new(value.value() + 2).expect("wrong value");
    assert!(!retained.verify_private(wrong_value, holder_tag));

    let debug = format!("{retained:?}");
    assert!(debug.contains("<receiver-private>"));
    assert!(!debug.contains("ItVssFq(13)"));
    assert!(!debug.contains("ItVssFq(328)"));
}

#[test]
fn it_vss_audited_tags_have_public_encoding_retained_tags_do_not() {
    let value = ItVssFq::new(7).expect("value");
    let b = ItVssFq::nonzero(5).expect("b");
    let y = ItVssFq::new(9).expect("y");
    let (_holder_tag, audited) =
        it_vss_audited_ic_tag_pair(PartyId(2), PartyId(3), 4, value, b, y).expect("audited tag");
    let encoded = encode_it_vss_audited_receiver_tag(&audited);

    assert_eq!(encoded.len(), 14);
    assert_eq!(&encoded[0..2], &2u16.to_le_bytes());
    assert_eq!(&encoded[2..4], &3u16.to_le_bytes());
    assert_eq!(&encoded[4..6], &4u16.to_le_bytes());
    assert_eq!(&encoded[6..10], &5u32.to_le_bytes());
    assert_eq!(&encoded[10..14], &(7u32 + 5 * 9).to_le_bytes());

    let (_holder_tag, retained) =
        it_vss_retained_ic_tag_pair(PartyId(2), PartyId(3), 4, value, b, y).expect("retained tag");
    assert!(retained.verify_private(
        value,
        ItVssHolderSideTag {
            holder: PartyId(2),
            receiver: PartyId(3),
            tag_index: 4,
            y,
        }
    ));
    // There is intentionally no public encoder accepting RetainedReceiverTag.
    let retained_debug = format!("{retained:?}");
    assert!(!retained_debug.contains("52"));
}

#[test]
fn it_vss_ic_tags_reject_zero_multiplier_and_noncanonical_field_elements() {
    assert_eq!(
        ItVssFq::new(IT_VSS_FIELD_Q),
        Err(DkgError::FieldShareCoefficientOutOfRange {
            index: 0,
            coefficient: IT_VSS_FIELD_Q as Coeff,
            modulus: IT_VSS_FIELD_Q as Coeff,
        })
    );
    assert_eq!(
        ItVssFq::nonzero(0),
        Err(DkgError::Backend("zero IT-VSS IC tag multiplier"))
    );
    assert_eq!(
        AuditedReceiverTag::new(PartyId(1), PartyId(2), 0, ItVssFq::zero(), ItVssFq::one(),),
        Err(DkgError::Backend("zero IT-VSS IC tag multiplier"))
    );
}

#[test]
fn it_vss_vector_ic_tag_authenticates_whole_vector() {
    let values = vec![
        ItVssFq::new(10).expect("value"),
        ItVssFq::new(20).expect("value"),
        ItVssFq::new(30).expect("value"),
    ];
    let y = vec![
        ItVssFq::new(7).expect("y"),
        ItVssFq::new(8).expect("y"),
        ItVssFq::new(9).expect("y"),
    ];
    let b = ItVssFq::nonzero(11).expect("b");
    let (holder_tag, audited) =
        it_vss_audited_vector_ic_tag_pair(PartyId(1), PartyId(2), 3, &values, b, &y)
            .expect("audited vector tag");
    assert!(audited.verify(&values, &holder_tag));

    let mut wrong_values = values.clone();
    wrong_values[1] = wrong_values[1].add_mod(ItVssFq::one());
    assert!(!audited.verify(&wrong_values, &holder_tag));

    let mut wrong_y = holder_tag.clone();
    wrong_y.y[2] = wrong_y.y[2].add_mod(ItVssFq::one());
    assert!(!audited.verify(&values, &wrong_y));

    assert_eq!(
        it_vss_vector_ic_tag_check_values(&values, b, &y[..2]),
        Err(DkgError::ItVssVectorLengthMismatch {
            expected: 3,
            got: 2,
        })
    );
}

#[test]
fn it_vss_vector_retained_tags_are_private_and_redacted() {
    let values = vec![
        ItVssFq::new(100).expect("value"),
        ItVssFq::new(200).expect("value"),
        ItVssFq::new(300).expect("value"),
        ItVssFq::new(400).expect("value"),
    ];
    let y = vec![
        ItVssFq::new(5).expect("y"),
        ItVssFq::new(6).expect("y"),
        ItVssFq::new(7).expect("y"),
        ItVssFq::new(8).expect("y"),
    ];
    let b = ItVssFq::nonzero(13).expect("b");
    let (holder_tag, retained) =
        it_vss_retained_vector_ic_tag_pair(PartyId(2), PartyId(3), 4, &values, b, &y)
            .expect("retained vector tag");
    assert!(retained.verify_private(&values, &holder_tag));
    assert_eq!(retained.holder(), PartyId(2));
    assert_eq!(retained.receiver(), PartyId(3));
    assert_eq!(retained.tag_index(), 4);

    let debug = format!("{retained:?}");
    assert!(debug.contains("<receiver-private>"));
    assert!(debug.contains("len"));
    assert!(!debug.contains("ItVssFq(13)"));
    assert!(!debug.contains("ItVssFq(165)"));

    let (audit_holder, audited) =
        it_vss_audited_vector_ic_tag_pair(PartyId(2), PartyId(3), 4, &values, b, &y)
            .expect("audited vector tag");
    assert!(audited.verify(&values, &audit_holder));
    let encoded = encode_it_vss_audited_vector_receiver_tag(&audited);
    assert_eq!(encoded.len(), 2 + 2 + 2 + 4 + 4 + values.len() * 4);
    assert_eq!(&encoded[10..14], &(values.len() as u32).to_le_bytes());
    // There is intentionally no public encoder accepting RetainedVectorReceiverTag.
}

#[test]
fn setup_cursor_release_gate_requires_complete_restart_state() {
    let mut cursors = InMemoryDkgSetupPhaseCursorLog::default();
    assert_eq!(
        ensure_dkg_setup_cursors_complete_for_release(&cursors),
        Err(DkgError::DkgSetupIncompleteAfterRestart)
    );
    cursors
        .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
            phase: DkgTransportPhase::ItVssArtifact,
            state: DkgSetupPhaseCursorState::Waiting,
            receiver: None,
            vector: None,
            coefficient_index: None,
            it_vss_phase: Some(ProductionItVssComplaintPhase::ResolveComplaints),
            expected: 3,
            got: 2,
        })
        .expect("persist waiting");
    assert_eq!(
        classify_dkg_setup_restart(cursors.latest_setup_phase_cursor()),
        DkgSetupRestartDecision::Resume
    );
    assert_eq!(
        ensure_dkg_setup_cursors_complete_for_release(&cursors),
        Err(DkgError::DkgSetupIncompleteAfterRestart)
    );
    cursors
        .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
            phase: DkgTransportPhase::ItVssArtifact,
            state: DkgSetupPhaseCursorState::Collected,
            receiver: None,
            vector: None,
            coefficient_index: None,
            it_vss_phase: Some(ProductionItVssComplaintPhase::CertifyAcceptedSharings),
            expected: 3,
            got: 3,
        })
        .expect("persist complete");
    assert_eq!(
        ensure_dkg_setup_cursors_complete_for_release(&cursors),
        Ok(())
    );
}

#[test]
fn release_setup_log_check_matches_certificate_artifact_hashes() {
    let config = config();
    let (public_commitments, resolution) = production_it_vss_artifacts_for_release_test(&config);
    let mut setup = test_setup_certificate(
        DkgSetupBackendId::ProductionInformationTheoretic,
        Vec::new(),
    );
    setup.it_vss_public_artifact_hash = hash_it_vss_public_artifacts(&public_commitments);
    setup.it_vss_resolution_hash = hash_it_vss_complaint_resolution(&resolution);
    let certificate = PublicKeyAssemblyCertificate {
        power2round: test_power2round_evidence(Power2RoundBackendId::ProductionItMpc),
        setup: Some(setup.clone()),
    };

    let mut runtimes = test_logged_dkg_transport_runtimes(&config);
    runtimes[0]
        .persist_it_vss_artifacts_logged(&public_commitments, &resolution)
        .expect("persist release artifacts");
    ensure_dkg_setup_log_matches_certificate_for_release(runtimes[0].wire_log(), &certificate)
        .expect("release log matches certificate");
    ensure_it_vss_artifact_log_uses_batched_vector_labels_for_release(
        &config,
        runtimes[0].wire_log(),
    )
    .expect("release labels are batched vector labels");

    let mut scalar_label_runtime = test_logged_dkg_transport_runtimes(&config)
        .into_iter()
        .next()
        .expect("runtime");
    let mut scalar_label_commitments = public_commitments.clone();
    scalar_label_commitments[0].label_hash = ItVssSharingLabel::new(
        &config,
        scalar_label_commitments[0].dealer,
        ItVssSharingDomain::MldsaS1,
        Some(0),
    )
    .expect("scalar label")
    .label_hash;
    scalar_label_runtime
        .persist_it_vss_artifacts_logged(&scalar_label_commitments, &resolution)
        .expect("persist scalar label artifact");
    assert_eq!(
        ensure_it_vss_artifact_log_uses_batched_vector_labels_for_release(
            &config,
            scalar_label_runtime.wire_log(),
        ),
        Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked)
    );

    let mut bad_certificate = certificate.clone();
    bad_certificate
        .setup
        .as_mut()
        .expect("setup")
        .it_vss_resolution_hash = [0xee; 32];
    assert!(matches!(
        ensure_dkg_setup_log_matches_certificate_for_release(
            runtimes[0].wire_log(),
            &bad_certificate
        ),
        Err(DkgError::TranscriptMismatch { .. })
    ));

    let mut scaffold_log_runtime = test_logged_dkg_transport_runtimes(&config)
        .into_iter()
        .next()
        .expect("runtime");
    let mut scaffold_commitments = public_commitments.clone();
    scaffold_commitments[0].backend_id = ItVssBackendId::InProcessHashBindingScaffold;
    scaffold_log_runtime
        .persist_it_vss_artifacts_logged(&scaffold_commitments, &resolution)
        .expect("persist scaffold artifact");
    assert_eq!(
        ensure_dkg_setup_log_matches_certificate_for_release(
            scaffold_log_runtime.wire_log(),
            &certificate,
        ),
        Err(DkgError::ItVssCertificateBackendMismatch)
    );

    let mut private_log_runtime = test_logged_dkg_transport_runtimes(&config)
        .into_iter()
        .next()
        .expect("runtime");
    private_log_runtime
        .send_vss_share_logged(
            PartyId(2),
            &DkgSharePayload {
                dealer: PartyId(1),
                receiver: PartyId(2),
                encrypted_share: IT_VSS_PRIVATE_DELIVERY_MAGIC.to_vec(),
                encrypted_seed_share: Vec::new(),
                proof: Vec::new(),
            },
        )
        .expect("persist private setup payload");
    assert_eq!(
        ensure_dkg_setup_log_excludes_forbidden_release_payloads(private_log_runtime.wire_log()),
        Err(DkgError::DkgReleaseArtifactContainsPrivateSetupPayload)
    );

    let mut private_batch_log_runtime = test_logged_dkg_transport_runtimes(&config)
        .into_iter()
        .next()
        .expect("runtime");
    private_batch_log_runtime
        .send_vss_share_logged(
            PartyId(2),
            &DkgSharePayload {
                dealer: PartyId(1),
                receiver: PartyId(2),
                encrypted_share: IT_VSS_PRIVATE_DELIVERY_BATCH_MAGIC.to_vec(),
                encrypted_seed_share: Vec::new(),
                proof: Vec::new(),
            },
        )
        .expect("persist private batch setup payload");
    assert_eq!(
        ensure_dkg_setup_log_excludes_forbidden_release_payloads(
            private_batch_log_runtime.wire_log()
        ),
        Err(DkgError::DkgReleaseArtifactContainsPrivateSetupPayload)
    );
}

#[test]
fn transport_backed_power2round_backend_requires_single_party_driver() {
    let config = config();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state machine");
    let mut backend = TransportBackedPower2RoundBackend::new(state);
    assert_eq!(
        backend.backend_id(),
        Power2RoundBackendId::TransportBackedPerPartyDriver
    );
    assert_eq!(
        ensure_power2round_backend_allowed_for_release(backend.backend_id()),
        Err(DkgError::InsecurePower2RoundBackend)
    );

    let material = sampled_material::<MlDsa65>(&config).expect("sample material");
    let shared_t = assemble_shared_t::<MlDsa65>(&config, [0x5e; 32], &material.s1, material.s2)
        .expect("shared t");
    assert!(matches!(
        backend.power2round_t1::<MlDsa65>(&config, shared_t),
        Err(DkgError::Power2RoundRequiresSinglePartyDriver)
    ));

    let runtime = backend.into_cursored_runtime(
        InMemoryPrimeFieldMpcWireMessageLog::default(),
        InMemoryPrimeFieldMpcPhaseCursorLog::default(),
    );
    assert!(runtime.cursor_log().latest_phase_cursor().is_none());
}

#[test]
fn production_power2round_driver_skeleton_enforces_phase_order() {
    let config = config();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state");
    let backend = TransportBackedPower2RoundBackend::new(state);
    let mut driver = backend.begin_production_driver();

    assert_eq!(
        driver.next_phase(),
        Some(ProductionPower2RoundDriverPhase::GenerateCanonicalMasks)
    );
    assert_eq!(
        driver.accept_phase(ProductionPower2RoundDriverPhase::OpenMaskedValues),
        Err(DkgError::Power2RoundDriverPhaseOutOfOrder)
    );
    assert_eq!(
        driver.accept_phase(ProductionPower2RoundDriverPhase::GenerateCanonicalMasks),
        Err(DkgError::Power2RoundCertifiedMaskRequired)
    );

    let root = Power2RoundTranscriptLabel::root(&config, [0x85; 32]);
    let mut mask_backend = LocalPrimeFieldMpcBackend::new([0x85; 32]);
    let mask = precompute_certified_power2round_mask_batch::<MlDsa65, _>(
        &mut mask_backend,
        8,
        root.child("power2round_t1_vec/mask"),
    )
    .expect("precompute driver mask");
    let mask_id = mask.id();
    driver
        .accept_precomputed_masks(&mask)
        .expect("accept precomputed masks");
    assert_eq!(driver.mask_batch_id(), Some(mask_id));

    assert_eq!(
        driver.accept_phase(ProductionPower2RoundDriverPhase::OpenMaskedValues),
        Err(DkgError::Power2RoundMaskedOpeningsRequired)
    );
    assert_eq!(
        driver.accept_masked_openings(7),
        Err(DkgError::Power2RoundMaskShapeMismatch)
    );
    driver
        .accept_masked_openings(8)
        .expect("accept masked opening lanes");
    assert_eq!(driver.opened_masked_value_lanes(), Some(8));
    assert_eq!(
        driver.accept_phase(ProductionPower2RoundDriverPhase::RecoverCanonicalBits),
        Err(DkgError::Power2RoundCanonicalBitsRequired)
    );
    assert_eq!(
        driver.accept_canonical_bit_recovery(7),
        Err(DkgError::Power2RoundMaskedOpeningsRequired)
    );
    driver
        .accept_canonical_bit_recovery(8)
        .expect("accept canonical bit recovery lanes");
    assert_eq!(driver.canonical_bit_lanes(), Some(8));

    assert_eq!(
        driver.accept_phase(ProductionPower2RoundDriverPhase::AddRoundConstant),
        Err(DkgError::Power2RoundAddRoundConstantRequired)
    );
    assert_eq!(
        driver.accept_add_round_constant(7),
        Err(DkgError::Power2RoundCanonicalBitsRequired)
    );
    driver
        .accept_add_round_constant(8)
        .expect("accept add-round-constant lanes");
    assert_eq!(driver.add_round_constant_lanes(), Some(8));

    assert_eq!(
        driver.accept_phase(ProductionPower2RoundDriverPhase::OpenT1Bits),
        Err(DkgError::Power2RoundT1BitsRequired)
    );
    let bad_t1 = PublicT1 {
        bytes: vec![0x11],
        coeffs: vec![0; 7],
    };
    assert_eq!(
        driver.accept_opened_t1(&bad_t1),
        Err(DkgError::InvalidBoundedSecretVectorLength {
            expected: 8,
            got: 7
        })
    );
    let t1 = PublicT1 {
        bytes: vec![0xaa; 4],
        coeffs: vec![0, 1, 2, 3, 1020, 1021, 1022, 1023],
    };
    driver.accept_opened_t1(&t1).expect("accept opened t1");
    assert_eq!(driver.opened_t1_lanes(), Some(8));
    assert_eq!(
        driver.opened_t1_hash(),
        Some(hash_bytes32(b"TALUS-DKG-v1/power2round-t1", &t1.bytes))
    );

    assert_eq!(
        driver.accept_phase(ProductionPower2RoundDriverPhase::CertifyEvidence),
        Err(DkgError::Power2RoundEvidenceRequired)
    );
    let assembly_label = PublicKeyAssemblyLabel::new(&config, [0x85; 32]);
    let evidence = power2round_certify_public_t1_evidence(
        Power2RoundBackendId::ProductionItMpc,
        &config,
        assembly_label,
        &t1,
    );
    let mut bad_evidence = evidence.clone();
    bad_evidence.output_t1_hash = [0x42; 32];
    assert_eq!(
        driver.accept_certified_evidence(&bad_evidence),
        Err(DkgError::Power2RoundEvidenceRequired)
    );
    driver
        .accept_certified_evidence(&evidence)
        .expect("accept public evidence");
    assert_eq!(
        driver.evidence_transcript_hash(),
        Some(evidence.transcript_hash)
    );
    assert!(driver.is_complete());
    assert_eq!(driver.next_phase(), None);
}

#[test]
fn production_power2round_driver_resumes_after_precomputed_masks() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x86; 32]);
    let mask_id = Power2RoundMaskBatchId::new(&root.child("power2round_t1_vec/mask"), 16);
    let mut driver = ProductionPower2RoundPerPartyDriver::resume_after_precomputed_masks(mask_id);

    assert_eq!(driver.mask_batch_id(), Some(mask_id));
    assert_eq!(
        driver.next_phase(),
        Some(ProductionPower2RoundDriverPhase::OpenMaskedValues)
    );
    assert_eq!(
        driver.accept_phase(ProductionPower2RoundDriverPhase::GenerateCanonicalMasks),
        Err(DkgError::Power2RoundDriverPhaseOutOfOrder)
    );
    assert_eq!(
        driver.accept_phase(ProductionPower2RoundDriverPhase::OpenMaskedValues),
        Err(DkgError::Power2RoundMaskedOpeningsRequired)
    );
    driver
        .accept_masked_openings(16)
        .expect("accept masked openings after resume");
    assert_eq!(
        driver.next_phase(),
        Some(ProductionPower2RoundDriverPhase::RecoverCanonicalBits)
    );
}

#[test]
fn production_power2round_vector_driver_collects_t1_and_recovers_from_logs() {
    let config = config();
    let lane_count = MlDsa65::K * MlDsa65::N;
    let root = Power2RoundTranscriptLabel::root(&config, [0x91; 32]);
    let label = root.child("power2round_t1_vec");
    let assembly_label = PublicKeyAssemblyLabel::new(&config, [0x91; 32]);
    let mask_id = Power2RoundMaskBatchId::new(&label.child("mask"), lane_count);
    let mut driver = ProductionPower2RoundPerPartyDriver::resume_after_precomputed_masks(mask_id);
    let mut runtimes = test_party_runtimes(&config)
        .into_iter()
        .map(|runtime| {
            CursoredTransportPrimeFieldMpcPartyRuntime::new(
                runtime,
                InMemoryPrimeFieldMpcPhaseCursorLog::default(),
            )
        })
        .collect::<Vec<_>>();

    let mut routed_broadcasts = 0usize;
    let masked_values = vec![17; lane_count];
    for runtime in &mut runtimes {
        runtime
            .drive_power2round_masked_c_vec(&label, &masked_values)
            .expect("send masked C vector");
    }
    route_cursored_prime_field_broadcast_messages(
        &mut runtimes,
        [0usize, 1, 2],
        &mut routed_broadcasts,
    );
    assert_eq!(
        runtimes[0]
            .drive_collect_power2round_masked_c_vec_and_advance(&mut driver, &label)
            .expect("collect masked C and advance"),
        ProductionPower2RoundVectorCollectResult::Collected(vec![
            (PartyId(1), masked_values.clone()),
            (PartyId(2), masked_values.clone()),
            (PartyId(3), masked_values.clone()),
        ])
    );
    assert_eq!(
        driver.next_phase(),
        Some(ProductionPower2RoundDriverPhase::RecoverCanonicalBits)
    );
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }
    routed_broadcasts = 0;

    let canonical_values = vec![0; lane_count];
    for runtime in &mut runtimes {
        runtime
            .drive_power2round_wrap_compare_vec(&label, &canonical_values)
            .expect("send wrap compare vector");
    }
    route_cursored_prime_field_broadcast_messages(
        &mut runtimes,
        [0usize, 1, 2],
        &mut routed_broadcasts,
    );
    runtimes[0]
        .drive_collect_power2round_wrap_compare_vec(&label)
        .expect("collect wrap compare vector");
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }
    routed_broadcasts = 0;

    for bit_idx in 0..24 {
        for runtime in &mut runtimes {
            runtime
                .drive_power2round_subtractor_share_vec(&label, bit_idx, &canonical_values)
                .expect("send subtractor vector");
        }
        route_cursored_prime_field_broadcast_messages(
            &mut runtimes,
            [0usize, 1, 2],
            &mut routed_broadcasts,
        );
        runtimes[0]
            .drive_collect_power2round_subtractor_share_vec(&label, bit_idx)
            .expect("collect subtractor vector");
        for runtime in &mut runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
        routed_broadcasts = 0;
    }

    for bit_idx in 0..23 {
        for runtime in &mut runtimes {
            runtime
                .drive_power2round_canonical_bitness_check_vec(&label, bit_idx, &canonical_values)
                .expect("send canonical bitness vector");
        }
        route_cursored_prime_field_broadcast_messages(
            &mut runtimes,
            [0usize, 1, 2],
            &mut routed_broadcasts,
        );
        runtimes[0]
            .drive_collect_power2round_canonical_bitness_check_vec(&label, bit_idx)
            .expect("collect canonical bitness vector");
        for runtime in &mut runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
        routed_broadcasts = 0;
    }

    for runtime in &mut runtimes {
        runtime
            .drive_power2round_canonical_range_check_vec(&label, &canonical_values)
            .expect("send canonical range vector");
    }
    route_cursored_prime_field_broadcast_messages(
        &mut runtimes,
        [0usize, 1, 2],
        &mut routed_broadcasts,
    );
    runtimes[0]
        .drive_collect_power2round_canonical_range_check_vec(&label)
        .expect("collect canonical range vector");
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }
    routed_broadcasts = 0;

    for runtime in &mut runtimes {
        runtime
            .drive_power2round_equality_check_vec(&label, &canonical_values)
            .expect("send equality vector");
    }
    route_cursored_prime_field_broadcast_messages(
        &mut runtimes,
        [0usize, 1, 2],
        &mut routed_broadcasts,
    );
    runtimes[0]
        .drive_collect_power2round_equality_check_vec(&label)
        .expect("collect equality vector");
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }
    routed_broadcasts = 0;

    let canonical_wire_log = runtimes[0].runtime().wire_log().clone();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state");
    let recovered_canonical_runtime =
        TransportPrimeFieldMpcPartyRuntime::new(state, canonical_wire_log);
    let mut recovered_canonical = CursoredTransportPrimeFieldMpcPartyRuntime::new(
        recovered_canonical_runtime,
        InMemoryPrimeFieldMpcPhaseCursorLog::default(),
    );
    assert_eq!(
        recovered_canonical
            .drive_collect_power2round_canonical_recovery_all_vec_and_advance(&mut driver, &label)
            .expect("recover canonical phases and advance"),
        ProductionPower2RoundVectorCollectResult::Collected(lane_count)
    );
    assert_eq!(
        driver.next_phase(),
        Some(ProductionPower2RoundDriverPhase::AddRoundConstant)
    );

    for bit_idx in 0..23 {
        let values = vec![0; lane_count];
        for runtime in &mut runtimes {
            runtime
                .drive_power2round_add4095_share_vec(&label, bit_idx, &values)
                .expect("send add4095 bit vector");
        }
        route_cursored_prime_field_broadcast_messages(
            &mut runtimes,
            [0usize, 1, 2],
            &mut routed_broadcasts,
        );
        runtimes[0]
            .drive_collect_power2round_add4095_share_vec(&label, bit_idx)
            .expect("collect add4095 bit vector");
        for runtime in &mut runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
        routed_broadcasts = 0;
    }
    let add4095_wire_log = runtimes[0].runtime().wire_log().clone();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state");
    let recovered_add4095_runtime =
        TransportPrimeFieldMpcPartyRuntime::new(state, add4095_wire_log);
    let mut recovered_add4095 = CursoredTransportPrimeFieldMpcPartyRuntime::new(
        recovered_add4095_runtime,
        InMemoryPrimeFieldMpcPhaseCursorLog::default(),
    );
    assert_eq!(
        recovered_add4095
            .drive_collect_power2round_add4095_all_vec_and_advance(&mut driver, &label)
            .expect("collect add4095 all"),
        ProductionPower2RoundVectorCollectResult::Collected(lane_count)
    );
    assert_eq!(
        driver.next_phase(),
        Some(ProductionPower2RoundDriverPhase::OpenT1Bits)
    );

    let expected_coeffs = (0..lane_count)
        .map(|index| (index as u16) & 1023)
        .collect::<Vec<_>>();
    for bit_idx in 0..10 {
        let values = expected_coeffs
            .iter()
            .map(|coefficient| ((coefficient >> bit_idx) & 1) as Coeff)
            .collect::<Vec<_>>();
        for runtime in &mut runtimes {
            runtime
                .drive_power2round_t1_bit_vec(&label, bit_idx, &values)
                .expect("send t1 bit vector");
        }
        route_cursored_prime_field_broadcast_messages(
            &mut runtimes,
            [0usize, 1, 2],
            &mut routed_broadcasts,
        );
        runtimes[0]
            .drive_collect_power2round_t1_bit_vec(&label, bit_idx)
            .expect("collect t1 bit vector");
        for runtime in &mut runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
        routed_broadcasts = 0;
    }
    let saved_wire_log = runtimes[0].runtime().wire_log().clone();
    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state");
    let recovered_runtime = TransportPrimeFieldMpcPartyRuntime::new(state, saved_wire_log.clone());
    let mut recovered = CursoredTransportPrimeFieldMpcPartyRuntime::new(
        recovered_runtime,
        InMemoryPrimeFieldMpcPhaseCursorLog::default(),
    );
    let output = match recovered
        .drive_collect_power2round_t1_bits_and_certify::<MlDsa65>(
            &mut driver,
            &config,
            assembly_label,
            &label,
        )
        .expect("collect t1 bits")
    {
        ProductionPower2RoundVectorCollectResult::Collected(result) => result,
        ProductionPower2RoundVectorCollectResult::Waiting(statuses) => {
            panic!("unexpected t1 wait: {statuses:?}")
        }
    };
    let (t1, evidence) = output.into_parts();
    assert_eq!(t1.coeffs, expected_coeffs);
    assert_eq!(evidence.backend_id, Power2RoundBackendId::ProductionItMpc);
    assert!(driver.is_complete());

    let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
    let state = TransportPrimeFieldMpcStateMachine::new(config.clone(), PartyId(1), transport)
        .expect("state");
    let recovered_runtime = TransportPrimeFieldMpcPartyRuntime::new(state, saved_wire_log);
    let mut recovered = CursoredTransportPrimeFieldMpcPartyRuntime::new(
        recovered_runtime,
        InMemoryPrimeFieldMpcPhaseCursorLog::default(),
    );
    let mut recovered_driver =
        ProductionPower2RoundPerPartyDriver::resume_after_precomputed_masks(mask_id);
    recovered_driver
        .accept_masked_openings(lane_count)
        .expect("recover masked openings");
    recovered_driver
        .accept_canonical_bit_recovery(lane_count)
        .expect("recover canonical bits");
    recovered_driver
        .accept_add_round_constant(lane_count)
        .expect("recover add4095");
    let recovered_output = match recovered
        .drive_collect_power2round_t1_bits_and_certify::<MlDsa65>(
            &mut recovered_driver,
            &config,
            assembly_label,
            &label,
        )
        .expect("recover t1 bits from logs")
    {
        ProductionPower2RoundVectorCollectResult::Collected(result) => result,
        ProductionPower2RoundVectorCollectResult::Waiting(statuses) => {
            panic!("unexpected recovered t1 wait: {statuses:?}")
        }
    };
    let (recovered_t1, recovered_evidence) = recovered_output.into_parts();
    assert_eq!(recovered_t1, t1);
    assert_eq!(recovered_evidence, evidence);
    assert!(recovered_driver.is_complete());
}

#[test]
fn prime_field_share_vec_debug_redacts_lanes() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x72; 32]);
    let backend = LocalPrimeFieldMpcBackend::new([0x72; 32]);
    let lanes = vec![
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(&backend, 7),
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(&backend, 9),
    ];
    let share_vec =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend, lanes,
        );
    let debug = format!("{share_vec:?}");
    assert!(debug.contains("len"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains('7'));
    assert!(!debug.contains('9'));

    let bits = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::random_bit_vec(
        &mut LocalPrimeFieldMpcBackend::new([0x73; 32]),
        2,
        root.child("bits"),
    )
    .expect("bits");
    let bit_debug = format!("{bits:?}");
    assert!(bit_debug.contains("BitShareVec"));
    assert!(bit_debug.contains("<redacted>"));
}

#[test]
fn local_prime_field_vector_ops_batch_and_count() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x74; 32]);
    let mut backend = LocalPrimeFieldMpcBackend::new([0x74; 32]);

    let public_lanes = vec![3, 5, 7]
        .into_iter()
        .map(|value| {
            <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                &backend, value,
            )
        })
        .collect::<Vec<_>>();
    let public_vec =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            public_lanes,
        );
    let doubled =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::mul_public_const_vec(
            &mut backend,
            public_vec,
            2,
            root.child("double_public"),
        )
        .expect("public vector mul");
    let opened = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
        &mut backend,
        doubled,
        root.child("open_doubled"),
    )
    .expect("open doubled");
    assert_eq!(opened, vec![6, 10, 14]);

    let left = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
        &backend,
        vec![2, 3, 4]
            .into_iter()
            .map(|value| {
                <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                    &backend, value,
                )
            })
            .collect(),
    );
    let right =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            vec![11, 13, 17]
                .into_iter()
                .map(|value| {
                    <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                        &backend, value,
                    )
                })
                .collect(),
        );
    let product = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::mul_vec(
        &mut backend,
        left,
        right,
        root.child("mul_vec"),
    )
    .expect("vector mul");
    let opened_product =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
            &mut backend,
            product,
            root.child("open_product"),
        )
        .expect("open product");
    assert_eq!(opened_product, vec![22, 39, 68]);

    let zero_vec = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_const_vec(
        &backend, 0, 4,
    );
    <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::assert_zero_vec(
        &mut backend,
        zero_vec,
        root.child("assert_zero_vec"),
    )
    .expect("zero vec");

    let bits = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::random_bit_vec(
        &mut backend,
        5,
        root.child("random_bits"),
    )
    .expect("random bits");
    assert_eq!(bits.len(), 5);
    let bit_share_vec =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            bits.into_lanes()
                .into_iter()
                .map(|bit| {
                    <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::bit_to_share(
                        &backend, &bit,
                    )
                })
                .collect(),
        );
    let bit_values =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
            &mut backend,
            bit_share_vec,
            root.child("open_random_bits"),
        )
        .expect("open bits");
    assert!(bit_values.iter().all(|bit| *bit == 0 || *bit == 1));

    let counters =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::counters(&backend)
            .expect("local counters");
    assert_eq!(counters.local_public_mul_lanes, 3);
    assert_eq!(counters.vector_mul_lanes, 3);
    assert_eq!(counters.vector_assert_zero_lanes, 4);
    assert_eq!(counters.vector_opening_lanes, 11);
    assert_eq!(counters.random_bits, 5);
    assert_eq!(counters.scalar_mul_gates, 0);
    assert_eq!(counters.scalar_openings, 0);
    assert_eq!(backend.opened_labels().len(), 3);
}

#[test]
fn in_process_shamir_vector_ops_use_single_batch_labels() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x7b; 32]);
    let mut backend = InProcessShamirPrimeFieldMpcBackend::new(config, [0x7b; 32]);
    let left =
        <InProcessShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            vec![2, 3, 4]
                .into_iter()
                .map(|value| {
                    <InProcessShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                        &backend, value,
                    )
                })
                .collect(),
        );
    let right =
        <InProcessShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            vec![11, 13, 17]
                .into_iter()
                .map(|value| {
                    <InProcessShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                        &backend, value,
                    )
                })
                .collect(),
        );

    let product =
        <InProcessShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::mul_vec(
            &mut backend,
            left,
            right,
            root.child("mul_vec"),
        )
        .expect("mul vec");
    assert_eq!(backend.gate_labels().len(), 1);
    assert!(backend.gate_labels()[0].contains("mul_vec"));

    let opened =
        <InProcessShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
            &mut backend,
            product,
            root.child("open_vec"),
        )
        .expect("open vec");
    assert_eq!(opened, vec![22, 39, 68]);
    assert_eq!(backend.opened_labels().len(), 1);
    assert!(backend.opened_labels()[0].contains("open_vec"));

    let zero_vec =
        <InProcessShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_const_vec(
            &backend, 0, 3,
        );
    <InProcessShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::assert_zero_vec(
        &mut backend,
        zero_vec,
        root.child("assert_zero_vec"),
    )
    .expect("assert zero vec");
    assert_eq!(backend.gate_labels().len(), 2);
    assert!(backend.gate_labels()[1].contains("assert_zero_vec"));
}

#[test]
fn networked_shamir_vector_ops_use_single_batch_labels() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x7c; 32]);
    let mut backend = NetworkedShamirPrimeFieldMpcBackend::new(config, [0x7c; 32]);
    let left =
        <NetworkedShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            vec![2, 3, 4]
                .into_iter()
                .map(|value| {
                    <NetworkedShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                        &backend, value,
                    )
                })
                .collect(),
        );
    let right =
        <NetworkedShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            vec![11, 13, 17]
                .into_iter()
                .map(|value| {
                    <NetworkedShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                        &backend, value,
                    )
                })
                .collect(),
        );

    let product =
        <NetworkedShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::mul_vec(
            &mut backend,
            left,
            right,
            root.child("mul_vec"),
        )
        .expect("mul vec");
    assert_eq!(backend.gate_labels().len(), 1);
    assert!(backend.gate_labels()[0].contains("mul_vec"));
    assert!(backend
        .network()
        .vector_messages()
        .iter()
        .any(|message| message.kind == PrimeFieldMpcRoundKind::MulDegreeReduce));
    assert!(backend.network().messages().is_empty());

    let opened =
        <NetworkedShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
            &mut backend,
            product,
            root.child("open_vec"),
        )
        .expect("open vec");
    assert_eq!(opened, vec![22, 39, 68]);
    assert_eq!(backend.opened_labels().len(), 1);
    assert!(backend.opened_labels()[0].contains("open_vec"));

    let zero_vec =
        <NetworkedShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_const_vec(
            &backend, 0, 3,
        );
    <NetworkedShamirPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::assert_zero_vec(
        &mut backend,
        zero_vec,
        root.child("assert_zero_vec"),
    )
    .expect("assert zero vec");
    assert_eq!(backend.gate_labels().len(), 2);
    assert!(backend.gate_labels()[1].contains("assert_zero_vec"));
    assert!(backend
        .network()
        .vector_messages()
        .iter()
        .any(|message| message.kind == PrimeFieldMpcRoundKind::AssertZero));
    assert!(backend
        .network()
        .vector_messages()
        .iter()
        .any(|message| message.kind == PrimeFieldMpcRoundKind::Open));
    assert!(backend
        .network()
        .vector_messages()
        .iter()
        .all(|message| message.values.len() == 3));
}

#[test]
fn in_memory_prime_field_network_rejects_vector_replay() {
    let config = config();
    let label = Power2RoundTranscriptLabel::root(&config, [0x7d; 32]).child("vector_replay");
    let mut network = InMemoryPrimeFieldMpcNetwork::default();
    let message = PrimeFieldMpcVectorMessage {
        sender: PartyId(1),
        receiver: Some(PartyId(2)),
        kind: PrimeFieldMpcRoundKind::Open,
        label_hash: power2round_label_hash(&label),
        values: vec![1, 2, 3],
    };
    network.send_vector(message.clone()).expect("first send");
    assert_eq!(network.vector_messages(), &[message.clone()]);
    assert_eq!(
        network.send_vector(message),
        Err(DkgError::PrimeFieldMpcReplayDetected)
    );
}

#[test]
fn local_prime_field_bit_vector_ops_match_boolean_truth_tables() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x75; 32]);
    let mut backend = LocalPrimeFieldMpcBackend::new([0x75; 32]);

    let x_bits = [false, true, true]
        .into_iter()
        .map(|bit| {
            <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(
                &backend, bit,
            )
        })
        .collect::<Vec<_>>();
    let y_bits = [false, false, true]
        .into_iter()
        .map(|bit| {
            <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(
                &backend, bit,
            )
        })
        .collect::<Vec<_>>();

    let and_bits = bit_and_vec::<MlDsa65, _>(
        &mut backend,
        BitShareVec::from_lanes(x_bits.clone()),
        BitShareVec::from_lanes(y_bits.clone()),
        root.child("and"),
    )
    .expect("and vec");
    let xor_bits = bit_xor_vec::<MlDsa65, _>(
        &mut backend,
        BitShareVec::from_lanes(x_bits.clone()),
        BitShareVec::from_lanes(y_bits),
        root.child("xor"),
    )
    .expect("xor vec");
    let not_bits = bit_not_vec::<MlDsa65, _>(&backend, BitShareVec::from_lanes(x_bits));

    let and_shares =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            and_bits
                .into_lanes()
                .into_iter()
                .map(|bit| {
                    <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::bit_to_share(
                        &backend, &bit,
                    )
                })
                .collect(),
        );
    let and_opened =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
            &mut backend,
            and_shares,
            root.child("open_and"),
        )
        .expect("open and");
    assert_eq!(and_opened, vec![0, 0, 1]);

    let xor_shares =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            xor_bits
                .into_lanes()
                .into_iter()
                .map(|bit| {
                    <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::bit_to_share(
                        &backend, &bit,
                    )
                })
                .collect(),
        );
    let xor_opened =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
            &mut backend,
            xor_shares,
            root.child("open_xor"),
        )
        .expect("open xor");
    assert_eq!(xor_opened, vec![0, 1, 0]);

    let not_shares =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            not_bits
                .into_lanes()
                .into_iter()
                .map(|bit| {
                    <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::bit_to_share(
                        &backend, &bit,
                    )
                })
                .collect(),
        );
    let not_opened =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
            &mut backend,
            not_shares,
            root.child("open_not"),
        )
        .expect("open not");
    assert_eq!(not_opened, vec![1, 0, 0]);

    let counters =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::counters(&backend)
            .expect("local counters");
    assert_eq!(counters.vector_mul_lanes, 6);
    assert_eq!(counters.local_public_mul_lanes, 3);
    assert_eq!(counters.scalar_mul_gates, 0);
}

#[test]
fn vectorized_power2round_add_4095_and_open_high_bits_matches_reference() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x76; 32]);
    let mut backend = LocalPrimeFieldMpcBackend::new([0x76; 32]);
    let values = vec![
        0,
        4095,
        4096,
        4097,
        8191,
        8192,
        MlDsa65::Q - 4096,
        MlDsa65::Q - 1,
    ];
    let bits_by_bit = (0..23)
        .map(|bit_index| {
            BitShareVec::from_lanes(
                values
                    .iter()
                    .map(|value| {
                        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(
                            &backend,
                            (((*value as u32) >> bit_index) & 1) == 1,
                        )
                    })
                    .collect(),
            )
        })
        .collect::<Vec<_>>();

    let s_bits = power2round_add_4095_vec::<MlDsa65, _>(
        &mut backend,
        &bits_by_bit,
        root.child("power2round_add_4095_vec"),
    )
    .expect("power2round add 4095 vec");
    let opened =
        power2round_open_t1_bits_vec::<MlDsa65, _>(&mut backend, &s_bits, root.child("open_t1"))
            .expect("open t1 vec");
    let expected = values
        .iter()
        .map(|&value| talus_core::power2round::<MlDsa65>(value).0 as u16)
        .collect::<Vec<_>>();
    assert_eq!(opened, expected);

    let counters =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::counters(&backend)
            .expect("local counters");
    assert_eq!(counters.vector_opening_lanes, values.len() as u64 * 10);
    assert_eq!(backend.opened_labels().len(), 1);
    assert!(backend.opened_labels()[0].contains("open_t1_bits"));
}

#[test]
fn power2round_public_t1_pack_and_evidence_are_transcript_bound() {
    let config = config();
    let mut coeffs = vec![0u16; MlDsa65::K * MlDsa65::N];
    coeffs[0] = 1023;
    coeffs[17] = 513;
    coeffs[MlDsa65::K * MlDsa65::N - 1] = 1;

    let t1 = power2round_public_t1_from_coeffs::<MlDsa65>(coeffs.clone()).expect("pack public t1");
    assert_eq!(t1.coeffs, coeffs);
    assert_eq!(t1.bytes.len(), MlDsa65::K * 320);

    let label = PublicKeyAssemblyLabel::new(&config, [0x79; 32]);
    let evidence = power2round_certify_public_t1_evidence(
        Power2RoundBackendId::ProductionItMpc,
        &config,
        label,
        &t1,
    );
    assert_eq!(evidence.backend_id, Power2RoundBackendId::ProductionItMpc);
    assert_eq!(
        evidence.output_t1_hash,
        hash_bytes32(b"TALUS-DKG-v1/power2round-t1", &t1.bytes)
    );

    let wrong_len = power2round_public_t1_from_coeffs::<MlDsa65>(vec![0; 7]);
    assert_eq!(
        wrong_len,
        Err(DkgError::InvalidBoundedSecretVectorLength {
            expected: MlDsa65::K * MlDsa65::N,
            got: 7
        })
    );

    let mut out_of_range = vec![0u16; MlDsa65::K * MlDsa65::N];
    out_of_range[0] = 1024;
    assert!(matches!(
        power2round_public_t1_from_coeffs::<MlDsa65>(out_of_range),
        Err(DkgError::Backend("t1 coefficient out of range"))
    ));
}

#[test]
fn production_power2round_output_requires_matching_evidence() {
    let config = config();
    let rho = [0x79; 32];
    let label = PublicKeyAssemblyLabel::new(&config, rho);
    let t1 = power2round_public_t1_from_coeffs::<MlDsa65>(vec![0u16; MlDsa65::K * MlDsa65::N])
        .expect("pack public t1");
    let evidence = power2round_certify_public_t1_evidence(
        Power2RoundBackendId::ProductionItMpc,
        &config,
        label,
        &t1,
    );

    let output = ProductionPower2RoundOutput::new(&config, label, t1.clone(), evidence.clone())
        .expect("production output");
    let (public, certificate) =
        assemble_public_output_from_production_power2round(&config, rho, &config.parties, output)
            .expect("assemble public output");
    assert_eq!(public.t1, t1.bytes);
    assert_eq!(certificate.power2round, evidence);

    let mut wrong_hash = evidence.clone();
    wrong_hash.output_t1_hash[0] ^= 1;
    assert_eq!(
        ProductionPower2RoundOutput::new(&config, label, t1.clone(), wrong_hash),
        Err(DkgError::Power2RoundEvidenceRequired)
    );

    let mut relabeled_simulator = evidence;
    relabeled_simulator.backend_id = Power2RoundBackendId::InsecureClearSimulator;
    assert_eq!(
        ProductionPower2RoundOutput::new(&config, label, t1, relabeled_simulator),
        Err(DkgError::InsecurePower2RoundBackend)
    );
}

#[test]
fn vectorized_public_comparators_match_scalar_truth_tables() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x77; 32]);
    let mut backend = LocalPrimeFieldMpcBackend::new([0x77; 32]);
    let values = [0, 4, 5, 6, MlDsa65::Q - 1];
    let bits_by_bit = (0..23)
        .map(|bit_index| {
            BitShareVec::from_lanes(
                values
                    .iter()
                    .map(|value| {
                        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(
                            &backend,
                            (((*value as u32) >> bit_index) & 1) == 1,
                        )
                    })
                    .collect(),
            )
        })
        .collect::<Vec<_>>();

    let lt = lt_public_vec::<MlDsa65, _>(&mut backend, &bits_by_bit, 5, root.child("lt_5"))
        .expect("lt vec");
    let lt_shares =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            lt.into_lanes()
                .into_iter()
                .map(|bit| {
                    <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::bit_to_share(
                        &backend, &bit,
                    )
                })
                .collect(),
        );
    let lt_opened =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
            &mut backend,
            lt_shares,
            root.child("open_lt"),
        )
        .expect("open lt");
    assert_eq!(lt_opened, vec![1, 1, 0, 0, 0]);

    let gt = gt_public_vec::<MlDsa65, _>(&mut backend, &bits_by_bit, 5, root.child("gt_5"))
        .expect("gt vec");
    let gt_shares =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            gt.into_lanes()
                .into_iter()
                .map(|bit| {
                    <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::bit_to_share(
                        &backend, &bit,
                    )
                })
                .collect(),
        );
    let gt_opened =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
            &mut backend,
            gt_shares,
            root.child("open_gt"),
        )
        .expect("open gt");
    assert_eq!(gt_opened, vec![0, 0, 0, 1, 1]);
}

#[test]
fn random_canonical_mask_q_vec_generates_canonical_masks() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x78; 32]);
    let mut backend = LocalPrimeFieldMpcBackend::new([0x78; 32]);
    let mask = random_canonical_mask_q_vec::<MlDsa65, _>(&mut backend, 16, root.child("mask_vec"))
        .expect("mask vec");
    assert_eq!(mask.bits_by_bit().len(), 23);
    assert!(mask.bits_by_bit().iter().all(|bits| bits.len() == 16));

    let opened = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
        &mut backend,
        mask.value().clone(),
        root.child("open_mask_values"),
    )
    .expect("open mask values");
    assert_eq!(opened.len(), 16);
    assert!(opened.iter().all(|value| (0..MlDsa65::Q).contains(value)));
}

#[test]
fn certified_power2round_mask_batch_is_transcript_bound_and_one_time() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x80; 32]);
    let mut backend = LocalPrimeFieldMpcBackend::new([0x80; 32]);
    let mask_label = root.child("precomputed_mask_batch");
    let mask = random_canonical_mask_q_vec::<MlDsa65, _>(&mut backend, 4, mask_label.clone())
        .expect("certified mask");

    assert_eq!(mask.id(), Power2RoundMaskBatchId::new(&mask_label, 4));
    assert_eq!(mask.bits_by_bit().len(), 23);
    assert_eq!(mask.value().len(), 4);
    assert!(format!("{mask:?}").contains("<redacted>"));

    let mut use_log = InMemoryPower2RoundMaskUseLog::default();
    let id = mask.id();
    let consumed = mask.consume(&mut use_log).expect("consume mask");
    assert_eq!(consumed.id(), id);
    assert_eq!(use_log.consumed(), &[id]);
    assert!(format!("{consumed:?}").contains("<redacted>"));
    assert_eq!(
        use_log.mark_mask_consumed(id),
        Err(DkgError::Power2RoundMaskAlreadyConsumed)
    );
}

#[cfg(feature = "std")]
#[test]
fn file_power2round_mask_use_log_survives_reopen_and_rejects_reuse() {
    let path = std::env::temp_dir().join(format!(
        "talus-power2round-mask-use-log-{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x82; 32]);
    let first = Power2RoundMaskBatchId::new(&root.child("mask_1"), 8);
    let second = Power2RoundMaskBatchId::new(&root.child("mask_2"), 8);
    {
        let mut log = FilePower2RoundMaskUseLog::open(&path).expect("open mask log");
        log.mark_mask_consumed(first)
            .expect("persist first consumed mask");
        log.mark_mask_consumed(second)
            .expect("persist second consumed mask");
        assert_eq!(log.consumed(), &[first, second]);
        assert_eq!(
            log.mark_mask_consumed(first),
            Err(DkgError::Power2RoundMaskAlreadyConsumed)
        );
    }

    let reopened = FilePower2RoundMaskUseLog::open(&path).expect("reopen mask log");
    assert_eq!(reopened.consumed(), &[first, second]);

    let mut duplicate_file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("open duplicate append");
    use std::io::Write;
    writeln!(
        duplicate_file,
        "{} {}",
        first.lane_count,
        Hex32(first.label_hash)
    )
    .expect("append duplicate mask id");
    duplicate_file.sync_data().expect("sync duplicate append");
    assert_eq!(
        FilePower2RoundMaskUseLog::open(&path),
        Err(DkgError::Power2RoundMaskAlreadyConsumed)
    );

    std::fs::write(&path, b"not a valid mask use log\n").expect("write corrupt");
    assert_eq!(
        FilePower2RoundMaskUseLog::open(&path),
        Err(DkgError::Power2RoundMaskUseLogCorrupt { line: 1 })
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn power2round_masked_c_vec_adds_t_and_mask_under_power2round_label() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x88; 32]);
    let label = root.child("masked_c_vec");
    let mut backend = LocalPrimeFieldMpcBackend::new([0x88; 32]);
    let mask = precompute_certified_power2round_mask_batch::<MlDsa65, _>(
        &mut backend,
        3,
        label.child("mask"),
    )
    .expect("precompute certified mask");
    let mut use_log = InMemoryPower2RoundMaskUseLog::default();
    let consumed = mask.consume(&mut use_log).expect("consume mask");

    let r_values = [1, 4097, MlDsa65::Q - 2];
    let r = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
        &backend,
        r_values
            .iter()
            .map(|&value| {
                <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                    &backend, value,
                )
            })
            .collect(),
    );
    let mask_values =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
            &mut backend,
            consumed.value().clone(),
            label.child("test_only_open_mask_values"),
        )
        .expect("open mask values in test");

    let opened =
        open_power2round_masked_c_vec::<MlDsa65, _>(&mut backend, r, &consumed, label.clone())
            .expect("open masked c vector");
    let expected = r_values
        .iter()
        .copied()
        .zip(mask_values.iter().copied())
        .map(|(r, mask)| reduce_mod_q::<MlDsa65>(r + mask))
        .collect::<Vec<_>>();
    assert_eq!(opened, expected);
    assert!(backend
        .opened_labels()
        .iter()
        .any(|opened_label| opened_label.ends_with("masked_c_vec/open_masked_c")));
}

#[test]
fn power2round_wrap_compare_vec_matches_mask_greater_than_opened_c() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x8a; 32]);
    let label = root.child("wrap_compare_vec");
    let mut backend = LocalPrimeFieldMpcBackend::new([0x8a; 32]);
    let mask_values = [0, 1, 2, MlDsa65::Q - 1];
    let bits_by_bit = (0..23)
        .map(|bit_index| {
            BitShareVec::from_lanes(
                mask_values
                    .iter()
                    .map(|value| {
                        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(
                            &backend,
                            (((*value as u32) >> bit_index) & 1) == 1,
                        )
                    })
                    .collect(),
            )
        })
        .collect::<Vec<_>>();
    let value =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            mask_values
                .iter()
                .map(|&value| {
                    <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                        &backend, value,
                    )
                })
                .collect(),
        );
    let unchecked = UncheckedPower2RoundMaskBatch::new(&label.child("mask"), bits_by_bit, value)
        .expect("unchecked mask");
    let certified =
        certify_power2round_mask_batch::<MlDsa65, _>(&mut backend, unchecked, label.child("mask"))
            .expect("certify known mask");
    let mut use_log = InMemoryPower2RoundMaskUseLog::default();
    let consumed = certified.consume(&mut use_log).expect("consume mask");

    let c_values = [0, 0, 3, MlDsa65::Q - 2];
    let wrap = power2round_wrap_compare_vec::<MlDsa65, _>(
        &mut backend,
        &consumed,
        &c_values,
        label.clone(),
    )
    .expect("wrap comparison");
    let wrap_shares = ShareVec::from_lanes(
        wrap.lanes()
            .iter()
            .map(|bit| {
                <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::bit_to_share(
                    &backend, bit,
                )
            })
            .collect(),
    );
    let opened = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
        &mut backend,
        wrap_shares,
        label.child("test_open_wrap_bits"),
    )
    .expect("open wrap bits in test");
    assert_eq!(opened, vec![0, 1, 0, 1]);

    assert_eq!(
        power2round_wrap_compare_vec::<MlDsa65, _>(&mut backend, &consumed, &[0, 1], label.clone(),),
        Err(DkgError::Power2RoundMaskShapeMismatch)
    );
    assert_eq!(
        power2round_wrap_compare_vec::<MlDsa65, _>(
            &mut backend,
            &consumed,
            &[0, 1, 2, MlDsa65::Q],
            label,
        ),
        Err(DkgError::Power2RoundCanonicalityFailure)
    );
}

#[test]
fn power2round_recover_canonical_r_bits_vec_matches_masked_difference() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x8c; 32]);
    let label = root.child("recover_r_bits_vec");
    let mut backend = LocalPrimeFieldMpcBackend::new([0x8c; 32]);
    let mask_values = [0, 1, 2, MlDsa65::Q - 1];
    let bits_by_bit = (0..23)
        .map(|bit_index| {
            BitShareVec::from_lanes(
                mask_values
                    .iter()
                    .map(|value| {
                        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(
                            &backend,
                            (((*value as u32) >> bit_index) & 1) == 1,
                        )
                    })
                    .collect(),
            )
        })
        .collect::<Vec<_>>();
    let value =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            mask_values
                .iter()
                .map(|&value| {
                    <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                        &backend, value,
                    )
                })
                .collect(),
        );
    let unchecked = UncheckedPower2RoundMaskBatch::new(&label.child("mask"), bits_by_bit, value)
        .expect("unchecked mask");
    let certified =
        certify_power2round_mask_batch::<MlDsa65, _>(&mut backend, unchecked, label.child("mask"))
            .expect("certify known mask");
    let mut use_log = InMemoryPower2RoundMaskUseLog::default();
    let consumed = certified.consume(&mut use_log).expect("consume mask");

    let r_values = [0, MlDsa65::Q - 1, 1, 4097];
    let c_values = r_values
        .iter()
        .copied()
        .zip(mask_values.iter().copied())
        .map(|(r, mask)| reduce_mod_q::<MlDsa65>(r + mask))
        .collect::<Vec<_>>();
    let wrap = power2round_wrap_compare_vec::<MlDsa65, _>(
        &mut backend,
        &consumed,
        &c_values,
        label.clone(),
    )
    .expect("wrap comparison");
    let r_bits = power2round_recover_canonical_r_bits_vec::<MlDsa65, _>(
        &mut backend,
        &c_values,
        wrap,
        &consumed,
        label.clone(),
    )
    .expect("recover r bits");
    assert_eq!(r_bits.len(), 23);
    let recovered = linear_combination_pow2_mod_q_vec::<MlDsa65, _>(
        &mut backend,
        &r_bits,
        label.child("test_recovered_value"),
    )
    .expect("combine recovered bits");
    let opened = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
        &mut backend,
        recovered,
        label.child("test_open_recovered"),
    )
    .expect("open recovered values in test");
    assert_eq!(opened, r_values);

    let bad_wrap = BitShareVec::from_lanes(vec![
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(&backend, false),
    ]);
    assert_eq!(
        power2round_recover_canonical_r_bits_vec::<MlDsa65, _>(
            &mut backend,
            &c_values,
            bad_wrap,
            &consumed,
            label.clone(),
        ),
        Err(DkgError::Backend(
            "prime-field vector subtractor shape mismatch"
        ))
    );
    let wrap = power2round_wrap_compare_vec::<MlDsa65, _>(
        &mut backend,
        &consumed,
        &c_values,
        label.clone(),
    )
    .expect("wrap comparison");
    assert_eq!(
        power2round_recover_canonical_r_bits_vec::<MlDsa65, _>(
            &mut backend,
            &[0, 1],
            wrap,
            &consumed,
            label.clone(),
        ),
        Err(DkgError::Power2RoundMaskShapeMismatch)
    );
}

#[test]
fn power2round_canonical_r_checks_reject_bad_bits_range_and_equality() {
    fn bits_for_values(
        backend: &LocalPrimeFieldMpcBackend,
        values: &[Coeff],
    ) -> Vec<BitShareVec<PrimeFieldBitShare>> {
        (0..23)
            .map(|bit_index| {
                BitShareVec::from_lanes(
                    values
                        .iter()
                        .map(|value| {
                            <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(
                                backend,
                                (((*value as u32) >> bit_index) & 1) == 1,
                            )
                        })
                        .collect(),
                )
            })
            .collect()
    }

    fn share_values(
        backend: &LocalPrimeFieldMpcBackend,
        values: &[Coeff],
    ) -> ShareVec<PrimeFieldShare> {
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            backend,
            values
                .iter()
                .map(|&value| {
                    <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                        backend, value,
                    )
                })
                .collect(),
        )
    }

    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x8e; 32]);
    let label = root.child("canonical_r_checks");
    let mut backend = LocalPrimeFieldMpcBackend::new([0x8e; 32]);

    let values = [0, 1, MlDsa65::Q - 1];
    let bits = bits_for_values(&backend, &values);
    let value_shares = share_values(&backend, &values);
    power2round_certify_canonical_r_bits_vec::<MlDsa65, _>(
        &mut backend,
        &bits,
        value_shares,
        label.clone(),
    )
    .expect("valid canonical r bits");

    let mut bad_bit = bits_for_values(&backend, &values);
    bad_bit[0] = BitShareVec::from_lanes(vec![
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::bit_from_share_unchecked(
            &backend,
            <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                &backend, 2,
            ),
        ),
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(&backend, false),
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(&backend, true),
    ]);
    assert_eq!(
        power2round_assert_r_bits_boolean_vec::<MlDsa65, _>(&mut backend, &bad_bit, label.clone(),),
        Err(DkgError::Power2RoundCanonicalityFailure)
    );

    let ge_q_bits = bits_for_values(&backend, &[MlDsa65::Q]);
    assert_eq!(
        power2round_assert_r_lt_q_vec::<MlDsa65, _>(&mut backend, &ge_q_bits, label.clone()),
        Err(DkgError::Power2RoundCanonicalityFailure)
    );

    let equality_bits = bits_for_values(&backend, &[0, 1]);
    let wrong_equality_shares = share_values(&backend, &[1, 1]);
    assert_eq!(
        power2round_assert_r_bits_equal_t_vec::<MlDsa65, _>(
            &mut backend,
            &equality_bits,
            wrong_equality_shares,
            label,
        ),
        Err(DkgError::Power2RoundCanonicalityFailure)
    );
}

#[cfg(feature = "std")]
#[test]
fn precomputed_power2round_masks_are_consumed_only_at_decomposition() {
    let path = std::env::temp_dir().join(format!(
        "talus-power2round-precomputed-mask-use-{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x83; 32]);
    let label = root.child("precomputed_decomp");
    let mut backend = LocalPrimeFieldMpcBackend::new([0x83; 32]);
    let mask = precompute_certified_power2round_mask_batch::<MlDsa65, _>(
        &mut backend,
        3,
        label.child("mask"),
    )
    .expect("precompute certified mask");

    let mut use_log = FilePower2RoundMaskUseLog::open(&path).expect("open mask-use log");
    assert!(use_log.consumed().is_empty());
    let mask_id = mask.id();
    let r = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
        &backend,
        [0, 4097, MlDsa65::Q - 1]
            .iter()
            .map(|&value| {
                <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                    &backend, value,
                )
            })
            .collect(),
    );

    let bits = canonical_bit_decompose_mod_q_vec_with_certified_mask::<MlDsa65, _, _>(
        &mut backend,
        r,
        mask,
        &mut use_log,
        label.clone(),
    )
    .expect("decompose with precomputed mask");
    assert_eq!(bits.len(), 23);
    assert_eq!(use_log.consumed(), &[mask_id]);

    let reopened = FilePower2RoundMaskUseLog::open(&path).expect("reopen mask-use log");
    assert_eq!(reopened.consumed(), &[mask_id]);

    let reuse_mask = precompute_certified_power2round_mask_batch::<MlDsa65, _>(
        &mut backend,
        3,
        label.child("mask"),
    )
    .expect("precompute replacement with same id");
    let r = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
        &backend,
        [1, 2, 3]
            .iter()
            .map(|&value| {
                <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                    &backend, value,
                )
            })
            .collect(),
    );
    assert_eq!(
        canonical_bit_decompose_mod_q_vec_with_certified_mask::<MlDsa65, _, _>(
            &mut backend,
            r,
            reuse_mask,
            &mut use_log,
            label,
        ),
        Err(DkgError::Power2RoundMaskAlreadyConsumed)
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn precomputed_power2round_masks_reject_wrong_decomposition_label_without_consuming() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x84; 32]);
    let label = root.child("precomputed_decomp");
    let wrong_label = root.child("wrong_decomp");
    let mut backend = LocalPrimeFieldMpcBackend::new([0x84; 32]);
    let mask = precompute_certified_power2round_mask_batch::<MlDsa65, _>(
        &mut backend,
        2,
        label.child("mask"),
    )
    .expect("precompute certified mask");
    let r = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
        &backend,
        [0, 1]
            .iter()
            .map(|&value| {
                <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                    &backend, value,
                )
            })
            .collect(),
    );
    let mut use_log = InMemoryPower2RoundMaskUseLog::default();

    assert!(matches!(
        canonical_bit_decompose_mod_q_vec_with_certified_mask::<MlDsa65, _, _>(
            &mut backend,
            r,
            mask,
            &mut use_log,
            wrong_label,
        ),
        Err(DkgError::Power2RoundMaskTranscriptMismatch)
    ));
    assert!(use_log.consumed().is_empty());
}

#[test]
fn power2round_mask_certification_rejects_wrong_label_bad_bits_and_bad_value() {
    fn unchecked_mask(
        backend: &LocalPrimeFieldMpcBackend,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> UncheckedPower2RoundMaskBatch<PrimeFieldShare, PrimeFieldBitShare> {
        let bits_by_bit = (0..23)
            .map(|bit_index| {
                BitShareVec::from_lanes(
                    values
                        .iter()
                        .map(|value| {
                            <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(
                                backend,
                                (((*value as u32) >> bit_index) & 1) == 1,
                            )
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        let value = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            backend,
            values
                .iter()
                .map(|&value| {
                    <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                        backend, value,
                    )
                })
                .collect(),
        );
        UncheckedPower2RoundMaskBatch::new(label, bits_by_bit, value).expect("unchecked mask")
    }

    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x81; 32]);
    let label = root.child("mask_label");
    let wrong_label = root.child("wrong_mask_label");
    let mut backend = LocalPrimeFieldMpcBackend::new([0x81; 32]);

    let unchecked = unchecked_mask(&backend, &label, &[0, 1, 2]);
    assert!(matches!(
        certify_power2round_mask_batch::<MlDsa65, _>(&mut backend, unchecked, wrong_label),
        Err(DkgError::Power2RoundMaskTranscriptMismatch)
    ));

    let mut bad_bit_columns = (0..23)
        .map(|bit_index| {
            BitShareVec::from_lanes(
                [0, 1, 2]
                    .iter()
                    .map(|value| {
                        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(
                            &backend,
                            (((*value as u32) >> bit_index) & 1) == 1,
                        )
                    })
                    .collect(),
            )
        })
        .collect::<Vec<_>>();
    bad_bit_columns[0] = BitShareVec::from_lanes(vec![
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::bit_from_share_unchecked(
            &backend,
            <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                &backend, 2,
            ),
        ),
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(&backend, false),
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(&backend, false),
    ]);
    let bad_bit_value =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            [0, 1, 2]
                .iter()
                .map(|&value| {
                    <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                        &backend, value,
                    )
                })
                .collect(),
        );
    let bad_bit = UncheckedPower2RoundMaskBatch::new(&label, bad_bit_columns, bad_bit_value)
        .expect("bad bit mask");
    assert!(matches!(
        certify_power2round_mask_batch::<MlDsa65, _>(&mut backend, bad_bit, label.clone()),
        Err(DkgError::Power2RoundCanonicalityFailure)
    ));

    let bad_value_bits = (0..23)
        .map(|_| {
            BitShareVec::from_lanes(vec![
                <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(
                    &backend, false,
                ),
                <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(
                    &backend, false,
                ),
            ])
        })
        .collect::<Vec<_>>();
    let bad_value =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
            &backend,
            vec![
                <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                    &backend, 0,
                ),
                <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                    &backend, 1,
                ),
            ],
        );
    let bad_value =
        UncheckedPower2RoundMaskBatch::new(&label, bad_value_bits, bad_value).expect("bad value");
    assert!(matches!(
        certify_power2round_mask_batch::<MlDsa65, _>(&mut backend, bad_value, label),
        Err(DkgError::Power2RoundCanonicalityFailure)
    ));
}

#[test]
fn canonical_bit_decompose_mod_q_vec_recovers_boundary_values() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x79; 32]);
    let mut backend = LocalPrimeFieldMpcBackend::new([0x79; 32]);
    let values = vec![
        0,
        1,
        4095,
        4096,
        4097,
        8191,
        8192,
        MlDsa65::Q - 4096,
        MlDsa65::Q - 1,
    ];
    let r = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::share_vec_from_lanes(
        &backend,
        values
            .iter()
            .map(|&value| {
                <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(
                    &backend, value,
                )
            })
            .collect(),
    );
    let r_bits =
        canonical_bit_decompose_mod_q_vec::<MlDsa65, _>(&mut backend, r, root.child("decomp_vec"))
            .expect("canonical vector decomp");
    assert_eq!(r_bits.len(), 23);
    assert!(r_bits.iter().all(|bits| bits.len() == values.len()));

    let reconstructed = linear_combination_pow2_mod_q_vec::<MlDsa65, _>(
        &mut backend,
        &r_bits,
        root.child("reconstruct"),
    )
    .expect("reconstruct");
    let opened = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::open_vec_checked(
        &mut backend,
        reconstructed,
        root.child("open_reconstructed"),
    )
    .expect("open reconstructed");
    assert_eq!(opened, values);

    let s_bits = add_public_constant_bits_23_vec::<MlDsa65, _>(
        &mut backend,
        &r_bits,
        4095,
        root.child("add_4095"),
    )
    .expect("add 4095");
    let t1 = open_t1_bits_vec::<MlDsa65, _>(&mut backend, &s_bits, root.child("open_t1"))
        .expect("open t1");
    let expected = values
        .iter()
        .map(|&value| talus_core::power2round::<MlDsa65>(value).0 as u16)
        .collect::<Vec<_>>();
    assert_eq!(t1, expected);
    assert!(backend
        .opened_labels()
        .iter()
        .any(|label| label.contains("open_masked_c")));
    assert!(!backend
        .opened_labels()
        .iter()
        .any(|label| label.contains("lower") || label.contains("t0")));
}

#[test]
fn canonical_bit_decomp_rejects_noncanonical_r_plus_q_witness() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x45; 32]);
    let r = 5;
    let noncanonical = (r + MlDsa65::Q) as u32;
    assert!(noncanonical < (1 << 23));
    let mut backend = LocalPrimeFieldMpcBackend::new([0x45; 32]);
    let bits = (0..23)
        .map(|index| {
            <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::public_bit(
                &backend,
                ((noncanonical >> index) & 1) == 1,
            )
        })
        .collect::<Vec<_>>();

    let from_bits = linear_combination_pow2_mod_q::<MlDsa65, _>(
        &mut backend,
        &bits,
        root.child("noncanonical_from_bits"),
    )
    .expect("from bits");
    let r_share =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(&backend, r);
    let diff = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::sub(
        &backend, from_bits, r_share,
    );
    assert_eq!(
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::assert_zero(
            &mut backend,
            diff,
            root.child("field_equality_passes"),
        ),
        Ok(())
    );

    let lt_q = lt_public::<MlDsa65, _>(&mut backend, &bits, MlDsa65::Q as u32, root.child("lt_q"))
        .expect("lt q");
    assert_eq!(
        assert_one_bit::<MlDsa65, _>(&mut backend, &lt_q, root.child("assert_lt_q")),
        Err(DkgError::Power2RoundCanonicalityFailure)
    );
}

#[test]
fn prime_field_mpc_rejects_non_boolean_bit() {
    let config = config();
    let root = Power2RoundTranscriptLabel::root(&config, [0x46; 32]);
    let mut backend = LocalPrimeFieldMpcBackend::new([0x46; 32]);
    let bad_share =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::secret_share(&backend, 2);
    let bad_bit =
        <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa65>>::bit_from_share_unchecked(
            &backend, bad_share,
        );

    assert_eq!(
        assert_bit::<MlDsa65, _>(&mut backend, &bad_bit, root.child("bad_bit")),
        Err(DkgError::Power2RoundCanonicalityFailure)
    );
}

#[test]
fn production_it_mpc_power2round_full_vector_matches_clear_simulator() {
    fn check<P: MlDsaParams>() {
        let config = config_for::<P>();
        let material = sampled_material::<P>(&config).expect("sample material");
        let rho = [0x47; 32];

        let mut clear_backend = ClearSimPower2RoundBackend;
        let (clear_output, _) = assemble_public_output_scaffold::<P, _>(
            &config,
            rho,
            material.clone(),
            &config.parties,
            &mut clear_backend,
        )
        .expect("clear output");

        let local_backend = LocalPrimeFieldMpcBackend::new([0x47; 32]);
        let mut mpc_backend = TestItMpcPower2RoundBackend::new(local_backend);
        let (mpc_output, certificate) = assemble_public_output_scaffold::<P, _>(
            &config,
            rho,
            material,
            &config.parties,
            &mut mpc_backend,
        )
        .expect("mpc output");

        assert_eq!(mpc_output.t1, clear_output.t1);
        assert_eq!(mpc_output.public_key, clear_output.public_key);
        assert_eq!(
            certificate.power2round.backend_id,
            Power2RoundBackendId::LocalPrimeFieldSimulator
        );
        assert!(mpc_backend
            .backend()
            .opened_labels()
            .iter()
            .all(|label| label.contains("open_mask_lt_q")
                || label.contains("open_masked_c")
                || label.contains("open_t1_bits")));
        assert!(!mpc_backend
            .backend()
            .opened_labels()
            .iter()
            .any(|label| label.contains("lower") || label.contains("t0")));
    }

    check::<MlDsa44>();
    check::<MlDsa65>();
    check::<MlDsa87>();
}

#[test]
fn local_power2round_backend_uses_vectorized_circuit_path() {
    let config = config_for::<MlDsa44>();
    let material = sampled_material::<MlDsa44>(&config).expect("sample material");
    let rho = [0x7a; 32];
    let shared_t =
        assemble_shared_t::<MlDsa44>(&config, rho, &material.s1, material.s2).expect("shared t");
    let local_backend = LocalPrimeFieldMpcBackend::new([0x7a; 32]);
    let mut mpc_backend = TestItMpcPower2RoundBackend::new(local_backend);
    let (public_t1, evidence) = mpc_backend
        .power2round_t1::<MlDsa44>(&config, shared_t)
        .expect("vectorized local power2round");

    assert_eq!(public_t1.coeffs.len(), MlDsa44::K * MlDsa44::N);
    assert_eq!(
        evidence.backend_id,
        Power2RoundBackendId::LocalPrimeFieldSimulator
    );
    let counters = <LocalPrimeFieldMpcBackend as ItMpcPrimeFieldBackend<MlDsa44>>::counters(
        mpc_backend.backend(),
    )
    .expect("local counters");
    assert_eq!(counters.scalar_mul_gates, 0);
    assert_eq!(counters.scalar_openings, 0);
    assert!(counters.vector_mul_lanes > 0);
    assert!(counters.vector_opening_lanes > 0);
    assert!(mpc_backend
        .backend()
        .opened_labels()
        .iter()
        .any(|label| label.contains("open_masked_c")));
    assert!(mpc_backend
        .backend()
        .opened_labels()
        .iter()
        .any(|label| label.contains("open_t1_bits")));
    assert!(!mpc_backend
        .backend()
        .opened_labels()
        .iter()
        .any(|label| label.contains("lower") || label.contains("t0")));
}

#[test]
fn dkg_key_package_excludes_s2_t_and_t0_material() {
    let config = config();
    let material = sampled_material::<MlDsa65>(&config).expect("sample material");
    let s1_packages =
        sampled_s1_to_dkg_secret_shares::<MlDsa65>(&config, &material.s1).expect("s1");
    let mut power2round = ClearSimPower2RoundBackend;
    let (output, certificate) = assemble_public_output_scaffold::<MlDsa65, _>(
        &config,
        [0x94; 32],
        material,
        &config.parties,
        &mut power2round,
    )
    .expect("assemble public output");
    let packages = dkg_key_packages_from_public_output(&output, s1_packages, certificate)
        .expect("key packages");

    assert_eq!(packages.len(), config.parties.len());
    for package in &packages {
        assert_eq!(package.public_key, output.public_key);
        assert_eq!(package.t1.bytes, output.t1);
        assert!(!package.s1_share.s1_share.is_empty());
        let debug = format!("{package:?}");
        assert!(!debug.contains("s2_share"));
        assert!(!debug.contains("t0_share"));
        assert!(!debug.contains("SharedT"));
    }
}

#[test]
fn release_guard_rejects_clear_sim_power2round_backend() {
    assert_eq!(
        ensure_power2round_backend_allowed_for_release(
            Power2RoundBackendId::InsecureClearSimulator
        ),
        Err(DkgError::InsecurePower2RoundBackend)
    );
    assert_eq!(
        ensure_power2round_backend_allowed_for_release(
            Power2RoundBackendId::LocalPrimeFieldSimulator
        ),
        Err(DkgError::InsecurePower2RoundBackend)
    );
    assert_eq!(
        ensure_power2round_backend_allowed_for_release(
            Power2RoundBackendId::InProcessShamirSimulator
        ),
        Err(DkgError::InsecurePower2RoundBackend)
    );
    assert_eq!(
        ensure_power2round_backend_allowed_for_release(
            Power2RoundBackendId::NetworkedShamirSimulator
        ),
        Err(DkgError::InsecurePower2RoundBackend)
    );
    assert_eq!(
        ensure_power2round_backend_allowed_for_release(
            Power2RoundBackendId::TransportBackedShamirSimulator
        ),
        Err(DkgError::InsecurePower2RoundBackend)
    );
    assert_eq!(
        ensure_power2round_backend_allowed_for_release(
            Power2RoundBackendId::RuntimeCoordinatedTransportShamirSimulator
        ),
        Err(DkgError::InsecurePower2RoundBackend)
    );
    assert_eq!(
        ensure_power2round_backend_allowed_for_release(
            Power2RoundBackendId::TransportBackedPerPartyDriver
        ),
        Err(DkgError::InsecurePower2RoundBackend)
    );
    assert_eq!(
        ensure_power2round_backend_allowed_for_release(Power2RoundBackendId::ProductionItMpc),
        Ok(())
    );
}

#[test]
fn release_guard_rejects_scalarized_prime_field_mpc_counters() {
    assert_eq!(
        ensure_prime_field_mpc_counters_vectorized_for_release(PrimeFieldMpcCounters {
            scalar_mul_gates: 1,
            vector_mul_lanes: 1024,
            ..PrimeFieldMpcCounters::default()
        }),
        Err(DkgError::PrimeFieldMpcScalarizedReleaseBlocked)
    );
    assert_eq!(
        ensure_prime_field_mpc_counters_vectorized_for_release(PrimeFieldMpcCounters::default()),
        Err(DkgError::PrimeFieldMpcScalarizedReleaseBlocked)
    );
    assert_eq!(
        ensure_prime_field_mpc_counters_vectorized_for_release(PrimeFieldMpcCounters {
            vector_mul_lanes: 1024,
            vector_opening_lanes: 1024,
            vector_assert_zero_lanes: 1024,
            local_public_mul_lanes: 1024,
            ..PrimeFieldMpcCounters::default()
        }),
        Ok(())
    );
}

#[test]
fn release_guard_rejects_scalar_prime_field_wire_logs() {
    fn mpc_record(values: Vec<Coeff>) -> PrimeFieldMpcWireMessageRecord {
        let payload = talus_wire::DkgPrimeFieldMpcPayload {
            round_kind: 1,
            phase: 1,
            receiver_party_id: 0,
            label_hash: [0x52; 32],
            value: 7,
            values,
        };
        PrimeFieldMpcWireMessageRecord {
            direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
            peer: None,
            message: WireMessage {
                header: WireHeader {
                    protocol_version: WIRE_PROTOCOL_VERSION,
                    suite: wire_suite(DkgSuite::MlDsa65),
                    round: RoundId::DkgPrimeFieldMpc,
                    sender_party_id: 1,
                    keygen_transcript_hash: [0x53; 32],
                    session_id: [0x54; 32],
                    signing_set_hash: [0x55; 32],
                    payload_kind: PayloadKind::DkgPrimeFieldMpc,
                },
                payload: encode_dkg_prime_field_mpc_payload(&payload),
            },
        }
    }

    let mut vector_log = InMemoryPrimeFieldMpcWireMessageLog::default();
    vector_log
        .persist_wire_message(&mpc_record(vec![1, 2, 3]))
        .expect("persist vector");
    assert_eq!(
        ensure_prime_field_mpc_wire_log_vectorized_for_release(&vector_log),
        Ok(())
    );

    let mut scalar_log = InMemoryPrimeFieldMpcWireMessageLog::default();
    scalar_log
        .persist_wire_message(&mpc_record(Vec::new()))
        .expect("persist scalar");
    assert_eq!(
        ensure_prime_field_mpc_wire_log_vectorized_for_release(&scalar_log),
        Err(DkgError::PrimeFieldMpcScalarizedReleaseBlocked)
    );
}

fn test_power2round_evidence(backend_id: Power2RoundBackendId) -> Power2RoundEvidence {
    Power2RoundEvidence {
        backend_id,
        epoch: KeygenEpoch(7),
        suite: DkgSuite::MlDsa65,
        party_set_hash: [0x11; 32],
        rho_hash: [0x12; 32],
        output_t1_hash: [0x13; 32],
        transcript_hash: [0x14; 32],
    }
}

fn test_setup_certificate(
    setup_backend_id: DkgSetupBackendId,
    release_blockers: Vec<DkgReleaseBlocker>,
) -> DkgSetupTranscriptCertificate {
    DkgSetupTranscriptCertificate {
        setup_backend_id,
        sampler_s1_hash: [0x21; 32],
        sampler_s2_hash: [0x22; 32],
        vss_commit_hash: [0x23; 32],
        vss_share_hash: [0x24; 32],
        complaint_hash: [0x25; 32],
        it_vss_public_artifact_hash: [0x26; 32],
        it_vss_resolution_hash: [0x27; 32],
        it_vss_backend_id: ItVssBackendId::ProductionInformationChecking,
        complaints: Vec::new(),
        accepted_dealers: parties(&[1, 2, 3]),
        rejected_dealers: Vec::new(),
        release_blockers,
    }
}

fn production_it_vss_artifacts_for_release_test(
    config: &DkgConfig,
) -> (Vec<ItVssPublicCommitment>, ItVssComplaintResolution) {
    let public_commitments = config
        .parties
        .iter()
        .copied()
        .flat_map(|dealer| {
            [SecretVectorKind::S1, SecretVectorKind::S2]
                .into_iter()
                .map(move |vector| {
                    let label = ItVssSharingLabel::new(
                        config,
                        dealer,
                        ItVssSharingDomain::for_secret_vector(vector),
                        None,
                    )
                    .expect("vector IT-VSS label");
                    ItVssPublicCommitment {
                        backend_id: ItVssBackendId::ProductionInformationChecking,
                        dealer,
                        label_hash: label.label_hash,
                        public_metadata_hash: [dealer.0 as u8
                            + match vector {
                                SecretVectorKind::S1 => 0x10,
                                SecretVectorKind::S2 => 0x20,
                            }; 32],
                    }
                })
        })
        .collect::<Vec<_>>();
    let complaint_hash = hash_dkg_complaint_payloads(&[]);
    let certificates = public_commitments
        .iter()
        .map(|commitment| VerifiedItVssSharingCertificate {
            backend_id: ItVssBackendId::ProductionInformationChecking,
            dealer: commitment.dealer,
            label_hash: commitment.label_hash,
            accepted_receivers: config.parties.clone(),
            complaint_hash,
            transcript_hash: hash_it_vss_public_commitment(commitment),
        })
        .collect::<Vec<_>>();
    (
        public_commitments,
        ItVssComplaintResolution {
            accepted_dealers: config.parties.clone(),
            rejected_dealers: Vec::new(),
            complaints: Vec::new(),
            certificates,
        },
    )
}

fn release_test_key_packages() -> Vec<DkgKeyPackage> {
    let config = config();
    let material = sampled_material::<MlDsa65>(&config).expect("sample material");
    let s1_packages =
        sampled_s1_to_dkg_secret_shares::<MlDsa65>(&config, &material.s1).expect("s1");
    let mut power2round = ClearSimPower2RoundBackend;
    let (output, mut certificate) = assemble_public_output_scaffold::<MlDsa65, _>(
        &config,
        [0xa1; 32],
        material,
        &config.parties,
        &mut power2round,
    )
    .expect("public output");
    let public_t1 = PublicT1 {
        bytes: output.t1.clone(),
        coeffs: Vec::new(),
    };
    certificate.power2round = power2round_certify_public_t1_evidence(
        Power2RoundBackendId::ProductionItMpc,
        &config,
        PublicKeyAssemblyLabel::new(&config, output.rho),
        &public_t1,
    );
    certificate.setup = Some(test_setup_certificate(
        DkgSetupBackendId::ProductionInformationTheoretic,
        Vec::new(),
    ));
    dkg_key_packages_from_public_output(&output, s1_packages, certificate).expect("key packages")
}

fn production_ready_native_dkg_readiness() -> ProductionNativeDkgCoordinatorReadiness {
    ProductionNativeDkgCoordinatorReadiness {
        coordinator: NativeDkgCoordinatorKind::ApplicationSuppliedTransport,
        setup_backend_id: DkgSetupBackendId::ProductionInformationTheoretic,
        it_vss_backend_id: ItVssBackendId::ProductionInformationChecking,
        power2round_backend_id: Power2RoundBackendId::ProductionItMpc,
        it_vss_readiness: ProductionItVssReadiness {
            information_checking_protocol: true,
            pq_private_channels: true,
            equivocation_resistant_broadcast: true,
            complaint_resolution_policy: true,
            external_review: true,
            ..ProductionItVssReadiness::default()
        },
        it_mpc_readiness: ProductionItMpcReadiness {
            per_party_power2round: true,
            pq_authenticated_transport: true,
            durable_round_log: true,
            blame_abort_policy: true,
            external_review: true,
        },
        application_transport_contract: true,
        reliable_broadcast_conformance: true,
        ml_kem_private_channels: true,
        ml_dsa_operational_identities: true,
        durable_restart_policy: true,
        no_scaffold_backends: true,
        external_review: true,
    }
}

fn native_dkg_transport_evidence_for_config(config: &DkgConfig) -> NativeDkgTransportEvidence {
    let party_ids = config
        .parties
        .iter()
        .map(|party| party.0)
        .collect::<Vec<_>>();
    NativeDkgTransportEvidence::new(
        wire_suite(config.suite),
        config.transcript_hash().0,
        &party_ids,
        talus_wire::MlKemChannelSessionEvidence::new([0x41; 32]).expect("ml-kem evidence"),
        talus_wire::MlDsaOperationalIdentityEvidence::new([0x42; 32]).expect("ml-dsa evidence"),
        talus_wire::ReliableBroadcastEvidence::new([0x43; 32]).expect("broadcast evidence"),
    )
    .expect("native dkg transport evidence")
}

#[test]
fn release_guard_rejects_incomplete_dkg_certificates() {
    let missing_setup = PublicKeyAssemblyCertificate {
        power2round: test_power2round_evidence(Power2RoundBackendId::ProductionItMpc),
        setup: None,
    };
    assert_eq!(
        ensure_dkg_certificate_allowed_for_release(&missing_setup),
        Err(DkgError::MissingDkgSetupCertificate)
    );

    let scaffold_setup = PublicKeyAssemblyCertificate {
        power2round: test_power2round_evidence(Power2RoundBackendId::ProductionItMpc),
        setup: Some(test_setup_certificate(
            DkgSetupBackendId::InProcessScaffold,
            Vec::new(),
        )),
    };
    assert_eq!(
        ensure_dkg_certificate_allowed_for_release(&scaffold_setup),
        Err(DkgError::InsecureDkgSetupBackend)
    );

    let mut scaffold_it_vss_setup = test_setup_certificate(
        DkgSetupBackendId::ProductionInformationTheoretic,
        Vec::new(),
    );
    scaffold_it_vss_setup.it_vss_backend_id = ItVssBackendId::InProcessHashBindingScaffold;
    let scaffold_it_vss = PublicKeyAssemblyCertificate {
        power2round: test_power2round_evidence(Power2RoundBackendId::ProductionItMpc),
        setup: Some(scaffold_it_vss_setup),
    };
    assert_eq!(
        ensure_dkg_certificate_allowed_for_release(&scaffold_it_vss),
        Err(DkgError::ItVssCertificateBackendMismatch)
    );

    let blocked_setup = PublicKeyAssemblyCertificate {
        power2round: test_power2round_evidence(Power2RoundBackendId::ProductionItMpc),
        setup: Some(test_setup_certificate(
            DkgSetupBackendId::ProductionInformationTheoretic,
            vec![DkgReleaseBlocker::ExternalReview],
        )),
    };
    assert_eq!(
        ensure_dkg_certificate_allowed_for_release(&blocked_setup),
        Err(DkgError::DkgCertificateReleaseBlockers)
    );

    let simulator_power2round = PublicKeyAssemblyCertificate {
        power2round: test_power2round_evidence(Power2RoundBackendId::InsecureClearSimulator),
        setup: Some(test_setup_certificate(
            DkgSetupBackendId::ProductionInformationTheoretic,
            Vec::new(),
        )),
    };
    assert_eq!(
        ensure_dkg_certificate_allowed_for_release(&simulator_power2round),
        Err(DkgError::InsecurePower2RoundBackend)
    );

    let production = PublicKeyAssemblyCertificate {
        power2round: test_power2round_evidence(Power2RoundBackendId::ProductionItMpc),
        setup: Some(test_setup_certificate(
            DkgSetupBackendId::ProductionInformationTheoretic,
            Vec::new(),
        )),
    };
    assert_eq!(
        ensure_dkg_certificate_allowed_for_release(&production),
        Ok(())
    );
}

#[test]
fn production_assembly_api_is_typed_and_scaffold_api_is_gated() {
    let source = include_str!("lib.rs");
    let scalar_vss_source = include_str!("scalar_vss.rs");
    let power2round_source = include_str!("power2round.rs");
    let power2round_dev_source = include_str!("power2round/dev_backends.rs");
    let production_start = source
        .find("pub fn assemble_logged_native_dkg_production_from_logs<P, T, L>(")
        .expect("production assembly function");
    let production_end = source[production_start..]
        .find(") -> Result<ProductionNativeDkgAssemblyOutput, DkgError>")
        .expect("production assembly signature end")
        + production_start;
    let production_signature = &source[production_start..production_end];
    assert!(production_signature.contains("power2round_output: ProductionPower2RoundOutput"));
    assert!(!production_signature.contains("MpcPower2RoundBackend"));
    assert!(source.contains("pub trait DistributedSmallSampler {"));
    let sampler_trait_start = source
        .find("pub trait DistributedSmallSampler {")
        .expect("sampler trait");
    let sampler_trait_end = source[sampler_trait_start..]
        .find("/// Test/scaffold extension for sampling directly from raw residue broadcasts.")
        .expect("sampler extension marker")
        + sampler_trait_start;
    let sampler_trait = &source[sampler_trait_start..sampler_trait_end];
    assert!(sampler_trait.contains("sample_verified_small_coeff"));
    assert!(sampler_trait.contains("sample_verified_small_polyvec"));
    assert!(!sampler_trait.contains("sample_small_coeff"));
    assert!(!sampler_trait.contains("sample_small_polyvec"));
    assert!(source.contains(
        "#[cfg(any(test, feature = \"scaffold-dev\"))]\npub trait DistributedSmallSamplerScaffoldExt"
    ));
    assert!(source.contains(
        "#[cfg(any(test, feature = \"scaffold-dev\"))]\npub type InProcessDistributedSmallSampler = VerifiedDistributedSmallSampler;"
    ));

    assert!(source.contains(
        "#[cfg(any(test, feature = \"scaffold-dev\"))]\n#[doc(hidden)]\npub fn assemble_public_output_scaffold"
    ));
    assert!(source.contains(
        "#[cfg(any(test, feature = \"scaffold-dev\"))]\n#[doc(hidden)]\npub fn assemble_logged_native_dkg_scaffold_from_logs"
    ));
    assert!(source.contains(
        "#[cfg(any(test, feature = \"scaffold-dev\"))]\n#[doc(hidden)]\npub fn assemble_logged_native_dkg_with_production_it_vss_from_logs"
    ));
    assert!(source.contains(
        "#[cfg(test)]\n#[derive(Clone, Debug, Eq, PartialEq)]\n#[doc(hidden)]\npub struct ScaffoldItVssCertifiedSmallResidueInputs"
    ));
    assert!(source.contains(
        "#[cfg(any(test, feature = \"scaffold-dev\"))]\n#[derive(Clone, Debug, Eq, PartialEq)]\n#[doc(hidden)]\npub struct NativeDkgAssemblyScaffoldOutput"
    ));
    assert!(source.contains(
        "#[cfg(any(test, feature = \"scaffold-dev\"))]\npub fn ensure_native_dkg_assembly_output_allowed_for_release"
    ));
    assert!(source
        .contains("#[cfg(any(test, feature = \"scaffold-dev\"))]\npub fn sum_small_residues_mod"));
    assert!(scalar_vss_source.contains(
        "#[cfg(any(test, feature = \"scaffold-dev\"))]\n#[derive(Clone, Debug, Eq, PartialEq)]\npub struct InProcessScalarItVssBackend"
    ));
    assert!(scalar_vss_source.contains(
        "#[cfg(any(test, feature = \"scaffold-dev\"))]\n#[derive(Clone, Debug, Eq, PartialEq)]\npub struct InProcessScalarVssPublicCheck"
    ));
    assert!(scalar_vss_source.contains(
        "#[cfg(any(test, feature = \"scaffold-dev\"))]\npub fn verify_in_process_scalar_vss_share"
    ));
    assert!(source.contains(
        "#[derive(Clone, Debug, Eq, PartialEq)]\npub struct ProductionNativeDkgAssemblyOutput"
    ));
    assert!(power2round_source.contains(
        "#[cfg(any(test, feature = \"scaffold-dev\"))]\n#[doc(hidden)]\npub mod dev_backends;"
    ));
    assert!(!power2round_source
        .contains("pub struct RuntimeCoordinatedTransportShamirPrimeFieldMpcBackend"));
    for backend in [
        "LocalPrimeFieldMpcBackend",
        "InProcessShamirPrimeFieldMpcBackend",
        "NetworkedShamirPrimeFieldMpcBackend",
        "ClearSimPower2RoundBackend",
        "TestItMpcPower2RoundBackend",
        "TransportBackedPower2RoundBackend",
        "TransportBackedShamirPrimeFieldMpcBackend",
        "TransportEvidenceShamirPower2RoundTestHarness",
    ] {
        let needle = format!("#[doc(hidden)]\npub struct {backend}");
        assert!(
            power2round_dev_source.contains(&needle),
            "missing hidden dev backend marker for {backend}"
        );
    }
}

#[test]
fn release_guard_checks_dkg_key_package_sets() {
    let packages = release_test_key_packages();
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&packages),
        Ok(config())
    );
    assert_eq!(
        ensure_dkg_key_package_allowed_for_release(&packages[0]),
        Ok(())
    );

    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&[]),
        Err(DkgError::MissingRoundMessages {
            round: DkgRound::Finalize,
            expected: 1,
            got: 0,
        })
    );

    let mut missing_setup = packages.clone();
    missing_setup[0].certificate.setup = None;
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&missing_setup),
        Err(DkgError::MissingDkgSetupCertificate)
    );

    let mut simulator_power2round = packages.clone();
    simulator_power2round[0].certificate.power2round.backend_id =
        Power2RoundBackendId::InsecureClearSimulator;
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&simulator_power2round),
        Err(DkgError::InsecurePower2RoundBackend)
    );

    let mut scaffold_setup = packages.clone();
    scaffold_setup[0]
        .certificate
        .setup
        .as_mut()
        .expect("setup")
        .setup_backend_id = DkgSetupBackendId::InProcessScaffold;
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&scaffold_setup),
        Err(DkgError::InsecureDkgSetupBackend)
    );

    let mut blocked_setup = packages.clone();
    blocked_setup[0]
        .certificate
        .setup
        .as_mut()
        .expect("setup")
        .release_blockers
        .push(DkgReleaseBlocker::ExternalReview);
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&blocked_setup),
        Err(DkgError::DkgCertificateReleaseBlockers)
    );

    let mut public_material_mismatch = packages.clone();
    public_material_mismatch[0].public_key[0] ^= 1;
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&public_material_mismatch),
        Err(DkgError::DkgKeyPackagePublicMaterialMismatch)
    );

    let mut evidence_mismatch = packages.clone();
    evidence_mismatch[0].certificate.power2round.output_t1_hash[0] ^= 1;
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&evidence_mismatch),
        Err(DkgError::Power2RoundEvidenceRequired)
    );

    let mut public_material_disagreement = packages.clone();
    public_material_disagreement[1].rho[0] ^= 1;
    public_material_disagreement[1].public_key[0] ^= 1;
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&public_material_disagreement),
        Err(DkgError::Power2RoundEvidenceRequired)
    );

    let mut certificate_disagreement = packages.clone();
    certificate_disagreement[1]
        .certificate
        .power2round
        .transcript_hash[0] ^= 1;
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&certificate_disagreement),
        Err(DkgError::Power2RoundEvidenceRequired)
    );

    let mut setup_certificate_disagreement = packages.clone();
    setup_certificate_disagreement[1]
        .certificate
        .setup
        .as_mut()
        .expect("setup")
        .complaint_hash[0] ^= 1;
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&setup_certificate_disagreement),
        Err(DkgError::DkgKeyPackageCertificateDisagreement)
    );
}

#[test]
fn native_dkg_release_context_gate_composes_packages_logs_cursors_and_transport() {
    let config = config();
    let (public_commitments, resolution) = production_it_vss_artifacts_for_release_test(&config);
    let public_hash = hash_it_vss_public_artifacts(&public_commitments);
    let resolution_hash = hash_it_vss_complaint_resolution(&resolution);

    let mut packages = release_test_key_packages();
    for package in &mut packages {
        let setup = package.certificate.setup.as_mut().expect("setup");
        setup.it_vss_public_artifact_hash = public_hash;
        setup.it_vss_resolution_hash = resolution_hash;
    }

    let mut runtime = test_logged_dkg_transport_runtimes(&config)
        .into_iter()
        .next()
        .expect("runtime");
    runtime
        .persist_it_vss_artifacts_logged(&public_commitments, &resolution)
        .expect("persist release artifacts");

    let mut cursors = InMemoryDkgSetupPhaseCursorLog::default();
    cursors
        .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
            phase: DkgTransportPhase::ItVssArtifact,
            state: DkgSetupPhaseCursorState::Collected,
            receiver: None,
            vector: None,
            coefficient_index: None,
            it_vss_phase: Some(ProductionItVssComplaintPhase::CertifyAcceptedSharings),
            expected: config.parties.len(),
            got: config.parties.len(),
        })
        .expect("persist complete cursor");

    let readiness = production_ready_native_dkg_readiness();
    let transport_evidence = native_dkg_transport_evidence_for_config(&config);
    assert_eq!(
        ensure_native_dkg_transport_evidence_matches_config(&config, &transport_evidence),
        Ok(())
    );
    assert_eq!(
        ensure_native_dkg_release_context_allowed_for_release(
            &packages,
            runtime.wire_log(),
            &cursors,
            readiness,
            &transport_evidence,
        ),
        Ok(config.clone())
    );

    let typed_output = ProductionNativeDkgAssemblyOutput {
        public: DkgPublicOutput {
            config: config.clone(),
            keygen_transcript_hash: KeygenTranscriptHash([0u8; 32]),
            public_key: packages[0].public_key.clone(),
            rho: packages[0].rho,
            t1: packages[0].t1.bytes.clone(),
            vss_commitments: vec![VssCommitment { bytes: vec![1] }],
            as1_commitments: config
                .parties
                .iter()
                .map(|&party| As1Commitment {
                    party,
                    bytes: vec![party.0 as u8],
                })
                .collect(),
            pairwise_seed_commitments: config
                .parties
                .iter()
                .map(|&party| PairwiseSeedCommitment {
                    party,
                    commitment: [party.0 as u8; 32],
                })
                .collect(),
        },
        key_packages: packages.clone(),
        certificate: packages[0].certificate.clone(),
        accepted_dealers: config.parties.clone(),
        rejected_dealers: Vec::new(),
        complaints: Vec::new(),
    };
    assert_eq!(
        typed_output.ensure_context_allowed_for_release(
            runtime.wire_log(),
            &cursors,
            readiness,
            &transport_evidence,
        ),
        Ok(config.clone())
    );

    assert_eq!(
        ensure_native_dkg_release_context_allowed_for_release(
            &packages,
            runtime.wire_log(),
            &InMemoryDkgSetupPhaseCursorLog::default(),
            readiness,
            &transport_evidence,
        ),
        Err(DkgError::DkgSetupIncompleteAfterRestart)
    );

    let wrong_transport_evidence = NativeDkgTransportEvidence::new(
        wire_suite(config.suite),
        [0xee; 32],
        &config
            .parties
            .iter()
            .map(|party| party.0)
            .collect::<Vec<_>>(),
        talus_wire::MlKemChannelSessionEvidence::new([0x41; 32]).expect("ml-kem evidence"),
        talus_wire::MlDsaOperationalIdentityEvidence::new([0x42; 32]).expect("ml-dsa evidence"),
        talus_wire::ReliableBroadcastEvidence::new([0x43; 32]).expect("broadcast evidence"),
    )
    .expect("wrong native dkg transport evidence");
    assert_eq!(
        ensure_native_dkg_release_context_allowed_for_release(
            &packages,
            runtime.wire_log(),
            &cursors,
            readiness,
            &wrong_transport_evidence,
        ),
        Err(DkgError::PrimeFieldMpcContextMismatch)
    );

    assert_eq!(
        ensure_native_dkg_release_context_allowed_for_release(
            &packages,
            runtime.wire_log(),
            &cursors,
            ProductionNativeDkgCoordinatorReadiness {
                no_scaffold_backends: false,
                ..readiness
            },
            &transport_evidence,
        ),
        Err(DkgError::BlockedPendingReview)
    );

    let mut private_log_runtime = test_logged_dkg_transport_runtimes(&config)
        .into_iter()
        .next()
        .expect("runtime");
    private_log_runtime
        .send_vss_share_logged(
            PartyId(2),
            &DkgSharePayload {
                dealer: PartyId(1),
                receiver: PartyId(2),
                encrypted_share: IT_VSS_PRIVATE_DELIVERY_MAGIC.to_vec(),
                encrypted_seed_share: Vec::new(),
                proof: Vec::new(),
            },
        )
        .expect("persist private setup payload");
    assert_eq!(
        ensure_native_dkg_release_context_allowed_for_release(
            &packages,
            private_log_runtime.wire_log(),
            &cursors,
            readiness,
            &transport_evidence,
        ),
        Err(DkgError::DkgReleaseArtifactContainsPrivateSetupPayload)
    );
}

#[cfg(feature = "production-release-checks")]
#[test]
fn production_release_checks_feature_exercises_dkg_release_gates() {
    let clean = release_test_key_packages();
    ensure_dkg_key_package_set_allowed_for_release(&clean).expect("clean package set");

    let mut scaffold_setup = clean.clone();
    scaffold_setup[0]
        .certificate
        .setup
        .as_mut()
        .expect("setup")
        .setup_backend_id = DkgSetupBackendId::InProcessScaffold;
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&scaffold_setup),
        Err(DkgError::InsecureDkgSetupBackend)
    );

    let mut simulator = clean.clone();
    simulator[0].certificate.power2round.backend_id = Power2RoundBackendId::InsecureClearSimulator;
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&simulator),
        Err(DkgError::InsecurePower2RoundBackend)
    );

    let mut missing_setup = clean.clone();
    missing_setup[0].certificate.setup = None;
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&missing_setup),
        Err(DkgError::MissingDkgSetupCertificate)
    );

    let mut blocked = clean.clone();
    blocked[0]
        .certificate
        .setup
        .as_mut()
        .expect("setup")
        .release_blockers
        .push(DkgReleaseBlocker::ExternalReview);
    assert_eq!(
        ensure_dkg_key_package_set_allowed_for_release(&blocked),
        Err(DkgError::DkgCertificateReleaseBlockers)
    );
}

#[test]
fn production_it_vss_boundary_is_transcript_bound_redacted_and_complaint_checked() {
    let config = config();
    let s1_label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        Some(7),
    )
    .expect("s1 label");
    let s2_label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S2),
        Some(7),
    )
    .expect("s2 label");
    let other_dealer_label = ItVssSharingLabel::new(
        &config,
        PartyId(2),
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        Some(7),
    )
    .expect("other dealer label");
    assert_ne!(s1_label.label_hash, s2_label.label_hash);
    assert_ne!(s1_label.label_hash, other_dealer_label.label_hash);
    assert_eq!(
        ItVssSharingLabel::new(
            &config,
            PartyId(9),
            ItVssSharingDomain::SmallResidue,
            Some(0),
        ),
        Err(DkgError::UnknownParty(PartyId(9)))
    );

    let tag = ItVssInformationTag {
        tagger: PartyId(1),
        verifier: PartyId(2),
        label_hash: s1_label.label_hash,
        tag: vec![7, 7, 7],
    };
    let delivery = ItVssPrivateShareDelivery {
        dealer: PartyId(1),
        receiver: PartyId(2),
        label_hash: s1_label.label_hash,
        share: vec![8, 8, 8],
        information_tags: vec![tag.clone()],
    };
    assert!(!format!("{tag:?}").contains("7, 7, 7"));
    assert!(!format!("{delivery:?}").contains("8, 8, 8"));

    let mut backend = TestInformationCheckingVssBackend;
    let outputs = config
        .parties
        .iter()
        .map(|&dealer| {
            let label = ItVssSharingLabel::new(
                &config,
                dealer,
                ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
                Some(7),
            )
            .expect("dealer label");
            backend
                .share_secret::<MlDsa65>(&config, label, &[dealer.0 as u8, 2, 3])
                .expect("production IT-VSS private delivery output")
        })
        .collect::<Vec<_>>();
    let public_commitments = outputs
        .iter()
        .map(|output| output.public_commitment.clone())
        .collect::<Vec<_>>();
    let output = outputs
        .iter()
        .find(|output| output.public_commitment.dealer == PartyId(1))
        .expect("dealer 1 output");
    assert_eq!(
        output.public_commitment.backend_id,
        ItVssBackendId::ProductionInformationChecking
    );
    assert_eq!(output.public_commitment.dealer, PartyId(1));
    assert_eq!(output.public_commitment.label_hash, s1_label.label_hash);
    assert_eq!(output.deliveries.len(), config.parties.len());
    for delivery in &output.deliveries {
        backend
            .verify_private_delivery::<MlDsa65>(&config, &output.public_commitment, delivery)
            .expect("production delivery verifies");
    }

    let mut tampered = output.deliveries[1].clone();
    tampered.share[0] ^= 0x80;
    assert_eq!(
        backend.verify_private_delivery::<MlDsa65>(&config, &output.public_commitment, &tampered,),
        Err(DkgError::ComplaintEvidenceMismatch)
    );
    let complaint = backend
        .complaint_for_invalid_delivery::<MlDsa65>(&config, &output.public_commitment, &tampered)
        .expect("complaint");
    assert_eq!(complaint.dealer, PartyId(1));
    assert_eq!(complaint.receiver, tampered.receiver);
    assert!(!format!("{complaint:?}").contains("128"));

    let resolution = backend
        .resolve_complaints::<MlDsa65>(&config, &public_commitments, &[complaint])
        .expect("resolution");
    assert_eq!(resolution.rejected_dealers, vec![PartyId(1)]);
    assert!(!resolution.accepted_dealers.contains(&PartyId(1)));
    assert_eq!(resolution.certificates.len(), config.parties.len() - 1);

    let clean_resolution = backend
        .resolve_complaints::<MlDsa65>(&config, &public_commitments, &[])
        .expect("clean resolution");
    assert!(clean_resolution.rejected_dealers.is_empty());
    assert!(clean_resolution.accepted_dealers.contains(&PartyId(1)));
    assert_eq!(clean_resolution.certificates.len(), config.parties.len());
    assert_eq!(
        clean_resolution.certificates[0].backend_id,
        ItVssBackendId::ProductionInformationChecking
    );
}

#[test]
fn batched_vector_it_vss_boundary_rejects_scalar_and_nonvector_shapes() {
    let config = config();
    let dealer = PartyId(1);
    let s1_vector = ItVssSharingLabel::new(
        &config,
        dealer,
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        None,
    )
    .expect("s1 vector label");
    let s2_vector = ItVssSharingLabel::new(
        &config,
        dealer,
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S2),
        None,
    )
    .expect("s2 vector label");
    let scalar = ItVssSharingLabel::new(
        &config,
        dealer,
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        Some(0),
    )
    .expect("scalar label");
    let aux = ItVssSharingLabel::new(&config, dealer, ItVssSharingDomain::PrimeFieldMpcAux, None)
        .expect("aux label");

    assert_eq!(ensure_it_vss_batched_vector_label(s1_vector), Ok(()));
    assert_eq!(
        ensure_it_vss_batched_vector_label(scalar),
        Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked)
    );
    assert_eq!(
        ensure_it_vss_batched_vector_label(aux),
        Err(DkgError::ItVssCertificateLabelMismatch)
    );

    let mut backend = DeterministicItVssTestBackend::new([0x61; 32]);
    let batch = it_vss_share_batched_vector_secrets::<MlDsa65, _>(
        &mut backend,
        &config,
        dealer,
        &[
            ItVssBatchedSecret {
                label: s1_vector,
                secret: b"s1-vector".to_vec(),
            },
            ItVssBatchedSecret {
                label: s2_vector,
                secret: b"s2-vector".to_vec(),
            },
        ],
    )
    .expect("batched vector share");
    assert_eq!(batch.public_commitments.len(), 2);
    assert_eq!(batch.deliveries.len(), 2 * config.parties.len());
    assert!(batch
        .public_commitments
        .iter()
        .all(
            |commitment| commitment.backend_id == ItVssBackendId::InProcessHashBindingScaffold
                && commitment.dealer == dealer
        ));
    assert!(batch.deliveries.iter().all(|delivery| {
        delivery.dealer == dealer
            && config.parties.contains(&delivery.receiver)
            && (delivery.label_hash == s1_vector.label_hash
                || delivery.label_hash == s2_vector.label_hash)
    }));

    assert_eq!(
        it_vss_share_batched_vector_secrets::<MlDsa65, _>(
            &mut backend,
            &config,
            dealer,
            &[ItVssBatchedSecret {
                label: scalar,
                secret: b"scalar".to_vec(),
            }],
        ),
        Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked)
    );
    assert_eq!(
        it_vss_share_batched_vector_secrets::<MlDsa65, _>(
            &mut backend,
            &config,
            dealer,
            &[
                ItVssBatchedSecret {
                    label: s1_vector,
                    secret: b"one".to_vec(),
                },
                ItVssBatchedSecret {
                    label: s1_vector,
                    secret: b"duplicate".to_vec(),
                }
            ],
        ),
        Err(DkgError::DuplicateItVssPublicCommitment {
            dealer,
            label_hash: s1_vector.label_hash,
        })
    );

    let wrong_dealer = ItVssSharingLabel::new(
        &config,
        PartyId(2),
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        None,
    )
    .expect("wrong dealer label");
    assert_eq!(
        it_vss_share_batched_vector_secrets::<MlDsa65, _>(
            &mut backend,
            &config,
            dealer,
            &[ItVssBatchedSecret {
                label: wrong_dealer,
                secret: b"wrong dealer".to_vec(),
            }],
        ),
        Err(DkgError::PartyMismatch {
            expected: dealer,
            got: PartyId(2),
        })
    );
}

fn test_production_it_vss_public_coin_transcript(
    config: &DkgConfig,
    label_hash: [u8; 32],
    seed: u8,
) -> ProductionItVssPublicCoinTranscript {
    let shares = config
        .parties
        .iter()
        .map(|&party| {
            let mut coin = [seed; 32];
            coin[0] = party.0 as u8;
            coin[1..3].copy_from_slice(&party.0.to_le_bytes());
            production_it_vss_public_coin_share(config, label_hash, party, coin)
                .expect("public coin share")
        })
        .collect::<Vec<_>>();
    production_it_vss_public_coin_transcript(config, label_hash, &shares)
        .expect("public coin transcript")
}

#[test]
fn production_it_vss_public_coin_artifact_roundtrips_and_is_required() {
    let config = config_for::<MlDsa44>();
    let dealer = PartyId(1);
    let label = ItVssSharingLabel::new(
        &config,
        dealer,
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        None,
    )
    .expect("label");
    let share = production_it_vss_public_coin_share(&config, label.label_hash, dealer, [0x44; 32])
        .expect("coin share");
    let encoded = encode_it_vss_public_coin_share_artifact(&share);
    assert_eq!(
        decode_it_vss_public_coin_share_artifact(&encoded).expect("decode coin share"),
        share
    );

    let mut backend = ProductionInformationCheckingVssBackend::with_params(
        [0x45; 32],
        ProductionItVssSecurityParams {
            audit_tags: 1,
            retained_tags: 1,
            consistency_rounds: 1,
            ..ProductionItVssSecurityParams::default()
        },
    )
    .expect("backend");
    assert!(matches!(
        backend.share_secret::<MlDsa44>(&config, label, &[1, 2, 3]),
        Err(DkgError::Backend(
            "missing production IT-VSS public coin transcript"
        ))
    ));
}

#[test]
fn production_it_vss_precommit_public_coin_finalize_roundtrip() {
    let config = config_for::<MlDsa44>();
    let dealer = PartyId(1);
    let label = ItVssSharingLabel::new(
        &config,
        dealer,
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        None,
    )
    .expect("label");
    let params = ProductionItVssSecurityParams {
        audit_tags: 1,
        retained_tags: 1,
        consistency_rounds: 2,
        ..ProductionItVssSecurityParams::default()
    };
    let public_coin =
        test_production_it_vss_public_coin_transcript(&config, label.label_hash, 0x61);
    let secret = vec![9, 8, 7, 6, 5, 4];

    let mut backend =
        ProductionInformationCheckingVssBackend::with_params([0x62; 32], params).expect("backend");
    let prepared = backend
        .prepare_secret::<MlDsa44>(&config, label, &secret)
        .expect("prepared");
    assert_eq!(prepared.public_precommitment.dealer, dealer);
    assert_eq!(prepared.public_precommitment.label_hash, label.label_hash);
    assert_ne!(
        prepared.public_precommitment.public_precommitment_hash,
        [0u8; 32]
    );
    let encoded = encode_it_vss_public_precommitment_artifact(&prepared.public_precommitment);
    assert_eq!(
        decode_it_vss_public_precommitment_artifact(&encoded).expect("decode precommitment"),
        prepared.public_precommitment
    );

    let output = backend
        .finalize_prepared_secret(&config, prepared.clone(), public_coin)
        .expect("finalized");
    assert_eq!(output.public_commitment.dealer, dealer);
    assert_eq!(output.public_commitment.label_hash, label.label_hash);
    assert_ne!(output.public_commitment.public_metadata_hash, [0u8; 32]);
    assert_eq!(output.deliveries.len(), config.parties.len());
    for delivery in &output.deliveries {
        backend
            .verify_private_delivery::<MlDsa44>(&config, &output.public_commitment, delivery)
            .expect("delivery verifies after finalize");
    }

    let one_shot = ProductionInformationCheckingVssBackend::with_params([0x62; 32], params)
        .expect("one-shot backend")
        .with_public_coin_transcripts(vec![test_production_it_vss_public_coin_transcript(
            &config,
            label.label_hash,
            0x61,
        )])
        .expect("install public coin");
    let mut one_shot = one_shot;
    let one_shot_output = one_shot
        .share_secret::<MlDsa44>(&config, label, &secret)
        .expect("one-shot share");
    assert_eq!(one_shot_output, output);

    let mut tampered = prepared;
    tampered.deliveries[0].share[0] ^= 0x01;
    assert_eq!(
        backend.finalize_prepared_secret(
            &config,
            tampered,
            test_production_it_vss_public_coin_transcript(&config, label.label_hash, 0x61),
        ),
        Err(DkgError::ComplaintEvidenceMismatch)
    );
}

#[test]
fn app_driver_it_vss_precommitment_phase_is_logged_and_recoverable() {
    let config = config_for::<MlDsa44>();
    let receiver_idx = 1usize;
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);
    let labels = sampler_vector_it_vss_sharing_labels(&config, &[SecretVectorKind::S1])
        .expect("sampler labels");
    let params = ProductionItVssSecurityParams {
        audit_tags: 1,
        retained_tags: 1,
        consistency_rounds: 1,
        ..ProductionItVssSecurityParams::default()
    };

    for runtime in &mut runtimes {
        let dealer = runtime.local_party();
        let label = labels
            .iter()
            .find(|label| label.dealer == dealer)
            .copied()
            .expect("dealer label");
        let mut backend =
            ProductionInformationCheckingVssBackend::with_params([dealer.0 as u8; 32], params)
                .expect("backend");
        let prepared = backend
            .prepare_secret::<MlDsa44>(&config, label, &[dealer.0 as u8, 1, 2, 3])
            .expect("prepared");
        runtime
            .drive_broadcast_it_vss_public_precommitment(&prepared.public_precommitment)
            .expect("broadcast precommitment");
        let latest = runtime
            .cursor_log()
            .latest_setup_phase_cursor()
            .expect("precommitment cursor");
        assert_eq!(
            latest.it_vss_phase,
            Some(ProductionItVssComplaintPhase::BroadcastPublicPrecommitments)
        );
    }

    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (_, precommitments) = runtimes[receiver_idx]
        .drive_collect_it_vss_public_precommitments()
        .expect("collect precommitments");
    assert_eq!(precommitments.len(), config.parties.len());
    assert!(precommitments.iter().all(|precommitment| {
        precommitment.backend_id == ItVssBackendId::ProductionInformationChecking
            && precommitment.public_precommitment_hash != [0u8; 32]
    }));
    let recovered = runtimes[receiver_idx]
        .runtime()
        .recover_it_vss_public_precommitments_from_log()
        .expect("recover precommitments");
    assert_eq!(recovered, precommitments);
}

#[test]
fn app_driver_it_vss_strict_precommit_coin_finalize_delivery_flow() {
    let config = config_for::<MlDsa44>();
    let receiver = PartyId(2);
    let receiver_idx = 1usize;
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);
    let labels = sampler_vector_it_vss_sharing_labels(&config, &[SecretVectorKind::S1])
        .expect("sampler labels");
    let params = ProductionItVssSecurityParams {
        audit_tags: 1,
        retained_tags: 1,
        consistency_rounds: 2,
        ..ProductionItVssSecurityParams::default()
    };
    let mut prepared_by_dealer = Vec::new();

    for runtime in &mut runtimes {
        let dealer = runtime.local_party();
        let label = labels
            .iter()
            .find(|label| label.dealer == dealer)
            .copied()
            .expect("dealer label");
        let mut backend =
            ProductionInformationCheckingVssBackend::with_params([dealer.0 as u8; 32], params)
                .expect("backend");
        let prepared = backend
            .prepare_secret::<MlDsa44>(
                &config,
                label,
                &[dealer.0 as u8, dealer.0 as u8 + 1, 0xaa, 0x55],
            )
            .expect("prepared");
        runtime
            .drive_broadcast_it_vss_public_precommitment(&prepared.public_precommitment)
            .expect("broadcast precommitment");
        prepared_by_dealer.push((dealer, label, prepared));
    }

    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (_, precommitments) = runtimes[receiver_idx]
        .drive_collect_it_vss_public_precommitments()
        .expect("collect precommitments");
    assert_eq!(precommitments.len(), config.parties.len());
    for (_, label, prepared) in &prepared_by_dealer {
        let precommitment = precommitments
            .iter()
            .find(|precommitment| precommitment.label_hash == label.label_hash)
            .expect("collected matching precommitment");
        assert_eq!(precommitment, &prepared.public_precommitment);
    }
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }

    let mut public_coin_transcripts = Vec::new();
    for (_, label, _) in &prepared_by_dealer {
        for runtime in &mut runtimes {
            let party = runtime.local_party();
            let mut coin = [0x72; 32];
            coin[0..2].copy_from_slice(&party.0.to_le_bytes());
            coin[2..4].copy_from_slice(&label.dealer.0.to_le_bytes());
            let share = production_it_vss_public_coin_share(&config, label.label_hash, party, coin)
                .expect("coin share");
            runtime
                .drive_broadcast_it_vss_public_coin_share(&share)
                .expect("broadcast public coin share");
        }
        route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
        let (_, transcript) = runtimes[receiver_idx]
            .drive_collect_it_vss_public_coin_transcript(&config, label.label_hash)
            .expect("collect public coin transcript");
        public_coin_transcripts.push((label.label_hash, transcript));
        for runtime in &mut runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
    }

    let finalize_backend = ProductionInformationCheckingVssBackend::with_params([0x73; 32], params)
        .expect("finalize backend");
    let mut outputs = Vec::new();
    for (dealer, label, prepared) in prepared_by_dealer {
        let transcript = public_coin_transcripts
            .iter()
            .find(|(label_hash, _)| *label_hash == label.label_hash)
            .map(|(_, transcript)| *transcript)
            .expect("transcript");
        let output = finalize_backend
            .finalize_prepared_secret(&config, prepared, transcript)
            .expect("finalize prepared secret");
        assert_eq!(output.public_commitment.dealer, dealer);
        assert_eq!(output.public_commitment.label_hash, label.label_hash);
        outputs.push(output);
    }

    for (runtime, output) in runtimes.iter_mut().zip(&outputs) {
        runtime
            .drive_broadcast_it_vss_public_commitment(&output.public_commitment)
            .expect("broadcast final commitment");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (_, public_commitments) = runtimes[receiver_idx]
        .drive_collect_it_vss_public_commitments()
        .expect("collect final commitments");
    assert_eq!(public_commitments.len(), config.parties.len());
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }

    for (runtime, output) in runtimes.iter_mut().zip(&outputs) {
        if runtime.local_party() == receiver {
            continue;
        }
        let delivery = output
            .deliveries
            .iter()
            .find(|delivery| delivery.receiver == receiver)
            .expect("receiver delivery");
        runtime
            .drive_send_it_vss_private_delivery(delivery)
            .expect("send private delivery");
    }
    route_cursored_logged_dkg_private_messages(&mut runtimes, [0usize, 2]);
    let (_, deliveries) = runtimes[receiver_idx]
        .drive_collect_it_vss_private_delivery_round(receiver)
        .expect("collect private deliveries");
    assert_eq!(deliveries.len(), config.parties.len() - 1);
    let complaints = verify_it_vss_private_deliveries_for_receiver::<MlDsa44, _>(
        &finalize_backend,
        &config,
        receiver,
        &public_commitments,
        &deliveries,
    )
    .expect("verify final private deliveries");
    assert!(complaints.is_empty());
}

#[test]
fn app_driver_public_coin_phase_feeds_production_it_vss_vector_sharing() {
    let config = config_for::<MlDsa44>();
    let receiver_idx = 1usize;
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);
    let labels = sampler_vector_it_vss_sharing_labels(&config, &[SecretVectorKind::S1])
        .expect("sampler vector labels");
    let mut transcripts = Vec::new();

    for label in &labels {
        for runtime in &mut runtimes {
            let party = runtime.local_party();
            let mut coin = [0x5c; 32];
            coin[0..2].copy_from_slice(&party.0.to_le_bytes());
            coin[2] = label.dealer.0 as u8;
            let share = production_it_vss_public_coin_share(&config, label.label_hash, party, coin)
                .expect("coin share");
            runtime
                .drive_broadcast_it_vss_public_coin_share(&share)
                .expect("broadcast public coin share");
        }
        route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
        let (_, transcript) = runtimes[receiver_idx]
            .drive_collect_it_vss_public_coin_transcript(&config, label.label_hash)
            .expect("collect public coin transcript");
        assert_eq!(transcript.label_hash, label.label_hash);
        transcripts.push(transcript);
        for runtime in &mut runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
    }

    let mut backend = ProductionInformationCheckingVssBackend::with_params(
        [0x5d; 32],
        ProductionItVssSecurityParams {
            audit_tags: 1,
            retained_tags: 1,
            consistency_rounds: 2,
            ..ProductionItVssSecurityParams::default()
        },
    )
    .expect("backend")
    .with_public_coin_transcripts(transcripts)
    .expect("install public coin transcripts");

    let s1_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S1);
    for runtime in &mut runtimes {
        let dealer = runtime.local_party();
        runtime
            .drive_share_small_residue_vector_batches_it_vss::<MlDsa44, _>(
                &mut backend,
                &config,
                &[SmallResidueVectorContributionBatch {
                    vector: SecretVectorKind::S1,
                    contributions: dealer_small_polyvec_contributions(&s1_rounds, dealer),
                }],
            )
            .expect("share production vector after public coin phase");
    }

    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (_, all_commitments) = runtimes[receiver_idx]
        .drive_collect_it_vss_public_commitments()
        .expect("collect final public metadata commitments");
    let expected_keys =
        expected_sampler_vector_it_vss_keys(&config, &[SecretVectorKind::S1]).expect("keys");
    let commitments = select_expected_it_vss_public_commitments(&all_commitments, &expected_keys)
        .expect("selected commitments");
    assert_eq!(commitments.len(), config.parties.len());
    assert!(commitments
        .iter()
        .all(|commitment| commitment.public_metadata_hash != [0u8; 32]));
}

#[test]
fn production_information_checking_vss_backend_shares_vectors_and_rejects_tampering() {
    let config = config_for::<MlDsa44>();
    let dealer = PartyId(1);
    let label = ItVssSharingLabel::new(
        &config,
        dealer,
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        None,
    )
    .expect("vector label");
    let labels = config
        .parties
        .iter()
        .map(|&party| {
            ItVssSharingLabel::new(
                &config,
                party,
                ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
                None,
            )
            .expect("dealer label")
        })
        .collect::<Vec<_>>();
    let public_coin_transcripts = labels
        .iter()
        .enumerate()
        .map(|(idx, label)| {
            test_production_it_vss_public_coin_transcript(
                &config,
                label.label_hash,
                0x90u8.wrapping_add(idx as u8),
            )
        })
        .collect::<Vec<_>>();
    let mut backend = ProductionInformationCheckingVssBackend::with_params(
        [0x31; 32],
        ProductionItVssSecurityParams {
            audit_tags: 2,
            retained_tags: 2,
            consistency_rounds: 4,
            ..ProductionItVssSecurityParams::default()
        },
    )
    .expect("backend")
    .with_public_coin_transcripts(public_coin_transcripts.clone())
    .expect("public coin transcripts");
    let secret = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let outputs = labels
        .iter()
        .map(|&label| {
            backend
                .share_secret::<MlDsa44>(&config, label, &secret)
                .expect("production vector vss share")
        })
        .collect::<Vec<_>>();
    let public_commitments = outputs
        .iter()
        .map(|output| output.public_commitment.clone())
        .collect::<Vec<_>>();
    let output = outputs
        .iter()
        .find(|output| output.public_commitment.dealer == dealer)
        .expect("dealer output");

    assert_eq!(
        output.public_commitment.backend_id,
        ItVssBackendId::ProductionInformationChecking
    );
    assert_eq!(output.public_commitment.dealer, dealer);
    assert_eq!(output.public_commitment.label_hash, label.label_hash);
    assert_eq!(output.deliveries.len(), config.parties.len());
    let audit_records =
        production_it_vss_public_audit_records_from_output(&config, output, backend.params())
            .expect("public audit records");
    assert_eq!(
        audit_records.len(),
        config.parties.len() * config.parties.len() * backend.params().audit_tags
    );
    assert!(audit_records.iter().all(|record| {
        record.dealer == dealer
            && config.parties.contains(&record.holder)
            && config.parties.contains(&record.receiver)
            && record.label_hash == label.label_hash
    }));
    let consistency_records = production_it_vss_public_consistency_records_from_output_with_coin(
        &config,
        output,
        backend.params(),
        Some(
            public_coin_transcripts
                .iter()
                .find(|transcript| transcript.label_hash == label.label_hash)
                .expect("dealer public coin transcript")
                .coin_hash,
        ),
    )
    .expect("public consistency records");
    assert_eq!(
        consistency_records.len(),
        config.parties.len() * backend.params().consistency_rounds
    );
    assert!(consistency_records.iter().all(|record| {
        record.dealer == dealer
            && config.parties.contains(&record.holder)
            && record.label_hash == label.label_hash
            && usize::from(record.round) < backend.params().consistency_rounds
            && record.challenge_bit <= 1
    }));
    let counters =
        production_it_vss_counters_from_dealer_output_with_params(output, backend.params())
            .expect("production counters");
    assert_eq!(counters.vector_sharings, 1);
    assert_eq!(counters.vector_lanes, secret.len() as u64);
    assert_eq!(
        counters.consistency_rounds,
        backend.params().consistency_rounds as u64
    );
    ensure_production_it_vss_counters_allowed_for_release(counters)
        .expect("production counters pass release gate");
    assert_eq!(
        ensure_production_it_vss_counters_allowed_for_release(ProductionItVssCounters {
            vector_sharings: 1,
            vector_lanes: secret.len() as u64,
            retained_tag_vectors: counters.retained_tag_vectors,
            retained_tag_lanes: counters.retained_tag_lanes,
            consistency_rounds: counters.consistency_rounds,
            ..ProductionItVssCounters::default()
        }),
        Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked)
    );
    for delivery in &output.deliveries {
        assert_eq!(delivery.dealer, dealer);
        assert!(config.parties.contains(&delivery.receiver));
        assert_eq!(delivery.label_hash, label.label_hash);
        assert!(!format!("{delivery:?}").contains("1, 2, 3, 4"));
        backend
            .verify_private_delivery::<MlDsa44>(&config, &output.public_commitment, delivery)
            .expect("delivery verifies");
    }

    let mut tampered = output.deliveries[0].clone();
    let last = tampered.share.last_mut().expect("share byte");
    *last ^= 1;
    assert_eq!(
        backend.verify_private_delivery::<MlDsa44>(&config, &output.public_commitment, &tampered,),
        Err(DkgError::ComplaintEvidenceMismatch)
    );
    let complaint = backend
        .complaint_for_invalid_delivery::<MlDsa44>(&config, &output.public_commitment, &tampered)
        .expect("complaint");
    assert_eq!(complaint.dealer, dealer);
    assert_eq!(complaint.receiver, tampered.receiver);
    assert!(!format!("{complaint:?}").contains("1, 2, 3, 4"));

    let mut tampered_gamma = output.deliveries[0].clone();
    let tampered_gamma_receiver = tampered_gamma.receiver;
    let gamma_tag = tampered_gamma
        .information_tags
        .iter_mut()
        .find(|tag| {
            tag.tagger == dealer
                && tag.verifier == tampered_gamma_receiver
                && tag.tag.starts_with(b"PIVST1\0\0")
                && tag.tag.get(8) == Some(&5)
        })
        .expect("consistency gamma tag");
    let gamma_last = gamma_tag.tag.last_mut().expect("gamma byte");
    *gamma_last ^= 1;
    assert_eq!(
        backend.verify_private_delivery::<MlDsa44>(
            &config,
            &output.public_commitment,
            &tampered_gamma,
        ),
        Err(DkgError::ComplaintEvidenceMismatch)
    );

    let clean_resolution = backend
        .resolve_complaints::<MlDsa44>(&config, &public_commitments, &[])
        .expect("clean resolution");
    assert_eq!(clean_resolution.rejected_dealers, Vec::<PartyId>::new());
    assert_eq!(clean_resolution.accepted_dealers, config.parties);
    assert_eq!(clean_resolution.certificates.len(), config.parties.len());
    assert_eq!(
        clean_resolution.certificates[0].backend_id,
        ItVssBackendId::ProductionInformationChecking
    );

    let scalar_label = ItVssSharingLabel::new(
        &config,
        dealer,
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        Some(0),
    )
    .expect("scalar label");
    assert_eq!(
        backend.share_secret::<MlDsa44>(&config, scalar_label, &secret),
        Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked)
    );
}

#[test]
fn small_residue_vector_batches_use_one_commitment_per_secret_vector() {
    let config = config_for::<MlDsa44>();
    let dealer = PartyId(2);
    let eta = SmallSecretEta::for_params::<MlDsa44>().expect("eta");
    let s1_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S1);
    let s2_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S2);
    let batches = [
        SmallResidueVectorContributionBatch {
            vector: SecretVectorKind::S1,
            contributions: dealer_small_polyvec_contributions(&s1_rounds, dealer),
        },
        SmallResidueVectorContributionBatch {
            vector: SecretVectorKind::S2,
            contributions: dealer_small_polyvec_contributions(&s2_rounds, dealer),
        },
    ];
    let mut backend = DeterministicItVssTestBackend::new([0x62; 32]);
    let output = it_vss_share_small_residue_vector_batches::<MlDsa44, _>(
        &mut backend,
        &config,
        eta,
        dealer,
        &batches,
    )
    .expect("share s1/s2 vector batches");
    let expected_keys = [
        ItVssSharingLabel::new(
            &config,
            dealer,
            ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
            None,
        )
        .expect("s1 label")
        .label_hash,
        ItVssSharingLabel::new(
            &config,
            dealer,
            ItVssSharingDomain::for_secret_vector(SecretVectorKind::S2),
            None,
        )
        .expect("s2 label")
        .label_hash,
    ];
    assert_eq!(output.public_commitments.len(), 2);
    assert_eq!(output.deliveries.len(), 2 * config.parties.len());
    assert!(output.public_commitments.iter().all(|commitment| {
        commitment.dealer == dealer
            && expected_keys.contains(&commitment.label_hash)
            && commitment.backend_id == ItVssBackendId::InProcessHashBindingScaffold
    }));
    assert!(output.deliveries.iter().all(|delivery| {
        delivery.dealer == dealer
            && expected_keys.contains(&delivery.label_hash)
            && config.parties.contains(&delivery.receiver)
    }));

    let mut malformed = batches.to_vec();
    malformed[0].contributions.pop();
    assert_eq!(
        it_vss_share_small_residue_vector_batches::<MlDsa44, _>(
            &mut backend,
            &config,
            eta,
            dealer,
            &malformed,
        ),
        Err(DkgError::InvalidBoundedSecretVectorLength {
            expected: SecretVectorKind::S1.coefficient_count::<MlDsa44>(),
            got: SecretVectorKind::S1.coefficient_count::<MlDsa44>() - 1,
        })
    );
}

#[test]
fn small_residue_vector_batches_use_production_information_checking_backend() {
    let config = config_for::<MlDsa44>();
    let eta = SmallSecretEta::for_params::<MlDsa44>().expect("eta");
    let s1_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S1);
    let s2_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S2);
    let dealer = PartyId(1);
    let s1_label = ItVssSharingLabel::new(
        &config,
        dealer,
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        None,
    )
    .expect("s1 label");
    let s2_label = ItVssSharingLabel::new(
        &config,
        dealer,
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S2),
        None,
    )
    .expect("s2 label");
    let public_coin_transcripts = vec![
        test_production_it_vss_public_coin_transcript(&config, s1_label.label_hash, 0xa1),
        test_production_it_vss_public_coin_transcript(&config, s2_label.label_hash, 0xa2),
    ];
    let mut backend = ProductionInformationCheckingVssBackend::with_params(
        [0x68; 32],
        ProductionItVssSecurityParams {
            audit_tags: 1,
            retained_tags: 1,
            consistency_rounds: 2,
            ..ProductionItVssSecurityParams::default()
        },
    )
    .expect("production backend")
    .with_public_coin_transcripts(public_coin_transcripts.clone())
    .expect("public coin transcripts");
    let output = it_vss_share_small_residue_vector_batches::<MlDsa44, _>(
        &mut backend,
        &config,
        eta,
        dealer,
        &[
            SmallResidueVectorContributionBatch {
                vector: SecretVectorKind::S1,
                contributions: dealer_small_polyvec_contributions(&s1_rounds, dealer),
            },
            SmallResidueVectorContributionBatch {
                vector: SecretVectorKind::S2,
                contributions: dealer_small_polyvec_contributions(&s2_rounds, dealer),
            },
        ],
    )
    .expect("production batch output");
    assert_eq!(output.public_commitments.len(), 2);
    assert_eq!(output.deliveries.len(), 2 * config.parties.len());
    assert!(output.public_commitments.iter().all(|commitment| {
        commitment.dealer == dealer
            && commitment.backend_id == ItVssBackendId::ProductionInformationChecking
    }));
    assert!(output.deliveries.iter().all(|delivery| {
        delivery.dealer == dealer
            && config.parties.contains(&delivery.receiver)
            && delivery.share.len() > SecretVectorKind::S1.coefficient_count::<MlDsa44>()
    }));
    for commitment in &output.public_commitments {
        let one_vector_output = ItVssDealerOutput {
            public_commitment: commitment.clone(),
            deliveries: output
                .deliveries
                .iter()
                .filter(|delivery| delivery.label_hash == commitment.label_hash)
                .cloned()
                .collect(),
        };
        let audit_records = production_it_vss_public_audit_records_from_output(
            &config,
            &one_vector_output,
            backend.params(),
        )
        .expect("audit records for sampler vector");
        assert_eq!(
            audit_records.len(),
            config.parties.len() * config.parties.len() * backend.params().audit_tags
        );
        let consistency_records =
            production_it_vss_public_consistency_records_from_output_with_coin(
                &config,
                &one_vector_output,
                backend.params(),
                Some(
                    public_coin_transcripts
                        .iter()
                        .find(|transcript| transcript.label_hash == commitment.label_hash)
                        .expect("sampler public coin transcript")
                        .coin_hash,
                ),
            )
            .expect("sampler consistency records");
        assert_eq!(
            consistency_records.len(),
            config.parties.len() * backend.params().consistency_rounds
        );
        ensure_production_it_vss_counters_allowed_for_release(
            production_it_vss_counters_from_dealer_output_with_params(
                &one_vector_output,
                backend.params(),
            )
            .expect("sampler vector counters"),
        )
        .expect("sampler vector counters allowed");
    }

    for &receiver in &config.parties {
        let receiver_deliveries = output
            .deliveries
            .iter()
            .filter(|delivery| delivery.receiver == receiver)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(receiver_deliveries.len(), 2);
        let complaints = verify_it_vss_private_deliveries_for_receiver::<MlDsa44, _>(
            &backend,
            &config,
            receiver,
            &output.public_commitments,
            &receiver_deliveries,
        )
        .expect("receiver verifies production deliveries");
        assert!(complaints.is_empty());
    }
}

#[test]
fn app_driver_batch_it_vss_shares_s1_s2_and_rejects_bad_dealer_batch() {
    let config = config_for::<MlDsa44>();
    let receiver = PartyId(2);
    let receiver_idx = 1usize;
    let mut backend = DeterministicItVssTestBackend::new([0x63; 32]);
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);

    let s1_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S1);
    let s2_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S2);
    for runtime in &mut runtimes {
        let dealer = runtime.local_party();
        let output = runtime
            .drive_share_small_residue_vector_batches_it_vss::<MlDsa44, _>(
                &mut backend,
                &config,
                &[
                    SmallResidueVectorContributionBatch {
                        vector: SecretVectorKind::S1,
                        contributions: dealer_small_polyvec_contributions(&s1_rounds, dealer),
                    },
                    SmallResidueVectorContributionBatch {
                        vector: SecretVectorKind::S2,
                        contributions: dealer_small_polyvec_contributions(&s2_rounds, dealer),
                    },
                ],
            )
            .expect("share s1/s2 batch");
        assert_eq!(output.public_commitments.len(), 2);
        assert_eq!(output.deliveries.len(), 2 * config.parties.len());
        let latest = runtime
            .cursor_log()
            .latest_setup_phase_cursor()
            .expect("batch cursor");
        assert_eq!(
            latest.it_vss_phase,
            Some(ProductionItVssComplaintPhase::DeliverPrivateShares)
        );
        assert_eq!(latest.expected, 2 * (config.parties.len() - 1));
        assert_eq!(latest.got, 2 * (config.parties.len() - 1));
    }

    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    let (_, all_commitments) = runtimes[receiver_idx]
        .drive_collect_it_vss_public_commitments()
        .expect("collect batch public commitments");
    let expected_keys =
        expected_sampler_vector_it_vss_keys(&config, &[SecretVectorKind::S1, SecretVectorKind::S2])
            .expect("expected batch keys");
    let selected_commitments =
        select_expected_it_vss_public_commitments(&all_commitments, &expected_keys)
            .expect("selected commitments");
    assert_eq!(selected_commitments.len(), 2 * config.parties.len());

    let bad_s1_label = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        None,
    )
    .expect("bad s1 label");
    let mut deliveries = Vec::new();
    for source_idx in [0usize, 1, 2] {
        let local_party = runtimes[source_idx].local_party().0;
        assert_eq!(
            runtimes[source_idx]
                .runtime()
                .state()
                .transport()
                .private_messages()
                .iter()
                .filter(|delivery| delivery.sender_party_id == local_party)
                .count(),
            config.parties.len() - 1
        );
        for delivery in runtimes[source_idx]
            .runtime()
            .state()
            .transport()
            .private_messages()
            .iter()
            .filter(|delivery| delivery.sender_party_id == local_party)
        {
            let mut message = delivery.message.clone();
            if delivery.sender_party_id == 1 && delivery.receiver_party_id == receiver.0 {
                let wire_payload = wire_decode_dkg_share_payload(&message.payload)
                    .expect("decode dkg share wire payload");
                let dkg_payload = DkgSharePayload {
                    dealer: PartyId(delivery.sender_party_id),
                    receiver: PartyId(wire_payload.receiver_party_id),
                    encrypted_share: wire_payload.encrypted_share,
                    encrypted_seed_share: wire_payload.encrypted_seed_share,
                    proof: wire_payload.proof,
                };
                let mut private_deliveries = it_vss_private_deliveries_from_dkg_share(&dkg_payload)
                    .expect("decode it-vss deliveries");
                if let Some(private_delivery) = private_deliveries
                    .iter_mut()
                    .find(|delivery| delivery.label_hash == bad_s1_label.label_hash)
                {
                    private_delivery.share[0] ^= 1;
                    let tampered =
                        dkg_share_payload_from_it_vss_private_delivery_batch(&private_deliveries)
                            .expect("tampered batch payload");
                    message.payload = wire_encode_dkg_share_payload(&WireDkgSharePayload {
                        receiver_party_id: tampered.receiver.0,
                        encrypted_share: tampered.encrypted_share,
                        encrypted_seed_share: tampered.encrypted_seed_share,
                        proof: tampered.proof,
                    });
                }
            }
            deliveries.push((
                delivery.sender_party_id,
                delivery.receiver_party_id,
                message,
            ));
        }
    }
    for (sender, receiver_party, message) in deliveries {
        let receiver_runtime = runtimes
            .iter_mut()
            .find(|runtime| runtime.local_party().0 == receiver_party)
            .expect("receiver runtime");
        if sender == receiver_party {
            continue;
        }
        receiver_runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .inject_private(sender, receiver_party, message)
            .expect("route private delivery");
    }

    let (_, accepted_deliveries) = runtimes[receiver_idx]
        .drive_collect_it_vss_private_delivery_round(receiver)
        .expect("collect batch private deliveries");
    assert_eq!(accepted_deliveries.len(), 2 * (config.parties.len() - 1));

    let (resolved_commitments, resolution) =
        persist_logged_small_residue_vector_batch_it_vss_artifacts_from_phase_logs::<
            MlDsa44,
            _,
            _,
            _,
        >(
            &config,
            runtimes[receiver_idx].runtime_mut(),
            &backend,
            &[SecretVectorKind::S1, SecretVectorKind::S2],
        )
        .expect("resolve batch complaints");
    assert_eq!(resolved_commitments.len(), 2 * config.parties.len());
    assert_eq!(resolution.rejected_dealers, vec![PartyId(1)]);
    assert_eq!(resolution.accepted_dealers, vec![PartyId(2), PartyId(3)]);
    assert_eq!(resolution.complaints.len(), 1);
    assert_eq!(
        resolution.certificates.len(),
        2 * resolution.accepted_dealers.len()
    );
    assert!(resolution
        .certificates
        .iter()
        .all(|certificate| certificate.dealer != PartyId(1)));
}

#[test]
fn app_driver_batch_it_vss_waits_for_distinct_senders_and_recovers_from_logs() {
    let config = config_for::<MlDsa44>();
    let receiver = PartyId(2);
    let receiver_idx = 1usize;
    let mut backend = DeterministicItVssTestBackend::new([0x64; 32]);
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);

    let s1_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S1);
    let s2_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S2);
    for runtime in &mut runtimes {
        let dealer = runtime.local_party();
        runtime
            .drive_share_small_residue_vector_batches_it_vss::<MlDsa44, _>(
                &mut backend,
                &config,
                &[
                    SmallResidueVectorContributionBatch {
                        vector: SecretVectorKind::S1,
                        contributions: dealer_small_polyvec_contributions(&s1_rounds, dealer),
                    },
                    SmallResidueVectorContributionBatch {
                        vector: SecretVectorKind::S2,
                        contributions: dealer_small_polyvec_contributions(&s2_rounds, dealer),
                    },
                ],
            )
            .expect("share s1/s2 batch");
    }

    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize]);
    let (status, commitments) = runtimes[receiver_idx]
        .drive_collect_it_vss_public_commitments()
        .expect("wait for delayed batch commitments");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::WaitingBroadcast {
            phase: DkgTransportPhase::ItVssArtifact,
            ..
        }
    ));
    assert!(commitments.is_empty());
    let mut restored_receiver = CursoredLoggedDkgTransportPartyRuntime::new(
        LoggedDkgTransportPartyRuntime::new(
            DkgTransportStateMachine::new(
                config.clone(),
                receiver,
                talus_wire::InMemoryTransport::new(2, vec![1, 2, 3]).expect("transport"),
            )
            .expect("state"),
            runtimes[receiver_idx].runtime().wire_log().clone(),
        ),
        runtimes[receiver_idx].cursor_log().clone(),
    );
    let latest = restored_receiver
        .resume()
        .expect("resume waiting batch public commitments")
        .expect("waiting batch public cursor");
    assert_eq!(latest.phase, DkgTransportPhase::ItVssArtifact);
    assert_eq!(latest.state, DkgSetupPhaseCursorState::Waiting);

    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [1usize, 2]);
    let (status, all_commitments) = runtimes[receiver_idx]
        .drive_collect_it_vss_public_commitments()
        .expect("collect delayed batch commitments");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::Collected {
            phase: DkgTransportPhase::ItVssArtifact,
            ..
        }
    ));
    let expected_keys =
        expected_sampler_vector_it_vss_keys(&config, &[SecretVectorKind::S1, SecretVectorKind::S2])
            .expect("expected batch keys");
    assert_eq!(
        select_expected_it_vss_public_commitments(&all_commitments, &expected_keys)
            .expect("selected batch commitments")
            .len(),
        2 * config.parties.len()
    );

    route_cursored_logged_dkg_private_messages(&mut runtimes, [0usize]);
    let (status, deliveries) = runtimes[receiver_idx]
        .drive_collect_it_vss_private_delivery_round(receiver)
        .expect("wait for delayed batch private deliveries");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::WaitingPrivate {
            phase: DkgTransportPhase::VssShare,
            receiver: PartyId(2),
            expected: 2,
            got: 1,
        }
    ));
    assert!(deliveries.is_empty());

    let mut restored_receiver = CursoredLoggedDkgTransportPartyRuntime::new(
        LoggedDkgTransportPartyRuntime::new(
            DkgTransportStateMachine::new(
                config.clone(),
                receiver,
                talus_wire::InMemoryTransport::new(2, vec![1, 2, 3]).expect("transport"),
            )
            .expect("state"),
            runtimes[receiver_idx].runtime().wire_log().clone(),
        ),
        runtimes[receiver_idx].cursor_log().clone(),
    );
    let latest = restored_receiver
        .resume()
        .expect("resume waiting batch private deliveries")
        .expect("waiting batch private cursor");
    assert_eq!(latest.phase, DkgTransportPhase::VssShare);
    assert_eq!(latest.state, DkgSetupPhaseCursorState::Waiting);
    assert_eq!(latest.receiver, Some(receiver));

    route_cursored_logged_dkg_private_messages(&mut runtimes, [2usize]);
    let (status, deliveries) = runtimes[receiver_idx]
        .drive_collect_it_vss_private_delivery_round(receiver)
        .expect("collect completed batch private deliveries");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::Collected {
            phase: DkgTransportPhase::VssShare,
            receiver: Some(PartyId(2)),
            ..
        }
    ));
    assert_eq!(deliveries.len(), 2 * (config.parties.len() - 1));

    let mut resolver_after_restart = LoggedDkgTransportPartyRuntime::new(
        DkgTransportStateMachine::new(
            config.clone(),
            receiver,
            talus_wire::InMemoryTransport::new(2, vec![1, 2, 3]).expect("transport"),
        )
        .expect("state"),
        runtimes[receiver_idx].runtime().wire_log().clone(),
    );
    let (public_commitments, resolution) =
        persist_logged_small_residue_vector_batch_it_vss_artifacts_from_phase_logs::<
            MlDsa44,
            _,
            _,
            _,
        >(
            &config,
            &mut resolver_after_restart,
            &backend,
            &[SecretVectorKind::S1, SecretVectorKind::S2],
        )
        .expect("resolve batch from recovered logs");
    assert_eq!(public_commitments.len(), 2 * config.parties.len());
    assert_eq!(resolution.accepted_dealers, config.parties);
    assert!(resolution.rejected_dealers.is_empty());
    assert!(resolution.complaints.is_empty());
    assert_eq!(resolution.certificates.len(), 2 * config.parties.len());
}

#[test]
fn app_driver_batch_it_vss_complaints_delay_restart_and_resolve_from_logs() {
    let config = config4_for::<MlDsa44>();
    let receiver = PartyId(2);
    let receiver_idx = config
        .parties
        .iter()
        .position(|party| *party == receiver)
        .expect("receiver index");
    let mut backend = DeterministicItVssTestBackend::new([0x65; 32]);
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);

    let s1_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S1);
    let s2_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S2);
    for runtime in &mut runtimes {
        let dealer = runtime.local_party();
        runtime
            .drive_share_small_residue_vector_batches_it_vss::<MlDsa44, _>(
                &mut backend,
                &config,
                &[
                    SmallResidueVectorContributionBatch {
                        vector: SecretVectorKind::S1,
                        contributions: dealer_small_polyvec_contributions(&s1_rounds, dealer),
                    },
                    SmallResidueVectorContributionBatch {
                        vector: SecretVectorKind::S2,
                        contributions: dealer_small_polyvec_contributions(&s2_rounds, dealer),
                    },
                ],
            )
            .expect("share s1/s2 batch");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2, 3]);
    let expected_keys =
        expected_sampler_vector_it_vss_keys(&config, &[SecretVectorKind::S1, SecretVectorKind::S2])
            .expect("expected batch keys");
    let mut public_commitments_by_receiver = Vec::new();
    for runtime in &mut runtimes {
        let (_, all_commitments) = runtime
            .drive_collect_it_vss_public_commitments()
            .expect("collect batch public commitments");
        public_commitments_by_receiver.push(
            select_expected_it_vss_public_commitments(&all_commitments, &expected_keys)
                .expect("selected commitments"),
        );
    }

    let tampered_pairs = [
        (PartyId(2), PartyId(1)),
        (PartyId(1), PartyId(2)),
        (PartyId(1), PartyId(3)),
        (PartyId(1), PartyId(4)),
    ];
    let mut routed = Vec::new();
    for source_idx in 0..runtimes.len() {
        let local_party = runtimes[source_idx].local_party();
        for delivery in runtimes[source_idx]
            .runtime()
            .state()
            .transport()
            .private_messages()
            .iter()
            .filter(|delivery| delivery.sender_party_id == local_party.0)
        {
            let dealer = PartyId(delivery.sender_party_id);
            let receiver_party = PartyId(delivery.receiver_party_id);
            let mut message = delivery.message.clone();
            if tampered_pairs.contains(&(dealer, receiver_party)) {
                message = tamper_it_vss_batch_delivery_message(
                    &config,
                    message,
                    dealer,
                    receiver_party,
                    SecretVectorKind::S1,
                );
            }
            routed.push((
                delivery.sender_party_id,
                delivery.receiver_party_id,
                message,
            ));
        }
    }
    for runtime in &mut runtimes {
        runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .clear_queued_messages();
    }
    for (sender, receiver_party, message) in routed {
        let receiver_runtime = runtimes
            .iter_mut()
            .find(|runtime| runtime.local_party().0 == receiver_party)
            .expect("receiver runtime");
        receiver_runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .inject_private(sender, receiver_party, message)
            .expect("route private delivery");
    }

    for (index, runtime) in runtimes.iter_mut().enumerate() {
        let complaints = runtime
            .drive_verify_it_vss_private_deliveries::<MlDsa44, _>(
                &backend,
                &config,
                &public_commitments_by_receiver[index],
            )
            .expect("verify and broadcast batch complaints");
        assert_eq!(complaints.len(), 1);
    }

    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize]);
    let (status, complaints) = runtimes[receiver_idx]
        .drive_collect_vss_complaint_round()
        .expect("wait for delayed complaint broadcasts");
    assert!(matches!(
        status,
        DkgTransportPhaseDriverStatus::WaitingBroadcast {
            phase: DkgTransportPhase::VssComplaint,
            ..
        }
    ));
    assert!(complaints.is_empty());
    let mut restored_receiver = CursoredLoggedDkgTransportPartyRuntime::new(
        LoggedDkgTransportPartyRuntime::new(
            DkgTransportStateMachine::new(
                config.clone(),
                receiver,
                talus_wire::InMemoryTransport::new(2, vec![1, 2, 3, 4]).expect("transport"),
            )
            .expect("state"),
            runtimes[receiver_idx].runtime().wire_log().clone(),
        ),
        runtimes[receiver_idx].cursor_log().clone(),
    );
    let latest = restored_receiver
        .resume()
        .expect("resume waiting complaint cursor")
        .expect("waiting complaint cursor");
    assert_eq!(latest.phase, DkgTransportPhase::VssComplaint);
    assert_eq!(latest.state, DkgSetupPhaseCursorState::Waiting);

    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [1usize, 2, 3]);
    let (_, complaints) = runtimes[receiver_idx]
        .drive_collect_vss_complaint_round()
        .expect("collect delayed complaint broadcasts");
    assert_eq!(complaints.len(), config.parties.len());

    let mut resolver_after_restart = LoggedDkgTransportPartyRuntime::new(
        DkgTransportStateMachine::new(
            config.clone(),
            receiver,
            talus_wire::InMemoryTransport::new(2, vec![1, 2, 3, 4]).expect("transport"),
        )
        .expect("state"),
        runtimes[receiver_idx].runtime().wire_log().clone(),
    );
    let (_, resolution) =
        persist_logged_small_residue_vector_batch_it_vss_artifacts_from_phase_logs::<
            MlDsa44,
            _,
            _,
            _,
        >(
            &config,
            &mut resolver_after_restart,
            &backend,
            &[SecretVectorKind::S1, SecretVectorKind::S2],
        )
        .expect("resolve delayed complaints from logs");
    assert_eq!(resolution.rejected_dealers, vec![PartyId(1), PartyId(2)]);
    assert_eq!(resolution.accepted_dealers, vec![PartyId(3), PartyId(4)]);
    assert_eq!(
        resolution.certificates.len(),
        2 * resolution.accepted_dealers.len()
    );
}

#[test]
fn batch_it_vss_rejects_malformed_private_batches_and_unexpected_complaints() {
    let config = config_for::<MlDsa44>();
    let dealer = PartyId(1);
    let receiver = PartyId(2);
    let mut backend = DeterministicItVssTestBackend::new([0x66; 32]);
    let s1_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S1);
    let s2_rounds = small_polyvec_contributions::<MlDsa44>(&config, SecretVectorKind::S2);
    let output = it_vss_share_small_residue_vector_batches::<MlDsa44, _>(
        &mut backend,
        &config,
        SmallSecretEta::for_params::<MlDsa44>().expect("eta"),
        dealer,
        &[
            SmallResidueVectorContributionBatch {
                vector: SecretVectorKind::S1,
                contributions: dealer_small_polyvec_contributions(&s1_rounds, dealer),
            },
            SmallResidueVectorContributionBatch {
                vector: SecretVectorKind::S2,
                contributions: dealer_small_polyvec_contributions(&s2_rounds, dealer),
            },
        ],
    )
    .expect("batch output");
    let receiver_deliveries = output
        .deliveries
        .iter()
        .filter(|delivery| delivery.receiver == receiver)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(receiver_deliveries.len(), 2);

    let mut duplicated = receiver_deliveries.clone();
    duplicated.push(receiver_deliveries[0].clone());
    assert_eq!(
        select_expected_it_vss_private_deliveries(
            &config,
            receiver,
            &duplicated,
            &expected_sampler_vector_it_vss_keys(
                &config,
                &[SecretVectorKind::S1, SecretVectorKind::S2],
            )
            .expect("expected keys"),
        ),
        Err(DkgError::DuplicateShare { dealer, receiver })
    );

    let mut wrong_receiver = receiver_deliveries.clone();
    wrong_receiver[1].receiver = PartyId(3);
    assert!(matches!(
        dkg_share_payload_from_it_vss_private_delivery_batch(&wrong_receiver),
        Err(DkgError::PartyMismatch { .. })
    ));

    let mut mixed_dealer = receiver_deliveries.clone();
    mixed_dealer[1].dealer = PartyId(3);
    assert!(matches!(
        dkg_share_payload_from_it_vss_private_delivery_batch(&mixed_dealer),
        Err(DkgError::PartyMismatch { .. })
    ));

    let mut wrong_label = receiver_deliveries.clone();
    wrong_label[0].label_hash[0] ^= 1;
    assert_eq!(
        verify_it_vss_private_deliveries_for_receiver::<MlDsa44, _>(
            &backend,
            &config,
            receiver,
            &output.public_commitments,
            &wrong_label,
        ),
        Err(DkgError::ItVssCertificateMissingCommitment {
            dealer,
            label_hash: wrong_label[0].label_hash,
        })
    );

    let outside_label = ItVssSharingLabel::new(
        &config,
        dealer,
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        Some(7),
    )
    .expect("outside scalar label");
    let outside_evidence = ItVssInformationCheckComplaintEvidence {
        dealer,
        receiver,
        tagger: receiver,
        label_hash: outside_label.label_hash,
        expected_tag_hash: [1; 32],
        received_share_hash: [2; 32],
        delivery_transcript_hash: [3; 32],
        transcript_hash: [4; 32],
    };
    let outside_complaint = DkgComplaintPayload {
        complainant: receiver,
        dealer,
        receiver,
        reason: DkgComplaintReason::InvalidVssShare,
        evidence: encode_it_vss_information_check_complaint_evidence(&outside_evidence),
    };
    let mut full_backend = DeterministicItVssTestBackend::new([0x67; 32]);
    let mut runtimes = test_cursored_logged_dkg_transport_runtimes(&config);
    for runtime in &mut runtimes {
        let dealer = runtime.local_party();
        runtime
            .drive_share_small_residue_vector_batches_it_vss::<MlDsa44, _>(
                &mut full_backend,
                &config,
                &[
                    SmallResidueVectorContributionBatch {
                        vector: SecretVectorKind::S1,
                        contributions: dealer_small_polyvec_contributions(&s1_rounds, dealer),
                    },
                    SmallResidueVectorContributionBatch {
                        vector: SecretVectorKind::S2,
                        contributions: dealer_small_polyvec_contributions(&s2_rounds, dealer),
                    },
                ],
            )
            .expect("share all dealer batches");
    }
    route_cursored_logged_dkg_broadcast_messages(&mut runtimes, [0usize, 1, 2]);
    runtimes[1]
        .drive_collect_it_vss_public_commitments()
        .expect("collect public commitments");
    route_cursored_logged_dkg_private_messages(&mut runtimes, [0usize, 1, 2]);
    runtimes[1]
        .drive_collect_it_vss_private_delivery_round(receiver)
        .expect("collect private deliveries");
    let complaint_message = runtimes[1].runtime().state().wire_message(
        DkgTransportPhase::VssComplaint,
        wire_encode_dkg_complaint_payload(&WireDkgComplaintPayload {
            dealer_party_id: outside_complaint.dealer.0,
            receiver_party_id: outside_complaint.receiver.0,
            reason_code: outside_complaint.reason.as_u8() as u16,
            evidence: outside_complaint.evidence.clone(),
        }),
    );
    let mut log = runtimes[1].runtime().wire_log().clone();
    log.persist_dkg_wire_message(&DkgWireMessageRecord {
        direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
        peer: None,
        message: complaint_message,
    })
    .expect("persist outside complaint");
    let mut resolver = LoggedDkgTransportPartyRuntime::new(
        DkgTransportStateMachine::new(
            config.clone(),
            receiver,
            talus_wire::InMemoryTransport::new(2, vec![1, 2, 3]).expect("transport"),
        )
        .expect("state"),
        log,
    );
    assert_eq!(
        resolver
            .recover_vss_complaint_round_from_log()
            .expect("recover outside complaint")
            .len(),
        1
    );
    assert_eq!(
        persist_logged_small_residue_vector_batch_it_vss_artifacts_from_phase_logs::<
            MlDsa44,
            _,
            _,
            _,
        >(
            &config,
            &mut resolver,
            &full_backend,
            &[SecretVectorKind::S1, SecretVectorKind::S2],
        ),
        Err(DkgError::ItVssCertificateMissingCommitment {
            dealer,
            label_hash: outside_label.label_hash,
        })
    );
}

#[test]
fn it_vss_hashes_bind_verified_sampler_inputs() {
    let config = config();
    let sampler_label =
        SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 3).expect("label");
    let sharing_label = ItVssSharingLabel::new(
        &config,
        PartyId(2),
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        Some(3),
    )
    .expect("sharing label");
    let public_commitment = ItVssPublicCommitment {
        backend_id: ItVssBackendId::ProductionInformationChecking,
        dealer: PartyId(2),
        label_hash: sharing_label.label_hash,
        public_metadata_hash: [0x41; 32],
    };
    let public_commitment_hash = hash_it_vss_public_commitment(&public_commitment);
    assert_ne!(public_commitment_hash, [0u8; 32]);
    let mut different_commitment = public_commitment.clone();
    different_commitment.public_metadata_hash[0] ^= 1;
    assert_ne!(
        public_commitment_hash,
        hash_it_vss_public_commitment(&different_commitment)
    );

    let certificate = VerifiedItVssSharingCertificate {
        backend_id: ItVssBackendId::ProductionInformationChecking,
        dealer: PartyId(2),
        label_hash: sharing_label.label_hash,
        accepted_receivers: parties(&[3, 1, 2]),
        complaint_hash: hash_dkg_complaint_payloads(&[]),
        transcript_hash: public_commitment_hash,
    };
    let certificate_hash = hash_verified_it_vss_sharing_certificate(&certificate);
    let mut reordered_certificate = certificate.clone();
    reordered_certificate.accepted_receivers = parties(&[1, 2, 3]);
    assert_eq!(
        certificate_hash,
        hash_verified_it_vss_sharing_certificate(&reordered_certificate)
    );

    let input = VerifiedSmallResidueInput::from_verified_it_vss_certificate(
        &config,
        sampler_label,
        SmallSecretEta::for_params::<MlDsa65>().expect("eta"),
        4,
        sharing_label,
        &certificate,
    )
    .expect("verified sampler input");
    assert_eq!(input.dealer, PartyId(2));
    assert_eq!(input.residue, 4);
    assert_eq!(
        input.verification,
        SmallResidueInputVerification::ItVssCertificate {
            label_hash: sharing_label.label_hash,
            certificate_hash,
        }
    );

    let wrong_domain_label = ItVssSharingLabel::new(
        &config,
        PartyId(2),
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S2),
        Some(3),
    )
    .expect("wrong domain label");
    let mut wrong_domain_certificate = certificate.clone();
    wrong_domain_certificate.label_hash = wrong_domain_label.label_hash;
    assert_eq!(
        VerifiedSmallResidueInput::from_verified_it_vss_certificate(
            &config,
            sampler_label,
            SmallSecretEta::for_params::<MlDsa65>().expect("eta"),
            4,
            wrong_domain_label,
            &wrong_domain_certificate,
        ),
        Err(DkgError::ItVssCertificateLabelMismatch)
    );

    let mut scaffold_certificate = certificate.clone();
    scaffold_certificate.backend_id = ItVssBackendId::InProcessHashBindingScaffold;
    assert_eq!(
        VerifiedSmallResidueInput::from_verified_it_vss_certificate(
            &config,
            sampler_label,
            SmallSecretEta::for_params::<MlDsa65>().expect("eta"),
            4,
            sharing_label,
            &scaffold_certificate,
        ),
        Err(DkgError::ItVssCertificateBackendMismatch)
    );

    let mut missing_receiver_certificate = certificate.clone();
    missing_receiver_certificate.accepted_receivers = parties(&[1, 2]);
    assert_eq!(
        VerifiedSmallResidueInput::from_verified_it_vss_certificate(
            &config,
            sampler_label,
            SmallSecretEta::for_params::<MlDsa65>().expect("eta"),
            4,
            sharing_label,
            &missing_receiver_certificate,
        ),
        Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: 3,
            got: 2,
        })
    );

    let complaints = vec![DkgComplaintPayload {
        complainant: PartyId(1),
        dealer: PartyId(3),
        receiver: PartyId(1),
        reason: DkgComplaintReason::InvalidVssShare,
        evidence: vec![9],
    }];
    let resolution = ItVssComplaintResolution {
        accepted_dealers: parties(&[3, 1]),
        rejected_dealers: parties(&[2]),
        complaints: complaints.clone(),
        certificates: vec![certificate.clone()],
    };
    let reordered_resolution = ItVssComplaintResolution {
        accepted_dealers: parties(&[1, 3]),
        rejected_dealers: parties(&[2]),
        complaints,
        certificates: vec![reordered_certificate],
    };
    assert_eq!(
        hash_it_vss_complaint_resolution(&resolution),
        hash_it_vss_complaint_resolution(&reordered_resolution)
    );
}

#[test]
fn it_vss_complaint_resolution_validator_rejects_bad_shapes() {
    let config = config();
    let label1 = ItVssSharingLabel::new(
        &config,
        PartyId(1),
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        Some(4),
    )
    .expect("label 1");
    let label2 = ItVssSharingLabel::new(
        &config,
        PartyId(2),
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        Some(4),
    )
    .expect("label 2");
    let label3 = ItVssSharingLabel::new(
        &config,
        PartyId(3),
        ItVssSharingDomain::for_secret_vector(SecretVectorKind::S1),
        Some(4),
    )
    .expect("label 3");
    let commitment1 = ItVssPublicCommitment {
        backend_id: ItVssBackendId::ProductionInformationChecking,
        dealer: PartyId(1),
        label_hash: label1.label_hash,
        public_metadata_hash: [0x51; 32],
    };
    let commitment2 = ItVssPublicCommitment {
        backend_id: ItVssBackendId::ProductionInformationChecking,
        dealer: PartyId(2),
        label_hash: label2.label_hash,
        public_metadata_hash: [0x52; 32],
    };
    let commitment3 = ItVssPublicCommitment {
        backend_id: ItVssBackendId::ProductionInformationChecking,
        dealer: PartyId(3),
        label_hash: label3.label_hash,
        public_metadata_hash: [0x53; 32],
    };
    let complaints = vec![DkgComplaintPayload {
        complainant: PartyId(3),
        dealer: PartyId(3),
        receiver: PartyId(3),
        reason: DkgComplaintReason::InvalidVssShare,
        evidence: vec![0xA5],
    }];
    let complaint_hash = hash_dkg_complaint_payloads(&complaints);
    let cert1 = VerifiedItVssSharingCertificate {
        backend_id: ItVssBackendId::ProductionInformationChecking,
        dealer: PartyId(1),
        label_hash: label1.label_hash,
        accepted_receivers: parties(&[1, 2, 3]),
        complaint_hash,
        transcript_hash: hash_it_vss_public_commitment(&commitment1),
    };
    let cert2 = VerifiedItVssSharingCertificate {
        backend_id: ItVssBackendId::ProductionInformationChecking,
        dealer: PartyId(2),
        label_hash: label2.label_hash,
        accepted_receivers: parties(&[3, 1, 2]),
        complaint_hash,
        transcript_hash: hash_it_vss_public_commitment(&commitment2),
    };
    let cert3 = VerifiedItVssSharingCertificate {
        backend_id: ItVssBackendId::ProductionInformationChecking,
        dealer: PartyId(3),
        label_hash: label3.label_hash,
        accepted_receivers: parties(&[1, 2, 3]),
        complaint_hash,
        transcript_hash: hash_it_vss_public_commitment(&commitment3),
    };
    let good = ItVssComplaintResolution {
        accepted_dealers: parties(&[1, 2]),
        rejected_dealers: parties(&[3]),
        complaints: complaints.clone(),
        certificates: vec![cert1.clone(), cert2.clone()],
    };
    validate_it_vss_complaint_resolution(
        &config,
        &[commitment1.clone(), commitment2.clone()],
        &good,
    )
    .expect("valid resolution");

    let too_few_accepted = ItVssComplaintResolution {
        accepted_dealers: parties(&[1]),
        rejected_dealers: parties(&[2, 3]),
        complaints: complaints.clone(),
        certificates: vec![cert1.clone()],
    };
    assert_eq!(
        validate_it_vss_complaint_resolution(
            &config,
            std::slice::from_ref(&commitment1),
            &too_few_accepted,
        ),
        Err(DkgError::InsufficientAcceptedDealers {
            threshold: 2,
            accepted: 1,
        })
    );

    let overlap = ItVssComplaintResolution {
        accepted_dealers: parties(&[1, 2]),
        rejected_dealers: parties(&[2]),
        complaints: complaints.clone(),
        certificates: vec![cert1.clone(), cert2.clone()],
    };
    assert_eq!(
        validate_it_vss_complaint_resolution(
            &config,
            &[commitment1.clone(), commitment2.clone()],
            &overlap,
        ),
        Err(DkgError::ItVssResolutionDealerOverlap { dealer: PartyId(2) })
    );

    let duplicate_certificate = ItVssComplaintResolution {
        accepted_dealers: parties(&[1, 2]),
        rejected_dealers: parties(&[3]),
        complaints: complaints.clone(),
        certificates: vec![cert1.clone(), cert1.clone()],
    };
    assert_eq!(
        validate_it_vss_complaint_resolution(
            &config,
            &[commitment1.clone(), commitment2.clone()],
            &duplicate_certificate,
        ),
        Err(DkgError::DuplicateItVssCertificate {
            dealer: PartyId(1),
            label_hash: label1.label_hash,
        })
    );

    let mut bad_hash_cert = cert1.clone();
    bad_hash_cert.complaint_hash = [0xAC; 32];
    let complaint_hash_mismatch = ItVssComplaintResolution {
        accepted_dealers: parties(&[1, 2]),
        rejected_dealers: parties(&[3]),
        complaints: complaints.clone(),
        certificates: vec![bad_hash_cert, cert2.clone()],
    };
    assert_eq!(
        validate_it_vss_complaint_resolution(
            &config,
            &[commitment1.clone(), commitment2.clone()],
            &complaint_hash_mismatch,
        ),
        Err(DkgError::ItVssCertificateComplaintHashMismatch)
    );

    let missing_commitment = ItVssComplaintResolution {
        accepted_dealers: parties(&[1, 2]),
        rejected_dealers: parties(&[3]),
        complaints: complaints.clone(),
        certificates: vec![cert1.clone(), cert2.clone()],
    };
    assert_eq!(
        validate_it_vss_complaint_resolution(
            &config,
            std::slice::from_ref(&commitment1),
            &missing_commitment
        ),
        Err(DkgError::ItVssCertificateMissingCommitment {
            dealer: PartyId(2),
            label_hash: label2.label_hash,
        })
    );

    let missing_certificate = ItVssComplaintResolution {
        accepted_dealers: parties(&[1, 2]),
        rejected_dealers: parties(&[3]),
        complaints: complaints.clone(),
        certificates: vec![cert1.clone()],
    };
    assert_eq!(
        validate_it_vss_complaint_resolution(
            &config,
            &[commitment1.clone(), commitment2.clone()],
            &missing_certificate,
        ),
        Err(DkgError::ItVssResolutionMissingCertificate { dealer: PartyId(2) })
    );

    let mut scaffold_cert = cert1.clone();
    scaffold_cert.backend_id = ItVssBackendId::InProcessHashBindingScaffold;
    let wrong_backend = ItVssComplaintResolution {
        accepted_dealers: parties(&[1, 2]),
        rejected_dealers: parties(&[3]),
        complaints: complaints.clone(),
        certificates: vec![scaffold_cert, cert2.clone()],
    };
    assert_eq!(
        validate_it_vss_complaint_resolution(
            &config,
            &[commitment1.clone(), commitment2.clone()],
            &wrong_backend,
        ),
        Err(DkgError::ItVssCertificateBackendMismatch)
    );

    let duplicate_commitment = [commitment1.clone(), commitment1.clone()];
    assert_eq!(
        validate_it_vss_complaint_resolution(&config, &duplicate_commitment, &good),
        Err(DkgError::DuplicateItVssPublicCommitment {
            dealer: PartyId(1),
            label_hash: label1.label_hash,
        })
    );

    let mut incomplete_receivers = cert1.clone();
    incomplete_receivers.accepted_receivers = parties(&[1, 2]);
    let incomplete_receiver_set = ItVssComplaintResolution {
        accepted_dealers: parties(&[1, 2]),
        rejected_dealers: parties(&[3]),
        complaints: complaints.clone(),
        certificates: vec![incomplete_receivers, cert2.clone()],
    };
    assert_eq!(
        validate_it_vss_complaint_resolution(
            &config,
            &[commitment1.clone(), commitment2.clone()],
            &incomplete_receiver_set,
        ),
        Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: 3,
            got: 2,
        })
    );

    let unexpected_certificate = ItVssComplaintResolution {
        accepted_dealers: parties(&[1, 2]),
        rejected_dealers: parties(&[3]),
        complaints: complaints.clone(),
        certificates: vec![cert1, cert2, cert3],
    };
    assert_eq!(
        validate_it_vss_complaint_resolution(
            &config,
            &[commitment1, commitment2, commitment3],
            &unexpected_certificate,
        ),
        Err(DkgError::ItVssResolutionUnexpectedCertificate { dealer: PartyId(3) })
    );
}

#[test]
fn production_it_vss_complaint_phase_skeleton_is_ordered() {
    assert_eq!(
        PRODUCTION_IT_VSS_COMPLAINT_PHASES,
        &[
            ProductionItVssComplaintPhase::BroadcastPublicPrecommitments,
            ProductionItVssComplaintPhase::BroadcastPublicCoins,
            ProductionItVssComplaintPhase::BroadcastPublicCommitments,
            ProductionItVssComplaintPhase::DeliverPrivateShares,
            ProductionItVssComplaintPhase::VerifyPrivateDeliveries,
            ProductionItVssComplaintPhase::BroadcastComplaints,
            ProductionItVssComplaintPhase::ResolveComplaints,
            ProductionItVssComplaintPhase::CertifyAcceptedSharings,
        ]
    );

    let mut machine = ProductionItVssComplaintStateMachine::new();
    assert_eq!(
        machine.accept_phase(ProductionItVssComplaintPhase::DeliverPrivateShares),
        Err(DkgError::ItVssComplaintPhaseOutOfOrder)
    );
    for phase in PRODUCTION_IT_VSS_COMPLAINT_PHASES {
        assert_eq!(machine.next_phase(), Some(*phase));
        machine.accept_phase(*phase).expect("phase in order");
    }
    assert!(machine.is_complete());
}

#[test]
fn public_key_assembly_scaffold_rejects_bad_vector_shape() {
    let config = config();
    let mut material = sampled_material::<MlDsa65>(&config).expect("sample material");
    material.s2.vector = SecretVectorKind::S1;
    let mut power2round = ClearSimPower2RoundBackend;

    assert_eq!(
        assemble_public_output_scaffold::<MlDsa65, _>(
            &config,
            [0x92; 32],
            material,
            &config.parties,
            &mut power2round,
        ),
        Err(DkgError::Backend("bad ML-DSA secret material shape"))
    );
}

#[test]
fn dkg_adversarial_sampler_rejects_equivocation_and_rushing_label() {
    let config = config();
    let eta = SmallSecretEta::for_params::<MlDsa65>().expect("eta");
    let label = SamplerLabel::new::<MlDsa65>(&config, SecretVectorKind::S1, 0).expect("label");
    let mut equivocated =
        small_contributions::<MlDsa65>(&config, SecretVectorKind::S1, 0, &[1, 2, 3]);
    equivocated.push(SmallResidueContribution::new(PartyId(2), label, eta, 4));
    assert_eq!(
        sum_small_residues_mod(&config, label, eta, &equivocated),
        Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: 3,
            got: 4,
        })
    );

    let mut rushing = small_contributions::<MlDsa65>(&config, SecretVectorKind::S1, 0, &[1, 2, 3]);
    let other_config =
        DkgConfig::new::<MlDsa65>(2, parties(&[1, 2, 3]), KeygenEpoch(8)).expect("config");
    rushing[2].label =
        SamplerLabel::new::<MlDsa65>(&other_config, SecretVectorKind::S1, 0).expect("other label");
    assert_eq!(
        sum_small_residues_mod(&config, label, eta, &rushing),
        Err(DkgError::SmallSamplerLabelMismatch)
    );
}

#[test]
fn in_memory_transcript_store_rejects_epoch_reuse() {
    let output = bound_output();
    let mut store = InMemoryDkgTranscriptStore::new();
    store.persist_output(&output).expect("persist output");
    assert!(store.contains_epoch(output.config.epoch));
    assert_eq!(
        store.persist_output(&output),
        Err(DkgError::EpochAlreadyCommitted(output.config.epoch))
    );
}

#[cfg(feature = "std")]
#[test]
fn file_transcript_store_survives_reopen_and_rejects_reuse() {
    let path = test_store_path("survives-reopen");
    let _ = std::fs::remove_file(&path);
    let output = bound_output();
    {
        let mut store = FileDkgTranscriptStore::open(&path).expect("open store");
        store.persist_output(&output).expect("persist output");
        assert!(store.contains_epoch(output.config.epoch));
    }

    let mut reopened = FileDkgTranscriptStore::open(&path).expect("reopen store");
    assert!(reopened.contains_epoch(output.config.epoch));
    assert_eq!(
        reopened.persist_output(&output),
        Err(DkgError::EpochAlreadyCommitted(output.config.epoch))
    );
    let _ = std::fs::remove_file(&path);
}

#[cfg(feature = "std")]
#[test]
fn file_transcript_store_rejects_corrupt_log() {
    let path = test_store_path("corrupt");
    std::fs::write(&path, "not-a-record\n").expect("write corrupt log");
    assert_eq!(
        FileDkgTranscriptStore::open(&path),
        Err(DkgError::TranscriptStoreCorrupt { line: 1 })
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn scalar_vss_complaint_evidence_round_trips_canonically() {
    let evidence = ScalarVssComplaintEvidence {
        dealer: PartyId(1),
        receiver: PartyId(2),
        point: 2,
        got: 10,
        expected: 11,
        commitment_binding: [0x44; 32],
    };

    let encoded = evidence.to_canonical_bytes();
    assert_eq!(encoded.len(), 48);
    assert_eq!(
        ScalarVssComplaintEvidence::from_canonical_bytes(&encoded),
        Ok(evidence)
    );
    assert_eq!(
        ScalarVssComplaintEvidence::from_canonical_bytes(&encoded[..47]),
        Err(DkgError::InvalidComplaintEvidenceLength {
            expected: 48,
            got: 47,
        })
    );
}

#[test]
fn test_only_scalar_vss_resolves_valid_complaints_to_rejected_dealers() {
    let config = config();
    let deals = vec![
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(1), &[10, 1])
            .expect("deal 1"),
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(2), &[20, 2])
            .expect("deal 2"),
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(3), &[30, 3])
            .expect("deal 3"),
    ];

    assert_eq!(
        test_only_resolve_scalar_vss_complaints::<MlDsa65>(&config, &deals, &[])
            .expect("resolve no complaints"),
        TestOnlyScalarVssResolution {
            accepted_dealers: parties(&[1, 2, 3]),
            rejected_dealers: Vec::new(),
        }
    );

    let mut tampered_shares = deals[1].shares.clone();
    tampered_shares[2].value += 1;
    let complaints =
        test_only_verify_scalar_vss_round::<MlDsa65>(&config, &deals[1], &tampered_shares)
            .expect("complaints");
    assert_eq!(
        test_only_resolve_scalar_vss_complaints::<MlDsa65>(&config, &deals, &complaints)
            .expect("resolve complaints"),
        TestOnlyScalarVssResolution {
            accepted_dealers: parties(&[1, 3]),
            rejected_dealers: parties(&[2]),
        }
    );
}

#[test]
fn test_only_scalar_vss_resolution_rejects_tampered_complaint_evidence() {
    let config = config();
    let deals = vec![
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(1), &[10, 1])
            .expect("deal 1"),
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(2), &[20, 2])
            .expect("deal 2"),
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(3), &[30, 3])
            .expect("deal 3"),
    ];

    let mut tampered_shares = deals[1].shares.clone();
    tampered_shares[0].value += 1;
    let mut complaints =
        test_only_verify_scalar_vss_round::<MlDsa65>(&config, &deals[1], &tampered_shares)
            .expect("complaints");
    complaints[0].evidence[20] ^= 1;
    assert_eq!(
        test_only_resolve_scalar_vss_complaints::<MlDsa65>(&config, &deals, &complaints),
        Err(DkgError::ComplaintEvidenceMismatch)
    );

    let mut complaints =
        test_only_verify_scalar_vss_round::<MlDsa65>(&config, &deals[1], &tampered_shares)
            .expect("complaints");
    complaints[0].reason = DkgComplaintReason::Backend;
    assert_eq!(
        test_only_resolve_scalar_vss_complaints::<MlDsa65>(&config, &deals, &complaints),
        Err(DkgError::UnsupportedComplaintReason(
            DkgComplaintReason::Backend
        ))
    );
}

#[test]
fn test_only_scalar_dkg_combines_accepted_dealer_contributions() {
    let config = config();
    let deals = vec![
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(1), &[10, 1])
            .expect("deal 1"),
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(2), &[20, 2])
            .expect("deal 2"),
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(3), &[30, 3])
            .expect("deal 3"),
    ];

    let output = test_only_combine_accepted_scalar_vss_deals::<MlDsa65>(&config, &deals, &[])
        .expect("combine");
    assert_eq!(output.accepted_dealers, parties(&[1, 2, 3]));
    assert_eq!(output.rejected_dealers, Vec::new());
    assert_eq!(output.clear_secret, 60);
    assert_eq!(
        output.shares,
        vec![
            TestOnlyCombinedScalarShare {
                receiver: PartyId(1),
                point: 1,
                value: 66,
            },
            TestOnlyCombinedScalarShare {
                receiver: PartyId(2),
                point: 2,
                value: 72,
            },
            TestOnlyCombinedScalarShare {
                receiver: PartyId(3),
                point: 3,
                value: 78,
            },
        ]
    );

    let reconstructable: Vec<ShamirScalarShare> = output
        .shares
        .iter()
        .take(2)
        .map(|share| ShamirScalarShare {
            point: share.point,
            value: share.value,
        })
        .collect();
    assert_eq!(
        reconstruct_scalar_at_zero::<MlDsa65>(&reconstructable).expect("reconstruct"),
        output.clear_secret
    );
}

#[test]
fn test_only_scalar_dkg_combination_excludes_rejected_dealers() {
    let config = config();
    let deals = vec![
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(1), &[10, 1])
            .expect("deal 1"),
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(2), &[20, 2])
            .expect("deal 2"),
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(3), &[30, 3])
            .expect("deal 3"),
    ];
    let mut tampered_shares = deals[1].shares.clone();
    tampered_shares[0].value += 1;
    let complaints =
        test_only_verify_scalar_vss_round::<MlDsa65>(&config, &deals[1], &tampered_shares)
            .expect("complaints");

    let output =
        test_only_combine_accepted_scalar_vss_deals::<MlDsa65>(&config, &deals, &complaints)
            .expect("combine");
    assert_eq!(output.accepted_dealers, parties(&[1, 3]));
    assert_eq!(output.rejected_dealers, parties(&[2]));
    assert_eq!(output.clear_secret, 40);

    let reconstructable: Vec<ShamirScalarShare> = output
        .shares
        .iter()
        .take(2)
        .map(|share| ShamirScalarShare {
            point: share.point,
            value: share.value,
        })
        .collect();
    assert_eq!(
        reconstruct_scalar_at_zero::<MlDsa65>(&reconstructable).expect("reconstruct"),
        output.clear_secret
    );
}

#[test]
fn test_only_scalar_dkg_combination_rejects_insufficient_dealers() {
    let config = config();
    let deals = vec![
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(1), &[10, 1])
            .expect("deal 1"),
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(2), &[20, 2])
            .expect("deal 2"),
        test_only_deal_scalar_vss_for_config::<MlDsa65>(&config, PartyId(3), &[30, 3])
            .expect("deal 3"),
    ];

    let mut complaints = Vec::new();
    for deal in deals.iter().take(2) {
        let mut tampered_shares = deal.shares.clone();
        tampered_shares[0].value += 1;
        complaints.extend(
            test_only_verify_scalar_vss_round::<MlDsa65>(&config, deal, &tampered_shares)
                .expect("complaints"),
        );
    }

    assert_eq!(
        test_only_combine_accepted_scalar_vss_deals::<MlDsa65>(&config, &deals, &complaints),
        Err(DkgError::InsufficientAcceptedDealers {
            threshold: 2,
            accepted: 1,
        })
    );
}

fn bounded_vector_with(first: Coeff) -> Vec<Coeff> {
    let mut coeffs = vec![0; MlDsa65::L * MlDsa65::N];
    coeffs[0] = first;
    coeffs
}

fn small_contributions<P: MlDsaParams>(
    config: &DkgConfig,
    vector: SecretVectorKind,
    coefficient_index: usize,
    residues: &[u8],
) -> Vec<SmallResidueContribution> {
    let eta = SmallSecretEta::for_params::<P>().expect("supported eta");
    let label = SamplerLabel::new::<P>(config, vector, coefficient_index).expect("valid label");
    config
        .parties
        .iter()
        .copied()
        .zip(residues.iter().copied())
        .map(|(party, residue)| SmallResidueContribution::new(party, label, eta, residue))
        .collect()
}

fn small_polyvec_contributions<P: MlDsaParams>(
    config: &DkgConfig,
    vector: SecretVectorKind,
) -> Vec<Vec<SmallResidueContribution>> {
    let eta = SmallSecretEta::for_params::<P>().expect("supported eta");
    let m = eta.modulus();
    (0..vector.coefficient_count::<P>())
        .map(|index| {
            let residues = config
                .parties
                .iter()
                .map(|party| ((index + usize::from(party.0)) % usize::from(m)) as u8)
                .collect::<Vec<_>>();
            small_contributions::<P>(config, vector, index, &residues)
        })
        .collect()
}

fn constant_small_polyvec_contributions<P: MlDsaParams>(
    config: &DkgConfig,
    vector: SecretVectorKind,
    residues: &[u8],
) -> Vec<Vec<SmallResidueContribution>> {
    (0..vector.coefficient_count::<P>())
        .map(|index| small_contributions::<P>(config, vector, index, residues))
        .collect()
}

fn dealer_small_polyvec_contributions(
    rounds: &[Vec<SmallResidueContribution>],
    dealer: PartyId,
) -> Vec<SmallResidueContribution> {
    rounds
        .iter()
        .map(|round| {
            round
                .iter()
                .find(|contribution| contribution.dealer == dealer)
                .expect("dealer contribution")
                .clone()
        })
        .collect()
}

fn reconstruct_small_coeff<P: MlDsaParams>(coeff: &SharedSmallCoeff, threshold: usize) -> Coeff {
    let shares = coeff
        .shares
        .iter()
        .take(threshold)
        .map(|share| ShamirScalarShare {
            point: share.point,
            value: share.value,
        })
        .collect::<Vec<_>>();
    reconstruct_scalar_at_zero::<P>(&shares).expect("reconstruct small coefficient")
}

fn signed_field_coeff<P: MlDsaParams>(coefficient: Coeff) -> Coeff {
    let coefficient = reduce_mod_q::<P>(coefficient);
    if coefficient > P::Q / 2 {
        coefficient - P::Q
    } else {
        coefficient
    }
}

fn sampled_material<P: MlDsaParams>(
    config: &DkgConfig,
) -> Result<SharedMldsaSecretMaterial, DkgError> {
    let mut sampler = InProcessDistributedSmallSampler::new([0x81; 32]);
    let s1 = sampler.sample_small_polyvec::<P>(
        config,
        SecretVectorKind::S1,
        &small_polyvec_contributions::<P>(config, SecretVectorKind::S1),
    )?;
    let s2 = sampler.sample_small_polyvec::<P>(
        config,
        SecretVectorKind::S2,
        &small_polyvec_contributions::<P>(config, SecretVectorKind::S2),
    )?;
    Ok(SharedMldsaSecretMaterial { s1, s2 })
}

fn drive_full_logged_small_sampler<P: MlDsaParams>(
    config: &DkgConfig,
    runtimes: &mut [TestCursoredLoggedDkgTransportRuntime],
) {
    for vector in [SecretVectorKind::S1, SecretVectorKind::S2] {
        for index in 0..vector.coefficient_count::<P>() {
            let contributions = small_contributions::<P>(config, vector, index, &[1, 2, 3]);
            for (runtime, contribution) in runtimes.iter_mut().zip(&contributions) {
                runtime
                    .drive_broadcast_small_residue(contribution)
                    .expect("broadcast logged sampler residue");
            }
            route_cursored_logged_dkg_broadcast_messages(runtimes, [0usize, 1, 2]);
            let label = SamplerLabel::new::<P>(config, vector, index).expect("sampler label");
            runtimes[1]
                .drive_collect_small_residue_round(
                    label,
                    SmallSecretEta::for_params::<P>().expect("eta"),
                )
                .expect("collect logged sampler residue");
            for runtime in runtimes.iter_mut() {
                runtime
                    .runtime_mut()
                    .state_mut()
                    .transport_mut()
                    .clear_queued_messages();
            }
        }
    }
}

#[cfg(feature = "std")]
fn test_store_path(name: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "talus-dkg-{name}-{}-{unique}.log",
        std::process::id()
    ))
}

#[test]
fn bounded_secret_vector_validation_enforces_shape_and_eta() {
    assert_eq!(
        validate_bounded_secret_vector::<MlDsa65>(&bounded_vector_with(MlDsa65::ETA)),
        Ok(())
    );

    let mut short = bounded_vector_with(0);
    short.pop();
    assert_eq!(
        validate_bounded_secret_vector::<MlDsa65>(&short),
        Err(DkgError::InvalidBoundedSecretVectorLength {
            expected: MlDsa65::L * MlDsa65::N,
            got: MlDsa65::L * MlDsa65::N - 1,
        })
    );

    assert_eq!(
        validate_bounded_secret_vector::<MlDsa65>(&bounded_vector_with(MlDsa65::ETA + 1)),
        Err(DkgError::BoundedSecretCoefficientOutOfRange {
            index: 0,
            coefficient: MlDsa65::ETA + 1,
            bound: MlDsa65::ETA,
        })
    );
}

#[test]
fn test_only_bounded_vector_dkg_combines_when_result_remains_bounded() {
    let config = config();
    let deals = vec![
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(1),
            &bounded_vector_with(1),
        )
        .expect("deal 1"),
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(2),
            &bounded_vector_with(-1),
        )
        .expect("deal 2"),
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(3),
            &bounded_vector_with(0),
        )
        .expect("deal 3"),
    ];

    let output = test_only_combine_bounded_secret_vector_deals::<MlDsa65>(&config, &deals, &[])
        .expect("combine");
    assert_eq!(output.accepted_dealers, parties(&[1, 2, 3]));
    assert_eq!(output.clear_secret_coeffs[0], 0);
    assert_eq!(output.clear_secret_coeffs.len(), MlDsa65::L * MlDsa65::N);
    assert_eq!(output.shares.len(), 3);
    assert!(output
        .shares
        .iter()
        .all(|share| share.coeffs.len() == MlDsa65::L * MlDsa65::N));

    let reconstructable = [
        ShamirScalarShare {
            point: output.shares[0].point,
            value: output.shares[0].coeffs[0],
        },
        ShamirScalarShare {
            point: output.shares[1].point,
            value: output.shares[1].coeffs[0],
        },
    ];
    assert_eq!(
        reconstruct_scalar_at_zero::<MlDsa65>(&reconstructable).expect("reconstruct"),
        0
    );
}

#[test]
fn test_only_bounded_vector_dkg_rejects_naive_sum_outside_eta() {
    let config = config();
    let deals = vec![
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(1),
            &bounded_vector_with(MlDsa65::ETA),
        )
        .expect("deal 1"),
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(2),
            &bounded_vector_with(MlDsa65::ETA),
        )
        .expect("deal 2"),
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(3),
            &bounded_vector_with(0),
        )
        .expect("deal 3"),
    ];

    assert_eq!(
        test_only_combine_bounded_secret_vector_deals::<MlDsa65>(&config, &deals, &[]),
        Err(DkgError::CombinedBoundedCoefficientOutOfRange {
            index: 0,
            coefficient: MlDsa65::ETA * 2,
            bound: MlDsa65::ETA,
        })
    );
}

#[test]
fn bounded_secret_vector_share_encodes_and_decodes_canonically() {
    let config = config();
    let mut coeffs = vec![0; MlDsa65::L * MlDsa65::N];
    coeffs[0] = 42;
    coeffs[1] = MlDsa65::Q - 1;
    let share = BoundedSecretVectorShare::new::<MlDsa65>(&config, PartyId(2), 2, coeffs.clone())
        .expect("typed share");

    assert_eq!(
        format!("{share:?}"),
        "BoundedSecretVectorShare { party: PartyId(2), point: 2, coeffs: \"<redacted>\" }"
    );

    let encoded = share.encode::<MlDsa65>(&config).expect("encode");
    assert_eq!(
        BoundedSecretVectorShare::decode::<MlDsa65>(&config, &encoded),
        Ok(share)
    );

    let mut bad_magic = encoded.clone();
    bad_magic[0] ^= 1;
    assert_eq!(
        BoundedSecretVectorShare::decode::<MlDsa65>(&config, &bad_magic),
        Err(DkgError::InvalidSecretShareEncoding(
            "bounded vector share magic mismatch"
        ))
    );

    let mut bad_suite = encoded.clone();
    bad_suite[8] = DkgSuite::MlDsa44.as_u8();
    assert_eq!(
        BoundedSecretVectorShare::decode::<MlDsa65>(&config, &bad_suite),
        Err(DkgError::InvalidSecretShareEncoding(
            "bounded vector share suite mismatch"
        ))
    );

    assert_eq!(
        BoundedSecretVectorShare::decode::<MlDsa65>(&config, &encoded[..18]),
        Err(DkgError::InvalidSecretShareEncoding(
            "bounded vector share is truncated"
        ))
    );
}

#[test]
fn bounded_secret_vector_share_rejects_bad_point_and_field_values() {
    let config = config();
    let coeffs = vec![0; MlDsa65::L * MlDsa65::N];
    assert_eq!(
        BoundedSecretVectorShare::new::<MlDsa65>(&config, PartyId(2), 9, coeffs.clone()),
        Err(DkgError::InvalidSharePoint {
            party: PartyId(2),
            expected: 2,
            got: 9,
        })
    );

    let mut bad_coeffs = coeffs;
    bad_coeffs[3] = MlDsa65::Q;
    assert_eq!(
        BoundedSecretVectorShare::new::<MlDsa65>(&config, PartyId(2), 2, bad_coeffs),
        Err(DkgError::FieldShareCoefficientOutOfRange {
            index: 3,
            coefficient: MlDsa65::Q,
            modulus: MlDsa65::Q,
        })
    );
}

#[test]
fn test_only_bounded_vector_output_converts_to_encoded_secret_shares() {
    let config = config();
    let deals = vec![
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(1),
            &bounded_vector_with(1),
        )
        .expect("deal 1"),
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(2),
            &bounded_vector_with(-1),
        )
        .expect("deal 2"),
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(3),
            &bounded_vector_with(0),
        )
        .expect("deal 3"),
    ];
    let output = test_only_combine_bounded_secret_vector_deals::<MlDsa65>(&config, &deals, &[])
        .expect("combine");

    let secret_shares =
        test_only_dkg_secret_shares_from_bounded_vector_output::<MlDsa65>(&config, &output)
            .expect("secret shares");
    assert_eq!(secret_shares.len(), 3);
    for secret in &secret_shares {
        let decoded = BoundedSecretVectorShare::decode::<MlDsa65>(&config, &secret.s1_share)
            .expect("decode s1 share");
        assert_eq!(decoded.party, secret.party);
        assert_eq!(decoded.point, u32::from(secret.party.0));
        assert_eq!(decoded.coeffs.len(), MlDsa65::L * MlDsa65::N);
    }
}

#[test]
fn test_only_bounded_vector_output_builds_importable_provisioning_packages() {
    let config = config();
    let deals = vec![
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(1),
            &bounded_vector_with(1),
        )
        .expect("deal 1"),
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(2),
            &bounded_vector_with(-1),
        )
        .expect("deal 2"),
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(3),
            &bounded_vector_with(0),
        )
        .expect("deal 3"),
    ];
    let vector_output =
        test_only_combine_bounded_secret_vector_deals::<MlDsa65>(&config, &deals, &[])
            .expect("combine");
    let public = bound_output();

    let packages = test_only_provisioned_key_shares_from_bounded_vector_output::<MlDsa65>(
        public.clone(),
        &vector_output,
        [0x55; 32],
    )
    .expect("provision packages");
    let imported = import_provisioned_key_shares(&config, packages).expect("import packages");
    assert_eq!(imported.len(), 3);
    assert!(imported.iter().all(|item| item.public == public));
    for item in imported {
        let decoded = BoundedSecretVectorShare::decode::<MlDsa65>(&config, &item.secret.s1_share)
            .expect("decode imported s1");
        assert_eq!(decoded.party, item.secret.party);
    }
}

#[test]
fn test_only_dkg_harness_rejects_dealer_and_imports_accepted_output() {
    let config = config();
    let deals = vec![
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(1),
            &bounded_vector_with(1),
        )
        .expect("deal 1"),
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(2),
            &bounded_vector_with(-1),
        )
        .expect("deal 2"),
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(3),
            &bounded_vector_with(0),
        )
        .expect("deal 3"),
    ];
    let vector_output =
        test_only_combine_bounded_secret_vector_deals::<MlDsa65>(&config, &deals, &[PartyId(2)])
            .expect("combine accepted dealers after complaint resolution");

    assert_eq!(vector_output.accepted_dealers, vec![PartyId(1), PartyId(3)]);
    assert_eq!(vector_output.rejected_dealers, vec![PartyId(2)]);
    assert_eq!(vector_output.clear_secret_coeffs[0], 1);
    assert!(vector_output.clear_secret_coeffs[1..]
        .iter()
        .all(|&coefficient| coefficient == 0));

    let public = bound_output();
    let packages = test_only_provisioned_key_shares_from_bounded_vector_output::<MlDsa65>(
        public.clone(),
        &vector_output,
        [0x66; 32],
    )
    .expect("provision packages from accepted output");
    let imported = import_provisioned_key_shares(&config, packages).expect("import packages");

    assert_eq!(imported.len(), config.parties.len());
    for item in imported {
        assert_eq!(item.public, public);
        let decoded = BoundedSecretVectorShare::decode::<MlDsa65>(&config, &item.secret.s1_share)
            .expect("decode imported s1");
        assert_eq!(decoded.party, item.secret.party);
        assert_eq!(decoded.coeffs.len(), MlDsa65::L * MlDsa65::N);
    }
}

#[test]
fn test_only_provisioning_builder_rejects_zero_ceremony_hash() {
    let config = config();
    let deals = vec![
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(1),
            &bounded_vector_with(1),
        )
        .expect("deal 1"),
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(2),
            &bounded_vector_with(-1),
        )
        .expect("deal 2"),
        test_only_deal_bounded_secret_vector::<MlDsa65>(
            &config,
            PartyId(3),
            &bounded_vector_with(0),
        )
        .expect("deal 3"),
    ];
    let vector_output =
        test_only_combine_bounded_secret_vector_deals::<MlDsa65>(&config, &deals, &[])
            .expect("combine");

    assert_eq!(
        test_only_provisioned_key_shares_from_bounded_vector_output::<MlDsa65>(
            bound_output(),
            &vector_output,
            [0; 32],
        ),
        Err(DkgError::EmptyProvisioningTranscript)
    );
}

#[test]
fn local_state_machine_accepts_valid_round_sequence() {
    let output = bound_output();
    let mut machine = DkgLocalStateMachine::new(config()).expect("valid state machine");
    let initial_hash = machine.transcript_hash();

    machine
        .accept_commit_round(commit_round())
        .expect("commit round accepted");
    assert_eq!(machine.state(), DkgState::Waiting(DkgRound::Share));
    assert_ne!(machine.transcript_hash(), initial_hash);

    machine
        .accept_share_round(share_round())
        .expect("share round accepted");
    machine
        .accept_complaint_round(Vec::new())
        .expect("empty complaint round accepted");
    let accepted = machine
        .accept_finalize_round(finalize_round(output.clone()))
        .expect("finalize round accepted");

    assert_eq!(accepted, output);
    assert_eq!(machine.state(), DkgState::Complete);
}

#[test]
fn local_state_machine_rejects_duplicate_or_missing_commit_senders() {
    let mut machine = DkgLocalStateMachine::new(config()).expect("valid state machine");
    let mut commits = commit_round();
    commits[1] = commits[0].clone();
    assert_eq!(
        machine.accept_commit_round(commits),
        Err(DkgError::DuplicateRoundSender {
            round: DkgRound::Commit,
            sender: PartyId(1),
        })
    );

    let mut machine = DkgLocalStateMachine::new(config()).expect("valid state machine");
    assert_eq!(
        machine.accept_commit_round(vec![commit_payload(PartyId(1))]),
        Err(DkgError::MissingRoundMessages {
            round: DkgRound::Commit,
            expected: 3,
            got: 1,
        })
    );
}

#[test]
fn local_state_machine_rejects_malformed_commit_and_wrong_phase() {
    let mut machine = DkgLocalStateMachine::new(config()).expect("valid state machine");
    assert!(matches!(
        machine.accept_share_round(share_round()),
        Err(DkgError::UnexpectedRound {
            expected: DkgRound::Share,
            got: DkgState::Waiting(DkgRound::Commit)
        })
    ));

    let mut machine = DkgLocalStateMachine::new(config()).expect("valid state machine");
    let mut commits = commit_round();
    commits[0].vss_commitments.clear();
    assert_eq!(
        machine.accept_commit_round(commits),
        Err(DkgError::EmptyDkgCommitments(PartyId(1)))
    );
}

#[test]
fn local_state_machine_rejects_bad_share_topology() {
    let mut machine = DkgLocalStateMachine::new(config()).expect("valid state machine");
    machine
        .accept_commit_round(commit_round())
        .expect("commit round accepted");
    let mut shares = share_round();
    shares[0].receiver = shares[0].dealer;
    assert_eq!(
        machine.accept_share_round(shares),
        Err(DkgError::InvalidShareReceiver {
            dealer: PartyId(1),
            receiver: PartyId(1),
        })
    );

    let mut machine = DkgLocalStateMachine::new(config()).expect("valid state machine");
    machine
        .accept_commit_round(commit_round())
        .expect("commit round accepted");
    let mut shares = share_round();
    shares[1] = shares[0].clone();
    assert_eq!(
        machine.accept_share_round(shares),
        Err(DkgError::DuplicateShare {
            dealer: PartyId(1),
            receiver: PartyId(2),
        })
    );
}

#[test]
fn local_state_machine_rejects_bad_complaints_and_final_disagreement() {
    let mut machine = DkgLocalStateMachine::new(config()).expect("valid state machine");
    machine
        .accept_commit_round(commit_round())
        .expect("commit round accepted");
    machine
        .accept_share_round(share_round())
        .expect("share round accepted");
    assert_eq!(
        machine.accept_complaint_round(vec![DkgComplaintPayload {
            complainant: PartyId(1),
            dealer: PartyId(2),
            receiver: PartyId(9),
            reason: DkgComplaintReason::MissingShare,
            evidence: vec![],
        }]),
        Err(DkgError::UnknownParty(PartyId(9)))
    );

    let mut machine = DkgLocalStateMachine::new(config()).expect("valid state machine");
    machine
        .accept_commit_round(commit_round())
        .expect("commit round accepted");
    machine
        .accept_share_round(share_round())
        .expect("share round accepted");
    machine
        .accept_complaint_round(Vec::new())
        .expect("complaint round accepted");
    let mut finalizers = finalize_round(bound_output());
    finalizers[1].output.public_key[0] ^= 1;
    finalizers[1].output.keygen_transcript_hash = finalizers[1].output.transcript_binding();
    assert_eq!(
        machine.accept_finalize_round(finalizers),
        Err(DkgError::FinalizeDisagreement)
    );
}
