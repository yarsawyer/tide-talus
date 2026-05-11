use talus_core::MlDsaParams;

pub(super) fn reconstruct_t1_from_shared_t<P: MlDsaParams>(
    shared_t: &talus_dkg::SharedT,
) -> Vec<u16> {
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
            let coeff = talus_dkg::reconstruct_scalar_at_zero::<P>(&shares).expect("reconstruct t");
            let (high, _low) = talus_core::power2round::<P>(coeff);
            out.push(high as u16);
        }
    }
    out
}

pub(super) fn drive_production_vector_power2round<P: MlDsaParams>(
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
            .drive_collect_power2round_canonical_recovery_all_vec_and_advance(&mut driver, &label)
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
