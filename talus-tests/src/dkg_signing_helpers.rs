use crate::dkg_power2round_driver::{
    drive_production_vector_power2round, reconstruct_t1_from_shared_t,
};
use talus_core::MlDsaParams;
use talus_mpc::dev_backends::{
    sign_polynomial_with_token, DkgBackedPolynomialShareProvider, NoopPolynomialPartialVerifier,
    PolynomialAggregation, PolynomialOnlineServices,
};
use talus_mpc::{
    certify_preprocessing_token, Commitment, ConsumedTokenStore, FinalSignature, FinalVerifier,
    NonceCommitment, PartyPreprocessInput, PreprocessError, SessionId, SessionRegistry,
    SignRequest, SigningCounters, TokenConsumptionStore, TokenPool, TranscriptHash,
    ONLINE_PROTOCOL_VERSION,
};
use talus_mpc_core::PartyId;

pub(super) fn dkg_to_talus_signing_verifies_with_standard_fips_verifier<P: MlDsaParams>(seed: u8) {
    let parties = vec![PartyId(1), PartyId(2), PartyId(3)];
    let config =
        talus_dkg::DkgConfig::new::<P>(2, parties.clone(), talus_dkg::KeygenEpoch(u64::from(seed)))
            .expect("dkg config");
    let rho = [seed; 32];

    let mut sampler = talus_dkg::VerifiedDistributedSmallSampler::new([seed ^ 0x5a; 32]);
    let s1 = sample_zero_secret_vector::<P>(&mut sampler, &config, talus_dkg::SecretVectorKind::S1);
    let s2 = sample_zero_secret_vector::<P>(&mut sampler, &config, talus_dkg::SecretVectorKind::S2);
    let shared_t =
        talus_dkg::assemble_shared_t::<P>(&config, rho, &s1, s2).expect("assemble shared t");
    let expected_t1 = reconstruct_t1_from_shared_t::<P>(&shared_t);
    assert!(
        expected_t1.iter().all(|&coeff| coeff == 0),
        "zero DKG material should assemble zero t1"
    );

    let power2round_output = drive_production_vector_power2round::<P>(&config, rho, &expected_t1);
    let (public, mut certificate) = talus_dkg::assemble_public_output_from_production_power2round(
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

pub(super) fn dkg_to_talus_generated_nonce_signing_verifies_with_standard_fips_verifier<
    P: MlDsaParams,
>(
    seed: u8,
) {
    let parties = vec![PartyId(1), PartyId(2), PartyId(3)];
    let config =
        talus_dkg::DkgConfig::new::<P>(2, parties.clone(), talus_dkg::KeygenEpoch(u64::from(seed)))
            .expect("dkg config");
    let rho = [seed; 32];

    let mut sampler = talus_dkg::VerifiedDistributedSmallSampler::new([seed ^ 0x3c; 32]);
    let s1 = sample_zero_secret_vector::<P>(&mut sampler, &config, talus_dkg::SecretVectorKind::S1);
    let s2 = sample_zero_secret_vector::<P>(&mut sampler, &config, talus_dkg::SecretVectorKind::S2);
    let shared_t =
        talus_dkg::assemble_shared_t::<P>(&config, rho, &s1, s2).expect("assemble shared t");
    let expected_t1 = reconstruct_t1_from_shared_t::<P>(&shared_t);
    let power2round_output = drive_production_vector_power2round::<P>(&config, rho, &expected_t1);
    let (public, mut certificate) = talus_dkg::assemble_public_output_from_production_power2round(
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

pub(super) fn dkg_to_talus_nonzero_nonce_signing_verifies_with_standard_fips_verifier<
    P: MlDsaParams,
>(
    seed: u8,
) {
    let parties = vec![PartyId(1), PartyId(2), PartyId(3)];
    let config =
        talus_dkg::DkgConfig::new::<P>(2, parties.clone(), talus_dkg::KeygenEpoch(u64::from(seed)))
            .expect("dkg config");
    let rho = [seed; 32];

    let mut sampler = talus_dkg::VerifiedDistributedSmallSampler::new([seed ^ 0x3c; 32]);
    let s1 = sample_zero_secret_vector::<P>(&mut sampler, &config, talus_dkg::SecretVectorKind::S1);
    let s2 = sample_zero_secret_vector::<P>(&mut sampler, &config, talus_dkg::SecretVectorKind::S2);
    let shared_t =
        talus_dkg::assemble_shared_t::<P>(&config, rho, &s1, s2).expect("assemble shared t");
    let expected_t1 = reconstruct_t1_from_shared_t::<P>(&shared_t);
    let power2round_output = drive_production_vector_power2round::<P>(&config, rho, &expected_t1);
    let (public, mut certificate) = talus_dkg::assemble_public_output_from_production_power2round(
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
            let label =
                talus_dkg::SamplerLabel::new::<P>(config, vector, index).expect("sampler label");
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
                    let label_hash = test_verified_residue_hash(0x31, party, vector, index, config);
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
    let provider = DkgBackedPolynomialShareProvider::<P>::from_key_packages(
        session_id,
        config.clone(),
        y_shares,
        key_packages,
    );
    let verifier =
        talus_mpc::FipsFinalVerifier::<P>::new(public_key.to_vec()).expect("standard verifier");
    let tr = talus_core::compute_tr(public_key);
    let mut pool = TokenPool::new();
    pool.insert_certified(token).expect("insert token");
    let mut consumed = ConsumedTokenStore::new();
    let mut counters = SigningCounters::default();
    let signature = sign_polynomial_with_token::<P, _, _, _, _>(
        &mut pool,
        &mut consumed,
        &mut counters,
        &request,
        PolynomialOnlineServices {
            tr: &tr,
            public_key,
            aggregation: PolynomialAggregation::LagrangeAtZero,
            partial_verifier: &NoopPolynomialPartialVerifier,
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
    let provider = DkgBackedPolynomialShareProvider::<P>::from_key_packages(
        session_id,
        config.clone(),
        y_shares,
        key_packages,
    );
    let verifier =
        talus_mpc::FipsFinalVerifier::<P>::new(public_key.to_vec()).expect("standard verifier");
    let tr = talus_core::compute_tr(public_key);
    let mut pool = TokenPool::new();
    pool.insert_certified(token).expect("insert token");
    let mut consumed = ConsumedTokenStore::new();
    let mut counters = SigningCounters::default();
    let signature = sign_polynomial_with_token::<P, _, _, _, _>(
        &mut pool,
        &mut consumed,
        &mut counters,
        &request,
        PolynomialOnlineServices {
            tr: &tr,
            public_key,
            aggregation: PolynomialAggregation::LagrangeAtZero,
            partial_verifier: &NoopPolynomialPartialVerifier,
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
