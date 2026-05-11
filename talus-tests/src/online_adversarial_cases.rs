use crate::{OnlineAdversarialCase, OnlineAdversarialOutcome};
use talus_core::{MlDsa65, MlDsaParams};
use talus_mpc::dev_backends::{
    sign_with_retry, sign_with_token, OnlineServices, PartialSignature, PartialSigner, RetryPolicy,
    SignatureAssembler,
};
use talus_mpc::{
    certify_preprocessing_token, ChallengeMaterial, Commitment, ConsumedTokenStore, FinalSignature,
    FinalVerifier, NonceCommitment, OnlineError, PartyPreprocessInput, SessionId, SessionRegistry,
    SignRequest, SigningCounters, TokenConsumptionStore, TokenPool, TranscriptHash,
    ONLINE_PROTOCOL_VERSION,
};
use talus_mpc_core::PartyId;

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
    let error = sign_with_token::<MlDsa65, _, _, _, _>(
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

    sign_with_token::<MlDsa65, _, _, _, _>(
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

    let error = sign_with_token::<MlDsa65, _, _, _, _>(
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

    let error = sign_with_retry::<MlDsa65, _, _, _, _>(
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
