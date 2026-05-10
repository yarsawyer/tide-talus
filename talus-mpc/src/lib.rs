#![forbid(unsafe_code)]
#![doc = "TALUS-MPC protocol state machines."]

pub mod local;
pub mod online;

pub use local::{
    certify_preprocessing_token, certify_preprocessing_token_with_consistency,
    ensure_pre_challenge_certification_evidence, ensure_pre_challenge_certification_policy,
    generate_distributed_nonce_shares, masked_broadcast_commitment, open_broadcasts,
    party_preprocess_input_from_distributed_nonce_share, prepare_masked_broadcast_envelope,
    BccCertificationEvidence, BroadcastEnvelope, CarryCompareCertificationEvidence, CertifiedToken,
    ClearMaskedBroadcastConsistencyVerifier, Commitment, CutAndChooseAuditPlan,
    DistributedNonceGenerationEvidence, DistributedNonceGenerationOptions,
    DistributedNonceGenerationOutput, DistributedNonceShare, MaskedBroadcast,
    MaskedBroadcastCertificationEvidence, MaskedBroadcastClearAudit,
    MaskedBroadcastConsistencyProof, MaskedBroadcastConsistencyStatement,
    MaskedBroadcastConsistencyVerifier, NonceCommitment, NonceRevealPolicyEvidence,
    PartyPreprocessInput, PreChallengeCertificationEvidence, PreChallengeCertificationPolicy,
    PreprocessError, PreprocessingOutbound, PreprocessingSession, PreprocessingSessionOptions,
    ProductMaskedBroadcastConsistencyVerifier, ProductZkMaskedBroadcastVerifier, SessionCounter,
    SessionCounterStore, SessionId, SessionRegistry, SessionStore, TokenCandidate,
    TokenPersistenceEvidence, TokenPool, TokenPoolError, TranscriptHash,
};

#[cfg(feature = "std")]
pub use local::{FileSessionCounter, FileSessionRegistry};
pub use online::{
    assemble_polynomial_response, compute_challenge_material, compute_polynomial_partial,
    encode_final_signature_candidate, encode_final_signature_candidate_from_public_key,
    encode_final_signature_candidate_with_az, sign_polynomial_with_retry,
    sign_polynomial_with_token, sign_with_retry, sign_with_token, validate_sign_request,
    ChallengeMaterial, CommitmentBackedPartialVerifier, ConsumedTokenStore,
    DkgBackedPolynomialShareProvider, FinalSignature, FinalVerifier, FipsFinalVerifier,
    NoopPolynomialPartialVerifier, OnlineError, OnlineServices, PartialSignature, PartialSigner,
    PolynomialAggregation, PolynomialOnlineServices, PolynomialPartialCommitment,
    PolynomialPartialSignature, PolynomialResponse, PolynomialShareProvider,
    PolynomialSigningShare, RetryPolicy, SignRequest, SignatureAssembler, SigningCounters,
    TokenConsumptionStore, ONLINE_PROTOCOL_VERSION,
};

#[cfg(feature = "std")]
pub use online::FileConsumedTokenStore;

/// Placeholder exported so the crate compiles before protocol state machines land.
pub const CRATE_STATUS: &str = "scaffold";
