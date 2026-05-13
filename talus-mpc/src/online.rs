#![doc = "Online TALUS-MPC signing state-machine shell."]

use core::{fmt, marker::PhantomData};

use crate::local::{
    ensure_certified_token_release_valid, CertifiedToken, SessionId, TokenPoolError, TranscriptHash,
};
use sha3::{Digest, Sha3_256};
use std::time::Instant;
use talus_core::{
    az_from_rho, compute_ctilde, compute_mu, compute_talus_hint_polyvec,
    lagrange_coefficients_at_zero, mul_challenge_polyvec, public_approx_from_az, public_key_decode,
    sample_in_ball, signature_encode, w1_encode, z_bound_holds, Fips204Verifier, HintError,
    MlDsaParams, NttError, Poly, PolyError, PolyVec, PublicKeyDecodeError, SignatureEncodingError,
    TalusPerformanceCounters, VerifyError,
};
use talus_dkg::{
    ensure_production_strict_signing_runtime_evidence_for_release,
    ensure_production_vector_it_mpc_runtime_evidence_for_release, BoundedSecretVectorShare,
    DkgConfig, DkgError, DkgSecretShare, Power2RoundTranscriptLabel, PrimeFieldMpcCounters,
    PrimeFieldMpcPhaseCursorLog, PrimeFieldMpcPhaseDriverStatus, PrimeFieldMpcWireMessageLog,
    ProductionBitShareVec, ProductionBitSumLeqPublicVecState,
    ProductionCanonicalBitDecompositionState, ProductionPublicComparisonVecState,
    ProductionShareVec, ProductionVectorItMpcCollectResult, ProductionVectorItMpcEntropy,
    ProductionVectorItMpcRuntimeEvidence, ProductionVectorPrimeFieldMpcRuntime,
};
use talus_mpc_core::PartyId;
use talus_wire::{
    decode_strict_sign_mpc_payload, encode_message, signing_set_hash, AuthenticatedP2pTransport,
    EquivocationResistantBroadcast, PayloadKind, RoundId, StrictSignMpcPayload, StrictSignMpcSlot,
    SuiteId as WireSuiteId, WireMessage,
};

/// Current online protocol version.
pub const ONLINE_PROTOCOL_VERSION: u16 = 1;

/// Online signing request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignRequest {
    /// Protocol version.
    pub protocol_version: u16,
    /// ML-DSA suite name.
    pub suite: &'static str,
    /// Preprocessing session id.
    pub session_id: SessionId,
    /// Signing set, expected to match the token exactly.
    pub signing_set: Vec<PartyId>,
    /// Message bytes, when `external_mu` is not supplied.
    pub message: Vec<u8>,
    /// Optional externally supplied FIPS `mu`.
    pub external_mu: Option<[u8; 64]>,
    /// FIPS context string.
    pub context: Vec<u8>,
    /// Token transcript hash.
    pub token_transcript_hash: TranscriptHash,
}

/// Challenge material derived from a valid request and certified token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeMaterial {
    /// FIPS message representative.
    pub mu: [u8; 64],
    /// Encoded `w1` used in the challenge hash.
    pub encoded_w1: Vec<u8>,
    /// Challenge seed `ctilde`.
    pub ctilde: Vec<u8>,
}

/// Public metadata for one consumed strict-signing candidate.
///
/// This contains only values derivable from the request and the certified
/// preprocessing token. It deliberately contains no response share, aggregate
/// `z`, hint, validity bit, failure reason, or private witness material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictCandidateMetadata {
    /// Candidate token session id.
    pub session_id: SessionId,
    /// Token transcript hash.
    pub token_transcript_hash: TranscriptHash,
    /// Public priority used for valid-candidate selection.
    pub priority: StrictCandidatePriority,
    /// FIPS message representative.
    pub mu: [u8; 64],
    /// Challenge seed for this candidate.
    pub ctilde: Vec<u8>,
    /// Hash of encoded `w1`, not the full vector.
    pub encoded_w1_hash: [u8; 32],
}

/// Final signature bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalSignature {
    /// Serialized FIPS ML-DSA signature.
    pub bytes: Vec<u8>,
}

/// Public counters for a strict private response-check circuit.
///
/// These counters are safe for release evidence because they describe circuit
/// size and opened selected-output shape, not per-token pass/fail results.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StrictResponseCheckCounters {
    /// Candidate tokens consumed by this strict signing attempt.
    pub candidates: usize,
    /// Secret-shared response vectors evaluated.
    pub private_response_vectors: usize,
    /// Private z-bound predicates evaluated.
    pub z_bound_checks: usize,
    /// Private hint-weight predicates evaluated.
    pub hint_weight_checks: usize,
    /// Private candidate-validity bits evaluated.
    pub validity_bits: usize,
    /// Selected signatures opened.
    pub selected_openings: usize,
}

impl StrictResponseCheckCounters {
    /// Validates the coarse circuit shape for one strict signing batch.
    pub fn validate_for_batch(&self, token_count: usize) -> Result<(), OnlineError> {
        if self.candidates != token_count
            || self.private_response_vectors != token_count
            || self.z_bound_checks != token_count
            || self.hint_weight_checks != token_count
            || self.validity_bits != token_count
            || self.selected_openings != 1
        {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        Ok(())
    }
}

/// Converts strict signing response-check evidence into the shared TALUS
/// performance model.
pub fn talus_performance_counters_from_strict_signing<P: MlDsaParams>(
    evidence: &StrictSigningEvidence,
) -> TalusPerformanceCounters {
    let token_count = evidence.token_count as u64;
    let response_lanes = token_count.saturating_mul((P::L * P::N) as u64);
    let hint_lanes = token_count.saturating_mul((P::K * P::N) as u64);
    TalusPerformanceCounters {
        rounds: STRICT_RESPONSE_CHECK_PHASES.len() as u64,
        vector_lanes: response_lanes.saturating_add(hint_lanes),
        chunks: token_count,
        opened_lanes: (P::L * P::N + P::K * P::N) as u64,
        checked_lanes: response_lanes.saturating_add(hint_lanes),
        token_batch_size: token_count,
        scalar_operations: if evidence
            .response_check_counters
            .validate_for_batch(evidence.token_count)
            .is_ok()
        {
            0
        } else {
            1
        },
        ..TalusPerformanceCounters::default()
    }
}

/// Safe public evidence that response bounds were evaluated for a batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictResponseBoundEvidence {
    /// Candidate tokens checked.
    pub token_count: usize,
    /// Response coefficients checked per candidate.
    pub coefficients_per_candidate: usize,
}

impl StrictResponseBoundEvidence {
    /// Validates the public shape of response-bound evidence.
    pub fn validate_for_batch<P: MlDsaParams>(
        &self,
        token_count: usize,
    ) -> Result<(), OnlineError> {
        if self.token_count != token_count || self.coefficients_per_candidate != P::L * P::N {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        Ok(())
    }
}

/// Safe public evidence that hint/highbits checks were evaluated for a batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictHintCheckEvidence {
    /// Candidate tokens checked.
    pub token_count: usize,
    /// Hint coefficients checked per candidate.
    pub coefficients_per_candidate: usize,
}

impl StrictHintCheckEvidence {
    /// Validates the public shape of hint-check evidence.
    pub fn validate_for_batch<P: MlDsaParams>(
        &self,
        token_count: usize,
    ) -> Result<(), OnlineError> {
        if self.token_count != token_count || self.coefficients_per_candidate != P::K * P::N {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        Ok(())
    }
}

/// Safe public evidence that candidate pass bits were privately combined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictPrivateSelectionEvidence {
    /// Candidate tokens considered.
    pub token_count: usize,
    /// Public priority of the selected valid candidate.
    pub selected_priority: StrictCandidatePriority,
}

impl StrictPrivateSelectionEvidence {
    /// Validates the public shape of selection evidence.
    pub fn validate_for_batch(&self, token_count: usize) -> Result<(), OnlineError> {
        if self.token_count != token_count {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        Ok(())
    }
}

/// Safe public evidence that only the selected output was opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictSelectedOpeningEvidence {
    /// Candidate tokens in the private selection batch.
    pub token_count: usize,
    /// Public priority of the selected valid candidate.
    pub selected_priority: StrictCandidatePriority,
    /// Hash of the selected signature bytes.
    pub signature_hash: [u8; 32],
}

impl StrictSelectedOpeningEvidence {
    /// Validates the public shape of selected-opening evidence.
    pub fn validate_for_selection(
        &self,
        selection: &StrictPrivateSelectionEvidence,
    ) -> Result<(), OnlineError> {
        if self.token_count != selection.token_count
            || self.selected_priority != selection.selected_priority
        {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        Ok(())
    }
}

/// Public evidence emitted by a strict private signing backend.
///
/// This evidence is intentionally coarse. It may identify the selected
/// priority and final signature hash, but it must not include rejected
/// candidate values, per-token pass/fail bits, failed predicate names, or
/// private circuit witnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictSigningEvidence {
    /// Number of consumed candidates checked privately.
    pub token_count: usize,
    /// Public response-check circuit counters.
    pub response_check_counters: StrictResponseCheckCounters,
    /// Public priority of the selected valid candidate.
    pub selected_priority: StrictCandidatePriority,
    /// Hash of the selected signature bytes.
    pub signature_hash: [u8; 32],
    /// Backend-specific public transcript/evidence hash.
    pub transcript_hash: [u8; 32],
}

/// Release certificate that strict signing checks used the durable production
/// vector IT-MPC runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictSigningVectorRuntimeCertificate {
    /// Durable runtime evidence from the vector IT-MPC backend.
    runtime_evidence: ProductionVectorItMpcRuntimeEvidence,
    /// Strict-signing release source that produced this certificate.
    source: StrictSigningRuntimeCertificateSource,
}

/// Source of a strict-signing vector runtime certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrictSigningRuntimeCertificateSource {
    /// Durable vector runtime evidence was validated but not bound to the
    /// selected-opening artifact handoff. This is useful for tests and
    /// lower-level adapters, but it is not sufficient for release strict
    /// signing output.
    RuntimeEvidenceOnly,
    /// Durable vector runtime evidence was attached through the
    /// selected-opening artifact handoff that validates request, token order,
    /// selected priority, and selected challenge seed.
    SelectedOpeningArtifact,
}

impl StrictSigningVectorRuntimeCertificate {
    /// Builds a strict-signing runtime certificate after applying the full
    /// Phase 3 vector-runtime release gate.
    pub fn new(
        runtime_evidence: ProductionVectorItMpcRuntimeEvidence,
    ) -> Result<Self, OnlineError> {
        ensure_production_vector_it_mpc_runtime_evidence_for_release(&runtime_evidence)
            .map_err(|_| OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        Ok(Self {
            runtime_evidence,
            source: StrictSigningRuntimeCertificateSource::RuntimeEvidenceOnly,
        })
    }

    /// Builds a strict-signing runtime certificate from evidence derived from
    /// the strict signing runtime log.
    pub fn new_for_strict_signing(
        runtime_evidence: ProductionVectorItMpcRuntimeEvidence,
    ) -> Result<Self, OnlineError> {
        ensure_production_strict_signing_runtime_evidence_for_release(&runtime_evidence)
            .map_err(|_| OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        Ok(Self {
            runtime_evidence,
            source: StrictSigningRuntimeCertificateSource::RuntimeEvidenceOnly,
        })
    }

    /// Marks this certificate as bound through the selected-opening artifact
    /// handoff.
    fn into_selected_opening_artifact(mut self) -> Self {
        self.source = StrictSigningRuntimeCertificateSource::SelectedOpeningArtifact;
        self
    }

    /// Returns durable runtime evidence from the vector IT-MPC backend.
    pub fn runtime_evidence(&self) -> &ProductionVectorItMpcRuntimeEvidence {
        &self.runtime_evidence
    }

    /// Returns the release-source boundary that produced this certificate.
    pub const fn source(&self) -> StrictSigningRuntimeCertificateSource {
        self.source
    }

    /// Returns true only for the selected-opening artifact release path.
    pub const fn is_selected_opening_artifact_bound(&self) -> bool {
        matches!(
            self.source,
            StrictSigningRuntimeCertificateSource::SelectedOpeningArtifact
        )
    }
}

/// Selected strict-signing output before the independent final verifier gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictSelectedSignature {
    /// Selected final signature candidate.
    pub signature: FinalSignature,
    /// Public evidence for the selected-opening path.
    pub evidence: StrictSigningEvidence,
    /// Durable production vector IT-MPC runtime certificate for strict signing.
    ///
    /// Dev/test strict backends may leave this absent. Release-capable strict
    /// signing output must carry the certificate on the selected output itself
    /// so final verification and persistence cannot detach it from the
    /// signature artifact.
    pub vector_runtime_certificate: Option<StrictSigningVectorRuntimeCertificate>,
}

impl StrictSelectedSignature {
    /// Attaches durable vector-runtime evidence to this strict selected output.
    pub fn with_vector_runtime_certificate(
        mut self,
        certificate: StrictSigningVectorRuntimeCertificate,
    ) -> Self {
        self.vector_runtime_certificate = Some(certificate);
        self
    }

    /// Returns the attached durable vector-runtime certificate, if present.
    pub fn vector_runtime_certificate(&self) -> Option<&StrictSigningVectorRuntimeCertificate> {
        self.vector_runtime_certificate.as_ref()
    }
}

/// Public priority used to select one valid strict-signing candidate.
///
/// The priority is derived from public request and token metadata. A strict
/// backend should select the valid candidate with the lowest priority rather
/// than the first valid candidate, so the opened result does not reveal that
/// earlier batch entries failed private checks.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StrictCandidatePriority(pub [u8; 32]);

/// Strict production signing request.
///
/// This request is intentionally batch-scoped instead of token-scoped. A
/// strict production attempt consumes a fixed batch of certified preprocessing
/// tokens before any challenge or response computation can begin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictSignRequest {
    /// Protocol version.
    pub protocol_version: u16,
    /// ML-DSA suite name.
    pub suite: &'static str,
    /// Signing set shared by every token in the batch.
    pub signing_set: Vec<PartyId>,
    /// Message bytes, when `external_mu` is not supplied.
    pub message: Vec<u8>,
    /// Optional externally supplied FIPS `mu`.
    pub external_mu: Option<[u8; 64]>,
    /// FIPS context string.
    pub context: Vec<u8>,
}

/// Batch of pre-challenge BCC-certified tokens accepted for strict signing.
pub struct BccCertifiedTokenBatch {
    signer_set: Vec<PartyId>,
    tokens: Vec<CertifiedToken>,
}

impl fmt::Debug for BccCertifiedTokenBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BccCertifiedTokenBatch")
            .field("signer_set", &self.signer_set)
            .field("token_count", &self.tokens.len())
            .finish()
    }
}

impl BccCertifiedTokenBatch {
    /// Creates a strict batch from certified tokens.
    pub fn new(tokens: Vec<CertifiedToken>, min_batch_size: usize) -> Result<Self, OnlineError> {
        if tokens.is_empty() {
            return Err(OnlineError::EmptyTokenBatch);
        }
        if tokens.len() < min_batch_size {
            return Err(OnlineError::TokenBatchTooSmall {
                min: min_batch_size,
                got: tokens.len(),
            });
        }

        let signer_set = tokens[0].signer_set.clone();
        let mut sessions = Vec::with_capacity(tokens.len());
        for token in &tokens {
            if !token.is_certified() {
                return Err(OnlineError::TokenPool(TokenPoolError::NotCertified(
                    token.session_id,
                )));
            }
            if token.signer_set != signer_set {
                return Err(OnlineError::TokenBatchSignerSetMismatch);
            }
            if sessions.contains(&token.session_id) {
                return Err(OnlineError::DuplicateTokenInBatch(token.session_id));
            }
            sessions.push(token.session_id);
        }

        Ok(Self { signer_set, tokens })
    }

    /// Creates a strict batch that is valid for release-capable signing.
    pub fn new_release_validated(
        tokens: Vec<CertifiedToken>,
        min_batch_size: usize,
    ) -> Result<Self, OnlineError> {
        let batch = Self::new(tokens, min_batch_size)?;
        for token in &batch.tokens {
            ensure_certified_token_release_valid(token).map_err(|_| {
                OnlineError::TokenPool(TokenPoolError::NotCertified(token.session_id))
            })?;
        }
        Ok(batch)
    }

    /// Number of tokens in the batch.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Returns true when no tokens are present.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Signing set shared by all tokens.
    pub fn signer_set(&self) -> &[PartyId] {
        &self.signer_set
    }

    /// Session ids in batch order.
    pub fn session_ids(&self) -> Vec<SessionId> {
        self.tokens.iter().map(|token| token.session_id).collect()
    }
}

/// A strict signing batch after durable token consumption.
///
/// Only this consumed form can be passed to the private signing backend.
pub struct ConsumedBccCertifiedTokenBatch {
    signer_set: Vec<PartyId>,
    tokens: Vec<CertifiedToken>,
}

impl fmt::Debug for ConsumedBccCertifiedTokenBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumedBccCertifiedTokenBatch")
            .field("signer_set", &self.signer_set)
            .field("token_count", &self.tokens.len())
            .finish()
    }
}

impl ConsumedBccCertifiedTokenBatch {
    /// Number of consumed tokens.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Returns true when no tokens are present.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Signing set shared by all consumed tokens.
    pub fn signer_set(&self) -> &[PartyId] {
        &self.signer_set
    }

    /// Consumed token references for a private backend.
    pub fn tokens(&self) -> &[CertifiedToken] {
        &self.tokens
    }

    /// Session ids in consumed batch order.
    pub fn session_ids(&self) -> Vec<SessionId> {
        self.tokens.iter().map(|token| token.session_id).collect()
    }
}

/// Ordered strict-signing phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrictSigningPhase {
    /// Tokens are durably consumed before challenge/response work.
    ConsumeTokenBatch,
    /// Challenges are derived locally for every consumed token.
    DeriveChallenges,
    /// Secret-shared candidate responses are computed.
    ComputePrivateResponses,
    /// Private z-bound, hint, hint-weight, and validity checks are evaluated.
    EvaluatePrivateChecks,
    /// A valid candidate is selected privately.
    SelectPrivateCandidate,
    /// Only the selected valid candidate is opened.
    OpenSelectedCandidate,
    /// Final FIPS verification is run before output.
    FinalVerify,
}

/// Canonical strict-signing phase order.
pub const STRICT_SIGNING_PHASES: &[StrictSigningPhase] = &[
    StrictSigningPhase::ConsumeTokenBatch,
    StrictSigningPhase::DeriveChallenges,
    StrictSigningPhase::ComputePrivateResponses,
    StrictSigningPhase::EvaluatePrivateChecks,
    StrictSigningPhase::SelectPrivateCandidate,
    StrictSigningPhase::OpenSelectedCandidate,
    StrictSigningPhase::FinalVerify,
];

/// Outbound strict-signing message emitted by [`StrictSigningSession`].
///
/// The current strict production facade is transport-shaped but still
/// single-process: no signing wire messages are emitted until the distributed
/// vector IT-MPC runtime lands behind the strict backend traits. The enum is
/// part of the stable application boundary so embedding applications can use
/// the same polling shape as DKG/preprocessing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StrictSigningOutbound {
    /// Directed private message for an application-provided authenticated
    /// private channel.
    Private {
        /// Authenticated receiver party id.
        receiver: PartyId,
        /// Canonical wire message.
        message: WireMessage,
    },
    /// Equivocation-resistant broadcast delivery.
    Broadcast {
        /// Canonical wire message.
        message: WireMessage,
    },
}

/// Coarse state of one [`StrictSigningSession`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrictSigningSessionPhase {
    /// Session has been initialized and can be finished.
    Ready,
    /// Session returned a final verified signature.
    Finished,
    /// Session consumed its batch but failed before returning a signature.
    Failed,
}

/// Durable identifier for one strict signing session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictSigningSessionId(pub [u8; 32]);

/// Durable coarse phase persisted by [`StrictSigningSession`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrictSigningCursorPhase {
    /// Session has been initialized but token consumption has not completed.
    Started,
    /// Every token in the fixed batch has been durably consumed.
    TokensConsumed,
    /// Session returned one verified FIPS signature.
    Finished,
    /// Session failed and must not be resumed with the same token batch.
    Failed,
}

/// Durable runtime slot for future distributed strict IT-MPC phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrictSigningRuntimeSlot {
    /// Compute private `[z_j] = [y_j] + c_j*[s1]` vectors.
    ResponsePreparation,
    /// Evaluate private response norm predicates.
    ResponseBoundChecks,
    /// Evaluate private HighBits/hint/hint-weight predicates.
    HintChecks,
    /// Combine pass bits and select a valid candidate by public priority.
    PrivateSelection,
    /// Open only the selected valid signature material.
    SelectedOpening,
}

impl StrictSigningRuntimeSlot {
    /// Returns the production wire runtime slot for this strict signing phase.
    pub const fn wire_slot(self) -> StrictSignMpcSlot {
        match self {
            Self::ResponsePreparation => StrictSignMpcSlot::PrepareCandidateShares,
            Self::ResponseBoundChecks => StrictSignMpcSlot::BoundChecks,
            Self::HintChecks => StrictSignMpcSlot::HintChecks,
            Self::PrivateSelection => StrictSignMpcSlot::PrivateSelection,
            Self::SelectedOpening => StrictSignMpcSlot::SelectedOpening,
        }
    }

    /// Parses a production wire runtime slot.
    pub const fn from_wire_slot(slot: StrictSignMpcSlot) -> Self {
        match slot {
            StrictSignMpcSlot::PrepareCandidateShares => Self::ResponsePreparation,
            StrictSignMpcSlot::BoundChecks => Self::ResponseBoundChecks,
            StrictSignMpcSlot::HintChecks => Self::HintChecks,
            StrictSignMpcSlot::PrivateSelection => Self::PrivateSelection,
            StrictSignMpcSlot::SelectedOpening => Self::SelectedOpening,
        }
    }
}

/// Canonical strict signing runtime slots.
pub const STRICT_SIGNING_RUNTIME_SLOTS: &[StrictSigningRuntimeSlot] = &[
    StrictSigningRuntimeSlot::ResponsePreparation,
    StrictSigningRuntimeSlot::ResponseBoundChecks,
    StrictSigningRuntimeSlot::HintChecks,
    StrictSigningRuntimeSlot::PrivateSelection,
    StrictSigningRuntimeSlot::SelectedOpening,
];

/// Persisted strict signing phase cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictSigningSessionCursor {
    /// Deterministic public session id.
    pub session_id: StrictSigningSessionId,
    /// Current coarse phase.
    pub phase: StrictSigningCursorPhase,
    /// Future distributed runtime slot, when inside private IT-MPC work.
    pub runtime_slot: Option<StrictSigningRuntimeSlot>,
    /// Hash of the public strict signing request.
    pub request_hash: [u8; 32],
    /// Token ids bound to this fixed signing batch.
    pub token_session_ids: Vec<SessionId>,
    /// Selected signature hash, present only after success.
    pub final_signature_hash: Option<[u8; 32]>,
    /// Hashes of accepted strict MPC wire messages.
    pub accepted_wire_message_hashes: Vec<[u8; 32]>,
    /// Hashes of queued outbound strict MPC wire messages.
    pub outbound_wire_message_hashes: Vec<[u8; 32]>,
    /// Strict MPC wire transcript hash.
    pub wire_transcript_hash: [u8; 32],
    /// Runtime slots completed through the distributed strict MPC boundary.
    pub completed_runtime_slots: Vec<StrictSigningRuntimeSlot>,
    /// Per-slot strict MPC runtime progress.
    pub runtime_slot_progress: Vec<StrictSigningRuntimeSlotProgress>,
}

/// Durable progress for one strict signing runtime slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictSigningRuntimeSlotProgress {
    /// Runtime slot.
    pub slot: StrictSigningRuntimeSlot,
    /// Slot-local phase accepted for this slot.
    pub phase: u8,
    /// Senders accepted for this slot and phase.
    pub accepted_senders: Vec<PartyId>,
    /// Outbound messages queued for this slot.
    pub outbound_messages: u32,
    /// Slot-local transcript hash.
    pub transcript_hash: [u8; 32],
    /// Whether the slot completed.
    pub completed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StrictSigningWireRecord {
    hash: [u8; 32],
    slot: StrictSigningRuntimeSlot,
    phase: u8,
    sender: PartyId,
    receiver: Option<PartyId>,
    payload: StrictSignMpcPayload,
}

/// Result of handling one strict signing distributed-runtime message.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StrictSigningRuntimeStep {
    /// Runtime slot completed by this step, if any.
    pub completed_slot: Option<StrictSigningRuntimeSlot>,
    /// Outbound strict MPC messages generated by this step.
    pub outbound: Vec<StrictSigningOutbound>,
}

/// Slot-driven distributed runtime boundary for strict signing.
///
/// Implementations consume decoded `StrictSignMpcPayload` messages, emit
/// strict MPC wire messages through the session, and report slot completion.
/// They must not expose unselected candidate responses, private pass bits, or
/// failure reasons in returned messages or errors.
///
/// This is a transport/session boundary, not a second strict-signing
/// implementation. Production runtimes must adapt the canonical response
/// preparation, bound-check, hint-check, private-selection, and selected-opening
/// component traits instead of reimplementing those algorithms here.
pub trait StrictSigningDistributedRuntime {
    /// Returns whether this runtime accepts strict MPC wire messages.
    ///
    /// Direct component-stack signing returns false so valid distributed
    /// runtime traffic cannot be silently persisted when no distributed runtime
    /// has been installed.
    fn accepts_runtime_messages(&self) -> bool {
        true
    }

    /// Handles one authenticated private strict MPC payload.
    fn handle_private_mpc(
        &mut self,
        sender: PartyId,
        payload: &StrictSignMpcPayload,
    ) -> Result<StrictSigningRuntimeStep, OnlineError>;

    /// Handles one reliable-broadcast strict MPC payload.
    fn handle_broadcast_mpc(
        &mut self,
        sender: PartyId,
        payload: &StrictSignMpcPayload,
    ) -> Result<StrictSigningRuntimeStep, OnlineError>;
}

/// Direct component-stack adapter used when strict signing is executed through
/// [`StrictPrivateSigningBackend`] rather than a distributed IT-MPC runtime.
///
/// This adapter deliberately rejects strict MPC wire messages. A caller that
/// wants app-driven distributed strict signing must install an explicit runtime
/// with [`StrictSigningSession::start_with_runtime`] or
/// [`StrictSigningSession::start_with_cursor_store_and_runtime`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectStrictSigningComponentRuntime;

impl StrictSigningDistributedRuntime for DirectStrictSigningComponentRuntime {
    fn accepts_runtime_messages(&self) -> bool {
        false
    }

    fn handle_private_mpc(
        &mut self,
        _sender: PartyId,
        _payload: &StrictSignMpcPayload,
    ) -> Result<StrictSigningRuntimeStep, OnlineError> {
        Err(OnlineError::UnexpectedStrictSigningPrivateMessage)
    }

    fn handle_broadcast_mpc(
        &mut self,
        _sender: PartyId,
        _payload: &StrictSignMpcPayload,
    ) -> Result<StrictSigningRuntimeStep, OnlineError> {
        Err(OnlineError::UnexpectedStrictSigningBroadcast)
    }
}

/// Durable strict signing cursor persistence API.
pub trait StrictSigningSessionStore {
    /// Persists the newest cursor state.
    fn persist_cursor(&mut self, cursor: &StrictSigningSessionCursor) -> Result<(), OnlineError>;

    /// Loads the newest cursor for `session_id`, if present.
    fn load_cursor(
        &self,
        session_id: StrictSigningSessionId,
    ) -> Result<Option<StrictSigningSessionCursor>, OnlineError>;
}

/// Observer used by strict signing runtimes to persist each private phase slot.
pub trait StrictSigningRuntimeObserver {
    /// Records entry into one runtime slot.
    fn enter_runtime_slot(&mut self, slot: StrictSigningRuntimeSlot) -> Result<(), OnlineError>;
}

/// Observer that discards runtime slot updates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoopStrictSigningRuntimeObserver;

impl StrictSigningRuntimeObserver for NoopStrictSigningRuntimeObserver {
    fn enter_runtime_slot(&mut self, _slot: StrictSigningRuntimeSlot) -> Result<(), OnlineError> {
        Ok(())
    }
}

/// In-memory strict signing cursor store for tests and embedding prototypes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StrictSigningCursorMemoryStore {
    cursors: Vec<StrictSigningSessionCursor>,
}

struct StrictSigningCursorObserver<'a, S>
where
    S: StrictSigningSessionStore,
{
    store: &'a mut S,
    cursor: StrictSigningSessionCursor,
}

impl<S> StrictSigningRuntimeObserver for StrictSigningCursorObserver<'_, S>
where
    S: StrictSigningSessionStore,
{
    fn enter_runtime_slot(&mut self, slot: StrictSigningRuntimeSlot) -> Result<(), OnlineError> {
        self.cursor.phase = StrictSigningCursorPhase::TokensConsumed;
        self.cursor.runtime_slot = Some(slot);
        self.cursor.final_signature_hash = None;
        self.store.persist_cursor(&self.cursor)
    }
}

impl StrictSigningCursorMemoryStore {
    /// Creates an empty cursor store.
    pub const fn new() -> Self {
        Self {
            cursors: Vec::new(),
        }
    }
}

impl StrictSigningSessionStore for StrictSigningCursorMemoryStore {
    fn persist_cursor(&mut self, cursor: &StrictSigningSessionCursor) -> Result<(), OnlineError> {
        if let Some(existing) = self
            .cursors
            .iter_mut()
            .find(|existing| existing.session_id == cursor.session_id)
        {
            *existing = cursor.clone();
        } else {
            self.cursors.push(cursor.clone());
        }
        Ok(())
    }

    fn load_cursor(
        &self,
        session_id: StrictSigningSessionId,
    ) -> Result<Option<StrictSigningSessionCursor>, OnlineError> {
        Ok(self
            .cursors
            .iter()
            .find(|cursor| cursor.session_id == session_id)
            .cloned())
    }
}

/// File-backed strict signing cursor log.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileStrictSigningSessionStore {
    path: std::path::PathBuf,
    inner: StrictSigningCursorMemoryStore,
}

#[cfg(feature = "std")]
impl FileStrictSigningSessionStore {
    /// Opens or creates an append-only cursor log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, OnlineError> {
        let path = path.into();
        let mut inner = StrictSigningCursorMemoryStore::new();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let cursor = parse_strict_signing_cursor_line(line).ok_or(
                        OnlineError::StrictSigningCursorStoreCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    inner.persist_cursor(&cursor)?;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| OnlineError::StrictSigningCursorStoreIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| OnlineError::StrictSigningCursorStoreIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(OnlineError::StrictSigningCursorStoreIo { operation: "read" });
            }
        }
        Ok(Self { path, inner })
    }
}

#[cfg(feature = "std")]
impl StrictSigningSessionStore for FileStrictSigningSessionStore {
    fn persist_cursor(&mut self, cursor: &StrictSigningSessionCursor) -> Result<(), OnlineError> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| OnlineError::StrictSigningCursorStoreIo { operation: "open" })?;
        use std::io::Write;
        writeln!(file, "{}", format_strict_signing_cursor_line(cursor))
            .map_err(|_| OnlineError::StrictSigningCursorStoreIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| OnlineError::StrictSigningCursorStoreIo { operation: "sync" })?;
        self.inner.persist_cursor(cursor)
    }

    fn load_cursor(
        &self,
        session_id: StrictSigningSessionId,
    ) -> Result<Option<StrictSigningSessionCursor>, OnlineError> {
        self.inner.load_cursor(session_id)
    }
}

/// Production-facing strict signing session facade.
///
/// This is the narrow API applications should drive. It owns the request,
/// certified token batch, consumed-token store, private signing backend, final
/// verifier, and counters. The current implementation emits no transport
/// messages because the distributed vector IT-MPC runtime is still the next
/// backend layer; unexpected private/broadcast messages are rejected so callers
/// cannot accidentally mix paper-fast partial-signature traffic into strict
/// production signing.
pub struct StrictSigningSession<
    P,
    B,
    S,
    V,
    C = StrictSigningCursorMemoryStore,
    R = DirectStrictSigningComponentRuntime,
> where
    P: MlDsaParams,
    B: StrictPrivateSigningBackend<P>,
    S: TokenConsumptionStore,
    V: FinalVerifier,
    C: StrictSigningSessionStore,
    R: StrictSigningDistributedRuntime,
{
    session_id: StrictSigningSessionId,
    token_session_ids: Vec<SessionId>,
    request: StrictSignRequest,
    tr: [u8; 64],
    batch: Option<BccCertifiedTokenBatch>,
    consumed: S,
    cursor_store: C,
    counters: SigningCounters,
    backend: B,
    verifier: V,
    phase: StrictSigningSessionPhase,
    final_signature: Option<FinalSignature>,
    runtime: R,
    accepted_wire_messages: Vec<StrictSigningWireRecord>,
    outbound_wire_messages: Vec<StrictSigningWireRecord>,
    completed_runtime_slots: Vec<StrictSigningRuntimeSlot>,
    runtime_slot_progress: Vec<StrictSigningRuntimeSlotProgress>,
    outbound_queue: Vec<StrictSigningOutbound>,
    wire_transcript_hash: [u8; 32],
    _params: PhantomData<P>,
}

impl<P, B, S, V>
    StrictSigningSession<
        P,
        B,
        S,
        V,
        StrictSigningCursorMemoryStore,
        DirectStrictSigningComponentRuntime,
    >
where
    P: MlDsaParams,
    B: StrictPrivateSigningBackend<P>,
    S: TokenConsumptionStore,
    V: FinalVerifier,
{
    /// Starts one strict signing session.
    pub fn start(
        request: StrictSignRequest,
        tr: [u8; 64],
        batch: BccCertifiedTokenBatch,
        consumed: S,
        backend: B,
        verifier: V,
    ) -> Result<Self, OnlineError> {
        Self::start_with_cursor_store(
            request,
            tr,
            batch,
            consumed,
            StrictSigningCursorMemoryStore::new(),
            backend,
            verifier,
        )
    }
}

impl<P, Source, Store, V>
    StrictSigningSession<
        P,
        ProductionStrictRuntimeSelectedOpeningArtifactBackend<Source>,
        Store,
        V,
        StrictSigningCursorMemoryStore,
        DirectStrictSigningComponentRuntime,
    >
where
    P: MlDsaParams,
    Source: StrictRuntimeSelectedOpeningArtifactSource<P>,
    Store: TokenConsumptionStore,
    V: FinalVerifier,
{
    /// Starts one release-capable strict signing session.
    ///
    /// This constructor requires a [`ProductionStrictRuntimeSelectedOpeningBackend`]
    /// that consumes the selected-opening artifact emitted by the distributed
    /// vector runtime. Dev/test callers may still use [`StrictSigningSession::start`],
    /// but release builds also re-check the selected-output certificate in
    /// [`StrictSigningSession::finish`].
    pub fn start_release_validated(
        request: StrictSignRequest,
        tr: [u8; 64],
        batch: BccCertifiedTokenBatch,
        consumed: Store,
        backend: ProductionStrictRuntimeSelectedOpeningArtifactBackend<Source>,
        verifier: V,
    ) -> Result<Self, OnlineError> {
        Self::start(request, tr, batch, consumed, backend, verifier)
    }
}

impl<P, B, S, V>
    StrictSigningSession<
        P,
        B,
        S,
        V,
        StrictSigningCursorMemoryStore,
        DirectStrictSigningComponentRuntime,
    >
where
    P: MlDsaParams,
    B: StrictPrivateSigningBackend<P>,
    S: TokenConsumptionStore,
    V: FinalVerifier,
{
    /// Starts one strict signing session with an explicit distributed runtime.
    pub fn start_with_runtime<R>(
        request: StrictSignRequest,
        tr: [u8; 64],
        batch: BccCertifiedTokenBatch,
        consumed: S,
        runtime: R,
        backend: B,
        verifier: V,
    ) -> Result<StrictSigningSession<P, B, S, V, StrictSigningCursorMemoryStore, R>, OnlineError>
    where
        R: StrictSigningDistributedRuntime,
    {
        StrictSigningSession::start_with_cursor_store_and_runtime(
            request,
            tr,
            batch,
            consumed,
            StrictSigningCursorMemoryStore::new(),
            runtime,
            backend,
            verifier,
        )
    }
}

impl<P, B, S, V, C> StrictSigningSession<P, B, S, V, C, DirectStrictSigningComponentRuntime>
where
    P: MlDsaParams,
    B: StrictPrivateSigningBackend<P>,
    S: TokenConsumptionStore,
    V: FinalVerifier,
    C: StrictSigningSessionStore,
{
    /// Starts one strict signing session with an explicit durable cursor store.
    pub fn start_with_cursor_store(
        request: StrictSignRequest,
        tr: [u8; 64],
        batch: BccCertifiedTokenBatch,
        consumed: S,
        cursor_store: C,
        backend: B,
        verifier: V,
    ) -> Result<Self, OnlineError> {
        Self::start_with_cursor_store_and_runtime(
            request,
            tr,
            batch,
            consumed,
            cursor_store,
            DirectStrictSigningComponentRuntime,
            backend,
            verifier,
        )
    }
}

impl<P, B, S, V, C, R> StrictSigningSession<P, B, S, V, C, R>
where
    P: MlDsaParams,
    B: StrictPrivateSigningBackend<P>,
    S: TokenConsumptionStore,
    V: FinalVerifier,
    C: StrictSigningSessionStore,
    R: StrictSigningDistributedRuntime,
{
    /// Starts one strict signing session with explicit cursor store and distributed runtime.
    pub fn start_with_cursor_store_and_runtime(
        request: StrictSignRequest,
        tr: [u8; 64],
        batch: BccCertifiedTokenBatch,
        consumed: S,
        cursor_store: C,
        runtime: R,
        backend: B,
        verifier: V,
    ) -> Result<Self, OnlineError> {
        validate_strict_sign_request::<P>(&request, &batch)?;
        let token_session_ids = batch.session_ids();
        let session_id = strict_signing_session_id(&request, &token_session_ids);
        let mut session = Self {
            session_id,
            token_session_ids,
            request,
            tr,
            batch: Some(batch),
            consumed,
            cursor_store,
            counters: SigningCounters::default(),
            backend,
            verifier,
            phase: StrictSigningSessionPhase::Ready,
            final_signature: None,
            runtime,
            accepted_wire_messages: Vec::new(),
            outbound_wire_messages: Vec::new(),
            completed_runtime_slots: Vec::new(),
            runtime_slot_progress: Vec::new(),
            outbound_queue: Vec::new(),
            wire_transcript_hash: [0u8; 32],
            _params: PhantomData,
        };
        if let Some(existing) = session.cursor_store.load_cursor(session_id)? {
            if existing.phase != StrictSigningCursorPhase::Started {
                return Err(OnlineError::StrictSigningSessionAlreadyFinished);
            }
            session.hydrate_started_cursor(existing);
        } else {
            session.persist_cursor(StrictSigningCursorPhase::Started, None, None)?;
        }
        Ok(session)
    }

    /// Durable strict signing session id.
    pub const fn session_id(&self) -> StrictSigningSessionId {
        self.session_id
    }

    /// Current coarse session phase.
    pub const fn phase(&self) -> StrictSigningSessionPhase {
        self.phase
    }

    /// Public signing counters accumulated by this session.
    pub const fn counters(&self) -> &SigningCounters {
        &self.counters
    }

    /// Loads the latest persisted cursor for this session.
    pub fn persisted_cursor(&self) -> Result<Option<StrictSigningSessionCursor>, OnlineError> {
        self.cursor_store.load_cursor(self.session_id)
    }

    /// Returns the next outbound application transport message.
    pub fn next_outbound(&mut self) -> Option<StrictSigningOutbound> {
        if self.outbound_queue.is_empty() {
            None
        } else {
            Some(self.outbound_queue.remove(0))
        }
    }

    /// Queues one strict signing private MPC message for application delivery.
    pub fn queue_private_mpc_message(
        &mut self,
        receiver: PartyId,
        message: WireMessage,
    ) -> Result<(), OnlineError> {
        let record = self.validate_strict_mpc_wire_message(&message, Some(receiver))?;
        if record.receiver != Some(receiver) {
            return Err(OnlineError::StrictSigningWireMessageRejected);
        }
        if self
            .outbound_wire_messages
            .iter()
            .any(|known| known.hash == record.hash)
        {
            return Err(OnlineError::StrictSigningWireReplay);
        }
        self.record_runtime_slot_outbound(&record)?;
        self.outbound_wire_messages.push(record);
        self.outbound_queue
            .push(StrictSigningOutbound::Private { receiver, message });
        self.persist_cursor(
            StrictSigningCursorPhase::Started,
            self.outbound_wire_messages.last().map(|record| record.slot),
            None,
        )
    }

    /// Queues one strict signing MPC broadcast message for application delivery.
    pub fn queue_broadcast_mpc_message(&mut self, message: WireMessage) -> Result<(), OnlineError> {
        let record = self.validate_strict_mpc_wire_message(&message, None)?;
        if record.receiver.is_some() {
            return Err(OnlineError::StrictSigningWireMessageRejected);
        }
        if self
            .outbound_wire_messages
            .iter()
            .any(|known| known.hash == record.hash)
        {
            return Err(OnlineError::StrictSigningWireReplay);
        }
        self.record_runtime_slot_outbound(&record)?;
        self.outbound_wire_messages.push(record);
        self.outbound_queue
            .push(StrictSigningOutbound::Broadcast { message });
        self.persist_cursor(
            StrictSigningCursorPhase::Started,
            self.outbound_wire_messages.last().map(|record| record.slot),
            None,
        )
    }

    /// Number of strict MPC wire messages accepted by this session.
    pub fn accepted_wire_message_count(&self) -> usize {
        self.accepted_wire_messages.len()
    }

    /// Number of queued outbound strict MPC wire messages.
    pub fn outbound_wire_message_count(&self) -> usize {
        self.outbound_queue.len()
    }

    /// Current strict MPC wire transcript hash.
    pub const fn wire_transcript_hash(&self) -> [u8; 32] {
        self.wire_transcript_hash
    }

    /// Runtime slots completed through the distributed runtime boundary.
    pub fn completed_runtime_slots(&self) -> &[StrictSigningRuntimeSlot] {
        &self.completed_runtime_slots
    }

    /// Per-slot strict MPC runtime progress.
    pub fn runtime_slot_progress(&self) -> &[StrictSigningRuntimeSlotProgress] {
        &self.runtime_slot_progress
    }

    /// Injects one application-authenticated private strict MPC message.
    pub fn handle_private(
        &mut self,
        sender: PartyId,
        message: WireMessage,
    ) -> Result<(), OnlineError> {
        let record = self.validate_strict_mpc_wire_message(&message, None)?;
        if !self.runtime.accepts_runtime_messages() {
            return Err(OnlineError::UnexpectedStrictSigningPrivateMessage);
        }
        if record.sender != sender || record.receiver.is_none() {
            return Err(OnlineError::UnexpectedStrictSigningPrivateMessage);
        }
        self.accept_strict_mpc_wire_record(record)?;
        let step = self.runtime.handle_private_mpc(
            sender,
            &self
                .accepted_wire_messages
                .last()
                .expect("just accepted")
                .payload,
        )?;
        self.apply_runtime_step(step)
    }

    /// Injects one reliable-broadcast strict MPC message.
    pub fn handle_broadcast(&mut self, message: WireMessage) -> Result<(), OnlineError> {
        let record = self.validate_strict_mpc_wire_message(&message, None)?;
        if !self.runtime.accepts_runtime_messages() {
            return Err(OnlineError::UnexpectedStrictSigningBroadcast);
        }
        if record.receiver.is_some() {
            return Err(OnlineError::UnexpectedStrictSigningBroadcast);
        }
        self.accept_strict_mpc_wire_record(record)?;
        let accepted = self.accepted_wire_messages.last().expect("just accepted");
        let step = self
            .runtime
            .handle_broadcast_mpc(accepted.sender, &accepted.payload)?;
        self.apply_runtime_step(step)
    }

    /// Finishes strict signing and returns one verified FIPS signature.
    ///
    /// Tokens are durably consumed inside this call before the private backend
    /// receives token material. If the call fails after consumption, the
    /// session moves to `Failed` and cannot be retried with the same batch.
    pub fn finish(&mut self) -> Result<FinalSignature, OnlineError> {
        if self.phase != StrictSigningSessionPhase::Ready {
            return Err(OnlineError::StrictSigningSessionAlreadyFinished);
        }
        let batch = self
            .batch
            .take()
            .ok_or(OnlineError::StrictSigningSessionAlreadyFinished)?;
        self.counters.attempts = self.counters.attempts.saturating_add(1);

        for session_id in batch.session_ids() {
            if let Err(err) = self.consumed.persist_consumed(session_id) {
                self.phase = StrictSigningSessionPhase::Failed;
                self.persist_cursor(StrictSigningCursorPhase::Failed, None, None)?;
                return Err(err);
            }
            self.counters.tokens_consumed = self.counters.tokens_consumed.saturating_add(1);
        }
        self.persist_cursor(StrictSigningCursorPhase::TokensConsumed, None, None)?;

        let strict_token_count = batch.len();
        let consumed_batch = ConsumedBccCertifiedTokenBatch {
            signer_set: batch.signer_set,
            tokens: batch.tokens,
        };
        let observer_cursor = self.cursor(StrictSigningCursorPhase::TokensConsumed, None, None);
        let mut observer = StrictSigningCursorObserver {
            store: &mut self.cursor_store,
            cursor: observer_cursor,
        };
        let result =
            self.backend
                .sign_consumed_batch_with_observer(
                    &self.request,
                    &self.tr,
                    consumed_batch,
                    &mut observer,
                )
                .and_then(|selected| {
                    if selected.evidence.token_count != strict_token_count {
                        return Err(OnlineError::StrictResponseCheckShapeMismatch);
                    }
                    selected
                        .evidence
                        .response_check_counters
                        .validate_for_batch(strict_token_count)?;
                    #[cfg(feature = "production-release-checks")]
                    {
                        if !selected.vector_runtime_certificate.as_ref().is_some_and(
                            |certificate| certificate.is_selected_opening_artifact_bound(),
                        ) {
                            return Err(OnlineError::StrictSigningRuntimeSlotIncomplete);
                        }
                    }
                    let verify_request = SignRequest {
                        protocol_version: self.request.protocol_version,
                        suite: self.request.suite,
                        session_id: SessionId([0u8; 32]),
                        signing_set: self.request.signing_set.clone(),
                        message: self.request.message.clone(),
                        external_mu: self.request.external_mu,
                        context: self.request.context.clone(),
                        token_transcript_hash: TranscriptHash([0u8; 32]),
                    };
                    if !self
                        .verifier
                        .verify_final(&verify_request, &selected.signature)
                    {
                        self.counters.final_verify_failures =
                            self.counters.final_verify_failures.saturating_add(1);
                        return Err(OnlineError::FinalVerifyFailed);
                    }
                    self.counters.signatures_returned =
                        self.counters.signatures_returned.saturating_add(1);
                    Ok(selected.signature)
                });
        match result {
            Ok(signature) => {
                self.phase = StrictSigningSessionPhase::Finished;
                self.final_signature = Some(signature.clone());
                self.persist_cursor(
                    StrictSigningCursorPhase::Finished,
                    None,
                    Some(strict_signature_hash(&signature)),
                )?;
                Ok(signature)
            }
            Err(err) => {
                self.phase = StrictSigningSessionPhase::Failed;
                self.persist_cursor(StrictSigningCursorPhase::Failed, None, None)?;
                Err(err)
            }
        }
    }

    fn cursor(
        &self,
        phase: StrictSigningCursorPhase,
        runtime_slot: Option<StrictSigningRuntimeSlot>,
        final_signature_hash: Option<[u8; 32]>,
    ) -> StrictSigningSessionCursor {
        StrictSigningSessionCursor {
            session_id: self.session_id,
            phase,
            runtime_slot,
            request_hash: strict_signing_request_hash(&self.request),
            token_session_ids: self.token_session_ids.clone(),
            final_signature_hash,
            accepted_wire_message_hashes: self
                .accepted_wire_messages
                .iter()
                .map(|record| record.hash)
                .collect(),
            outbound_wire_message_hashes: self
                .outbound_wire_messages
                .iter()
                .map(|record| record.hash)
                .collect(),
            wire_transcript_hash: self.wire_transcript_hash,
            completed_runtime_slots: self.completed_runtime_slots.clone(),
            runtime_slot_progress: self.runtime_slot_progress.clone(),
        }
    }

    fn persist_cursor(
        &mut self,
        phase: StrictSigningCursorPhase,
        runtime_slot: Option<StrictSigningRuntimeSlot>,
        final_signature_hash: Option<[u8; 32]>,
    ) -> Result<(), OnlineError> {
        let cursor = self.cursor(phase, runtime_slot, final_signature_hash);
        self.cursor_store.persist_cursor(&cursor)
    }

    /// Consumes the session and returns owned components for persistence or
    /// inspection by the embedding application.
    pub fn into_parts(self) -> (S, C, B, V, SigningCounters, Option<FinalSignature>) {
        (
            self.consumed,
            self.cursor_store,
            self.backend,
            self.verifier,
            self.counters,
            self.final_signature,
        )
    }

    /// Consumes the session and also returns the distributed runtime.
    pub fn into_parts_with_runtime(
        self,
    ) -> (S, C, R, B, V, SigningCounters, Option<FinalSignature>) {
        (
            self.consumed,
            self.cursor_store,
            self.runtime,
            self.backend,
            self.verifier,
            self.counters,
            self.final_signature,
        )
    }

    fn accept_strict_mpc_wire_record(
        &mut self,
        record: StrictSigningWireRecord,
    ) -> Result<(), OnlineError> {
        if self
            .accepted_wire_messages
            .iter()
            .any(|known| known.hash == record.hash)
        {
            return Err(OnlineError::StrictSigningWireReplay);
        }
        self.record_runtime_slot_accept(&record)?;
        self.wire_transcript_hash =
            strict_signing_wire_transcript_hash(self.wire_transcript_hash, record.hash);
        let slot = record.slot;
        self.accepted_wire_messages.push(record);
        self.persist_cursor(StrictSigningCursorPhase::Started, Some(slot), None)
    }

    fn record_runtime_slot_accept(
        &mut self,
        record: &StrictSigningWireRecord,
    ) -> Result<(), OnlineError> {
        if let Some(progress) = self
            .runtime_slot_progress
            .iter_mut()
            .find(|progress| progress.slot == record.slot)
        {
            if progress.completed {
                return Err(OnlineError::StrictSigningRuntimeSlotOutOfOrder);
            }
            if progress.phase != record.phase {
                return Err(OnlineError::StrictSigningRuntimeSlotPhaseMismatch);
            }
            if progress.accepted_senders.contains(&record.sender) {
                return Err(OnlineError::StrictSigningRuntimeDuplicateSender);
            }
            progress.accepted_senders.push(record.sender);
            progress.accepted_senders.sort_by_key(|party| party.0);
            progress.transcript_hash =
                strict_signing_wire_transcript_hash(progress.transcript_hash, record.hash);
        } else {
            self.runtime_slot_progress
                .push(StrictSigningRuntimeSlotProgress {
                    slot: record.slot,
                    phase: record.phase,
                    accepted_senders: vec![record.sender],
                    outbound_messages: 0,
                    transcript_hash: strict_signing_wire_transcript_hash([0u8; 32], record.hash),
                    completed: false,
                });
        }
        Ok(())
    }

    fn record_runtime_slot_outbound(
        &mut self,
        record: &StrictSigningWireRecord,
    ) -> Result<(), OnlineError> {
        if let Some(progress) = self
            .runtime_slot_progress
            .iter_mut()
            .find(|progress| progress.slot == record.slot)
        {
            if progress.phase != record.phase {
                return Err(OnlineError::StrictSigningRuntimeSlotPhaseMismatch);
            }
            progress.outbound_messages = progress.outbound_messages.saturating_add(1);
        } else {
            self.runtime_slot_progress
                .push(StrictSigningRuntimeSlotProgress {
                    slot: record.slot,
                    phase: record.phase,
                    accepted_senders: Vec::new(),
                    outbound_messages: 1,
                    transcript_hash: [0u8; 32],
                    completed: false,
                });
        }
        Ok(())
    }

    fn hydrate_started_cursor(&mut self, cursor: StrictSigningSessionCursor) {
        self.accepted_wire_messages = cursor
            .accepted_wire_message_hashes
            .iter()
            .copied()
            .map(strict_wire_record_placeholder)
            .collect();
        self.outbound_wire_messages = cursor
            .outbound_wire_message_hashes
            .iter()
            .copied()
            .map(strict_wire_record_placeholder)
            .collect();
        self.completed_runtime_slots = cursor.completed_runtime_slots;
        self.runtime_slot_progress = cursor.runtime_slot_progress;
        self.wire_transcript_hash = cursor.wire_transcript_hash;
    }

    fn apply_runtime_step(&mut self, step: StrictSigningRuntimeStep) -> Result<(), OnlineError> {
        for outbound in step.outbound {
            match outbound {
                StrictSigningOutbound::Private { receiver, message } => {
                    self.queue_private_mpc_message(receiver, message)?;
                }
                StrictSigningOutbound::Broadcast { message } => {
                    self.queue_broadcast_mpc_message(message)?;
                }
            }
        }
        if let Some(slot) = step.completed_slot {
            self.complete_runtime_slot(slot)?;
        }
        Ok(())
    }

    fn complete_runtime_slot(&mut self, slot: StrictSigningRuntimeSlot) -> Result<(), OnlineError> {
        let expected = STRICT_SIGNING_RUNTIME_SLOTS
            .get(self.completed_runtime_slots.len())
            .copied()
            .ok_or(OnlineError::StrictSigningRuntimeSlotOutOfOrder)?;
        if expected != slot {
            return Err(OnlineError::StrictSigningRuntimeSlotOutOfOrder);
        }
        let expected_senders = self.request.signing_set.clone();
        let progress = self
            .runtime_slot_progress
            .iter_mut()
            .find(|progress| progress.slot == slot)
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        if progress.completed {
            return Err(OnlineError::StrictSigningRuntimeSlotOutOfOrder);
        }
        let mut accepted = progress.accepted_senders.clone();
        accepted.sort_by_key(|party| party.0);
        let mut expected_senders = expected_senders;
        expected_senders.sort_by_key(|party| party.0);
        if accepted != expected_senders {
            return Err(OnlineError::StrictSigningRuntimeSlotIncomplete);
        }
        progress.completed = true;
        self.completed_runtime_slots.push(slot);
        self.persist_cursor(StrictSigningCursorPhase::Started, Some(slot), None)
    }

    fn validate_strict_mpc_wire_message(
        &self,
        message: &WireMessage,
        expected_receiver: Option<PartyId>,
    ) -> Result<StrictSigningWireRecord, OnlineError> {
        if self.phase != StrictSigningSessionPhase::Ready {
            return Err(OnlineError::StrictSigningSessionAlreadyFinished);
        }
        if message.header.round != RoundId::StrictSignMpc
            || message.header.payload_kind != PayloadKind::StrictSignMpc
            || message.header.session_id != self.session_id.0
            || message.header.signing_set_hash != strict_wire_signing_set_hash(&self.request)
            || message.header.suite != strict_wire_suite::<P>()?
        {
            return Err(OnlineError::StrictSigningWireMessageRejected);
        }
        let sender = PartyId(message.header.sender_party_id);
        if !self.request.signing_set.contains(&sender) {
            return Err(OnlineError::StrictSigningWireMessageRejected);
        }
        let payload = decode_strict_sign_mpc_payload(&message.payload)
            .map_err(|_| OnlineError::StrictSigningWireMessageRejected)?;
        let receiver = if payload.receiver_party_id == 0 {
            None
        } else {
            let receiver = PartyId(payload.receiver_party_id);
            if !self.request.signing_set.contains(&receiver) {
                return Err(OnlineError::StrictSigningWireMessageRejected);
            }
            Some(receiver)
        };
        if let Some(expected) = expected_receiver {
            if receiver != Some(expected) {
                return Err(OnlineError::StrictSigningWireMessageRejected);
            }
        }
        Ok(StrictSigningWireRecord {
            hash: strict_signing_wire_message_hash(message)?,
            slot: StrictSigningRuntimeSlot::from_wire_slot(payload.slot),
            phase: payload.phase,
            sender,
            receiver,
            payload,
        })
    }
}

/// Ordered phases inside the strict private response-check circuit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrictResponseCheckPhase {
    /// Public request/token metadata has been derived for every consumed token.
    DeriveCandidateMetadata,
    /// Secret-shared response vectors have been computed.
    ComputeSharedResponses,
    /// Private response-bound predicates have been evaluated.
    CheckResponseBounds,
    /// Private hint and hint-weight predicates have been evaluated.
    CheckHints,
    /// Private per-candidate pass bits have been combined.
    CombinePrivatePassBits,
    /// A valid candidate has been selected by public priority inside MPC.
    SelectByPriority,
    /// Only the selected candidate has been opened.
    OpenSelected,
}

/// Canonical strict response-check phase order.
pub const STRICT_RESPONSE_CHECK_PHASES: &[StrictResponseCheckPhase] = &[
    StrictResponseCheckPhase::DeriveCandidateMetadata,
    StrictResponseCheckPhase::ComputeSharedResponses,
    StrictResponseCheckPhase::CheckResponseBounds,
    StrictResponseCheckPhase::CheckHints,
    StrictResponseCheckPhase::CombinePrivatePassBits,
    StrictResponseCheckPhase::SelectByPriority,
    StrictResponseCheckPhase::OpenSelected,
];

/// State machine for one strict private response-check circuit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictResponseCheckPhaseDriver {
    next_index: usize,
    token_count: Option<usize>,
    selected: bool,
}

impl StrictResponseCheckPhaseDriver {
    /// Starts a response-check driver.
    pub const fn new() -> Self {
        Self {
            next_index: 0,
            token_count: None,
            selected: false,
        }
    }

    /// Returns the next required response-check phase.
    pub fn next_phase(&self) -> Option<StrictResponseCheckPhase> {
        STRICT_RESPONSE_CHECK_PHASES.get(self.next_index).copied()
    }

    /// Records public metadata derivation for every candidate.
    pub fn accept_metadata(&mut self, count: usize) -> Result<(), OnlineError> {
        self.expect_phase(StrictResponseCheckPhase::DeriveCandidateMetadata)?;
        if count == 0 {
            return Err(OnlineError::EmptyTokenBatch);
        }
        self.token_count = Some(count);
        self.next_index += 1;
        Ok(())
    }

    /// Records private response-vector computation.
    pub fn accept_shared_responses(&mut self, count: usize) -> Result<(), OnlineError> {
        self.expect_phase(StrictResponseCheckPhase::ComputeSharedResponses)?;
        self.expect_count(count)?;
        self.next_index += 1;
        Ok(())
    }

    /// Records private response-bound checks.
    pub fn accept_response_bounds(&mut self, count: usize) -> Result<(), OnlineError> {
        self.expect_phase(StrictResponseCheckPhase::CheckResponseBounds)?;
        self.expect_count(count)?;
        self.next_index += 1;
        Ok(())
    }

    /// Records private hint and hint-weight checks.
    pub fn accept_hint_checks(&mut self, count: usize) -> Result<(), OnlineError> {
        self.expect_phase(StrictResponseCheckPhase::CheckHints)?;
        self.expect_count(count)?;
        self.next_index += 1;
        Ok(())
    }

    /// Records combining per-candidate private pass bits.
    pub fn accept_private_pass_bits(&mut self, count: usize) -> Result<(), OnlineError> {
        self.expect_phase(StrictResponseCheckPhase::CombinePrivatePassBits)?;
        self.expect_count(count)?;
        self.next_index += 1;
        Ok(())
    }

    /// Records private selection by public priority.
    pub fn accept_priority_selection(&mut self, selected: bool) -> Result<(), OnlineError> {
        self.expect_phase(StrictResponseCheckPhase::SelectByPriority)?;
        if !selected {
            return Err(OnlineError::GenericBatchFailure);
        }
        self.selected = true;
        self.next_index += 1;
        Ok(())
    }

    /// Records selected-only opening.
    pub fn accept_selected_opening(&mut self) -> Result<(), OnlineError> {
        self.expect_phase(StrictResponseCheckPhase::OpenSelected)?;
        if !self.selected {
            return Err(OnlineError::StrictResponseCheckPhaseOutOfOrder);
        }
        self.next_index += 1;
        Ok(())
    }

    /// Builds safe response-check counters for this completed run.
    pub fn counters(&self) -> Result<StrictResponseCheckCounters, OnlineError> {
        if self.next_phase().is_some() {
            return Err(OnlineError::StrictResponseCheckPhaseOutOfOrder);
        }
        let token_count = self
            .token_count
            .ok_or(OnlineError::StrictResponseCheckPhaseOutOfOrder)?;
        Ok(StrictResponseCheckCounters {
            candidates: token_count,
            private_response_vectors: token_count,
            z_bound_checks: token_count,
            hint_weight_checks: token_count,
            validity_bits: token_count,
            selected_openings: 1,
        })
    }

    fn expect_phase(&self, expected: StrictResponseCheckPhase) -> Result<(), OnlineError> {
        if self.next_phase() == Some(expected) {
            Ok(())
        } else {
            Err(OnlineError::StrictResponseCheckPhaseOutOfOrder)
        }
    }

    fn expect_count(&self, got: usize) -> Result<(), OnlineError> {
        match self.token_count {
            Some(expected) if expected == got => Ok(()),
            _ => Err(OnlineError::StrictResponseCheckPhaseOutOfOrder),
        }
    }
}

impl Default for StrictResponseCheckPhaseDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal state machine for strict no-rejected-z signing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictSigningPhaseDriver {
    next_index: usize,
    token_count: Option<usize>,
    valid_candidate_selected: bool,
    selected_candidate_opened: bool,
}

impl StrictSigningPhaseDriver {
    /// Starts a strict-signing driver.
    pub const fn new() -> Self {
        Self {
            next_index: 0,
            token_count: None,
            valid_candidate_selected: false,
            selected_candidate_opened: false,
        }
    }

    /// Returns the next required phase.
    pub fn next_phase(&self) -> Option<StrictSigningPhase> {
        STRICT_SIGNING_PHASES.get(self.next_index).copied()
    }

    /// Records durable token-batch consumption.
    pub fn accept_consumed_batch(&mut self, token_count: usize) -> Result<(), OnlineError> {
        self.expect_phase(StrictSigningPhase::ConsumeTokenBatch)?;
        if token_count == 0 {
            return Err(OnlineError::EmptyTokenBatch);
        }
        self.token_count = Some(token_count);
        self.next_index += 1;
        Ok(())
    }

    /// Records local challenge derivation for every consumed token.
    pub fn accept_challenges(&mut self, challenge_count: usize) -> Result<(), OnlineError> {
        self.expect_phase(StrictSigningPhase::DeriveChallenges)?;
        self.expect_count(challenge_count)?;
        self.next_index += 1;
        Ok(())
    }

    /// Records private response computation for every consumed token.
    pub fn accept_private_responses(&mut self, response_count: usize) -> Result<(), OnlineError> {
        self.expect_phase(StrictSigningPhase::ComputePrivateResponses)?;
        self.expect_count(response_count)?;
        self.next_index += 1;
        Ok(())
    }

    /// Records private validity checks for every consumed token.
    pub fn accept_private_checks(&mut self, checked_count: usize) -> Result<(), OnlineError> {
        self.expect_phase(StrictSigningPhase::EvaluatePrivateChecks)?;
        self.expect_count(checked_count)?;
        self.next_index += 1;
        Ok(())
    }

    /// Records private random-priority candidate selection.
    pub fn accept_private_selection(&mut self, selected: bool) -> Result<(), OnlineError> {
        self.expect_phase(StrictSigningPhase::SelectPrivateCandidate)?;
        if !selected {
            return Err(OnlineError::GenericBatchFailure);
        }
        self.valid_candidate_selected = true;
        self.next_index += 1;
        Ok(())
    }

    /// Records opening only the selected valid candidate.
    pub fn accept_selected_opening(&mut self) -> Result<(), OnlineError> {
        self.expect_phase(StrictSigningPhase::OpenSelectedCandidate)?;
        if !self.valid_candidate_selected {
            return Err(OnlineError::StrictSigningPhaseOutOfOrder);
        }
        self.selected_candidate_opened = true;
        self.next_index += 1;
        Ok(())
    }

    /// Records final verification.
    pub fn accept_final_verify(&mut self, verified: bool) -> Result<(), OnlineError> {
        self.expect_phase(StrictSigningPhase::FinalVerify)?;
        if !self.selected_candidate_opened {
            return Err(OnlineError::StrictSigningPhaseOutOfOrder);
        }
        if !verified {
            return Err(OnlineError::FinalVerifyFailed);
        }
        self.next_index += 1;
        Ok(())
    }

    fn expect_phase(&self, expected: StrictSigningPhase) -> Result<(), OnlineError> {
        if self.next_phase() == Some(expected) {
            Ok(())
        } else {
            Err(OnlineError::StrictSigningPhaseOutOfOrder)
        }
    }

    fn expect_count(&self, got: usize) -> Result<(), OnlineError> {
        match self.token_count {
            Some(expected) if expected == got => Ok(()),
            _ => Err(OnlineError::StrictSigningPhaseOutOfOrder),
        }
    }
}

impl Default for StrictSigningPhaseDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// Private strict-signing backend.
///
/// Implementations must not open rejected candidate `z`, per-party `z_i`,
/// candidate hints, validity bits, or detailed private-check failure reasons.
/// When more than one candidate is privately valid, implementations should use
/// [`strict_candidate_priority`] to select the lowest-priority valid candidate
/// instead of selecting the first valid candidate.
pub trait StrictPrivateSigningBackend<P: MlDsaParams> {
    /// Computes one selected candidate from an already consumed token batch.
    fn sign_consumed_batch(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: ConsumedBccCertifiedTokenBatch,
    ) -> Result<StrictSelectedSignature, OnlineError>;

    /// Computes one selected candidate while reporting runtime slot progress.
    fn sign_consumed_batch_with_observer<O>(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: ConsumedBccCertifiedTokenBatch,
        observer: &mut O,
    ) -> Result<StrictSelectedSignature, OnlineError>
    where
        O: StrictSigningRuntimeObserver,
    {
        let _ = observer;
        self.sign_consumed_batch(request, tr, batch)
    }
}

/// One production runtime boundary for strict private signing.
pub trait StrictSigningRuntime<P: MlDsaParams> {
    /// Executes the strict private runtime after token consumption.
    fn execute_strict_runtime<O>(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: ConsumedBccCertifiedTokenBatch,
        observer: &mut O,
    ) -> Result<StrictSelectedSignature, OnlineError>
    where
        O: StrictSigningRuntimeObserver;
}

/// Prepared private response-check inputs for a strict signing batch.
pub struct StrictPreparedResponseBatch<Candidate> {
    /// Backend-specific private candidate handles.
    ///
    /// The handles are consumed and returned by every response-check phase, so
    /// production implementations cannot rely on hidden shared local state
    /// between independent phase objects.
    pub candidates: Vec<Candidate>,
    /// Public key bytes used for the final hint relation.
    pub public_key: Vec<u8>,
    /// Public certified `w1` vectors, one per batch entry.
    pub w1_vectors: Vec<Vec<u32>>,
}

impl<Candidate> StrictPreparedResponseBatch<Candidate> {
    /// Number of prepared batch entries.
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Returns true when no entries are prepared.
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    fn validate_len(&self, token_count: usize) -> Result<(), OnlineError> {
        if self.candidates.len() != token_count || self.w1_vectors.len() != token_count {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        Ok(())
    }
}

/// Production boundary for computing private response-check inputs.
///
/// A concrete implementation is responsible for deriving per-entry challenges
/// locally, computing shared responses, and returning backend-private handles
/// for the later check/selection/opening phases.
pub trait StrictResponsePreparationBackend<P: MlDsaParams> {
    /// Backend-specific candidate handle consumed by private selection.
    type Candidate;

    /// Prepares response-check inputs for an already consumed batch.
    fn prepare_private_responses(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: &ConsumedBccCertifiedTokenBatch,
        metadata: &[StrictCandidateMetadata],
    ) -> Result<StrictPreparedResponseBatch<Self::Candidate>, OnlineError>;
}

/// Production strict signing backend composed from audited boundary traits.
///
/// This is the canonical strict response-check pipeline. Distributed runtimes
/// and app drivers must delegate to these component boundaries rather than
/// implementing a parallel response-preparation/check/selection/opening stack.
pub struct ProductionStrictSigningBackend<Prepare, Bounds, Hints, Select, Open> {
    /// Private response preparation backend.
    pub prepare: Prepare,
    /// Private response-bound checker.
    pub bounds: Bounds,
    /// Private hint/highbits checker.
    pub hints: Hints,
    /// Private candidate selector.
    pub select: Select,
    /// Selected-only opener.
    pub open: Open,
    response_driver: StrictResponseCheckPhaseDriver,
}

impl<Prepare, Bounds, Hints, Select, Open>
    ProductionStrictSigningBackend<Prepare, Bounds, Hints, Select, Open>
{
    /// Creates a production strict signing backend from component boundaries.
    pub const fn new(
        prepare: Prepare,
        bounds: Bounds,
        hints: Hints,
        select: Select,
        open: Open,
    ) -> Self {
        Self {
            prepare,
            bounds,
            hints,
            select,
            open,
            response_driver: StrictResponseCheckPhaseDriver::new(),
        }
    }
}

impl<P, Prepare, Bounds, Hints, Select, Open> StrictSigningRuntime<P>
    for ProductionStrictSigningBackend<Prepare, Bounds, Hints, Select, Open>
where
    P: MlDsaParams,
    Prepare: StrictResponsePreparationBackend<P>,
    Bounds: StrictResponseBoundCheckBackend<P, ResponseVector = Prepare::Candidate>,
    Hints: StrictHintCheckBackend<P, ResponseVector = Prepare::Candidate>,
    Select: StrictPrivateSelectionBackend<Candidate = Prepare::Candidate>,
    Open: StrictSelectedOpeningBackend<Candidate = Prepare::Candidate>,
{
    fn execute_strict_runtime<O>(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: ConsumedBccCertifiedTokenBatch,
        observer: &mut O,
    ) -> Result<StrictSelectedSignature, OnlineError>
    where
        O: StrictSigningRuntimeObserver,
    {
        self.response_driver = StrictResponseCheckPhaseDriver::new();
        let token_count = batch.len();
        let metadata: Vec<_> = batch
            .tokens()
            .iter()
            .map(|token| strict_candidate_metadata::<P>(request, token, tr))
            .collect();
        self.response_driver.accept_metadata(token_count)?;

        observer.enter_runtime_slot(StrictSigningRuntimeSlot::ResponsePreparation)?;
        let prepared = self
            .prepare
            .prepare_private_responses(request, tr, &batch, &metadata)?;
        prepared.validate_len(token_count)?;
        self.response_driver.accept_shared_responses(token_count)?;

        let mut candidates = prepared.candidates;
        observer.enter_runtime_slot(StrictSigningRuntimeSlot::ResponseBoundChecks)?;
        let (next_candidates, bound_evidence) =
            self.bounds
                .check_response_bounds(&metadata, candidates, &mut self.response_driver)?;
        candidates = next_candidates;
        bound_evidence.validate_for_batch::<P>(token_count)?;

        let w1_refs: Vec<&[u32]> = prepared.w1_vectors.iter().map(Vec::as_slice).collect();
        observer.enter_runtime_slot(StrictSigningRuntimeSlot::HintChecks)?;
        let (next_candidates, hint_evidence) = self.hints.check_hints(
            &metadata,
            candidates,
            &prepared.public_key,
            &w1_refs,
            &mut self.response_driver,
        )?;
        candidates = next_candidates;
        hint_evidence.validate_for_batch::<P>(token_count)?;

        observer.enter_runtime_slot(StrictSigningRuntimeSlot::PrivateSelection)?;
        let (selected, selection_evidence) =
            self.select
                .select_candidate(&metadata, candidates, &mut self.response_driver)?;
        selection_evidence.validate_for_batch(token_count)?;

        observer.enter_runtime_slot(StrictSigningRuntimeSlot::SelectedOpening)?;
        let (signature, opening_evidence) =
            self.open
                .open_selected(&selection_evidence, selected, &mut self.response_driver)?;
        opening_evidence.validate_for_selection(&selection_evidence)?;

        let counters = self.response_driver.counters()?;
        counters.validate_for_batch(token_count)?;
        let evidence = StrictSigningEvidence {
            token_count,
            response_check_counters: counters,
            selected_priority: opening_evidence.selected_priority,
            signature_hash: opening_evidence.signature_hash,
            transcript_hash: strict_backend_transcript_hash(
                request,
                token_count,
                opening_evidence.selected_priority,
                opening_evidence.signature_hash,
            ),
        };
        Ok(StrictSelectedSignature {
            signature,
            evidence,
            vector_runtime_certificate: None,
        })
    }
}

impl<P, Prepare, Bounds, Hints, Select, Open> StrictPrivateSigningBackend<P>
    for ProductionStrictSigningBackend<Prepare, Bounds, Hints, Select, Open>
where
    P: MlDsaParams,
    Prepare: StrictResponsePreparationBackend<P>,
    Bounds: StrictResponseBoundCheckBackend<P, ResponseVector = Prepare::Candidate>,
    Hints: StrictHintCheckBackend<P, ResponseVector = Prepare::Candidate>,
    Select: StrictPrivateSelectionBackend<Candidate = Prepare::Candidate>,
    Open: StrictSelectedOpeningBackend<Candidate = Prepare::Candidate>,
{
    fn sign_consumed_batch(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: ConsumedBccCertifiedTokenBatch,
    ) -> Result<StrictSelectedSignature, OnlineError> {
        let mut observer = NoopStrictSigningRuntimeObserver;
        self.execute_strict_runtime(request, tr, batch, &mut observer)
    }

    fn sign_consumed_batch_with_observer<O>(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: ConsumedBccCertifiedTokenBatch,
        observer: &mut O,
    ) -> Result<StrictSelectedSignature, OnlineError>
    where
        O: StrictSigningRuntimeObserver,
    {
        self.execute_strict_runtime(request, tr, batch, observer)
    }
}

/// Release adapter that binds strict-signing output to durable production
/// vector IT-MPC runtime evidence.
///
/// The canonical component stack intentionally emits no release certificate by
/// itself. A release-capable caller must drive the vector runtime, collect
/// durable evidence from that runtime, and wrap the component stack with this
/// adapter so the selected signature cannot be persisted without the Phase 3
/// evidence gate passing.
pub struct ProductionStrictSigningVectorMpcRuntimeBackend<B> {
    inner: B,
    runtime_certificate: StrictSigningVectorRuntimeCertificate,
}

impl<B> ProductionStrictSigningVectorMpcRuntimeBackend<B> {
    /// Creates a release-capable strict-signing adapter from durable runtime
    /// evidence. Incomplete, scalarized, or local-only evidence is rejected by
    /// [`StrictSigningVectorRuntimeCertificate::new`].
    pub fn new(
        inner: B,
        runtime_evidence: ProductionVectorItMpcRuntimeEvidence,
    ) -> Result<Self, OnlineError> {
        let runtime_certificate = StrictSigningVectorRuntimeCertificate::new(runtime_evidence)?;
        Ok(Self {
            inner,
            runtime_certificate,
        })
    }

    /// Creates an adapter from an already validated strict-signing runtime
    /// certificate.
    pub const fn with_certificate(
        inner: B,
        runtime_certificate: StrictSigningVectorRuntimeCertificate,
    ) -> Self {
        Self {
            inner,
            runtime_certificate,
        }
    }

    /// Returns the validated runtime certificate attached by this adapter.
    pub fn runtime_certificate(&self) -> &StrictSigningVectorRuntimeCertificate {
        &self.runtime_certificate
    }

    /// Consumes the adapter and returns the wrapped backend.
    pub fn into_inner(self) -> B {
        self.inner
    }
}

impl<P, B> StrictPrivateSigningBackend<P> for ProductionStrictSigningVectorMpcRuntimeBackend<B>
where
    P: MlDsaParams,
    B: StrictPrivateSigningBackend<P>,
{
    fn sign_consumed_batch(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: ConsumedBccCertifiedTokenBatch,
    ) -> Result<StrictSelectedSignature, OnlineError> {
        let selected = self.inner.sign_consumed_batch(request, tr, batch)?;
        Ok(selected.with_vector_runtime_certificate(self.runtime_certificate.clone()))
    }

    fn sign_consumed_batch_with_observer<O>(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: ConsumedBccCertifiedTokenBatch,
        observer: &mut O,
    ) -> Result<StrictSelectedSignature, OnlineError>
    where
        O: StrictSigningRuntimeObserver,
    {
        let selected = self
            .inner
            .sign_consumed_batch_with_observer(request, tr, batch, observer)?;
        Ok(selected.with_vector_runtime_certificate(self.runtime_certificate.clone()))
    }
}

/// One party's private polynomial shares for strict vector signing.
#[derive(Clone, Eq, PartialEq)]
pub struct StrictPolynomialSigningShare {
    /// Party identifier.
    pub party: PartyId,
    /// Local nonce polynomial-vector share.
    pub y: PolyVec,
    /// Local `s1` polynomial-vector share.
    pub s1: PolyVec,
}

impl fmt::Debug for StrictPolynomialSigningShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrictPolynomialSigningShare")
            .field("party", &self.party)
            .field("y", &"<redacted>")
            .field("s1", &"<redacted>")
            .finish()
    }
}

/// Supplies private polynomial shares to a strict vector response backend.
pub trait StrictPolynomialShareProvider {
    /// Returns the signing shares for `party` in `session_id`.
    fn signing_share(
        &self,
        session_id: SessionId,
        party: PartyId,
    ) -> Result<StrictPolynomialSigningShare, OnlineError>;
}

impl<T> StrictPolynomialShareProvider for &T
where
    T: StrictPolynomialShareProvider + ?Sized,
{
    fn signing_share(
        &self,
        session_id: SessionId,
        party: PartyId,
    ) -> Result<StrictPolynomialSigningShare, OnlineError> {
        (**self).signing_share(session_id, party)
    }
}

/// Opaque handle for one strict vector signing candidate.
#[derive(Clone)]
pub struct StrictVectorCandidateHandle {
    priority: StrictCandidatePriority,
    ctilde: Vec<u8>,
    response: PolyVec,
    bound_ok: Option<bool>,
    hint_ok: Option<bool>,
    hint: Option<PolyVec>,
    signature: Option<FinalSignature>,
}

impl fmt::Debug for StrictVectorCandidateHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrictVectorCandidateHandle")
            .field("priority", &self.priority)
            .finish()
    }
}

/// Runtime-owned strict-signing candidate.
///
/// This is the release-path candidate shape. It carries only production vector
/// MPC handles and public metadata; it does not contain local `PolyVec`
/// responses, local pass/fail booleans, or prebuilt signatures.
#[derive(Clone)]
pub struct StrictRuntimeCandidateHandle {
    priority: StrictCandidatePriority,
    ctilde: Vec<u8>,
    z_share: ProductionShareVec,
    z_bound_ok: Option<ProductionBitShareVec>,
    h_bits: Option<ProductionBitShareVec>,
    hint_ok: Option<ProductionBitShareVec>,
    valid: Option<ProductionBitShareVec>,
    selected_z_share: Option<ProductionShareVec>,
    selected_h_bits: Option<ProductionBitShareVec>,
}

impl StrictRuntimeCandidateHandle {
    /// Creates a runtime-owned candidate after response preparation.
    pub fn new_runtime_prepared(
        priority: StrictCandidatePriority,
        ctilde: Vec<u8>,
        z_share: ProductionShareVec,
    ) -> Self {
        Self {
            priority,
            ctilde,
            z_share,
            z_bound_ok: None,
            h_bits: None,
            hint_ok: None,
            valid: None,
            selected_z_share: None,
            selected_h_bits: None,
        }
    }

    /// Public priority for private selection.
    pub const fn priority(&self) -> StrictCandidatePriority {
        self.priority
    }

    /// Public challenge seed bound to this candidate.
    pub fn ctilde(&self) -> &[u8] {
        &self.ctilde
    }

    /// Runtime-owned shared response `[z]`.
    pub const fn z_share(&self) -> &ProductionShareVec {
        &self.z_share
    }

    /// Private response-bound pass bit, once computed.
    pub const fn z_bound_ok(&self) -> Option<&ProductionBitShareVec> {
        self.z_bound_ok.as_ref()
    }

    /// Private hint/highbits pass bit, once computed.
    pub const fn hint_ok(&self) -> Option<&ProductionBitShareVec> {
        self.hint_ok.as_ref()
    }

    /// Private hint-bit vector, once computed.
    pub const fn h_bits(&self) -> Option<&ProductionBitShareVec> {
        self.h_bits.as_ref()
    }

    /// Private combined validity bit, once computed.
    pub const fn valid(&self) -> Option<&ProductionBitShareVec> {
        self.valid.as_ref()
    }

    /// Selected shared response handle, once private selection has run.
    pub const fn selected_z_share(&self) -> Option<&ProductionShareVec> {
        self.selected_z_share.as_ref()
    }

    /// Selected shared hint-bit handle, once private selection has run.
    pub const fn selected_h_bits(&self) -> Option<&ProductionBitShareVec> {
        self.selected_h_bits.as_ref()
    }

    /// Installs the private response-bound pass bit.
    pub fn with_z_bound_ok(mut self, bit: ProductionBitShareVec) -> Self {
        self.z_bound_ok = Some(bit);
        self
    }

    /// Installs the private hint/highbits pass bit.
    pub fn with_hint_ok(mut self, bit: ProductionBitShareVec) -> Self {
        self.hint_ok = Some(bit);
        self
    }

    /// Installs the private hint-bit vector.
    pub fn with_h_bits(mut self, bits: ProductionBitShareVec) -> Self {
        self.h_bits = Some(bits);
        self
    }

    /// Installs the private combined validity bit.
    pub fn with_valid(mut self, bit: ProductionBitShareVec) -> Self {
        self.valid = Some(bit);
        self
    }

    /// Installs selected-output handles produced by private selection.
    pub fn with_selected_handles(
        mut self,
        z_share: ProductionShareVec,
        h_bits: ProductionBitShareVec,
    ) -> Self {
        self.selected_z_share = Some(z_share);
        self.selected_h_bits = Some(h_bits);
        self
    }
}

impl fmt::Debug for StrictRuntimeCandidateHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrictRuntimeCandidateHandle")
            .field("priority", &self.priority)
            .field("ctilde_len", &self.ctilde.len())
            .field("z_share", &self.z_share.id())
            .field("z_bound_ok", &self.z_bound_ok.as_ref().map(|bit| bit.id()))
            .field("h_bits", &self.h_bits.as_ref().map(|bits| bits.id()))
            .field("hint_ok", &self.hint_ok.as_ref().map(|bit| bit.id()))
            .field("valid", &self.valid.as_ref().map(|bit| bit.id()))
            .field(
                "selected_z_share",
                &self.selected_z_share.as_ref().map(|share| share.id()),
            )
            .field(
                "selected_h_bits",
                &self.selected_h_bits.as_ref().map(|bits| bits.id()),
            )
            .finish()
    }
}

/// Converts a polynomial vector to runtime lane order:
/// `poly_0[0..256], poly_1[0..256], ...`.
pub fn strict_polyvec_to_runtime_lanes<P: MlDsaParams>(
    polyvec: &PolyVec,
) -> Result<Vec<talus_core::Coeff>, OnlineError> {
    if polyvec.len() != P::L {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let mut lanes = Vec::with_capacity(P::L * P::N);
    for poly in polyvec.polys() {
        lanes.extend_from_slice(poly.coeffs());
    }
    Ok(lanes)
}

/// Builds the runtime-owned response share `[z] = [y] + c[s1]`.
///
/// The challenge multiplication is public-linear and therefore stays local to
/// the vector runtime; no secret-dependent value is opened.
pub fn strict_prepare_runtime_z_share<P, T, L, C>(
    runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    y_share: &ProductionShareVec,
    s1_share: &ProductionShareVec,
    ctilde: &[u8],
    label: &Power2RoundTranscriptLabel,
) -> Result<ProductionShareVec, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    let c_s1 = runtime
        .mul_public_challenge_polyvec_share_vec::<P>(
            config,
            s1_share,
            ctilde,
            &label.child("c_times_s1"),
        )
        .map_err(OnlineError::from)?;
    runtime
        .add_share_vec::<P>(config, y_share, &c_s1, &label.child("z"))
        .map_err(OnlineError::from)
}

fn strict_runtime_polyvec_to_lanes(polyvec: &PolyVec) -> Vec<talus_core::Coeff> {
    let mut lanes = Vec::with_capacity(polyvec.len() * 256);
    for poly in polyvec.polys() {
        lanes.extend_from_slice(poly.coeffs());
    }
    lanes
}

/// Computes the public-linear `A[z]` share for strict signing.
pub fn strict_runtime_az_share<P, T, L, C>(
    runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    rho: &[u8; 32],
    z_share: &ProductionShareVec,
    label: &Power2RoundTranscriptLabel,
) -> Result<ProductionShareVec, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    runtime
        .az_from_rho_share_vec::<P>(config, rho, z_share, label)
        .map_err(OnlineError::from)
}

/// Computes the private verifier approximation share
/// `[r] = A[z] - c*t1*2^d` for strict hint checks.
pub fn strict_runtime_hint_approx_share<P, T, L, C>(
    runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    public_key: &[u8],
    ctilde: &[u8],
    z_share: &ProductionShareVec,
    label: &Power2RoundTranscriptLabel,
) -> Result<ProductionShareVec, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    let decoded = public_key_decode::<P>(public_key)?;
    let az = strict_runtime_az_share::<P, T, L, C>(
        runtime,
        config,
        &decoded.rho,
        z_share,
        &label.child("az"),
    )?;
    let challenge = sample_in_ball::<P>(ctilde);
    let t1_2d = talus_core::t1_times_2d::<P>(&decoded.t1);
    let ct1 = mul_challenge_polyvec::<P>(&challenge, &t1_2d);
    let ct1_lanes = strict_runtime_polyvec_to_lanes(&ct1);
    let ct1_share = runtime
        .public_lanes_share_vec::<P>(config, &label.child("ct1_2d"), &ct1_lanes)
        .map_err(OnlineError::from)?;
    runtime
        .sub_share_vec::<P>(config, &az, &ct1_share, &label.child("hint_approx"))
        .map_err(OnlineError::from)
}

/// Runtime-owned private z-bound check state.
///
/// Given canonical bits of `[z]`, this state computes the private predicate
/// `z_bound_ok = ([z] < Gamma) OR ([z] > q - Gamma)`, where
/// `Gamma = gamma1 - beta`. No coefficient, failed predicate, or pass bit is
/// opened by this state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictRuntimeZBoundCheckState {
    lt_gamma: ProductionPublicComparisonVecState,
    gt_upper: ProductionPublicComparisonVecState,
    pending_or: bool,
    ok: Option<ProductionBitShareVec>,
}

impl StrictRuntimeZBoundCheckState {
    /// Initializes the private z-bound comparisons from canonical bits of z.
    pub fn new<P, T, L, C>(
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        z_bits_by_bit_le: &[ProductionBitShareVec],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Self, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if z_bits_by_bit_le.len() != 23 {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let gamma = u32::try_from(P::GAMMA1 - P::BETA)
            .map_err(|_| OnlineError::StrictResponseCheckShapeMismatch)?;
        let upper = P::Q as u32 - gamma;
        Ok(Self {
            lt_gamma: runtime
                .start_lt_public_vec::<P>(
                    config,
                    z_bits_by_bit_le,
                    gamma,
                    &label.child("z_lt_gamma"),
                )
                .map_err(OnlineError::from)?,
            gt_upper: runtime
                .start_gt_public_vec::<P>(
                    config,
                    z_bits_by_bit_le,
                    upper,
                    &label.child("z_gt_q_minus_gamma"),
                )
                .map_err(OnlineError::from)?,
            pending_or: false,
            ok: None,
        })
    }

    /// Returns the private z-bound result once available.
    pub fn result(&self) -> Option<&ProductionBitShareVec> {
        self.ok.as_ref()
    }

    /// Drives one multiplication layer of the lower-bound comparison.
    pub fn drive_lt_gamma_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        runtime
            .drive_public_comparison_vec_step::<P, E>(config, &mut self.lt_gamma, entropy)
            .map_err(OnlineError::from)
    }

    /// Collects one multiplication layer of the lower-bound comparison.
    pub fn collect_lt_gamma_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        runtime
            .collect_public_comparison_vec_step::<P>(config, &mut self.lt_gamma)
            .map_err(OnlineError::from)
    }

    /// Drives one multiplication layer of the upper-bound comparison.
    pub fn drive_gt_upper_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        runtime
            .drive_public_comparison_vec_step::<P, E>(config, &mut self.gt_upper, entropy)
            .map_err(OnlineError::from)
    }

    /// Collects one multiplication layer of the upper-bound comparison.
    pub fn collect_gt_upper_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        runtime
            .collect_public_comparison_vec_step::<P>(config, &mut self.gt_upper)
            .map_err(OnlineError::from)
    }

    /// Drives the private OR of the two completed comparison bits.
    pub fn drive_or_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        if self.pending_or {
            return Err(OnlineError::StrictSigningRuntimeSlotIncomplete);
        }
        let lt = self
            .lt_gamma
            .result()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let gt = self
            .gt_upper
            .result()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        runtime
            .drive_bit_and_vec::<P, E>(config, lt, gt, &label.child("z_bound_or"), entropy)
            .map_err(OnlineError::from)?;
        self.pending_or = true;
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver: runtime.local_party(),
            kind: talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase: talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare,
            label_hash: talus_dkg::power2round_label_hash(
                &label
                    .child("z_bound_or")
                    .child("bit_and")
                    .child("mul_layer"),
            ),
        })
    }

    /// Collects the private OR result.
    pub fn collect_or_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if !self.pending_or {
            return Err(OnlineError::StrictSigningRuntimeSlotIncomplete);
        }
        let (status, and_bit) = match runtime
            .collect_bit_and_vec::<P>(config, &label.child("z_bound_or"))
        {
            Ok(ProductionVectorItMpcCollectResult::Waiting(status)) => {
                return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
            }
            Ok(ProductionVectorItMpcCollectResult::Collected { status, value }) => (status, value),
            Err(err) => return Err(OnlineError::from(err)),
        };
        let lt = self
            .lt_gamma
            .result()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let gt = self
            .gt_upper
            .result()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        self.ok = Some(
            runtime
                .bit_or_from_and_vec::<P>(config, lt, gt, &and_bit, &label.child("z_bound_ok"))
                .map_err(OnlineError::from)?,
        );
        self.pending_or = false;
        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
    }
}

fn strict_highbits_interval_constants<P: MlDsaParams>(
    w1: &[u32],
) -> Result<
    (
        Vec<talus_core::Coeff>,
        Vec<talus_core::Coeff>,
        Vec<talus_core::Coeff>,
    ),
    OnlineError,
> {
    let expected = P::K * P::N;
    if w1.len() != expected {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let high_mod = ((P::Q - 1) / (2 * P::GAMMA2)) as u32;
    let alpha = 2 * P::GAMMA2;
    let mut lower = Vec::with_capacity(expected);
    let mut upper_exclusive = Vec::with_capacity(expected);
    let mut wraps_zero = Vec::with_capacity(expected);
    for (idx, &high) in w1.iter().enumerate() {
        if high >= high_mod {
            return Err(OnlineError::Hint(HintError::W1OutOfRange {
                index: idx,
                value: high,
            }));
        }
        if high == 0 {
            lower.push(P::Q - P::GAMMA2 - 1);
            upper_exclusive.push(P::GAMMA2 + 1);
            wraps_zero.push(1);
        } else {
            let center = i64::from(high) * i64::from(alpha);
            lower.push((center - i64::from(P::GAMMA2)) as talus_core::Coeff);
            upper_exclusive.push((center + i64::from(P::GAMMA2) + 1) as talus_core::Coeff);
            wraps_zero.push(0);
        }
    }
    Ok((lower, upper_exclusive, wraps_zero))
}

/// Runtime-owned private hint-bit derivation state.
///
/// Given canonical bits of `[r] = A[z] - c*t1*2^d`, this state computes the
/// private TALUS hint vector `h = HighBits(r) != w1` without opening `r`,
/// `HighBits(r)`, per-coefficient pass/fail bits, or hint weight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictRuntimeHintBitsCheckState {
    gt_lower: ProductionPublicComparisonVecState,
    lt_upper: ProductionPublicComparisonVecState,
    wraps_zero: Vec<talus_core::Coeff>,
    pending_and: bool,
    pending_or: bool,
    interval_and: Option<ProductionBitShareVec>,
    interval_or: Option<ProductionBitShareVec>,
    hint_bits: Option<ProductionBitShareVec>,
}

impl StrictRuntimeHintBitsCheckState {
    /// Initializes private interval checks for `HighBits(r) == w1`.
    pub fn new<P, T, L, C>(
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        r_bits_by_bit_le: &[ProductionBitShareVec],
        w1: &[u32],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Self, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if r_bits_by_bit_le.len() != 23 {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let (lower, upper_exclusive, wraps_zero) = strict_highbits_interval_constants::<P>(w1)?;
        Ok(Self {
            gt_lower: runtime
                .start_gt_public_lanes_vec::<P>(
                    config,
                    r_bits_by_bit_le,
                    &lower,
                    &label.child("highbits_gt_lower"),
                )
                .map_err(OnlineError::from)?,
            lt_upper: runtime
                .start_lt_public_lanes_vec::<P>(
                    config,
                    r_bits_by_bit_le,
                    &upper_exclusive,
                    &label.child("highbits_lt_upper"),
                )
                .map_err(OnlineError::from)?,
            wraps_zero,
            pending_and: false,
            pending_or: false,
            interval_and: None,
            interval_or: None,
            hint_bits: None,
        })
    }

    /// Returns the private hint bits once available.
    pub fn hint_bits(&self) -> Option<&ProductionBitShareVec> {
        self.hint_bits.as_ref()
    }

    /// Drives one multiplication layer of the lower interval comparison.
    pub fn drive_gt_lower_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        runtime
            .drive_public_comparison_vec_step::<P, E>(config, &mut self.gt_lower, entropy)
            .map_err(OnlineError::from)
    }

    /// Collects one multiplication layer of the lower interval comparison.
    pub fn collect_gt_lower_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        runtime
            .collect_public_comparison_vec_step::<P>(config, &mut self.gt_lower)
            .map_err(OnlineError::from)
    }

    /// Drives one multiplication layer of the upper interval comparison.
    pub fn drive_lt_upper_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        runtime
            .drive_public_comparison_vec_step::<P, E>(config, &mut self.lt_upper, entropy)
            .map_err(OnlineError::from)
    }

    /// Collects one multiplication layer of the upper interval comparison.
    pub fn collect_lt_upper_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        runtime
            .collect_public_comparison_vec_step::<P>(config, &mut self.lt_upper)
            .map_err(OnlineError::from)
    }

    /// Drives the private `gt_lower AND lt_upper` interval bit.
    pub fn drive_interval_and_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        if self.pending_and {
            return Err(OnlineError::StrictSigningRuntimeSlotIncomplete);
        }
        let gt = self
            .gt_lower
            .result()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let lt = self
            .lt_upper
            .result()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        runtime
            .drive_bit_and_vec::<P, E>(config, gt, lt, &label.child("highbits_interval"), entropy)
            .map_err(OnlineError::from)?;
        self.pending_and = true;
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver: runtime.local_party(),
            kind: talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase: talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare,
            label_hash: talus_dkg::power2round_label_hash(
                &label
                    .child("highbits_interval")
                    .child("bit_and")
                    .child("mul_layer"),
            ),
        })
    }

    /// Collects `gt_lower AND lt_upper`.
    pub fn collect_interval_and_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if !self.pending_and {
            return Err(OnlineError::StrictSigningRuntimeSlotIncomplete);
        }
        match runtime.collect_bit_and_vec::<P>(config, &label.child("highbits_interval")) {
            Ok(ProductionVectorItMpcCollectResult::Waiting(status)) => {
                Ok(ProductionVectorItMpcCollectResult::Waiting(status))
            }
            Ok(ProductionVectorItMpcCollectResult::Collected { status, value }) => {
                self.interval_and = Some(value);
                self.pending_and = false;
                Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
            }
            Err(err) => Err(OnlineError::from(err)),
        }
    }

    /// Drives the private wrap interval OR used when public `w1 == 0`.
    pub fn drive_wrap_or_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        if self.pending_or {
            return Err(OnlineError::StrictSigningRuntimeSlotIncomplete);
        }
        let gt = self
            .gt_lower
            .result()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let lt = self
            .lt_upper
            .result()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        runtime
            .drive_bit_and_vec::<P, E>(config, gt, lt, &label.child("highbits_wrap_or"), entropy)
            .map_err(OnlineError::from)?;
        self.pending_or = true;
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver: runtime.local_party(),
            kind: talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase: talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare,
            label_hash: talus_dkg::power2round_label_hash(
                &label
                    .child("highbits_wrap_or")
                    .child("bit_and")
                    .child("mul_layer"),
            ),
        })
    }

    /// Collects the wrap interval OR and finalizes private hint bits.
    pub fn collect_wrap_or_and_finalize<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if !self.pending_or {
            return Err(OnlineError::StrictSigningRuntimeSlotIncomplete);
        }
        let (status, and_bit) = match runtime
            .collect_bit_and_vec::<P>(config, &label.child("highbits_wrap_or"))
        {
            Ok(ProductionVectorItMpcCollectResult::Waiting(status)) => {
                return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
            }
            Ok(ProductionVectorItMpcCollectResult::Collected { status, value }) => (status, value),
            Err(err) => return Err(OnlineError::from(err)),
        };
        let gt = self
            .gt_lower
            .result()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let lt = self
            .lt_upper
            .result()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let interval_or = runtime
            .bit_or_from_and_vec::<P>(config, gt, lt, &and_bit, &label.child("interval_wrap_or"))
            .map_err(OnlineError::from)?;
        self.interval_or = Some(interval_or);
        self.pending_or = false;
        self.finalize_hint_bits::<P, T, L, C>(runtime, config, label)?;
        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
    }

    fn finalize_hint_bits<P, T, L, C>(
        &mut self,
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(), OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let interval_and = self
            .interval_and
            .as_ref()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let interval_or = self
            .interval_or
            .as_ref()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let eq_high = runtime
            .public_lane_select_bit_vec::<P>(
                config,
                interval_or,
                interval_and,
                &self.wraps_zero,
                &label.child("eq_highbits"),
            )
            .map_err(OnlineError::from)?;
        self.hint_bits = Some(
            runtime
                .bit_not_vec::<P>(config, &eq_high, &label.child("hint_bits"))
                .map_err(OnlineError::from)?,
        );
        Ok(())
    }
}

fn strict_split_bit_vec_lanes<P, T, L, C>(
    runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    bits: &ProductionBitShareVec,
    label: &Power2RoundTranscriptLabel,
) -> Result<Vec<ProductionBitShareVec>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    runtime
        .split_bit_share_vec_lanes::<P>(config, bits, label)
        .map_err(OnlineError::from)
}

/// Runtime-owned private hint-weight check state.
///
/// This converts a private hint vector into a single private pass bit
/// `[wt(h) <= omega]`. The pass bit is not opened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictRuntimeHintWeightCheckState {
    threshold: ProductionBitSumLeqPublicVecState,
}

impl StrictRuntimeHintWeightCheckState {
    /// Initializes private `wt(h) <= omega`.
    pub fn new<P, T, L, C>(
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        h_bits: &ProductionBitShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Self, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if h_bits.len() != P::K * P::N {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let bits = strict_split_bit_vec_lanes::<P, T, L, C>(runtime, config, h_bits, label)?;
        Ok(Self {
            threshold: runtime
                .start_bit_sum_leq_public_vec::<P>(
                    config,
                    &bits,
                    P::OMEGA as u32,
                    &label.child("hint_weight_leq_omega"),
                )
                .map_err(OnlineError::from)?,
        })
    }

    /// Returns the private pass bit once available.
    pub fn result(&self) -> Option<&ProductionBitShareVec> {
        self.threshold.result()
    }

    /// Drives one multiplication layer of the private hint-weight check.
    pub fn drive_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        runtime
            .drive_bit_sum_leq_public_vec_step::<P, E>(config, &mut self.threshold, entropy)
            .map_err(OnlineError::from)
    }

    /// Collects one multiplication layer of the private hint-weight check.
    pub fn collect_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        runtime
            .collect_bit_sum_leq_public_vec_step::<P>(config, &mut self.threshold)
            .map_err(OnlineError::from)
    }
}

/// Runtime-owned private `AND` over every lane in a bit vector.
///
/// This returns a single private bit proving all input lanes were one by
/// checking `sum(!bits) <= 0`. It is used to turn per-coefficient z-bound
/// predicates into one candidate-level private pass bit without opening failed
/// coefficient locations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictRuntimeAllBitsTrueState {
    threshold: ProductionBitSumLeqPublicVecState,
}

impl StrictRuntimeAllBitsTrueState {
    /// Initializes private `all(bits)`.
    pub fn new<P, T, L, C>(
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        bits: &ProductionBitShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Self, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let not_bits = runtime
            .bit_not_vec::<P>(config, bits, &label.child("not_bits"))
            .map_err(OnlineError::from)?;
        let violation_bits =
            strict_split_bit_vec_lanes::<P, T, L, C>(runtime, config, &not_bits, label)?;
        Ok(Self {
            threshold: runtime
                .start_bit_sum_leq_public_vec::<P>(
                    config,
                    &violation_bits,
                    0,
                    &label.child("all_bits_true"),
                )
                .map_err(OnlineError::from)?,
        })
    }

    /// Returns the private all-true bit once available.
    pub fn result(&self) -> Option<&ProductionBitShareVec> {
        self.threshold.result()
    }

    /// Drives one multiplication layer.
    pub fn drive_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        runtime
            .drive_bit_sum_leq_public_vec_step::<P, E>(config, &mut self.threshold, entropy)
            .map_err(OnlineError::from)
    }

    /// Collects one multiplication layer.
    pub fn collect_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        runtime
            .collect_bit_sum_leq_public_vec_step::<P>(config, &mut self.threshold)
            .map_err(OnlineError::from)
    }
}

/// Runtime-owned private valid-bit combination state.
///
/// Computes `valid = z_bound_ok AND hint_ok` without opening either predicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictRuntimeValidBitState {
    pending: bool,
    valid: Option<ProductionBitShareVec>,
}

impl StrictRuntimeValidBitState {
    /// Creates an empty valid-bit combiner.
    pub const fn new() -> Self {
        Self {
            pending: false,
            valid: None,
        }
    }

    /// Returns the private valid bit once available.
    pub fn result(&self) -> Option<&ProductionBitShareVec> {
        self.valid.as_ref()
    }

    /// Drives `z_bound_ok AND hint_ok`.
    pub fn drive_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        z_bound_ok: &ProductionBitShareVec,
        hint_ok: &ProductionBitShareVec,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        if self.pending {
            return Err(OnlineError::StrictSigningRuntimeSlotIncomplete);
        }
        runtime
            .drive_bit_and_vec::<P, E>(
                config,
                z_bound_ok,
                hint_ok,
                &label.child("valid_bit"),
                entropy,
            )
            .map_err(OnlineError::from)?;
        self.pending = true;
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver: runtime.local_party(),
            kind: talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase: talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare,
            label_hash: talus_dkg::power2round_label_hash(
                &label.child("valid_bit").child("bit_and").child("mul_layer"),
            ),
        })
    }

    /// Collects the private valid bit.
    pub fn collect_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if !self.pending {
            return Err(OnlineError::StrictSigningRuntimeSlotIncomplete);
        }
        match runtime.collect_bit_and_vec::<P>(config, &label.child("valid_bit")) {
            Ok(ProductionVectorItMpcCollectResult::Waiting(status)) => {
                Ok(ProductionVectorItMpcCollectResult::Waiting(status))
            }
            Ok(ProductionVectorItMpcCollectResult::Collected { status, value }) => {
                self.valid = Some(value);
                self.pending = false;
                Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
            }
            Err(err) => Err(OnlineError::from(err)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StrictPrioritySelectionPending {
    SelectedAnd,
    PrefixOr,
}

/// Runtime-owned private priority selection state.
///
/// Candidates are processed in public-priority order. For candidate `j`, the
/// state computes:
///
/// `selected_j = valid_j AND !any_lower_priority_valid`
///
/// and updates the private prefix bit. No `valid_j`, selected bit, invalid set,
/// or failure reason is opened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictRuntimePrioritySelectionState {
    order: Vec<usize>,
    cursor: usize,
    prefix_valid: ProductionBitShareVec,
    pending: Option<StrictPrioritySelectionPending>,
    selected_bits: Vec<Option<ProductionBitShareVec>>,
}

impl StrictRuntimePrioritySelectionState {
    /// Initializes private priority selection.
    pub fn new<P, T, L, C>(
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        priorities: &[StrictCandidatePriority],
        valid_bits: &[ProductionBitShareVec],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Self, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if priorities.len() != valid_bits.len() || priorities.is_empty() {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        if valid_bits.iter().any(|bit| bit.len() != 1) {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let mut order = (0..priorities.len()).collect::<Vec<_>>();
        order.sort_by_key(|&idx| priorities[idx]);
        Ok(Self {
            order,
            cursor: 0,
            prefix_valid: runtime
                .public_bit_share_vec::<P>(config, &label.child("prefix_valid_init"), false, 1)
                .map_err(OnlineError::from)?,
            pending: None,
            selected_bits: vec![None; priorities.len()],
        })
    }

    /// Returns true after every candidate has a private selected bit.
    pub fn is_done(&self) -> bool {
        self.cursor >= self.order.len() && self.pending.is_none()
    }

    /// Returns private one-hot selected bits once available.
    pub fn selected_bits(&self) -> Option<Vec<ProductionBitShareVec>> {
        if !self.is_done() {
            return None;
        }
        self.selected_bits.iter().cloned().collect()
    }

    /// Returns the private "at least one valid candidate" bit after priority
    /// selection completes.
    pub fn any_valid_bit(&self) -> Option<ProductionBitShareVec> {
        self.is_done().then(|| self.prefix_valid.clone())
    }

    /// Drives the next private selection multiplication layer.
    pub fn drive_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        valid_bits: &[ProductionBitShareVec],
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        if self.pending.is_some() {
            return Err(OnlineError::StrictSigningRuntimeSlotIncomplete);
        }
        if self.cursor >= self.order.len() {
            return Ok(PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: None,
                kind: talus_dkg::PrimeFieldMpcRoundKind::AssertZero,
                phase: talus_dkg::PrimeFieldMpcPhase::BitSumThresholdCheck,
                label_hash: talus_dkg::power2round_label_hash(label),
                senders: Vec::new(),
            });
        }
        let candidate_idx = self.order[self.cursor];
        if self.selected_bits[candidate_idx].is_some() {
            runtime
                .drive_bit_and_vec::<P, E>(
                    config,
                    &self.prefix_valid,
                    &valid_bits[candidate_idx],
                    &label.child(format!("candidate_{candidate_idx}/prefix_or")),
                    entropy,
                )
                .map_err(OnlineError::from)?;
            self.pending = Some(StrictPrioritySelectionPending::PrefixOr);
            return Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
                receiver: runtime.local_party(),
                kind: talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce,
                phase: talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare,
                label_hash: talus_dkg::power2round_label_hash(
                    &label
                        .child(format!("candidate_{candidate_idx}/prefix_or"))
                        .child("bit_and")
                        .child("mul_layer"),
                ),
            });
        }
        let not_prefix = runtime
            .bit_not_vec::<P>(
                config,
                &self.prefix_valid,
                &label.child(format!("candidate_{candidate_idx}/not_prefix")),
            )
            .map_err(OnlineError::from)?;
        runtime
            .drive_bit_and_vec::<P, E>(
                config,
                &valid_bits[candidate_idx],
                &not_prefix,
                &label.child(format!("candidate_{candidate_idx}/selected")),
                entropy,
            )
            .map_err(OnlineError::from)?;
        self.pending = Some(StrictPrioritySelectionPending::SelectedAnd);
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver: runtime.local_party(),
            kind: talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase: talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare,
            label_hash: talus_dkg::power2round_label_hash(
                &label
                    .child(format!("candidate_{candidate_idx}/selected"))
                    .child("bit_and")
                    .child("mul_layer"),
            ),
        })
    }

    /// Collects the pending private selection multiplication layer.
    pub fn collect_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        valid_bits: &[ProductionBitShareVec],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let pending = self
            .pending
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let candidate_idx = self.order[self.cursor];
        match pending {
            StrictPrioritySelectionPending::SelectedAnd => {
                let selected_label = label.child(format!("candidate_{candidate_idx}/selected"));
                let (status, selected) =
                    match runtime.collect_bit_and_vec::<P>(config, &selected_label) {
                        Ok(ProductionVectorItMpcCollectResult::Waiting(status)) => {
                            return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
                        }
                        Ok(ProductionVectorItMpcCollectResult::Collected { status, value }) => {
                            (status, value)
                        }
                        Err(err) => return Err(OnlineError::from(err)),
                    };
                self.selected_bits[candidate_idx] = Some(selected);
                self.pending = None;
                Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
            }
            StrictPrioritySelectionPending::PrefixOr => {
                let prefix_label = label.child(format!("candidate_{candidate_idx}/prefix_or"));
                let (status, and_bit) =
                    match runtime.collect_bit_and_vec::<P>(config, &prefix_label) {
                        Ok(ProductionVectorItMpcCollectResult::Waiting(status)) => {
                            return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
                        }
                        Ok(ProductionVectorItMpcCollectResult::Collected { status, value }) => {
                            (status, value)
                        }
                        Err(err) => return Err(OnlineError::from(err)),
                    };
                self.prefix_valid = runtime
                    .bit_or_from_and_vec::<P>(
                        config,
                        &self.prefix_valid,
                        &valid_bits[candidate_idx],
                        &and_bit,
                        &label.child(format!("candidate_{candidate_idx}/prefix_valid")),
                    )
                    .map_err(OnlineError::from)?;
                self.cursor += 1;
                self.pending = None;
                Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
            }
        }
    }
}

fn strict_hint_bits_to_polyvec<P: MlDsaParams>(
    h_bits: &[talus_core::Coeff],
) -> Result<PolyVec, OnlineError> {
    if h_bits.len() != P::K * P::N {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let mut polys = Vec::with_capacity(P::K);
    for poly_idx in 0..P::K {
        let mut coeffs = [0; 256];
        for coeff_idx in 0..P::N {
            let bit = h_bits[poly_idx * P::N + coeff_idx];
            if bit != 0 && bit != 1 {
                return Err(OnlineError::StrictResponseCheckShapeMismatch);
            }
            coeffs[coeff_idx] = bit;
        }
        polys.push(Poly::from_coeffs(coeffs));
    }
    Ok(PolyVec::new(polys))
}

/// Drives private selected-vector products `selected_j * value_j` for all
/// candidates. The one-lane selected bits are repeated privately to the value
/// vector shape before multiplication.
pub fn strict_drive_selected_share_products<P, T, L, C, E>(
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    selected_bits: &[ProductionBitShareVec],
    values: &[ProductionShareVec],
    label: &Power2RoundTranscriptLabel,
    entropy: &mut E,
) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
    E: ProductionVectorItMpcEntropy,
{
    if selected_bits.len() != values.len() || values.is_empty() {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    for (idx, (selected, value)) in selected_bits.iter().zip(values).enumerate() {
        let repeated = runtime
            .repeat_one_lane_bit_share_vec::<P>(
                config,
                selected,
                value.len(),
                &label.child(format!("candidate_{idx}/selected_repeated")),
            )
            .map_err(OnlineError::from)?;
        runtime
            .drive_selection_product_vec::<P, E>(
                config,
                &repeated,
                value,
                &label.child(format!("selection_product_{idx}")),
                entropy,
            )
            .map_err(OnlineError::from)?;
    }
    Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
        receiver: runtime.local_party(),
        kind: talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce,
        phase: talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare,
        label_hash: talus_dkg::power2round_label_hash(label),
    })
}

/// Collects selected-vector products and returns the privately selected share.
pub fn strict_collect_selected_share_products<P, T, L, C>(
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    candidate_count: usize,
    label: &Power2RoundTranscriptLabel,
) -> Result<ProductionVectorItMpcCollectResult<ProductionShareVec>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    runtime
        .collect_selection_products_vec::<P>(config, candidate_count, label)
        .map_err(OnlineError::from)
}

fn strict_u8_lanes_from_opening(lanes: &[talus_core::Coeff]) -> Result<Vec<u8>, OnlineError> {
    lanes
        .iter()
        .map(|&lane| u8::try_from(lane).map_err(|_| OnlineError::StrictResponseCheckShapeMismatch))
        .collect()
}

fn strict_selected_public_lanes_share<P, T, L, C>(
    runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    selected_bits: &[ProductionBitShareVec],
    public_lanes: &[Vec<u8>],
    label: &Power2RoundTranscriptLabel,
) -> Result<ProductionShareVec, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    if selected_bits.len() != public_lanes.len() || public_lanes.is_empty() {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let lane_count = public_lanes[0].len();
    if lane_count == 0
        || public_lanes.iter().any(|lanes| lanes.len() != lane_count)
        || selected_bits.iter().any(|bit| bit.len() != 1)
    {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let mut selected = runtime
        .public_const_share_vec::<P>(config, &label.child("init"), 0, lane_count)
        .map_err(OnlineError::from)?;
    for (idx, (bit, lanes)) in selected_bits.iter().zip(public_lanes).enumerate() {
        let repeated = runtime
            .repeat_one_lane_bit_share_vec::<P>(
                config,
                bit,
                lane_count,
                &label.child(format!("candidate_{idx}/selected_repeated")),
            )
            .map_err(OnlineError::from)?;
        let weighted = runtime
            .mul_public_lanes_share_vec::<P>(
                config,
                repeated.certified_share(),
                &lanes
                    .iter()
                    .copied()
                    .map(talus_core::Coeff::from)
                    .collect::<Vec<_>>(),
                &label.child(format!("candidate_{idx}/weighted")),
            )
            .map_err(OnlineError::from)?;
        selected = runtime
            .add_share_vec::<P>(
                config,
                &selected,
                &weighted,
                &label.child(format!("candidate_{idx}/accumulate")),
            )
            .map_err(OnlineError::from)?;
    }
    Ok(selected)
}

/// Drives checked opening of the selected response `z`.
pub fn strict_drive_selected_z_opening<P, T, L, C>(
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    selected_z: &ProductionShareVec,
    label: &Power2RoundTranscriptLabel,
) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    if selected_z.len() != P::L * P::N {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    runtime
        .drive_open_share_vec::<P>(config, selected_z, &label.child("open_selected_z"))
        .map_err(OnlineError::from)
}

/// Collects checked selected `z` opening.
pub fn strict_collect_selected_z_opening<P, T, L, C>(
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    label: &Power2RoundTranscriptLabel,
) -> Result<ProductionVectorItMpcCollectResult<PolyVec>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    match runtime
        .collect_open_share_vec::<P>(config, &label.child("open_selected_z"))
        .map_err(OnlineError::from)?
    {
        ProductionVectorItMpcCollectResult::Waiting(status) => {
            Ok(ProductionVectorItMpcCollectResult::Waiting(status))
        }
        ProductionVectorItMpcCollectResult::Collected { status, value } => {
            Ok(ProductionVectorItMpcCollectResult::Collected {
                status,
                value: strict_runtime_lanes_to_opened_polyvec::<P>(&value, P::L)?,
            })
        }
    }
}

fn strict_runtime_lanes_to_opened_polyvec<P: MlDsaParams>(
    lanes: &[talus_core::Coeff],
    poly_count: usize,
) -> Result<PolyVec, OnlineError> {
    if lanes.len() != poly_count * P::N {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let mut polys = Vec::with_capacity(poly_count);
    for poly_idx in 0..poly_count {
        let mut coeffs = [0; 256];
        coeffs.copy_from_slice(&lanes[poly_idx * P::N..(poly_idx + 1) * P::N]);
        polys.push(Poly::from_coeffs(coeffs));
    }
    Ok(PolyVec::new(polys))
}

/// Drives checked opening of selected hint bits.
pub fn strict_drive_selected_h_opening<P, T, L, C>(
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    selected_h: &ProductionBitShareVec,
    label: &Power2RoundTranscriptLabel,
) -> Result<PrimeFieldMpcPhaseDriverStatus, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    if selected_h.len() != P::K * P::N {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    runtime
        .drive_open_bit_share_vec::<P>(config, selected_h, &label.child("open_selected_h"))
        .map_err(OnlineError::from)
}

/// Collects checked selected hint bits opening.
pub fn strict_collect_selected_h_opening<P, T, L, C>(
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    label: &Power2RoundTranscriptLabel,
) -> Result<ProductionVectorItMpcCollectResult<PolyVec>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    match runtime
        .collect_open_bit_share_vec::<P>(config, &label.child("open_selected_h"))
        .map_err(OnlineError::from)?
    {
        ProductionVectorItMpcCollectResult::Waiting(status) => {
            Ok(ProductionVectorItMpcCollectResult::Waiting(status))
        }
        ProductionVectorItMpcCollectResult::Collected { status, value } => {
            Ok(ProductionVectorItMpcCollectResult::Collected {
                status,
                value: strict_hint_bits_to_polyvec::<P>(&value)?,
            })
        }
    }
}

/// Encodes the final signature after selected `ctilde`, `z`, and `h` are
/// available. This is intentionally after selected opening; candidate
/// signatures are not prebuilt or stored on runtime handles.
pub fn strict_encode_selected_signature<P: MlDsaParams>(
    ctilde: &[u8],
    z: &PolyVec,
    h: &PolyVec,
) -> Result<FinalSignature, OnlineError> {
    signature_encode::<P>(ctilde, z, h)
        .map(|bytes| FinalSignature { bytes })
        .map_err(OnlineError::from)
}

/// Builds the selected strict-signing output after selected opening only.
///
/// This function is the final non-verifier step for the runtime-backed path:
/// it encodes `ctilde*`, opened selected `z*`, and opened selected `h*`, then
/// emits coarse public evidence. It accepts no unselected candidates and no
/// pass/fail bits.
pub fn strict_build_selected_signature_output<P: MlDsaParams>(
    request: &StrictSignRequest,
    token_count: usize,
    selected_priority: StrictCandidatePriority,
    ctilde: &[u8],
    z: &PolyVec,
    h: &PolyVec,
) -> Result<StrictSelectedSignature, OnlineError> {
    let signature = strict_encode_selected_signature::<P>(ctilde, z, h)?;
    let signature_hash = strict_signature_hash(&signature);
    let counters = StrictResponseCheckCounters {
        candidates: token_count,
        private_response_vectors: token_count,
        z_bound_checks: token_count,
        hint_weight_checks: token_count,
        validity_bits: token_count,
        selected_openings: 1,
    };
    counters.validate_for_batch(token_count)?;
    Ok(StrictSelectedSignature {
        signature,
        evidence: StrictSigningEvidence {
            token_count,
            response_check_counters: counters,
            selected_priority,
            signature_hash,
            transcript_hash: strict_backend_transcript_hash(
                request,
                token_count,
                selected_priority,
                signature_hash,
            ),
        },
        vector_runtime_certificate: None,
    })
}

/// Selected-opening artifact emitted by the distributed strict runtime.
///
/// This is the handoff boundary between the app-driven vector MPC runtime and
/// `StrictSigningSession::finish`: it contains only selected public material
/// plus the durable runtime certificate. It must not contain rejected
/// candidate values, validity bits, failure reasons, or local partial
/// responses.
#[derive(Clone, Eq, PartialEq)]
pub struct StrictRuntimeSelectedOpeningArtifact {
    /// Hash of the strict signing request this artifact is bound to.
    pub request_hash: [u8; 32],
    /// Consumed token session ids in batch order.
    pub token_session_ids: Vec<SessionId>,
    /// Public priority of the privately selected valid candidate.
    pub selected_priority: StrictCandidatePriority,
    /// Selected challenge seed.
    pub selected_ctilde: Vec<u8>,
    /// Opened selected response.
    pub selected_z: PolyVec,
    /// Opened selected hint bits.
    pub selected_h: PolyVec,
    /// Durable vector runtime certificate proving the private checks/opening
    /// were produced by the production vector runtime.
    pub runtime_certificate: StrictSigningVectorRuntimeCertificate,
}

impl fmt::Debug for StrictRuntimeSelectedOpeningArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrictRuntimeSelectedOpeningArtifact")
            .field("request_hash", &self.request_hash)
            .field("token_count", &self.token_session_ids.len())
            .field("selected_priority", &self.selected_priority)
            .field("selected_ctilde_len", &self.selected_ctilde.len())
            .field("selected_z", &"<opened-selected-redacted>")
            .field("selected_h", &"<opened-selected-redacted>")
            .field("runtime_certificate", &"<validated>")
            .finish()
    }
}

impl StrictRuntimeSelectedOpeningArtifact {
    /// Creates a selected-opening artifact from the runtime output boundary.
    pub fn new(
        request_hash: [u8; 32],
        token_session_ids: Vec<SessionId>,
        selected_priority: StrictCandidatePriority,
        selected_ctilde: Vec<u8>,
        selected_z: PolyVec,
        selected_h: PolyVec,
        runtime_certificate: StrictSigningVectorRuntimeCertificate,
    ) -> Self {
        Self {
            request_hash,
            token_session_ids,
            selected_priority,
            selected_ctilde,
            selected_z,
            selected_h,
            runtime_certificate,
        }
    }
}

/// Source that runs or resumes the distributed vector runtime and returns the
/// selected-opening artifact for one already consumed strict-signing batch.
///
/// Implementations are the release handoff point for app-driven strict
/// signing. They must drive the private response/check/select/open phases and
/// return only the selected public material captured in
/// [`StrictRuntimeSelectedOpeningArtifact`].
pub trait StrictRuntimeSelectedOpeningArtifactSource<P: MlDsaParams> {
    /// Produces the selected-opening artifact for `batch`.
    fn produce_selected_opening_artifact(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: &ConsumedBccCertifiedTokenBatch,
    ) -> Result<StrictRuntimeSelectedOpeningArtifact, OnlineError>;
}

/// Live vector-MPC input handles for one strict signing candidate.
#[derive(Clone, Debug)]
pub struct StrictRuntimeCandidateShareInput {
    /// Token/session id this input belongs to.
    pub token_session_id: SessionId,
    /// Shared nonce response component `[y_j]`.
    pub y_share: ProductionShareVec,
    /// Shared long-term key component `[s1]`.
    pub s1_share: ProductionShareVec,
    /// Certified canonical mask value for decomposing `[z_j]`.
    pub z_mask_value: ProductionShareVec,
    /// Certified canonical mask bits for decomposing `[z_j]`.
    pub z_mask_bits_by_bit: Vec<ProductionBitShareVec>,
    /// Certified canonical mask value for decomposing
    /// `[A*z_j - c_j*t1*2^d]`.
    pub hint_mask_value: ProductionShareVec,
    /// Certified canonical mask bits for decomposing
    /// `[A*z_j - c_j*t1*2^d]`.
    pub hint_mask_bits_by_bit: Vec<ProductionBitShareVec>,
    /// Public `w1` vector for the candidate token.
    pub w1: Vec<u32>,
}

impl StrictRuntimeCandidateShareInput {
    fn validate_for<P: MlDsaParams>(&self) -> Result<(), OnlineError> {
        if self.y_share.len() != P::L * P::N
            || self.s1_share.len() != P::L * P::N
            || self.z_mask_value.len() != P::L * P::N
            || self.hint_mask_value.len() != P::K * P::N
            || self.z_mask_bits_by_bit.len() != 23
            || self.hint_mask_bits_by_bit.len() != 23
            || self
                .z_mask_bits_by_bit
                .iter()
                .any(|bits| bits.len() != P::L * P::N)
            || self
                .hint_mask_bits_by_bit
                .iter()
                .any(|bits| bits.len() != P::K * P::N)
            || self.w1.len() != P::K * P::N
        {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        Ok(())
    }
}

/// Non-secret profile entry for one live strict-signing vector runtime phase.
///
/// This is diagnostic data only. It records wall-clock time and durable-runtime
/// counter deltas by coarse phase; it must not contain candidate values,
/// validity bits, hints, z values, masks, or failure reasons.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictLiveVectorMpcPhaseProfile {
    /// Coarse phase name.
    pub phase: String,
    /// Candidate index for per-candidate phases.
    pub candidate_index: Option<usize>,
    /// Elapsed wall-clock time in milliseconds.
    pub elapsed_ms: u128,
    /// Counter delta observed in the durable runtime log during this phase.
    pub counter_delta: PrimeFieldMpcCounters,
}

fn strict_counter_delta(
    after: PrimeFieldMpcCounters,
    before: PrimeFieldMpcCounters,
) -> PrimeFieldMpcCounters {
    PrimeFieldMpcCounters {
        rounds: after.rounds.saturating_sub(before.rounds),
        private_messages: after
            .private_messages
            .saturating_sub(before.private_messages),
        broadcasts: after.broadcasts.saturating_sub(before.broadcasts),
        wire_bytes: after.wire_bytes.saturating_sub(before.wire_bytes),
        durable_log_bytes: after
            .durable_log_bytes
            .saturating_sub(before.durable_log_bytes),
        vector_lanes: after.vector_lanes.saturating_sub(before.vector_lanes),
        multiplication_layers: after
            .multiplication_layers
            .saturating_sub(before.multiplication_layers),
        wall_clock_ms: after.wall_clock_ms.saturating_sub(before.wall_clock_ms),
        scalar_mul_gates: after
            .scalar_mul_gates
            .saturating_sub(before.scalar_mul_gates),
        vector_mul_lanes: after
            .vector_mul_lanes
            .saturating_sub(before.vector_mul_lanes),
        scalar_openings: after.scalar_openings.saturating_sub(before.scalar_openings),
        vector_opening_lanes: after
            .vector_opening_lanes
            .saturating_sub(before.vector_opening_lanes),
        scalar_assert_zero: after
            .scalar_assert_zero
            .saturating_sub(before.scalar_assert_zero),
        vector_assert_zero_lanes: after
            .vector_assert_zero_lanes
            .saturating_sub(before.vector_assert_zero_lanes),
        random_bits: after.random_bits.saturating_sub(before.random_bits),
        local_public_mul_lanes: after
            .local_public_mul_lanes
            .saturating_sub(before.local_public_mul_lanes),
    }
}

/// Release-facing strict signing source backed by live vector MPC handles.
///
/// This source owns the runtime and candidate share handles. It prepares
/// `[z]`, derives private response-bound and hint predicates via the vector
/// runtime state machines, performs private priority selection, opens only the
/// selected `z` and `h`, and derives its certificate from the runtime's
/// durable wire log.
#[derive(Clone, Debug)]
pub struct ProductionStrictLiveVectorMpcArtifactSource<T, L, C, E> {
    config: DkgConfig,
    runtime: ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    entropy: E,
    public_key: Vec<u8>,
    candidate_inputs: Vec<StrictRuntimeCandidateShareInput>,
    profile: Vec<StrictLiveVectorMpcPhaseProfile>,
}

impl<T, L, C, E> ProductionStrictLiveVectorMpcArtifactSource<T, L, C, E> {
    /// Creates a live vector-MPC artifact source.
    pub fn new(
        config: DkgConfig,
        runtime: ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        entropy: E,
        public_key: Vec<u8>,
        candidate_inputs: Vec<StrictRuntimeCandidateShareInput>,
    ) -> Self {
        Self {
            config,
            runtime,
            entropy,
            public_key,
            candidate_inputs,
            profile: Vec::new(),
        }
    }

    /// Returns the owned runtime.
    pub const fn runtime(&self) -> &ProductionVectorPrimeFieldMpcRuntime<T, L, C> {
        &self.runtime
    }

    /// Returns the non-secret strict-signing runtime profile captured by the
    /// latest execution.
    pub fn profile(&self) -> &[StrictLiveVectorMpcPhaseProfile] {
        &self.profile
    }
}

impl<T, L, C, E> ProductionStrictLiveVectorMpcArtifactSource<T, L, C, E>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    fn profile_start(&self) -> (Instant, PrimeFieldMpcCounters) {
        let counters = self
            .runtime
            .runtime_evidence()
            .map(|evidence| evidence.counters)
            .unwrap_or_default();
        (Instant::now(), counters)
    }

    fn profile_finish(
        &mut self,
        phase: impl Into<String>,
        candidate_index: Option<usize>,
        started_at: Instant,
        counters_before: PrimeFieldMpcCounters,
    ) {
        let counters_after = self
            .runtime
            .runtime_evidence()
            .map(|evidence| evidence.counters)
            .unwrap_or_default();
        self.profile.push(StrictLiveVectorMpcPhaseProfile {
            phase: phase.into(),
            candidate_index,
            elapsed_ms: started_at.elapsed().as_millis(),
            counter_delta: strict_counter_delta(counters_after, counters_before),
        });
    }

    #[cfg(test)]
    fn print_profile(&self) {
        eprintln!("strict live vector MPC profile:");
        for entry in &self.profile {
            eprintln!(
                "  phase={} candidate={:?} elapsed_ms={} delta={:?}",
                entry.phase, entry.candidate_index, entry.elapsed_ms, entry.counter_delta
            );
        }
    }
}

fn strict_collected_unit(
    result: ProductionVectorItMpcCollectResult<()>,
) -> Result<(), OnlineError> {
    match result {
        ProductionVectorItMpcCollectResult::Collected { .. } => Ok(()),
        ProductionVectorItMpcCollectResult::Waiting(_) => {
            Err(OnlineError::StrictSigningRuntimeSlotIncomplete)
        }
    }
}

fn strict_collected_value<T>(
    result: ProductionVectorItMpcCollectResult<T>,
) -> Result<T, OnlineError> {
    match result {
        ProductionVectorItMpcCollectResult::Collected { value, .. } => Ok(value),
        ProductionVectorItMpcCollectResult::Waiting(_) => {
            Err(OnlineError::StrictSigningRuntimeSlotIncomplete)
        }
    }
}

fn strict_certify_canonical_bits<P, T, L, C, E>(
    state: &mut ProductionCanonicalBitDecompositionState,
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    label: &Power2RoundTranscriptLabel,
    entropy: &mut E,
) -> Result<Vec<ProductionBitShareVec>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
    E: ProductionVectorItMpcEntropy,
{
    state
        .drive_masked_c_opening_checked::<P, _, _, _>(runtime, config, label)
        .map_err(OnlineError::from)?;
    strict_collected_value(
        state
            .collect_masked_c_opening_checked::<P, _, _, _>(runtime, config, label)
            .map_err(OnlineError::from)?,
    )?;
    state
        .start_wrap_comparison::<P, _, _, _>(runtime, config, label)
        .map_err(OnlineError::from)?;
    loop {
        let status = state
            .drive_wrap_comparison_step::<P, _, _, _, _>(runtime, config, entropy)
            .map_err(OnlineError::from)?;
        if matches!(status, PrimeFieldMpcPhaseDriverStatus::Collected { .. }) {
            break;
        }
        strict_collected_unit(
            state
                .collect_wrap_comparison_step::<P, _, _, _>(runtime, config)
                .map_err(OnlineError::from)?,
        )?;
    }
    state
        .start_canonical_bit_recovery::<P, _, _, _>(runtime, config, label)
        .map_err(OnlineError::from)?;
    while state.r_bits_by_bit().is_none() {
        state
            .drive_canonical_bit_recovery_step::<P, _, _, _, _>(runtime, config, label, entropy)
            .map_err(OnlineError::from)?;
        strict_collected_unit(
            state
                .collect_canonical_bit_recovery_step::<P, _, _, _>(runtime, config, label)
                .map_err(OnlineError::from)?,
        )?;
    }
    for bit_idx in 0..23 {
        state
            .drive_r_bitness_product::<P, _, _, _, _>(runtime, config, label, bit_idx, entropy)
            .map_err(OnlineError::from)?;
        strict_collected_unit(
            state
                .collect_r_bitness_product::<P, _, _, _>(runtime, config, label, bit_idx)
                .map_err(OnlineError::from)?,
        )?;
        state
            .drive_r_bitness_zero_check::<P, _, _, _>(runtime, config, label, bit_idx)
            .map_err(OnlineError::from)?;
        strict_collected_unit(
            state
                .collect_r_bitness_zero_check::<P, _, _, _>(runtime, config, label, bit_idx)
                .map_err(OnlineError::from)?,
        )?;
    }
    state
        .start_r_lt_q_check::<P, _, _, _>(runtime, config, label)
        .map_err(OnlineError::from)?;
    while state.r_lt_q().is_none() {
        state
            .drive_r_lt_q_check_step::<P, _, _, _, _>(runtime, config, entropy)
            .map_err(OnlineError::from)?;
        strict_collected_unit(
            state
                .collect_r_lt_q_check_step::<P, _, _, _>(runtime, config)
                .map_err(OnlineError::from)?,
        )?;
    }
    state
        .drive_r_lt_q_assert_true::<P, _, _, _>(runtime, config, label)
        .map_err(OnlineError::from)?;
    strict_collected_unit(
        state
            .collect_r_lt_q_assert_true::<P, _, _, _>(runtime, config, label)
            .map_err(OnlineError::from)?,
    )?;
    state
        .drive_r_bits_equal_value_check::<P, _, _, _>(runtime, config, label)
        .map_err(OnlineError::from)?;
    strict_collected_unit(
        state
            .collect_r_bits_equal_value_check::<P, _, _, _>(runtime, config, label)
            .map_err(OnlineError::from)?,
    )?;
    state
        .r_bits_by_bit()
        .map(|bits| bits.to_vec())
        .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)
}

impl<P, T, L, C, E> StrictRuntimeSelectedOpeningArtifactSource<P>
    for ProductionStrictLiveVectorMpcArtifactSource<T, L, C, E>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
    E: ProductionVectorItMpcEntropy,
{
    fn produce_selected_opening_artifact(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: &ConsumedBccCertifiedTokenBatch,
    ) -> Result<StrictRuntimeSelectedOpeningArtifact, OnlineError> {
        if request.suite != P::NAME || request.signing_set.as_slice() != batch.signer_set() {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        if self.candidate_inputs.len() != batch.len() {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let metadata = strict_candidate_metadata_batch::<P>(request, batch, tr);
        let token_session_ids = batch.session_ids();
        let root_label = Power2RoundTranscriptLabel::root(
            &self.config,
            strict_signing_session_id(request, &token_session_ids).0,
        )
        .child("strict_signing");

        let mut candidates = Vec::with_capacity(batch.len());
        let mut valid_bits = Vec::with_capacity(batch.len());
        for idx in 0..batch.len() {
            let token = &batch.tokens()[idx];
            let meta = &metadata[idx];
            let input = self.candidate_inputs[idx].clone();
            if input.token_session_id != token.session_id {
                return Err(OnlineError::StrictResponseCheckShapeMismatch);
            }
            input.validate_for::<P>()?;
            let label = root_label.child(format!("candidate_{idx}"));
            let (started_at, counters_before) = self.profile_start();
            let z_share = strict_prepare_runtime_z_share::<P, _, _, _>(
                &self.runtime,
                &self.config,
                &input.y_share,
                &input.s1_share,
                &meta.ctilde,
                &label.child("response"),
            )?;
            self.profile_finish("z_response_prep", Some(idx), started_at, counters_before);

            let (started_at, counters_before) = self.profile_start();
            let mut z_decomp = ProductionCanonicalBitDecompositionState::new::<P, _, _, _>(
                &self.runtime,
                &self.config,
                z_share.clone(),
                input.z_mask_value.clone(),
                input.z_mask_bits_by_bit.clone(),
            )
            .map_err(OnlineError::from)?;
            let z_bits = strict_certify_canonical_bits::<P, _, _, _, _>(
                &mut z_decomp,
                &mut self.runtime,
                &self.config,
                &label.child("z_canonical"),
                &mut self.entropy,
            )?;
            self.profile_finish(
                "z_canonical_decomposition",
                Some(idx),
                started_at,
                counters_before,
            );

            let (started_at, counters_before) = self.profile_start();
            let mut z_bound = StrictRuntimeZBoundCheckState::new::<P, _, _, _>(
                &self.runtime,
                &self.config,
                &z_bits,
                &label.child("z_bound"),
            )?;
            while z_bound.lt_gamma.result().is_none() {
                z_bound.drive_lt_gamma_step::<P, _, _, _, _>(
                    &mut self.runtime,
                    &self.config,
                    &mut self.entropy,
                )?;
                strict_collected_unit(
                    z_bound.collect_lt_gamma_step::<P, _, _, _>(&mut self.runtime, &self.config)?,
                )?;
            }
            while z_bound.gt_upper.result().is_none() {
                z_bound.drive_gt_upper_step::<P, _, _, _, _>(
                    &mut self.runtime,
                    &self.config,
                    &mut self.entropy,
                )?;
                strict_collected_unit(
                    z_bound.collect_gt_upper_step::<P, _, _, _>(&mut self.runtime, &self.config)?,
                )?;
            }
            z_bound.drive_or_step::<P, _, _, _, _>(
                &mut self.runtime,
                &self.config,
                &label.child("z_bound"),
                &mut self.entropy,
            )?;
            strict_collected_unit(z_bound.collect_or_step::<P, _, _, _>(
                &mut self.runtime,
                &self.config,
                &label.child("z_bound"),
            )?)?;
            self.profile_finish("z_bound_checks", Some(idx), started_at, counters_before);

            let (started_at, counters_before) = self.profile_start();
            let mut all_z_bound = StrictRuntimeAllBitsTrueState::new::<P, _, _, _>(
                &self.runtime,
                &self.config,
                z_bound
                    .result()
                    .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?,
                &label.child("z_bound_all"),
            )?;
            while all_z_bound.result().is_none() {
                all_z_bound.drive_step::<P, _, _, _, _>(
                    &mut self.runtime,
                    &self.config,
                    &mut self.entropy,
                )?;
                strict_collected_unit(
                    all_z_bound.collect_step::<P, _, _, _>(&mut self.runtime, &self.config)?,
                )?;
            }
            self.profile_finish("z_bound_all", Some(idx), started_at, counters_before);

            let (started_at, counters_before) = self.profile_start();
            let hint_approx = strict_runtime_hint_approx_share::<P, _, _, _>(
                &self.runtime,
                &self.config,
                &self.public_key,
                &meta.ctilde,
                &z_share,
                &label.child("hint_approx"),
            )?;
            self.profile_finish("hint_approx", Some(idx), started_at, counters_before);

            let (started_at, counters_before) = self.profile_start();
            let mut hint_decomp = ProductionCanonicalBitDecompositionState::new::<P, _, _, _>(
                &self.runtime,
                &self.config,
                hint_approx,
                input.hint_mask_value.clone(),
                input.hint_mask_bits_by_bit.clone(),
            )
            .map_err(OnlineError::from)?;
            let hint_bits_input = strict_certify_canonical_bits::<P, _, _, _, _>(
                &mut hint_decomp,
                &mut self.runtime,
                &self.config,
                &label.child("hint_canonical"),
                &mut self.entropy,
            )?;
            self.profile_finish(
                "hint_canonical_decomposition",
                Some(idx),
                started_at,
                counters_before,
            );

            let (started_at, counters_before) = self.profile_start();
            let mut hint_bits = StrictRuntimeHintBitsCheckState::new::<P, _, _, _>(
                &self.runtime,
                &self.config,
                &hint_bits_input,
                &input.w1,
                &label.child("hint_bits"),
            )?;
            while hint_bits.gt_lower.result().is_none() {
                hint_bits.drive_gt_lower_step::<P, _, _, _, _>(
                    &mut self.runtime,
                    &self.config,
                    &mut self.entropy,
                )?;
                strict_collected_unit(
                    hint_bits
                        .collect_gt_lower_step::<P, _, _, _>(&mut self.runtime, &self.config)?,
                )?;
            }
            while hint_bits.lt_upper.result().is_none() {
                hint_bits.drive_lt_upper_step::<P, _, _, _, _>(
                    &mut self.runtime,
                    &self.config,
                    &mut self.entropy,
                )?;
                strict_collected_unit(
                    hint_bits
                        .collect_lt_upper_step::<P, _, _, _>(&mut self.runtime, &self.config)?,
                )?;
            }
            hint_bits.drive_interval_and_step::<P, _, _, _, _>(
                &mut self.runtime,
                &self.config,
                &label.child("hint_bits"),
                &mut self.entropy,
            )?;
            strict_collected_unit(hint_bits.collect_interval_and_step::<P, _, _, _>(
                &mut self.runtime,
                &self.config,
                &label.child("hint_bits"),
            )?)?;
            hint_bits.drive_wrap_or_step::<P, _, _, _, _>(
                &mut self.runtime,
                &self.config,
                &label.child("hint_bits"),
                &mut self.entropy,
            )?;
            strict_collected_unit(hint_bits.collect_wrap_or_and_finalize::<P, _, _, _>(
                &mut self.runtime,
                &self.config,
                &label.child("hint_bits"),
            )?)?;
            self.profile_finish(
                "hint_highbits_checks",
                Some(idx),
                started_at,
                counters_before,
            );
            let h_bits = hint_bits
                .hint_bits()
                .cloned()
                .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
            let (started_at, counters_before) = self.profile_start();
            let mut hint_weight = StrictRuntimeHintWeightCheckState::new::<P, _, _, _>(
                &self.runtime,
                &self.config,
                &h_bits,
                &label.child("hint_weight"),
            )?;
            while hint_weight.result().is_none() {
                hint_weight.drive_step::<P, _, _, _, _>(
                    &mut self.runtime,
                    &self.config,
                    &mut self.entropy,
                )?;
                strict_collected_unit(
                    hint_weight.collect_step::<P, _, _, _>(&mut self.runtime, &self.config)?,
                )?;
            }
            self.profile_finish("hint_weight_check", Some(idx), started_at, counters_before);

            let (started_at, counters_before) = self.profile_start();
            let mut valid = StrictRuntimeValidBitState::new();
            valid.drive_step::<P, _, _, _, _>(
                &mut self.runtime,
                &self.config,
                all_z_bound
                    .result()
                    .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?,
                hint_weight
                    .result()
                    .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?,
                &label.child("valid"),
                &mut self.entropy,
            )?;
            strict_collected_unit(valid.collect_step::<P, _, _, _>(
                &mut self.runtime,
                &self.config,
                &label.child("valid"),
            )?)?;
            self.profile_finish("valid_bit", Some(idx), started_at, counters_before);
            let valid_bit = valid
                .result()
                .cloned()
                .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
            valid_bits.push(valid_bit.clone());
            candidates.push(
                StrictRuntimeCandidateHandle::new_runtime_prepared(
                    meta.priority,
                    meta.ctilde.clone(),
                    z_share,
                )
                .with_z_bound_ok(
                    all_z_bound
                        .result()
                        .cloned()
                        .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?,
                )
                .with_h_bits(h_bits.clone())
                .with_hint_ok(
                    hint_weight
                        .result()
                        .cloned()
                        .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?,
                )
                .with_valid(valid_bit),
            );
        }

        let priorities = candidates
            .iter()
            .map(StrictRuntimeCandidateHandle::priority)
            .collect::<Vec<_>>();
        let (started_at, counters_before) = self.profile_start();
        let mut selection = StrictRuntimePrioritySelectionState::new::<P, _, _, _>(
            &self.runtime,
            &self.config,
            &priorities,
            &valid_bits,
            &root_label.child("priority_selection"),
        )?;
        while !selection.is_done() {
            selection.drive_step::<P, _, _, _, _>(
                &mut self.runtime,
                &self.config,
                &valid_bits,
                &root_label.child("priority_selection"),
                &mut self.entropy,
            )?;
            strict_collected_unit(selection.collect_step::<P, _, _, _>(
                &mut self.runtime,
                &self.config,
                &valid_bits,
                &root_label.child("priority_selection"),
            )?)?;
        }
        let selected_bits = selection
            .selected_bits()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let any_valid = selection
            .any_valid_bit()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        self.profile_finish("priority_selection", None, started_at, counters_before);

        let (started_at, counters_before) = self.profile_start();
        let selection_residual = self
            .runtime
            .one_hot_sum_minus_one::<P>(
                &self.config,
                &selected_bits,
                &root_label.child("priority_selection/one_hot"),
            )
            .map_err(OnlineError::from)?;
        self.runtime
            .drive_private_selection_check_share_vec::<P>(
                &self.config,
                &selection_residual,
                &root_label.child("priority_selection/one_hot"),
            )
            .map_err(OnlineError::from)?;
        strict_collected_unit(
            self.runtime
                .collect_private_selection_check_share_vec::<P>(
                    &self.config,
                    &root_label.child("priority_selection/one_hot"),
                )
                .map_err(OnlineError::from)?,
        )?;
        self.profile_finish("one_hot_selection_check", None, started_at, counters_before);

        let (started_at, counters_before) = self.profile_start();
        self.runtime
            .drive_open_bit_share_vec::<P>(
                &self.config,
                &any_valid,
                &root_label.child("any_valid/open"),
            )
            .map_err(OnlineError::from)?;
        let opened_any_valid = strict_collected_value(
            self.runtime
                .collect_open_bit_share_vec::<P>(&self.config, &root_label.child("any_valid/open"))
                .map_err(OnlineError::from)?,
        )?;
        match opened_any_valid.as_slice() {
            [1] => {}
            [0] => return Err(OnlineError::GenericBatchFailure),
            _ => return Err(OnlineError::StrictResponseCheckShapeMismatch),
        }
        self.profile_finish("any_valid_opening", None, started_at, counters_before);

        let (started_at, counters_before) = self.profile_start();
        let selected_priority_share = strict_selected_public_lanes_share::<P, _, _, _>(
            &self.runtime,
            &self.config,
            &selected_bits,
            &priorities
                .iter()
                .map(|priority| priority.0.to_vec())
                .collect::<Vec<_>>(),
            &root_label.child("selected_priority"),
        )?;
        self.runtime
            .drive_open_share_vec::<P>(
                &self.config,
                &selected_priority_share,
                &root_label.child("selected_priority/open"),
            )
            .map_err(OnlineError::from)?;
        let selected_priority_bytes = strict_u8_lanes_from_opening(&strict_collected_value(
            self.runtime
                .collect_open_share_vec::<P>(
                    &self.config,
                    &root_label.child("selected_priority/open"),
                )
                .map_err(OnlineError::from)?,
        )?)?;
        let selected_priority = StrictCandidatePriority(
            selected_priority_bytes
                .try_into()
                .map_err(|_| OnlineError::StrictResponseCheckShapeMismatch)?,
        );
        self.profile_finish(
            "selected_priority_opening",
            None,
            started_at,
            counters_before,
        );

        let (started_at, counters_before) = self.profile_start();
        let selected_ctilde_share = strict_selected_public_lanes_share::<P, _, _, _>(
            &self.runtime,
            &self.config,
            &selected_bits,
            &metadata
                .iter()
                .map(|candidate| candidate.ctilde.clone())
                .collect::<Vec<_>>(),
            &root_label.child("selected_ctilde"),
        )?;
        self.runtime
            .drive_open_share_vec::<P>(
                &self.config,
                &selected_ctilde_share,
                &root_label.child("selected_ctilde/open"),
            )
            .map_err(OnlineError::from)?;
        let selected_ctilde = strict_u8_lanes_from_opening(&strict_collected_value(
            self.runtime
                .collect_open_share_vec::<P>(
                    &self.config,
                    &root_label.child("selected_ctilde/open"),
                )
                .map_err(OnlineError::from)?,
        )?)?;
        self.profile_finish("selected_ctilde_opening", None, started_at, counters_before);
        let z_values = candidates
            .iter()
            .map(|candidate| candidate.z_share().clone())
            .collect::<Vec<_>>();
        let h_values = candidates
            .iter()
            .map(|candidate| {
                candidate
                    .h_bits()
                    .cloned()
                    .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (started_at, counters_before) = self.profile_start();
        strict_drive_selected_share_products::<P, _, _, _, _>(
            &mut self.runtime,
            &self.config,
            &selected_bits,
            &z_values,
            &root_label.child("selected_z"),
            &mut self.entropy,
        )?;
        let selected_z =
            strict_collected_value(strict_collect_selected_share_products::<P, _, _, _>(
                &mut self.runtime,
                &self.config,
                candidates.len(),
                &root_label.child("selected_z"),
            )?)?;
        self.profile_finish("selected_z_product", None, started_at, counters_before);

        let (started_at, counters_before) = self.profile_start();
        strict_drive_selected_share_products::<P, _, _, _, _>(
            &mut self.runtime,
            &self.config,
            &selected_bits,
            &h_values
                .iter()
                .map(|bits| bits.certified_share().clone())
                .collect::<Vec<_>>(),
            &root_label.child("selected_h"),
            &mut self.entropy,
        )?;
        let selected_h_share =
            strict_collected_value(strict_collect_selected_share_products::<P, _, _, _>(
                &mut self.runtime,
                &self.config,
                candidates.len(),
                &root_label.child("selected_h"),
            )?)?;
        let selected_h = ProductionBitShareVec::from_certified_share(selected_h_share);
        self.profile_finish("selected_h_product", None, started_at, counters_before);

        let (started_at, counters_before) = self.profile_start();
        strict_drive_selected_z_opening::<P, _, _, _>(
            &mut self.runtime,
            &self.config,
            &selected_z,
            &root_label.child("selected_opening"),
        )?;
        let opened_z = strict_collected_value(strict_collect_selected_z_opening::<P, _, _, _>(
            &mut self.runtime,
            &self.config,
            &root_label.child("selected_opening"),
        )?)?;
        self.profile_finish("selected_z_opening", None, started_at, counters_before);

        let (started_at, counters_before) = self.profile_start();
        strict_drive_selected_h_opening::<P, _, _, _>(
            &mut self.runtime,
            &self.config,
            &selected_h,
            &root_label.child("selected_opening"),
        )?;
        let opened_h = strict_collected_value(strict_collect_selected_h_opening::<P, _, _, _>(
            &mut self.runtime,
            &self.config,
            &root_label.child("selected_opening"),
        )?)?;
        self.profile_finish("selected_h_opening", None, started_at, counters_before);

        let (started_at, counters_before) = self.profile_start();
        let runtime_evidence = self.runtime.runtime_evidence().map_err(OnlineError::from)?;
        let certificate =
            StrictSigningVectorRuntimeCertificate::new_for_strict_signing(runtime_evidence)?;
        self.profile_finish("runtime_certificate", None, started_at, counters_before);
        #[cfg(test)]
        self.print_profile();
        Ok(StrictRuntimeSelectedOpeningArtifact::new(
            strict_signing_request_hash(request),
            token_session_ids,
            selected_priority,
            selected_ctilde,
            opened_z,
            opened_h,
            certificate,
        ))
    }
}

/// Release backend that obtains the selected-opening artifact from an owned
/// distributed-runtime source after token consumption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionStrictRuntimeSelectedOpeningArtifactBackend<S> {
    source: S,
}

impl<S> ProductionStrictRuntimeSelectedOpeningArtifactBackend<S> {
    /// Creates a release backend from an app-driven runtime artifact source.
    pub fn new(source: S) -> Self {
        Self { source }
    }

    /// Returns the underlying artifact source.
    pub const fn source(&self) -> &S {
        &self.source
    }

    /// Consumes the backend and returns the underlying artifact source.
    pub fn into_source(self) -> S {
        self.source
    }
}

impl<P, S> StrictPrivateSigningBackend<P>
    for ProductionStrictRuntimeSelectedOpeningArtifactBackend<S>
where
    P: MlDsaParams,
    S: StrictRuntimeSelectedOpeningArtifactSource<P>,
{
    fn sign_consumed_batch(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: ConsumedBccCertifiedTokenBatch,
    ) -> Result<StrictSelectedSignature, OnlineError> {
        let artifact = self
            .source
            .produce_selected_opening_artifact(request, tr, &batch)?;
        StrictPrivateSigningBackend::<P>::sign_consumed_batch(
            &mut ProductionStrictRuntimeSelectedOpeningBackend::new(artifact),
            request,
            tr,
            batch,
        )
    }
}

/// Concrete strict artifact source that adapts the canonical vector component
/// stack into the selected-opening artifact handoff.
///
/// This source does not expose the component-stack selected output as a release
/// signature. It runs the canonical response/check/select/open boundaries
/// internally and returns only the artifact consumed by
/// [`ProductionStrictRuntimeSelectedOpeningArtifactBackend`].
#[cfg(any(test, feature = "scaffold-dev"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionStrictVectorMpcArtifactSource<SP> {
    public_key: Vec<u8>,
    share_provider: SP,
    runtime_certificate: StrictSigningVectorRuntimeCertificate,
}

#[cfg(any(test, feature = "scaffold-dev"))]
impl<SP> ProductionStrictVectorMpcArtifactSource<SP> {
    /// Creates an artifact source from a share provider and durable runtime
    /// evidence.
    pub fn new(
        public_key: Vec<u8>,
        share_provider: SP,
        runtime_evidence: ProductionVectorItMpcRuntimeEvidence,
    ) -> Result<Self, OnlineError> {
        Ok(Self {
            public_key,
            share_provider,
            runtime_certificate: StrictSigningVectorRuntimeCertificate::new(runtime_evidence)?,
        })
    }

    /// Creates an artifact source from a pre-validated runtime certificate.
    pub fn with_certificate(
        public_key: Vec<u8>,
        share_provider: SP,
        runtime_certificate: StrictSigningVectorRuntimeCertificate,
    ) -> Self {
        Self {
            public_key,
            share_provider,
            runtime_certificate,
        }
    }
}

#[cfg(any(test, feature = "scaffold-dev"))]
impl<P, SP> StrictRuntimeSelectedOpeningArtifactSource<P>
    for ProductionStrictVectorMpcArtifactSource<SP>
where
    P: MlDsaParams,
    SP: StrictPolynomialShareProvider,
{
    fn produce_selected_opening_artifact(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: &ConsumedBccCertifiedTokenBatch,
    ) -> Result<StrictRuntimeSelectedOpeningArtifact, OnlineError> {
        let metadata = strict_candidate_metadata_batch::<P>(request, batch, tr);
        let mut driver = StrictResponseCheckPhaseDriver::new();
        driver.accept_metadata(batch.len())?;

        let mut prepare = ProductionVectorResponsePreparationBackend::new(
            self.public_key.clone(),
            &self.share_provider,
        );
        let prepared =
            <ProductionVectorResponsePreparationBackend<&SP> as StrictResponsePreparationBackend<
                P,
            >>::prepare_private_responses(&mut prepare, request, tr, batch, &metadata)?;
        prepared.validate_len(batch.len())?;
        driver.accept_shared_responses(batch.len())?;

        let mut bounds = ProductionVectorResponseBoundCheckBackend;
        let (candidates, bound_evidence) =
            <ProductionVectorResponseBoundCheckBackend as StrictResponseBoundCheckBackend<
                P,
            >>::check_response_bounds(&mut bounds, &metadata, prepared.candidates, &mut driver)?;
        bound_evidence.validate_for_batch::<P>(batch.len())?;

        let mut hints = ProductionVectorHintCheckBackend;
        let w1_refs = prepared
            .w1_vectors
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let (candidates, hint_evidence) =
            <ProductionVectorHintCheckBackend as StrictHintCheckBackend<P>>::check_hints(
                &mut hints,
                &metadata,
                candidates,
                &prepared.public_key,
                &w1_refs,
                &mut driver,
            )?;
        hint_evidence.validate_for_batch::<P>(batch.len())?;

        let mut selector = ProductionVectorPrivateSelectionBackend::new();
        let (selected, selection_evidence) =
            selector.select_candidate(&metadata, candidates, &mut driver)?;
        selection_evidence.validate_for_batch(batch.len())?;

        let selected_ctilde = selected.ctilde.clone();
        let selected_z = selected.response.clone();
        let selected_h = selected
            .hint
            .clone()
            .ok_or(OnlineError::GenericBatchFailure)?;
        let mut opener = ProductionVectorSelectedOpeningBackend::new();
        let (_signature, opening_evidence) =
            opener.open_selected(&selection_evidence, selected, &mut driver)?;
        opening_evidence.validate_for_selection(&selection_evidence)?;
        driver.counters()?.validate_for_batch(batch.len())?;

        Ok(StrictRuntimeSelectedOpeningArtifact::new(
            strict_signing_request_hash(request),
            batch
                .tokens()
                .iter()
                .map(|token| token.session_id)
                .collect(),
            opening_evidence.selected_priority,
            selected_ctilde,
            selected_z,
            selected_h,
            self.runtime_certificate.clone(),
        ))
    }
}

/// Release backend that consumes only a distributed runtime selected-opening
/// artifact.
///
/// Unlike the local component stack, this backend does not compute responses,
/// checks, selection, or openings. It validates that the supplied artifact is
/// bound to the request and consumed token batch, then encodes the final
/// signature from selected material only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionStrictRuntimeSelectedOpeningBackend {
    artifact: Option<StrictRuntimeSelectedOpeningArtifact>,
}

impl ProductionStrictRuntimeSelectedOpeningBackend {
    /// Creates a backend from one selected-opening runtime artifact.
    pub fn new(artifact: StrictRuntimeSelectedOpeningArtifact) -> Self {
        Self {
            artifact: Some(artifact),
        }
    }
}

impl<P: MlDsaParams> StrictPrivateSigningBackend<P>
    for ProductionStrictRuntimeSelectedOpeningBackend
{
    fn sign_consumed_batch(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: ConsumedBccCertifiedTokenBatch,
    ) -> Result<StrictSelectedSignature, OnlineError> {
        let artifact = self
            .artifact
            .take()
            .ok_or(OnlineError::StrictSigningSessionAlreadyFinished)?;
        if artifact.request_hash != strict_signing_request_hash(request) {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let token_session_ids = batch
            .tokens()
            .iter()
            .map(|token| token.session_id)
            .collect::<Vec<_>>();
        if artifact.token_session_ids != token_session_ids {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let selected_metadata = batch
            .tokens()
            .iter()
            .map(|token| strict_candidate_metadata::<P>(request, token, tr))
            .find(|metadata| metadata.priority == artifact.selected_priority)
            .ok_or(OnlineError::GenericBatchFailure)?;
        if selected_metadata.ctilde != artifact.selected_ctilde {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let selected = strict_build_selected_signature_output::<P>(
            request,
            batch.len(),
            artifact.selected_priority,
            &artifact.selected_ctilde,
            &artifact.selected_z,
            &artifact.selected_h,
        )?;
        Ok(selected.with_vector_runtime_certificate(
            artifact
                .runtime_certificate
                .into_selected_opening_artifact(),
        ))
    }
}

/// Production vector response-preparation backend for strict signing.
pub struct ProductionVectorResponsePreparationBackend<SP> {
    /// Serialized FIPS public key.
    pub public_key: Vec<u8>,
    /// Provider for private polynomial shares.
    pub share_provider: SP,
}

impl<SP> ProductionVectorResponsePreparationBackend<SP> {
    /// Creates a vector response-preparation backend.
    pub fn new(public_key: Vec<u8>, share_provider: SP) -> Self {
        Self {
            public_key,
            share_provider,
        }
    }
}

impl<P, SP> StrictResponsePreparationBackend<P> for ProductionVectorResponsePreparationBackend<SP>
where
    P: MlDsaParams,
    SP: StrictPolynomialShareProvider,
{
    type Candidate = StrictVectorCandidateHandle;

    fn prepare_private_responses(
        &mut self,
        _request: &StrictSignRequest,
        _tr: &[u8; 64],
        batch: &ConsumedBccCertifiedTokenBatch,
        metadata: &[StrictCandidateMetadata],
    ) -> Result<StrictPreparedResponseBatch<Self::Candidate>, OnlineError> {
        if metadata.len() != batch.len() {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let mut candidates = Vec::with_capacity(metadata.len());
        for (token, meta) in batch.tokens().iter().zip(metadata) {
            let mut points = Vec::with_capacity(token.signer_set.len());
            let mut responses = Vec::with_capacity(token.signer_set.len());
            for &party in &token.signer_set {
                let share = self.share_provider.signing_share(token.session_id, party)?;
                if share.party != party {
                    return Err(OnlineError::StrictResponseCheckShapeMismatch);
                }
                points.push(u32::from(party.0));
                responses.push(strict_response_polyvec::<P>(
                    &meta.ctilde,
                    &share.y,
                    &share.s1,
                )?);
            }
            let response = strict_aggregate_response_lagrange::<P>(&points, &responses)?;
            candidates.push(StrictVectorCandidateHandle {
                priority: meta.priority,
                ctilde: meta.ctilde.clone(),
                response,
                bound_ok: None,
                hint_ok: None,
                hint: None,
                signature: None,
            });
        }
        Ok(StrictPreparedResponseBatch {
            candidates,
            public_key: self.public_key.clone(),
            w1_vectors: batch
                .tokens()
                .iter()
                .map(|token| token.w1.clone())
                .collect(),
        })
    }
}

/// Batched vector response-bound checker for strict signing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProductionVectorResponseBoundCheckBackend;

impl<P: MlDsaParams> StrictResponseBoundCheckBackend<P>
    for ProductionVectorResponseBoundCheckBackend
{
    type ResponseVector = StrictVectorCandidateHandle;

    fn check_response_bounds(
        &mut self,
        metadata: &[StrictCandidateMetadata],
        mut responses: Vec<Self::ResponseVector>,
        driver: &mut StrictResponseCheckPhaseDriver,
    ) -> Result<(Vec<Self::ResponseVector>, StrictResponseBoundEvidence), OnlineError> {
        if metadata.len() != responses.len() {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        for handle in &mut responses {
            handle.bound_ok = Some(z_bound_holds::<P>(&handle.response));
        }
        driver.accept_response_bounds(responses.len())?;
        let token_count = responses.len();
        Ok((
            responses,
            StrictResponseBoundEvidence {
                token_count,
                coefficients_per_candidate: P::L * P::N,
            },
        ))
    }
}

/// Batched vector hint/highbits checker for strict signing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProductionVectorHintCheckBackend;

impl<P: MlDsaParams> StrictHintCheckBackend<P> for ProductionVectorHintCheckBackend {
    type ResponseVector = StrictVectorCandidateHandle;

    fn check_hints(
        &mut self,
        metadata: &[StrictCandidateMetadata],
        mut responses: Vec<Self::ResponseVector>,
        public_key: &[u8],
        w1_vectors: &[&[u32]],
        driver: &mut StrictResponseCheckPhaseDriver,
    ) -> Result<(Vec<Self::ResponseVector>, StrictHintCheckEvidence), OnlineError> {
        if metadata.len() != responses.len() || responses.len() != w1_vectors.len() {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let decoded = public_key_decode::<P>(public_key)?;
        for (handle, w1) in responses.iter_mut().zip(w1_vectors) {
            let result = az_from_rho::<P>(&decoded.rho, &handle.response)
                .map_err(OnlineError::from)
                .and_then(|az| {
                    public_approx_from_az::<P>(&az, &handle.ctilde, &decoded.t1)
                        .map_err(OnlineError::from)
                })
                .and_then(|approx| {
                    compute_talus_hint_polyvec::<P>(&approx, w1).map_err(OnlineError::from)
                });
            match result {
                Ok(hint) => {
                    let signature = signature_encode::<P>(&handle.ctilde, &handle.response, &hint)
                        .map(|bytes| FinalSignature { bytes })
                        .map_err(OnlineError::from)?;
                    handle.hint_ok = Some(true);
                    handle.hint = Some(hint);
                    handle.signature = Some(signature);
                }
                Err(_) => {
                    handle.hint_ok = Some(false);
                    handle.hint = None;
                    handle.signature = None;
                }
            }
        }
        driver.accept_hint_checks(responses.len())?;
        let token_count = responses.len();
        Ok((
            responses,
            StrictHintCheckEvidence {
                token_count,
                coefficients_per_candidate: P::K * P::N,
            },
        ))
    }
}

/// Private valid-bit combiner and priority selector for vector strict signing.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ProductionVectorPrivateSelectionBackend {
    selected_priority: Option<StrictCandidatePriority>,
}

impl fmt::Debug for ProductionVectorPrivateSelectionBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProductionVectorPrivateSelectionBackend")
            .field("selected", &self.selected_priority.is_some())
            .finish()
    }
}

impl ProductionVectorPrivateSelectionBackend {
    /// Creates an empty private selector.
    pub const fn new() -> Self {
        Self {
            selected_priority: None,
        }
    }
}

impl StrictPrivateSelectionBackend for ProductionVectorPrivateSelectionBackend {
    type Candidate = StrictVectorCandidateHandle;

    fn select_candidate(
        &mut self,
        metadata: &[StrictCandidateMetadata],
        candidates: Vec<Self::Candidate>,
        driver: &mut StrictResponseCheckPhaseDriver,
    ) -> Result<(Self::Candidate, StrictPrivateSelectionEvidence), OnlineError> {
        if metadata.len() != candidates.len() {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        driver.accept_private_pass_bits(candidates.len())?;
        let selected_priority = candidates
            .iter()
            .filter_map(|handle| {
                let ok = handle.bound_ok? && handle.hint_ok? && handle.signature.is_some();
                ok.then_some(handle.priority)
            })
            .min();
        driver.accept_priority_selection(selected_priority.is_some())?;
        let selected_priority = selected_priority.ok_or(OnlineError::GenericBatchFailure)?;
        let selected = candidates
            .into_iter()
            .find(|handle| {
                handle.priority == selected_priority
                    && handle.bound_ok == Some(true)
                    && handle.hint_ok == Some(true)
                    && handle.signature.is_some()
            })
            .ok_or(OnlineError::GenericBatchFailure)?;
        self.selected_priority = Some(selected_priority);
        Ok((
            selected,
            StrictPrivateSelectionEvidence {
                token_count: metadata.len(),
                selected_priority,
            },
        ))
    }
}

/// Selected-only opener for vector strict signing.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ProductionVectorSelectedOpeningBackend {
    opened_hash: Option<[u8; 32]>,
}

impl fmt::Debug for ProductionVectorSelectedOpeningBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProductionVectorSelectedOpeningBackend")
            .field("opened", &self.opened_hash.is_some())
            .finish()
    }
}

impl ProductionVectorSelectedOpeningBackend {
    /// Creates an empty selected opener.
    pub const fn new() -> Self {
        Self { opened_hash: None }
    }
}

impl StrictSelectedOpeningBackend for ProductionVectorSelectedOpeningBackend {
    type Candidate = StrictVectorCandidateHandle;

    fn open_selected(
        &mut self,
        selection: &StrictPrivateSelectionEvidence,
        selected: Self::Candidate,
        driver: &mut StrictResponseCheckPhaseDriver,
    ) -> Result<(FinalSignature, StrictSelectedOpeningEvidence), OnlineError> {
        if selected.priority != selection.selected_priority
            || selected.bound_ok != Some(true)
            || selected.hint_ok != Some(true)
        {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let signature = selected.signature.ok_or(OnlineError::GenericBatchFailure)?;
        driver.accept_selected_opening()?;
        let signature_hash = strict_signature_hash(&signature);
        self.opened_hash = Some(signature_hash);
        Ok((
            signature,
            StrictSelectedOpeningEvidence {
                token_count: selection.token_count,
                selected_priority: selection.selected_priority,
                signature_hash,
            },
        ))
    }
}

/// Canonical production strict-signing backend stack.
///
/// Normal callers should use this alias or [`strict_production_signing_backend`]
/// instead of manually composing a parallel response/check/select/open path.
pub type StrictProductionSigningBackend<SP> = ProductionStrictSigningBackend<
    ProductionVectorResponsePreparationBackend<SP>,
    ProductionVectorResponseBoundCheckBackend,
    ProductionVectorHintCheckBackend,
    ProductionVectorPrivateSelectionBackend,
    ProductionVectorSelectedOpeningBackend,
>;

/// Builds the canonical strict production signing backend.
pub fn strict_production_signing_backend<SP>(
    public_key: Vec<u8>,
    share_provider: SP,
) -> StrictProductionSigningBackend<SP> {
    ProductionStrictSigningBackend::new(
        ProductionVectorResponsePreparationBackend::new(public_key, share_provider),
        ProductionVectorResponseBoundCheckBackend,
        ProductionVectorHintCheckBackend,
        ProductionVectorPrivateSelectionBackend::new(),
        ProductionVectorSelectedOpeningBackend::new(),
    )
}

fn strict_response_polyvec<P: MlDsaParams>(
    ctilde: &[u8],
    y: &PolyVec,
    s1: &PolyVec,
) -> Result<PolyVec, OnlineError> {
    if ctilde.len() != P::CTILDE_LEN {
        return Err(OnlineError::Polynomial(PolyError::ChallengeLength {
            expected: P::CTILDE_LEN,
            got: ctilde.len(),
        }));
    }
    if y.len() != P::L {
        return Err(OnlineError::Polynomial(PolyError::PolyVecLength {
            expected: P::L,
            got: y.len(),
        }));
    }
    if s1.len() != P::L {
        return Err(OnlineError::Polynomial(PolyError::PolyVecLength {
            expected: P::L,
            got: s1.len(),
        }));
    }
    let challenge = sample_in_ball::<P>(ctilde);
    Ok(y.add_mod_q::<P>(&mul_challenge_polyvec::<P>(&challenge, s1)))
}

fn strict_aggregate_response_lagrange<P: MlDsaParams>(
    points: &[u32],
    responses: &[PolyVec],
) -> Result<PolyVec, OnlineError> {
    if points.len() != responses.len() {
        return Err(OnlineError::Polynomial(
            PolyError::InterpolationPointCountMismatch {
                points: points.len(),
                shares: responses.len(),
            },
        ));
    }
    if responses.is_empty() {
        return Err(OnlineError::Polynomial(PolyError::EmptyPartialSet));
    }
    for response in responses {
        if response.len() != P::L {
            return Err(OnlineError::Polynomial(PolyError::PolyVecLength {
                expected: P::L,
                got: response.len(),
            }));
        }
    }

    let coefficients = lagrange_coefficients_at_zero::<P>(points)?;
    let mut aggregate = PolyVec::zero(P::L);
    for (coefficient, response) in coefficients.iter().zip(responses) {
        aggregate = aggregate.add_mod_q::<P>(&response.mul_scalar_mod_q::<P>(*coefficient));
    }
    Ok(aggregate)
}

/// Production boundary for private response-bound checks.
///
/// Implementations evaluate the ML-DSA response bound for every candidate
/// response vector while keeping per-candidate predicate bits private. The
/// returned evidence is public shape evidence only.
pub trait StrictResponseBoundCheckBackend<P: MlDsaParams> {
    /// Backend-specific secret-shared or locally simulated response vector.
    type ResponseVector;

    /// Evaluates private response-bound predicates for every candidate.
    fn check_response_bounds(
        &mut self,
        metadata: &[StrictCandidateMetadata],
        responses: Vec<Self::ResponseVector>,
        driver: &mut StrictResponseCheckPhaseDriver,
    ) -> Result<(Vec<Self::ResponseVector>, StrictResponseBoundEvidence), OnlineError>;
}

/// Production boundary for private hint/highbits checks.
///
/// Implementations evaluate the selected TALUS hint predicate and hint-weight
/// limit for every candidate while keeping per-candidate predicate bits
/// private. The returned evidence is public shape evidence only.
pub trait StrictHintCheckBackend<P: MlDsaParams> {
    /// Backend-specific secret-shared or locally simulated response vector.
    type ResponseVector;

    /// Evaluates private hint/highbits predicates for every candidate.
    fn check_hints(
        &mut self,
        metadata: &[StrictCandidateMetadata],
        responses: Vec<Self::ResponseVector>,
        public_key: &[u8],
        w1_vectors: &[&[u32]],
        driver: &mut StrictResponseCheckPhaseDriver,
    ) -> Result<(Vec<Self::ResponseVector>, StrictHintCheckEvidence), OnlineError>;
}

/// Production boundary for private pass-bit combination and priority selection.
///
/// Implementations combine private predicate bits and select the valid
/// candidate with the lowest public priority. The selected priority is public,
/// but unselected pass bits and failure reasons remain private.
pub trait StrictPrivateSelectionBackend {
    /// Backend-specific candidate handle.
    type Candidate;

    /// Selects one valid candidate by public priority.
    fn select_candidate(
        &mut self,
        metadata: &[StrictCandidateMetadata],
        candidates: Vec<Self::Candidate>,
        driver: &mut StrictResponseCheckPhaseDriver,
    ) -> Result<(Self::Candidate, StrictPrivateSelectionEvidence), OnlineError>;
}

/// Production boundary for opening only the privately selected candidate.
///
/// Implementations must receive exactly one candidate handle: the output of
/// [`StrictPrivateSelectionBackend`]. They must not accept or inspect the full
/// candidate batch at this phase.
pub trait StrictSelectedOpeningBackend {
    /// Backend-specific selected candidate handle.
    type Candidate;

    /// Opens only the selected candidate.
    fn open_selected(
        &mut self,
        selection: &StrictPrivateSelectionEvidence,
        selected: Self::Candidate,
        driver: &mut StrictResponseCheckPhaseDriver,
    ) -> Result<(FinalSignature, StrictSelectedOpeningEvidence), OnlineError>;
}

/// Independent `fips204` final verifier adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FipsFinalVerifier<P: MlDsaParams> {
    verifier: Fips204Verifier<P>,
    _params: PhantomData<P>,
}

impl<P: MlDsaParams> FipsFinalVerifier<P> {
    /// Creates a verifier from serialized public key bytes.
    pub fn new(public_key: Vec<u8>) -> Result<Self, VerifyError> {
        Ok(Self {
            verifier: Fips204Verifier::<P>::new(public_key)?,
            _params: PhantomData,
        })
    }
}

impl<P: MlDsaParams> FinalVerifier for FipsFinalVerifier<P> {
    fn verify_final(&self, request: &SignRequest, signature: &FinalSignature) -> bool {
        if request.external_mu.is_some() {
            return false;
        }
        self.verifier
            .verify(&request.message, &signature.bytes, &request.context)
    }
}

/// Trait used to verify the final assembled FIPS signature before returning it.
pub trait FinalVerifier {
    /// Returns whether `signature` verifies for this request.
    fn verify_final(&self, request: &SignRequest, signature: &FinalSignature) -> bool;
}

/// Decodes a canonical DKG bounded-vector `s1` share into the polynomial-vector
/// shape used by online ML-DSA signing.
pub fn polyvec_from_bounded_secret_vector_share<P: MlDsaParams>(
    share: &BoundedSecretVectorShare,
) -> Result<PolyVec, OnlineError> {
    let expected = P::L * P::N;
    if share.coeffs.len() != expected {
        return Err(OnlineError::Dkg(
            DkgError::InvalidBoundedSecretVectorLength {
                expected,
                got: share.coeffs.len(),
            },
        ));
    }

    let mut polys = Vec::with_capacity(P::L);
    for row in 0..P::L {
        let coeffs = core::array::from_fn(|index| share.coeffs[row * P::N + index]);
        polys.push(Poly::from_coeffs(coeffs));
    }

    Ok(PolyVec::new(polys))
}

/// Decodes a `DkgSecretShare.s1_share` package into the typed online `s1_i`
/// polynomial vector for the selected ML-DSA suite.
pub fn polyvec_from_dkg_s1_share<P: MlDsaParams>(
    config: &DkgConfig,
    secret: &DkgSecretShare,
) -> Result<PolyVec, OnlineError> {
    let decoded = BoundedSecretVectorShare::decode::<P>(config, &secret.s1_share)?;
    if decoded.party != secret.party {
        return Err(OnlineError::Dkg(DkgError::PartyMismatch {
            expected: secret.party,
            got: decoded.party,
        }));
    }

    polyvec_from_bounded_secret_vector_share::<P>(&decoded)
}

/// Consumed-token persistence surface.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConsumedTokenStore {
    consumed: Vec<SessionId>,
}

/// Durable consumed-token persistence API.
pub trait TokenConsumptionStore {
    /// Persists token consumption durably.
    fn persist_consumed(&mut self, session_id: SessionId) -> Result<(), OnlineError>;

    /// Returns whether a token has already been consumed.
    fn is_consumed(&self, session_id: SessionId) -> bool;
}

impl ConsumedTokenStore {
    /// Creates an empty consumed-token store.
    pub const fn new() -> Self {
        Self {
            consumed: Vec::new(),
        }
    }
}

impl TokenConsumptionStore for ConsumedTokenStore {
    fn persist_consumed(&mut self, session_id: SessionId) -> Result<(), OnlineError> {
        if self.consumed.contains(&session_id) {
            return Err(OnlineError::TokenAlreadyConsumed(session_id));
        }

        self.consumed.push(session_id);
        Ok(())
    }

    fn is_consumed(&self, session_id: SessionId) -> bool {
        self.consumed.contains(&session_id)
    }
}

/// File-backed consumed-token store for deterministic crash/reopen tests.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileConsumedTokenStore {
    path: std::path::PathBuf,
    inner: ConsumedTokenStore,
}

#[cfg(feature = "std")]
impl FileConsumedTokenStore {
    /// Opens or creates a consumed-token log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, OnlineError> {
        let path = path.into();
        let mut inner = ConsumedTokenStore::new();

        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let session_id = parse_session_id_hex(line).ok_or(
                        OnlineError::ConsumedTokenStoreCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    if !inner.consumed.contains(&session_id) {
                        inner.consumed.push(session_id);
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| OnlineError::ConsumedTokenStoreIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| OnlineError::ConsumedTokenStoreIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(OnlineError::ConsumedTokenStoreIo { operation: "read" });
            }
        }

        Ok(Self { path, inner })
    }
}

#[cfg(feature = "std")]
impl TokenConsumptionStore for FileConsumedTokenStore {
    fn persist_consumed(&mut self, session_id: SessionId) -> Result<(), OnlineError> {
        if self.inner.is_consumed(session_id) {
            return Err(OnlineError::TokenAlreadyConsumed(session_id));
        }

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| OnlineError::ConsumedTokenStoreIo { operation: "open" })?;
        use std::io::Write;
        writeln!(file, "{}", hex32(session_id.0))
            .map_err(|_| OnlineError::ConsumedTokenStoreIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| OnlineError::ConsumedTokenStoreIo { operation: "sync" })?;

        self.inner.persist_consumed(session_id)
    }

    fn is_consumed(&self, session_id: SessionId) -> bool {
        self.inner.is_consumed(session_id)
    }
}

/// Online signing counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SigningCounters {
    /// Attempts started.
    pub attempts: u64,
    /// Tokens consumed.
    pub tokens_consumed: u64,
    /// Attempts that returned a verified signature.
    pub signatures_returned: u64,
    /// Attempts that failed final verification after consuming a token.
    pub final_verify_failures: u64,
    /// Retry attempts exhausted without returning a signature.
    pub retry_exhausted: u64,
}

/// Online signing failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnlineError {
    /// Protocol version mismatch.
    BadProtocolVersion {
        /// Expected version.
        expected: u16,
        /// Actual version.
        got: u16,
    },
    /// Suite mismatch.
    SuiteMismatch {
        /// Expected suite.
        expected: &'static str,
        /// Actual suite.
        got: &'static str,
    },
    /// Session mismatch.
    SessionMismatch,
    /// Signing-set mismatch.
    SigningSetMismatch,
    /// Token transcript hash mismatch.
    TranscriptMismatch,
    /// Empty message without external `mu`.
    EmptyMessage,
    /// Context is too long for FIPS 204 domain separation.
    ContextTooLong(usize),
    /// Token pool failure.
    TokenPool(TokenPoolError),
    /// Token was already consumed.
    TokenAlreadyConsumed(SessionId),
    /// Consumed-token store I/O failed.
    ConsumedTokenStoreIo {
        /// Storage operation.
        operation: &'static str,
    },
    /// Consumed-token store file was malformed.
    ConsumedTokenStoreCorrupt {
        /// One-based line number.
        line: usize,
    },
    /// Strict signing cursor store I/O failed.
    StrictSigningCursorStoreIo {
        /// Storage operation.
        operation: &'static str,
    },
    /// Strict signing cursor log was malformed.
    StrictSigningCursorStoreCorrupt {
        /// One-based line number.
        line: usize,
    },
    /// Strict signing batch was empty.
    EmptyTokenBatch,
    /// Strict signing batch was smaller than policy.
    TokenBatchTooSmall {
        /// Required minimum token count.
        min: usize,
        /// Actual token count.
        got: usize,
    },
    /// Strict signing batch contains different signer sets.
    TokenBatchSignerSetMismatch,
    /// Strict signing batch contains a duplicate token session.
    DuplicateTokenInBatch(SessionId),
    /// Strict signing request did not match the consumed token batch.
    StrictRequestBatchMismatch,
    /// Strict signing session received an unexpected private message.
    UnexpectedStrictSigningPrivateMessage,
    /// Strict signing session received an unexpected broadcast message.
    UnexpectedStrictSigningBroadcast,
    /// Strict signing wire message was malformed or not bound to this session.
    StrictSigningWireMessageRejected,
    /// Strict signing wire message was replayed.
    StrictSigningWireReplay,
    /// Strict signing distributed runtime completed slots out of order.
    StrictSigningRuntimeSlotOutOfOrder,
    /// Strict signing distributed runtime tried to complete an incomplete slot.
    StrictSigningRuntimeSlotIncomplete,
    /// Strict signing distributed runtime received a duplicate sender for a slot.
    StrictSigningRuntimeDuplicateSender,
    /// Strict signing distributed runtime received a wrong phase for a slot.
    StrictSigningRuntimeSlotPhaseMismatch,
    /// Strict signing session has already finished or failed.
    StrictSigningSessionAlreadyFinished,
    /// Strict private signing backend reported no selected valid candidate.
    GenericBatchFailure,
    /// Strict signing phases were driven out of order.
    StrictSigningPhaseOutOfOrder,
    /// Strict private response-check evidence had the wrong coarse shape.
    StrictResponseCheckShapeMismatch,
    /// Strict private response-check phases were driven out of order.
    StrictResponseCheckPhaseOutOfOrder,
    /// Partial signer failed.
    #[cfg(any(test, feature = "paper-fast-dev"))]
    PartialSignerFailed(PartyId),
    /// Partial response count mismatch.
    #[cfg(any(test, feature = "paper-fast-dev"))]
    PartialCountMismatch {
        /// Expected number of partials.
        expected: usize,
        /// Actual number of partials.
        got: usize,
    },
    /// Partial response was not bound to the request.
    #[cfg(any(test, feature = "paper-fast-dev"))]
    PartialMismatch(PartyId),
    /// A party is blamed for an invalid partial response.
    #[cfg(any(test, feature = "paper-fast-dev"))]
    Blame(PartyId),
    /// Public partial-verification commitment was missing.
    #[cfg(any(test, feature = "paper-fast-dev"))]
    PublicCommitmentMissing(PartyId),
    /// Public partial-verification commitment had the wrong vector length.
    #[cfg(any(test, feature = "paper-fast-dev"))]
    PublicCommitmentLength {
        /// Party identifier.
        party: PartyId,
        /// Expected polynomial count.
        expected: usize,
        /// Actual polynomial count.
        got: usize,
    },
    /// Polynomial adapter failure.
    Polynomial(PolyError),
    /// DKG key-share package failure.
    Dkg(DkgError),
    /// Public hint computation failure.
    Hint(HintError),
    /// Signature encoding failure.
    SignatureEncoding(SignatureEncodingError),
    /// Public key decoding failure.
    PublicKeyDecode(PublicKeyDecodeError),
    /// NTT/ExpandA adapter failure.
    Ntt(NttError),
    /// Aggregated `z` exceeds the strict ML-DSA signing bound.
    ZNormExceeded {
        /// Observed infinity norm.
        norm: i32,
        /// Required strict upper bound.
        bound: i32,
    },
    /// Final signature failed independent verification.
    FinalVerifyFailed,
    /// Retry policy exhausted all supplied attempts.
    #[cfg(any(test, feature = "paper-fast-dev"))]
    RetryExhausted,
}

impl fmt::Display for OnlineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadProtocolVersion { expected, got } => {
                write!(f, "bad protocol version: expected {expected}, got {got}")
            }
            Self::SuiteMismatch { expected, got } => {
                write!(f, "suite mismatch: expected {expected}, got {got}")
            }
            Self::SessionMismatch => write!(f, "sign request session does not match token"),
            Self::SigningSetMismatch => write!(f, "sign request signing set does not match token"),
            Self::TranscriptMismatch => {
                write!(f, "sign request transcript hash does not match token")
            }
            Self::EmptyMessage => write!(f, "sign request has empty message and no external mu"),
            Self::ContextTooLong(len) => write!(f, "FIPS context too long: {len} bytes"),
            Self::TokenPool(err) => write!(f, "token pool error: {err:?}"),
            Self::TokenAlreadyConsumed(session_id) => {
                write!(f, "token already consumed: {}", hex32(session_id.0))
            }
            Self::ConsumedTokenStoreIo { operation } => {
                write!(f, "consumed-token store I/O failed during {operation}")
            }
            Self::ConsumedTokenStoreCorrupt { line } => {
                write!(f, "consumed-token store corrupt at line {line}")
            }
            Self::StrictSigningCursorStoreIo { operation } => {
                write!(
                    f,
                    "strict signing cursor store I/O failed during {operation}"
                )
            }
            Self::StrictSigningCursorStoreCorrupt { line } => {
                write!(f, "strict signing cursor store corrupt at line {line}")
            }
            Self::EmptyTokenBatch => write!(f, "strict signing token batch is empty"),
            Self::TokenBatchTooSmall { min, got } => {
                write!(
                    f,
                    "strict signing token batch too small: need {min}, got {got}"
                )
            }
            Self::TokenBatchSignerSetMismatch => {
                write!(f, "strict signing token batch signer-set mismatch")
            }
            Self::DuplicateTokenInBatch(session_id) => {
                write!(
                    f,
                    "duplicate token in strict batch: {}",
                    hex32(session_id.0)
                )
            }
            Self::StrictRequestBatchMismatch => {
                write!(f, "strict signing request does not match token batch")
            }
            Self::UnexpectedStrictSigningPrivateMessage => {
                write!(f, "unexpected strict signing private message")
            }
            Self::UnexpectedStrictSigningBroadcast => {
                write!(f, "unexpected strict signing broadcast message")
            }
            Self::StrictSigningWireMessageRejected => {
                write!(f, "strict signing wire message rejected")
            }
            Self::StrictSigningWireReplay => {
                write!(f, "strict signing wire message replay")
            }
            Self::StrictSigningRuntimeSlotOutOfOrder => {
                write!(f, "strict signing runtime slot completed out of order")
            }
            Self::StrictSigningRuntimeSlotIncomplete => {
                write!(f, "strict signing runtime slot is incomplete")
            }
            Self::StrictSigningRuntimeDuplicateSender => {
                write!(f, "strict signing runtime duplicate sender")
            }
            Self::StrictSigningRuntimeSlotPhaseMismatch => {
                write!(f, "strict signing runtime slot phase mismatch")
            }
            Self::StrictSigningSessionAlreadyFinished => {
                write!(f, "strict signing session already finished or failed")
            }
            Self::GenericBatchFailure => write!(f, "strict signing batch produced no output"),
            Self::StrictSigningPhaseOutOfOrder => {
                write!(f, "strict signing phases were driven out of order")
            }
            Self::StrictResponseCheckShapeMismatch => {
                write!(f, "strict private response-check shape mismatch")
            }
            Self::StrictResponseCheckPhaseOutOfOrder => {
                write!(
                    f,
                    "strict private response-check phases were driven out of order"
                )
            }
            #[cfg(any(test, feature = "paper-fast-dev"))]
            Self::PartialSignerFailed(party) => {
                write!(f, "partial signer failed for party {}", party.0)
            }
            #[cfg(any(test, feature = "paper-fast-dev"))]
            Self::PartialCountMismatch { expected, got } => {
                write!(f, "partial count mismatch: expected {expected}, got {got}")
            }
            #[cfg(any(test, feature = "paper-fast-dev"))]
            Self::PartialMismatch(party) => {
                write!(f, "partial response mismatch for party {}", party.0)
            }
            #[cfg(any(test, feature = "paper-fast-dev"))]
            Self::Blame(party) => write!(f, "blame party {}", party.0),
            #[cfg(any(test, feature = "paper-fast-dev"))]
            Self::PublicCommitmentMissing(party) => {
                write!(f, "missing public commitment for party {}", party.0)
            }
            #[cfg(any(test, feature = "paper-fast-dev"))]
            Self::PublicCommitmentLength {
                party,
                expected,
                got,
            } => {
                write!(
                    f,
                    "bad public commitment length for party {}: expected {expected}, got {got}",
                    party.0
                )
            }
            Self::Polynomial(err) => write!(f, "polynomial adapter error: {err}"),
            Self::Dkg(err) => write!(f, "DKG key-share error: {err:?}"),
            Self::Hint(err) => write!(f, "hint computation error: {err:?}"),
            Self::SignatureEncoding(err) => write!(f, "signature encoding error: {err:?}"),
            Self::PublicKeyDecode(err) => write!(f, "public key decode error: {err:?}"),
            Self::Ntt(err) => write!(f, "NTT adapter error: {err}"),
            Self::ZNormExceeded { norm, bound } => {
                write!(f, "z norm exceeded: norm {norm}, bound {bound}")
            }
            Self::FinalVerifyFailed => write!(f, "final signature failed independent verification"),
            #[cfg(any(test, feature = "paper-fast-dev"))]
            Self::RetryExhausted => write!(f, "retry policy exhausted"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OnlineError {}

impl From<TokenPoolError> for OnlineError {
    fn from(value: TokenPoolError) -> Self {
        Self::TokenPool(value)
    }
}

impl From<PolyError> for OnlineError {
    fn from(value: PolyError) -> Self {
        Self::Polynomial(value)
    }
}

impl From<DkgError> for OnlineError {
    fn from(value: DkgError) -> Self {
        Self::Dkg(value)
    }
}

impl From<HintError> for OnlineError {
    fn from(value: HintError) -> Self {
        Self::Hint(value)
    }
}

impl From<SignatureEncodingError> for OnlineError {
    fn from(value: SignatureEncodingError) -> Self {
        Self::SignatureEncoding(value)
    }
}

impl From<PublicKeyDecodeError> for OnlineError {
    fn from(value: PublicKeyDecodeError) -> Self {
        Self::PublicKeyDecode(value)
    }
}

impl From<NttError> for OnlineError {
    fn from(value: NttError) -> Self {
        Self::Ntt(value)
    }
}

/// Validates one sign request against a certified token.
pub fn validate_sign_request<P: MlDsaParams>(
    request: &SignRequest,
    token: &CertifiedToken,
) -> Result<(), OnlineError> {
    if request.protocol_version != ONLINE_PROTOCOL_VERSION {
        return Err(OnlineError::BadProtocolVersion {
            expected: ONLINE_PROTOCOL_VERSION,
            got: request.protocol_version,
        });
    }
    if request.suite != P::NAME {
        return Err(OnlineError::SuiteMismatch {
            expected: P::NAME,
            got: request.suite,
        });
    }
    if request.session_id != token.session_id {
        return Err(OnlineError::SessionMismatch);
    }
    if request.signing_set != token.signer_set {
        return Err(OnlineError::SigningSetMismatch);
    }
    if request.token_transcript_hash != token.transcript_hash {
        return Err(OnlineError::TranscriptMismatch);
    }
    if request.external_mu.is_none() && request.message.is_empty() {
        return Err(OnlineError::EmptyMessage);
    }
    if request.context.len() > u8::MAX as usize {
        return Err(OnlineError::ContextTooLong(request.context.len()));
    }

    Ok(())
}

/// Validates one strict signing request against a certified token batch.
pub fn validate_strict_sign_request<P: MlDsaParams>(
    request: &StrictSignRequest,
    batch: &BccCertifiedTokenBatch,
) -> Result<(), OnlineError> {
    if request.protocol_version != ONLINE_PROTOCOL_VERSION {
        return Err(OnlineError::BadProtocolVersion {
            expected: ONLINE_PROTOCOL_VERSION,
            got: request.protocol_version,
        });
    }
    if request.suite != P::NAME {
        return Err(OnlineError::SuiteMismatch {
            expected: P::NAME,
            got: request.suite,
        });
    }
    if request.signing_set != batch.signer_set {
        return Err(OnlineError::StrictRequestBatchMismatch);
    }
    if request.external_mu.is_none() && request.message.is_empty() {
        return Err(OnlineError::EmptyMessage);
    }
    if request.context.len() > u8::MAX as usize {
        return Err(OnlineError::ContextTooLong(request.context.len()));
    }
    Ok(())
}

/// Derives a public random-priority value for a strict signing candidate.
///
/// This value is public metadata only. It must not include private validity
/// bits or candidate response material. Backends use it after private validity
/// checks to choose one valid candidate without leaking first-valid order.
pub fn strict_candidate_priority(
    request: &StrictSignRequest,
    token: &CertifiedToken,
) -> StrictCandidatePriority {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-MPC-v1/strict-candidate-priority");
    hash_u16(&mut hasher, request.protocol_version);
    hash_bytes(&mut hasher, request.suite.as_bytes());
    hash_party_set(&mut hasher, &request.signing_set);
    hash_bytes(&mut hasher, &request.message);
    match request.external_mu {
        Some(mu) => {
            hasher.update([1u8]);
            hasher.update(mu);
        }
        None => hasher.update([0u8]),
    }
    hash_bytes(&mut hasher, &request.context);
    hasher.update(token.session_id.0);
    hasher.update(token.transcript_hash.0);
    hash_party_set(&mut hasher, &token.signer_set);
    hash_usize(&mut hasher, token.w1.len());
    for coeff in &token.w1 {
        hasher.update(coeff.to_le_bytes());
    }
    StrictCandidatePriority(hasher.finalize().into())
}

/// Derives public strict-signing candidate metadata for a consumed token.
pub fn strict_candidate_metadata<P: MlDsaParams>(
    request: &StrictSignRequest,
    token: &CertifiedToken,
    tr: &[u8; 64],
) -> StrictCandidateMetadata {
    let sign_request = SignRequest {
        protocol_version: request.protocol_version,
        suite: request.suite,
        session_id: token.session_id,
        signing_set: request.signing_set.clone(),
        message: request.message.clone(),
        external_mu: request.external_mu,
        context: request.context.clone(),
        token_transcript_hash: token.transcript_hash,
    };
    let challenge = compute_challenge_material::<P>(&sign_request, token, tr);
    StrictCandidateMetadata {
        session_id: token.session_id,
        token_transcript_hash: token.transcript_hash,
        priority: strict_candidate_priority(request, token),
        mu: challenge.mu,
        ctilde: challenge.ctilde,
        encoded_w1_hash: hash_public_bytes(&challenge.encoded_w1),
    }
}

/// Derives public candidate metadata for every token in a consumed batch.
pub fn strict_candidate_metadata_batch<P: MlDsaParams>(
    request: &StrictSignRequest,
    batch: &ConsumedBccCertifiedTokenBatch,
    tr: &[u8; 64],
) -> Vec<StrictCandidateMetadata> {
    batch
        .tokens()
        .iter()
        .map(|token| strict_candidate_metadata::<P>(request, token, tr))
        .collect()
}

/// Strict production signing entry point.
///
/// This function persists consumption for every token in `batch` before the
/// private backend receives any nonce material. It does not expose clear
/// partial responses, rejected candidate values, validity bits, or failure
/// reasons.
pub fn sign_strict_no_rejected_z<P, B, S, V>(
    request: &StrictSignRequest,
    tr: &[u8; 64],
    batch: BccCertifiedTokenBatch,
    consumed: &mut S,
    counters: &mut SigningCounters,
    backend: &mut B,
    verifier: &V,
) -> Result<FinalSignature, OnlineError>
where
    P: MlDsaParams,
    B: StrictPrivateSigningBackend<P>,
    S: TokenConsumptionStore,
    V: FinalVerifier,
{
    validate_strict_sign_request::<P>(request, &batch)?;
    #[cfg(feature = "production-release-checks")]
    {
        for token in &batch.tokens {
            ensure_certified_token_release_valid(token).map_err(|_| {
                OnlineError::TokenPool(TokenPoolError::NotCertified(token.session_id))
            })?;
        }
    }
    counters.attempts = counters.attempts.saturating_add(1);

    for session_id in batch.session_ids() {
        consumed.persist_consumed(session_id)?;
        counters.tokens_consumed = counters.tokens_consumed.saturating_add(1);
    }

    let strict_token_count = batch.len();
    let consumed_batch = ConsumedBccCertifiedTokenBatch {
        signer_set: batch.signer_set,
        tokens: batch.tokens,
    };
    let selected = backend.sign_consumed_batch(request, tr, consumed_batch)?;
    if selected.evidence.token_count != strict_token_count {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    selected
        .evidence
        .response_check_counters
        .validate_for_batch(strict_token_count)?;
    #[cfg(feature = "production-release-checks")]
    {
        if !selected
            .vector_runtime_certificate
            .as_ref()
            .is_some_and(|certificate| certificate.is_selected_opening_artifact_bound())
        {
            return Err(OnlineError::StrictSigningRuntimeSlotIncomplete);
        }
    }
    let verify_request = SignRequest {
        protocol_version: request.protocol_version,
        suite: request.suite,
        session_id: SessionId([0u8; 32]),
        signing_set: request.signing_set.clone(),
        message: request.message.clone(),
        external_mu: request.external_mu,
        context: request.context.clone(),
        token_transcript_hash: TranscriptHash([0u8; 32]),
    };
    if !verifier.verify_final(&verify_request, &selected.signature) {
        counters.final_verify_failures = counters.final_verify_failures.saturating_add(1);
        return Err(OnlineError::FinalVerifyFailed);
    }

    counters.signatures_returned = counters.signatures_returned.saturating_add(1);
    Ok(selected.signature)
}

/// Hashes a selected final signature for public strict-signing evidence.
pub fn strict_signature_hash(signature: &FinalSignature) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-MPC-v1/strict-selected-signature");
    hash_bytes(&mut hasher, &signature.bytes);
    hasher.finalize().into()
}

fn strict_backend_transcript_hash(
    request: &StrictSignRequest,
    token_count: usize,
    selected_priority: StrictCandidatePriority,
    signature_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-MPC-v1/strict-production-backend");
    hash_u16(&mut hasher, request.protocol_version);
    hash_bytes(&mut hasher, request.suite.as_bytes());
    hash_usize(&mut hasher, request.signing_set.len());
    for party in &request.signing_set {
        hasher.update(party.0.to_le_bytes());
    }
    hash_usize(&mut hasher, token_count);
    hasher.update(selected_priority.0);
    hasher.update(signature_hash);
    hasher.finalize().into()
}

/// Derives the deterministic public id for one strict signing session.
pub fn strict_signing_session_id(
    request: &StrictSignRequest,
    token_session_ids: &[SessionId],
) -> StrictSigningSessionId {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-MPC-v1/strict-signing-session-id");
    hasher.update(strict_signing_request_hash(request));
    hash_usize(&mut hasher, token_session_ids.len());
    for session_id in token_session_ids {
        hasher.update(session_id.0);
    }
    StrictSigningSessionId(hasher.finalize().into())
}

/// Hashes the public strict signing request for durable cursor binding.
pub fn strict_signing_request_hash(request: &StrictSignRequest) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-MPC-v1/strict-signing-request");
    hash_u16(&mut hasher, request.protocol_version);
    hash_bytes(&mut hasher, request.suite.as_bytes());
    hash_party_set(&mut hasher, &request.signing_set);
    hash_bytes(&mut hasher, &request.message);
    match request.external_mu {
        Some(mu) => {
            hasher.update([1u8]);
            hasher.update(mu);
        }
        None => hasher.update([0u8]),
    }
    hash_bytes(&mut hasher, &request.context);
    hasher.finalize().into()
}

fn strict_wire_suite<P: MlDsaParams>() -> Result<WireSuiteId, OnlineError> {
    match P::NAME {
        "ML-DSA-44" => Ok(WireSuiteId::MlDsa44),
        "ML-DSA-65" => Ok(WireSuiteId::MlDsa65),
        "ML-DSA-87" => Ok(WireSuiteId::MlDsa87),
        got => Err(OnlineError::SuiteMismatch {
            expected: "ML-DSA-44/65/87",
            got,
        }),
    }
}

fn strict_wire_signing_set_hash(request: &StrictSignRequest) -> [u8; 32] {
    let parties = request
        .signing_set
        .iter()
        .map(|party| party.0)
        .collect::<Vec<_>>();
    signing_set_hash(&parties)
}

fn strict_signing_wire_message_hash(message: &WireMessage) -> Result<[u8; 32], OnlineError> {
    let encoded =
        encode_message(message).map_err(|_| OnlineError::StrictSigningWireMessageRejected)?;
    Ok(hash_public_bytes(&encoded))
}

fn strict_signing_wire_transcript_hash(previous: [u8; 32], message_hash: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-MPC-v1/strict-signing-wire-transcript");
    hasher.update(previous);
    hasher.update(message_hash);
    hasher.finalize().into()
}

fn strict_wire_record_placeholder(hash: [u8; 32]) -> StrictSigningWireRecord {
    StrictSigningWireRecord {
        hash,
        slot: StrictSigningRuntimeSlot::ResponsePreparation,
        phase: 0,
        sender: PartyId(0),
        receiver: None,
        payload: StrictSignMpcPayload {
            slot: StrictSignMpcSlot::PrepareCandidateShares,
            phase: 0,
            receiver_party_id: 0,
            label_hash: [0u8; 32],
            transcript_hash: [0u8; 32],
            opaque_payload: Vec::new(),
        },
    }
}

#[cfg(feature = "std")]
fn format_strict_signing_cursor_line(cursor: &StrictSigningSessionCursor) -> String {
    let tokens = cursor
        .token_session_ids
        .iter()
        .map(|session_id| format!("{}", hex32(session_id.0)))
        .collect::<Vec<_>>()
        .join(",");
    let final_hash = cursor
        .final_signature_hash
        .map(|hash| format!("{}", hex32(hash)))
        .unwrap_or_else(|| "-".to_string());
    let accepted = format_hex32_list(&cursor.accepted_wire_message_hashes);
    let outbound = format_hex32_list(&cursor.outbound_wire_message_hashes);
    let completed = format_runtime_slot_list(&cursor.completed_runtime_slots);
    let progress = format_runtime_slot_progress_list(&cursor.runtime_slot_progress);
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        hex32(cursor.session_id.0),
        strict_cursor_phase_code(cursor.phase),
        cursor
            .runtime_slot
            .map(strict_runtime_slot_code)
            .unwrap_or(0),
        hex32(cursor.request_hash),
        tokens,
        accepted,
        outbound,
        hex32(cursor.wire_transcript_hash),
        completed,
        progress,
        final_hash
    )
}

#[cfg(feature = "std")]
fn parse_strict_signing_cursor_line(value: &str) -> Option<StrictSigningSessionCursor> {
    let mut parts = value.split('|');
    let session_id = StrictSigningSessionId(parse_hex32(parts.next()?)?);
    let phase = strict_cursor_phase_from_code(parts.next()?.parse().ok()?)?;
    let slot_code: u8 = parts.next()?.parse().ok()?;
    let runtime_slot = if slot_code == 0 {
        None
    } else {
        Some(strict_runtime_slot_from_code(slot_code)?)
    };
    let request_hash = parse_hex32(parts.next()?)?;
    let token_part = parts.next()?;
    let token_session_ids = if token_part.is_empty() {
        Vec::new()
    } else {
        token_part
            .split(',')
            .map(parse_session_id_hex)
            .collect::<Option<Vec<_>>>()?
    };
    let remaining = parts.collect::<Vec<_>>();
    let (
        accepted_wire_message_hashes,
        outbound_wire_message_hashes,
        wire_transcript_hash,
        completed_runtime_slots,
        runtime_slot_progress,
        final_part,
    ) = match remaining.as_slice() {
        [final_part] => (
            Vec::new(),
            Vec::new(),
            [0u8; 32],
            Vec::new(),
            Vec::new(),
            *final_part,
        ),
        [accepted, outbound, transcript, final_part] => (
            parse_hex32_list(accepted)?,
            parse_hex32_list(outbound)?,
            parse_hex32(transcript)?,
            Vec::new(),
            Vec::new(),
            *final_part,
        ),
        [accepted, outbound, transcript, completed, final_part] => (
            parse_hex32_list(accepted)?,
            parse_hex32_list(outbound)?,
            parse_hex32(transcript)?,
            parse_runtime_slot_list(completed)?,
            Vec::new(),
            *final_part,
        ),
        [accepted, outbound, transcript, completed, progress, final_part] => (
            parse_hex32_list(accepted)?,
            parse_hex32_list(outbound)?,
            parse_hex32(transcript)?,
            parse_runtime_slot_list(completed)?,
            parse_runtime_slot_progress_list(progress)?,
            *final_part,
        ),
        _ => return None,
    };
    let final_signature_hash = if final_part == "-" {
        None
    } else {
        Some(parse_hex32(final_part)?)
    };
    Some(StrictSigningSessionCursor {
        session_id,
        phase,
        runtime_slot,
        request_hash,
        token_session_ids,
        final_signature_hash,
        accepted_wire_message_hashes,
        outbound_wire_message_hashes,
        wire_transcript_hash,
        completed_runtime_slots,
        runtime_slot_progress,
    })
}

#[cfg(feature = "std")]
fn format_hex32_list(values: &[[u8; 32]]) -> String {
    values
        .iter()
        .map(|value| format!("{}", hex32(*value)))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(feature = "std")]
fn parse_hex32_list(value: &str) -> Option<Vec<[u8; 32]>> {
    if value.is_empty() {
        Some(Vec::new())
    } else {
        value.split(',').map(parse_hex32).collect()
    }
}

#[cfg(feature = "std")]
fn format_runtime_slot_list(values: &[StrictSigningRuntimeSlot]) -> String {
    values
        .iter()
        .copied()
        .map(strict_runtime_slot_code)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(feature = "std")]
fn parse_runtime_slot_list(value: &str) -> Option<Vec<StrictSigningRuntimeSlot>> {
    if value.is_empty() {
        Some(Vec::new())
    } else {
        value
            .split(',')
            .map(|part| strict_runtime_slot_from_code(part.parse().ok()?))
            .collect()
    }
}

#[cfg(feature = "std")]
fn format_runtime_slot_progress_list(values: &[StrictSigningRuntimeSlotProgress]) -> String {
    values
        .iter()
        .map(|progress| {
            let senders = progress
                .accepted_senders
                .iter()
                .map(|party| party.0.to_string())
                .collect::<Vec<_>>()
                .join(".");
            format!(
                "{}:{}:{}:{}:{}:{}",
                strict_runtime_slot_code(progress.slot),
                progress.phase,
                senders,
                progress.outbound_messages,
                hex32(progress.transcript_hash),
                if progress.completed { 1 } else { 0 }
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

#[cfg(feature = "std")]
fn parse_runtime_slot_progress_list(value: &str) -> Option<Vec<StrictSigningRuntimeSlotProgress>> {
    if value.is_empty() {
        return Some(Vec::new());
    }
    value
        .split(';')
        .map(|item| {
            let mut parts = item.split(':');
            let slot = strict_runtime_slot_from_code(parts.next()?.parse().ok()?)?;
            let phase = parts.next()?.parse().ok()?;
            let accepted_senders = parse_party_dot_list(parts.next()?)?;
            let outbound_messages = parts.next()?.parse().ok()?;
            let transcript_hash = parse_hex32(parts.next()?)?;
            let completed = match parts.next()? {
                "0" => false,
                "1" => true,
                _ => return None,
            };
            if parts.next().is_some() {
                return None;
            }
            Some(StrictSigningRuntimeSlotProgress {
                slot,
                phase,
                accepted_senders,
                outbound_messages,
                transcript_hash,
                completed,
            })
        })
        .collect()
}

#[cfg(feature = "std")]
fn parse_party_dot_list(value: &str) -> Option<Vec<PartyId>> {
    if value.is_empty() {
        Some(Vec::new())
    } else {
        value
            .split('.')
            .map(|part| Some(PartyId(part.parse().ok()?)))
            .collect()
    }
}

fn strict_cursor_phase_code(phase: StrictSigningCursorPhase) -> u8 {
    match phase {
        StrictSigningCursorPhase::Started => 1,
        StrictSigningCursorPhase::TokensConsumed => 2,
        StrictSigningCursorPhase::Finished => 3,
        StrictSigningCursorPhase::Failed => 4,
    }
}

fn strict_cursor_phase_from_code(code: u8) -> Option<StrictSigningCursorPhase> {
    match code {
        1 => Some(StrictSigningCursorPhase::Started),
        2 => Some(StrictSigningCursorPhase::TokensConsumed),
        3 => Some(StrictSigningCursorPhase::Finished),
        4 => Some(StrictSigningCursorPhase::Failed),
        _ => None,
    }
}

fn strict_runtime_slot_code(slot: StrictSigningRuntimeSlot) -> u8 {
    match slot {
        StrictSigningRuntimeSlot::ResponsePreparation => 1,
        StrictSigningRuntimeSlot::ResponseBoundChecks => 2,
        StrictSigningRuntimeSlot::HintChecks => 3,
        StrictSigningRuntimeSlot::PrivateSelection => 4,
        StrictSigningRuntimeSlot::SelectedOpening => 5,
    }
}

fn strict_runtime_slot_from_code(code: u8) -> Option<StrictSigningRuntimeSlot> {
    match code {
        1 => Some(StrictSigningRuntimeSlot::ResponsePreparation),
        2 => Some(StrictSigningRuntimeSlot::ResponseBoundChecks),
        3 => Some(StrictSigningRuntimeSlot::HintChecks),
        4 => Some(StrictSigningRuntimeSlot::PrivateSelection),
        5 => Some(StrictSigningRuntimeSlot::SelectedOpening),
        _ => None,
    }
}

fn hash_public_bytes(value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-MPC-v1/public-bytes");
    hash_bytes(&mut hasher, value);
    hasher.finalize().into()
}

fn hash_u16(hasher: &mut Sha3_256, value: u16) {
    hasher.update(value.to_le_bytes());
}

fn hash_usize(hasher: &mut Sha3_256, value: usize) {
    hasher.update((value as u64).to_le_bytes());
}

fn hash_bytes(hasher: &mut Sha3_256, value: &[u8]) {
    hash_usize(hasher, value.len());
    hasher.update(value);
}

fn hash_party_set(hasher: &mut Sha3_256, parties: &[PartyId]) {
    hash_usize(hasher, parties.len());
    for party in parties {
        hasher.update(party.0.to_le_bytes());
    }
}

/// Computes `mu`, `w1Encode(w1)`, and `ctilde` for the online challenge.
pub fn compute_challenge_material<P: MlDsaParams>(
    request: &SignRequest,
    token: &CertifiedToken,
    tr: &[u8; 64],
) -> ChallengeMaterial {
    let mu = request
        .external_mu
        .unwrap_or_else(|| compute_mu(tr, &request.context, &request.message));
    let encoded_w1 = w1_encode::<P>(&token.w1);
    let ctilde = compute_ctilde::<P>(&mu, &encoded_w1);

    ChallengeMaterial {
        mu,
        encoded_w1,
        ctilde,
    }
}

fn hex32(bytes: [u8; 32]) -> Hex32 {
    Hex32(bytes)
}

#[cfg(feature = "std")]
fn parse_session_id_hex(value: &str) -> Option<SessionId> {
    Some(SessionId(parse_hex32(value)?))
}

#[cfg(feature = "std")]
fn parse_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }

    let mut bytes = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Some(bytes)
}

#[cfg(feature = "std")]
fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

struct Hex32([u8; 32]);

impl fmt::Display for Hex32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![cfg_attr(feature = "production-release-checks", allow(dead_code))]

    use super::*;
    use crate::local::{
        certify_preprocessing_token, preprocessing_runtime_transcript_aggregate_hash, Commitment,
        NonceCommitment, PartyPreprocessInput, PreprocessingCertificationRuntimeTranscripts,
        PreprocessingVectorRuntimeCertificate, SessionRegistry,
    };
    use std::cell::RefCell;
    use std::rc::Rc;
    use talus_core::{Coeff, MlDsa65};

    #[derive(Clone, Debug, Default)]
    struct TestProductionVectorEntropy {
        next: u64,
    }

    impl ProductionVectorItMpcEntropy for TestProductionVectorEntropy {
        fn fill_field_coefficients<P: MlDsaParams>(
            &mut self,
            _label: &Power2RoundTranscriptLabel,
            count: usize,
        ) -> Result<Vec<Coeff>, DkgError> {
            let mut out = Vec::with_capacity(count);
            for _ in 0..count {
                self.next = self.next.saturating_add(1);
                out.push((self.next % P::Q as u64) as Coeff);
            }
            Ok(out)
        }
    }

    fn session(byte: u8) -> SessionId {
        SessionId([byte; 32])
    }

    fn input(party: u16) -> PartyPreprocessInput {
        let coeffs = MlDsa65::K * MlDsa65::N;
        PartyPreprocessInput {
            party: PartyId(party),
            highs: vec![party as u32; coeffs],
            lows: vec![party as u32 + 2; coeffs],
            y_share: vec![party as u8; 4],
            ay_contribution: None,
            nonce_commitment: NonceCommitment([party as u8; 32]),
            randomness_commitment: Commitment([(party + 10) as u8; 32]),
        }
    }

    fn token(byte: u8, parties: &[u16]) -> CertifiedToken {
        let mut registry = SessionRegistry::new();
        certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(byte),
            parties.iter().copied().map(input).collect(),
        )
        .expect("test token certifies")
    }

    fn strict_request() -> StrictSignRequest {
        StrictSignRequest {
            protocol_version: ONLINE_PROTOCOL_VERSION,
            suite: MlDsa65::NAME,
            signing_set: vec![PartyId(1), PartyId(2)],
            message: b"message".to_vec(),
            external_mu: None,
            context: b"ctx".to_vec(),
        }
    }

    #[cfg(feature = "production-release-checks")]
    fn strict_request_one_party() -> StrictSignRequest {
        StrictSignRequest {
            protocol_version: ONLINE_PROTOCOL_VERSION,
            suite: MlDsa65::NAME,
            signing_set: vec![PartyId(1)],
            message: b"message".to_vec(),
            external_mu: None,
            context: b"ctx".to_vec(),
        }
    }

    fn release_vector_runtime_evidence() -> ProductionVectorItMpcRuntimeEvidence {
        ProductionVectorItMpcRuntimeEvidence {
            counters: talus_dkg::PrimeFieldMpcCounters {
                rounds: 9,
                private_messages: 3,
                broadcasts: 3,
                wire_bytes: 512,
                durable_log_bytes: 1024,
                vector_lanes: 10_000,
                multiplication_layers: 4,
                vector_mul_lanes: 10_000,
                vector_opening_lanes: 10_000,
                vector_assert_zero_lanes: 10_000,
                random_bits: 10_000,
                local_public_mul_lanes: 10_000,
                ..talus_dkg::PrimeFieldMpcCounters::default()
            },
            coverage: talus_dkg::ProductionVectorItMpcRuntimeCoverage {
                open_many_checked: true,
                assert_zero_vec: true,
                assert_bit_vec: true,
                random_bit_vec: true,
                mul_vec: true,
                comparison_to_public: true,
                equality_to_public: true,
                bit_sum_or_threshold_check: true,
                private_one_hot_selection: true,
                preprocessing_masked_broadcast: true,
                preprocessing_carry_compare: true,
                preprocessing_cef_bcc: true,
            },
            transcript_hash: [0x6b; 32],
        }
    }

    fn release_vector_runtime_evidence_for_token(
        token: &CertifiedToken,
    ) -> ProductionVectorItMpcRuntimeEvidence {
        let mut evidence = release_vector_runtime_evidence();
        evidence.transcript_hash = preprocessing_runtime_transcript_aggregate_hash(
            token.session_id,
            token.transcript_hash,
            PreprocessingCertificationRuntimeTranscripts {
                masked_broadcast: token
                    .certification_evidence
                    .masked_broadcast
                    .expect("masked-broadcast evidence")
                    .runtime_transcript_hash,
                carry_compare: token
                    .certification_evidence
                    .carry_compare
                    .expect("carry evidence")
                    .runtime_transcript_hash,
                bcc: token
                    .certification_evidence
                    .bcc
                    .expect("bcc evidence")
                    .runtime_transcript_hash,
            },
        )
        .expect("aggregate preprocessing runtime transcript");
        evidence
    }

    #[cfg(feature = "production-release-checks")]
    fn release_valid_token(byte: u8, parties: &[u16]) -> CertifiedToken {
        let token = token(byte, parties);
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token,
            release_vector_runtime_evidence_for_token(&token),
        )
        .expect("preprocessing runtime certificate");
        token.with_vector_runtime_certificate(certificate)
    }

    #[cfg(feature = "production-release-checks")]
    fn release_valid_zero_w1_token(byte: u8, parties: &[u16]) -> CertifiedToken {
        let mut token = token(byte, parties);
        token.w1.fill(0);
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token,
            release_vector_runtime_evidence_for_token(&token),
        )
        .expect("preprocessing runtime certificate");
        token.with_vector_runtime_certificate(certificate)
    }

    #[derive(Clone, Default)]
    struct SharedConsumedStore {
        consumed: Rc<RefCell<Vec<SessionId>>>,
    }

    impl TokenConsumptionStore for SharedConsumedStore {
        fn persist_consumed(&mut self, session_id: SessionId) -> Result<(), OnlineError> {
            let mut consumed = self.consumed.borrow_mut();
            if consumed.contains(&session_id) {
                return Err(OnlineError::TokenAlreadyConsumed(session_id));
            }
            consumed.push(session_id);
            Ok(())
        }

        fn is_consumed(&self, session_id: SessionId) -> bool {
            self.consumed.borrow().contains(&session_id)
        }
    }

    #[derive(Clone, Default)]
    struct RecordingCursorStore {
        cursors: Rc<RefCell<Vec<StrictSigningSessionCursor>>>,
    }

    impl StrictSigningSessionStore for RecordingCursorStore {
        fn persist_cursor(
            &mut self,
            cursor: &StrictSigningSessionCursor,
        ) -> Result<(), OnlineError> {
            self.cursors.borrow_mut().push(cursor.clone());
            Ok(())
        }

        fn load_cursor(
            &self,
            session_id: StrictSigningSessionId,
        ) -> Result<Option<StrictSigningSessionCursor>, OnlineError> {
            Ok(self
                .cursors
                .borrow()
                .iter()
                .rev()
                .find(|cursor| cursor.session_id == session_id)
                .cloned())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct ScriptedStrictRuntime {
        outbound: Vec<StrictSigningOutbound>,
        private_calls: usize,
        broadcast_calls: usize,
        complete_after: Option<usize>,
    }

    impl ScriptedStrictRuntime {
        fn hold() -> Self {
            Self {
                complete_after: None,
                ..Self::default()
            }
        }

        fn complete_immediately() -> Self {
            Self {
                complete_after: Some(0),
                ..Self::default()
            }
        }

        fn complete_after(count: usize) -> Self {
            Self {
                complete_after: Some(count),
                ..Self::default()
            }
        }

        fn step_for_payload(&mut self, payload: &StrictSignMpcPayload) -> StrictSigningRuntimeStep {
            let total = self.private_calls + self.broadcast_calls;
            let complete = self
                .complete_after
                .is_some_and(|target| target == 0 || total >= target);
            StrictSigningRuntimeStep {
                completed_slot: complete
                    .then_some(StrictSigningRuntimeSlot::from_wire_slot(payload.slot)),
                outbound: if complete {
                    core::mem::take(&mut self.outbound)
                } else {
                    Vec::new()
                },
            }
        }
    }

    impl StrictSigningDistributedRuntime for ScriptedStrictRuntime {
        fn handle_private_mpc(
            &mut self,
            _sender: PartyId,
            payload: &StrictSignMpcPayload,
        ) -> Result<StrictSigningRuntimeStep, OnlineError> {
            self.private_calls += 1;
            Ok(self.step_for_payload(payload))
        }

        fn handle_broadcast_mpc(
            &mut self,
            _sender: PartyId,
            payload: &StrictSignMpcPayload,
        ) -> Result<StrictSigningRuntimeStep, OnlineError> {
            self.broadcast_calls += 1;
            Ok(self.step_for_payload(payload))
        }
    }

    struct AssertConsumedBackend {
        consumed: Rc<RefCell<Vec<SessionId>>>,
        expected_sessions: Vec<SessionId>,
        calls: usize,
        signature: Vec<u8>,
        bad_shape: bool,
    }

    impl StrictPrivateSigningBackend<MlDsa65> for AssertConsumedBackend {
        fn sign_consumed_batch(
            &mut self,
            request: &StrictSignRequest,
            _tr: &[u8; 64],
            batch: ConsumedBccCertifiedTokenBatch,
        ) -> Result<StrictSelectedSignature, OnlineError> {
            self.calls += 1;
            assert_eq!(batch.session_ids_for_test(), self.expected_sessions);
            for session_id in &self.expected_sessions {
                assert!(
                    self.consumed.borrow().contains(session_id),
                    "backend must run only after token consumption is durable"
                );
            }
            let selected_token = batch.tokens().first().expect("nonempty strict batch");
            let selected_priority = strict_candidate_priority(request, selected_token);
            let signature = FinalSignature {
                bytes: self.signature.clone(),
            };
            let response_check_counters = if self.bad_shape {
                StrictResponseCheckCounters {
                    candidates: batch.len(),
                    private_response_vectors: 0,
                    z_bound_checks: batch.len(),
                    hint_weight_checks: batch.len(),
                    validity_bits: batch.len(),
                    selected_openings: 1,
                }
            } else {
                StrictResponseCheckCounters {
                    candidates: batch.len(),
                    private_response_vectors: batch.len(),
                    z_bound_checks: batch.len(),
                    hint_weight_checks: batch.len(),
                    validity_bits: batch.len(),
                    selected_openings: 1,
                }
            };
            Ok(StrictSelectedSignature {
                evidence: StrictSigningEvidence {
                    token_count: batch.len(),
                    response_check_counters,
                    selected_priority,
                    signature_hash: strict_signature_hash(&signature),
                    transcript_hash: [0xA5; 32],
                },
                signature,
                vector_runtime_certificate: None,
            })
        }
    }

    impl ConsumedBccCertifiedTokenBatch {
        fn session_ids_for_test(&self) -> Vec<SessionId> {
            self.tokens.iter().map(|token| token.session_id).collect()
        }
    }

    struct AcceptSignature;

    impl FinalVerifier for AcceptSignature {
        fn verify_final(&self, _request: &SignRequest, signature: &FinalSignature) -> bool {
            signature.bytes == vec![1, 2, 3]
        }
    }

    struct AcceptMlDsa65Length;

    impl FinalVerifier for AcceptMlDsa65Length {
        fn verify_final(&self, _request: &SignRequest, signature: &FinalSignature) -> bool {
            signature.bytes.len() == MlDsa65::SIG_LEN
        }
    }

    #[derive(Clone, Eq, PartialEq)]
    struct TestStrictShareProvider {
        shares: Vec<(SessionId, PartyId, PolyVec, PolyVec)>,
    }

    impl StrictPolynomialShareProvider for TestStrictShareProvider {
        fn signing_share(
            &self,
            session_id: SessionId,
            party: PartyId,
        ) -> Result<StrictPolynomialSigningShare, OnlineError> {
            let (_, _, y, s1) = self
                .shares
                .iter()
                .find(|(candidate_session, candidate_party, _, _)| {
                    *candidate_session == session_id && *candidate_party == party
                })
                .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?;
            Ok(StrictPolynomialSigningShare {
                party,
                y: y.clone(),
                s1: s1.clone(),
            })
        }
    }

    fn zero_strict_share_provider(tokens: &[&CertifiedToken]) -> TestStrictShareProvider {
        TestStrictShareProvider {
            shares: tokens
                .iter()
                .flat_map(|token| {
                    token.signer_set.iter().map(move |&party| {
                        (
                            token.session_id,
                            party,
                            PolyVec::zero(MlDsa65::L),
                            PolyVec::zero(MlDsa65::L),
                        )
                    })
                })
                .collect(),
        }
    }

    fn zero_w1_token(byte: u8, parties: &[u16]) -> CertifiedToken {
        let mut token = token(byte, parties);
        token.w1.fill(0);
        token
    }

    #[derive(Clone)]
    struct StackCandidate {
        priority: StrictCandidatePriority,
        signature: FinalSignature,
        accepted: bool,
    }

    struct StackPrepare {
        public_key: Vec<u8>,
        accepted_index: Option<usize>,
    }

    impl StrictResponsePreparationBackend<MlDsa65> for StackPrepare {
        type Candidate = StackCandidate;

        fn prepare_private_responses(
            &mut self,
            _request: &StrictSignRequest,
            _tr: &[u8; 64],
            batch: &ConsumedBccCertifiedTokenBatch,
            metadata: &[StrictCandidateMetadata],
        ) -> Result<StrictPreparedResponseBatch<Self::Candidate>, OnlineError> {
            let mut candidates = Vec::with_capacity(metadata.len());
            for (index, item) in metadata.iter().enumerate() {
                let accepted = self.accepted_index == Some(index);
                candidates.push(StackCandidate {
                    priority: item.priority,
                    signature: FinalSignature {
                        bytes: if accepted { vec![1, 2, 3] } else { vec![9] },
                    },
                    accepted,
                });
            }
            Ok(StrictPreparedResponseBatch {
                candidates,
                public_key: self.public_key.clone(),
                w1_vectors: batch
                    .tokens()
                    .iter()
                    .map(|token| token.w1.clone())
                    .collect(),
            })
        }
    }

    struct StackBounds;

    impl StrictResponseBoundCheckBackend<MlDsa65> for StackBounds {
        type ResponseVector = StackCandidate;

        fn check_response_bounds(
            &mut self,
            metadata: &[StrictCandidateMetadata],
            responses: Vec<Self::ResponseVector>,
            driver: &mut StrictResponseCheckPhaseDriver,
        ) -> Result<(Vec<Self::ResponseVector>, StrictResponseBoundEvidence), OnlineError> {
            assert_eq!(metadata.len(), responses.len());
            driver.accept_response_bounds(responses.len())?;
            let token_count = responses.len();
            Ok((
                responses,
                StrictResponseBoundEvidence {
                    token_count,
                    coefficients_per_candidate: MlDsa65::L * MlDsa65::N,
                },
            ))
        }
    }

    struct StackHints;

    impl StrictHintCheckBackend<MlDsa65> for StackHints {
        type ResponseVector = StackCandidate;

        fn check_hints(
            &mut self,
            metadata: &[StrictCandidateMetadata],
            responses: Vec<Self::ResponseVector>,
            public_key: &[u8],
            w1_vectors: &[&[u32]],
            driver: &mut StrictResponseCheckPhaseDriver,
        ) -> Result<(Vec<Self::ResponseVector>, StrictHintCheckEvidence), OnlineError> {
            assert_eq!(metadata.len(), responses.len());
            assert_eq!(responses.len(), w1_vectors.len());
            assert!(!public_key.is_empty());
            driver.accept_hint_checks(responses.len())?;
            let token_count = responses.len();
            Ok((
                responses,
                StrictHintCheckEvidence {
                    token_count,
                    coefficients_per_candidate: MlDsa65::K * MlDsa65::N,
                },
            ))
        }
    }

    struct StackSelect;

    impl StrictPrivateSelectionBackend for StackSelect {
        type Candidate = StackCandidate;

        fn select_candidate(
            &mut self,
            metadata: &[StrictCandidateMetadata],
            mut candidates: Vec<Self::Candidate>,
            driver: &mut StrictResponseCheckPhaseDriver,
        ) -> Result<(Self::Candidate, StrictPrivateSelectionEvidence), OnlineError> {
            assert_eq!(metadata.len(), candidates.len());
            driver.accept_private_pass_bits(candidates.len())?;
            let selected_priority = candidates
                .iter()
                .filter(|candidate| candidate.accepted)
                .map(|candidate| candidate.priority)
                .min()
                .ok_or(OnlineError::GenericBatchFailure)?;
            driver.accept_priority_selection(true)?;
            candidates.sort_by_key(|candidate| candidate.priority);
            let selected = candidates
                .into_iter()
                .find(|candidate| candidate.accepted && candidate.priority == selected_priority)
                .ok_or(OnlineError::GenericBatchFailure)?;
            Ok((
                selected,
                StrictPrivateSelectionEvidence {
                    token_count: metadata.len(),
                    selected_priority,
                },
            ))
        }
    }

    struct StackOpen;

    impl StrictSelectedOpeningBackend for StackOpen {
        type Candidate = StackCandidate;

        fn open_selected(
            &mut self,
            selection: &StrictPrivateSelectionEvidence,
            selected: Self::Candidate,
            driver: &mut StrictResponseCheckPhaseDriver,
        ) -> Result<(FinalSignature, StrictSelectedOpeningEvidence), OnlineError> {
            if selected.priority != selection.selected_priority {
                return Err(OnlineError::StrictResponseCheckShapeMismatch);
            }
            driver.accept_selected_opening()?;
            let signature = selected.signature;
            let signature_hash = strict_signature_hash(&signature);
            Ok((
                signature,
                StrictSelectedOpeningEvidence {
                    token_count: selection.token_count,
                    selected_priority: selection.selected_priority,
                    signature_hash,
                },
            ))
        }
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_batch_rejects_uncertified_shape_errors() {
        assert_eq!(
            BccCertifiedTokenBatch::new(Vec::new(), 1).map(|batch| batch.len()),
            Err(OnlineError::EmptyTokenBatch)
        );

        let one = token(1, &[1, 2]);
        assert_eq!(
            BccCertifiedTokenBatch::new(vec![one], 2).map(|batch| batch.len()),
            Err(OnlineError::TokenBatchTooSmall { min: 2, got: 1 })
        );

        let duplicate_a = token(2, &[1, 2]);
        let duplicate_b = token(2, &[1, 2]);
        assert_eq!(
            BccCertifiedTokenBatch::new(vec![duplicate_a, duplicate_b], 1).map(|batch| batch.len()),
            Err(OnlineError::DuplicateTokenInBatch(session(2)))
        );

        let left = token(3, &[1, 2]);
        let right = token(4, &[1, 3]);
        assert_eq!(
            BccCertifiedTokenBatch::new(vec![left, right], 1).map(|batch| batch.len()),
            Err(OnlineError::TokenBatchSignerSetMismatch)
        );
    }

    #[test]
    fn strict_release_batch_requires_preprocessing_runtime_certificates() {
        let left = token(5, &[1, 2]);
        let right = token(6, &[1, 2]);
        assert_eq!(
            BccCertifiedTokenBatch::new_release_validated(vec![left, right], 2)
                .map(|batch| batch.len()),
            Err(OnlineError::TokenPool(TokenPoolError::NotCertified(
                session(5)
            )))
        );

        let left = token(7, &[1, 2]);
        let left_certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &left,
            release_vector_runtime_evidence_for_token(&left),
        )
        .expect("left preprocessing runtime certificate");
        let left = left.with_vector_runtime_certificate(left_certificate);
        let right = token(8, &[1, 2]);
        let right_certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &right,
            release_vector_runtime_evidence_for_token(&right),
        )
        .expect("right preprocessing runtime certificate");
        let right = right.with_vector_runtime_certificate(right_certificate);
        assert_eq!(
            BccCertifiedTokenBatch::new_release_validated(vec![left, right], 2)
                .map(|batch| batch.len()),
            Ok(2)
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_signing_release_checks_reject_uncertified_tokens_before_consumption() {
        let new_err = BccCertifiedTokenBatch::new(vec![token(9, &[1, 2]), token(10, &[1, 2])], 2)
            .expect_err("release-mode batch constructor rejects uncertified tokens");
        assert_eq!(
            new_err,
            OnlineError::TokenPool(TokenPoolError::NotCertified(session(9)))
        );

        let first = token(9, &[1, 2]);
        let second = token(10, &[1, 2]);
        let expected_sessions = vec![first.session_id, second.session_id];
        let batch = BccCertifiedTokenBatch {
            signer_set: first.signer_set.clone(),
            tokens: vec![first, second],
        };
        let mut store = SharedConsumedStore::default();
        let consumed_ref = store.consumed.clone();
        let mut backend = AssertConsumedBackend {
            consumed: consumed_ref,
            expected_sessions,
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: false,
        };
        let mut counters = SigningCounters::default();

        let err = sign_strict_no_rejected_z::<MlDsa65, _, _, _>(
            &strict_request(),
            &[0x42; 64],
            batch,
            &mut store,
            &mut counters,
            &mut backend,
            &AcceptSignature,
        )
        .expect_err("release mode rejects non-release preprocessing token");

        assert_eq!(
            err,
            OnlineError::TokenPool(TokenPoolError::NotCertified(session(9)))
        );
        assert!(store.consumed.borrow().is_empty());
        assert_eq!(backend.calls, 0);
        assert_eq!(counters, SigningCounters::default());
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_signing_consumes_batch_before_private_backend() {
        let first = token(11, &[1, 2]);
        let second = token(12, &[1, 2]);
        let expected_sessions = vec![first.session_id, second.session_id];
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let mut store = SharedConsumedStore::default();
        let consumed_ref = store.consumed.clone();
        let mut backend = AssertConsumedBackend {
            consumed: consumed_ref,
            expected_sessions: expected_sessions.clone(),
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: false,
        };
        let mut counters = SigningCounters::default();

        let signature = sign_strict_no_rejected_z::<MlDsa65, _, _, _>(
            &strict_request(),
            &[0x42; 64],
            batch,
            &mut store,
            &mut counters,
            &mut backend,
            &AcceptSignature,
        )
        .expect("strict signing succeeds");

        assert_eq!(signature.bytes, vec![1, 2, 3]);
        assert_eq!(backend.calls, 1);
        assert_eq!(
            store.consumed.borrow().as_slice(),
            expected_sessions.as_slice()
        );
        assert_eq!(counters.attempts, 1);
        assert_eq!(counters.tokens_consumed, 2);
        assert_eq!(counters.signatures_returned, 1);
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn production_strict_stack_drives_all_private_boundaries() {
        let first = token(31, &[1, 2]);
        let second = token(32, &[1, 2]);
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let mut store = SharedConsumedStore::default();
        let mut counters = SigningCounters::default();
        let mut backend = ProductionStrictSigningBackend::new(
            StackPrepare {
                public_key: vec![7],
                accepted_index: Some(1),
            },
            StackBounds,
            StackHints,
            StackSelect,
            StackOpen,
        );

        let signature = sign_strict_no_rejected_z::<MlDsa65, _, _, _>(
            &strict_request(),
            &[0x33; 64],
            batch,
            &mut store,
            &mut counters,
            &mut backend,
            &AcceptSignature,
        )
        .expect("strict stack signs");

        assert_eq!(signature.bytes, vec![1, 2, 3]);
        assert_eq!(counters.tokens_consumed, 2);
        assert_eq!(counters.signatures_returned, 1);
    }

    #[test]
    fn strict_vector_runtime_adapter_attaches_certificate_from_runtime_evidence() {
        let first = token(35, &[1, 2]);
        let second = token(36, &[1, 2]);
        let consumed_batch = ConsumedBccCertifiedTokenBatch {
            signer_set: first.signer_set.clone(),
            tokens: vec![first, second],
        };
        let mut backend = ProductionStrictSigningVectorMpcRuntimeBackend::new(
            ProductionStrictSigningBackend::new(
                StackPrepare {
                    public_key: vec![7],
                    accepted_index: Some(0),
                },
                StackBounds,
                StackHints,
                StackSelect,
                StackOpen,
            ),
            release_vector_runtime_evidence(),
        )
        .expect("strict signing runtime adapter");

        let selected = StrictPrivateSigningBackend::<MlDsa65>::sign_consumed_batch(
            &mut backend,
            &strict_request(),
            &[0x35; 64],
            consumed_batch,
        )
        .expect("strict signing output");

        let certificate = selected
            .vector_runtime_certificate()
            .expect("runtime certificate is attached to selected output");
        assert_eq!(
            certificate.source(),
            StrictSigningRuntimeCertificateSource::RuntimeEvidenceOnly
        );
        assert!(certificate.runtime_evidence().counters.vector_lanes > 0);
        assert!(
            certificate
                .runtime_evidence()
                .coverage
                .private_one_hot_selection
        );
        assert_eq!(selected.signature.bytes, vec![1, 2, 3]);
    }

    #[test]
    fn strict_vector_runtime_adapter_rejects_incomplete_runtime_evidence() {
        let mut evidence = release_vector_runtime_evidence();
        evidence.coverage.private_one_hot_selection = false;
        let backend = ProductionStrictSigningBackend::new(
            StackPrepare {
                public_key: vec![7],
                accepted_index: Some(0),
            },
            StackBounds,
            StackHints,
            StackSelect,
            StackOpen,
        );

        let result = ProductionStrictSigningVectorMpcRuntimeBackend::new(backend, evidence);
        assert!(matches!(
            result,
            Err(OnlineError::StrictSigningRuntimeSlotIncomplete)
        ));
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_release_signing_rejects_local_stack_without_runtime_certificate() {
        let first = release_valid_token(37, &[1, 2]);
        let second = release_valid_token(38, &[1, 2]);
        let batch =
            BccCertifiedTokenBatch::new_release_validated(vec![first, second], 2).expect("batch");
        let mut store = SharedConsumedStore::default();
        let mut counters = SigningCounters::default();
        let mut backend = ProductionStrictSigningBackend::new(
            StackPrepare {
                public_key: vec![7],
                accepted_index: Some(0),
            },
            StackBounds,
            StackHints,
            StackSelect,
            StackOpen,
        );

        let err = sign_strict_no_rejected_z::<MlDsa65, _, _, _>(
            &strict_request(),
            &[0x37; 64],
            batch,
            &mut store,
            &mut counters,
            &mut backend,
            &AcceptSignature,
        )
        .expect_err("release signing rejects uncertified strict-signing runtime");

        assert_eq!(err, OnlineError::StrictSigningRuntimeSlotIncomplete);
        assert_eq!(counters.tokens_consumed, 2);
        assert_eq!(counters.signatures_returned, 0);
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_session_release_rejects_local_stack_without_runtime_certificate() {
        let first = release_valid_token(39, &[1, 2]);
        let second = release_valid_token(40, &[1, 2]);
        let batch =
            BccCertifiedTokenBatch::new_release_validated(vec![first, second], 2).expect("batch");
        let store = SharedConsumedStore::default();
        let consumed = store.consumed.clone();
        let backend = ProductionStrictSigningBackend::new(
            StackPrepare {
                public_key: vec![7],
                accepted_index: Some(0),
            },
            StackBounds,
            StackHints,
            StackSelect,
            StackOpen,
        );
        let mut session = StrictSigningSession::<MlDsa65, _, _, _>::start(
            strict_request(),
            [0x39; 64],
            batch,
            store,
            backend,
            AcceptSignature,
        )
        .expect("start strict session");

        let err = session
            .finish()
            .expect_err("release session rejects missing signing runtime evidence");

        assert_eq!(err, OnlineError::StrictSigningRuntimeSlotIncomplete);
        assert_eq!(consumed.borrow().len(), 2);
        assert_eq!(session.phase(), StrictSigningSessionPhase::Failed);
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_session_release_rejects_generic_runtime_evidence_wrapper() {
        let first = release_valid_token(41, &[1, 2]);
        let second = release_valid_token(42, &[1, 2]);
        let batch =
            BccCertifiedTokenBatch::new_release_validated(vec![first, second], 2).expect("batch");
        let backend = ProductionStrictSigningVectorMpcRuntimeBackend::new(
            ProductionStrictSigningBackend::new(
                StackPrepare {
                    public_key: vec![7],
                    accepted_index: Some(0),
                },
                StackBounds,
                StackHints,
                StackSelect,
                StackOpen,
            ),
            release_vector_runtime_evidence(),
        )
        .expect("runtime-certified backend");
        let mut session = StrictSigningSession::<MlDsa65, _, _, _>::start(
            strict_request(),
            [0x41; 64],
            batch,
            SharedConsumedStore::default(),
            backend,
            AcceptSignature,
        )
        .expect("start strict session");

        let err = session
            .finish()
            .expect_err("release session rejects generic runtime-evidence wrapper");

        assert_eq!(err, OnlineError::StrictSigningRuntimeSlotIncomplete);
        assert_eq!(session.phase(), StrictSigningSessionPhase::Failed);
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_session_release_accepts_selected_opening_artifact_backend() {
        let first = release_valid_zero_w1_token(43, &[1, 2]);
        let second = release_valid_zero_w1_token(44, &[1, 2]);
        let provider = zero_strict_share_provider(&[&first, &second]);
        let batch =
            BccCertifiedTokenBatch::new_release_validated(vec![first, second], 2).expect("batch");
        let request = strict_request();
        let tr = [0x43; 64];
        let source = ProductionStrictVectorMpcArtifactSource::new(
            vec![0u8; MlDsa65::PK_LEN],
            provider,
            release_vector_runtime_evidence(),
        )
        .expect("strict vector artifact source");
        let backend = ProductionStrictRuntimeSelectedOpeningArtifactBackend::new(source);
        let mut session = StrictSigningSession::<
            MlDsa65,
            ProductionStrictRuntimeSelectedOpeningArtifactBackend<
                ProductionStrictVectorMpcArtifactSource<TestStrictShareProvider>,
            >,
            _,
            _,
        >::start_release_validated(
            request,
            tr,
            batch,
            SharedConsumedStore::default(),
            backend,
            AcceptMlDsa65Length,
        )
        .expect("start strict session");

        let signature = session
            .finish()
            .expect("release session accepts selected-opening artifact backend");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert_eq!(session.phase(), StrictSigningSessionPhase::Finished);
        assert_eq!(session.counters().signatures_returned, 1);
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    #[ignore = "requires a multi-party app-driven vector MPC scheduler to deliver runtime phases"]
    fn strict_session_release_uses_live_vector_mpc_artifact_source() {
        let token = release_valid_zero_w1_token(45, &[1]);
        let token_session_id = token.session_id;
        let batch =
            BccCertifiedTokenBatch::new_release_validated(vec![token], 1).expect("release batch");
        let request = strict_request_one_party();
        let tr = [0x45; 64];
        let (config, runtime, label) = strict_test_vector_runtime_one_party(45);
        let y_lanes = vec![0; MlDsa65::L * MlDsa65::N];
        let s1_lanes = vec![0; MlDsa65::L * MlDsa65::N];
        let z_mask_lanes = vec![0; MlDsa65::L * MlDsa65::N];
        let hint_mask_lanes = vec![0; MlDsa65::K * MlDsa65::N];
        let z_bits = (0..23)
            .map(|bit| {
                runtime
                    .bit_share_vec_from_local_lanes::<MlDsa65>(
                        &config,
                        &label.child(format!("z_mask_bit_{bit}")),
                        vec![0; MlDsa65::L * MlDsa65::N],
                    )
                    .expect("z mask bit")
            })
            .collect::<Vec<_>>();
        let hint_bits = (0..23)
            .map(|bit| {
                runtime
                    .bit_share_vec_from_local_lanes::<MlDsa65>(
                        &config,
                        &label.child(format!("hint_mask_bit_{bit}")),
                        vec![0; MlDsa65::K * MlDsa65::N],
                    )
                    .expect("hint mask bit")
            })
            .collect::<Vec<_>>();
        let input = StrictRuntimeCandidateShareInput {
            token_session_id,
            y_share: runtime
                .share_vec_from_local_lanes::<MlDsa65>(&config, &label.child("y"), y_lanes)
                .expect("y share"),
            s1_share: runtime
                .share_vec_from_local_lanes::<MlDsa65>(&config, &label.child("s1"), s1_lanes)
                .expect("s1 share"),
            z_mask_value: runtime
                .share_vec_from_local_lanes::<MlDsa65>(
                    &config,
                    &label.child("z_mask"),
                    z_mask_lanes,
                )
                .expect("z mask"),
            z_mask_bits_by_bit: z_bits,
            hint_mask_value: runtime
                .share_vec_from_local_lanes::<MlDsa65>(
                    &config,
                    &label.child("hint_mask"),
                    hint_mask_lanes,
                )
                .expect("hint mask"),
            hint_mask_bits_by_bit: hint_bits,
            w1: vec![0; MlDsa65::K * MlDsa65::N],
        };
        let source = ProductionStrictLiveVectorMpcArtifactSource::new(
            config,
            runtime,
            TestProductionVectorEntropy::default(),
            vec![0u8; MlDsa65::PK_LEN],
            vec![input],
        );
        let backend = ProductionStrictRuntimeSelectedOpeningArtifactBackend::new(source);
        let mut session = StrictSigningSession::<
            MlDsa65,
            ProductionStrictRuntimeSelectedOpeningArtifactBackend<
                ProductionStrictLiveVectorMpcArtifactSource<
                    LatestRoundInMemoryTransport,
                    talus_dkg::InMemoryPrimeFieldMpcWireMessageLog,
                    talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog,
                    TestProductionVectorEntropy,
                >,
            >,
            _,
            _,
        >::start_release_validated(
            request,
            tr,
            batch,
            SharedConsumedStore::default(),
            backend,
            AcceptMlDsa65Length,
        )
        .expect("start strict session");

        let signature = session
            .finish()
            .expect("live vector runtime source signs selected material");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert_eq!(session.phase(), StrictSigningSessionPhase::Finished);
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_production_backend_constructor_uses_canonical_component_stack() {
        let first = zero_w1_token(81, &[1, 2]);
        let second = zero_w1_token(82, &[1, 2]);
        let provider = zero_strict_share_provider(&[&first, &second]);
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let mut store = SharedConsumedStore::default();
        let mut counters = SigningCounters::default();
        let mut backend = strict_production_signing_backend(vec![0u8; MlDsa65::PK_LEN], provider);

        let signature = sign_strict_no_rejected_z::<MlDsa65, _, _, _>(
            &strict_request(),
            &[0x83; 64],
            batch,
            &mut store,
            &mut counters,
            &mut backend,
            &AcceptMlDsa65Length,
        )
        .expect("canonical strict production stack signs");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert_eq!(counters.tokens_consumed, 2);
        assert_eq!(counters.signatures_returned, 1);
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_no_valid_batch_consumes_tokens_and_returns_generic_failure_only() {
        let first = token(83, &[1, 2]);
        let second = token(84, &[1, 2]);
        let expected_sessions = vec![first.session_id, second.session_id];
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let mut store = SharedConsumedStore::default();
        let mut counters = SigningCounters::default();
        let mut backend = ProductionStrictSigningBackend::new(
            StackPrepare {
                public_key: vec![7],
                accepted_index: None,
            },
            StackBounds,
            StackHints,
            StackSelect,
            StackOpen,
        );

        let err = sign_strict_no_rejected_z::<MlDsa65, _, _, _>(
            &strict_request(),
            &[0x84; 64],
            batch,
            &mut store,
            &mut counters,
            &mut backend,
            &AcceptSignature,
        )
        .expect_err("no valid candidate returns generic failure");

        assert_eq!(err, OnlineError::GenericBatchFailure);
        assert_eq!(
            store.consumed.borrow().as_slice(),
            expected_sessions.as_slice()
        );
        assert_eq!(counters.tokens_consumed, 2);
        assert_eq!(counters.signatures_returned, 0);
        let display = err.to_string();
        for forbidden in [
            "z",
            "hint",
            "bound",
            "candidate",
            "token",
            "valid",
            "invalid",
        ] {
            assert!(
                !display.contains(forbidden),
                "generic strict failure must not reveal {forbidden}"
            );
        }
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_request_rejects_forked_signing_set_before_token_consumption() {
        let first = token(85, &[1, 2]);
        let second = token(86, &[1, 2]);
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let mut request = strict_request();
        request.signing_set = vec![PartyId(1), PartyId(3)];
        let mut store = SharedConsumedStore::default();
        let mut counters = SigningCounters::default();
        let mut backend = AssertConsumedBackend {
            consumed: store.consumed.clone(),
            expected_sessions: vec![],
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: false,
        };

        assert_eq!(
            sign_strict_no_rejected_z::<MlDsa65, _, _, _>(
                &request,
                &[0x85; 64],
                batch,
                &mut store,
                &mut counters,
                &mut backend,
                &AcceptSignature,
            ),
            Err(OnlineError::StrictRequestBatchMismatch)
        );
        assert!(store.consumed.borrow().is_empty());
        assert_eq!(backend.calls, 0);
    }

    #[test]
    fn strict_candidate_challenge_is_recomputed_from_bound_request() {
        let token = token(87, &[1, 2]);
        let request = strict_request();
        let mut forked_request = request.clone();
        forked_request.message = b"forked message".to_vec();

        let metadata = strict_candidate_metadata::<MlDsa65>(&request, &token, &[0x87; 64]);
        let forked_metadata =
            strict_candidate_metadata::<MlDsa65>(&forked_request, &token, &[0x87; 64]);

        assert_ne!(metadata.ctilde, forked_metadata.ctilde);
        assert_ne!(metadata.priority, forked_metadata.priority);
        assert_ne!(
            strict_signing_request_hash(&request),
            strict_signing_request_hash(&forked_request)
        );
    }

    fn dummy_strict_wire_message() -> WireMessage {
        WireMessage {
            header: talus_wire::WireHeader {
                protocol_version: talus_wire::WIRE_PROTOCOL_VERSION,
                suite: talus_wire::SuiteId::MlDsa65,
                round: talus_wire::RoundId::SignRequest,
                sender_party_id: 1,
                keygen_transcript_hash: [0xAB; 32],
                session_id: [0xCD; 32],
                signing_set_hash: [0xEF; 32],
                payload_kind: talus_wire::PayloadKind::SignRequest,
            },
            payload: Vec::new(),
        }
    }

    fn strict_mpc_wire_message(
        session_id: StrictSigningSessionId,
        sender: u16,
        receiver: u16,
        slot: StrictSignMpcSlot,
        phase: u8,
        payload_byte: u8,
    ) -> WireMessage {
        WireMessage {
            header: talus_wire::WireHeader {
                protocol_version: talus_wire::WIRE_PROTOCOL_VERSION,
                suite: talus_wire::SuiteId::MlDsa65,
                round: talus_wire::RoundId::StrictSignMpc,
                sender_party_id: sender,
                keygen_transcript_hash: [0xAB; 32],
                session_id: session_id.0,
                signing_set_hash: talus_wire::signing_set_hash(&[1, 2]),
                payload_kind: talus_wire::PayloadKind::StrictSignMpc,
            },
            payload: talus_wire::encode_strict_sign_mpc_payload(
                &talus_wire::StrictSignMpcPayload {
                    slot,
                    phase,
                    receiver_party_id: receiver,
                    label_hash: [phase; 32],
                    transcript_hash: [payload_byte; 32],
                    opaque_payload: vec![payload_byte],
                },
            ),
        }
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_signing_session_drives_finish_and_rejects_transport_until_runtime_lands() {
        let first = token(33, &[1, 2]);
        let second = token(34, &[1, 2]);
        let expected_sessions = vec![first.session_id, second.session_id];
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let store = SharedConsumedStore::default();
        let consumed_ref = store.consumed.clone();
        let backend = AssertConsumedBackend {
            consumed: consumed_ref,
            expected_sessions: expected_sessions.clone(),
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: false,
        };
        let mut session = StrictSigningSession::<MlDsa65, _, _, _>::start(
            strict_request(),
            [0x44; 64],
            batch,
            store,
            backend,
            AcceptSignature,
        )
        .expect("start strict signing session");

        assert_eq!(session.phase(), StrictSigningSessionPhase::Ready);
        assert_eq!(session.next_outbound(), None);
        assert_eq!(
            session.handle_private(PartyId(1), dummy_strict_wire_message()),
            Err(OnlineError::StrictSigningWireMessageRejected)
        );
        assert_eq!(
            session.handle_broadcast(dummy_strict_wire_message()),
            Err(OnlineError::StrictSigningWireMessageRejected)
        );
        let valid_direct_private = strict_mpc_wire_message(
            session.session_id(),
            1,
            2,
            StrictSignMpcSlot::PrepareCandidateShares,
            1,
            9,
        );
        assert_eq!(
            session.handle_private(PartyId(1), valid_direct_private),
            Err(OnlineError::UnexpectedStrictSigningPrivateMessage)
        );
        assert_eq!(session.accepted_wire_message_count(), 0);

        let signature = session.finish().expect("finish strict signing");
        assert_eq!(signature.bytes, vec![1, 2, 3]);
        assert_eq!(session.phase(), StrictSigningSessionPhase::Finished);
        assert_eq!(
            session.finish(),
            Err(OnlineError::StrictSigningSessionAlreadyFinished)
        );

        let (store, _cursor_store, backend, _verifier, counters, final_signature) =
            session.into_parts();
        assert_eq!(backend.calls, 1);
        assert_eq!(
            store.consumed.borrow().as_slice(),
            expected_sessions.as_slice()
        );
        assert_eq!(counters.tokens_consumed, 2);
        assert_eq!(counters.signatures_returned, 1);
        assert_eq!(
            final_signature.expect("stored final signature").bytes,
            vec![1, 2, 3]
        );
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_signing_session_routes_strict_mpc_wire_messages_and_persists_hashes() {
        let first = token(44, &[1, 2]);
        let second = token(45, &[1, 2]);
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let store = SharedConsumedStore::default();
        let backend = AssertConsumedBackend {
            consumed: store.consumed.clone(),
            expected_sessions: vec![session(44), session(45)],
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: false,
        };
        let mut session = StrictSigningSession::<MlDsa65, _, _, _>::start_with_runtime(
            strict_request(),
            [0x49; 64],
            batch,
            store,
            ScriptedStrictRuntime::hold(),
            backend,
            AcceptSignature,
        )
        .expect("start strict signing session");

        let private = strict_mpc_wire_message(
            session.session_id(),
            1,
            2,
            StrictSignMpcSlot::PrepareCandidateShares,
            1,
            9,
        );
        session
            .handle_private(PartyId(1), private.clone())
            .expect("accept private strict mpc");
        assert_eq!(session.accepted_wire_message_count(), 1);
        assert_ne!(session.wire_transcript_hash(), [0u8; 32]);
        assert_eq!(
            session.handle_private(PartyId(1), private),
            Err(OnlineError::StrictSigningWireReplay)
        );

        let broadcast = strict_mpc_wire_message(
            session.session_id(),
            2,
            0,
            StrictSignMpcSlot::BoundChecks,
            2,
            10,
        );
        session
            .handle_broadcast(broadcast)
            .expect("accept broadcast strict mpc");
        assert_eq!(session.accepted_wire_message_count(), 2);

        let outbound = strict_mpc_wire_message(
            session.session_id(),
            1,
            2,
            StrictSignMpcSlot::PrivateSelection,
            3,
            11,
        );
        session
            .queue_private_mpc_message(PartyId(2), outbound.clone())
            .expect("queue outbound private");
        assert_eq!(session.outbound_wire_message_count(), 1);
        assert_eq!(
            session.next_outbound(),
            Some(StrictSigningOutbound::Private {
                receiver: PartyId(2),
                message: outbound,
            })
        );
        assert_eq!(session.next_outbound(), None);

        let cursor = session
            .persisted_cursor()
            .expect("load cursor")
            .expect("cursor");
        assert_eq!(cursor.accepted_wire_message_hashes.len(), 2);
        assert_eq!(cursor.outbound_wire_message_hashes.len(), 1);
        assert_eq!(cursor.wire_transcript_hash, session.wire_transcript_hash());
        assert_eq!(
            cursor.runtime_slot,
            Some(StrictSigningRuntimeSlot::PrivateSelection)
        );
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_signing_session_delegates_to_distributed_runtime_and_tracks_completion() {
        let first = token(48, &[1, 2]);
        let second = token(49, &[1, 2]);
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let store = SharedConsumedStore::default();
        let backend = AssertConsumedBackend {
            consumed: store.consumed.clone(),
            expected_sessions: vec![session(48), session(49)],
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: false,
        };
        let request = strict_request();
        let runtime_outbound = strict_mpc_wire_message(
            strict_signing_session_id(&request, &[session(48), session(49)]),
            1,
            0,
            StrictSignMpcSlot::BoundChecks,
            2,
            12,
        );
        let runtime = ScriptedStrictRuntime {
            outbound: vec![StrictSigningOutbound::Broadcast {
                message: runtime_outbound.clone(),
            }],
            ..ScriptedStrictRuntime::complete_after(2)
        };
        let mut session = StrictSigningSession::<MlDsa65, _, _, _>::start_with_runtime(
            request,
            [0x4b; 64],
            batch,
            store,
            runtime,
            backend,
            AcceptSignature,
        )
        .expect("start strict signing session");

        let private = strict_mpc_wire_message(
            session.session_id(),
            1,
            2,
            StrictSignMpcSlot::PrepareCandidateShares,
            1,
            9,
        );
        session
            .handle_private(PartyId(1), private)
            .expect("runtime handles private strict mpc");
        assert!(session.completed_runtime_slots().is_empty());
        let second_private = strict_mpc_wire_message(
            session.session_id(),
            2,
            1,
            StrictSignMpcSlot::PrepareCandidateShares,
            1,
            10,
        );
        session
            .handle_private(PartyId(2), second_private)
            .expect("runtime completes after all senders");
        assert_eq!(
            session.completed_runtime_slots(),
            &[StrictSigningRuntimeSlot::ResponsePreparation]
        );
        assert_eq!(
            session.next_outbound(),
            Some(StrictSigningOutbound::Broadcast {
                message: runtime_outbound,
            })
        );

        let (_consumed, _cursor_store, runtime, _backend, _verifier, _counters, _signature) =
            session.into_parts_with_runtime();
        assert_eq!(runtime.private_calls, 2);
        assert_eq!(runtime.broadcast_calls, 0);
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_signing_session_rejects_out_of_order_runtime_completion() {
        let first = token(50, &[1, 2]);
        let second = token(51, &[1, 2]);
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let store = SharedConsumedStore::default();
        let backend = AssertConsumedBackend {
            consumed: store.consumed.clone(),
            expected_sessions: vec![session(50), session(51)],
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: false,
        };
        let mut session = StrictSigningSession::<MlDsa65, _, _, _>::start_with_runtime(
            strict_request(),
            [0x4c; 64],
            batch,
            store,
            ScriptedStrictRuntime::complete_immediately(),
            backend,
            AcceptSignature,
        )
        .expect("start strict signing session");

        let early_bound_check = strict_mpc_wire_message(
            session.session_id(),
            1,
            2,
            StrictSignMpcSlot::BoundChecks,
            1,
            9,
        );
        assert_eq!(
            session.handle_private(PartyId(1), early_bound_check),
            Err(OnlineError::StrictSigningRuntimeSlotOutOfOrder)
        );
        assert!(session.completed_runtime_slots().is_empty());
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_signing_session_enforces_runtime_sender_and_phase_discipline() {
        let first = token(54, &[1, 2]);
        let second = token(55, &[1, 2]);
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let store = SharedConsumedStore::default();
        let backend = AssertConsumedBackend {
            consumed: store.consumed.clone(),
            expected_sessions: vec![session(54), session(55)],
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: false,
        };
        let mut session = StrictSigningSession::<MlDsa65, _, _, _>::start_with_runtime(
            strict_request(),
            [0x4e; 64],
            batch,
            store,
            ScriptedStrictRuntime::complete_after(3),
            backend,
            AcceptSignature,
        )
        .expect("start strict signing session");

        let first_message = strict_mpc_wire_message(
            session.session_id(),
            1,
            2,
            StrictSignMpcSlot::PrepareCandidateShares,
            1,
            9,
        );
        session
            .handle_private(PartyId(1), first_message)
            .expect("first sender accepted");

        let duplicate_sender = strict_mpc_wire_message(
            session.session_id(),
            1,
            2,
            StrictSignMpcSlot::PrepareCandidateShares,
            1,
            10,
        );
        assert_eq!(
            session.handle_private(PartyId(1), duplicate_sender),
            Err(OnlineError::StrictSigningRuntimeDuplicateSender)
        );

        let wrong_phase = strict_mpc_wire_message(
            session.session_id(),
            2,
            1,
            StrictSignMpcSlot::PrepareCandidateShares,
            2,
            11,
        );
        assert_eq!(
            session.handle_private(PartyId(2), wrong_phase),
            Err(OnlineError::StrictSigningRuntimeSlotPhaseMismatch)
        );
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_signing_session_rejects_completion_before_required_senders_arrive() {
        let first = token(56, &[1, 2]);
        let second = token(57, &[1, 2]);
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let store = SharedConsumedStore::default();
        let backend = AssertConsumedBackend {
            consumed: store.consumed.clone(),
            expected_sessions: vec![session(56), session(57)],
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: false,
        };
        let mut session = StrictSigningSession::<MlDsa65, _, _, _>::start_with_runtime(
            strict_request(),
            [0x4f; 64],
            batch,
            store,
            ScriptedStrictRuntime::complete_immediately(),
            backend,
            AcceptSignature,
        )
        .expect("start strict signing session");

        let message = strict_mpc_wire_message(
            session.session_id(),
            1,
            2,
            StrictSignMpcSlot::PrepareCandidateShares,
            1,
            9,
        );
        assert_eq!(
            session.handle_private(PartyId(1), message),
            Err(OnlineError::StrictSigningRuntimeSlotIncomplete)
        );
        assert!(session.completed_runtime_slots().is_empty());
        let progress = session.runtime_slot_progress();
        assert_eq!(progress.len(), 1);
        assert_eq!(progress[0].accepted_senders, vec![PartyId(1)]);
        assert!(!progress[0].completed);
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_signing_session_rejects_malformed_strict_mpc_wire_messages() {
        let first = token(46, &[1, 2]);
        let second = token(47, &[1, 2]);
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let store = SharedConsumedStore::default();
        let backend = AssertConsumedBackend {
            consumed: store.consumed.clone(),
            expected_sessions: vec![session(46), session(47)],
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: false,
        };
        let mut session = StrictSigningSession::<MlDsa65, _, _, _>::start(
            strict_request(),
            [0x4a; 64],
            batch,
            store,
            backend,
            AcceptSignature,
        )
        .expect("start strict signing session");

        let mut wrong_sender = strict_mpc_wire_message(
            session.session_id(),
            3,
            2,
            StrictSignMpcSlot::PrepareCandidateShares,
            1,
            1,
        );
        assert_eq!(
            session.handle_private(PartyId(3), wrong_sender.clone()),
            Err(OnlineError::StrictSigningWireMessageRejected)
        );

        wrong_sender.header.sender_party_id = 1;
        assert_eq!(
            session.handle_private(PartyId(2), wrong_sender),
            Err(OnlineError::UnexpectedStrictSigningPrivateMessage)
        );

        let wrong_receiver = strict_mpc_wire_message(
            session.session_id(),
            1,
            3,
            StrictSignMpcSlot::PrepareCandidateShares,
            1,
            2,
        );
        assert_eq!(
            session.handle_private(PartyId(1), wrong_receiver),
            Err(OnlineError::StrictSigningWireMessageRejected)
        );

        let mut wrong_session = strict_mpc_wire_message(
            session.session_id(),
            1,
            2,
            StrictSignMpcSlot::PrepareCandidateShares,
            1,
            3,
        );
        wrong_session.header.session_id = [0x55; 32];
        assert_eq!(
            session.handle_private(PartyId(1), wrong_session),
            Err(OnlineError::StrictSigningWireMessageRejected)
        );

        let broadcast_with_receiver = strict_mpc_wire_message(
            session.session_id(),
            1,
            2,
            StrictSignMpcSlot::BoundChecks,
            1,
            4,
        );
        assert_eq!(
            session.handle_broadcast(broadcast_with_receiver),
            Err(OnlineError::UnexpectedStrictSigningBroadcast)
        );

        let legacy = dummy_strict_wire_message();
        assert_eq!(
            session.queue_broadcast_mpc_message(legacy),
            Err(OnlineError::StrictSigningWireMessageRejected)
        );
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_signing_session_failure_is_terminal_after_consumption() {
        let first = token(36, &[1, 2]);
        let second = token(37, &[1, 2]);
        let expected_sessions = vec![first.session_id, second.session_id];
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let store = SharedConsumedStore::default();
        let consumed_ref = store.consumed.clone();
        let backend = AssertConsumedBackend {
            consumed: consumed_ref,
            expected_sessions: expected_sessions.clone(),
            calls: 0,
            signature: vec![9, 9, 9],
            bad_shape: false,
        };
        let mut session = StrictSigningSession::<MlDsa65, _, _, _>::start(
            strict_request(),
            [0x45; 64],
            batch,
            store,
            backend,
            AcceptSignature,
        )
        .expect("start strict signing session");

        assert_eq!(session.finish(), Err(OnlineError::FinalVerifyFailed));
        assert_eq!(session.phase(), StrictSigningSessionPhase::Failed);
        assert_eq!(
            session.finish(),
            Err(OnlineError::StrictSigningSessionAlreadyFinished)
        );
        let (store, _cursor_store, backend, _verifier, counters, final_signature) =
            session.into_parts();
        assert_eq!(backend.calls, 1);
        assert_eq!(
            store.consumed.borrow().as_slice(),
            expected_sessions.as_slice()
        );
        assert_eq!(counters.tokens_consumed, 2);
        assert_eq!(counters.signatures_returned, 0);
        assert_eq!(counters.final_verify_failures, 1);
        assert_eq!(final_signature, None);
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_signing_session_persists_start_and_finished_cursor() {
        let first = token(38, &[1, 2]);
        let second = token(39, &[1, 2]);
        let token_ids = vec![first.session_id, second.session_id];
        let request = strict_request();
        let expected_session_id = strict_signing_session_id(&request, &token_ids);
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let store = SharedConsumedStore::default();
        let consumed_ref = store.consumed.clone();
        let backend = AssertConsumedBackend {
            consumed: consumed_ref,
            expected_sessions: token_ids.clone(),
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: false,
        };
        let mut session = StrictSigningSession::<MlDsa65, _, _, _, _>::start_with_cursor_store(
            request.clone(),
            [0x46; 64],
            batch,
            store,
            StrictSigningCursorMemoryStore::new(),
            backend,
            AcceptSignature,
        )
        .expect("start strict signing session");

        let started = session
            .persisted_cursor()
            .expect("load cursor")
            .expect("started cursor");
        assert_eq!(started.session_id, expected_session_id);
        assert_eq!(started.phase, StrictSigningCursorPhase::Started);
        assert_eq!(started.request_hash, strict_signing_request_hash(&request));
        assert_eq!(started.token_session_ids, token_ids);
        assert_eq!(started.final_signature_hash, None);

        let signature = session.finish().expect("finish strict signing");
        let finished = session
            .persisted_cursor()
            .expect("load cursor")
            .expect("finished cursor");
        assert_eq!(finished.phase, StrictSigningCursorPhase::Finished);
        assert_eq!(
            finished.final_signature_hash,
            Some(strict_signature_hash(&signature))
        );
        assert_eq!(finished.runtime_slot, None);
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_signing_session_persists_every_runtime_slot() {
        let first = zero_w1_token(42, &[1, 2]);
        let second = zero_w1_token(43, &[1, 2]);
        let provider = zero_strict_share_provider(&[&first, &second]);
        let token_ids = vec![first.session_id, second.session_id];
        let request = strict_request();
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let consumed = SharedConsumedStore::default();
        let cursor_store = RecordingCursorStore::default();
        let cursor_log = cursor_store.cursors.clone();
        let backend = ProductionStrictSigningBackend::new(
            ProductionVectorResponsePreparationBackend::new(vec![0u8; MlDsa65::PK_LEN], provider),
            ProductionVectorResponseBoundCheckBackend,
            ProductionVectorHintCheckBackend,
            ProductionVectorPrivateSelectionBackend::new(),
            ProductionVectorSelectedOpeningBackend::new(),
        );
        let mut session = StrictSigningSession::<MlDsa65, _, _, _, _>::start_with_cursor_store(
            request,
            [0x48; 64],
            batch,
            consumed,
            cursor_store,
            backend,
            AcceptMlDsa65Length,
        )
        .expect("start strict signing session");

        let signature = session.finish().expect("finish strict signing");
        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        let cursors = cursor_log.borrow();
        let slots = cursors
            .iter()
            .filter_map(|cursor| cursor.runtime_slot)
            .collect::<Vec<_>>();
        assert_eq!(slots, STRICT_SIGNING_RUNTIME_SLOTS);
        assert_eq!(
            cursors.first().map(|cursor| cursor.phase),
            Some(StrictSigningCursorPhase::Started)
        );
        assert!(cursors.iter().any(|cursor| cursor.phase
            == StrictSigningCursorPhase::TokensConsumed
            && cursor.runtime_slot.is_none()));
        let finished = cursors.last().expect("finished cursor");
        assert_eq!(finished.phase, StrictSigningCursorPhase::Finished);
        assert_eq!(finished.runtime_slot, None);
        assert_eq!(finished.token_session_ids, token_ids);
        assert_eq!(
            finished.final_signature_hash,
            Some(strict_signature_hash(&signature))
        );
    }

    #[test]
    fn strict_runtime_slots_match_production_wire_slots() {
        let wire_slots = STRICT_SIGNING_RUNTIME_SLOTS
            .iter()
            .copied()
            .map(StrictSigningRuntimeSlot::wire_slot)
            .collect::<Vec<_>>();

        assert_eq!(
            wire_slots,
            vec![
                StrictSignMpcSlot::PrepareCandidateShares,
                StrictSignMpcSlot::BoundChecks,
                StrictSignMpcSlot::HintChecks,
                StrictSignMpcSlot::PrivateSelection,
                StrictSignMpcSlot::SelectedOpening,
            ]
        );
    }

    #[cfg(feature = "std")]
    fn strict_session_store_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "talus-strict-session-{name}-{}-{}.log",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[cfg(feature = "std")]
    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_signing_session_restart_preserves_accepted_wire_hashes_before_completion() {
        let cursor_path = strict_session_store_path("wire-restart");
        let first = token(52, &[1, 2]);
        let second = token(53, &[1, 2]);
        let token_ids = vec![first.session_id, second.session_id];
        let request = strict_request();
        let message;

        {
            let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
            let store = SharedConsumedStore::default();
            let backend = AssertConsumedBackend {
                consumed: store.consumed.clone(),
                expected_sessions: token_ids.clone(),
                calls: 0,
                signature: vec![1, 2, 3],
                bad_shape: false,
            };
            let cursor_store =
                FileStrictSigningSessionStore::open(&cursor_path).expect("open cursor store");
            let mut session =
                StrictSigningSession::<MlDsa65, _, _, _, _, _>::start_with_cursor_store_and_runtime(
                    request.clone(),
                    [0x4d; 64],
                    batch,
                    store,
                    cursor_store,
                    ScriptedStrictRuntime::hold(),
                    backend,
                    AcceptSignature,
                )
                .expect("start strict signing session");
            message = strict_mpc_wire_message(
                session.session_id(),
                1,
                2,
                StrictSignMpcSlot::PrepareCandidateShares,
                1,
                9,
            );
            session
                .handle_private(PartyId(1), message.clone())
                .expect("accept held private strict mpc");
            assert_eq!(session.accepted_wire_message_count(), 1);
            assert!(session.completed_runtime_slots().is_empty());
        }

        let first_again = token(52, &[1, 2]);
        let second_again = token(53, &[1, 2]);
        let batch =
            BccCertifiedTokenBatch::new(vec![first_again, second_again], 2).expect("strict batch");
        let store = SharedConsumedStore::default();
        let backend = AssertConsumedBackend {
            consumed: store.consumed.clone(),
            expected_sessions: token_ids,
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: false,
        };
        let cursor_store =
            FileStrictSigningSessionStore::open(&cursor_path).expect("reopen cursor store");
        let mut restarted =
            StrictSigningSession::<MlDsa65, _, _, _, _, _>::start_with_cursor_store_and_runtime(
                request,
                [0x4d; 64],
                batch,
                store,
                cursor_store,
                ScriptedStrictRuntime::hold(),
                backend,
                AcceptSignature,
            )
            .expect("restart strict signing session");
        assert_eq!(restarted.accepted_wire_message_count(), 1);
        assert!(restarted.completed_runtime_slots().is_empty());
        assert_eq!(
            restarted.handle_private(PartyId(1), message),
            Err(OnlineError::StrictSigningWireReplay)
        );

        let _ = std::fs::remove_file(cursor_path);
    }

    #[cfg(feature = "std")]
    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn file_strict_signing_cursor_survives_reopen_and_blocks_consumed_batch_reuse() {
        let cursor_path = strict_session_store_path("cursor-reopen");
        let consumed_path = strict_session_store_path("consumed-reopen");
        let first = token(40, &[1, 2]);
        let second = token(41, &[1, 2]);
        let token_ids = vec![first.session_id, second.session_id];
        let request = strict_request();
        let session_id = strict_signing_session_id(&request, &token_ids);

        {
            let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
            let consumed =
                FileConsumedTokenStore::open(&consumed_path).expect("open consumed store");
            let cursor_store =
                FileStrictSigningSessionStore::open(&cursor_path).expect("open cursor store");
            let backend = AssertConsumedBackend {
                consumed: Rc::new(RefCell::new(token_ids.clone())),
                expected_sessions: token_ids.clone(),
                calls: 0,
                signature: vec![9, 9, 9],
                bad_shape: false,
            };
            let mut session = StrictSigningSession::<MlDsa65, _, _, _, _>::start_with_cursor_store(
                request.clone(),
                [0x47; 64],
                batch,
                consumed,
                cursor_store,
                backend,
                AcceptSignature,
            )
            .expect("start strict signing session");
            assert_eq!(session.finish(), Err(OnlineError::FinalVerifyFailed));
        }

        let reopened_cursor =
            FileStrictSigningSessionStore::open(&cursor_path).expect("reopen cursor store");
        let cursor = reopened_cursor
            .load_cursor(session_id)
            .expect("load cursor")
            .expect("cursor exists");
        assert_eq!(cursor.phase, StrictSigningCursorPhase::Failed);
        assert_eq!(cursor.token_session_ids, token_ids);

        let reopened_consumed =
            FileConsumedTokenStore::open(&consumed_path).expect("reopen consumed store");
        for session_id in &token_ids {
            assert!(reopened_consumed.is_consumed(*session_id));
        }

        let first_again = token(40, &[1, 2]);
        let second_again = token(41, &[1, 2]);
        let batch =
            BccCertifiedTokenBatch::new(vec![first_again, second_again], 2).expect("strict batch");
        let backend = AssertConsumedBackend {
            consumed: Rc::new(RefCell::new(token_ids.clone())),
            expected_sessions: token_ids.clone(),
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: false,
        };
        assert_eq!(
            StrictSigningSession::<MlDsa65, _, _, _, _>::start_with_cursor_store(
                request,
                [0x47; 64],
                batch,
                reopened_consumed,
                reopened_cursor,
                backend,
                AcceptSignature,
            )
            .map(|_| ()),
            Err(OnlineError::StrictSigningSessionAlreadyFinished)
        );

        let _ = std::fs::remove_file(cursor_path);
        let _ = std::fs::remove_file(consumed_path);
    }

    #[test]
    fn production_vector_backend_signs_real_token_batch_without_dev_backend() {
        let first = zero_w1_token(41, &[1, 2]);
        let second = zero_w1_token(42, &[1, 2]);
        let provider = zero_strict_share_provider(&[&first, &second]);
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let mut store = SharedConsumedStore::default();
        let mut counters = SigningCounters::default();
        let mut backend = ProductionStrictSigningBackend::new(
            ProductionVectorResponsePreparationBackend::new(vec![0u8; MlDsa65::PK_LEN], provider),
            ProductionVectorResponseBoundCheckBackend,
            ProductionVectorHintCheckBackend,
            ProductionVectorPrivateSelectionBackend::new(),
            ProductionVectorSelectedOpeningBackend::new(),
        );

        let signature = sign_strict_no_rejected_z::<MlDsa65, _, _, _>(
            &strict_request(),
            &[0x55; 64],
            batch,
            &mut store,
            &mut counters,
            &mut backend,
            &AcceptMlDsa65Length,
        )
        .expect("strict vector backend signs");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert_eq!(counters.tokens_consumed, 2);
        assert_eq!(counters.signatures_returned, 1);
    }

    #[test]
    fn production_vector_handles_do_not_debug_private_material() {
        let first = zero_w1_token(43, &[1, 2]);
        let provider = zero_strict_share_provider(&[&first]);
        let batch = ConsumedBccCertifiedTokenBatch {
            signer_set: first.signer_set.clone(),
            tokens: vec![first],
        };
        let request = strict_request();
        let metadata = strict_candidate_metadata_batch::<MlDsa65>(&request, &batch, &[0x66; 64]);
        let mut prepare =
            ProductionVectorResponsePreparationBackend::new(vec![0u8; MlDsa65::PK_LEN], provider);
        let prepared =
            <ProductionVectorResponsePreparationBackend<_> as StrictResponsePreparationBackend<
                MlDsa65,
            >>::prepare_private_responses(
                &mut prepare, &request, &[0x66; 64], &batch, &metadata
            )
            .expect("prepare responses");
        let handle_debug = format!("{:?}", prepared.candidates[0]);

        for forbidden in ["response", "bound_ok", "hint_ok", "signature"] {
            assert!(
                !handle_debug.contains(forbidden),
                "vector handle debug must not expose {forbidden}"
            );
        }
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_final_verify_failure_consumes_without_output() {
        let first = token(21, &[1, 2]);
        let second = token(22, &[1, 2]);
        let expected_sessions = vec![first.session_id, second.session_id];
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let mut store = SharedConsumedStore::default();
        let consumed_ref = store.consumed.clone();
        let mut backend = AssertConsumedBackend {
            consumed: consumed_ref,
            expected_sessions: expected_sessions.clone(),
            calls: 0,
            signature: vec![9, 9, 9],
            bad_shape: false,
        };
        let mut counters = SigningCounters::default();

        assert_eq!(
            sign_strict_no_rejected_z::<MlDsa65, _, _, _>(
                &strict_request(),
                &[0x42; 64],
                batch,
                &mut store,
                &mut counters,
                &mut backend,
                &AcceptSignature,
            ),
            Err(OnlineError::FinalVerifyFailed)
        );

        assert_eq!(backend.calls, 1);
        assert_eq!(
            store.consumed.borrow().as_slice(),
            expected_sessions.as_slice()
        );
        assert_eq!(counters.tokens_consumed, 2);
        assert_eq!(counters.signatures_returned, 0);
        assert_eq!(counters.final_verify_failures, 1);
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn strict_response_check_shape_is_enforced_before_output() {
        let first = token(24, &[1, 2]);
        let second = token(25, &[1, 2]);
        let expected_sessions = vec![first.session_id, second.session_id];
        let batch = BccCertifiedTokenBatch::new(vec![first, second], 2).expect("strict batch");
        let mut store = SharedConsumedStore::default();
        let consumed_ref = store.consumed.clone();
        let mut backend = AssertConsumedBackend {
            consumed: consumed_ref,
            expected_sessions: expected_sessions.clone(),
            calls: 0,
            signature: vec![1, 2, 3],
            bad_shape: true,
        };
        let mut counters = SigningCounters::default();

        assert_eq!(
            sign_strict_no_rejected_z::<MlDsa65, _, _, _>(
                &strict_request(),
                &[0x42; 64],
                batch,
                &mut store,
                &mut counters,
                &mut backend,
                &AcceptSignature,
            ),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        );

        assert_eq!(backend.calls, 1);
        assert_eq!(
            store.consumed.borrow().as_slice(),
            expected_sessions.as_slice()
        );
        assert_eq!(counters.tokens_consumed, 2);
        assert_eq!(counters.signatures_returned, 0);
    }

    #[test]
    fn strict_candidate_priority_is_public_stable_and_bound() {
        let request = strict_request();
        let token_a = token(31, &[1, 2]);
        let token_b = token(32, &[1, 2]);

        assert_eq!(
            strict_candidate_priority(&request, &token_a),
            strict_candidate_priority(&request, &token_a)
        );
        assert_ne!(
            strict_candidate_priority(&request, &token_a),
            strict_candidate_priority(&request, &token_b)
        );

        let mut changed_message = request.clone();
        changed_message.message = b"other message".to_vec();
        assert_ne!(
            strict_candidate_priority(&request, &token_a),
            strict_candidate_priority(&changed_message, &token_a)
        );

        let mut changed_context = request.clone();
        changed_context.context = b"other context".to_vec();
        assert_ne!(
            strict_candidate_priority(&request, &token_a),
            strict_candidate_priority(&changed_context, &token_a)
        );
    }

    #[test]
    fn strict_candidate_metadata_excludes_response_material() {
        let request = strict_request();
        let token = token(35, &[1, 2]);
        let metadata = strict_candidate_metadata::<MlDsa65>(&request, &token, &[0x42; 64]);

        assert_eq!(metadata.session_id, token.session_id);
        assert_eq!(metadata.token_transcript_hash, token.transcript_hash);
        assert_eq!(
            metadata.priority,
            strict_candidate_priority(&request, &token)
        );
        assert_eq!(metadata.ctilde.len(), MlDsa65::CTILDE_LEN);
        assert_ne!(metadata.encoded_w1_hash, [0u8; 32]);

        let debug = format!("{metadata:?}");
        for forbidden in [
            "clear response",
            "aggregate response",
            "pass/fail",
            "failure",
            "witness",
        ] {
            assert!(
                !debug.contains(forbidden),
                "candidate metadata must not expose {forbidden}"
            );
        }
    }

    #[test]
    fn strict_phase_driver_enforces_no_rejected_z_order() {
        let mut driver = StrictSigningPhaseDriver::new();
        assert_eq!(
            driver.accept_challenges(2),
            Err(OnlineError::StrictSigningPhaseOutOfOrder)
        );

        driver.accept_consumed_batch(2).expect("consume");
        assert_eq!(
            driver.accept_private_responses(2),
            Err(OnlineError::StrictSigningPhaseOutOfOrder)
        );
        driver.accept_challenges(2).expect("challenges");
        assert_eq!(
            driver.accept_private_responses(1),
            Err(OnlineError::StrictSigningPhaseOutOfOrder)
        );
        driver.accept_private_responses(2).expect("responses");
        driver.accept_private_checks(2).expect("checks");
        assert_eq!(
            driver.accept_private_selection(false),
            Err(OnlineError::GenericBatchFailure)
        );

        let mut driver = StrictSigningPhaseDriver::new();
        driver.accept_consumed_batch(2).expect("consume");
        driver.accept_challenges(2).expect("challenges");
        driver.accept_private_responses(2).expect("responses");
        driver.accept_private_checks(2).expect("checks");
        driver.accept_private_selection(true).expect("selection");
        driver.accept_selected_opening().expect("opening");
        assert_eq!(
            driver.accept_final_verify(false),
            Err(OnlineError::FinalVerifyFailed)
        );

        let mut driver = StrictSigningPhaseDriver::new();
        driver.accept_consumed_batch(2).expect("consume");
        driver.accept_challenges(2).expect("challenges");
        driver.accept_private_responses(2).expect("responses");
        driver.accept_private_checks(2).expect("checks");
        driver.accept_private_selection(true).expect("selection");
        driver.accept_selected_opening().expect("opening");
        driver.accept_final_verify(true).expect("verify");
        assert_eq!(driver.next_phase(), None);
    }

    #[test]
    fn strict_response_check_driver_enforces_inner_circuit_order() {
        let mut driver = StrictResponseCheckPhaseDriver::new();
        assert_eq!(
            driver.accept_shared_responses(2),
            Err(OnlineError::StrictResponseCheckPhaseOutOfOrder)
        );

        driver.accept_metadata(2).expect("metadata");
        assert_eq!(
            driver.accept_hint_checks(2),
            Err(OnlineError::StrictResponseCheckPhaseOutOfOrder)
        );
        assert_eq!(
            driver.accept_shared_responses(1),
            Err(OnlineError::StrictResponseCheckPhaseOutOfOrder)
        );
        driver.accept_shared_responses(2).expect("responses");
        driver.accept_response_bounds(2).expect("bounds");
        driver.accept_hint_checks(2).expect("hints");
        driver.accept_private_pass_bits(2).expect("pass bits");
        assert_eq!(
            driver.accept_priority_selection(false),
            Err(OnlineError::GenericBatchFailure)
        );

        let mut driver = StrictResponseCheckPhaseDriver::new();
        driver.accept_metadata(2).expect("metadata");
        driver.accept_shared_responses(2).expect("responses");
        driver.accept_response_bounds(2).expect("bounds");
        driver.accept_hint_checks(2).expect("hints");
        driver.accept_private_pass_bits(2).expect("pass bits");
        driver.accept_priority_selection(true).expect("selection");
        driver.accept_selected_opening().expect("opening");
        assert_eq!(
            driver.counters().expect("complete counters"),
            StrictResponseCheckCounters {
                candidates: 2,
                private_response_vectors: 2,
                z_bound_checks: 2,
                hint_weight_checks: 2,
                validity_bits: 2,
                selected_openings: 1,
            }
        );
        let evidence = StrictSigningEvidence {
            token_count: 2,
            response_check_counters: driver.counters().expect("complete counters"),
            selected_priority: StrictCandidatePriority([0x66; 32]),
            signature_hash: [0x67; 32],
            transcript_hash: [0x68; 32],
        };
        let shared = talus_performance_counters_from_strict_signing::<MlDsa65>(&evidence);
        assert_eq!(shared.rounds, STRICT_RESPONSE_CHECK_PHASES.len() as u64);
        assert_eq!(shared.token_batch_size, 2);
        assert_eq!(
            shared.opened_lanes,
            (MlDsa65::L + MlDsa65::K) as u64 * MlDsa65::N as u64
        );
        assert_eq!(shared.scalar_operations, 0);
    }

    #[test]
    fn strict_selected_signature_carries_runtime_certificate_on_output() {
        let evidence = StrictSigningEvidence {
            token_count: 2,
            response_check_counters: StrictResponseCheckCounters {
                candidates: 2,
                private_response_vectors: 2,
                z_bound_checks: 2,
                hint_weight_checks: 2,
                validity_bits: 2,
                selected_openings: 1,
            },
            selected_priority: StrictCandidatePriority([0x71; 32]),
            signature_hash: [0x72; 32],
            transcript_hash: [0x73; 32],
        };
        let selected = StrictSelectedSignature {
            signature: FinalSignature {
                bytes: vec![1, 2, 3],
            },
            evidence,
            vector_runtime_certificate: None,
        };
        assert!(selected.vector_runtime_certificate().is_none());

        let certificate =
            StrictSigningVectorRuntimeCertificate::new(release_vector_runtime_evidence())
                .expect("release vector runtime certificate");
        let selected = selected.with_vector_runtime_certificate(certificate.clone());
        assert_eq!(selected.vector_runtime_certificate(), Some(&certificate));
    }

    #[test]
    fn strict_vector_candidate_handle_debug_redacts_rejected_material() {
        let handle = StrictVectorCandidateHandle {
            priority: StrictCandidatePriority([0x81; 32]),
            ctilde: vec![0x82; 32],
            response: PolyVec::zero(MlDsa65::L),
            bound_ok: Some(false),
            hint_ok: Some(false),
            hint: None,
            signature: Some(FinalSignature {
                bytes: vec![0x83; MlDsa65::SIG_LEN],
            }),
        };

        let debug = format!("{handle:?}");
        assert!(debug.contains("priority"));
        for forbidden in [
            "ctilde",
            "response",
            "bound_ok",
            "hint_ok",
            "signature",
            "0x82",
            "0x83",
            "valid",
            "invalid",
            "failure",
            "hint",
        ] {
            assert!(
                !debug.contains(forbidden),
                "candidate debug leaked {forbidden}: {debug}"
            );
        }
    }

    #[test]
    fn strict_runtime_response_preparation_builds_runtime_z_handle() {
        let config = DkgConfig::new::<MlDsa65>(
            2,
            vec![PartyId(1), PartyId(2), PartyId(3)],
            talus_dkg::KeygenEpoch(7),
        )
        .expect("config");
        let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
        let state = talus_dkg::TransportPrimeFieldMpcStateMachine::new(
            config.clone(),
            PartyId(1),
            transport,
        )
        .expect("state machine");
        let party_runtime = talus_dkg::TransportPrimeFieldMpcPartyRuntime::new(
            state,
            talus_dkg::InMemoryPrimeFieldMpcWireMessageLog::default(),
        );
        let runtime = ProductionVectorPrimeFieldMpcRuntime::new(
            talus_dkg::CursoredTransportPrimeFieldMpcPartyRuntime::new(
                party_runtime,
                talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog::default(),
            ),
        );
        let label = Power2RoundTranscriptLabel::root(&config, [0x91; 32])
            .child("strict_signing")
            .child("candidate_0");
        let lane_count = MlDsa65::L * MlDsa65::N;
        let y_share = runtime
            .share_vec_from_local_lanes::<MlDsa65>(&config, &label.child("y"), vec![3; lane_count])
            .expect("y share");
        let s1_share = runtime
            .share_vec_from_local_lanes::<MlDsa65>(&config, &label.child("s1"), vec![1; lane_count])
            .expect("s1 share");
        let ctilde = vec![0x44; MlDsa65::CTILDE_LEN];

        let z_share = strict_prepare_runtime_z_share::<MlDsa65, _, _, _>(
            &runtime,
            &config,
            &y_share,
            &s1_share,
            &ctilde,
            &label.child("response"),
        )
        .expect("runtime z share");
        let candidate = StrictRuntimeCandidateHandle::new_runtime_prepared(
            StrictCandidatePriority([0x92; 32]),
            ctilde,
            z_share,
        );

        assert_eq!(candidate.z_share().len(), lane_count);
        assert_eq!(candidate.ctilde().len(), MlDsa65::CTILDE_LEN);
        let debug = format!("{candidate:?}");
        assert!(debug.contains("z_share"));
        assert!(!debug.contains("lanes"));
        assert!(!debug.contains("ctilde:"));
        assert!(!debug.contains("response"));
    }

    fn strict_test_vector_runtime(
        epoch: u64,
    ) -> (
        DkgConfig,
        ProductionVectorPrimeFieldMpcRuntime<
            talus_wire::InMemoryTransport,
            talus_dkg::InMemoryPrimeFieldMpcWireMessageLog,
            talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog,
        >,
        Power2RoundTranscriptLabel,
    ) {
        let config = DkgConfig::new::<MlDsa65>(
            2,
            vec![PartyId(1), PartyId(2), PartyId(3)],
            talus_dkg::KeygenEpoch(epoch),
        )
        .expect("config");
        let transport = talus_wire::InMemoryTransport::new(1, vec![1, 2, 3]).expect("transport");
        let state = talus_dkg::TransportPrimeFieldMpcStateMachine::new(
            config.clone(),
            PartyId(1),
            transport,
        )
        .expect("state machine");
        let party_runtime = talus_dkg::TransportPrimeFieldMpcPartyRuntime::new(
            state,
            talus_dkg::InMemoryPrimeFieldMpcWireMessageLog::default(),
        );
        let runtime = ProductionVectorPrimeFieldMpcRuntime::new(
            talus_dkg::CursoredTransportPrimeFieldMpcPartyRuntime::new(
                party_runtime,
                talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog::default(),
            ),
        );
        let label = Power2RoundTranscriptLabel::root(&config, [0x93; 32]).child("strict_signing");
        (config, runtime, label)
    }

    #[cfg(feature = "production-release-checks")]
    fn strict_test_vector_runtime_one_party(
        epoch: u64,
    ) -> (
        DkgConfig,
        ProductionVectorPrimeFieldMpcRuntime<
            LatestRoundInMemoryTransport,
            talus_dkg::InMemoryPrimeFieldMpcWireMessageLog,
            talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog,
        >,
        Power2RoundTranscriptLabel,
    ) {
        let config = DkgConfig::new::<MlDsa65>(1, vec![PartyId(1)], talus_dkg::KeygenEpoch(epoch))
            .expect("config");
        let transport = LatestRoundInMemoryTransport::new(1, vec![1]).expect("transport");
        let state = talus_dkg::TransportPrimeFieldMpcStateMachine::new(
            config.clone(),
            PartyId(1),
            transport,
        )
        .expect("state machine");
        let party_runtime = talus_dkg::TransportPrimeFieldMpcPartyRuntime::new(
            state,
            talus_dkg::InMemoryPrimeFieldMpcWireMessageLog::default(),
        );
        let runtime = ProductionVectorPrimeFieldMpcRuntime::new(
            talus_dkg::CursoredTransportPrimeFieldMpcPartyRuntime::new(
                party_runtime,
                talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog::default(),
            ),
        );
        let label = Power2RoundTranscriptLabel::root(&config, [0x44; 32]).child("strict_signing");
        (config, runtime, label)
    }

    #[cfg(feature = "production-release-checks")]
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct LatestRoundInMemoryTransport {
        inner: talus_wire::InMemoryTransport,
    }

    #[cfg(feature = "production-release-checks")]
    impl LatestRoundInMemoryTransport {
        fn new(local_party_id: u16, parties: Vec<u16>) -> Result<Self, talus_wire::TransportError> {
            talus_wire::InMemoryTransport::new(local_party_id, parties).map(|inner| Self { inner })
        }
    }

    #[cfg(feature = "production-release-checks")]
    impl AuthenticatedP2pTransport for LatestRoundInMemoryTransport {
        fn send_private(
            &mut self,
            receiver_party_id: u16,
            message: talus_wire::WireMessage,
        ) -> Result<(), talus_wire::TransportError> {
            self.inner.send_private(receiver_party_id, message)
        }

        fn collect_private_round(
            &self,
            receiver_party_id: u16,
            expected_round: talus_wire::RoundId,
            expected: &talus_wire::ExpectedContext,
        ) -> Result<Vec<talus_wire::WireMessage>, talus_wire::TransportError> {
            let mut latest_by_sender = std::collections::BTreeMap::new();
            for delivery in self.inner.private_messages() {
                if delivery.receiver_party_id != receiver_party_id
                    || delivery.message.header.round != expected_round
                {
                    continue;
                }
                latest_by_sender.insert(
                    delivery.message.header.sender_party_id,
                    delivery.message.clone(),
                );
            }
            let messages = latest_by_sender.into_values().collect::<Vec<_>>();
            talus_wire::validate_round_batch(&messages, expected_round, expected)
                .map_err(talus_wire::TransportError::Wire)?;
            Ok(messages)
        }
    }

    #[cfg(feature = "production-release-checks")]
    impl EquivocationResistantBroadcast for LatestRoundInMemoryTransport {
        fn broadcast(
            &mut self,
            message: talus_wire::WireMessage,
        ) -> Result<(), talus_wire::TransportError> {
            self.inner.broadcast(message)
        }

        fn collect_broadcast_view(
            &self,
            observer_party_id: u16,
            expected_round: talus_wire::RoundId,
            expected: &talus_wire::ExpectedContext,
        ) -> Result<Vec<talus_wire::WireMessage>, talus_wire::TransportError> {
            let mut latest_by_sender = std::collections::BTreeMap::new();
            for delivery in self.inner.broadcast_deliveries() {
                if delivery.observer_party_id != observer_party_id
                    || delivery.message.header.round != expected_round
                {
                    continue;
                }
                latest_by_sender.insert(
                    delivery.message.header.sender_party_id,
                    delivery.message.clone(),
                );
            }
            let messages = latest_by_sender.into_values().collect::<Vec<_>>();
            talus_wire::validate_round_batch(&messages, expected_round, expected)
                .map_err(talus_wire::TransportError::Wire)?;
            Ok(messages)
        }

        fn collect_equivocation_checked_round(
            &self,
            expected_round: talus_wire::RoundId,
            expected: &talus_wire::ExpectedContext,
        ) -> Result<Vec<talus_wire::WireMessage>, talus_wire::TransportError> {
            let mut canonical = Vec::new();
            for observer in &expected.allowed_parties {
                let view = self.collect_broadcast_view(*observer, expected_round, expected)?;
                if view.len() != expected.allowed_parties.len() {
                    return Err(talus_wire::TransportError::IncompleteBroadcastView {
                        observer_party_id: *observer,
                        expected: expected.allowed_parties.len(),
                        got: view.len(),
                    });
                }
                for message in view {
                    let sender = message.header.sender_party_id;
                    match canonical
                        .iter()
                        .position(|known: &talus_wire::WireMessage| {
                            known.header.sender_party_id == sender
                        }) {
                        Some(idx) => {
                            if talus_wire::encode_message(&canonical[idx])
                                .map_err(talus_wire::TransportError::Wire)?
                                != talus_wire::encode_message(&message)
                                    .map_err(talus_wire::TransportError::Wire)?
                            {
                                return Err(talus_wire::TransportError::Equivocation { sender });
                            }
                        }
                        None => canonical.push(message),
                    }
                }
            }
            canonical.sort_by_key(|message| message.header.sender_party_id);
            talus_wire::validate_round_batch(&canonical, expected_round, expected)
                .map_err(talus_wire::TransportError::Wire)?;
            Ok(canonical)
        }
    }

    #[test]
    fn strict_runtime_hint_and_weight_states_are_runtime_owned() {
        let (config, runtime, label) = strict_test_vector_runtime(8);
        let lane_count = MlDsa65::K * MlDsa65::N;
        let r_bits = (0..23)
            .map(|bit| {
                runtime
                    .bit_share_vec_from_local_lanes::<MlDsa65>(
                        &config,
                        &label.child(format!("r_bit_{bit}")),
                        vec![0; lane_count],
                    )
                    .expect("bit share")
            })
            .collect::<Vec<_>>();
        let w1 = vec![0u32; lane_count];

        let hint_state = StrictRuntimeHintBitsCheckState::new::<MlDsa65, _, _, _>(
            &runtime,
            &config,
            &r_bits,
            &w1,
            &label.child("hint_bits"),
        )
        .expect("hint state");
        assert!(hint_state.hint_bits().is_none());

        let h_bits = runtime
            .bit_share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child("h_bits"),
                vec![0; lane_count],
            )
            .expect("h bits");
        let weight_state = StrictRuntimeHintWeightCheckState::new::<MlDsa65, _, _, _>(
            &runtime,
            &config,
            &h_bits,
            &label.child("hint_weight"),
        )
        .expect("hint weight state");
        assert!(weight_state.result().is_none());

        let all_bits_state = StrictRuntimeAllBitsTrueState::new::<MlDsa65, _, _, _>(
            &runtime,
            &config,
            &h_bits,
            &label.child("all_hint_bits_true"),
        )
        .expect("all bits state");
        assert!(all_bits_state.result().is_none());
    }

    #[test]
    fn strict_runtime_hint_approx_and_selection_handles_do_not_prebuild_signature() {
        let (config, mut runtime, label) = strict_test_vector_runtime(9);
        let z_lane_count = MlDsa65::L * MlDsa65::N;
        let z_share = runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child("z"),
                vec![0; z_lane_count],
            )
            .expect("z share");
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let ctilde = vec![0x24; MlDsa65::CTILDE_LEN];
        let approx = strict_runtime_hint_approx_share::<MlDsa65, _, _, _>(
            &runtime,
            &config,
            &public_key,
            &ctilde,
            &z_share,
            &label.child("hint_approx"),
        )
        .expect("hint approx");
        assert_eq!(approx.len(), MlDsa65::K * MlDsa65::N);

        let selected = runtime
            .bit_share_vec_from_local_lanes::<MlDsa65>(&config, &label.child("selected"), vec![1])
            .expect("selected bit");
        let selected_bits = vec![selected];
        let values = vec![z_share.clone()];
        let mut entropy = TestProductionVectorEntropy::default();
        strict_drive_selected_share_products::<MlDsa65, _, _, _, _>(
            &mut runtime,
            &config,
            &selected_bits,
            &values,
            &label.child("selected_z"),
            &mut entropy,
        )
        .expect("drive selected product");

        let candidate = StrictRuntimeCandidateHandle::new_runtime_prepared(
            StrictCandidatePriority([0x94; 32]),
            ctilde,
            z_share,
        );
        let debug = format!("{candidate:?}");
        assert!(!debug.contains("signature"));
        assert!(!debug.contains("response"));
        assert!(!debug.contains("lanes"));
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_selected_public_metadata_uses_private_selected_bit_not_min_priority() {
        let (config, mut runtime, label) = strict_test_vector_runtime_one_party(91);
        let selected_bits = vec![
            runtime
                .bit_share_vec_from_local_lanes::<MlDsa65>(
                    &config,
                    &label.child("selected_0"),
                    vec![0],
                )
                .expect("unselected bit"),
            runtime
                .bit_share_vec_from_local_lanes::<MlDsa65>(
                    &config,
                    &label.child("selected_1"),
                    vec![1],
                )
                .expect("selected bit"),
        ];
        let public_priorities = vec![vec![1u8; 32], vec![2u8; 32]];
        let priority_share = strict_selected_public_lanes_share::<MlDsa65, _, _, _>(
            &runtime,
            &config,
            &selected_bits,
            &public_priorities,
            &label.child("selected_priority"),
        )
        .expect("selected priority share");
        runtime
            .drive_open_share_vec::<MlDsa65>(
                &config,
                &priority_share,
                &label.child("selected_priority/open"),
            )
            .expect("drive priority open");
        let opened_priority = strict_collected_value(
            runtime
                .collect_open_share_vec::<MlDsa65>(&config, &label.child("selected_priority/open"))
                .expect("collect priority open"),
        )
        .expect("opened priority");

        assert_eq!(
            strict_u8_lanes_from_opening(&opened_priority).expect("priority bytes"),
            vec![2u8; 32],
            "selected public metadata must follow the private one-hot bit, not the lowest public priority"
        );
    }

    #[test]
    fn strict_selected_output_builder_encodes_only_selected_material() {
        let request = strict_request();
        let selected_priority = StrictCandidatePriority([0x95; 32]);
        let ctilde = vec![0x25; MlDsa65::CTILDE_LEN];
        let z = PolyVec::zero(MlDsa65::L);
        let h = PolyVec::zero(MlDsa65::K);

        let selected = strict_build_selected_signature_output::<MlDsa65>(
            &request,
            3,
            selected_priority,
            &ctilde,
            &z,
            &h,
        )
        .expect("selected signature output");

        assert_eq!(selected.evidence.token_count, 3);
        assert_eq!(selected.evidence.selected_priority, selected_priority);
        selected
            .evidence
            .response_check_counters
            .validate_for_batch(3)
            .expect("coarse counters");
        assert!(selected.vector_runtime_certificate().is_none());
        assert_eq!(&selected.signature.bytes[..MlDsa65::CTILDE_LEN], &ctilde);
        let debug = format!("{selected:?}");
        assert!(!debug.contains("valid_j"));
        assert!(!debug.contains("failure"));
        assert!(!debug.contains("unselected"));
    }

    fn strict_selected_opening_artifact_for_test(
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: &ConsumedBccCertifiedTokenBatch,
        selected_index: usize,
    ) -> StrictRuntimeSelectedOpeningArtifact {
        let metadata = strict_candidate_metadata_batch::<MlDsa65>(request, batch, tr);
        let selected = metadata
            .get(selected_index)
            .expect("selected test metadata exists");
        StrictRuntimeSelectedOpeningArtifact::new(
            strict_signing_request_hash(request),
            batch.session_ids_for_test(),
            selected.priority,
            selected.ctilde.clone(),
            PolyVec::zero(MlDsa65::L),
            PolyVec::zero(MlDsa65::K),
            StrictSigningVectorRuntimeCertificate::new(release_vector_runtime_evidence())
                .expect("strict signing runtime certificate"),
        )
    }

    #[cfg(feature = "production-release-checks")]
    fn strict_selected_opening_artifact_from_batch_for_test(
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: &BccCertifiedTokenBatch,
        selected_index: usize,
    ) -> StrictRuntimeSelectedOpeningArtifact {
        let metadata = batch
            .tokens
            .iter()
            .map(|token| strict_candidate_metadata::<MlDsa65>(request, token, tr))
            .collect::<Vec<_>>();
        let selected = metadata
            .get(selected_index)
            .expect("selected test metadata exists");
        StrictRuntimeSelectedOpeningArtifact::new(
            strict_signing_request_hash(request),
            batch.session_ids(),
            selected.priority,
            selected.ctilde.clone(),
            PolyVec::zero(MlDsa65::L),
            PolyVec::zero(MlDsa65::K),
            StrictSigningVectorRuntimeCertificate::new(release_vector_runtime_evidence())
                .expect("strict signing runtime certificate"),
        )
    }

    #[cfg(feature = "production-release-checks")]
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct FixedSelectedOpeningArtifactSource {
        artifact: Option<StrictRuntimeSelectedOpeningArtifact>,
    }

    #[cfg(feature = "production-release-checks")]
    impl FixedSelectedOpeningArtifactSource {
        fn new(artifact: StrictRuntimeSelectedOpeningArtifact) -> Self {
            Self {
                artifact: Some(artifact),
            }
        }
    }

    #[cfg(feature = "production-release-checks")]
    impl StrictRuntimeSelectedOpeningArtifactSource<MlDsa65> for FixedSelectedOpeningArtifactSource {
        fn produce_selected_opening_artifact(
            &mut self,
            _request: &StrictSignRequest,
            _tr: &[u8; 64],
            _batch: &ConsumedBccCertifiedTokenBatch,
        ) -> Result<StrictRuntimeSelectedOpeningArtifact, OnlineError> {
            self.artifact
                .take()
                .ok_or(OnlineError::StrictSigningSessionAlreadyFinished)
        }
    }

    #[test]
    fn strict_runtime_selected_opening_backend_accepts_bound_artifact_only() {
        let request = strict_request();
        let tr = [0x96; 64];
        let first = token(96, &[1, 2]);
        let second = token(97, &[1, 2]);
        let consumed_batch = ConsumedBccCertifiedTokenBatch {
            signer_set: first.signer_set.clone(),
            tokens: vec![first, second],
        };
        let artifact = strict_selected_opening_artifact_for_test(&request, &tr, &consumed_batch, 1);
        let mut backend = ProductionStrictRuntimeSelectedOpeningBackend::new(artifact.clone());

        let selected = StrictPrivateSigningBackend::<MlDsa65>::sign_consumed_batch(
            &mut backend,
            &request,
            &tr,
            consumed_batch,
        )
        .expect("selected opening artifact signs");

        assert_eq!(selected.evidence.token_count, 2);
        assert_eq!(
            selected.evidence.selected_priority,
            artifact.selected_priority
        );
        assert_eq!(
            &selected.signature.bytes[..MlDsa65::CTILDE_LEN],
            artifact.selected_ctilde.as_slice()
        );
        let certificate = selected
            .vector_runtime_certificate()
            .expect("selected opening artifact carries runtime certificate");
        assert!(
            certificate
                .runtime_evidence()
                .coverage
                .private_one_hot_selection
        );
        assert_eq!(
            StrictPrivateSigningBackend::<MlDsa65>::sign_consumed_batch(
                &mut backend,
                &request,
                &tr,
                ConsumedBccCertifiedTokenBatch {
                    signer_set: vec![PartyId(1), PartyId(2)],
                    tokens: vec![token(98, &[1, 2]), token(99, &[1, 2])],
                },
            ),
            Err(OnlineError::StrictSigningSessionAlreadyFinished)
        );
    }

    #[test]
    fn strict_runtime_selected_opening_backend_rejects_unbound_artifacts() {
        let request = strict_request();
        let tr = [0x97; 64];
        let consumed_batch = ConsumedBccCertifiedTokenBatch {
            signer_set: vec![PartyId(1), PartyId(2)],
            tokens: vec![token(101, &[1, 2]), token(102, &[1, 2])],
        };

        let mut wrong_request =
            strict_selected_opening_artifact_for_test(&request, &tr, &consumed_batch, 0);
        wrong_request.request_hash = [0xAA; 32];
        let mut backend = ProductionStrictRuntimeSelectedOpeningBackend::new(wrong_request);
        assert_eq!(
            StrictPrivateSigningBackend::<MlDsa65>::sign_consumed_batch(
                &mut backend,
                &request,
                &tr,
                ConsumedBccCertifiedTokenBatch {
                    signer_set: vec![PartyId(1), PartyId(2)],
                    tokens: vec![token(101, &[1, 2]), token(102, &[1, 2])],
                },
            ),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        );

        let mut wrong_tokens =
            strict_selected_opening_artifact_for_test(&request, &tr, &consumed_batch, 0);
        wrong_tokens.token_session_ids.reverse();
        let mut backend = ProductionStrictRuntimeSelectedOpeningBackend::new(wrong_tokens);
        assert_eq!(
            StrictPrivateSigningBackend::<MlDsa65>::sign_consumed_batch(
                &mut backend,
                &request,
                &tr,
                ConsumedBccCertifiedTokenBatch {
                    signer_set: vec![PartyId(1), PartyId(2)],
                    tokens: vec![token(101, &[1, 2]), token(102, &[1, 2])],
                },
            ),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        );

        let mut wrong_ctilde =
            strict_selected_opening_artifact_for_test(&request, &tr, &consumed_batch, 0);
        wrong_ctilde.selected_ctilde[0] ^= 1;
        let mut backend = ProductionStrictRuntimeSelectedOpeningBackend::new(wrong_ctilde);
        assert_eq!(
            StrictPrivateSigningBackend::<MlDsa65>::sign_consumed_batch(
                &mut backend,
                &request,
                &tr,
                ConsumedBccCertifiedTokenBatch {
                    signer_set: vec![PartyId(1), PartyId(2)],
                    tokens: vec![token(101, &[1, 2]), token(102, &[1, 2])],
                },
            ),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        );
    }

    #[test]
    fn strict_runtime_selected_opening_artifact_debug_redacts_selected_material() {
        let request = strict_request();
        let tr = [0x98; 64];
        let first = token(103, &[1, 2]);
        let second = token(104, &[1, 2]);
        let consumed_batch = ConsumedBccCertifiedTokenBatch {
            signer_set: first.signer_set.clone(),
            tokens: vec![first, second],
        };
        let artifact = strict_selected_opening_artifact_for_test(&request, &tr, &consumed_batch, 0);

        let debug = format!("{artifact:?}");
        assert!(debug.contains("selected_ctilde_len"));
        assert!(debug.contains("<opened-selected-redacted>"));
        assert!(!debug.contains("selected_z: PolyVec"));
        assert!(!debug.contains("selected_h: PolyVec"));
        assert!(!debug.contains("valid_j"));
        assert!(!debug.contains("unselected"));
        assert!(!debug.contains("failure"));
    }
}
