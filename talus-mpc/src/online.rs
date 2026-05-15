#![doc = "Online TALUS-MPC signing state-machine shell."]

use core::{fmt, marker::PhantomData};

#[cfg(feature = "std")]
use crate::local::FilePreprocessingReleaseTokenBatchLog;
use crate::local::{
    ensure_certified_token_release_valid, CertifiedToken, SessionId, TokenPoolError, TranscriptHash,
};
#[cfg(test)]
use crate::local::{
    ensure_preprocessing_release_token_batch_log_for_release, PreprocessingReleaseTokenLogEntry,
};
use sha3::{Digest, Sha3_256};
use std::time::Instant;
use talus_core::{
    az_from_rho, compute_ctilde, compute_mu, compute_talus_hint_polyvec,
    lagrange_coefficients_at_zero, mul_challenge_polyvec, public_approx_from_az, public_key_decode,
    sample_in_ball, signature_encode, w1_encode, z_bound_holds, Fips204Verifier, HintError,
    MlDsaParams, NttError, Poly, PolyError, PolyVec, ProductionBatchSizingPolicy,
    PublicKeyDecodeError, SignatureEncodingError, StrictTokenBatchSizingDecision,
    TalusPerformanceCounters, TokenPassProbabilityEstimate, VerifyError,
};
use talus_dkg::{
    ensure_production_strict_signing_runtime_evidence_for_release,
    ensure_production_vector_it_mpc_runtime_evidence_for_release, As1SecretVectorShare,
    BoundedSecretVectorShare, DkgConfig, DkgError, DkgKeyPackage, DkgSecretShare,
    Power2RoundTranscriptLabel, PrimeFieldMpcCounters, PrimeFieldMpcPhaseCursorLog,
    PrimeFieldMpcPhaseDriverStatus, PrimeFieldMpcWireMessageLog, ProductionBitShareVec,
    ProductionBitSumLeqPublicVecState, ProductionCanonicalBitDecompositionState,
    ProductionPublicComparisonVecState, ProductionShareVec, ProductionVectorItMpcCollectResult,
    ProductionVectorItMpcEntropy, ProductionVectorItMpcRuntimeEvidence,
    ProductionVectorPrimeFieldMpcRuntime,
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
    /// Returns the empirical strict-signing batch-sizing decision for a suite.
    pub fn sizing_decision_for_suite<P: MlDsaParams>(
        estimate: TokenPassProbabilityEstimate,
        target_no_valid_probability: f64,
    ) -> Option<StrictTokenBatchSizingDecision> {
        ProductionBatchSizingPolicy::for_suite::<P>()
            .strict_token_batch_sizing(estimate, target_no_valid_probability)
    }

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

    /// Creates a strict batch using an empirical pass-probability sizing
    /// decision for the selected suite and no-valid risk target.
    pub fn new_with_empirical_sizing<P: MlDsaParams>(
        tokens: Vec<CertifiedToken>,
        estimate: TokenPassProbabilityEstimate,
        target_no_valid_probability: f64,
    ) -> Result<(Self, StrictTokenBatchSizingDecision), OnlineError> {
        let decision = Self::sizing_decision_for_suite::<P>(estimate, target_no_valid_probability)
            .ok_or(OnlineError::TokenBatchSizingUnavailable)?;
        let batch = Self::new(tokens, decision.recommended_batch_size)?;
        Ok((batch, decision))
    }

    /// Internal lower-level release-token validator.
    ///
    /// Normal release admission must use
    /// `new_release_validated_with_log`, which replays the typed durable
    /// preprocessing token-batch log before constructing the batch. This
    /// helper remains crate-internal for negative tests and for the logged
    /// constructor after log replay has already succeeded.
    pub(crate) fn new_release_validated(
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

    /// Internal release batch constructor after typed public log replay.
    ///
    /// Public release setup must use `new_release_validated_with_file_log` so
    /// the token-batch log is replayed from durable storage. This in-memory
    /// variant remains crate-internal for tests and for callers that have
    /// already loaded a file-backed typed log.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_release_validated_with_log(
        tokens: Vec<CertifiedToken>,
        min_batch_size: usize,
        entries: &[PreprocessingReleaseTokenLogEntry],
    ) -> Result<Self, OnlineError> {
        ensure_preprocessing_release_token_batch_log_for_release(&tokens, entries)
            .map_err(|_| OnlineError::TokenPool(TokenPoolError::ReleaseLogMismatch))?;
        Self::new_release_validated(tokens, min_batch_size)
    }

    /// Creates a release-capable strict batch after replaying a file-backed
    /// typed public preprocessing token-batch log.
    #[cfg(feature = "std")]
    pub fn new_release_validated_with_file_log(
        tokens: Vec<CertifiedToken>,
        min_batch_size: usize,
        log: &FilePreprocessingReleaseTokenBatchLog,
    ) -> Result<Self, OnlineError> {
        log.replay_for_release(&tokens)
            .map_err(OnlineError::TokenPool)?;
        Self::new_release_validated(tokens, min_batch_size)
    }

    /// Creates a release-capable strict batch from a file-backed token log
    /// using empirical pass-probability sizing.
    #[cfg(feature = "std")]
    pub fn new_release_validated_with_file_log_and_empirical_sizing<P: MlDsaParams>(
        tokens: Vec<CertifiedToken>,
        log: &FilePreprocessingReleaseTokenBatchLog,
        estimate: TokenPassProbabilityEstimate,
        target_no_valid_probability: f64,
    ) -> Result<(Self, StrictTokenBatchSizingDecision), OnlineError> {
        let decision = Self::sizing_decision_for_suite::<P>(estimate, target_no_valid_probability)
            .ok_or(OnlineError::TokenBatchSizingUnavailable)?;
        let batch = Self::new_release_validated_with_file_log(
            tokens,
            decision.recommended_batch_size,
            log,
        )?;
        Ok((batch, decision))
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

/// Public one-time-use id for strict-signing canonical-mask inventory.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StrictSigningMaskInventoryId {
    /// Token/session that owns this mask inventory.
    pub session_id: SessionId,
    /// Hash binding the token-owned mask provenance and handle ids.
    pub inventory_hash: [u8; 32],
}

impl StrictSigningMaskInventoryId {
    /// Builds the strict mask inventory id for a release-certified token.
    pub fn for_token(token: &CertifiedToken) -> Result<Self, OnlineError> {
        let masks = token
            .strict_signing_masks()
            .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?;
        let provenance = masks
            .provenance()
            .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?;
        if provenance.session_id != token.session_id
            || provenance.transcript_hash != token.transcript_hash
            || provenance.hint_lane_count != token.w1.len()
        {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS strict signing mask inventory id v1");
        hasher.update(token.session_id.0);
        hasher.update(token.transcript_hash.0);
        hasher.update(provenance.runtime_transcript_hash);
        hasher.update(provenance.z_mask_value_label_hash);
        hasher.update(provenance.hint_mask_value_label_hash);
        hasher.update((provenance.z_lane_count as u64).to_le_bytes());
        hasher.update((provenance.hint_lane_count as u64).to_le_bytes());
        hasher.update((token.w1.len() as u64).to_le_bytes());
        Ok(Self {
            session_id: token.session_id,
            inventory_hash: hasher.finalize().into(),
        })
    }
}

/// Durable one-time-use contract for strict signing mask inventories.
pub trait StrictSigningMaskUseLog {
    /// Persists mask inventory consumption.
    fn mark_mask_consumed(&mut self, id: StrictSigningMaskInventoryId) -> Result<(), OnlineError>;

    /// Returns whether a mask inventory has already been consumed.
    fn is_mask_consumed(&self, id: StrictSigningMaskInventoryId) -> bool;
}

/// In-memory strict mask-use log for tests/local sessions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryStrictSigningMaskUseLog {
    consumed: Vec<StrictSigningMaskInventoryId>,
}

impl InMemoryStrictSigningMaskUseLog {
    /// Returns consumed strict mask inventory ids.
    pub fn consumed(&self) -> &[StrictSigningMaskInventoryId] {
        &self.consumed
    }
}

impl StrictSigningMaskUseLog for InMemoryStrictSigningMaskUseLog {
    fn mark_mask_consumed(&mut self, id: StrictSigningMaskInventoryId) -> Result<(), OnlineError> {
        if self.consumed.contains(&id) {
            return Err(OnlineError::StrictSigningMaskAlreadyConsumed(id));
        }
        self.consumed.push(id);
        Ok(())
    }

    fn is_mask_consumed(&self, id: StrictSigningMaskInventoryId) -> bool {
        self.consumed.contains(&id)
    }
}

/// File-backed strict mask-use log.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileStrictSigningMaskUseLog {
    path: std::path::PathBuf,
    inner: InMemoryStrictSigningMaskUseLog,
}

#[cfg(feature = "std")]
impl FileStrictSigningMaskUseLog {
    /// Opens or creates a file-backed strict mask-use log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, OnlineError> {
        let path = path.into();
        let mut inner = InMemoryStrictSigningMaskUseLog::default();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let id = parse_strict_signing_mask_use_log_line(line).ok_or(
                        OnlineError::StrictSigningMaskUseLogCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    inner.mark_mask_consumed(id)?;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| OnlineError::StrictSigningMaskUseLogIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| OnlineError::StrictSigningMaskUseLogIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(OnlineError::StrictSigningMaskUseLogIo { operation: "read" });
            }
        }
        Ok(Self { path, inner })
    }

    /// Returns consumed strict mask inventory ids.
    pub fn consumed(&self) -> &[StrictSigningMaskInventoryId] {
        self.inner.consumed()
    }
}

#[cfg(feature = "std")]
impl StrictSigningMaskUseLog for FileStrictSigningMaskUseLog {
    fn mark_mask_consumed(&mut self, id: StrictSigningMaskInventoryId) -> Result<(), OnlineError> {
        self.inner.mark_mask_consumed(id)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| OnlineError::StrictSigningMaskUseLogIo { operation: "open" })?;
        use std::io::Write;
        writeln!(
            file,
            "{} {}",
            hex32(id.session_id.0),
            hex32(id.inventory_hash)
        )
        .map_err(|_| OnlineError::StrictSigningMaskUseLogIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| OnlineError::StrictSigningMaskUseLogIo { operation: "sync" })?;
        Ok(())
    }

    fn is_mask_consumed(&self, id: StrictSigningMaskInventoryId) -> bool {
        self.inner.is_mask_consumed(id)
    }
}

#[cfg(feature = "std")]
fn parse_strict_signing_mask_use_log_line(line: &str) -> Option<StrictSigningMaskInventoryId> {
    let mut fields = line.split_whitespace();
    let session_id = parse_session_id_hex(fields.next()?)?;
    let inventory_hash = parse_hex32(fields.next()?)?;
    if fields.next().is_some() {
        return None;
    }
    Some(StrictSigningMaskInventoryId {
        session_id,
        inventory_hash,
    })
}

/// Marks every strict mask inventory in `batch` consumed before private
/// response work starts.
pub fn consume_strict_signing_masks_for_batch(
    batch: &BccCertifiedTokenBatch,
    log: &mut impl StrictSigningMaskUseLog,
) -> Result<Vec<StrictSigningMaskInventoryId>, OnlineError> {
    let mut ids = Vec::with_capacity(batch.tokens.len());
    for token in &batch.tokens {
        let id = StrictSigningMaskInventoryId::for_token(token)?;
        log.mark_mask_consumed(id)?;
        ids.push(id);
    }
    Ok(ids)
}

/// Strict signing helper class that must be consumed exactly once.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StrictSigningHelperKind {
    /// Comparison helper material.
    Comparison,
    /// Threshold-check helper material.
    Threshold,
    /// Selected-opening multiplication helper material.
    SelectedOpening,
}

/// Public one-time-use id for strict signing helper inventories.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StrictSigningHelperInventoryId {
    /// Token/session that owns this helper material.
    pub session_id: SessionId,
    /// Helper class.
    pub kind: StrictSigningHelperKind,
    /// Hash binding helper provenance.
    pub inventory_hash: [u8; 32],
}

impl StrictSigningHelperInventoryId {
    /// Builds helper inventory ids for one release-certified token.
    pub fn for_token(token: &CertifiedToken) -> Result<[Self; 3], OnlineError> {
        let helpers = token
            .strict_signing_helpers()
            .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?;
        let provenance = helpers.provenance();
        if provenance.session_id != token.session_id
            || provenance.transcript_hash != token.transcript_hash
            || provenance.hint_lane_count != token.w1.len()
            || provenance.runtime_transcript_hash == [0u8; 32]
        {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        Ok([
            Self {
                session_id: token.session_id,
                kind: StrictSigningHelperKind::Comparison,
                inventory_hash: provenance.comparison_helper_hash,
            },
            Self {
                session_id: token.session_id,
                kind: StrictSigningHelperKind::Threshold,
                inventory_hash: provenance.threshold_helper_hash,
            },
            Self {
                session_id: token.session_id,
                kind: StrictSigningHelperKind::SelectedOpening,
                inventory_hash: provenance.selected_opening_helper_hash,
            },
        ])
    }
}

/// Durable one-time-use contract for strict signing helper inventories.
pub trait StrictSigningHelperUseLog {
    /// Persists helper inventory consumption.
    fn mark_helper_consumed(
        &mut self,
        id: StrictSigningHelperInventoryId,
    ) -> Result<(), OnlineError>;

    /// Returns whether helper inventory has already been consumed.
    fn is_helper_consumed(&self, id: StrictSigningHelperInventoryId) -> bool;
}

/// In-memory strict helper-use log for tests/local sessions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryStrictSigningHelperUseLog {
    consumed: Vec<StrictSigningHelperInventoryId>,
}

impl InMemoryStrictSigningHelperUseLog {
    /// Returns consumed strict helper inventory ids.
    pub fn consumed(&self) -> &[StrictSigningHelperInventoryId] {
        &self.consumed
    }
}

impl StrictSigningHelperUseLog for InMemoryStrictSigningHelperUseLog {
    fn mark_helper_consumed(
        &mut self,
        id: StrictSigningHelperInventoryId,
    ) -> Result<(), OnlineError> {
        if self.consumed.contains(&id) {
            return Err(OnlineError::StrictSigningHelperAlreadyConsumed(id));
        }
        self.consumed.push(id);
        Ok(())
    }

    fn is_helper_consumed(&self, id: StrictSigningHelperInventoryId) -> bool {
        self.consumed.contains(&id)
    }
}

/// File-backed strict helper-use log.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileStrictSigningHelperUseLog {
    path: std::path::PathBuf,
    inner: InMemoryStrictSigningHelperUseLog,
}

#[cfg(feature = "std")]
impl FileStrictSigningHelperUseLog {
    /// Opens or creates a file-backed strict helper-use log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, OnlineError> {
        let path = path.into();
        let mut inner = InMemoryStrictSigningHelperUseLog::default();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let id = parse_strict_signing_helper_use_log_line(line).ok_or(
                        OnlineError::StrictSigningHelperUseLogCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    inner.mark_helper_consumed(id)?;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| OnlineError::StrictSigningHelperUseLogIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| OnlineError::StrictSigningHelperUseLogIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(OnlineError::StrictSigningHelperUseLogIo { operation: "read" });
            }
        }
        Ok(Self { path, inner })
    }

    /// Returns consumed strict helper inventory ids.
    pub fn consumed(&self) -> &[StrictSigningHelperInventoryId] {
        self.inner.consumed()
    }
}

#[cfg(feature = "std")]
impl StrictSigningHelperUseLog for FileStrictSigningHelperUseLog {
    fn mark_helper_consumed(
        &mut self,
        id: StrictSigningHelperInventoryId,
    ) -> Result<(), OnlineError> {
        self.inner.mark_helper_consumed(id)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| OnlineError::StrictSigningHelperUseLogIo { operation: "open" })?;
        use std::io::Write;
        writeln!(
            file,
            "{} {} {}",
            hex32(id.session_id.0),
            strict_signing_helper_kind_name(id.kind),
            hex32(id.inventory_hash)
        )
        .map_err(|_| OnlineError::StrictSigningHelperUseLogIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| OnlineError::StrictSigningHelperUseLogIo { operation: "sync" })?;
        Ok(())
    }

    fn is_helper_consumed(&self, id: StrictSigningHelperInventoryId) -> bool {
        self.inner.is_helper_consumed(id)
    }
}

fn strict_signing_helper_kind_name(kind: StrictSigningHelperKind) -> &'static str {
    match kind {
        StrictSigningHelperKind::Comparison => "comparison",
        StrictSigningHelperKind::Threshold => "threshold",
        StrictSigningHelperKind::SelectedOpening => "selected-opening",
    }
}

#[cfg(feature = "std")]
fn parse_strict_signing_helper_use_log_line(line: &str) -> Option<StrictSigningHelperInventoryId> {
    let mut fields = line.split_whitespace();
    let session_id = parse_session_id_hex(fields.next()?)?;
    let kind = match fields.next()? {
        "comparison" => StrictSigningHelperKind::Comparison,
        "threshold" => StrictSigningHelperKind::Threshold,
        "selected-opening" => StrictSigningHelperKind::SelectedOpening,
        _ => return None,
    };
    let inventory_hash = parse_hex32(fields.next()?)?;
    if fields.next().is_some() {
        return None;
    }
    Some(StrictSigningHelperInventoryId {
        session_id,
        kind,
        inventory_hash,
    })
}

/// Marks every strict helper inventory consumed before private online response
/// checks and selected-opening products start.
pub fn consume_strict_signing_helpers_for_batch(
    batch: &BccCertifiedTokenBatch,
    log: &mut impl StrictSigningHelperUseLog,
) -> Result<Vec<StrictSigningHelperInventoryId>, OnlineError> {
    let mut ids = Vec::with_capacity(batch.tokens.len() * 3);
    for token in &batch.tokens {
        for id in StrictSigningHelperInventoryId::for_token(token)? {
            log.mark_helper_consumed(id)?;
            ids.push(id);
        }
    }
    Ok(ids)
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
    /// Starts one release-capable strict signing session from tokens whose
    /// typed durable token-batch log has been replayed from disk.
    #[cfg(feature = "std")]
    pub fn start_release_validated_with_file_log(
        request: StrictSignRequest,
        tr: [u8; 64],
        tokens: Vec<CertifiedToken>,
        min_batch_size: usize,
        token_log: &FilePreprocessingReleaseTokenBatchLog,
        consumed: Store,
        backend: ProductionStrictRuntimeSelectedOpeningArtifactBackend<Source>,
        verifier: V,
    ) -> Result<Self, OnlineError> {
        let batch = BccCertifiedTokenBatch::new_release_validated_with_file_log(
            tokens,
            min_batch_size,
            token_log,
        )?;
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
        let mut mask_use_log = InMemoryStrictSigningMaskUseLog::default();
        let mut helper_use_log = InMemoryStrictSigningHelperUseLog::default();
        self.finish_with_helper_use_logs(&mut mask_use_log, &mut helper_use_log)
    }

    /// Finishes strict signing with an explicit durable strict-mask use log.
    ///
    /// Release callers that use file-backed token consumption should pass a
    /// file-backed strict-mask log here as well. Mask inventories are persisted
    /// consumed immediately after token consumption and before private response
    /// runtime work starts.
    pub fn finish_with_mask_use_log(
        &mut self,
        mask_use_log: &mut impl StrictSigningMaskUseLog,
    ) -> Result<FinalSignature, OnlineError> {
        let mut helper_use_log = InMemoryStrictSigningHelperUseLog::default();
        self.finish_with_helper_use_logs(mask_use_log, &mut helper_use_log)
    }

    /// Finishes strict signing with explicit durable strict-helper use logs.
    ///
    /// Release callers should pass file-backed logs for token consumption,
    /// canonical masks, and comparison/threshold helper inventories. Helper
    /// inventories are persisted consumed after tokens and masks but before
    /// private response checks start.
    pub fn finish_with_helper_use_logs(
        &mut self,
        mask_use_log: &mut impl StrictSigningMaskUseLog,
        helper_use_log: &mut impl StrictSigningHelperUseLog,
    ) -> Result<FinalSignature, OnlineError> {
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
        if cfg!(feature = "production-release-checks")
            || batch
                .tokens
                .iter()
                .any(|token| token.strict_signing_masks().is_some())
        {
            if let Err(err) = consume_strict_signing_masks_for_batch(&batch, mask_use_log) {
                self.phase = StrictSigningSessionPhase::Failed;
                self.persist_cursor(StrictSigningCursorPhase::Failed, None, None)?;
                return Err(err);
            }
        }
        if cfg!(feature = "production-release-checks")
            || batch
                .tokens
                .iter()
                .any(|token| token.strict_signing_helpers().is_some())
        {
            if let Err(err) = consume_strict_signing_helpers_for_batch(&batch, helper_use_log) {
                self.phase = StrictSigningSessionPhase::Failed;
                self.persist_cursor(StrictSigningCursorPhase::Failed, None, None)?;
                return Err(err);
            }
        }

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

/// Computes the private verifier approximation share using precomputed
/// `[w] = [A*y]` and `[As1] = [A*s1]`:
///
/// `[r] = [w] + c*[As1] - c*t1*2^d`.
///
/// This keeps the same strict private hint checks but removes the online
/// `A*z` transform from release paths that can provide certified preprocessing
/// and key-state handles.
pub fn strict_runtime_hint_approx_share_from_precomputed<P, T, L, C>(
    runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    public_key: &[u8],
    ctilde: &[u8],
    w_share: &ProductionShareVec,
    as1_share: &ProductionShareVec,
    label: &Power2RoundTranscriptLabel,
) -> Result<ProductionShareVec, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    let decoded = public_key_decode::<P>(public_key)?;
    if w_share.len() != P::K * P::N || as1_share.len() != P::K * P::N {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let c_as1 = runtime
        .mul_public_challenge_polyveck_share_vec::<P>(
            config,
            as1_share,
            ctilde,
            &label.child("c_times_as1"),
        )
        .map_err(OnlineError::from)?;
    let w_plus_c_as1 = runtime
        .add_share_vec::<P>(config, w_share, &c_as1, &label.child("w_plus_c_as1"))
        .map_err(OnlineError::from)?;
    let challenge = sample_in_ball::<P>(ctilde);
    let t1_2d = talus_core::t1_times_2d::<P>(&decoded.t1);
    let ct1 = mul_challenge_polyvec::<P>(&challenge, &t1_2d);
    let ct1_lanes = strict_runtime_polyvec_to_lanes(&ct1);
    let ct1_share = runtime
        .public_lanes_share_vec::<P>(config, &label.child("ct1_2d"), &ct1_lanes)
        .map_err(OnlineError::from)?;
    runtime
        .sub_share_vec::<P>(
            config,
            &w_plus_c_as1,
            &ct1_share,
            &label.child("hint_approx"),
        )
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
    packed_lt_bounds: ProductionPublicComparisonVecState,
    lane_count: usize,
    lt_gamma: Option<ProductionBitShareVec>,
    gt_upper: Option<ProductionBitShareVec>,
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
        let upper_exclusive = upper
            .checked_add(1)
            .filter(|&value| value < P::Q as u32)
            .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?;
        let lane_count = z_bits_by_bit_le[0].len();
        let packed_bits = z_bits_by_bit_le
            .iter()
            .enumerate()
            .map(|(bit_idx, bit)| {
                runtime
                    .pack_bit_share_vecs_for_runtime_batch::<P>(
                        config,
                        &[bit.clone(), bit.clone()],
                        &label.child(format!("packed_z_bit_{bit_idx}")),
                    )
                    .map_err(OnlineError::from)
            })
            .collect::<Result<Vec<_>, OnlineError>>()?;
        let mut constants = Vec::with_capacity(lane_count * 2);
        constants.extend(std::iter::repeat_n(gamma as talus_core::Coeff, lane_count));
        constants.extend(std::iter::repeat_n(
            upper_exclusive as talus_core::Coeff,
            lane_count,
        ));
        Ok(Self {
            packed_lt_bounds: runtime
                .start_lt_public_lanes_vec::<P>(
                    config,
                    &packed_bits,
                    &constants,
                    &label.child("z_packed_lt_bounds"),
                )
                .map_err(OnlineError::from)?,
            lane_count,
            lt_gamma: None,
            gt_upper: None,
            pending_or: false,
            ok: None,
        })
    }

    /// Returns the private z-bound result once available.
    pub fn result(&self) -> Option<&ProductionBitShareVec> {
        self.ok.as_ref()
    }

    /// Drives one multiplication layer of the packed lower/upper comparison.
    pub fn drive_packed_bounds_step<P, T, L, C, E>(
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
            .drive_public_comparison_vec_step::<P, E>(config, &mut self.packed_lt_bounds, entropy)
            .map_err(OnlineError::from)
    }

    /// Collects one multiplication layer of the packed lower/upper comparison.
    pub fn collect_packed_bounds_step<P, T, L, C>(
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
        match runtime
            .collect_public_comparison_vec_step::<P>(config, &mut self.packed_lt_bounds)
            .map_err(OnlineError::from)?
        {
            ProductionVectorItMpcCollectResult::Waiting(status) => {
                Ok(ProductionVectorItMpcCollectResult::Waiting(status))
            }
            ProductionVectorItMpcCollectResult::Collected { status, value } => {
                if self.packed_lt_bounds.is_done() && self.lt_gamma.is_none() {
                    let packed = self
                        .packed_lt_bounds
                        .result()
                        .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
                    let chunks = runtime
                        .unpack_bit_share_vec_runtime_batch::<P>(
                            config,
                            packed,
                            self.lane_count,
                            &self.packed_lt_bounds.label().child("z_bound_chunks"),
                        )
                        .map_err(OnlineError::from)?;
                    if chunks.len() != 2 {
                        return Err(OnlineError::StrictResponseCheckShapeMismatch);
                    }
                    self.lt_gamma = Some(chunks[0].clone());
                    self.gt_upper = Some(
                        runtime
                            .bit_not_vec::<P>(
                                config,
                                &chunks[1],
                                &self.packed_lt_bounds.label().child("z_gt_q_minus_gamma"),
                            )
                            .map_err(OnlineError::from)?,
                    );
                }
                Ok(ProductionVectorItMpcCollectResult::Collected { status, value })
            }
        }
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
            .as_ref()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let gt = self
            .gt_upper
            .as_ref()
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
            .as_ref()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let gt = self
            .gt_upper
            .as_ref()
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

#[cfg(test)]
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
    strict_highbits_interval_constants_for_lanes::<P>(w1)
}

fn strict_highbits_interval_constants_for_lanes<P: MlDsaParams>(
    w1: &[u32],
) -> Result<
    (
        Vec<talus_core::Coeff>,
        Vec<talus_core::Coeff>,
        Vec<talus_core::Coeff>,
    ),
    OnlineError,
> {
    let high_mod = ((P::Q - 1) / (2 * P::GAMMA2)) as u32;
    let alpha = 2 * P::GAMMA2;
    let mut lower = Vec::with_capacity(w1.len());
    let mut upper_exclusive = Vec::with_capacity(w1.len());
    let mut wraps_zero = Vec::with_capacity(w1.len());
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
    packed_lt_bounds: ProductionPublicComparisonVecState,
    lane_count: usize,
    gt_lower: Option<ProductionBitShareVec>,
    lt_upper: Option<ProductionBitShareVec>,
    wraps_zero: Vec<talus_core::Coeff>,
    pending_and: bool,
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
        let (lower, upper_exclusive, wraps_zero) =
            strict_highbits_interval_constants_for_lanes::<P>(w1)?;
        let lane_count = r_bits_by_bit_le[0].len();
        if lower.len() != lane_count || upper_exclusive.len() != lane_count {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let packed_bits = r_bits_by_bit_le
            .iter()
            .enumerate()
            .map(|(bit_idx, bit)| {
                runtime
                    .pack_bit_share_vecs_for_runtime_batch::<P>(
                        config,
                        &[bit.clone(), bit.clone()],
                        &label.child(format!("packed_r_bit_{bit_idx}")),
                    )
                    .map_err(OnlineError::from)
            })
            .collect::<Result<Vec<_>, OnlineError>>()?;
        let mut constants = Vec::with_capacity(lane_count * 2);
        for value in lower.iter() {
            constants.push(
                value
                    .checked_add(1)
                    .filter(|&bound| bound < P::Q)
                    .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?,
            );
        }
        constants.extend_from_slice(&upper_exclusive);
        Ok(Self {
            packed_lt_bounds: runtime
                .start_lt_public_lanes_vec::<P>(
                    config,
                    &packed_bits,
                    &constants,
                    &label.child("highbits_packed_lt_bounds"),
                )
                .map_err(OnlineError::from)?,
            lane_count,
            gt_lower: None,
            lt_upper: None,
            wraps_zero,
            pending_and: false,
            interval_and: None,
            interval_or: None,
            hint_bits: None,
        })
    }

    /// Returns the private hint bits once available.
    pub fn hint_bits(&self) -> Option<&ProductionBitShareVec> {
        self.hint_bits.as_ref()
    }

    /// Drives one multiplication layer of the packed interval comparison.
    pub fn drive_packed_bounds_step<P, T, L, C, E>(
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
            .drive_public_comparison_vec_step::<P, E>(config, &mut self.packed_lt_bounds, entropy)
            .map_err(OnlineError::from)
    }

    /// Collects one multiplication layer of the packed interval comparison.
    pub fn collect_packed_bounds_step<P, T, L, C>(
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
        match runtime
            .collect_public_comparison_vec_step::<P>(config, &mut self.packed_lt_bounds)
            .map_err(OnlineError::from)?
        {
            ProductionVectorItMpcCollectResult::Waiting(status) => {
                Ok(ProductionVectorItMpcCollectResult::Waiting(status))
            }
            ProductionVectorItMpcCollectResult::Collected { status, value } => {
                if self.packed_lt_bounds.is_done() && self.gt_lower.is_none() {
                    let packed = self
                        .packed_lt_bounds
                        .result()
                        .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
                    let chunks = runtime
                        .unpack_bit_share_vec_runtime_batch::<P>(
                            config,
                            packed,
                            self.lane_count,
                            &self
                                .packed_lt_bounds
                                .label()
                                .child("highbits_bounds_chunks"),
                        )
                        .map_err(OnlineError::from)?;
                    if chunks.len() != 2 {
                        return Err(OnlineError::StrictResponseCheckShapeMismatch);
                    }
                    self.gt_lower = Some(
                        runtime
                            .bit_not_vec::<P>(
                                config,
                                &chunks[0],
                                &self.packed_lt_bounds.label().child("highbits_gt_lower"),
                            )
                            .map_err(OnlineError::from)?,
                    );
                    self.lt_upper = Some(chunks[1].clone());
                }
                Ok(ProductionVectorItMpcCollectResult::Collected { status, value })
            }
        }
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
            .as_ref()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let lt = self
            .lt_upper
            .as_ref()
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

    /// Collects `gt_lower AND lt_upper`, derives the wrap interval from the
    /// same product, and finalizes private hint bits.
    pub fn collect_interval_and_finalize<P, T, L, C>(
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
                self.finalize_hint_bits::<P, _, _, _>(runtime, config, label)?;
                Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
            }
            Err(err) => Err(OnlineError::from(err)),
        }
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
        let gt = self
            .gt_lower
            .as_ref()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let lt = self
            .lt_upper
            .as_ref()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let interval_or = runtime
            .bit_or_from_and_vec::<P>(
                config,
                gt,
                lt,
                interval_and,
                &label.child("interval_wrap_or"),
            )
            .map_err(OnlineError::from)?;
        self.interval_or = Some(interval_or.clone());
        let eq_high = runtime
            .public_lane_select_bit_vec::<P>(
                config,
                &interval_or,
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
    SelectionAndPrefix,
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
    ///
    /// For each public-priority candidate this packs both required private
    /// products into one vector MPC layer:
    ///
    /// - `selected_j = valid_j AND !prefix_valid`
    /// - `prefix_and = prefix_valid AND valid_j`
    ///
    /// The prefix update is then local from `prefix_and`.
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
        let not_prefix = runtime
            .bit_not_vec::<P>(
                config,
                &self.prefix_valid,
                &label.child(format!("candidate_{candidate_idx}/not_prefix")),
            )
            .map_err(OnlineError::from)?;
        let packed_left = runtime
            .pack_bit_share_vecs_for_runtime_batch::<P>(
                config,
                &[valid_bits[candidate_idx].clone(), self.prefix_valid.clone()],
                &label.child(format!("candidate_{candidate_idx}/selection_pack_left")),
            )
            .map_err(OnlineError::from)?;
        let packed_right = runtime
            .pack_bit_share_vecs_for_runtime_batch::<P>(
                config,
                &[not_prefix, valid_bits[candidate_idx].clone()],
                &label.child(format!("candidate_{candidate_idx}/selection_pack_right")),
            )
            .map_err(OnlineError::from)?;
        runtime
            .drive_bit_and_vec::<P, E>(
                config,
                &packed_left,
                &packed_right,
                &label.child(format!("candidate_{candidate_idx}/selection_and_prefix")),
                entropy,
            )
            .map_err(OnlineError::from)?;
        self.pending = Some(StrictPrioritySelectionPending::SelectionAndPrefix);
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver: runtime.local_party(),
            kind: talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase: talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare,
            label_hash: talus_dkg::power2round_label_hash(
                &label
                    .child(format!("candidate_{candidate_idx}/selection_and_prefix"))
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
            StrictPrioritySelectionPending::SelectionAndPrefix => {
                let selection_label =
                    label.child(format!("candidate_{candidate_idx}/selection_and_prefix"));
                let (status, packed_products) =
                    match runtime.collect_bit_and_vec::<P>(config, &selection_label) {
                        Ok(ProductionVectorItMpcCollectResult::Waiting(status)) => {
                            return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
                        }
                        Ok(ProductionVectorItMpcCollectResult::Collected { status, value }) => {
                            (status, value)
                        }
                        Err(err) => return Err(OnlineError::from(err)),
                    };
                let chunks = runtime
                    .unpack_bit_share_vec_runtime_batch::<P>(
                        config,
                        &packed_products,
                        valid_bits[candidate_idx].len(),
                        &label.child(format!("candidate_{candidate_idx}/selection_products")),
                    )
                    .map_err(OnlineError::from)?;
                if chunks.len() != 2 {
                    return Err(OnlineError::StrictResponseCheckShapeMismatch);
                }
                let selected = chunks[0].clone();
                let prefix_and = chunks[1].clone();
                self.selected_bits[candidate_idx] = Some(selected);
                self.prefix_valid = runtime
                    .bit_or_from_and_vec::<P>(
                        config,
                        &self.prefix_valid,
                        &valid_bits[candidate_idx],
                        &prefix_and,
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

/// Drives private selected-vector products for one-hot selection.
///
/// Instead of multiplying every candidate as `selected_j * value_j`, this uses
/// the affine one-hot form:
///
/// `selected = value_0 + sum_{j>0} selected_j * (value_j - value_0)`.
///
/// The one-hot and any-valid checks run before selected opening, so this keeps
/// the same selected-only security boundary while saving one full vector
/// product. For the common two-token batch this halves selected-opening
/// multiplication lanes.
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
    if values.len() == 1 {
        return Ok(PrimeFieldMpcPhaseDriverStatus::Collected {
            receiver: None,
            kind: talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase: talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare,
            label_hash: talus_dkg::power2round_label_hash(label),
            senders: Vec::new(),
        });
    }
    let base = &values[0];
    let mut repeated_parts = Vec::with_capacity(values.len() - 1);
    let mut delta_parts = Vec::with_capacity(values.len() - 1);
    for (idx, (selected, value)) in selected_bits.iter().zip(values).enumerate().skip(1) {
        repeated_parts.push(
            runtime
                .repeat_one_lane_bit_share_vec::<P>(
                    config,
                    selected,
                    value.len(),
                    &label.child(format!("candidate_{idx}/selected_repeated")),
                )
                .map_err(OnlineError::from)?,
        );
        delta_parts.push(
            runtime
                .sub_share_vec::<P>(
                    config,
                    value,
                    base,
                    &label.child(format!("candidate_{idx}/delta_from_base")),
                )
                .map_err(OnlineError::from)?,
        );
    }
    let packed_selected = runtime
        .concat_bit_share_vecs_for_runtime_batch::<P>(
            config,
            &repeated_parts,
            &label.child("packed_selected"),
        )
        .map_err(OnlineError::from)?;
    let packed_values = runtime
        .concat_share_vecs_for_runtime_batch::<P>(
            config,
            &delta_parts,
            &label.child("packed_deltas"),
        )
        .map_err(OnlineError::from)?;
    runtime
        .drive_selection_product_vec::<P, E>(
            config,
            &packed_selected,
            &packed_values,
            &label.child("packed_selection_product"),
            entropy,
        )
        .map_err(OnlineError::from)?;
    Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
        receiver: runtime.local_party(),
        kind: talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce,
        phase: talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare,
        label_hash: talus_dkg::power2round_label_hash(label),
    })
}

/// Collects affine selected-vector products and returns the privately selected share.
pub fn strict_collect_selected_share_products<P, T, L, C>(
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    values: &[ProductionShareVec],
    label: &Power2RoundTranscriptLabel,
) -> Result<ProductionVectorItMpcCollectResult<ProductionShareVec>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    let candidate_count = values.len();
    let lane_count = values
        .first()
        .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?
        .len();
    if candidate_count == 0 || lane_count == 0 {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    if values.iter().any(|value| value.len() != lane_count) {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    if candidate_count == 1 {
        return Ok(ProductionVectorItMpcCollectResult::Collected {
            status: PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: None,
                kind: talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce,
                phase: talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare,
                label_hash: talus_dkg::power2round_label_hash(label),
                senders: Vec::new(),
            },
            value: values[0].clone(),
        });
    }
    let packed = match runtime
        .collect_selection_product_vec::<P>(config, &label.child("packed_selection_product"))
        .map_err(OnlineError::from)?
    {
        ProductionVectorItMpcCollectResult::Waiting(status) => {
            return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
        }
        ProductionVectorItMpcCollectResult::Collected { status, value } => (status, value),
    };
    let (status, packed_value) = packed;
    let mut products = Vec::with_capacity(candidate_count);
    products.push(values[0].clone());
    for idx in 1..candidate_count {
        products.push(
            runtime
                .slice_share_vec_lanes_for_runtime_chunk::<P>(
                    config,
                    &packed_value,
                    (idx - 1) * lane_count..idx * lane_count,
                    &label.child(format!("candidate_{idx}/product")),
                )
                .map_err(OnlineError::from)?,
        );
    }
    let selected = runtime
        .sum_share_vecs::<P>(config, &products, &label.child("selected_sum"))
        .map_err(OnlineError::from)?;
    Ok(ProductionVectorItMpcCollectResult::Collected {
        status,
        value: selected,
    })
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

fn strict_selected_share_opening_chunks<P, T, L, C, E>(
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    selected_bits: &[ProductionBitShareVec],
    values: &[ProductionShareVec],
    max_lanes_per_chunk: usize,
    label: &Power2RoundTranscriptLabel,
    entropy: &mut E,
) -> Result<Vec<talus_core::Coeff>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
    E: ProductionVectorItMpcEntropy,
{
    if values.is_empty() || values.len() != selected_bits.len() {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let lane_count = values[0].len();
    if values.iter().any(|value| value.len() != lane_count) {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let mut opened = Vec::with_capacity(lane_count);
    for (chunk_idx, range) in strict_lane_chunk_ranges(lane_count, max_lanes_per_chunk)?
        .into_iter()
        .enumerate()
    {
        let chunk_values = values
            .iter()
            .enumerate()
            .map(|(candidate_idx, value)| {
                runtime
                    .slice_share_vec_lanes_for_runtime_chunk::<P>(
                        config,
                        value,
                        range.clone(),
                        &label.child(format!("chunk_{chunk_idx}/candidate_{candidate_idx}")),
                    )
                    .map_err(OnlineError::from)
            })
            .collect::<Result<Vec<_>, OnlineError>>()?;
        let chunk_label = label.child(format!("chunk_{chunk_idx}"));
        strict_drive_selected_share_products::<P, _, _, _, _>(
            runtime,
            config,
            selected_bits,
            &chunk_values,
            &chunk_label.child("selected_product"),
            entropy,
        )?;
        let selected_chunk =
            strict_collected_value(strict_collect_selected_share_products::<P, _, _, _>(
                runtime,
                config,
                &chunk_values,
                &chunk_label.child("selected_product"),
            )?)?;
        runtime
            .drive_open_share_vec::<P>(config, &selected_chunk, &chunk_label.child("open"))
            .map_err(OnlineError::from)?;
        opened.extend(strict_collected_value(
            runtime
                .collect_open_share_vec::<P>(config, &chunk_label.child("open"))
                .map_err(OnlineError::from)?,
        )?);
    }
    Ok(opened)
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
    /// Optional certified precomputed `[w_j] = [A*y_j]` handle.
    ///
    /// When present together with `as1_share`, strict signing computes the
    /// hint relation as `[w_j] + c_j*[As1] - c_j*t1*2^d` instead of recomputing
    /// `A*[z_j]` online.
    pub w_share: Option<ProductionShareVec>,
    /// Optional certified precomputed `[As1] = [A*s1]` key-state handle.
    pub as1_share: Option<ProductionShareVec>,
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

/// Runtime-owned strict signing key-state handles.
///
/// This is private release helper material. It contains `[s1]` for response
/// preparation and `[As1] = [A*s1]` for the optimized hint relation, but never
/// exposes public exact `A*s1_i` commitments.
#[derive(Clone)]
pub struct StrictRuntimeSigningKeyState {
    s1_share: ProductionShareVec,
    as1_share: ProductionShareVec,
}

impl StrictRuntimeSigningKeyState {
    /// Creates key-state handles from already certified runtime shares.
    pub fn new(s1_share: ProductionShareVec, as1_share: ProductionShareVec) -> Self {
        Self {
            s1_share,
            as1_share,
        }
    }

    /// Computes `[As1] = A[s1]` from the retained private `[s1]` handle and
    /// the public `rho` encoded in `public_key`.
    #[cfg(not(feature = "production-release-checks"))]
    pub fn from_s1_share<P, T, L, C>(
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        public_key: &[u8],
        s1_share: ProductionShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Self, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if s1_share.len() != P::L * P::N {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let decoded = public_key_decode::<P>(public_key)?;
        let as1_share = runtime
            .az_from_rho_share_vec::<P>(config, &decoded.rho, &s1_share, label)
            .map_err(OnlineError::from)?;
        Ok(Self::new(s1_share, as1_share))
    }

    /// Builds key-state handles from a release DKG key package that already
    /// stores certified private `[As1] = [A*s1]` state.
    pub fn from_dkg_key_package<P, T, L, C>(
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        package: &DkgKeyPackage,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Self, OnlineError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if package.party != package.s1_share.party || package.party != package.as1_share.party {
            return Err(OnlineError::Dkg(DkgError::PartyMismatch {
                expected: package.party,
                got: package.s1_share.party,
            }));
        }
        let s1 = BoundedSecretVectorShare::decode::<P>(config, &package.s1_share.s1_share)?;
        let as1 = As1SecretVectorShare::decode::<P>(config, &package.as1_share.as1_share)?;
        if s1.party != package.party || as1.party != package.party || s1.point != as1.point {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let s1_share = runtime
            .share_vec_from_local_lanes::<P>(config, &label.child("s1"), s1.coeffs)
            .map_err(OnlineError::from)?;
        let as1_share = runtime
            .share_vec_from_local_lanes::<P>(config, &label.child("as1"), as1.coeffs)
            .map_err(OnlineError::from)?;
        let state = Self::new(s1_share, as1_share);
        state.validate_for::<P>()?;
        Ok(state)
    }

    /// Private `[s1]` handle.
    pub const fn s1_share(&self) -> &ProductionShareVec {
        &self.s1_share
    }

    /// Private `[As1]` handle.
    pub const fn as1_share(&self) -> &ProductionShareVec {
        &self.as1_share
    }

    fn validate_for<P: MlDsaParams>(&self) -> Result<(), OnlineError> {
        if self.s1_share.len() == P::L * P::N && self.as1_share.len() == P::K * P::N {
            Ok(())
        } else {
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        }
    }
}

impl fmt::Debug for StrictRuntimeSigningKeyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrictRuntimeSigningKeyState")
            .field("s1_share", &self.s1_share.id())
            .field("as1_share", &self.as1_share.id())
            .finish()
    }
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
        match (&self.w_share, &self.as1_share) {
            (Some(w_share), Some(as1_share))
                if w_share.len() == P::K * P::N && as1_share.len() == P::K * P::N => {}
            #[cfg(not(feature = "production-release-checks"))]
            (None, None) => {}
            _ => return Err(OnlineError::StrictResponseCheckShapeMismatch),
        }
        Ok(())
    }
}

/// Builds one strict runtime candidate input from a certified token and
/// private key-state handles.
///
/// This is the release-facing assembly point for precomputed strict signing
/// material: `[w]` comes from the preprocessing token, `[As1]` comes from
/// key-state, and masks are passed as one-time runtime handles.
pub fn strict_runtime_candidate_input_from_token_and_key_state<P: MlDsaParams>(
    token: &CertifiedToken,
    key_state: &StrictRuntimeSigningKeyState,
    y_share: ProductionShareVec,
) -> Result<StrictRuntimeCandidateShareInput, OnlineError> {
    key_state.validate_for::<P>()?;
    let masks = token
        .strict_signing_masks()
        .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?;
    let input = StrictRuntimeCandidateShareInput {
        token_session_id: token.session_id,
        y_share,
        s1_share: key_state.s1_share().clone(),
        w_share: Some(
            token
                .precomputed_w_share()
                .cloned()
                .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?,
        ),
        as1_share: Some(key_state.as1_share().clone()),
        z_mask_value: masks.z_mask_value().clone(),
        z_mask_bits_by_bit: masks.z_mask_bits_by_bit().to_vec(),
        hint_mask_value: masks.hint_mask_value().clone(),
        hint_mask_bits_by_bit: masks.hint_mask_bits_by_bit().to_vec(),
        w1: token.w1.clone(),
    };
    input.validate_for::<P>()?;
    Ok(input)
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

/// Non-secret best-shape strict-signing performance report.
///
/// This is a bottleneck/regression artifact, not a final product acceptance
/// target. It aggregates release-runtime profile counters without including
/// candidate values, pass bits, hints, z values, masks, or failure reasons.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StrictSigningBestShapePerformanceReport {
    /// ML-DSA suite name.
    pub suite: &'static str,
    /// Candidate tokens consumed by this signing attempt.
    pub token_count: usize,
    /// Coarse live-runtime phase count.
    pub phase_count: usize,
    /// Total measured wall-clock milliseconds across coarse phases.
    pub wall_clock_ms: u128,
    /// Aggregated runtime counters.
    pub counters: PrimeFieldMpcCounters,
    /// True when the report contains no scalar fallback counters.
    pub no_scalarized_release_counters: bool,
}

/// Non-secret slot names used by strict-signing benchmark reports.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StrictSigningBenchmarkSlot {
    /// `[z_j] = [y_j] + c_j [s1]` response preparation.
    ResponsePrep,
    /// Canonical decomposition of candidate `z` shares.
    ZDecomp,
    /// Private `z` bound checks.
    ZBound,
    /// Canonical decomposition of hint-side runtime shares.
    HintDecomp,
    /// Private high-bit/hint-bit and hint-weight checks.
    HintCheck,
    /// Private validity-bit combination and priority selection.
    Selection,
    /// Selected candidate product/opening path.
    SelectedOpen,
    /// Independent final signature verification.
    FinalVerify,
}

/// Non-secret timing and counter aggregate for one strict-signing benchmark
/// slot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StrictSigningBenchmarkSlotReport {
    /// Slot represented by this aggregate.
    pub slot: StrictSigningBenchmarkSlot,
    /// Coarse runtime phases merged into the slot.
    pub phase_count: usize,
    /// Wall-clock milliseconds for this slot.
    pub elapsed_ms: u128,
    /// Runtime counter aggregate for this slot.
    pub counters: PrimeFieldMpcCounters,
}

impl Default for StrictSigningBenchmarkSlot {
    fn default() -> Self {
        Self::ResponsePrep
    }
}

/// LAN-like transport estimate for a strict-signing run.
///
/// This is a deterministic simulation from runtime counters and an assumed RTT.
/// It does not implement TCP/QUIC; production applications still provide
/// transport. The estimate is intentionally public-shape-only.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StrictSigningTransportSimulationReport {
    /// Assumed round-trip time in microseconds.
    pub rtt_micros: u64,
    /// Runtime rounds counted in durable vector evidence.
    pub rounds: u64,
    /// Private messages counted in durable vector evidence.
    pub private_messages: u64,
    /// Broadcast messages counted in durable vector evidence.
    pub broadcasts: u64,
    /// Wire bytes counted in durable vector evidence.
    pub wire_bytes: u64,
    /// Durable log bytes counted in durable vector evidence.
    pub durable_log_bytes: u64,
    /// Estimated latency-only transport time in microseconds.
    pub estimated_latency_micros: u128,
}

/// Full preprocessing + strict-online signing benchmark report.
///
/// The report is safe to persist or print: it contains only public execution
/// shape, counters, timing, token-batch policy data, and final verifier result.
/// It must never include rejected candidate material, pass bits, low bits,
/// selected/unselected candidate values, masks, or failure reasons.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictSigningFullPipelineBenchmarkReport {
    /// ML-DSA suite name.
    pub suite: &'static str,
    /// Number of parties in the benchmark configuration.
    pub parties: usize,
    /// Signing threshold in the benchmark configuration.
    pub threshold: usize,
    /// Candidate-token batch size used by the strict signing attempt.
    pub token_batch_size: usize,
    /// Estimated token pass probability for the preprocessing batch.
    pub token_pass_probability: Option<(u64, u64)>,
    /// Preprocessing wall-clock milliseconds.
    pub preprocessing_ms: u128,
    /// Strict-online signing wall-clock milliseconds.
    pub strict_online_ms: u128,
    /// Final verification wall-clock milliseconds.
    pub final_verify_ms: u128,
    /// Final FIPS verifier result supplied by the benchmark harness.
    pub final_fips_verify_ok: bool,
    /// Preprocessing wire bytes.
    pub preprocessing_wire_bytes: u64,
    /// Preprocessing durable log bytes.
    pub preprocessing_durable_log_bytes: u64,
    /// Strict-online wire bytes.
    pub strict_wire_bytes: u64,
    /// Strict-online durable log bytes.
    pub strict_durable_log_bytes: u64,
    /// Amortized total wire bytes per successful signature.
    pub amortized_wire_bytes_per_success: u64,
    /// Amortized durable log bytes per successful signature.
    pub amortized_durable_log_bytes_per_success: u64,
    /// Per-slot strict-online timings/counters.
    pub slots: Vec<StrictSigningBenchmarkSlotReport>,
    /// LAN-like transport estimates for requested RTT values.
    pub transport_estimates: Vec<StrictSigningTransportSimulationReport>,
    /// True when strict runtime counters contain no scalar fallback.
    pub no_scalar_fallback: bool,
    /// True when the profile has only selected-opening phases and never an
    /// obsolete per-candidate rejected-material opening phase.
    pub selected_opening_only: bool,
    /// True when the runtime profile respects the vector/chunk envelopes.
    pub runtime_profile_within_envelope: bool,
}

/// Builds a best-shape performance report from a strict live-vector profile.
pub fn strict_signing_best_shape_performance_report<P: MlDsaParams>(
    profile: &[StrictLiveVectorMpcPhaseProfile],
    token_count: usize,
) -> Result<StrictSigningBestShapePerformanceReport, OnlineError> {
    ensure_strict_live_vector_profile_release_envelope::<P>(profile, token_count)?;
    let mut counters = PrimeFieldMpcCounters::default();
    let mut wall_clock_ms = 0u128;
    for entry in profile {
        wall_clock_ms = wall_clock_ms.saturating_add(entry.elapsed_ms);
        counters = strict_counter_sum(counters, entry.counter_delta);
    }
    Ok(StrictSigningBestShapePerformanceReport {
        suite: P::NAME,
        token_count,
        phase_count: profile.len(),
        wall_clock_ms,
        no_scalarized_release_counters: counters.scalar_mul_gates == 0
            && counters.scalar_openings == 0
            && counters.scalar_assert_zero == 0,
        counters,
    })
}

fn strict_benchmark_slot_for_phase(phase: &str) -> Option<StrictSigningBenchmarkSlot> {
    match phase {
        STRICT_PROFILE_Z_RESPONSE_PREP_BATCH => Some(StrictSigningBenchmarkSlot::ResponsePrep),
        STRICT_PROFILE_Z_CANONICAL_DECOMPOSITION_BATCH => Some(StrictSigningBenchmarkSlot::ZDecomp),
        STRICT_PROFILE_Z_BOUND_CHECKS_BATCH => Some(StrictSigningBenchmarkSlot::ZBound),
        STRICT_PROFILE_HINT_APPROX_BATCH | STRICT_PROFILE_HINT_CANONICAL_DECOMPOSITION_BATCH => {
            Some(StrictSigningBenchmarkSlot::HintDecomp)
        }
        STRICT_PROFILE_HINT_HIGHBITS_CHECKS_BATCH | STRICT_PROFILE_FUSED_VALIDITY_BATCH => {
            Some(StrictSigningBenchmarkSlot::HintCheck)
        }
        STRICT_PROFILE_PRIORITY_SELECTION_BATCH
        | STRICT_PROFILE_ONE_HOT_SELECTION_CHECK
        | STRICT_PROFILE_ANY_VALID_OPENING => Some(StrictSigningBenchmarkSlot::Selection),
        STRICT_PROFILE_SELECTED_PRIORITY_OPENING
        | STRICT_PROFILE_SELECTED_CTILDE_OPENING
        | STRICT_PROFILE_SELECTED_PRODUCTS_BATCH
        | STRICT_PROFILE_RUNTIME_CERTIFICATE => Some(StrictSigningBenchmarkSlot::SelectedOpen),
        _ => None,
    }
}

/// Aggregates strict live-vector profile entries into benchmark slots.
pub fn strict_signing_benchmark_slots(
    profile: &[StrictLiveVectorMpcPhaseProfile],
    final_verify_ms: u128,
) -> Result<Vec<StrictSigningBenchmarkSlotReport>, OnlineError> {
    let ordered = [
        StrictSigningBenchmarkSlot::ResponsePrep,
        StrictSigningBenchmarkSlot::ZDecomp,
        StrictSigningBenchmarkSlot::ZBound,
        StrictSigningBenchmarkSlot::HintDecomp,
        StrictSigningBenchmarkSlot::HintCheck,
        StrictSigningBenchmarkSlot::Selection,
        StrictSigningBenchmarkSlot::SelectedOpen,
        StrictSigningBenchmarkSlot::FinalVerify,
    ];
    let mut slots = ordered
        .iter()
        .copied()
        .map(|slot| StrictSigningBenchmarkSlotReport {
            slot,
            ..StrictSigningBenchmarkSlotReport::default()
        })
        .collect::<Vec<_>>();
    for entry in profile {
        let Some(slot) = strict_benchmark_slot_for_phase(&entry.phase) else {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        };
        let idx = ordered
            .iter()
            .position(|candidate| *candidate == slot)
            .expect("slot is known");
        let report = &mut slots[idx];
        report.phase_count = report.phase_count.saturating_add(1);
        report.elapsed_ms = report.elapsed_ms.saturating_add(entry.elapsed_ms);
        report.counters = strict_counter_sum(report.counters, entry.counter_delta);
    }
    if let Some(final_verify) = slots
        .iter_mut()
        .find(|slot| slot.slot == StrictSigningBenchmarkSlot::FinalVerify)
    {
        final_verify.phase_count = 1;
        final_verify.elapsed_ms = final_verify_ms;
    }
    Ok(slots)
}

/// Builds LAN-like transport estimates from strict runtime counters.
pub fn strict_signing_transport_simulation_reports(
    strict_report: &StrictSigningBestShapePerformanceReport,
    rtt_micros: &[u64],
) -> Vec<StrictSigningTransportSimulationReport> {
    rtt_micros
        .iter()
        .copied()
        .map(|rtt_micros| StrictSigningTransportSimulationReport {
            rtt_micros,
            rounds: strict_report.counters.rounds,
            private_messages: strict_report.counters.private_messages,
            broadcasts: strict_report.counters.broadcasts,
            wire_bytes: strict_report.counters.wire_bytes,
            durable_log_bytes: strict_report.counters.durable_log_bytes,
            estimated_latency_micros: strict_report.counters.rounds as u128 * rtt_micros as u128,
        })
        .collect()
}

/// Builds a full preprocessing + strict-online signing report.
#[cfg(feature = "production-release-checks")]
pub fn strict_signing_full_pipeline_benchmark_report<P: MlDsaParams>(
    preprocessing_report: &crate::local::PreprocessingBestShapePerformanceReport,
    strict_profile: &[StrictLiveVectorMpcPhaseProfile],
    parties: usize,
    threshold: usize,
    token_batch_size: usize,
    final_verify_ms: u128,
    final_fips_verify_ok: bool,
    rtt_micros: &[u64],
) -> Result<StrictSigningFullPipelineBenchmarkReport, OnlineError> {
    if preprocessing_report.suite != P::NAME {
        return Err(OnlineError::SuiteMismatch {
            expected: P::NAME,
            got: preprocessing_report.suite,
        });
    }
    let strict_report =
        strict_signing_best_shape_performance_report::<P>(strict_profile, token_batch_size)?;
    let slots = strict_signing_benchmark_slots(strict_profile, final_verify_ms)?;
    let selected_opening_only = strict_profile.iter().all(|entry| {
        !STRICT_LIVE_VECTOR_OBSOLETE_PROFILE_PHASES.contains(&entry.phase.as_str())
            && entry.phase != "selected_z_product"
            && entry.phase != "selected_h_product"
    });
    let no_scalar_fallback = strict_report.no_scalarized_release_counters
        && preprocessing_report.no_scalarized_release_profile;
    let preprocessing_ms = preprocessing_report
        .timings
        .iter()
        .fold(0u128, |acc, timing| acc.saturating_add(timing.elapsed_ms));
    let preprocessing_wire_bytes = preprocessing_report.profile_totals.wire_bytes;
    let preprocessing_durable_log_bytes = preprocessing_report.profile_totals.durable_log_bytes;
    let strict_wire_bytes = strict_report.counters.wire_bytes;
    let strict_durable_log_bytes = strict_report.counters.durable_log_bytes;
    let certified = preprocessing_report.certified_tokens.max(1);
    let token_pass_probability = if preprocessing_report.attempted_tokens == 0 {
        None
    } else {
        Some((
            preprocessing_report.certified_tokens,
            preprocessing_report.attempted_tokens,
        ))
    };
    let amortized_wire_bytes_per_success = preprocessing_wire_bytes
        .saturating_div(certified)
        .saturating_mul(token_batch_size as u64)
        .saturating_add(strict_wire_bytes);
    let amortized_durable_log_bytes_per_success = preprocessing_durable_log_bytes
        .saturating_div(certified)
        .saturating_mul(token_batch_size as u64)
        .saturating_add(strict_durable_log_bytes);
    Ok(StrictSigningFullPipelineBenchmarkReport {
        suite: P::NAME,
        parties,
        threshold,
        token_batch_size,
        token_pass_probability,
        preprocessing_ms,
        strict_online_ms: strict_report.wall_clock_ms,
        final_verify_ms,
        final_fips_verify_ok,
        preprocessing_wire_bytes,
        preprocessing_durable_log_bytes,
        strict_wire_bytes,
        strict_durable_log_bytes,
        amortized_wire_bytes_per_success,
        amortized_durable_log_bytes_per_success,
        slots,
        transport_estimates: strict_signing_transport_simulation_reports(
            &strict_report,
            rtt_micros,
        ),
        no_scalar_fallback,
        selected_opening_only,
        runtime_profile_within_envelope: preprocessing_report.chunk_policy_ok,
    })
}

fn strict_counter_sum(
    left: PrimeFieldMpcCounters,
    right: PrimeFieldMpcCounters,
) -> PrimeFieldMpcCounters {
    PrimeFieldMpcCounters {
        rounds: left.rounds.saturating_add(right.rounds),
        private_messages: left.private_messages.saturating_add(right.private_messages),
        broadcasts: left.broadcasts.saturating_add(right.broadcasts),
        wire_bytes: left.wire_bytes.saturating_add(right.wire_bytes),
        durable_log_bytes: left
            .durable_log_bytes
            .saturating_add(right.durable_log_bytes),
        vector_lanes: left.vector_lanes.saturating_add(right.vector_lanes),
        multiplication_layers: left
            .multiplication_layers
            .saturating_add(right.multiplication_layers),
        wall_clock_ms: left.wall_clock_ms.saturating_add(right.wall_clock_ms),
        scalar_mul_gates: left.scalar_mul_gates.saturating_add(right.scalar_mul_gates),
        vector_mul_lanes: left.vector_mul_lanes.saturating_add(right.vector_mul_lanes),
        scalar_openings: left.scalar_openings.saturating_add(right.scalar_openings),
        vector_opening_lanes: left
            .vector_opening_lanes
            .saturating_add(right.vector_opening_lanes),
        scalar_assert_zero: left
            .scalar_assert_zero
            .saturating_add(right.scalar_assert_zero),
        vector_assert_zero_lanes: left
            .vector_assert_zero_lanes
            .saturating_add(right.vector_assert_zero_lanes),
        random_bits: left.random_bits.saturating_add(right.random_bits),
        local_public_mul_lanes: left
            .local_public_mul_lanes
            .saturating_add(right.local_public_mul_lanes),
    }
}

const STRICT_PROFILE_Z_RESPONSE_PREP_BATCH: &str = "z_response_prep_batch";
const STRICT_PROFILE_Z_CANONICAL_DECOMPOSITION_BATCH: &str = "z_canonical_decomposition_batch";
const STRICT_PROFILE_Z_BOUND_CHECKS_BATCH: &str = "z_bound_checks_batch";
const STRICT_PROFILE_Z_BOUND_ALL_BATCH: &str = "z_bound_all_batch";
const STRICT_PROFILE_HINT_APPROX_BATCH: &str = "hint_approx_batch";
const STRICT_PROFILE_HINT_CANONICAL_DECOMPOSITION_BATCH: &str =
    "hint_canonical_decomposition_batch";
const STRICT_PROFILE_HINT_HIGHBITS_CHECKS_BATCH: &str = "hint_highbits_checks_batch";
const STRICT_PROFILE_HINT_WEIGHT_CHECK_BATCH: &str = "hint_weight_check_batch";
const STRICT_PROFILE_VALID_BIT_BATCH: &str = "valid_bit_batch";
const STRICT_PROFILE_FUSED_VALIDITY_BATCH: &str = "fused_validity_batch";
const STRICT_PROFILE_PRIORITY_SELECTION_BATCH: &str = "priority_selection_batch";
const STRICT_PROFILE_ONE_HOT_SELECTION_CHECK: &str = "one_hot_selection_check";
const STRICT_PROFILE_ANY_VALID_OPENING: &str = "any_valid_opening";
const STRICT_PROFILE_SELECTED_PRIORITY_OPENING: &str = "selected_priority_opening";
const STRICT_PROFILE_SELECTED_CTILDE_OPENING: &str = "selected_ctilde_opening";
const STRICT_PROFILE_SELECTED_PRODUCTS_BATCH: &str = "selected_products_batch";
const STRICT_PROFILE_RUNTIME_CERTIFICATE: &str = "runtime_certificate";

const STRICT_LIVE_VECTOR_BATCHED_PROFILE_PHASES: &[&str] = &[
    STRICT_PROFILE_Z_RESPONSE_PREP_BATCH,
    STRICT_PROFILE_Z_CANONICAL_DECOMPOSITION_BATCH,
    STRICT_PROFILE_Z_BOUND_CHECKS_BATCH,
    STRICT_PROFILE_HINT_APPROX_BATCH,
    STRICT_PROFILE_HINT_CANONICAL_DECOMPOSITION_BATCH,
    STRICT_PROFILE_HINT_HIGHBITS_CHECKS_BATCH,
    STRICT_PROFILE_FUSED_VALIDITY_BATCH,
    STRICT_PROFILE_PRIORITY_SELECTION_BATCH,
    STRICT_PROFILE_ONE_HOT_SELECTION_CHECK,
    STRICT_PROFILE_ANY_VALID_OPENING,
    STRICT_PROFILE_SELECTED_PRIORITY_OPENING,
    STRICT_PROFILE_SELECTED_CTILDE_OPENING,
    STRICT_PROFILE_SELECTED_PRODUCTS_BATCH,
    STRICT_PROFILE_RUNTIME_CERTIFICATE,
];

const STRICT_LIVE_VECTOR_OBSOLETE_PROFILE_PHASES: &[&str] = &[
    "z_response_prep",
    "z_canonical_decomposition",
    "z_bound_checks",
    "z_bound_all",
    "hint_canonical_decomposition",
    "hint_highbits_checks",
    "hint_weight_check",
    "valid_bit",
    STRICT_PROFILE_Z_BOUND_ALL_BATCH,
    STRICT_PROFILE_HINT_WEIGHT_CHECK_BATCH,
    STRICT_PROFILE_VALID_BIT_BATCH,
    "priority_selection",
    "selected_z_product",
    "selected_h_product",
];

fn strict_live_vector_phase_round_cap(phase: &str, token_count: usize) -> Option<u64> {
    let token_count = token_count as u64;
    match phase {
        STRICT_PROFILE_Z_RESPONSE_PREP_BATCH => Some(0),
        STRICT_PROFILE_Z_CANONICAL_DECOMPOSITION_BATCH => Some(350),
        STRICT_PROFILE_Z_BOUND_CHECKS_BATCH => Some(128),
        STRICT_PROFILE_HINT_APPROX_BATCH => Some(0),
        STRICT_PROFILE_HINT_CANONICAL_DECOMPOSITION_BATCH => Some(350),
        STRICT_PROFILE_HINT_HIGHBITS_CHECKS_BATCH => Some(192),
        STRICT_PROFILE_FUSED_VALIDITY_BATCH => Some(192),
        STRICT_PROFILE_PRIORITY_SELECTION_BATCH => Some(token_count),
        STRICT_PROFILE_ONE_HOT_SELECTION_CHECK => Some(token_count),
        STRICT_PROFILE_ANY_VALID_OPENING => Some(1),
        STRICT_PROFILE_SELECTED_PRIORITY_OPENING => Some(token_count),
        STRICT_PROFILE_SELECTED_CTILDE_OPENING => Some(token_count),
        STRICT_PROFILE_SELECTED_PRODUCTS_BATCH => Some(token_count.saturating_mul(4).max(4)),
        STRICT_PROFILE_RUNTIME_CERTIFICATE => Some(0),
        _ => None,
    }
}

fn strict_live_vector_phase_counter_envelope(
    entry: &StrictLiveVectorMpcPhaseProfile,
    token_count: usize,
) -> Result<(), OnlineError> {
    let counters = entry.counter_delta;
    if counters.scalar_mul_gates != 0
        || counters.scalar_openings != 0
        || counters.scalar_assert_zero != 0
    {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    if let Some(round_cap) = strict_live_vector_phase_round_cap(&entry.phase, token_count) {
        if counters.rounds > round_cap {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
    }
    if counters.wire_bytes > 0 {
        let vector_wire_cap = counters
            .vector_lanes
            .saturating_mul(64)
            .saturating_add(counters.rounds.saturating_mul(4096))
            .saturating_add(4096);
        if counters.wire_bytes > vector_wire_cap {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
    }
    if counters.durable_log_bytes > 0 {
        let durable_cap = counters.wire_bytes.saturating_mul(4).saturating_add(16_384);
        if counters.durable_log_bytes > durable_cap {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
    }
    Ok(())
}

/// Validates the strict-signing live-vector profile shape required by release
/// builds.
///
/// This is intentionally a scheduler/counter envelope gate, not a wall-clock
/// benchmark. It fails if the release-capable strict path loses the batched
/// phase shape, falls back to old per-candidate phase names, records scalar
/// gates, or exceeds the current suite-independent round/log envelopes for
/// strict live-vector signing phases.
pub fn ensure_strict_live_vector_profile_release_envelope<P: MlDsaParams>(
    profile: &[StrictLiveVectorMpcPhaseProfile],
    token_count: usize,
) -> Result<(), OnlineError> {
    if token_count == 0 {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    for required in STRICT_LIVE_VECTOR_BATCHED_PROFILE_PHASES {
        let count = profile
            .iter()
            .filter(|entry| entry.phase == *required)
            .count();
        if count != 1 {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
    }
    for entry in profile {
        if STRICT_LIVE_VECTOR_OBSOLETE_PROFILE_PHASES
            .iter()
            .any(|obsolete| entry.phase == *obsolete)
        {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        if entry.phase.ends_with("_batch") && entry.candidate_index.is_some() {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        strict_live_vector_phase_counter_envelope(entry, token_count)?;
    }
    Ok(())
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

struct StrictCanonicalBatchItem {
    state: ProductionCanonicalBitDecompositionState,
    label: Power2RoundTranscriptLabel,
}

fn strict_certify_canonical_bits_batch<P, T, L, C, E>(
    items: &mut [StrictCanonicalBatchItem],
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    entropy: &mut E,
) -> Result<Vec<Vec<ProductionBitShareVec>>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
    E: ProductionVectorItMpcEntropy,
{
    for item in items.iter_mut() {
        item.state
            .drive_masked_c_opening_checked::<P, _, _, _>(runtime, config, &item.label)
            .map_err(OnlineError::from)?;
    }
    for item in items.iter_mut() {
        strict_collected_value(
            item.state
                .collect_masked_c_opening_checked::<P, _, _, _>(runtime, config, &item.label)
                .map_err(OnlineError::from)?,
        )?;
    }

    for item in items.iter_mut() {
        item.state
            .start_wrap_comparison::<P, _, _, _>(runtime, config, &item.label)
            .map_err(OnlineError::from)?;
    }
    loop {
        let mut drove = vec![false; items.len()];
        for (idx, item) in items.iter_mut().enumerate() {
            let status = item
                .state
                .drive_wrap_comparison_step::<P, _, _, _, _>(runtime, config, entropy)
                .map_err(OnlineError::from)?;
            if !matches!(status, PrimeFieldMpcPhaseDriverStatus::Collected { .. }) {
                drove[idx] = true;
            }
        }
        if drove.iter().all(|drove| !*drove) {
            break;
        }
        for (idx, item) in items.iter_mut().enumerate() {
            if drove[idx] {
                strict_collected_unit(
                    item.state
                        .collect_wrap_comparison_step::<P, _, _, _>(runtime, config)
                        .map_err(OnlineError::from)?,
                )?;
            }
        }
    }

    for item in items.iter_mut() {
        item.state
            .start_canonical_bit_recovery::<P, _, _, _>(runtime, config, &item.label)
            .map_err(OnlineError::from)?;
    }
    while items
        .iter()
        .any(|item| item.state.r_bits_by_bit().is_none())
    {
        let mut drove = vec![false; items.len()];
        for (idx, item) in items.iter_mut().enumerate() {
            if item.state.r_bits_by_bit().is_none() {
                item.state
                    .drive_canonical_bit_recovery_step::<P, _, _, _, _>(
                        runtime,
                        config,
                        &item.label,
                        entropy,
                    )
                    .map_err(OnlineError::from)?;
                drove[idx] = true;
            }
        }
        for (idx, item) in items.iter_mut().enumerate() {
            if drove[idx] {
                strict_collected_unit(
                    item.state
                        .collect_canonical_bit_recovery_step::<P, _, _, _>(
                            runtime,
                            config,
                            &item.label,
                        )
                        .map_err(OnlineError::from)?,
                )?;
            }
        }
    }

    // Strict signing consumes preprocessing-certified mask bits and recovers
    // R_bits through a checked arithmetic circuit from those bits plus public
    // masked openings. Booleanity of the recovered bits follows by
    // construction, so the online path keeps only the security-critical
    // canonical range and equality checks here. Power2Round still keeps its
    // standalone bitness assertions because it is a separate release circuit.

    for item in items.iter_mut() {
        item.state
            .start_r_lt_q_check::<P, _, _, _>(runtime, config, &item.label)
            .map_err(OnlineError::from)?;
    }
    while items.iter().any(|item| item.state.r_lt_q().is_none()) {
        let mut drove = vec![false; items.len()];
        for (idx, item) in items.iter_mut().enumerate() {
            if item.state.r_lt_q().is_none() {
                item.state
                    .drive_r_lt_q_check_step::<P, _, _, _, _>(runtime, config, entropy)
                    .map_err(OnlineError::from)?;
                drove[idx] = true;
            }
        }
        for (idx, item) in items.iter_mut().enumerate() {
            if drove[idx] {
                strict_collected_unit(
                    item.state
                        .collect_r_lt_q_check_step::<P, _, _, _>(runtime, config)
                        .map_err(OnlineError::from)?,
                )?;
            }
        }
    }

    for item in items.iter_mut() {
        item.state
            .drive_r_lt_q_assert_true::<P, _, _, _>(runtime, config, &item.label)
            .map_err(OnlineError::from)?;
    }
    for item in items.iter_mut() {
        strict_collected_unit(
            item.state
                .collect_r_lt_q_assert_true::<P, _, _, _>(runtime, config, &item.label)
                .map_err(OnlineError::from)?,
        )?;
    }

    for item in items.iter_mut() {
        item.state
            .drive_r_bits_equal_value_check::<P, _, _, _>(runtime, config, &item.label)
            .map_err(OnlineError::from)?;
    }
    for item in items.iter_mut() {
        strict_collected_unit(
            item.state
                .collect_r_bits_equal_value_check::<P, _, _, _>(runtime, config, &item.label)
                .map_err(OnlineError::from)?,
        )?;
    }

    items
        .iter()
        .map(|item| {
            item.state
                .r_bits_by_bit()
                .map(|bits| bits.to_vec())
                .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)
        })
        .collect()
}

#[cfg(test)]
fn strict_run_z_bound_checks_batch<P, T, L, C, E>(
    states: &mut [StrictRuntimeZBoundCheckState],
    labels: &[Power2RoundTranscriptLabel],
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    entropy: &mut E,
) -> Result<Vec<ProductionBitShareVec>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
    E: ProductionVectorItMpcEntropy,
{
    if states.len() != labels.len() {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    while states.iter().any(|state| state.lt_gamma.is_none()) {
        let mut drove = vec![false; states.len()];
        for (idx, state) in states.iter_mut().enumerate() {
            if state.lt_gamma.is_none() {
                state.drive_packed_bounds_step::<P, _, _, _, _>(runtime, config, entropy)?;
                drove[idx] = true;
            }
        }
        for (idx, state) in states.iter_mut().enumerate() {
            if drove[idx] {
                strict_collected_unit(
                    state.collect_packed_bounds_step::<P, _, _, _>(runtime, config)?,
                )?;
            }
        }
    }
    for (state, label) in states.iter_mut().zip(labels.iter()) {
        state.drive_or_step::<P, _, _, _, _>(runtime, config, label, entropy)?;
    }
    for (state, label) in states.iter_mut().zip(labels.iter()) {
        strict_collected_unit(state.collect_or_step::<P, _, _, _>(runtime, config, label)?)?;
    }
    states
        .iter()
        .map(|state| {
            state
                .result()
                .cloned()
                .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)
        })
        .collect()
}

#[cfg(test)]
#[allow(dead_code)]
fn strict_bit_width_for_public_lt_threshold(threshold: u32) -> Result<usize, OnlineError> {
    if threshold == 0 {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    Ok((u32::BITS - (threshold - 1).leading_zeros()) as usize)
}

#[cfg(test)]
#[allow(dead_code)]
fn strict_run_z_bound_checks_specialized_batch<P, T, L, C, E>(
    z_bits_by_candidate: &[Vec<ProductionBitShareVec>],
    labels: &[Power2RoundTranscriptLabel],
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    root_label: &Power2RoundTranscriptLabel,
    entropy: &mut E,
) -> Result<Vec<ProductionBitShareVec>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
    E: ProductionVectorItMpcEntropy,
{
    if z_bits_by_candidate.is_empty() || z_bits_by_candidate.len() != labels.len() {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let lane_count = z_bits_by_candidate[0]
        .first()
        .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?
        .len();
    if z_bits_by_candidate
        .iter()
        .any(|bits| bits.len() != 23 || bits.iter().any(|bit| bit.len() != lane_count))
    {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }

    let gamma1 =
        u32::try_from(P::GAMMA1).map_err(|_| OnlineError::StrictResponseCheckShapeMismatch)?;
    if !gamma1.is_power_of_two() {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let gamma = u32::try_from(P::GAMMA1 - P::BETA)
        .map_err(|_| OnlineError::StrictResponseCheckShapeMismatch)?;
    let gamma_width = gamma1.trailing_zeros() as usize;
    let upper_complement_threshold = gamma
        .checked_add(8190)
        .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?;
    let upper_complement_width =
        strict_bit_width_for_public_lt_threshold(upper_complement_threshold)?;
    if gamma_width >= 23 || upper_complement_width >= 23 {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }

    let mut lower_states = Vec::with_capacity(z_bits_by_candidate.len());
    let mut upper_states = Vec::with_capacity(z_bits_by_candidate.len());
    let mut complement_bits_by_candidate = Vec::with_capacity(z_bits_by_candidate.len());
    for (idx, bits) in z_bits_by_candidate.iter().enumerate() {
        let complement_bits = bits
            .iter()
            .enumerate()
            .map(|(bit_idx, bit)| {
                runtime
                    .bit_not_vec::<P>(
                        config,
                        bit,
                        &labels[idx].child(format!("z_bound_special/complement_bit_{bit_idx}")),
                    )
                    .map_err(OnlineError::from)
            })
            .collect::<Result<Vec<_>, OnlineError>>()?;
        lower_states.push(
            runtime
                .start_lt_public_vec::<P>(
                    config,
                    &bits[..gamma_width],
                    gamma,
                    &labels[idx].child("z_bound_special/lower_low_lt_gamma"),
                )
                .map_err(OnlineError::from)?,
        );
        upper_states.push(
            runtime
                .start_lt_public_vec::<P>(
                    config,
                    &complement_bits[..upper_complement_width],
                    upper_complement_threshold,
                    &labels[idx].child("z_bound_special/upper_complement_lt"),
                )
                .map_err(OnlineError::from)?,
        );
        complement_bits_by_candidate.push(complement_bits);
    }

    while lower_states.iter().any(|state| !state.is_done()) {
        let mut drove = vec![false; lower_states.len()];
        for (idx, state) in lower_states.iter_mut().enumerate() {
            if !state.is_done() {
                runtime
                    .drive_public_comparison_vec_step::<P, E>(config, state, entropy)
                    .map_err(OnlineError::from)?;
                drove[idx] = true;
            }
        }
        for (idx, state) in lower_states.iter_mut().enumerate() {
            if drove[idx] {
                strict_collected_unit(
                    runtime
                        .collect_public_comparison_vec_step::<P>(config, state)
                        .map_err(OnlineError::from)?,
                )?;
            }
        }
    }
    while upper_states.iter().any(|state| !state.is_done()) {
        let mut drove = vec![false; upper_states.len()];
        for (idx, state) in upper_states.iter_mut().enumerate() {
            if !state.is_done() {
                runtime
                    .drive_public_comparison_vec_step::<P, E>(config, state, entropy)
                    .map_err(OnlineError::from)?;
                drove[idx] = true;
            }
        }
        for (idx, state) in upper_states.iter_mut().enumerate() {
            if drove[idx] {
                strict_collected_unit(
                    runtime
                        .collect_public_comparison_vec_step::<P>(config, state)
                        .map_err(OnlineError::from)?,
                )?;
            }
        }
    }

    let mut lower_ok = Vec::with_capacity(z_bits_by_candidate.len());
    let mut upper_ok = Vec::with_capacity(z_bits_by_candidate.len());
    for idx in 0..z_bits_by_candidate.len() {
        let lower_high_any = strict_run_private_or_reduce_packed::<P, _, _, _, _>(
            z_bits_by_candidate[idx][gamma_width..].to_vec(),
            runtime,
            config,
            &labels[idx].child("z_bound_special/lower_high_any"),
            entropy,
        )?;
        let lower_high_zero = runtime
            .bit_not_vec::<P>(
                config,
                &lower_high_any,
                &labels[idx].child("z_bound_special/lower_high_zero"),
            )
            .map_err(OnlineError::from)?;
        let upper_high_any = strict_run_private_or_reduce_packed::<P, _, _, _, _>(
            complement_bits_by_candidate[idx][upper_complement_width..].to_vec(),
            runtime,
            config,
            &labels[idx].child("z_bound_special/upper_complement_high_any"),
            entropy,
        )?;
        let upper_high_zero = runtime
            .bit_not_vec::<P>(
                config,
                &upper_high_any,
                &labels[idx].child("z_bound_special/upper_complement_high_zero"),
            )
            .map_err(OnlineError::from)?;
        let lower_cmp = lower_states[idx]
            .result()
            .cloned()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let upper_cmp = upper_states[idx]
            .result()
            .cloned()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let packed_left = runtime
            .concat_bit_share_vecs_for_runtime_batch::<P>(
                config,
                &[lower_cmp, upper_cmp],
                &labels[idx].child("z_bound_special/ok_left"),
            )
            .map_err(OnlineError::from)?;
        let packed_right = runtime
            .concat_bit_share_vecs_for_runtime_batch::<P>(
                config,
                &[lower_high_zero, upper_high_zero],
                &labels[idx].child("z_bound_special/ok_right"),
            )
            .map_err(OnlineError::from)?;
        runtime
            .drive_bit_and_vec::<P, E>(
                config,
                &packed_left,
                &packed_right,
                &labels[idx].child("z_bound_special/ok_products"),
                entropy,
            )
            .map_err(OnlineError::from)?;
        let products = strict_collected_value(
            runtime
                .collect_bit_and_vec::<P>(config, &labels[idx].child("z_bound_special/ok_products"))
                .map_err(OnlineError::from)?,
        )?;
        let chunks = runtime
            .unpack_bit_share_vec_runtime_batch::<P>(
                config,
                &products,
                lane_count,
                &labels[idx].child("z_bound_special/ok_chunks"),
            )
            .map_err(OnlineError::from)?;
        if chunks.len() != 2 {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        lower_ok.push(chunks[0].clone());
        upper_ok.push(chunks[1].clone());
    }

    let mut out = Vec::with_capacity(z_bits_by_candidate.len());
    for idx in 0..z_bits_by_candidate.len() {
        runtime
            .drive_bit_and_vec::<P, E>(
                config,
                &lower_ok[idx],
                &upper_ok[idx],
                &labels[idx].child("z_bound_special/final_or_product"),
                entropy,
            )
            .map_err(OnlineError::from)?;
        let and = strict_collected_value(
            runtime
                .collect_bit_and_vec::<P>(
                    config,
                    &labels[idx].child("z_bound_special/final_or_product"),
                )
                .map_err(OnlineError::from)?,
        )?;
        out.push(
            runtime
                .bit_or_from_and_vec::<P>(
                    config,
                    &lower_ok[idx],
                    &upper_ok[idx],
                    &and,
                    &root_label.child(format!("candidate_{idx}/z_bound_special_ok")),
                )
                .map_err(OnlineError::from)?,
        );
    }
    Ok(out)
}

fn strict_lane_chunk_ranges(
    lane_count: usize,
    max_lanes: usize,
) -> Result<Vec<core::ops::Range<usize>>, OnlineError> {
    if lane_count == 0 || max_lanes == 0 {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < lane_count {
        let end = start.saturating_add(max_lanes).min(lane_count);
        ranges.push(start..end);
        start = end;
    }
    Ok(ranges)
}

#[cfg(test)]
fn strict_slice_bit_columns_for_chunk<P, T, L, C>(
    runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    bits_by_bit_le: &[ProductionBitShareVec],
    range: core::ops::Range<usize>,
    label: &Power2RoundTranscriptLabel,
) -> Result<Vec<ProductionBitShareVec>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    bits_by_bit_le
        .iter()
        .enumerate()
        .map(|(bit_idx, bits)| {
            runtime
                .slice_bit_share_vec_lanes_for_runtime_chunk::<P>(
                    config,
                    bits,
                    range.clone(),
                    &label.child(format!("bit_{bit_idx}")),
                )
                .map_err(OnlineError::from)
        })
        .collect()
}

#[cfg(test)]
fn strict_concat_candidate_bit_chunks<P, T, L, C>(
    runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    chunks_by_candidate: &[Vec<ProductionBitShareVec>],
    label: &Power2RoundTranscriptLabel,
) -> Result<Vec<ProductionBitShareVec>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    chunks_by_candidate
        .iter()
        .enumerate()
        .map(|(candidate_idx, chunks)| {
            runtime
                .concat_bit_share_vecs_for_runtime_batch::<P>(
                    config,
                    chunks,
                    &label.child(format!("candidate_{candidate_idx}")),
                )
                .map_err(OnlineError::from)
        })
        .collect()
}

#[cfg(test)]
fn strict_run_z_bound_checks_chunked_batch<P, T, L, C, E>(
    z_bits_by_candidate: &[Vec<ProductionBitShareVec>],
    labels: &[Power2RoundTranscriptLabel],
    max_lanes_per_chunk: usize,
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    root_label: &Power2RoundTranscriptLabel,
    entropy: &mut E,
) -> Result<Vec<ProductionBitShareVec>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
    E: ProductionVectorItMpcEntropy,
{
    if z_bits_by_candidate.is_empty() || z_bits_by_candidate.len() != labels.len() {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let lane_count = z_bits_by_candidate[0]
        .first()
        .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?
        .len();
    if z_bits_by_candidate
        .iter()
        .any(|bits| bits.len() != 23 || bits.iter().any(|bit| bit.len() != lane_count))
    {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let ranges = strict_lane_chunk_ranges(lane_count, max_lanes_per_chunk)?;
    let mut chunk_ok_by_candidate =
        vec![Vec::with_capacity(ranges.len()); z_bits_by_candidate.len()];
    for (chunk_idx, range) in ranges.iter().cloned().enumerate() {
        let chunk_label = root_label.child(format!("chunk_{chunk_idx}"));
        let z_bound_labels = labels
            .iter()
            .map(|label| label.child(format!("chunk_{chunk_idx}")))
            .collect::<Vec<_>>();
        let mut states = z_bits_by_candidate
            .iter()
            .zip(z_bound_labels.iter())
            .map(|(bits, label)| {
                let chunk_bits = strict_slice_bit_columns_for_chunk::<P, _, _, _>(
                    runtime,
                    config,
                    bits,
                    range.clone(),
                    &label.child("z_bits"),
                )?;
                StrictRuntimeZBoundCheckState::new::<P, _, _, _>(
                    runtime,
                    config,
                    &chunk_bits,
                    label,
                )
            })
            .collect::<Result<Vec<_>, OnlineError>>()?;
        let predicates = strict_run_z_bound_checks_batch::<P, _, _, _, _>(
            &mut states,
            &z_bound_labels,
            runtime,
            config,
            entropy,
        )?;
        let chunk_ok = strict_run_all_bits_true_packed_batch::<P, _, _, _, _>(
            &predicates,
            runtime,
            config,
            &chunk_label.child("all_true"),
            entropy,
        )?;
        for (candidate_idx, ok) in chunk_ok.into_iter().enumerate() {
            chunk_ok_by_candidate[candidate_idx].push(ok);
        }
    }
    let packed_chunk_ok = strict_concat_candidate_bit_chunks::<P, _, _, _>(
        runtime,
        config,
        &chunk_ok_by_candidate,
        &root_label.child("candidate_chunk_ok"),
    )?;
    strict_run_all_bits_true_packed_batch::<P, _, _, _, _>(
        &packed_chunk_ok,
        runtime,
        config,
        &root_label.child("aggregate_chunks"),
        entropy,
    )
}

fn strict_run_fused_z_bound_and_hint_bits_batch<P, T, L, C, E>(
    z_bits_by_candidate: &[Vec<ProductionBitShareVec>],
    hint_bits_input_by_candidate: &[Vec<ProductionBitShareVec>],
    w1_by_candidate: &[Vec<u32>],
    labels: &[Power2RoundTranscriptLabel],
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    root_label: &Power2RoundTranscriptLabel,
    entropy: &mut E,
) -> Result<(Vec<ProductionBitShareVec>, Vec<ProductionBitShareVec>), OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
    E: ProductionVectorItMpcEntropy,
{
    let candidate_count = z_bits_by_candidate.len();
    if candidate_count == 0
        || hint_bits_input_by_candidate.len() != candidate_count
        || w1_by_candidate.len() != candidate_count
        || labels.len() != candidate_count
    {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let z_lane_count = P::L * P::N;
    let hint_lane_count = P::K * P::N;
    let gamma = u32::try_from(P::GAMMA1 - P::BETA)
        .map_err(|_| OnlineError::StrictResponseCheckShapeMismatch)?;
    let upper_exclusive = (P::Q as u32)
        .checked_sub(gamma)
        .and_then(|upper| upper.checked_add(1))
        .filter(|&value| value < P::Q as u32)
        .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?;

    let mut constants =
        Vec::with_capacity(candidate_count * (2 * z_lane_count + 2 * hint_lane_count));
    let mut packed_bits_parts_by_bit = (0..23)
        .map(|_| Vec::with_capacity(candidate_count * 4))
        .collect::<Vec<Vec<ProductionBitShareVec>>>();
    let mut wraps_zero_by_candidate = Vec::with_capacity(candidate_count);
    for idx in 0..candidate_count {
        let z_bits = &z_bits_by_candidate[idx];
        let hint_bits = &hint_bits_input_by_candidate[idx];
        if z_bits.len() != 23
            || hint_bits.len() != 23
            || z_bits.iter().any(|bit| bit.len() != z_lane_count)
            || hint_bits.iter().any(|bit| bit.len() != hint_lane_count)
            || w1_by_candidate[idx].len() != hint_lane_count
        {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let (hint_lower, hint_upper, wraps_zero) =
            strict_highbits_interval_constants_for_lanes::<P>(&w1_by_candidate[idx])?;
        wraps_zero_by_candidate.push(wraps_zero);

        constants.extend(std::iter::repeat_n(
            gamma as talus_core::Coeff,
            z_lane_count,
        ));
        constants.extend(std::iter::repeat_n(
            upper_exclusive as talus_core::Coeff,
            z_lane_count,
        ));
        constants.extend(
            hint_lower
                .iter()
                .map(|value| {
                    value
                        .checked_add(1)
                        .filter(|&bound| bound < P::Q)
                        .ok_or(OnlineError::StrictResponseCheckShapeMismatch)
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        constants.extend_from_slice(&hint_upper);

        for bit_idx in 0..23 {
            packed_bits_parts_by_bit[bit_idx].push(z_bits[bit_idx].clone());
            packed_bits_parts_by_bit[bit_idx].push(z_bits[bit_idx].clone());
            packed_bits_parts_by_bit[bit_idx].push(hint_bits[bit_idx].clone());
            packed_bits_parts_by_bit[bit_idx].push(hint_bits[bit_idx].clone());
        }
    }

    let packed_bits = packed_bits_parts_by_bit
        .iter()
        .enumerate()
        .map(|(bit_idx, parts)| {
            runtime
                .concat_bit_share_vecs_for_runtime_batch::<P>(
                    config,
                    parts,
                    &root_label.child(format!("all_candidate_fused_bounds/bit_{bit_idx}")),
                )
                .map_err(OnlineError::from)
        })
        .collect::<Result<Vec<_>, OnlineError>>()?;
    let mut state = runtime
        .start_lt_public_lanes_vec::<P>(
            config,
            &packed_bits,
            &constants,
            &root_label.child("all_candidate_fused_z_hint_bounds"),
        )
        .map_err(OnlineError::from)?;

    while !state.is_done() {
        runtime
            .drive_public_comparison_vec_step::<P, E>(config, &mut state, entropy)
            .map_err(OnlineError::from)?;
        strict_collected_unit(
            runtime
                .collect_public_comparison_vec_step::<P>(config, &mut state)
                .map_err(OnlineError::from)?,
        )?;
    }

    let mut z_lt_gamma = Vec::with_capacity(candidate_count);
    let mut z_gt_upper = Vec::with_capacity(candidate_count);
    let mut hint_gt_lower = Vec::with_capacity(candidate_count);
    let mut hint_lt_upper = Vec::with_capacity(candidate_count);
    let packed = state
        .result()
        .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
    let candidate_stride = 2 * z_lane_count + 2 * hint_lane_count;
    for idx in 0..candidate_count {
        let offset = idx * candidate_stride;
        let label = &labels[idx];
        let z_lt = runtime
            .slice_bit_share_vec_lanes_for_runtime_chunk::<P>(
                config,
                packed,
                offset..offset + z_lane_count,
                &label.child("fused_bounds/z_lt_gamma"),
            )
            .map_err(OnlineError::from)?;
        let z_lt_upper = runtime
            .slice_bit_share_vec_lanes_for_runtime_chunk::<P>(
                config,
                packed,
                offset + z_lane_count..offset + 2 * z_lane_count,
                &label.child("fused_bounds/z_lt_upper_exclusive"),
            )
            .map_err(OnlineError::from)?;
        let hint_lt_lower_plus_one = runtime
            .slice_bit_share_vec_lanes_for_runtime_chunk::<P>(
                config,
                packed,
                offset + 2 * z_lane_count..offset + 2 * z_lane_count + hint_lane_count,
                &label.child("fused_bounds/hint_lt_lower_plus_one"),
            )
            .map_err(OnlineError::from)?;
        let hint_lt = runtime
            .slice_bit_share_vec_lanes_for_runtime_chunk::<P>(
                config,
                packed,
                offset + 2 * z_lane_count + hint_lane_count
                    ..offset + 2 * z_lane_count + 2 * hint_lane_count,
                &label.child("fused_bounds/hint_lt_upper"),
            )
            .map_err(OnlineError::from)?;
        z_lt_gamma.push(z_lt);
        z_gt_upper.push(
            runtime
                .bit_not_vec::<P>(config, &z_lt_upper, &label.child("fused_bounds/z_gt_upper"))
                .map_err(OnlineError::from)?,
        );
        hint_gt_lower.push(
            runtime
                .bit_not_vec::<P>(
                    config,
                    &hint_lt_lower_plus_one,
                    &label.child("fused_bounds/hint_gt_lower"),
                )
                .map_err(OnlineError::from)?,
        );
        hint_lt_upper.push(hint_lt);
    }

    let mut packed_left_parts = Vec::with_capacity(candidate_count * 2);
    let mut packed_right_parts = Vec::with_capacity(candidate_count * 2);
    for idx in 0..candidate_count {
        packed_left_parts.push(z_lt_gamma[idx].clone());
        packed_left_parts.push(hint_gt_lower[idx].clone());
        packed_right_parts.push(z_gt_upper[idx].clone());
        packed_right_parts.push(hint_lt_upper[idx].clone());
    }
    let product_label = root_label.child("all_candidate_fused_bound_products");
    let packed_left = runtime
        .concat_bit_share_vecs_for_runtime_batch::<P>(
            config,
            &packed_left_parts,
            &product_label.child("left"),
        )
        .map_err(OnlineError::from)?;
    let packed_right = runtime
        .concat_bit_share_vecs_for_runtime_batch::<P>(
            config,
            &packed_right_parts,
            &product_label.child("right"),
        )
        .map_err(OnlineError::from)?;
    runtime
        .drive_bit_and_vec::<P, E>(config, &packed_left, &packed_right, &product_label, entropy)
        .map_err(OnlineError::from)?;
    let packed_and = strict_collected_value(
        runtime
            .collect_bit_and_vec::<P>(config, &product_label)
            .map_err(OnlineError::from)?,
    )?;

    let mut z_ok_by_candidate = Vec::with_capacity(candidate_count);
    let mut h_bits_by_candidate = Vec::with_capacity(candidate_count);
    for idx in 0..candidate_count {
        let label = &labels[idx];
        let offset = idx * (z_lane_count + hint_lane_count);
        let z_and = runtime
            .slice_bit_share_vec_lanes_for_runtime_chunk::<P>(
                config,
                &packed_and,
                offset..offset + z_lane_count,
                &label.child("fused_bound_products/z_and"),
            )
            .map_err(OnlineError::from)?;
        let hint_and = runtime
            .slice_bit_share_vec_lanes_for_runtime_chunk::<P>(
                config,
                &packed_and,
                offset + z_lane_count..offset + z_lane_count + hint_lane_count,
                &label.child("fused_bound_products/hint_and"),
            )
            .map_err(OnlineError::from)?;
        let z_ok = match runtime.bit_or_from_and_vec::<P>(
            config,
            &z_lt_gamma[idx],
            &z_gt_upper[idx],
            &z_and,
            &label.child("fused_bound_products/z_bound_ok"),
        ) {
            Ok(value) => value,
            Err(err) => return Err(OnlineError::from(err)),
        };
        z_ok_by_candidate.push(z_ok);
        let hint_or = match runtime.bit_or_from_and_vec::<P>(
            config,
            &hint_gt_lower[idx],
            &hint_lt_upper[idx],
            &hint_and,
            &label.child("fused_bound_products/hint_interval_or"),
        ) {
            Ok(value) => value,
            Err(err) => return Err(OnlineError::from(err)),
        };
        let eq_highbits = match runtime.public_lane_select_bit_vec::<P>(
            config,
            &hint_or,
            &hint_and,
            &wraps_zero_by_candidate[idx],
            &label.child("fused_bound_products/hint_eq_highbits"),
        ) {
            Ok(value) => value,
            Err(err) => return Err(OnlineError::from(err)),
        };
        h_bits_by_candidate.push(
            match runtime.bit_not_vec::<P>(
                config,
                &eq_highbits,
                &label.child("fused_bound_products/hint_bits"),
            ) {
                Ok(value) => value,
                Err(err) => return Err(OnlineError::from(err)),
            },
        );
    }

    Ok((z_ok_by_candidate, h_bits_by_candidate))
}

#[cfg(test)]
fn strict_run_all_bits_true_packed_batch<P, T, L, C, E>(
    bits_by_candidate: &[ProductionBitShareVec],
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
    if bits_by_candidate.is_empty() {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let bits_by_coeff = runtime
        .transpose_bit_share_vec_lanes_for_runtime_batch::<P>(
            config,
            bits_by_candidate,
            &label.child("candidate_lanes"),
        )
        .map_err(OnlineError::from)?;
    let violation_bits = bits_by_coeff
        .iter()
        .enumerate()
        .map(|(idx, bits)| {
            runtime
                .bit_not_vec::<P>(config, bits, &label.child(format!("not_bits_{idx}")))
                .map_err(OnlineError::from)
        })
        .collect::<Result<Vec<_>, OnlineError>>()?;
    let any_violation = strict_run_private_or_reduce_packed::<P, _, _, _, _>(
        violation_bits,
        runtime,
        config,
        &label.child("any_violation"),
        entropy,
    )?;
    let result = runtime
        .bit_not_vec::<P>(config, &any_violation, &label.child("all_bits_true_packed"))
        .map_err(OnlineError::from)?;
    runtime
        .split_bit_share_vec_lanes::<P>(config, &result, &label.child("candidate_results"))
        .map_err(OnlineError::from)
}

fn strict_run_private_or_reduce_packed<P, T, L, C, E>(
    mut bits: Vec<ProductionBitShareVec>,
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    label: &Power2RoundTranscriptLabel,
    entropy: &mut E,
) -> Result<ProductionBitShareVec, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
    E: ProductionVectorItMpcEntropy,
{
    if bits.is_empty() {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    while bits.len() > 1 {
        let layer_idx = bit_width_for_private_reduce_layer(bits.len());
        let layer_label = label.child(format!("or_layer_{layer_idx}"));
        let pair_count = bits.len() / 2;
        let mut left = Vec::with_capacity(pair_count);
        let mut right = Vec::with_capacity(pair_count);
        let mut next = Vec::with_capacity(pair_count + bits.len() % 2);
        for pair in bits[..pair_count * 2].chunks_exact(2) {
            left.push(pair[0].clone());
            right.push(pair[1].clone());
        }
        if let Some(remainder) = bits.get(pair_count * 2) {
            next.push(remainder.clone());
        }
        let packed_left = runtime
            .pack_bit_share_vecs_for_runtime_batch::<P>(config, &left, &layer_label.child("left"))
            .map_err(OnlineError::from)?;
        let packed_right = runtime
            .pack_bit_share_vecs_for_runtime_batch::<P>(config, &right, &layer_label.child("right"))
            .map_err(OnlineError::from)?;
        runtime
            .drive_bit_and_vec::<P, E>(
                config,
                &packed_left,
                &packed_right,
                &layer_label.child("and"),
                entropy,
            )
            .map_err(OnlineError::from)?;
        let packed_and = strict_collected_value(
            runtime
                .collect_bit_and_vec::<P>(config, &layer_label.child("and"))
                .map_err(OnlineError::from)?,
        )?;
        let and_chunks = runtime
            .unpack_bit_share_vec_runtime_batch::<P>(
                config,
                &packed_and,
                left.first()
                    .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?
                    .len(),
                &layer_label.child("and_chunks"),
            )
            .map_err(OnlineError::from)?;
        for ((left_bit, right_bit), and_bit) in left
            .into_iter()
            .zip(right.into_iter())
            .zip(and_chunks.into_iter())
        {
            next.push(
                runtime
                    .bit_or_from_and_vec::<P>(
                        config,
                        &left_bit,
                        &right_bit,
                        &and_bit,
                        &layer_label.child(format!("or_{}", next.len())),
                    )
                    .map_err(OnlineError::from)?,
            );
        }
        bits = next;
    }
    bits.pop()
        .ok_or(OnlineError::StrictResponseCheckShapeMismatch)
}

fn bit_width_for_private_reduce_layer(width: usize) -> usize {
    let mut value = width;
    let mut layers = 0usize;
    while value > 1 {
        value = value.div_ceil(2);
        layers += 1;
    }
    layers
}

#[cfg(test)]
fn strict_run_hint_bits_checks_batch<P, T, L, C, E>(
    states: &mut [StrictRuntimeHintBitsCheckState],
    labels: &[Power2RoundTranscriptLabel],
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    entropy: &mut E,
) -> Result<Vec<ProductionBitShareVec>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
    E: ProductionVectorItMpcEntropy,
{
    if states.len() != labels.len() {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    while states.iter().any(|state| state.gt_lower.is_none()) {
        let mut drove = vec![false; states.len()];
        for (idx, state) in states.iter_mut().enumerate() {
            if state.gt_lower.is_none() {
                state.drive_packed_bounds_step::<P, _, _, _, _>(runtime, config, entropy)?;
                drove[idx] = true;
            }
        }
        for (idx, state) in states.iter_mut().enumerate() {
            if drove[idx] {
                strict_collected_unit(
                    state.collect_packed_bounds_step::<P, _, _, _>(runtime, config)?,
                )?;
            }
        }
    }
    for (state, label) in states.iter_mut().zip(labels.iter()) {
        state.drive_interval_and_step::<P, _, _, _, _>(runtime, config, label, entropy)?;
    }
    for (state, label) in states.iter_mut().zip(labels.iter()) {
        strict_collected_unit(
            state.collect_interval_and_finalize::<P, _, _, _>(runtime, config, label)?,
        )?;
    }
    states
        .iter()
        .map(|state| {
            state
                .hint_bits()
                .cloned()
                .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)
        })
        .collect()
}

#[cfg(test)]
fn strict_run_hint_bits_checks_chunked_batch<P, T, L, C, E>(
    hint_bits_input_by_candidate: &[Vec<ProductionBitShareVec>],
    w1_by_candidate: &[Vec<u32>],
    labels: &[Power2RoundTranscriptLabel],
    max_lanes_per_chunk: usize,
    runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    config: &DkgConfig,
    root_label: &Power2RoundTranscriptLabel,
    entropy: &mut E,
) -> Result<Vec<ProductionBitShareVec>, OnlineError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
    E: ProductionVectorItMpcEntropy,
{
    if hint_bits_input_by_candidate.is_empty()
        || hint_bits_input_by_candidate.len() != labels.len()
        || hint_bits_input_by_candidate.len() != w1_by_candidate.len()
    {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let lane_count = hint_bits_input_by_candidate[0]
        .first()
        .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?
        .len();
    if hint_bits_input_by_candidate
        .iter()
        .any(|bits| bits.len() != 23 || bits.iter().any(|bit| bit.len() != lane_count))
        || w1_by_candidate.iter().any(|w1| w1.len() != lane_count)
    {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let ranges = strict_lane_chunk_ranges(lane_count, max_lanes_per_chunk)?;
    let mut h_chunks_by_candidate =
        vec![Vec::with_capacity(ranges.len()); hint_bits_input_by_candidate.len()];
    for (chunk_idx, range) in ranges.iter().cloned().enumerate() {
        let hint_labels = labels
            .iter()
            .map(|label| label.child(format!("chunk_{chunk_idx}")))
            .collect::<Vec<_>>();
        let mut states = hint_bits_input_by_candidate
            .iter()
            .zip(w1_by_candidate.iter())
            .zip(hint_labels.iter())
            .map(|((bits, w1), label)| {
                let chunk_bits = strict_slice_bit_columns_for_chunk::<P, _, _, _>(
                    runtime,
                    config,
                    bits,
                    range.clone(),
                    &label.child("r_bits"),
                )?;
                StrictRuntimeHintBitsCheckState::new::<P, _, _, _>(
                    runtime,
                    config,
                    &chunk_bits,
                    &w1[range.clone()],
                    label,
                )
            })
            .collect::<Result<Vec<_>, OnlineError>>()?;
        let h_chunks = strict_run_hint_bits_checks_batch::<P, _, _, _, _>(
            &mut states,
            &hint_labels,
            runtime,
            config,
            entropy,
        )?;
        for (candidate_idx, h_chunk) in h_chunks.into_iter().enumerate() {
            h_chunks_by_candidate[candidate_idx].push(h_chunk);
        }
    }
    strict_concat_candidate_bit_chunks::<P, _, _, _>(
        runtime,
        config,
        &h_chunks_by_candidate,
        &root_label.child("candidate_h_chunks"),
    )
}

#[cfg(test)]
fn strict_run_hint_weight_checks_packed_batch<P, T, L, C, E>(
    h_bits_by_candidate: &[ProductionBitShareVec],
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
    if h_bits_by_candidate.is_empty()
        || h_bits_by_candidate
            .iter()
            .any(|bits| bits.len() != P::K * P::N)
    {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let bits_by_coeff = runtime
        .transpose_bit_share_vec_lanes_for_runtime_batch::<P>(
            config,
            h_bits_by_candidate,
            &label.child("candidate_lanes"),
        )
        .map_err(OnlineError::from)?;
    let mut threshold = runtime
        .start_bit_sum_leq_public_vec::<P>(
            config,
            &bits_by_coeff,
            P::OMEGA as u32,
            &label.child("hint_weight_leq_omega_packed"),
        )
        .map_err(OnlineError::from)?;
    while threshold.result().is_none() {
        runtime
            .drive_bit_sum_leq_public_vec_step::<P, E>(config, &mut threshold, entropy)
            .map_err(OnlineError::from)?;
        strict_collected_unit(
            runtime
                .collect_bit_sum_leq_public_vec_step::<P>(config, &mut threshold)
                .map_err(OnlineError::from)?,
        )?;
    }
    let result = threshold
        .result()
        .cloned()
        .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
    runtime
        .split_bit_share_vec_lanes::<P>(config, &result, &label.child("candidate_results"))
        .map_err(OnlineError::from)
}

#[cfg(test)]
fn strict_run_private_bit_sum_accumulator<P, T, L, C, E>(
    bits: &[ProductionBitShareVec],
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
    if bits.is_empty() {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let mut sum = runtime
        .start_bit_sum_leq_public_vec::<P>(config, bits, bits.len() as u32, label)
        .map_err(OnlineError::from)?;
    while sum.result().is_none() {
        runtime
            .drive_bit_sum_leq_public_vec_step::<P, E>(config, &mut sum, entropy)
            .map_err(OnlineError::from)?;
        strict_collected_unit(
            runtime
                .collect_bit_sum_leq_public_vec_step::<P>(config, &mut sum)
                .map_err(OnlineError::from)?,
        )?;
    }
    Ok(sum.accumulator_bits_le().to_vec())
}

#[cfg(test)]
fn strict_run_hint_weight_checks_chunked_batch<P, T, L, C, E>(
    h_bits_by_candidate: &[ProductionBitShareVec],
    max_lanes_per_chunk: usize,
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
    if h_bits_by_candidate.is_empty()
        || h_bits_by_candidate
            .iter()
            .any(|bits| bits.len() != P::K * P::N)
    {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let ranges = strict_lane_chunk_ranges(P::K * P::N, max_lanes_per_chunk)?;
    let mut weighted_units_by_candidate = vec![Vec::new(); h_bits_by_candidate.len()];
    for (candidate_idx, h_bits) in h_bits_by_candidate.iter().enumerate() {
        for (chunk_idx, range) in ranges.iter().cloned().enumerate() {
            let chunk = runtime
                .slice_bit_share_vec_lanes_for_runtime_chunk::<P>(
                    config,
                    h_bits,
                    range,
                    &label.child(format!("candidate_{candidate_idx}/chunk_{chunk_idx}/bits")),
                )
                .map_err(OnlineError::from)?;
            let lanes = runtime
                .split_bit_share_vec_lanes::<P>(
                    config,
                    &chunk,
                    &label.child(format!("candidate_{candidate_idx}/chunk_{chunk_idx}/lanes")),
                )
                .map_err(OnlineError::from)?;
            let count_bits = strict_run_private_bit_sum_accumulator::<P, _, _, _, _>(
                &lanes,
                runtime,
                config,
                &label.child(format!("candidate_{candidate_idx}/chunk_{chunk_idx}/count")),
                entropy,
            )?;
            for (bit_idx, bit) in count_bits.iter().enumerate() {
                let weight = (1usize << bit_idx).min(P::OMEGA as usize + 1);
                for _ in 0..weight {
                    weighted_units_by_candidate[candidate_idx].push(bit.clone());
                }
            }
        }
    }
    let unit_count = weighted_units_by_candidate
        .first()
        .ok_or(OnlineError::StrictResponseCheckShapeMismatch)?
        .len();
    if unit_count == 0
        || weighted_units_by_candidate
            .iter()
            .any(|units| units.len() != unit_count)
    {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }
    let bits_by_unit = (0..unit_count)
        .map(|unit_idx| {
            let candidate_bits = weighted_units_by_candidate
                .iter()
                .map(|units| units[unit_idx].clone())
                .collect::<Vec<_>>();
            runtime
                .transpose_bit_share_vec_lanes_for_runtime_batch::<P>(
                    config,
                    &candidate_bits,
                    &label.child(format!("unit_{unit_idx}")),
                )
                .map_err(OnlineError::from)
                .and_then(|mut lanes| {
                    if lanes.len() != 1 {
                        return Err(OnlineError::StrictResponseCheckShapeMismatch);
                    }
                    Ok(lanes.remove(0))
                })
        })
        .collect::<Result<Vec<_>, OnlineError>>()?;
    let mut threshold = runtime
        .start_bit_sum_leq_public_vec::<P>(
            config,
            &bits_by_unit,
            P::OMEGA as u32,
            &label.child("hint_weight_chunked_total_leq_omega"),
        )
        .map_err(OnlineError::from)?;
    while threshold.result().is_none() {
        runtime
            .drive_bit_sum_leq_public_vec_step::<P, E>(config, &mut threshold, entropy)
            .map_err(OnlineError::from)?;
        strict_collected_unit(
            runtime
                .collect_bit_sum_leq_public_vec_step::<P>(config, &mut threshold)
                .map_err(OnlineError::from)?,
        )?;
    }
    let result = threshold
        .result()
        .cloned()
        .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
    runtime
        .split_bit_share_vec_lanes::<P>(config, &result, &label.child("candidate_results"))
        .map_err(OnlineError::from)
}

fn strict_bit_width_for_sum_inputs(input_count: usize) -> usize {
    let mut width = 1usize;
    let mut capacity = 2usize;
    while capacity <= input_count {
        width += 1;
        capacity <<= 1;
    }
    width
}

fn strict_threshold_reducer_layer_score(input_count: usize) -> Option<usize> {
    if input_count == 0 {
        return None;
    }
    let width = strict_bit_width_for_sum_inputs(input_count);
    let mut columns = vec![0usize; width];
    columns[0] = input_count;
    let mut csa_layers = 0usize;
    loop {
        let mut triples = Vec::new();
        let mut next_columns = vec![0usize; columns.len()];
        for (column, &count) in columns.iter().enumerate() {
            let triple_count = count / 3;
            triples.extend(std::iter::repeat_n(column, triple_count));
            next_columns[column] += count % 3;
        }
        if triples.is_empty() {
            break;
        }
        next_columns.push(0);
        for column in triples {
            if column + 1 >= next_columns.len() {
                next_columns.resize(column + 2, 0);
            }
            next_columns[column] += 1;
            next_columns[column + 1] += 1;
        }
        columns = next_columns;
        csa_layers += 2;
    }

    let normal_width = width + 1;
    let mut ripple_layers = 0usize;
    let mut carry = 0usize;
    for column in 0..normal_width {
        let operands = columns.get(column).copied().unwrap_or_default() + carry;
        match operands {
            0 | 1 => carry = 0,
            2 => {
                ripple_layers += 1;
                carry = 1;
            }
            3 => {
                ripple_layers += 2;
                carry = 1;
            }
            _ => return None,
        }
    }
    Some(csa_layers + ripple_layers)
}

fn strict_public_zero_threshold_padding(input_count: usize, max_padding: usize) -> usize {
    let Some(base_score) = strict_threshold_reducer_layer_score(input_count) else {
        return 0;
    };
    let mut best_padding = 0usize;
    let mut best_score = base_score;
    for padding in 1..=max_padding {
        let Some(score) = strict_threshold_reducer_layer_score(input_count + padding) else {
            continue;
        };
        if score < best_score {
            best_score = score;
            best_padding = padding;
        }
    }
    best_padding
}

fn strict_run_fused_validity_checks_batch<P, T, L, C, E>(
    z_coeff_ok_by_candidate: &[ProductionBitShareVec],
    h_bits_by_candidate: &[ProductionBitShareVec],
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
    if z_coeff_ok_by_candidate.is_empty()
        || h_bits_by_candidate.len() != z_coeff_ok_by_candidate.len()
        || z_coeff_ok_by_candidate
            .iter()
            .any(|bits| bits.len() != P::L * P::N)
        || h_bits_by_candidate
            .iter()
            .any(|bits| bits.len() != P::K * P::N)
    {
        return Err(OnlineError::StrictResponseCheckShapeMismatch);
    }

    let z_bits_by_coeff = runtime
        .transpose_bit_share_vec_lanes_for_runtime_batch::<P>(
            config,
            z_coeff_ok_by_candidate,
            &label.child("z_coeff_candidate_lanes"),
        )
        .map_err(OnlineError::from)?;
    let z_violation_bits = z_bits_by_coeff
        .iter()
        .enumerate()
        .map(|(idx, bits)| {
            runtime
                .bit_not_vec::<P>(config, bits, &label.child(format!("z_violation_{idx}")))
                .map_err(OnlineError::from)
        })
        .collect::<Result<Vec<_>, OnlineError>>()?;
    let z_any_violation = strict_run_private_or_reduce_packed::<P, _, _, _, _>(
        z_violation_bits,
        runtime,
        config,
        &label.child("z_any_violation"),
        entropy,
    )?;

    let mut threshold_inputs = runtime
        .transpose_bit_share_vec_lanes_for_runtime_batch::<P>(
            config,
            h_bits_by_candidate,
            &label.child("hint_candidate_lanes"),
        )
        .map_err(OnlineError::from)?;

    // A single z-bound failure or missing BCC admission must invalidate the
    // candidate regardless of hint weight. Encode those as omega+1 units in
    // the same private threshold check that counts hint bits.
    let penalty_units = P::OMEGA as usize + 1;
    threshold_inputs.extend(std::iter::repeat_n(z_any_violation.clone(), penalty_units));
    let bcc_admission_failed = runtime
        .public_bit_share_vec::<P>(
            config,
            &label.child("bcc_admission_failed"),
            false,
            z_coeff_ok_by_candidate.len(),
        )
        .map_err(OnlineError::from)?;
    threshold_inputs.extend(std::iter::repeat_n(bcc_admission_failed, penalty_units));
    let false_padding = strict_public_zero_threshold_padding(threshold_inputs.len(), 128);
    if false_padding != 0 {
        let public_false = runtime
            .public_bit_share_vec::<P>(
                config,
                &label.child("threshold_public_false_padding"),
                false,
                z_coeff_ok_by_candidate.len(),
            )
            .map_err(OnlineError::from)?;
        threshold_inputs.extend(std::iter::repeat_n(public_false, false_padding));
    }

    let mut threshold = runtime
        .start_bit_sum_leq_public_vec::<P>(
            config,
            &threshold_inputs,
            P::OMEGA as u32,
            &label.child("validity_threshold"),
        )
        .map_err(OnlineError::from)?;
    while threshold.result().is_none() {
        runtime
            .drive_bit_sum_leq_public_vec_step::<P, E>(config, &mut threshold, entropy)
            .map_err(OnlineError::from)?;
        strict_collected_unit(
            runtime
                .collect_bit_sum_leq_public_vec_step::<P>(config, &mut threshold)
                .map_err(OnlineError::from)?,
        )?;
    }
    let valid = threshold
        .result()
        .cloned()
        .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
    runtime
        .split_bit_share_vec_lanes::<P>(config, &valid, &label.child("candidate_results"))
        .map_err(OnlineError::from)
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
        let chunk_policy = ProductionBatchSizingPolicy::for_suite::<P>();
        let root_label = Power2RoundTranscriptLabel::root(
            &self.config,
            strict_signing_session_id(request, &token_session_ids).0,
        )
        .child("strict_signing");

        let mut candidate_inputs = Vec::with_capacity(batch.len());
        let mut candidate_labels = Vec::with_capacity(batch.len());
        let mut z_shares = Vec::with_capacity(batch.len());
        let (started_at, counters_before) = self.profile_start();
        for idx in 0..batch.len() {
            let token = &batch.tokens()[idx];
            let meta = &metadata[idx];
            let input = self.candidate_inputs[idx].clone();
            if input.token_session_id != token.session_id {
                return Err(OnlineError::StrictResponseCheckShapeMismatch);
            }
            input.validate_for::<P>()?;
            let label = root_label.child(format!("candidate_{idx}"));
            let z_share = strict_prepare_runtime_z_share::<P, _, _, _>(
                &self.runtime,
                &self.config,
                &input.y_share,
                &input.s1_share,
                &meta.ctilde,
                &label.child("response"),
            )?;
            candidate_inputs.push(input);
            candidate_labels.push(label);
            z_shares.push(z_share);
        }
        self.profile_finish(
            STRICT_PROFILE_Z_RESPONSE_PREP_BATCH,
            None,
            started_at,
            counters_before,
        );

        let (started_at, counters_before) = self.profile_start();
        let mut hint_approx_shares = Vec::with_capacity(batch.len());
        for idx in 0..batch.len() {
            let meta = &metadata[idx];
            let input = &candidate_inputs[idx];
            let label = &candidate_labels[idx];
            let z_share = &z_shares[idx];

            let hint_approx = match (&input.w_share, &input.as1_share) {
                (Some(w_share), Some(as1_share)) => {
                    strict_runtime_hint_approx_share_from_precomputed::<P, _, _, _>(
                        &self.runtime,
                        &self.config,
                        &self.public_key,
                        &meta.ctilde,
                        w_share,
                        as1_share,
                        &label.child("hint_approx_precomputed"),
                    )?
                }
                (None, None) => strict_runtime_hint_approx_share::<P, _, _, _>(
                    &self.runtime,
                    &self.config,
                    &self.public_key,
                    &meta.ctilde,
                    z_share,
                    &label.child("hint_approx"),
                )?,
                _ => return Err(OnlineError::StrictResponseCheckShapeMismatch),
            };
            hint_approx_shares.push(hint_approx);
        }
        self.profile_finish(
            STRICT_PROFILE_HINT_APPROX_BATCH,
            None,
            started_at,
            counters_before,
        );

        let (started_at, counters_before) = self.profile_start();
        let z_lane_count = P::L * P::N;
        let hint_lane_count = P::K * P::N;
        let mut fused_value_parts = Vec::with_capacity(batch.len() * 2);
        let mut fused_mask_value_parts = Vec::with_capacity(batch.len() * 2);
        for idx in 0..batch.len() {
            let input = &candidate_inputs[idx];
            fused_value_parts.push(z_shares[idx].clone());
            fused_value_parts.push(hint_approx_shares[idx].clone());
            fused_mask_value_parts.push(input.z_mask_value.clone());
            fused_mask_value_parts.push(input.hint_mask_value.clone());
        }
        let fused_value = self
            .runtime
            .concat_share_vecs_for_runtime_batch::<P>(
                &self.config,
                &fused_value_parts,
                &root_label.child("fused_all_candidates_canonical/value"),
            )
            .map_err(OnlineError::from)?;
        let fused_mask_value = self
            .runtime
            .concat_share_vecs_for_runtime_batch::<P>(
                &self.config,
                &fused_mask_value_parts,
                &root_label.child("fused_all_candidates_canonical/mask_value"),
            )
            .map_err(OnlineError::from)?;
        let fused_mask_bits_by_bit = (0..23)
            .map(|bit_idx| {
                let mut parts = Vec::with_capacity(batch.len() * 2);
                for input in &candidate_inputs {
                    parts.push(input.z_mask_bits_by_bit[bit_idx].clone());
                    parts.push(input.hint_mask_bits_by_bit[bit_idx].clone());
                }
                self.runtime
                    .concat_bit_share_vecs_for_runtime_batch::<P>(
                        &self.config,
                        &parts,
                        &root_label
                            .child(format!("fused_all_candidates_canonical/mask_bit_{bit_idx}")),
                    )
                    .map_err(OnlineError::from)
            })
            .collect::<Result<Vec<_>, OnlineError>>()?;
        let mut fused_decomps = vec![StrictCanonicalBatchItem {
            state: ProductionCanonicalBitDecompositionState::new::<P, _, _, _>(
                &self.runtime,
                &self.config,
                fused_value,
                fused_mask_value,
                fused_mask_bits_by_bit,
            )
            .map_err(OnlineError::from)?,
            label: root_label.child("fused_all_candidates_canonical"),
        }];
        let fused_bits_by_candidate = strict_certify_canonical_bits_batch::<P, _, _, _, _>(
            &mut fused_decomps,
            &mut self.runtime,
            &self.config,
            &mut self.entropy,
        )?;
        let fused_bits_all_candidates = fused_bits_by_candidate
            .first()
            .ok_or(OnlineError::StrictSigningRuntimeSlotIncomplete)?;
        let mut z_bits_by_candidate = Vec::with_capacity(batch.len());
        let mut hint_bits_input_by_candidate = Vec::with_capacity(batch.len());
        for idx in 0..batch.len() {
            let label = &candidate_labels[idx];
            let mut z_bits = Vec::with_capacity(23);
            let mut hint_bits = Vec::with_capacity(23);
            let offset = idx * (z_lane_count + hint_lane_count);
            for (bit_idx, bits) in fused_bits_all_candidates.iter().enumerate() {
                z_bits.push(
                    self.runtime
                        .slice_bit_share_vec_lanes_for_runtime_chunk::<P>(
                            &self.config,
                            bits,
                            offset..offset + z_lane_count,
                            &label.child(format!("fused_canonical/z_bit_{bit_idx}")),
                        )
                        .map_err(OnlineError::from)?,
                );
                hint_bits.push(
                    self.runtime
                        .slice_bit_share_vec_lanes_for_runtime_chunk::<P>(
                            &self.config,
                            bits,
                            offset + z_lane_count..offset + z_lane_count + hint_lane_count,
                            &label.child(format!("fused_canonical/hint_bit_{bit_idx}")),
                        )
                        .map_err(OnlineError::from)?,
                );
            }
            z_bits_by_candidate.push(z_bits);
            hint_bits_input_by_candidate.push(hint_bits);
        }
        self.profile_finish(
            STRICT_PROFILE_Z_CANONICAL_DECOMPOSITION_BATCH,
            None,
            started_at,
            counters_before,
        );

        let (started_at, counters_before) = self.profile_start();
        self.profile_finish(
            STRICT_PROFILE_HINT_CANONICAL_DECOMPOSITION_BATCH,
            None,
            started_at,
            counters_before,
        );

        let (started_at, counters_before) = self.profile_start();
        let (z_bound_coeff_ok_by_candidate, h_bits_by_candidate) =
            match strict_run_fused_z_bound_and_hint_bits_batch::<P, _, _, _, _>(
                &z_bits_by_candidate,
                &hint_bits_input_by_candidate,
                &candidate_inputs
                    .iter()
                    .map(|input| input.w1.clone())
                    .collect::<Vec<_>>(),
                &candidate_labels
                    .iter()
                    .map(|label| label.child("fused_bounds"))
                    .collect::<Vec<_>>(),
                &mut self.runtime,
                &self.config,
                &root_label.child("fused_z_hint_bounds"),
                &mut self.entropy,
            ) {
                Ok(result) => result,
                Err(err) => return Err(err),
            };
        self.profile_finish(
            STRICT_PROFILE_Z_BOUND_CHECKS_BATCH,
            None,
            started_at,
            counters_before,
        );
        let (started_at, counters_before) = self.profile_start();
        self.profile_finish(
            STRICT_PROFILE_HINT_HIGHBITS_CHECKS_BATCH,
            None,
            started_at,
            counters_before,
        );

        let (started_at, counters_before) = self.profile_start();
        let valid_bits = match strict_run_fused_validity_checks_batch::<P, _, _, _, _>(
            &z_bound_coeff_ok_by_candidate,
            &h_bits_by_candidate,
            &mut self.runtime,
            &self.config,
            &root_label.child("fused_validity"),
            &mut self.entropy,
        ) {
            Ok(result) => result,
            Err(err) => return Err(err),
        };
        self.profile_finish(
            STRICT_PROFILE_FUSED_VALIDITY_BATCH,
            None,
            started_at,
            counters_before,
        );

        let mut candidates = Vec::with_capacity(batch.len());
        for idx in 0..batch.len() {
            let meta = &metadata[idx];
            let z_share = &z_shares[idx];
            let h_bits = &h_bits_by_candidate[idx];
            let valid_bit = valid_bits[idx].clone();
            candidates.push(
                StrictRuntimeCandidateHandle::new_runtime_prepared(
                    meta.priority,
                    meta.ctilde.clone(),
                    z_share.clone(),
                )
                .with_h_bits(h_bits.clone())
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
        self.profile_finish(
            STRICT_PROFILE_PRIORITY_SELECTION_BATCH,
            None,
            started_at,
            counters_before,
        );

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
        let h_value_shares = h_values
            .iter()
            .map(|bits| bits.certified_share().clone())
            .collect::<Vec<_>>();
        let combined_values = candidates
            .iter()
            .zip(h_value_shares.iter())
            .enumerate()
            .map(|(idx, candidate)| {
                let (candidate, h_share) = candidate;
                self.runtime
                    .concat_share_vecs_for_runtime_batch::<P>(
                        &self.config,
                        &[candidate.z_share().clone(), h_share.clone()],
                        &root_label.child(format!("selected_z_h/candidate_{idx}")),
                    )
                    .map_err(OnlineError::from)
            })
            .collect::<Result<Vec<_>, OnlineError>>()?;
        let opened_selected_lanes = strict_selected_share_opening_chunks::<P, _, _, _, _>(
            &mut self.runtime,
            &self.config,
            &selected_bits,
            &combined_values,
            chunk_policy.max_vector_lanes_per_chunk,
            &root_label.child("selected_z_h_opening_chunks"),
            &mut self.entropy,
        )?;
        self.profile_finish(
            STRICT_PROFILE_SELECTED_PRODUCTS_BATCH,
            None,
            started_at,
            counters_before,
        );
        let z_lane_count = P::L * P::N;
        let h_lane_count = P::K * P::N;
        if opened_selected_lanes.len() != z_lane_count + h_lane_count {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        let opened_z_lanes = opened_selected_lanes[..z_lane_count].to_vec();
        let opened_h_lanes =
            opened_selected_lanes[z_lane_count..z_lane_count + h_lane_count].to_vec();
        let opened_z = strict_runtime_lanes_to_opened_polyvec::<P>(&opened_z_lanes, P::L)?;
        let opened_h = strict_hint_bits_to_polyvec::<P>(&opened_h_lanes)?;

        let (started_at, counters_before) = self.profile_start();
        let runtime_evidence = self.runtime.runtime_evidence().map_err(OnlineError::from)?;
        let certificate =
            match StrictSigningVectorRuntimeCertificate::new_for_strict_signing(runtime_evidence) {
                Ok(certificate) => certificate,
                Err(err) => {
                    #[cfg(test)]
                    {
                        eprintln!("strict signing runtime certificate failed: {err:?}");
                        self.print_profile();
                    }
                    return Err(err);
                }
            };
        self.profile_finish("runtime_certificate", None, started_at, counters_before);
        #[cfg(feature = "production-release-checks")]
        if let Err(err) =
            ensure_strict_live_vector_profile_release_envelope::<P>(&self.profile, metadata.len())
        {
            #[cfg(test)]
            {
                eprintln!("strict live vector profile release envelope failed: {err:?}");
                self.print_profile();
            }
            return Err(err);
        }
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
    /// Strict signing mask inventory was already consumed.
    StrictSigningMaskAlreadyConsumed(StrictSigningMaskInventoryId),
    /// Strict signing comparison/threshold helper inventory was already consumed.
    StrictSigningHelperAlreadyConsumed(StrictSigningHelperInventoryId),
    /// Strict signing mask-use log I/O failed.
    StrictSigningMaskUseLogIo {
        /// Storage operation.
        operation: &'static str,
    },
    /// Strict signing mask-use log was malformed.
    StrictSigningMaskUseLogCorrupt {
        /// One-based line number.
        line: usize,
    },
    /// Strict signing helper-use log I/O failed.
    StrictSigningHelperUseLogIo {
        /// Storage operation.
        operation: &'static str,
    },
    /// Strict signing helper-use log was malformed.
    StrictSigningHelperUseLogCorrupt {
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
    /// Empirical token-batch sizing input was invalid.
    TokenBatchSizingUnavailable,
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
            Self::StrictSigningMaskAlreadyConsumed(id) => {
                write!(
                    f,
                    "strict signing mask inventory already consumed: {} {}",
                    hex32(id.session_id.0),
                    hex32(id.inventory_hash)
                )
            }
            Self::StrictSigningHelperAlreadyConsumed(id) => {
                write!(
                    f,
                    "strict signing helper inventory already consumed: {} {:?} {}",
                    hex32(id.session_id.0),
                    id.kind,
                    hex32(id.inventory_hash)
                )
            }
            Self::StrictSigningMaskUseLogIo { operation } => {
                write!(
                    f,
                    "strict signing mask-use log I/O failed during {operation}"
                )
            }
            Self::StrictSigningMaskUseLogCorrupt { line } => {
                write!(f, "strict signing mask-use log corrupt at line {line}")
            }
            Self::StrictSigningHelperUseLogIo { operation } => {
                write!(
                    f,
                    "strict signing helper-use log I/O failed during {operation}"
                )
            }
            Self::StrictSigningHelperUseLogCorrupt { line } => {
                write!(f, "strict signing helper-use log corrupt at line {line}")
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
            Self::TokenBatchSizingUnavailable => {
                write!(f, "strict signing token batch sizing unavailable")
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
        certify_preprocessing_token, Commitment, NonceCommitment, PartyPreprocessInput,
        SessionRegistry,
    };
    #[cfg(feature = "production-release-checks")]
    use crate::local::{
        preprocessing_release_token_log_entry, preprocessing_runtime_transcript_aggregate_hash,
        FilePreprocessingReleaseTokenBatchLog, PreprocessingCertificationRuntimeTranscripts,
        PreprocessingVectorRuntimeCertificate,
    };
    use std::cell::RefCell;
    use std::rc::Rc;
    use talus_core::{compute_tr, Coeff, MlDsa44, MlDsa65, MlDsa87};

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

    #[derive(Clone, Debug, Default)]
    struct ZeroProductionVectorEntropy;

    impl ProductionVectorItMpcEntropy for ZeroProductionVectorEntropy {
        fn fill_field_coefficients<P: MlDsaParams>(
            &mut self,
            _label: &Power2RoundTranscriptLabel,
            count: usize,
        ) -> Result<Vec<Coeff>, DkgError> {
            Ok(vec![0; count])
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

    fn strict_test_dkg_key_package_from_s1_lanes(
        config: &DkgConfig,
        party: PartyId,
        rho: [u8; 32],
        s1_lanes: Vec<Coeff>,
    ) -> DkgKeyPackage {
        let point = config
            .interpolation_point::<MlDsa65>(party)
            .expect("configured party");
        let s1_share =
            talus_dkg::BoundedSecretVectorShare::new::<MlDsa65>(config, party, point, s1_lanes)
                .expect("typed s1")
                .encode::<MlDsa65>(config)
                .expect("encoded s1");
        let s1_decoded = talus_dkg::BoundedSecretVectorShare::decode::<MlDsa65>(config, &s1_share)
            .expect("decoded s1");
        let s1_polyvec = PolyVec::new(
            (0..MlDsa65::L)
                .map(|row| {
                    Poly::from_coeffs(core::array::from_fn(|index| {
                        s1_decoded.coeffs[row * MlDsa65::N + index]
                    }))
                })
                .collect(),
        );
        let as1 = az_from_rho::<MlDsa65>(&rho, &s1_polyvec).expect("as1");
        let mut as1_coeffs = Vec::with_capacity(MlDsa65::K * MlDsa65::N);
        for poly in as1.polys() {
            as1_coeffs.extend_from_slice(poly.coeffs());
        }
        let as1_share =
            talus_dkg::As1SecretVectorShare::new::<MlDsa65>(config, party, point, as1_coeffs)
                .expect("typed as1")
                .encode::<MlDsa65>(config)
                .expect("encoded as1");
        DkgKeyPackage {
            suite: config.suite,
            epoch: config.epoch,
            party,
            threshold: config.threshold,
            rho,
            t1: talus_dkg::PublicT1 {
                bytes: vec![0; config.suite.t1_len()],
                coeffs: Vec::new(),
            },
            public_key: {
                let mut public_key = Vec::with_capacity(config.suite.public_key_len());
                public_key.extend_from_slice(&rho);
                public_key.extend_from_slice(&vec![0; config.suite.t1_len()]);
                public_key
            },
            s1_share: talus_dkg::DkgS1SecretShare {
                party,
                s1_share,
                pairwise_seed_shares: Vec::new(),
            },
            as1_share: talus_dkg::DkgAs1SecretShare { party, as1_share },
            certificate: talus_dkg::PublicKeyAssemblyCertificate {
                power2round: talus_dkg::Power2RoundEvidence {
                    backend_id: talus_dkg::Power2RoundBackendId::ProductionItMpc,
                    epoch: config.epoch,
                    suite: config.suite,
                    party_set_hash: [0; 32],
                    rho_hash: [0; 32],
                    output_t1_hash: [0; 32],
                    transcript_hash: [0; 32],
                },
                power2round_runtime: None,
                power2round_setup_input_hash: None,
                setup: None,
            },
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

    #[cfg(feature = "production-release-checks")]
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
        let token =
            token(byte, parties).with_precomputed_w_share(release_precomputed_w_share(byte));
        let masks = release_strict_signing_masks_for_token(&token, byte);
        let helpers = release_strict_signing_helpers_for_token(&token, byte);
        let token = token
            .with_strict_signing_canonical_masks(masks)
            .with_strict_signing_helper_material(helpers);
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token,
            release_vector_runtime_evidence_for_token(&token),
        )
        .expect("preprocessing runtime certificate");
        token.with_vector_runtime_certificate(certificate)
    }

    #[cfg(feature = "production-release-checks")]
    fn release_valid_zero_w1_token(byte: u8, parties: &[u16]) -> CertifiedToken {
        let mut token =
            token(byte, parties).with_precomputed_w_share(release_precomputed_w_share(byte));
        let masks = release_strict_signing_masks_for_token(&token, byte);
        let helpers = release_strict_signing_helpers_for_token(&token, byte);
        token = token
            .with_strict_signing_canonical_masks(masks)
            .with_strict_signing_helper_material(helpers);
        token.w1.fill(0);
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token,
            release_vector_runtime_evidence_for_token(&token),
        )
        .expect("preprocessing runtime certificate");
        token.with_vector_runtime_certificate(certificate)
    }

    #[cfg(feature = "production-release-checks")]
    fn release_validated_batch(
        tokens: Vec<CertifiedToken>,
        min_batch_size: usize,
    ) -> BccCertifiedTokenBatch {
        release_validated_batch_result(tokens, min_batch_size).expect("release batch")
    }

    #[cfg(feature = "production-release-checks")]
    fn release_validated_batch_result(
        tokens: Vec<CertifiedToken>,
        min_batch_size: usize,
    ) -> Result<BccCertifiedTokenBatch, OnlineError> {
        let entries = tokens
            .iter()
            .enumerate()
            .map(|(idx, token)| {
                preprocessing_release_token_log_entry(token, idx)
                    .map_err(|_| OnlineError::TokenPool(TokenPoolError::ReleaseLogMismatch))
            })
            .collect::<Result<Vec<_>, _>>()?;
        BccCertifiedTokenBatch::new_release_validated_with_log(tokens, min_batch_size, &entries)
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    fn release_token_file_log_for_tokens(
        name: &str,
        tokens: &[&CertifiedToken],
    ) -> FilePreprocessingReleaseTokenBatchLog {
        let path = strict_session_store_path(name);
        let mut log = FilePreprocessingReleaseTokenBatchLog::open(&path).expect("open token log");
        let entries = tokens
            .iter()
            .enumerate()
            .map(|(idx, token)| {
                preprocessing_release_token_log_entry(token, idx).expect("release token log entry")
            })
            .collect::<Vec<_>>();
        log.append_batch(&entries)
            .expect("append token log entries");
        FilePreprocessingReleaseTokenBatchLog::open(&path).expect("reopen token log")
    }

    #[cfg(feature = "production-release-checks")]
    fn release_precomputed_w_share(byte: u8) -> ProductionShareVec {
        let (config, runtime, label) = strict_test_vector_runtime_one_party(10_000 + byte as u64);
        runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child(format!("release_w_precomputed_{byte}")),
                vec![0; MlDsa65::K * MlDsa65::N],
            )
            .expect("release precomputed w share")
    }

    #[cfg(feature = "production-release-checks")]
    fn release_strict_signing_masks_for_token(
        token: &CertifiedToken,
        byte: u8,
    ) -> crate::local::StrictSigningCanonicalMaskInventory {
        let (config, runtime, label) = strict_test_vector_runtime_one_party(20_000 + byte as u64);
        let z_mask = runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child(format!("release_z_mask_{byte}")),
                vec![0; MlDsa65::L * MlDsa65::N],
            )
            .expect("release z mask");
        let hint_mask = runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child(format!("release_hint_mask_{byte}")),
                vec![0; MlDsa65::K * MlDsa65::N],
            )
            .expect("release hint mask");
        let z_bits = (0..23)
            .map(|bit| {
                runtime
                    .bit_share_vec_from_local_lanes::<MlDsa65>(
                        &config,
                        &label.child(format!("release_z_mask_bit_{byte}_{bit}")),
                        vec![0; MlDsa65::L * MlDsa65::N],
                    )
                    .expect("release z mask bit")
            })
            .collect::<Vec<_>>();
        let hint_bits = (0..23)
            .map(|bit| {
                runtime
                    .bit_share_vec_from_local_lanes::<MlDsa65>(
                        &config,
                        &label.child(format!("release_hint_mask_bit_{byte}_{bit}")),
                        vec![0; MlDsa65::K * MlDsa65::N],
                    )
                    .expect("release hint mask bit")
            })
            .collect::<Vec<_>>();
        let provenance = crate::local::StrictSigningCanonicalMaskProvenance {
            session_id: token.session_id,
            transcript_hash: token.transcript_hash,
            runtime_transcript_hash: release_vector_runtime_evidence_for_token(token)
                .transcript_hash,
            z_mask_value_label_hash: z_mask.id().label_hash,
            hint_mask_value_label_hash: hint_mask.id().label_hash,
            z_lane_count: z_mask.len(),
            hint_lane_count: hint_mask.len(),
        };
        crate::local::StrictSigningCanonicalMaskInventory::new_with_preprocessing_provenance(
            provenance, z_mask, z_bits, hint_mask, hint_bits,
        )
        .expect("release strict signing masks")
    }

    #[cfg(feature = "production-release-checks")]
    fn release_strict_signing_helpers_for_token(
        token: &CertifiedToken,
        byte: u8,
    ) -> crate::local::StrictSigningHelperMaterialInventory {
        let runtime_hash = release_vector_runtime_evidence_for_token(token).transcript_hash;
        let mut comparison_hasher = Sha3_256::new();
        comparison_hasher.update(b"test strict signing comparison helpers");
        comparison_hasher.update(token.session_id.0);
        comparison_hasher.update(token.transcript_hash.0);
        comparison_hasher.update(runtime_hash);
        comparison_hasher.update([byte]);
        let mut threshold_hasher = Sha3_256::new();
        threshold_hasher.update(b"test strict signing threshold helpers");
        threshold_hasher.update(token.session_id.0);
        threshold_hasher.update(token.transcript_hash.0);
        threshold_hasher.update(runtime_hash);
        threshold_hasher.update([byte]);
        let mut selected_opening_hasher = Sha3_256::new();
        selected_opening_hasher.update(b"test strict signing selected opening helpers");
        selected_opening_hasher.update(token.session_id.0);
        selected_opening_hasher.update(token.transcript_hash.0);
        selected_opening_hasher.update(runtime_hash);
        selected_opening_hasher.update([byte]);
        crate::local::StrictSigningHelperMaterialInventory::new_with_preprocessing_provenance(
            crate::local::StrictSigningHelperMaterialProvenance {
                session_id: token.session_id,
                transcript_hash: token.transcript_hash,
                runtime_transcript_hash: runtime_hash,
                comparison_helper_hash: comparison_hasher.finalize().into(),
                threshold_helper_hash: threshold_hasher.finalize().into(),
                selected_opening_helper_hash: selected_opening_hasher.finalize().into(),
                z_lane_count: MlDsa65::L * MlDsa65::N,
                hint_lane_count: MlDsa65::K * MlDsa65::N,
            },
        )
        .expect("release strict signing helpers")
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

    #[cfg(feature = "production-release-checks")]
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

        let left = release_valid_token(7, &[1, 2]);
        let right = release_valid_token(8, &[1, 2]);
        assert_eq!(
            release_validated_batch_result(vec![left, right], 2).map(|batch| batch.len()),
            Ok(2)
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_release_batch_replays_preprocessing_token_log() {
        let left = release_valid_token(17, &[1, 2]);
        let right = release_valid_token(18, &[1, 2]);
        let entries = [&left, &right]
            .into_iter()
            .enumerate()
            .map(|(idx, token)| {
                preprocessing_release_token_log_entry(token, idx).expect("release token log entry")
            })
            .collect::<Vec<_>>();

        assert_eq!(
            BccCertifiedTokenBatch::new_release_validated_with_log(vec![left, right], 2, &entries,)
                .map(|batch| batch.len()),
            Ok(2)
        );

        let left = release_valid_token(19, &[1, 2]);
        let right = release_valid_token(20, &[1, 2]);
        let mut wrong_entries = [&left, &right]
            .into_iter()
            .enumerate()
            .map(|(idx, token)| {
                preprocessing_release_token_log_entry(token, idx).expect("release token log entry")
            })
            .collect::<Vec<_>>();
        wrong_entries[1].token_binding_hash[0] ^= 0x40;
        assert_eq!(
            BccCertifiedTokenBatch::new_release_validated_with_log(
                vec![left, right],
                2,
                &wrong_entries,
            )
            .map(|batch| batch.len()),
            Err(OnlineError::TokenPool(TokenPoolError::ReleaseLogMismatch))
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_release_batch_can_use_empirical_token_sizing() {
        let estimate =
            TokenPassProbabilityEstimate::new(100, 75).expect("observed pass probability");
        let decision =
            BccCertifiedTokenBatch::sizing_decision_for_suite::<MlDsa65>(estimate, 1.0e-6)
                .expect("sizing decision");
        let tokens = (0..decision.recommended_batch_size)
            .map(|idx| release_valid_token(120 + idx as u8, &[1, 2]))
            .collect::<Vec<_>>();

        let (batch, used_decision) =
            BccCertifiedTokenBatch::new_with_empirical_sizing::<MlDsa65>(tokens, estimate, 1.0e-6)
                .expect("sized release batch");
        assert_eq!(batch.len(), used_decision.recommended_batch_size);
        assert!(used_decision.modeled_no_valid_probability <= 1.0e-6);

        let too_few = (0..used_decision.recommended_batch_size - 1)
            .map(|idx| release_valid_token(40 + idx as u8, &[1, 2]))
            .collect::<Vec<_>>();
        assert_eq!(
            BccCertifiedTokenBatch::new_with_empirical_sizing::<MlDsa65>(
                too_few,
                estimate,
                1.0e-6,
            )
            .map(|(batch, _)| batch.len()),
            Err(OnlineError::TokenBatchTooSmall {
                min: used_decision.recommended_batch_size,
                got: used_decision.recommended_batch_size - 1,
            })
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
        let batch = release_validated_batch(vec![first, second], 2);
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
        let batch = release_validated_batch(vec![first, second], 2);
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
        let batch = release_validated_batch(vec![first, second], 2);
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

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn strict_session_release_accepts_selected_opening_artifact_backend() {
        let first = release_valid_zero_w1_token(43, &[1, 2]);
        let second = release_valid_zero_w1_token(44, &[1, 2]);
        let provider = zero_strict_share_provider(&[&first, &second]);
        let token_log =
            release_token_file_log_for_tokens("release-selected-opening", &[&first, &second]);
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
        >::start_release_validated_with_file_log(
            request,
            tr,
            vec![first, second],
            2,
            &token_log,
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

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn strict_session_release_consumes_helper_inventories_before_backend() {
        let first = release_valid_zero_w1_token(155, &[1, 2]);
        let second = release_valid_zero_w1_token(156, &[1, 2]);
        let first_id = StrictSigningMaskInventoryId::for_token(&first).expect("first mask id");
        let second_id = StrictSigningMaskInventoryId::for_token(&second).expect("second mask id");
        let first_helper_ids =
            StrictSigningHelperInventoryId::for_token(&first).expect("first helper ids");
        let second_helper_ids =
            StrictSigningHelperInventoryId::for_token(&second).expect("second helper ids");
        let provider = zero_strict_share_provider(&[&first, &second]);
        let token_log =
            release_token_file_log_for_tokens("release-mask-consumption", &[&first, &second]);
        let request = strict_request();
        let tr = [0x55; 64];
        let source = ProductionStrictVectorMpcArtifactSource::new(
            vec![0u8; MlDsa65::PK_LEN],
            provider,
            release_vector_runtime_evidence(),
        )
        .expect("strict vector artifact source");
        let backend = ProductionStrictRuntimeSelectedOpeningArtifactBackend::new(source);
        let mut mask_log = InMemoryStrictSigningMaskUseLog::default();
        let mut helper_log = InMemoryStrictSigningHelperUseLog::default();
        let mut session = StrictSigningSession::<
            MlDsa65,
            ProductionStrictRuntimeSelectedOpeningArtifactBackend<
                ProductionStrictVectorMpcArtifactSource<TestStrictShareProvider>,
            >,
            _,
            _,
        >::start_release_validated_with_file_log(
            request,
            tr,
            vec![first, second],
            2,
            &token_log,
            SharedConsumedStore::default(),
            backend,
            AcceptMlDsa65Length,
        )
        .expect("start strict session");

        let signature = session
            .finish_with_helper_use_logs(&mut mask_log, &mut helper_log)
            .expect("release session signs");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert!(mask_log.is_mask_consumed(first_id));
        assert!(mask_log.is_mask_consumed(second_id));
        assert_eq!(mask_log.consumed(), &[first_id, second_id]);
        let expected_helper_ids = [
            first_helper_ids[0],
            first_helper_ids[1],
            first_helper_ids[2],
            second_helper_ids[0],
            second_helper_ids[1],
            second_helper_ids[2],
        ];
        assert_eq!(helper_log.consumed(), &expected_helper_ids);
        assert!(expected_helper_ids
            .iter()
            .all(|id| helper_log.is_helper_consumed(*id)));
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    #[ignore = "requires a multi-party app-driven vector MPC scheduler to deliver runtime phases"]
    fn strict_session_release_uses_live_vector_mpc_artifact_source() {
        let mut token = token(45, &[1]);
        token.w1.fill(0);
        let request = strict_request_one_party();
        let tr = [0x45; 64];
        let (config, runtime, label) = strict_test_vector_runtime_one_party(45);
        let y_lanes = vec![0; MlDsa65::L * MlDsa65::N];
        let s1_lanes = vec![0; MlDsa65::L * MlDsa65::N];
        let z_mask = runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child("z_mask"),
                vec![0; MlDsa65::L * MlDsa65::N],
            )
            .expect("z mask");
        let hint_mask = runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child("hint_mask"),
                vec![0; MlDsa65::K * MlDsa65::N],
            )
            .expect("hint mask");
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
        let w_share = runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child("w_precomputed"),
                vec![0; MlDsa65::K * MlDsa65::N],
            )
            .expect("w share");
        let provenance = crate::local::StrictSigningCanonicalMaskProvenance {
            session_id: token.session_id,
            transcript_hash: token.transcript_hash,
            runtime_transcript_hash: release_vector_runtime_evidence_for_token(&token)
                .transcript_hash,
            z_mask_value_label_hash: z_mask.id().label_hash,
            hint_mask_value_label_hash: hint_mask.id().label_hash,
            z_lane_count: z_mask.len(),
            hint_lane_count: hint_mask.len(),
        };
        let strict_masks =
            crate::local::StrictSigningCanonicalMaskInventory::new_with_preprocessing_provenance(
                provenance, z_mask, z_bits, hint_mask, hint_bits,
            )
            .expect("strict signing masks");
        let strict_helpers = release_strict_signing_helpers_for_token(&token, 45);
        token = token
            .with_precomputed_w_share(w_share.clone())
            .with_strict_signing_canonical_masks(strict_masks)
            .with_strict_signing_helper_material(strict_helpers);
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token,
            release_vector_runtime_evidence_for_token(&token),
        )
        .expect("preprocessing runtime certificate");
        token = token.with_vector_runtime_certificate(certificate);
        let token_log = release_token_file_log_for_tokens("release-live-vector", &[&token]);
        let y_share = runtime
            .share_vec_from_local_lanes::<MlDsa65>(&config, &label.child("y"), y_lanes)
            .expect("y share");
        let rho = [0u8; 32];
        let package = strict_test_dkg_key_package_from_s1_lanes(&config, PartyId(1), rho, s1_lanes);
        let public_key = package.public_key.clone();
        let key_state = StrictRuntimeSigningKeyState::from_dkg_key_package::<MlDsa65, _, _, _>(
            &runtime,
            &config,
            &package,
            &label.child("key_state_as1"),
        )
        .expect("strict key state");
        let input = strict_runtime_candidate_input_from_token_and_key_state::<MlDsa65>(
            &token, &key_state, y_share,
        )
        .expect("strict runtime candidate input");
        let source = ProductionStrictLiveVectorMpcArtifactSource::new(
            config,
            runtime,
            TestProductionVectorEntropy::default(),
            public_key,
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
        >::start_release_validated_with_file_log(
            request,
            tr,
            vec![token],
            1,
            &token_log,
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

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_release_candidate_input_requires_precomputed_hint_handles() {
        let (config, runtime, label) = strict_test_vector_runtime_one_party(46);
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
            token_session_id: SessionId([0x46; 32]),
            y_share: runtime
                .share_vec_from_local_lanes::<MlDsa65>(
                    &config,
                    &label.child("y"),
                    vec![0; MlDsa65::L * MlDsa65::N],
                )
                .expect("y share"),
            s1_share: runtime
                .share_vec_from_local_lanes::<MlDsa65>(
                    &config,
                    &label.child("s1"),
                    vec![0; MlDsa65::L * MlDsa65::N],
                )
                .expect("s1 share"),
            w_share: None,
            as1_share: None,
            z_mask_value: runtime
                .share_vec_from_local_lanes::<MlDsa65>(
                    &config,
                    &label.child("z_mask"),
                    vec![0; MlDsa65::L * MlDsa65::N],
                )
                .expect("z mask"),
            z_mask_bits_by_bit: z_bits,
            hint_mask_value: runtime
                .share_vec_from_local_lanes::<MlDsa65>(
                    &config,
                    &label.child("hint_mask"),
                    vec![0; MlDsa65::K * MlDsa65::N],
                )
                .expect("hint mask"),
            hint_mask_bits_by_bit: hint_bits,
            w1: vec![0; MlDsa65::K * MlDsa65::N],
        };

        assert!(matches!(
            input.validate_for::<MlDsa65>(),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        ));
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn release_batch_rejects_token_without_precomputed_w_share() {
        let token = token(47, &[1]);
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token,
            release_vector_runtime_evidence_for_token(&token),
        )
        .expect("preprocessing runtime certificate");
        let token = token.with_vector_runtime_certificate(certificate);

        assert_eq!(
            release_validated_batch_result(vec![token], 1)
                .expect_err("missing w share rejects before admission"),
            OnlineError::TokenPool(TokenPoolError::ReleaseLogMismatch)
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn release_batch_rejects_token_without_strict_signing_masks() {
        let token = token(48, &[1]).with_precomputed_w_share(release_precomputed_w_share(48));
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token,
            release_vector_runtime_evidence_for_token(&token),
        )
        .expect("preprocessing runtime certificate");
        let token = token.with_vector_runtime_certificate(certificate);

        assert_eq!(
            release_validated_batch_result(vec![token], 1)
                .expect_err("missing strict masks reject before admission"),
            OnlineError::TokenPool(TokenPoolError::ReleaseLogMismatch)
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn release_batch_rejects_token_without_strict_helper_material() {
        let token = token(52, &[1]).with_precomputed_w_share(release_precomputed_w_share(52));
        let masks = release_strict_signing_masks_for_token(&token, 52);
        let token = token.with_strict_signing_canonical_masks(masks);
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token,
            release_vector_runtime_evidence_for_token(&token),
        )
        .expect("preprocessing runtime certificate");
        let token = token.with_vector_runtime_certificate(certificate);

        assert_eq!(
            release_validated_batch_result(vec![token], 1)
                .expect_err("missing strict helper material rejects before admission"),
            OnlineError::TokenPool(TokenPoolError::ReleaseLogMismatch)
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn release_batch_rejects_anonymous_strict_signing_masks() {
        let (config, runtime, label) = strict_test_vector_runtime_one_party(148);
        let token = token(148, &[1]).with_precomputed_w_share(release_precomputed_w_share(148));
        let z_mask = runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child("anonymous_z_mask"),
                vec![0; MlDsa65::K * MlDsa65::N],
            )
            .expect("anonymous z mask");
        let hint_mask = runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child("anonymous_hint_mask"),
                vec![0; MlDsa65::K * MlDsa65::N],
            )
            .expect("anonymous hint mask");
        let z_bits = (0..23)
            .map(|bit| {
                runtime
                    .bit_share_vec_from_local_lanes::<MlDsa65>(
                        &config,
                        &label.child(format!("anonymous_z_bit_{bit}")),
                        vec![0; MlDsa65::K * MlDsa65::N],
                    )
                    .expect("anonymous z bit")
            })
            .collect::<Vec<_>>();
        let hint_bits = (0..23)
            .map(|bit| {
                runtime
                    .bit_share_vec_from_local_lanes::<MlDsa65>(
                        &config,
                        &label.child(format!("anonymous_hint_bit_{bit}")),
                        vec![0; MlDsa65::K * MlDsa65::N],
                    )
                    .expect("anonymous hint bit")
            })
            .collect::<Vec<_>>();
        let masks = crate::local::StrictSigningCanonicalMaskInventory::new(
            z_mask, z_bits, hint_mask, hint_bits,
        )
        .expect("anonymous masks have valid shape");
        let token = token.with_strict_signing_canonical_masks(masks);
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token,
            release_vector_runtime_evidence_for_token(&token),
        )
        .expect("certificate binds anonymous material");
        let token = token.with_vector_runtime_certificate(certificate);

        assert_eq!(
            release_validated_batch_result(vec![token], 1)
                .expect_err("anonymous strict masks reject before admission"),
            OnlineError::TokenPool(TokenPoolError::ReleaseLogMismatch)
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn release_batch_rejects_cross_token_strict_signing_masks() {
        let source = token(150, &[1]).with_precomputed_w_share(release_precomputed_w_share(150));
        let masks = release_strict_signing_masks_for_token(&source, 150);
        let target = token(151, &[1])
            .with_precomputed_w_share(release_precomputed_w_share(151))
            .with_strict_signing_canonical_masks(masks);
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &target,
            release_vector_runtime_evidence_for_token(&target),
        )
        .expect("certificate binds substituted masks");
        let target = target.with_vector_runtime_certificate(certificate);

        assert_eq!(
            release_validated_batch_result(vec![target], 1)
                .expect_err("cross-token strict masks reject before admission"),
            OnlineError::TokenPool(TokenPoolError::ReleaseLogMismatch)
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn release_batch_rejects_cross_token_strict_helper_material() {
        let source = release_valid_token(155, &[1]);
        let helpers = *source
            .strict_signing_helpers()
            .expect("source helper material");
        let target = token(156, &[1])
            .with_precomputed_w_share(release_precomputed_w_share(156))
            .with_strict_signing_canonical_masks(release_strict_signing_masks_for_token(
                &token(156, &[1]).with_precomputed_w_share(release_precomputed_w_share(156)),
                156,
            ))
            .with_strict_signing_helper_material(helpers);
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &target,
            release_vector_runtime_evidence_for_token(&target),
        )
        .expect("certificate binds substituted helper material");
        let target = target.with_vector_runtime_certificate(certificate);

        assert_eq!(
            release_validated_batch_result(vec![target], 1)
                .expect_err("cross-token strict helper material rejects before admission"),
            OnlineError::TokenPool(TokenPoolError::ReleaseLogMismatch)
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn release_candidate_input_uses_token_bound_strict_masks() {
        let (config, runtime, label) = strict_test_vector_runtime_one_party(49);
        let token = release_valid_zero_w1_token(49, &[1]);
        let y_share = runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child("candidate_y"),
                vec![0; MlDsa65::L * MlDsa65::N],
            )
            .expect("candidate y");
        let package = strict_test_dkg_key_package_from_s1_lanes(
            &config,
            PartyId(1),
            [0u8; 32],
            vec![0; MlDsa65::L * MlDsa65::N],
        );
        let key_state = StrictRuntimeSigningKeyState::from_dkg_key_package::<MlDsa65, _, _, _>(
            &runtime,
            &config,
            &package,
            &label.child("candidate_key_state"),
        )
        .expect("candidate key state");

        let input = strict_runtime_candidate_input_from_token_and_key_state::<MlDsa65>(
            &token, &key_state, y_share,
        )
        .expect("candidate input");

        let masks = token
            .strict_signing_masks()
            .expect("release token has masks");
        assert_eq!(input.z_mask_value.id(), masks.z_mask_value().id());
        assert_eq!(input.hint_mask_value.id(), masks.hint_mask_value().id());
        assert_eq!(input.z_mask_bits_by_bit.len(), 23);
        assert_eq!(input.hint_mask_bits_by_bit.len(), 23);
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_mask_use_log_rejects_reuse() {
        let first = release_valid_token(152, &[1, 2]);
        let second = release_valid_token(153, &[1, 2]);
        let batch = release_validated_batch(vec![first, second], 2);
        let mut log = InMemoryStrictSigningMaskUseLog::default();

        let ids =
            consume_strict_signing_masks_for_batch(&batch, &mut log).expect("consume masks once");
        assert_eq!(ids.len(), 2);
        assert_eq!(log.consumed(), ids.as_slice());
        assert!(ids.iter().all(|id| log.is_mask_consumed(*id)));

        assert_eq!(
            consume_strict_signing_masks_for_batch(&batch, &mut log),
            Err(OnlineError::StrictSigningMaskAlreadyConsumed(ids[0]))
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_helper_use_log_rejects_reuse() {
        let first = release_valid_token(157, &[1, 2]);
        let second = release_valid_token(158, &[1, 2]);
        let batch = release_validated_batch(vec![first, second], 2);
        let mut log = InMemoryStrictSigningHelperUseLog::default();

        let ids = consume_strict_signing_helpers_for_batch(&batch, &mut log)
            .expect("consume helpers once");
        assert_eq!(ids.len(), 4);
        assert_eq!(log.consumed(), ids.as_slice());
        assert!(ids.iter().all(|id| log.is_helper_consumed(*id)));

        assert_eq!(
            consume_strict_signing_helpers_for_batch(&batch, &mut log),
            Err(OnlineError::StrictSigningHelperAlreadyConsumed(ids[0]))
        );
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn file_strict_mask_use_log_survives_reopen_and_blocks_reuse() {
        let path = strict_session_store_path("strict-mask-use");
        let token = release_valid_token(154, &[1, 2]);
        let batch = release_validated_batch(vec![token], 1);
        let expected_id =
            StrictSigningMaskInventoryId::for_token(&batch.tokens[0]).expect("mask inventory id");

        {
            let mut log = FileStrictSigningMaskUseLog::open(&path).expect("open mask log");
            let ids = consume_strict_signing_masks_for_batch(&batch, &mut log)
                .expect("consume mask inventory");
            assert_eq!(ids, vec![expected_id]);
        }

        let mut reopened = FileStrictSigningMaskUseLog::open(&path).expect("reopen mask log");
        assert!(reopened.is_mask_consumed(expected_id));
        assert_eq!(
            consume_strict_signing_masks_for_batch(&batch, &mut reopened),
            Err(OnlineError::StrictSigningMaskAlreadyConsumed(expected_id))
        );
        let _ = std::fs::remove_file(path);
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn file_strict_helper_use_log_survives_reopen_and_blocks_reuse() {
        let path = strict_session_store_path("strict-helper-use");
        let token = release_valid_token(159, &[1, 2]);
        let batch = release_validated_batch(vec![token], 1);
        let expected_ids =
            StrictSigningHelperInventoryId::for_token(&batch.tokens[0]).expect("helper ids");

        {
            let mut log = FileStrictSigningHelperUseLog::open(&path).expect("open helper log");
            let ids = consume_strict_signing_helpers_for_batch(&batch, &mut log)
                .expect("consume helper inventory");
            assert_eq!(ids, expected_ids);
        }

        let mut reopened = FileStrictSigningHelperUseLog::open(&path).expect("reopen helper log");
        assert!(expected_ids
            .iter()
            .all(|id| reopened.is_helper_consumed(*id)));
        assert_eq!(
            consume_strict_signing_helpers_for_batch(&batch, &mut reopened),
            Err(OnlineError::StrictSigningHelperAlreadyConsumed(
                expected_ids[0]
            ))
        );
        let _ = std::fs::remove_file(path);
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

    #[test]
    fn strict_live_vector_profile_contract_tracks_batched_predicate_shape() {
        let phases = STRICT_LIVE_VECTOR_BATCHED_PROFILE_PHASES;
        for expected in [
            STRICT_PROFILE_Z_RESPONSE_PREP_BATCH,
            STRICT_PROFILE_Z_CANONICAL_DECOMPOSITION_BATCH,
            STRICT_PROFILE_Z_BOUND_CHECKS_BATCH,
            STRICT_PROFILE_HINT_APPROX_BATCH,
            STRICT_PROFILE_HINT_CANONICAL_DECOMPOSITION_BATCH,
            STRICT_PROFILE_HINT_HIGHBITS_CHECKS_BATCH,
            STRICT_PROFILE_FUSED_VALIDITY_BATCH,
            STRICT_PROFILE_PRIORITY_SELECTION_BATCH,
            STRICT_PROFILE_SELECTED_PRODUCTS_BATCH,
        ] {
            assert!(
                phases.contains(&expected),
                "batched live strict profile is missing {expected}"
            );
        }
        for obsolete in STRICT_LIVE_VECTOR_OBSOLETE_PROFILE_PHASES {
            assert!(
                !phases.contains(&obsolete),
                "batched live strict profile must not advertise obsolete per-candidate phase {obsolete}"
            );
        }
    }

    #[test]
    fn strict_live_vector_release_envelope_rejects_obsolete_profile_shape() {
        let mut profile = STRICT_LIVE_VECTOR_BATCHED_PROFILE_PHASES
            .iter()
            .map(|phase| StrictLiveVectorMpcPhaseProfile {
                phase: (*phase).to_string(),
                candidate_index: None,
                elapsed_ms: 0,
                counter_delta: PrimeFieldMpcCounters::default(),
            })
            .collect::<Vec<_>>();
        ensure_strict_live_vector_profile_release_envelope::<MlDsa65>(&profile, 2)
            .expect("batched profile accepted");

        profile.push(StrictLiveVectorMpcPhaseProfile {
            phase: "selected_z_product".to_string(),
            candidate_index: Some(0),
            elapsed_ms: 0,
            counter_delta: PrimeFieldMpcCounters::default(),
        });
        assert!(matches!(
            ensure_strict_live_vector_profile_release_envelope::<MlDsa65>(&profile, 2),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        ));

        let mut missing = STRICT_LIVE_VECTOR_BATCHED_PROFILE_PHASES
            .iter()
            .filter(|phase| **phase != STRICT_PROFILE_PRIORITY_SELECTION_BATCH)
            .map(|phase| StrictLiveVectorMpcPhaseProfile {
                phase: (*phase).to_string(),
                candidate_index: None,
                elapsed_ms: 0,
                counter_delta: PrimeFieldMpcCounters::default(),
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            ensure_strict_live_vector_profile_release_envelope::<MlDsa65>(&missing, 2),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        ));

        missing.push(StrictLiveVectorMpcPhaseProfile {
            phase: STRICT_PROFILE_PRIORITY_SELECTION_BATCH.to_string(),
            candidate_index: Some(0),
            elapsed_ms: 0,
            counter_delta: PrimeFieldMpcCounters::default(),
        });
        assert!(matches!(
            ensure_strict_live_vector_profile_release_envelope::<MlDsa65>(&missing, 2),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        ));
    }

    #[test]
    fn strict_live_vector_release_envelope_rejects_numeric_regressions() {
        let mut profile = STRICT_LIVE_VECTOR_BATCHED_PROFILE_PHASES
            .iter()
            .map(|phase| StrictLiveVectorMpcPhaseProfile {
                phase: (*phase).to_string(),
                candidate_index: None,
                elapsed_ms: 0,
                counter_delta: PrimeFieldMpcCounters::default(),
            })
            .collect::<Vec<_>>();
        ensure_strict_live_vector_profile_release_envelope::<MlDsa65>(&profile, 2)
            .expect("baseline profile accepted");

        let z_bound_idx = profile
            .iter()
            .position(|entry| entry.phase == STRICT_PROFILE_Z_BOUND_CHECKS_BATCH)
            .expect("z-bound profile");
        profile[z_bound_idx].counter_delta.rounds = 10_000;
        assert!(matches!(
            ensure_strict_live_vector_profile_release_envelope::<MlDsa65>(&profile, 2),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        ));
        profile[z_bound_idx].counter_delta = PrimeFieldMpcCounters::default();

        profile[z_bound_idx].counter_delta.scalar_mul_gates = 1;
        assert!(matches!(
            ensure_strict_live_vector_profile_release_envelope::<MlDsa65>(&profile, 2),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        ));
        profile[z_bound_idx].counter_delta = PrimeFieldMpcCounters::default();

        profile[z_bound_idx].counter_delta.vector_lanes = 1;
        profile[z_bound_idx].counter_delta.wire_bytes = 1_000_000;
        assert!(matches!(
            ensure_strict_live_vector_profile_release_envelope::<MlDsa65>(&profile, 2),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        ));
    }

    #[test]
    fn strict_best_shape_report_aggregates_release_profile_without_targets() {
        let mut profile = STRICT_LIVE_VECTOR_BATCHED_PROFILE_PHASES
            .iter()
            .map(|phase| StrictLiveVectorMpcPhaseProfile {
                phase: (*phase).to_string(),
                candidate_index: None,
                elapsed_ms: 2,
                counter_delta: PrimeFieldMpcCounters {
                    rounds: u64::from(
                        strict_live_vector_phase_round_cap(phase, 2).unwrap_or(1) > 0,
                    ),
                    vector_lanes: 8,
                    vector_mul_lanes: 8,
                    ..PrimeFieldMpcCounters::default()
                },
            })
            .collect::<Vec<_>>();
        let report = strict_signing_best_shape_performance_report::<MlDsa65>(&profile, 2)
            .expect("best-shape report");
        assert_eq!(report.suite, MlDsa65::NAME);
        assert_eq!(report.token_count, 2);
        assert_eq!(
            report.phase_count,
            STRICT_LIVE_VECTOR_BATCHED_PROFILE_PHASES.len()
        );
        assert_eq!(
            report.wall_clock_ms,
            2 * STRICT_LIVE_VECTOR_BATCHED_PROFILE_PHASES.len() as u128
        );
        assert!(report.no_scalarized_release_counters);
        let expected_rounds = STRICT_LIVE_VECTOR_BATCHED_PROFILE_PHASES
            .iter()
            .filter(|phase| strict_live_vector_phase_round_cap(phase, 2).unwrap_or(1) > 0)
            .count() as u64;
        assert_eq!(report.counters.rounds, expected_rounds);

        profile[0].counter_delta.scalar_openings = 1;
        assert!(matches!(
            strict_signing_best_shape_performance_report::<MlDsa65>(&profile, 2),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        ));
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn zero_t1_strict_signature_candidate_verifies_with_fips() {
        let token = release_valid_zero_w1_token(220, &[1]);
        let request = strict_request_one_party();
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let tr = compute_tr(&public_key);
        let sign_request = SignRequest {
            protocol_version: ONLINE_PROTOCOL_VERSION,
            suite: MlDsa65::NAME,
            session_id: token.session_id,
            signing_set: vec![PartyId(1)],
            message: request.message.clone(),
            external_mu: None,
            context: request.context.clone(),
            token_transcript_hash: token.transcript_hash,
        };
        let challenge = compute_challenge_material::<MlDsa65>(&sign_request, &token, &tr);
        let signature = strict_encode_selected_signature::<MlDsa65>(
            &challenge.ctilde,
            &PolyVec::zero(MlDsa65::L),
            &PolyVec::zero(MlDsa65::K),
        )
        .expect("zero-t1 strict signature candidate encodes");
        let verifier = FipsFinalVerifier::<MlDsa65>::new(public_key)
            .expect("zero public key has valid FIPS encoding shape");
        assert!(verifier.verify_final(&sign_request, &signature));
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    fn release_preprocessing_token_from_session_for_benchmark(
        config: &DkgConfig,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<
            LatestRoundInMemoryTransport,
            talus_dkg::InMemoryPrimeFieldMpcWireMessageLog,
            talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog,
        >,
        session_id: SessionId,
        rho: [u8; 32],
    ) -> (
        Vec<CertifiedToken>,
        FilePreprocessingReleaseTokenBatchLog,
        crate::local::PreprocessingBestShapePerformanceReport,
        Vec<crate::local::DistributedNonceShare>,
    ) {
        let mut sessions = Vec::new();
        let mut nonce_shares = Vec::new();
        for idx in 0..2u8 {
            let token_session_id = SessionId([session_id.0[0].wrapping_add(idx); 32]);
            let nonce_share = crate::local::DistributedNonceShare {
                party: PartyId(1),
                y_share: PolyVec::new(vec![Poly::from_coeffs([0; 256]); MlDsa65::L]),
                nonce_commitment: NonceCommitment([0x71u8.wrapping_add(idx); 32]),
                randomness_commitment: Commitment([0x72u8.wrapping_add(idx); 32]),
            };
            let input =
                crate::local::party_preprocess_input_from_distributed_nonce_share::<MlDsa65>(
                    token_session_id,
                    &config.parties,
                    &rho,
                    &nonce_share,
                )
                .expect("nonce-backed preprocessing input");
            let options = crate::local::PreprocessingSessionOptions {
                session_id: token_session_id,
                signer_set: config.parties.clone(),
                keygen_transcript_hash: config.transcript_hash().0,
            };
            let mut session = crate::local::PreprocessingSession::<MlDsa65, _, _>::start(
                options,
                input,
                SessionRegistry::new(),
                crate::local::ProductMaskedBroadcastConsistencyVerifier,
            )
            .expect("start preprocessing session");
            while let Some(outbound) = session.next_outbound() {
                match outbound {
                    crate::local::PreprocessingOutbound::Broadcast { message } => session
                        .handle_broadcast(message)
                        .expect("route one-party preprocessing broadcast"),
                    crate::local::PreprocessingOutbound::Private { .. } => {
                        panic!("preprocessing benchmark should not emit private messages")
                    }
                }
            }
            nonce_shares.push(nonce_share);
            sessions.push(session);
        }

        let mut drivers = Vec::new();
        for (session, nonce_share) in sessions.into_iter().zip(nonce_shares.iter().cloned()) {
            let mut adapter =
                crate::local::ProductionPreprocessingCertificationRuntime::new(runtime);
            drivers.push(
                session
                    .into_release_driver(
                        config.clone(),
                        rho,
                        nonce_share,
                        &mut adapter,
                        crate::local::PreprocessingReleaseSessionCursorMemoryStore::new(),
                    )
                    .expect("release preprocessing driver"),
            );
        }
        let mut batch = crate::local::PreprocessingReleaseBatchDriver::new(drivers)
            .expect("release preprocessing batch driver");
        let mut timings = Vec::new();
        let private_started = std::time::Instant::now();
        {
            let adapter = crate::local::ProductionPreprocessingCertificationRuntime::new(runtime);
            batch
                .start_fused_private_runtime(&adapter)
                .expect("start fused preprocessing runtime");
        }
        let mut round = 0u64;
        while batch
            .phases()
            .iter()
            .any(|phase| *phase == crate::local::PreprocessingReleaseDriverPhase::PrivateRuntime)
        {
            let mut entropy = TestProductionVectorEntropy {
                next: 1_700_000 + round * 10_000,
            };
            let mut adapter =
                crate::local::ProductionPreprocessingCertificationRuntime::new(runtime);
            batch
                .drive_fused_private_runtime_step::<_, _, _, _>(&mut adapter, &mut entropy)
                .expect("drive fused release preprocessing");
            let mut adapter =
                crate::local::ProductionPreprocessingCertificationRuntime::new(runtime);
            match batch
                .collect_fused_private_runtime_step(&mut adapter)
                .expect("collect fused release preprocessing")
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("fused release preprocessing did not complete: {status:?}")
                }
            }
            round = round.saturating_add(1);
            assert!(round < 512, "release preprocessing did not converge");
        }
        timings.push(crate::local::PreprocessingBestShapePhaseTiming {
            phase: "fused_private_carry_cef_bcc",
            elapsed_ms: private_started.elapsed().as_millis(),
        });

        let mask_started = std::time::Instant::now();
        let members = batch.strict_mask_batch_members();
        let mut adapter = crate::local::ProductionPreprocessingCertificationRuntime::new(runtime);
        let mut fused_masks = adapter
            .start_strict_signing_canonical_mask_batch_generation(&members)
            .expect("start fused strict masks");
        let mut mask_round = 0u64;
        while !fused_masks.is_done() {
            let mut entropy = ZeroProductionVectorEntropy;
            adapter
                .drive_strict_signing_canonical_mask_generation_step::<MlDsa65, _>(
                    config,
                    &mut fused_masks,
                    &mut entropy,
                )
                .expect("drive fused strict masks");
            match adapter
                .collect_strict_signing_canonical_mask_generation_step::<MlDsa65>(
                    config,
                    &mut fused_masks,
                )
                .expect("collect fused strict masks")
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("fused strict masks did not complete: {status:?}")
                }
            }
            mask_round = mask_round.saturating_add(1);
            assert!(mask_round < 512, "fused strict masks did not converge");
        }
        let inventories = adapter
            .finish_strict_signing_canonical_mask_batch_generation::<MlDsa65>(
                config,
                fused_masks,
                &members,
            )
            .expect("finish fused strict masks");
        batch
            .install_fused_strict_mask_inventories(inventories)
            .expect("install fused strict masks");
        timings.push(crate::local::PreprocessingBestShapePhaseTiming {
            phase: "fused_strict_masks",
            elapsed_ms: mask_started.elapsed().as_millis(),
        });

        let token_log_path = strict_session_store_path("real-preprocessing-token-benchmark");
        let mut token_log =
            FilePreprocessingReleaseTokenBatchLog::open(&token_log_path).expect("token log");
        let mut adapter = crate::local::ProductionPreprocessingCertificationRuntime::new(runtime);
        let mut outputs = batch
            .finish_fused_private_and_append_token_log(&mut adapter, &mut token_log)
            .expect("release-certified preprocessing token");
        assert_eq!(outputs.len(), 2);
        let tokens = outputs
            .drain(..)
            .map(|(token, _cursor_store)| token)
            .collect::<Vec<_>>();
        assert!(tokens.iter().all(CertifiedToken::is_release_certified));
        token_log
            .replay_for_release(&tokens)
            .expect("release token log replays");

        let fill =
            crate::local::PreprocessingTokenBatchFillReport::from_certified_tokens(2, &tokens);
        let phase_profile = runtime
            .runtime_phase_profile()
            .expect("preprocessing profile");
        let preprocessing_report = crate::local::preprocessing_best_shape_performance_report::<
            MlDsa65,
        >(fill, timings, &phase_profile, 8)
        .expect("preprocessing report from real release token");
        (tokens, token_log, preprocessing_report, nonce_shares)
    }

    #[cfg(feature = "production-release-checks")]
    fn synthetic_preprocessing_report<P: MlDsaParams>(
        certified_tokens: u64,
    ) -> crate::local::PreprocessingBestShapePerformanceReport {
        crate::local::PreprocessingBestShapePerformanceReport {
            suite: P::NAME,
            attempted_tokens: certified_tokens,
            certified_tokens,
            preprocessing_counters: crate::local::PreprocessingCertificationCounters::default(),
            timings: vec![
                crate::local::PreprocessingBestShapePhaseTiming {
                    phase: "fused_private_carry_cef_bcc",
                    elapsed_ms: 11,
                },
                crate::local::PreprocessingBestShapePhaseTiming {
                    phase: "fused_strict_masks",
                    elapsed_ms: 7,
                },
                crate::local::PreprocessingBestShapePhaseTiming {
                    phase: "certificate_and_log",
                    elapsed_ms: 2,
                },
            ],
            profile_totals: crate::local::PreprocessingBestShapeProfileTotals {
                records: 12,
                private_records: 8,
                broadcast_records: 4,
                vector_lanes: certified_tokens * (P::L as u64 + P::K as u64) * P::N as u64,
                wire_bytes: 50_000 * certified_tokens,
                durable_log_bytes: 75_000 * certified_tokens,
            },
            top_durable_log_phases: Vec::new(),
            chunk_policy_ok: true,
            no_scalarized_release_profile: true,
        }
    }

    fn synthetic_strict_live_profile(token_count: usize) -> Vec<StrictLiveVectorMpcPhaseProfile> {
        STRICT_LIVE_VECTOR_BATCHED_PROFILE_PHASES
            .iter()
            .map(|phase| StrictLiveVectorMpcPhaseProfile {
                phase: (*phase).to_string(),
                candidate_index: None,
                elapsed_ms: 2,
                counter_delta: PrimeFieldMpcCounters {
                    rounds: u64::from(
                        strict_live_vector_phase_round_cap(phase, token_count).unwrap_or(1) > 0,
                    ),
                    private_messages: 2,
                    broadcasts: 1,
                    wire_bytes: 4096,
                    durable_log_bytes: 8192,
                    vector_lanes: 8_192,
                    vector_mul_lanes: 8_192,
                    vector_opening_lanes: 8_192,
                    vector_assert_zero_lanes: 8_192,
                    random_bits: 8_192,
                    ..PrimeFieldMpcCounters::default()
                },
            })
            .collect()
    }

    #[cfg(feature = "production-release-checks")]
    fn check_full_pipeline_report_for_suite<P: MlDsaParams>(parties: usize, threshold: usize) {
        let preprocessing = synthetic_preprocessing_report::<P>(2);
        let profile = synthetic_strict_live_profile(2);
        let report = strict_signing_full_pipeline_benchmark_report::<P>(
            &preprocessing,
            &profile,
            parties,
            threshold,
            2,
            1,
            true,
            &[200, 500, 1_000],
        )
        .expect("full pipeline report");

        assert_eq!(report.suite, P::NAME);
        assert_eq!(report.parties, parties);
        assert_eq!(report.threshold, threshold);
        assert_eq!(report.token_batch_size, 2);
        assert_eq!(report.token_pass_probability, Some((2, 2)));
        assert!(report.final_fips_verify_ok);
        assert!(report.no_scalar_fallback);
        assert!(report.selected_opening_only);
        assert!(report.runtime_profile_within_envelope);
        assert_eq!(report.transport_estimates.len(), 3);
        assert!(report.transport_estimates.iter().all(|estimate| {
            estimate.private_messages > 0
                && estimate.broadcasts > 0
                && estimate.wire_bytes > 0
                && estimate.durable_log_bytes > 0
                && estimate.estimated_latency_micros
                    == estimate.rounds as u128 * estimate.rtt_micros as u128
        }));
        let slots = report
            .slots
            .iter()
            .map(|slot| slot.slot)
            .collect::<Vec<_>>();
        assert_eq!(
            slots,
            vec![
                StrictSigningBenchmarkSlot::ResponsePrep,
                StrictSigningBenchmarkSlot::ZDecomp,
                StrictSigningBenchmarkSlot::ZBound,
                StrictSigningBenchmarkSlot::HintDecomp,
                StrictSigningBenchmarkSlot::HintCheck,
                StrictSigningBenchmarkSlot::Selection,
                StrictSigningBenchmarkSlot::SelectedOpen,
                StrictSigningBenchmarkSlot::FinalVerify,
            ]
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_full_pipeline_report_covers_all_suites_and_party_counts() {
        for (parties, threshold) in [(3, 2), (5, 3), (7, 4)] {
            check_full_pipeline_report_for_suite::<MlDsa44>(parties, threshold);
            check_full_pipeline_report_for_suite::<MlDsa65>(parties, threshold);
            check_full_pipeline_report_for_suite::<MlDsa87>(parties, threshold);
        }
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_full_pipeline_report_rejects_scalar_and_obsolete_opening_regressions() {
        let preprocessing = synthetic_preprocessing_report::<MlDsa65>(2);
        let mut profile = synthetic_strict_live_profile(2);
        profile[0].counter_delta.scalar_mul_gates = 1;
        assert!(matches!(
            strict_signing_full_pipeline_benchmark_report::<MlDsa65>(
                &preprocessing,
                &profile,
                3,
                2,
                2,
                1,
                true,
                &[500],
            ),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        ));

        let mut profile = synthetic_strict_live_profile(2);
        profile.push(StrictLiveVectorMpcPhaseProfile {
            phase: "selected_z_product".to_string(),
            candidate_index: Some(0),
            elapsed_ms: 1,
            counter_delta: PrimeFieldMpcCounters::default(),
        });
        assert!(matches!(
            strict_signing_full_pipeline_benchmark_report::<MlDsa65>(
                &preprocessing,
                &profile,
                3,
                2,
                2,
                1,
                true,
                &[500],
            ),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        ));
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    #[ignore = "strict release benchmark harness; run with --release --ignored --nocapture"]
    fn strict_full_pipeline_release_benchmark_harness_mldsa65_live_runtime() {
        let (config, runtime, _label) = strict_test_vector_runtime_one_party(221);
        let request = strict_request_one_party();
        let rho = [0u8; 32];
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let tr = compute_tr(&public_key);
        let mut preprocessing_runtime = runtime;
        let (tokens, _preprocessing_token_log, preprocessing_report, nonce_shares) =
            release_preprocessing_token_from_session_for_benchmark(
                &config,
                &mut preprocessing_runtime,
                session(221),
                rho,
            );
        assert_eq!(tokens.len(), 2);
        assert_eq!(nonce_shares.len(), 2);
        let first_token_session_id = tokens[0].session_id;
        let first_token_transcript_hash = tokens[0].transcript_hash;
        let token_refs = tokens.iter().collect::<Vec<_>>();
        let token_log = release_token_file_log_for_tokens(
            "strict-benchmark-real-preprocessing-token-batch",
            &token_refs,
        );
        let transport =
            LatestRoundInMemoryTransport::new(1, vec![1]).expect("strict signing transport");
        let state = talus_dkg::TransportPrimeFieldMpcStateMachine::new(
            config.clone(),
            PartyId(1),
            transport,
        )
        .expect("strict signing state machine");
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
        let label = Power2RoundTranscriptLabel::root(&config, [0x73; 32]).child("strict_signing");
        let s1_lanes = vec![0; MlDsa65::L * MlDsa65::N];
        let package = strict_test_dkg_key_package_from_s1_lanes(&config, PartyId(1), rho, s1_lanes);
        let key_state = StrictRuntimeSigningKeyState::from_dkg_key_package::<MlDsa65, _, _, _>(
            &runtime,
            &config,
            &package,
            &label.child("benchmark_key_state"),
        )
        .expect("key state");
        let candidate_inputs = tokens
            .iter()
            .zip(nonce_shares.iter())
            .enumerate()
            .map(|(idx, (token, nonce_share))| {
                let y_share = runtime
                    .share_vec_from_local_lanes::<MlDsa65>(
                        &config,
                        &label.child(format!("benchmark_y_{idx}")),
                        nonce_share
                            .y_share
                            .polys()
                            .iter()
                            .flat_map(|poly| poly.coeffs().iter().copied())
                            .collect::<Vec<_>>(),
                    )
                    .expect("y share");
                strict_runtime_candidate_input_from_token_and_key_state::<MlDsa65>(
                    token, &key_state, y_share,
                )
                .expect("candidate input")
            })
            .collect::<Vec<_>>();
        let source = ProductionStrictLiveVectorMpcArtifactSource::new(
            config,
            runtime,
            TestProductionVectorEntropy::default(),
            package.public_key.clone(),
            candidate_inputs,
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
        >::start_release_validated_with_file_log(
            request,
            tr,
            tokens,
            2,
            &token_log,
            SharedConsumedStore::default(),
            backend,
            FipsFinalVerifier::<MlDsa65>::new(package.public_key.clone()).expect("FIPS verifier"),
        )
        .expect("start strict benchmark session");

        let signature = match session.finish() {
            Ok(signature) => signature,
            Err(err) => panic!("strict benchmark signs: {err:?}"),
        };
        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        let verify_request = SignRequest {
            protocol_version: ONLINE_PROTOCOL_VERSION,
            suite: MlDsa65::NAME,
            session_id: first_token_session_id,
            signing_set: vec![PartyId(1)],
            message: b"message".to_vec(),
            external_mu: None,
            context: b"ctx".to_vec(),
            token_transcript_hash: first_token_transcript_hash,
        };
        let final_verify_started = std::time::Instant::now();
        let final_fips_verify_ok = FipsFinalVerifier::<MlDsa65>::new(package.public_key.clone())
            .expect("FIPS verifier")
            .verify_final(&verify_request, &signature);
        let final_verify_ms = final_verify_started.elapsed().as_millis();
        let (_store, _cursor, backend, _verifier, counters, final_signature) = session.into_parts();
        assert_eq!(counters.signatures_returned, 1);
        assert!(final_signature.is_some());
        let source = backend.into_source();
        let report = strict_signing_full_pipeline_benchmark_report::<MlDsa65>(
            &preprocessing_report,
            source.profile(),
            3,
            2,
            2,
            final_verify_ms,
            final_fips_verify_ok,
            &[200, 500, 1_000],
        )
        .expect("full pipeline live-runtime report");
        eprintln!("strict full pipeline live-runtime benchmark:\n{report:#?}");
        assert!(report.no_scalar_fallback);
        assert!(report.selected_opening_only);
        assert_eq!(report.token_batch_size, 2);
        assert!(
            report
                .transport_estimates
                .iter()
                .all(|estimate| estimate.rounds <= 128),
            "candidate batching should widen vector lanes without adding per-token rounds"
        );
        assert!(report.strict_wire_bytes > 0);
        assert!(report.strict_durable_log_bytes > 0);
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
        let k_lane_count = MlDsa65::K * MlDsa65::N;
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

        let w_share = runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child("w_precomputed"),
                vec![0; k_lane_count],
            )
            .expect("w share");
        let as1_share = runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child("as1_precomputed"),
                vec![0; k_lane_count],
            )
            .expect("as1 share");
        let fast_approx = strict_runtime_hint_approx_share_from_precomputed::<MlDsa65, _, _, _>(
            &runtime,
            &config,
            &public_key,
            &ctilde,
            &w_share,
            &as1_share,
            &label.child("hint_approx_precomputed"),
        )
        .expect("precomputed hint approx");
        assert_eq!(fast_approx.len(), MlDsa65::K * MlDsa65::N);

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
    fn strict_priority_selection_packs_selection_and_prefix_update() {
        let (config, mut runtime, label) = strict_test_vector_runtime_one_party(89);
        let priorities = vec![
            StrictCandidatePriority([0x20; 32]),
            StrictCandidatePriority([0x10; 32]),
            StrictCandidatePriority([0x30; 32]),
        ];
        let valid_bits = [false, true, true]
            .into_iter()
            .enumerate()
            .map(|(idx, bit)| {
                runtime
                    .bit_share_vec_from_local_lanes::<MlDsa65>(
                        &config,
                        &label.child(format!("valid_{idx}")),
                        vec![i32::from(bit)],
                    )
                    .expect("valid bit")
            })
            .collect::<Vec<_>>();
        let mut selection = StrictRuntimePrioritySelectionState::new::<MlDsa65, _, _, _>(
            &runtime,
            &config,
            &priorities,
            &valid_bits,
            &label.child("priority_selection"),
        )
        .expect("selection state");
        let mut entropy = TestProductionVectorEntropy::default();

        while !selection.is_done() {
            selection
                .drive_step::<MlDsa65, _, _, _, _>(
                    &mut runtime,
                    &config,
                    &valid_bits,
                    &label.child("priority_selection"),
                    &mut entropy,
                )
                .expect("drive selection");
            strict_collected_unit(
                selection
                    .collect_step::<MlDsa65, _, _, _>(
                        &mut runtime,
                        &config,
                        &valid_bits,
                        &label.child("priority_selection"),
                    )
                    .expect("collect selection"),
            )
            .expect("selected step");
        }

        let selected_bits = selection.selected_bits().expect("selected bits");
        let opened = selected_bits
            .iter()
            .enumerate()
            .map(|(idx, bit)| {
                let open_label = label.child(format!("selected_{idx}/open"));
                runtime
                    .drive_open_bit_share_vec::<MlDsa65>(&config, bit, &open_label)
                    .expect("drive selected open");
                strict_collected_value(
                    runtime
                        .collect_open_bit_share_vec::<MlDsa65>(&config, &open_label)
                        .expect("collect selected open"),
                )
                .expect("opened selected")[0]
            })
            .collect::<Vec<_>>();
        assert_eq!(
            opened,
            vec![0, 1, 0],
            "private priority selection must select the valid candidate with lowest public priority"
        );

        let profile = runtime.runtime_phase_profile().expect("runtime profile");
        let selection_profile = profile
            .iter()
            .find(|entry| {
                entry.kind == talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce
                    && entry.phase == talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare
            })
            .expect("selection mul profile");
        assert_eq!(
            selection_profile.distinct_labels,
            priorities.len() as u64,
            "selection and prefix update must share one packed vector MPC layer per candidate"
        );
        assert_eq!(selection_profile.max_record_lanes, 2);
        assert_eq!(selection_profile.records, priorities.len() as u64 * 2);
        assert_eq!(selection_profile.vector_lanes, priorities.len() as u64 * 4);
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_hint_weight_check_packs_candidates_as_runtime_lanes() {
        let (config, mut runtime, label) = strict_test_vector_runtime_one_party(90);
        let lane_count = MlDsa44::K * MlDsa44::N;
        let mut valid_hint = vec![0; lane_count];
        for bit in valid_hint.iter_mut().take(MlDsa44::OMEGA as usize) {
            *bit = 1;
        }
        let mut invalid_hint = vec![0; lane_count];
        for bit in invalid_hint.iter_mut().take(MlDsa44::OMEGA as usize + 1) {
            *bit = 1;
        }
        let h_bits_by_candidate = vec![
            runtime
                .bit_share_vec_from_local_lanes::<MlDsa44>(
                    &config,
                    &label.child("valid_hint"),
                    valid_hint,
                )
                .expect("valid hint"),
            runtime
                .bit_share_vec_from_local_lanes::<MlDsa44>(
                    &config,
                    &label.child("invalid_hint"),
                    invalid_hint,
                )
                .expect("invalid hint"),
        ];
        let mut entropy = TestProductionVectorEntropy::default();
        let results = strict_run_hint_weight_checks_packed_batch::<MlDsa44, _, _, _, _>(
            &h_bits_by_candidate,
            &mut runtime,
            &config,
            &label.child("hint_weight_packed"),
            &mut entropy,
        )
        .expect("packed hint weight");
        let opened = results
            .iter()
            .enumerate()
            .map(|(idx, result)| {
                let open_label = label.child(format!("hint_ok_{idx}/open"));
                runtime
                    .drive_open_bit_share_vec::<MlDsa44>(&config, result, &open_label)
                    .expect("drive hint ok open");
                strict_collected_value(
                    runtime
                        .collect_open_bit_share_vec::<MlDsa44>(&config, &open_label)
                        .expect("collect hint ok open"),
                )
                .expect("opened hint ok")[0]
            })
            .collect::<Vec<_>>();
        assert_eq!(opened, vec![1, 0]);

        let profile = runtime.runtime_phase_profile().expect("runtime profile");
        let threshold_profile = profile
            .iter()
            .find(|entry| {
                entry.phase == talus_dkg::PrimeFieldMpcPhase::BitSumThresholdCheck
                    && entry.kind == talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce
            })
            .expect("threshold profile");
        assert!(
            threshold_profile.max_record_lanes >= 2,
            "hint-weight candidates should be packed as vector lanes"
        );
        assert!(
            threshold_profile.distinct_labels <= 96,
            "packed hint-weight threshold should not duplicate threshold rounds per candidate"
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_fused_validity_rejects_z_failure_after_hint_threshold() {
        let (config, mut runtime, label) = strict_test_vector_runtime_one_party(102);
        let h_bits = vec![runtime
            .bit_share_vec_from_local_lanes::<MlDsa44>(
                &config,
                &label.child("h_bits"),
                vec![0; MlDsa44::K * MlDsa44::N],
            )
            .expect("h bits")];
        let z_ok = vec![runtime
            .bit_share_vec_from_local_lanes::<MlDsa44>(
                &config,
                &label.child("z_ok"),
                vec![1; MlDsa44::L * MlDsa44::N],
            )
            .expect("z ok")];
        let mut entropy = TestProductionVectorEntropy::default();
        let valid = strict_run_fused_validity_checks_batch::<MlDsa44, _, _, _, _>(
            &z_ok,
            &h_bits,
            &mut runtime,
            &config,
            &label.child("valid_all_ok"),
            &mut entropy,
        )
        .expect("validity all ok");
        let open_label = label.child("valid_all_ok/open");
        runtime
            .drive_open_bit_share_vec::<MlDsa44>(&config, &valid[0], &open_label)
            .expect("drive valid open");
        let opened = strict_collected_value(
            runtime
                .collect_open_bit_share_vec::<MlDsa44>(&config, &open_label)
                .expect("collect valid open"),
        )
        .expect("opened valid");
        assert_eq!(opened, vec![1]);

        let mut z_bad_lanes = vec![1; MlDsa44::L * MlDsa44::N];
        z_bad_lanes[0] = 0;
        let z_bad = vec![runtime
            .bit_share_vec_from_local_lanes::<MlDsa44>(&config, &label.child("z_bad"), z_bad_lanes)
            .expect("z bad")];
        let invalid = strict_run_fused_validity_checks_batch::<MlDsa44, _, _, _, _>(
            &z_bad,
            &h_bits,
            &mut runtime,
            &config,
            &label.child("valid_z_bad"),
            &mut entropy,
        )
        .expect("validity z bad");
        let open_label = label.child("valid_z_bad/open");
        runtime
            .drive_open_bit_share_vec::<MlDsa44>(&config, &invalid[0], &open_label)
            .expect("drive invalid open");
        let opened = strict_collected_value(
            runtime
                .collect_open_bit_share_vec::<MlDsa44>(&config, &open_label)
                .expect("collect invalid open"),
        )
        .expect("opened invalid");
        assert_eq!(opened, vec![0]);
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_all_bits_true_packs_candidates_as_runtime_lanes() {
        let (config, mut runtime, label) = strict_test_vector_runtime_one_party(92);
        let lane_count = MlDsa44::L * MlDsa44::N;
        let mut invalid = vec![1; lane_count];
        invalid[lane_count / 2] = 0;
        let bits_by_candidate = vec![
            runtime
                .bit_share_vec_from_local_lanes::<MlDsa44>(
                    &config,
                    &label.child("all_true"),
                    vec![1; lane_count],
                )
                .expect("all true"),
            runtime
                .bit_share_vec_from_local_lanes::<MlDsa44>(
                    &config,
                    &label.child("one_false"),
                    invalid,
                )
                .expect("one false"),
        ];
        let mut entropy = TestProductionVectorEntropy::default();
        let results = strict_run_all_bits_true_packed_batch::<MlDsa44, _, _, _, _>(
            &bits_by_candidate,
            &mut runtime,
            &config,
            &label.child("all_bits_true_packed"),
            &mut entropy,
        )
        .expect("packed all true");
        let opened = results
            .iter()
            .enumerate()
            .map(|(idx, result)| {
                let open_label = label.child(format!("all_true_ok_{idx}/open"));
                runtime
                    .drive_open_bit_share_vec::<MlDsa44>(&config, result, &open_label)
                    .expect("drive all true open");
                strict_collected_value(
                    runtime
                        .collect_open_bit_share_vec::<MlDsa44>(&config, &open_label)
                        .expect("collect all true open"),
                )
                .expect("opened all true")[0]
            })
            .collect::<Vec<_>>();
        assert_eq!(opened, vec![1, 0]);

        let profile = runtime.runtime_phase_profile().expect("runtime profile");
        let threshold_profile = profile
            .iter()
            .find(|entry| {
                entry.phase == talus_dkg::PrimeFieldMpcPhase::BitSumThresholdCheck
                    && entry.kind == talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce
            })
            .expect("threshold profile");
        assert!(
            threshold_profile.max_record_lanes >= 2,
            "all-true candidates should be packed as vector lanes"
        );
        assert!(
            threshold_profile.distinct_labels <= 96,
            "packed all-true threshold should not duplicate threshold rounds per candidate"
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_z_bound_check_packs_lower_and_upper_comparisons() {
        let (config, mut runtime, label) = strict_test_vector_runtime_one_party(93);
        let gamma = (MlDsa65::GAMMA1 - MlDsa65::BETA) as Coeff;
        let upper = MlDsa65::Q - gamma;
        let z_values = vec![0, gamma - 1, gamma, upper, upper + 1, MlDsa65::Q - 1];
        let z_bits = (0..23)
            .map(|bit_idx| {
                runtime
                    .bit_share_vec_from_local_lanes::<MlDsa65>(
                        &config,
                        &label.child(format!("z_bit_{bit_idx}")),
                        z_values
                            .iter()
                            .map(|&value| (value >> bit_idx) & 1)
                            .collect::<Vec<_>>(),
                    )
                    .expect("z bit")
            })
            .collect::<Vec<_>>();
        let mut state = StrictRuntimeZBoundCheckState::new::<MlDsa65, _, _, _>(
            &runtime,
            &config,
            &z_bits,
            &label.child("z_bound"),
        )
        .expect("z-bound state");
        let mut entropy = TestProductionVectorEntropy::default();
        while state.lt_gamma.is_none() {
            state
                .drive_packed_bounds_step::<MlDsa65, _, _, _, _>(
                    &mut runtime,
                    &config,
                    &mut entropy,
                )
                .expect("drive packed z-bound");
            strict_collected_unit(
                state
                    .collect_packed_bounds_step::<MlDsa65, _, _, _>(&mut runtime, &config)
                    .expect("collect packed z-bound"),
            )
            .expect("packed z-bound step");
        }
        state
            .drive_or_step::<MlDsa65, _, _, _, _>(
                &mut runtime,
                &config,
                &label.child("z_bound"),
                &mut entropy,
            )
            .expect("drive z-bound or");
        strict_collected_unit(
            state
                .collect_or_step::<MlDsa65, _, _, _>(&mut runtime, &config, &label.child("z_bound"))
                .expect("collect z-bound or"),
        )
        .expect("z-bound or step");
        let result = state.result().expect("z-bound result").clone();
        let open_label = label.child("z_bound/open");
        runtime
            .drive_open_bit_share_vec::<MlDsa65>(&config, &result, &open_label)
            .expect("drive z-bound open");
        let opened = strict_collected_value(
            runtime
                .collect_open_bit_share_vec::<MlDsa65>(&config, &open_label)
                .expect("collect z-bound open"),
        )
        .expect("opened z-bound");
        assert_eq!(opened, vec![1, 1, 0, 0, 1, 1]);

        let profile = runtime.runtime_phase_profile().expect("runtime profile");
        let comparison_profile = profile
            .iter()
            .find(|entry| {
                entry.phase == talus_dkg::PrimeFieldMpcPhase::ComparisonToPublicCheck
                    && entry.kind == talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce
            })
            .expect("comparison profile");
        assert!(
            comparison_profile.max_record_lanes >= z_values.len() as u64 * 2,
            "z-bound lower/upper comparisons should be packed in one comparison state"
        );
        assert!(
            comparison_profile.distinct_labels <= 23,
            "packed z-bound should not run separate lower and upper comparison states"
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_hint_highbits_packs_bounds_and_reuses_interval_product() {
        let (config, mut runtime, label) = strict_test_vector_runtime_one_party(94);
        let lane_count = MlDsa44::K * MlDsa44::N;
        let mut w1 = vec![0u32; lane_count];
        w1[1] = 1;
        w1[2] = 2;
        w1[4] = 1;
        w1[5] = 2;
        let (lower, upper_exclusive, wraps_zero) =
            strict_highbits_interval_constants::<MlDsa44>(&w1).expect("interval constants");
        let mut r_values = vec![0 as Coeff; lane_count];
        for (idx, value) in r_values.iter_mut().enumerate() {
            *value = if wraps_zero[idx] == 1 {
                0
            } else {
                lower[idx] + 1
            };
        }
        let mut expected_hint_bits = vec![0 as Coeff; lane_count];
        r_values[1] = lower[1];
        expected_hint_bits[1] = 1;
        r_values[3] = upper_exclusive[3];
        expected_hint_bits[3] = 1;
        r_values[5] = upper_exclusive[5];
        expected_hint_bits[5] = 1;

        let r_bits = (0..23)
            .map(|bit_idx| {
                runtime
                    .bit_share_vec_from_local_lanes::<MlDsa44>(
                        &config,
                        &label.child(format!("hint_r_bit_{bit_idx}")),
                        r_values
                            .iter()
                            .map(|&value| (value >> bit_idx) & 1)
                            .collect::<Vec<_>>(),
                    )
                    .expect("hint r bit")
            })
            .collect::<Vec<_>>();
        let mut state = StrictRuntimeHintBitsCheckState::new::<MlDsa44, _, _, _>(
            &runtime,
            &config,
            &r_bits,
            &w1,
            &label.child("hint_bits"),
        )
        .expect("hint state");
        let mut entropy = TestProductionVectorEntropy::default();
        while state.gt_lower.is_none() {
            state
                .drive_packed_bounds_step::<MlDsa44, _, _, _, _>(
                    &mut runtime,
                    &config,
                    &mut entropy,
                )
                .expect("drive packed highbits bounds");
            strict_collected_unit(
                state
                    .collect_packed_bounds_step::<MlDsa44, _, _, _>(&mut runtime, &config)
                    .expect("collect packed highbits bounds"),
            )
            .expect("packed highbits bounds");
        }
        state
            .drive_interval_and_step::<MlDsa44, _, _, _, _>(
                &mut runtime,
                &config,
                &label.child("hint_bits"),
                &mut entropy,
            )
            .expect("drive highbits interval product");
        strict_collected_unit(
            state
                .collect_interval_and_finalize::<MlDsa44, _, _, _>(
                    &mut runtime,
                    &config,
                    &label.child("hint_bits"),
                )
                .expect("collect highbits interval product"),
        )
        .expect("highbits interval product");

        let result = state.hint_bits().expect("hint bits").clone();
        let open_label = label.child("hint_bits/open");
        runtime
            .drive_open_bit_share_vec::<MlDsa44>(&config, &result, &open_label)
            .expect("drive hint open");
        let opened = strict_collected_value(
            runtime
                .collect_open_bit_share_vec::<MlDsa44>(&config, &open_label)
                .expect("collect hint open"),
        )
        .expect("opened hint bits");
        assert_eq!(&opened[..8], &expected_hint_bits[..8]);
        assert!(
            opened
                .iter()
                .zip(expected_hint_bits.iter())
                .all(|(actual, expected)| actual == expected),
            "private highbits hint bits must match the interval relation without opening intermediate predicates"
        );

        let profile = runtime.runtime_phase_profile().expect("runtime profile");
        let comparison_profile = profile
            .iter()
            .find(|entry| {
                entry.phase == talus_dkg::PrimeFieldMpcPhase::ComparisonToPublicCheck
                    && entry.kind == talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce
            })
            .expect("highbits comparison profile");
        assert!(
            comparison_profile.max_record_lanes >= lane_count as u64 * 2,
            "hint highbits lower/upper comparisons should be packed in one comparison state"
        );
        assert!(
            comparison_profile.distinct_labels <= 23,
            "packed hint highbits should not run separate lower and upper comparison states"
        );
        let interval_profile = profile
            .iter()
            .find(|entry| {
                entry.phase == talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare
                    && entry.kind == talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce
                    && entry.max_record_lanes >= lane_count as u64
            })
            .expect("highbits interval profile");
        assert!(
            interval_profile.distinct_labels <= 24,
            "hint highbits should reuse one interval product instead of separate AND and OR products"
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_chunked_z_bound_and_hint_checks_aggregate_private_chunk_bits() {
        let (config, mut runtime, label) = strict_test_vector_runtime_one_party(95);
        let gamma = (MlDsa65::GAMMA1 - MlDsa65::BETA) as Coeff;
        let z_values = vec![0, gamma - 1, gamma, MlDsa65::Q - 1, 1, 2];
        let z_bits_by_candidate = [&z_values]
            .iter()
            .enumerate()
            .map(|(candidate_idx, values)| {
                (0..23)
                    .map(|bit_idx| {
                        runtime
                            .bit_share_vec_from_local_lanes::<MlDsa65>(
                                &config,
                                &label.child(format!("z_candidate_{candidate_idx}/bit_{bit_idx}")),
                                values
                                    .iter()
                                    .map(|&value| (value >> bit_idx) & 1)
                                    .collect::<Vec<_>>(),
                            )
                            .expect("z bit")
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let labels = (0..1)
            .map(|idx| label.child(format!("candidate_{idx}")))
            .collect::<Vec<_>>();
        let mut entropy = TestProductionVectorEntropy::default();
        let z_ok = strict_run_z_bound_checks_chunked_batch::<MlDsa65, _, _, _, _>(
            &z_bits_by_candidate,
            &labels,
            2,
            &mut runtime,
            &config,
            &label.child("chunked_z_bound"),
            &mut entropy,
        )
        .expect("chunked z-bound");
        let z_opened = z_ok
            .iter()
            .enumerate()
            .map(|(idx, bit)| {
                let open_label = label.child(format!("z_ok_{idx}/open"));
                runtime
                    .drive_open_bit_share_vec::<MlDsa65>(&config, bit, &open_label)
                    .expect("drive z ok open");
                strict_collected_value(
                    runtime
                        .collect_open_bit_share_vec::<MlDsa65>(&config, &open_label)
                        .expect("collect z ok open"),
                )
                .expect("opened z ok")[0]
            })
            .collect::<Vec<_>>();
        assert_eq!(z_opened, vec![0]);

        let lane_count = 6;
        let mut w1 = vec![0u32; lane_count];
        w1[1] = 1;
        w1[3] = 2;
        let (lower, upper_exclusive, wraps_zero) =
            strict_highbits_interval_constants_for_lanes::<MlDsa44>(&w1).expect("hint constants");
        let mut r_values = vec![0 as Coeff; lane_count];
        for (idx, value) in r_values.iter_mut().enumerate() {
            *value = if wraps_zero[idx] == 1 {
                0
            } else {
                lower[idx] + 1
            };
        }
        r_values[3] = upper_exclusive[3];
        let hint_bits_by_candidate = [&r_values]
            .iter()
            .enumerate()
            .map(|(candidate_idx, values)| {
                (0..23)
                    .map(|bit_idx| {
                        runtime
                            .bit_share_vec_from_local_lanes::<MlDsa44>(
                                &config,
                                &label
                                    .child(format!("hint_candidate_{candidate_idx}/bit_{bit_idx}")),
                                values
                                    .iter()
                                    .map(|&value| (value >> bit_idx) & 1)
                                    .collect::<Vec<_>>(),
                            )
                            .expect("hint bit")
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let h_bits = strict_run_hint_bits_checks_chunked_batch::<MlDsa44, _, _, _, _>(
            &hint_bits_by_candidate,
            &[w1],
            &labels,
            2,
            &mut runtime,
            &config,
            &label.child("chunked_hint"),
            &mut entropy,
        )
        .expect("chunked hint");
        let opened_h = h_bits
            .iter()
            .enumerate()
            .map(|(idx, bits)| {
                let open_label = label.child(format!("h_bits_{idx}/open"));
                runtime
                    .drive_open_bit_share_vec::<MlDsa44>(&config, bits, &open_label)
                    .expect("drive h open");
                strict_collected_value(
                    runtime
                        .collect_open_bit_share_vec::<MlDsa44>(&config, &open_label)
                        .expect("collect h open"),
                )
                .expect("opened h")
            })
            .collect::<Vec<_>>();
        assert_eq!(opened_h[0][3], 1);
        assert_eq!(
            opened_h[0]
                .iter()
                .enumerate()
                .filter(|(_, bit)| **bit == 1)
                .map(|(idx, _)| idx)
                .collect::<Vec<_>>(),
            vec![3],
            "only the out-of-interval chunk lane should become a hint bit"
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_chunked_hint_weight_aggregates_private_partial_counts() {
        let (config, mut runtime, label) = strict_test_vector_runtime_one_party(96);
        let lane_count = MlDsa44::K * MlDsa44::N;
        let mut too_many_hints = vec![0; lane_count];
        for bit in too_many_hints.iter_mut().take(MlDsa44::OMEGA as usize + 1) {
            *bit = 1;
        }
        let h_bits = vec![runtime
            .bit_share_vec_from_local_lanes::<MlDsa44>(
                &config,
                &label.child("h_bits"),
                too_many_hints,
            )
            .expect("h bits")];
        let mut entropy = TestProductionVectorEntropy::default();
        let result = strict_run_hint_weight_checks_chunked_batch::<MlDsa44, _, _, _, _>(
            &h_bits,
            64,
            &mut runtime,
            &config,
            &label.child("hint_weight_chunked"),
            &mut entropy,
        )
        .expect("chunked hint weight");
        let open_label = label.child("hint_weight_chunked/open");
        runtime
            .drive_open_bit_share_vec::<MlDsa44>(&config, &result[0], &open_label)
            .expect("drive chunked hint open");
        let opened = strict_collected_value(
            runtime
                .collect_open_bit_share_vec::<MlDsa44>(&config, &open_label)
                .expect("collect chunked hint open"),
        )
        .expect("opened chunked hint");
        assert_eq!(
            opened,
            vec![0],
            "private partial counts across chunks must reject total hint weight above omega"
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_selected_share_opening_chunks_open_only_selected_lanes() {
        let (config, mut runtime, label) = strict_test_vector_runtime_one_party(97);
        let selected = vec![runtime
            .bit_share_vec_from_local_lanes::<MlDsa65>(&config, &label.child("selected"), vec![1])
            .expect("selected bit")];
        let values = vec![runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &label.child("value"),
                vec![1, 2, 3, 4, 5, 6],
            )
            .expect("value share")];
        let mut entropy = TestProductionVectorEntropy::default();
        let opened = strict_selected_share_opening_chunks::<MlDsa65, _, _, _, _>(
            &mut runtime,
            &config,
            &selected,
            &values,
            2,
            &label.child("selected_chunks"),
            &mut entropy,
        )
        .expect("chunked selected opening");
        assert_eq!(opened, vec![1, 2, 3, 4, 5, 6]);

        let profile = runtime.runtime_phase_profile().expect("runtime profile");
        let opening_profile = profile
            .iter()
            .find(|entry| {
                entry.phase == talus_dkg::PrimeFieldMpcPhase::OpenShare
                    && entry.max_record_lanes <= 2
            })
            .expect("chunked selected opening profile");
        assert!(
            opening_profile.records >= 3,
            "selected opening should be split into bounded chunks"
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_selected_share_opening_uses_affine_one_hot_products() {
        let (config, mut runtime, label) = strict_test_vector_runtime_one_party(101);
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
        let values = vec![
            runtime
                .share_vec_from_local_lanes::<MlDsa65>(
                    &config,
                    &label.child("value_0"),
                    vec![10, 20, 30, 40],
                )
                .expect("value 0"),
            runtime
                .share_vec_from_local_lanes::<MlDsa65>(
                    &config,
                    &label.child("value_1"),
                    vec![1, 2, 3, 4],
                )
                .expect("value 1"),
        ];
        let mut entropy = TestProductionVectorEntropy::default();
        let opened = strict_selected_share_opening_chunks::<MlDsa65, _, _, _, _>(
            &mut runtime,
            &config,
            &selected_bits,
            &values,
            4,
            &label.child("selected_affine"),
            &mut entropy,
        )
        .expect("affine selected opening");
        assert_eq!(opened, vec![1, 2, 3, 4]);

        let profile = runtime.runtime_phase_profile().expect("runtime profile");
        let mul_profile = profile
            .iter()
            .find(|entry| {
                entry.kind == talus_dkg::PrimeFieldMpcRoundKind::MulDegreeReduce
                    && entry.phase == talus_dkg::PrimeFieldMpcPhase::MulDegreeReductionShare
            })
            .expect("selected product profile");
        assert_eq!(
            mul_profile.distinct_labels, 1,
            "two-candidate affine selected opening should use one product label"
        );
        assert_eq!(
            mul_profile.max_record_lanes, 4,
            "two-candidate affine selected opening should send one delta vector per product record"
        );
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
