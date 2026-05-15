#![doc = "Internal implementation for production-facing TALUS preprocessing APIs."]

use core::fmt;
use core::marker::PhantomData;

use sha3::{Digest, Sha3_256};
use talus_core::{
    az_from_rho, bcc_holds_coeff, high_bits_unsigned, lagrange_coefficients_at_zero,
    low_bits_unsigned, reduce_mod_q, Coeff, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Poly, PolyVec,
    ProductionBatchSizingPolicy, TalusPerformanceCounters, TokenPassProbabilityEstimate,
};
use talus_dkg::{
    ensure_preprocessing_wire_log_private_circuits_for_release,
    ensure_prime_field_mpc_counters_vectorized_for_release,
    ensure_prime_field_mpc_wire_log_contains_broadcast_vec, evaluate_shamir_polynomial,
    hash_it_vss_complaint_resolution, hash_it_vss_public_commitment, power2round_label_hash,
    production_it_vss_public_coin_share, production_it_vss_public_coin_transcript, DkgConfig,
    DkgError, ItVssComplaintResolution, ItVssPrivateShareDelivery, ItVssPublicCommitment,
    ItVssPublicPrecommitment, ItVssSharingDomain, ItVssSharingLabel, Power2RoundTranscriptLabel,
    PrimeFieldMpcPhase, PrimeFieldMpcPhaseCursor, PrimeFieldMpcPhaseCursorLog,
    PrimeFieldMpcPhaseCursorState, PrimeFieldMpcPhaseDriverStatus, PrimeFieldMpcRoundKind,
    PrimeFieldMpcWireMessageLog, ProductionBitShareVec, ProductionBitSumLeqPublicVecState,
    ProductionInformationCheckingVssBackend, ProductionItVssBackend,
    ProductionItVssPreparedDealerOutput, ProductionItVssPublicCoinShare,
    ProductionItVssSecurityParams, ProductionPublicComparisonVecState, ProductionShareVec,
    ProductionVectorItMpcCollectResult, ProductionVectorItMpcEntropy,
    ProductionVectorItMpcRuntimeEvidence, ProductionVectorPrimeFieldMpcRuntime,
};
use talus_mpc_core::PartyId;
use talus_wire::{
    decode_commit_payload, decode_masked_broadcast_open_payload, encode_commit_payload,
    encode_masked_broadcast_open_payload, signing_set_hash, validate_round_batch,
    AuthenticatedP2pTransport, CommitPayload, EquivocationResistantBroadcast, ExpectedContext,
    MaskedBroadcastOpenPayload, PayloadKind, RoundId, SuiteId, WireHeader, WireMessage,
    WIRE_PROTOCOL_VERSION,
};
use zeroize::Zeroizing;

#[cfg(any(test, feature = "paper-fast-dev"))]
use crate::local_dev::MaskedBroadcastClearAudit;

/// TALUS preprocessing session identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId(pub [u8; 32]);

/// Transcript hash.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TranscriptHash(pub [u8; 32]);

/// Commit/open commitment.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Commitment(pub [u8; 32]);

/// Nonce commitment placeholder bound into certified tokens.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NonceCommitment(pub [u8; 32]);

/// One party's clear local preprocessing input for the current adapter layer.
#[derive(Clone, Eq, PartialEq)]
pub struct PartyPreprocessInput {
    /// Party identifier.
    pub party: PartyId,
    /// Unsigned high bits of this party's local `A*yhat_i` contribution.
    pub highs: Vec<u32>,
    /// Unsigned low bits of this party's local `A*yhat_i` contribution.
    pub lows: Vec<u32>,
    /// Secret local nonce-share material retained in the certified token.
    pub y_share: Vec<u8>,
    /// Optional local `A*y_i` contribution witness for tests/dev diagnostics.
    /// Production CEF/BCC certification must not depend on this field and
    /// certifies token admission from the opened masked-broadcast material.
    pub ay_contribution: Option<PolyVec>,
    /// Public nonce commitment.
    pub nonce_commitment: NonceCommitment,
    /// Local randomness commitment used by rho derivation.
    pub randomness_commitment: Commitment,
}

impl fmt::Debug for PartyPreprocessInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartyPreprocessInput")
            .field("party", &self.party)
            .field("highs_len", &self.highs.len())
            .field("lows_len", &self.lows.len())
            .field("y_share", &"<redacted>")
            .field("ay_contribution", &"<redacted>")
            .field("nonce_commitment", &self.nonce_commitment)
            .field("randomness_commitment", &self.randomness_commitment)
            .finish()
    }
}

/// Options for starting one production-facing preprocessing session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreprocessingSessionOptions {
    /// Fresh preprocessing session id.
    pub session_id: SessionId,
    /// Canonical signer set expected in this preprocessing session.
    pub signer_set: Vec<PartyId>,
    /// DKG/keygen transcript hash bound into transport messages.
    pub keygen_transcript_hash: [u8; 32],
}

/// Outbound preprocessing message emitted by [`PreprocessingSession`].
///
/// The crate emits canonical TALUS wire messages only. The embedding
/// application owns transport, ML-KEM channel/session establishment, ML-DSA
/// identity authentication, reliable broadcast, retries, and durable delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreprocessingOutbound {
    /// Directed private message. Current preprocessing certification is
    /// broadcast-only, so this variant is reserved for future proof backends.
    Private {
        /// Authenticated receiver party id.
        receiver: PartyId,
        /// Canonical wire message to deliver over the private channel.
        message: WireMessage,
    },
    /// Equivocation-resistant broadcast delivery.
    Broadcast {
        /// Canonical wire message to deliver through reliable broadcast.
        message: WireMessage,
    },
}

/// Production-facing preprocessing session facade.
///
/// This is the narrow API applications should use for preprocessing:
/// create a session from local preprocessing input, route outbound wire
/// messages through the application transport, inject reliable-broadcast
/// messages received from the signer set, then finish with a certified token.
///
/// The current adapter carries local preprocessing inputs through a commit/open
/// transcript and finishes through the existing CEF/BCC certification primitive.
/// Nonce generation, product masked-broadcast proofs, and crash-safe token
/// persistence plug in behind this same facade rather than changing the
/// application transport API.
///
/// `finish` returns a pre-challenge certified token. Release-capable token
/// output must be built through
/// [`certify_preprocessing_token_release_validated_with_runtime`], which
/// requires the private vector-runtime proof bundle and durable runtime
/// evidence before attaching a release certificate.
pub struct PreprocessingSession<P, S, V>
where
    P: MlDsaParams,
    S: SessionStore,
    V: MaskedBroadcastConsistencyVerifier,
{
    options: PreprocessingSessionOptions,
    local_input: PartyPreprocessInput,
    registry: S,
    verifier: V,
    expected_context: ExpectedContext,
    commits: Vec<(PartyId, Commitment)>,
    envelopes: Vec<BroadcastEnvelope>,
    inputs: Vec<PartyPreprocessInput>,
    outbound: Vec<PreprocessingOutbound>,
    open_sent: bool,
    _params: PhantomData<P>,
}

impl<P, S, V> PreprocessingSession<P, S, V>
where
    P: MlDsaParams,
    S: SessionStore,
    V: MaskedBroadcastConsistencyVerifier,
{
    /// Starts a preprocessing session for one local party.
    pub fn start(
        options: PreprocessingSessionOptions,
        local_input: PartyPreprocessInput,
        registry: S,
        verifier: V,
    ) -> Result<Self, PreprocessError> {
        let signer_set = canonical_signer_set(&options.signer_set)?;
        if !signer_set.contains(&local_input.party) {
            return Err(PreprocessError::UnknownParty(local_input.party));
        }
        validate_inputs::<P>(core::slice::from_ref(&local_input))?;

        let expected_context = preprocessing_expected_context::<P>(
            options.session_id,
            &signer_set,
            options.keygen_transcript_hash,
        );
        let options = PreprocessingSessionOptions {
            signer_set,
            ..options
        };
        let mut session = Self {
            options,
            local_input,
            registry,
            verifier,
            expected_context,
            commits: Vec::new(),
            envelopes: Vec::new(),
            inputs: Vec::new(),
            outbound: Vec::new(),
            open_sent: false,
            _params: PhantomData,
        };
        session.enqueue_local_commit();
        Ok(session)
    }

    /// Injects one application-authenticated private message.
    ///
    /// Current preprocessing certification is broadcast-only; private
    /// deliveries are rejected so applications do not accidentally route a
    /// different protocol into this session.
    pub fn handle_private(
        &mut self,
        _sender: PartyId,
        _message: WireMessage,
    ) -> Result<(), PreprocessError> {
        Err(PreprocessError::UnexpectedPrivateMessage)
    }

    /// Injects one reliable-broadcast message delivered to this local party.
    pub fn handle_broadcast(&mut self, message: WireMessage) -> Result<(), PreprocessError> {
        match message.header.round {
            RoundId::PreprocessCommit => {
                validate_round_batch(
                    core::slice::from_ref(&message),
                    RoundId::PreprocessCommit,
                    &self.expected_context,
                )
                .map_err(|_| PreprocessError::UnexpectedWireMessage)?;
                if message.header.payload_kind != PayloadKind::PreprocessCommit {
                    return Err(PreprocessError::UnexpectedWireMessage);
                }
                let payload = decode_commit_payload(&message.payload)
                    .map_err(|_| PreprocessError::UnexpectedWireMessage)?;
                let party = PartyId(message.header.sender_party_id);
                self.insert_commit(party, Commitment(payload.commitment))?;
            }
            RoundId::PreprocessOpen => {
                validate_round_batch(
                    core::slice::from_ref(&message),
                    RoundId::PreprocessOpen,
                    &self.expected_context,
                )
                .map_err(|_| PreprocessError::UnexpectedWireMessage)?;
                if message.header.payload_kind != PayloadKind::MaskedBroadcastOpen {
                    return Err(PreprocessError::UnexpectedWireMessage);
                }
                let payload = decode_masked_broadcast_open_payload(&message.payload)
                    .map_err(|_| PreprocessError::UnexpectedWireMessage)?;
                let party = PartyId(message.header.sender_party_id);
                self.insert_open(party, payload)?;
            }
            _ => return Err(PreprocessError::UnexpectedWireMessage),
        }
        self.advance()
    }

    /// Returns the next outbound message for the embedding application to
    /// deliver.
    pub fn next_outbound(&mut self) -> Option<PreprocessingOutbound> {
        if self.outbound.is_empty() {
            None
        } else {
            Some(self.outbound.remove(0))
        }
    }

    /// Finishes preprocessing and returns a certified token.
    pub fn finish(mut self) -> Result<CertifiedToken, PreprocessError> {
        self.advance()?;
        self.ensure_complete()?;
        certify_opened_masked_broadcasts_with_consistency::<P, V>(
            &mut self.verifier,
            &mut self.registry,
            self.options.session_id,
            self.inputs,
            self.envelopes,
            preprocessing_session_open_hash::<P>(self.options.session_id, &self.options.signer_set),
            None,
        )
    }

    /// Finishes preprocessing and returns a release-valid token by consuming
    /// the completed preprocessing transcript plus runtime-owned private
    /// preprocessing and strict-signing helper states.
    ///
    /// This is the release-oriented facade over the lower-level constructor:
    /// applications drive transport messages and vector runtime cursors, then
    /// call this method instead of manually assembling a release token. The
    /// token's `[w]` handle is derived from `nonce_share` as `[A*y]`; callers
    /// cannot inject a standalone precomputed `[w]` handle here.
    pub fn finish_with_release_runtime<T, L, C>(
        self,
        config: &DkgConfig,
        rho: &[u8; 32],
        nonce_share: &DistributedNonceShare,
        runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
        completed_state: &PreprocessingPrivateCircuitDriverState,
        completed_mask_state: StrictSigningCanonicalMaskGenerationState,
    ) -> Result<CertifiedToken, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let mut cursor_store = PreprocessingReleaseSessionCursorMemoryStore::new();
        self.finish_with_release_runtime_and_cursor_store(
            config,
            rho,
            nonce_share,
            runtime,
            completed_state,
            completed_mask_state,
            &mut cursor_store,
        )
    }

    /// Same as [`Self::finish_with_release_runtime`], additionally persisting a
    /// coarse release-preprocessing cursor before and after final token
    /// certification. The vector MPC runtime still owns fine-grained
    /// per-gate/round cursor persistence.
    pub fn finish_with_release_runtime_and_cursor_store<T, L, C, K>(
        mut self,
        config: &DkgConfig,
        rho: &[u8; 32],
        nonce_share: &DistributedNonceShare,
        runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
        completed_state: &PreprocessingPrivateCircuitDriverState,
        completed_mask_state: StrictSigningCanonicalMaskGenerationState,
        cursor_store: &mut K,
    ) -> Result<CertifiedToken, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        K: PreprocessingReleaseSessionCursorStore,
    {
        self.advance()?;
        self.ensure_complete()?;
        let transcript =
            preprocessing_session_open_hash::<P>(self.options.session_id, &self.options.signer_set);
        cursor_store.persist_release_cursor(&PreprocessingReleaseSessionCursor {
            session_id: self.options.session_id,
            phase: PreprocessingReleaseSessionPhase::TranscriptComplete,
            transcript_hash: transcript,
            token_binding_hash: None,
        })?;
        if !completed_state.is_done() {
            cursor_store.persist_release_cursor(&PreprocessingReleaseSessionCursor {
                session_id: self.options.session_id,
                phase: PreprocessingReleaseSessionPhase::Aborted,
                transcript_hash: transcript,
                token_binding_hash: None,
            })?;
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        cursor_store.persist_release_cursor(&PreprocessingReleaseSessionCursor {
            session_id: self.options.session_id,
            phase: PreprocessingReleaseSessionPhase::PrivateRuntimeComplete,
            transcript_hash: transcript,
            token_binding_hash: None,
        })?;
        if !completed_mask_state.is_done() {
            cursor_store.persist_release_cursor(&PreprocessingReleaseSessionCursor {
                session_id: self.options.session_id,
                phase: PreprocessingReleaseSessionPhase::Aborted,
                transcript_hash: transcript,
                token_binding_hash: None,
            })?;
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        cursor_store.persist_release_cursor(&PreprocessingReleaseSessionCursor {
            session_id: self.options.session_id,
            phase: PreprocessingReleaseSessionPhase::StrictMasksComplete,
            transcript_hash: transcript,
            token_binding_hash: None,
        })?;
        certify_preprocessing_token_release_validated_with_finished_runtime_driver_strict_material_and_nonce_share::<
            P, V, T, L, C,
        >(
            &mut self.verifier,
            &mut self.registry,
            self.options.session_id,
            self.inputs,
            self.envelopes,
            transcript,
            config,
            rho,
            &self.options.signer_set,
            nonce_share,
            runtime,
            completed_state,
            completed_mask_state,
        )
        .and_then(|token| {
            let token_binding_hash = token
                .vector_runtime_certificate()
                .and_then(PreprocessingVectorRuntimeCertificate::token_binding_hash);
            cursor_store.persist_release_cursor(&PreprocessingReleaseSessionCursor {
                session_id: token.session_id,
                phase: PreprocessingReleaseSessionPhase::ReleaseTokenCertified,
                transcript_hash: token.transcript_hash,
                token_binding_hash,
            })?;
            Ok(token)
        })
    }

    /// Starts the release preprocessing driver that owns private runtime
    /// scheduling, strict mask generation, coarse cursor persistence, and
    /// final release-token certification.
    pub fn into_release_driver<T, L, C, K>(
        self,
        config: DkgConfig,
        rho: [u8; 32],
        nonce_share: DistributedNonceShare,
        runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
        cursor_store: K,
    ) -> Result<PreprocessingReleaseDriver<P, S, V, K>, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        K: PreprocessingReleaseSessionCursorStore,
    {
        PreprocessingReleaseDriver::start(self, config, rho, nonce_share, runtime, cursor_store)
    }

    fn ensure_complete(&self) -> Result<(), PreprocessError> {
        if self.commits.len() != self.options.signer_set.len()
            || self.envelopes.len() != self.options.signer_set.len()
            || self.inputs.len() != self.options.signer_set.len()
            || !self.outbound.is_empty()
        {
            return Err(PreprocessError::IncompleteSession);
        }
        let mut input_parties = self
            .inputs
            .iter()
            .map(|input| input.party)
            .collect::<Vec<_>>();
        input_parties.sort_unstable();
        if input_parties != self.options.signer_set {
            return Err(PreprocessError::IncompleteSession);
        }
        Ok(())
    }

    fn advance(&mut self) -> Result<(), PreprocessError> {
        if !self.open_sent && self.commits.len() == self.options.signer_set.len() {
            self.enqueue_local_open()?;
            self.open_sent = true;
        }
        Ok(())
    }

    fn enqueue_local_commit(&mut self) {
        let open_hash =
            preprocessing_session_open_hash::<P>(self.options.session_id, &self.options.signer_set);
        let envelope = prepare_masked_broadcast_envelope::<P>(
            self.options.session_id,
            &self.options.signer_set,
            &self.local_input,
            open_hash,
        )
        .expect("local preprocessing input was validated at session start");
        let message = self.wire_message(
            self.local_input.party,
            RoundId::PreprocessCommit,
            PayloadKind::PreprocessCommit,
            encode_commit_payload(&CommitPayload {
                commitment: envelope.commitment.0,
            }),
        );
        self.outbound
            .push(PreprocessingOutbound::Broadcast { message });
    }

    fn enqueue_local_open(&mut self) -> Result<(), PreprocessError> {
        let open_hash =
            preprocessing_session_open_hash::<P>(self.options.session_id, &self.options.signer_set);
        let envelope = prepare_masked_broadcast_envelope::<P>(
            self.options.session_id,
            &self.options.signer_set,
            &self.local_input,
            open_hash,
        )?;
        let payload = MaskedBroadcastOpenPayload {
            masked_highs: envelope.message.masked_highs,
            masked_lows: envelope.message.masked_lows,
            nonce_commitment: envelope.message.nonce_commitment.0,
            rho_bits_commitment: envelope.message.rho_bits_commitment.0,
            transcript_hash: envelope.message.transcript_hash.0,
            consistency_proof: envelope.consistency_proof.bytes,
            salt: envelope.salt,
        };
        let payload = encode_masked_broadcast_open_payload(&payload)
            .map_err(|_| PreprocessError::UnexpectedWireMessage)?;
        let message = self.wire_message(
            self.local_input.party,
            RoundId::PreprocessOpen,
            PayloadKind::MaskedBroadcastOpen,
            payload,
        );
        self.outbound
            .push(PreprocessingOutbound::Broadcast { message });
        Ok(())
    }

    fn insert_commit(
        &mut self,
        party: PartyId,
        commitment: Commitment,
    ) -> Result<(), PreprocessError> {
        if !self.options.signer_set.contains(&party) {
            return Err(PreprocessError::UnknownParty(party));
        }
        if self.commits.iter().any(|(seen, _)| *seen == party) {
            return Err(PreprocessError::DuplicateBroadcast(party));
        }
        self.commits.push((party, commitment));
        Ok(())
    }

    fn insert_open(
        &mut self,
        party: PartyId,
        payload: MaskedBroadcastOpenPayload,
    ) -> Result<(), PreprocessError> {
        if !self.options.signer_set.contains(&party) {
            return Err(PreprocessError::UnknownParty(party));
        }
        if self.inputs.iter().any(|input| input.party == party) {
            return Err(PreprocessError::DuplicateBroadcast(party));
        }
        let expected_open_hash =
            preprocessing_session_open_hash::<P>(self.options.session_id, &self.options.signer_set);
        if payload.transcript_hash != expected_open_hash.0 {
            return Err(PreprocessError::TranscriptMismatch(party));
        }
        let message = MaskedBroadcast {
            party,
            masked_highs: payload.masked_highs,
            masked_lows: payload.masked_lows,
            nonce_commitment: NonceCommitment(payload.nonce_commitment),
            rho_bits_commitment: Commitment(payload.rho_bits_commitment),
            transcript_hash: TranscriptHash(payload.transcript_hash),
        };
        let expected_commitment =
            masked_broadcast_commitment(self.options.session_id, &message, payload.salt);
        let Some((_, actual_commitment)) = self.commits.iter().find(|(seen, _)| *seen == party)
        else {
            return Err(PreprocessError::CommitmentMismatch(party));
        };
        if *actual_commitment != expected_commitment {
            return Err(PreprocessError::CommitmentMismatch(party));
        }
        let mut input = unmask_preprocess_input_from_broadcast::<P>(
            self.options.session_id,
            &self.options.signer_set,
            &message,
        )?;
        if party == self.local_input.party {
            input.y_share = self.local_input.y_share.clone();
        }
        validate_inputs::<P>(core::slice::from_ref(&input))?;
        self.envelopes.push(BroadcastEnvelope {
            commitment: expected_commitment,
            message,
            consistency_proof: MaskedBroadcastConsistencyProof {
                bytes: payload.consistency_proof,
            },
            salt: payload.salt,
        });
        self.inputs.push(input);
        Ok(())
    }

    fn wire_message(
        &self,
        party: PartyId,
        round: RoundId,
        payload_kind: PayloadKind,
        payload: Vec<u8>,
    ) -> WireMessage {
        WireMessage {
            header: WireHeader {
                protocol_version: WIRE_PROTOCOL_VERSION,
                suite: preprocessing_wire_suite::<P>(),
                round,
                sender_party_id: party.0,
                keygen_transcript_hash: self.options.keygen_transcript_hash,
                session_id: self.options.session_id.0,
                signing_set_hash: signing_set_hash(
                    &self
                        .options
                        .signer_set
                        .iter()
                        .map(|party| party.0)
                        .collect::<Vec<_>>(),
                ),
                payload_kind,
            },
            payload,
        }
    }
}

/// Coarse durable phase for release-capable preprocessing finalization.
///
/// Fine-grained vector MPC phase cursors remain in the Phase 3 runtime cursor
/// log. This cursor records the application-level release-token lifecycle so a
/// restart can distinguish a complete transcript from a release-certified
/// token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreprocessingReleaseSessionPhase {
    /// Reliable-broadcast commit/open transcript is complete.
    TranscriptComplete,
    /// Private preprocessing CarryCompare/CEF/BCC runtime state is complete.
    PrivateRuntimeComplete,
    /// Strict-signing mask generation runtime state is complete.
    StrictMasksComplete,
    /// A release-certified token was emitted.
    ReleaseTokenCertified,
    /// Session failed closed.
    Aborted,
}

/// Durable coarse cursor for one release-capable preprocessing session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreprocessingReleaseSessionCursor {
    /// Preprocessing session id.
    pub session_id: SessionId,
    /// Coarse release phase.
    pub phase: PreprocessingReleaseSessionPhase,
    /// Transcript hash of the completed preprocessing commit/open material.
    pub transcript_hash: TranscriptHash,
    /// Token-binding hash once the release certificate exists.
    pub token_binding_hash: Option<[u8; 32]>,
}

/// Persistence API for release-preprocessing coarse cursors.
pub trait PreprocessingReleaseSessionCursorStore {
    /// Persists one cursor update.
    fn persist_release_cursor(
        &mut self,
        cursor: &PreprocessingReleaseSessionCursor,
    ) -> Result<(), PreprocessError>;

    /// Returns all persisted cursors.
    fn release_cursors(&self) -> &[PreprocessingReleaseSessionCursor];

    /// Returns the latest cursor for `session_id`.
    fn latest_release_cursor(
        &self,
        session_id: SessionId,
    ) -> Option<&PreprocessingReleaseSessionCursor> {
        self.release_cursors()
            .iter()
            .rev()
            .find(|cursor| cursor.session_id == session_id)
    }
}

/// In-memory release preprocessing cursor store.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PreprocessingReleaseSessionCursorMemoryStore {
    cursors: Vec<PreprocessingReleaseSessionCursor>,
}

impl PreprocessingReleaseSessionCursorMemoryStore {
    /// Creates an empty cursor store.
    pub fn new() -> Self {
        Self {
            cursors: Vec::new(),
        }
    }
}

impl PreprocessingReleaseSessionCursorStore for PreprocessingReleaseSessionCursorMemoryStore {
    fn persist_release_cursor(
        &mut self,
        cursor: &PreprocessingReleaseSessionCursor,
    ) -> Result<(), PreprocessError> {
        if self.cursors.last() == Some(cursor) {
            return Ok(());
        }
        self.cursors.push(*cursor);
        Ok(())
    }

    fn release_cursors(&self) -> &[PreprocessingReleaseSessionCursor] {
        &self.cursors
    }
}

/// File-backed release preprocessing cursor store.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePreprocessingReleaseSessionCursorStore {
    path: std::path::PathBuf,
    inner: PreprocessingReleaseSessionCursorMemoryStore,
}

#[cfg(feature = "std")]
impl FilePreprocessingReleaseSessionCursorStore {
    /// Opens or creates a release preprocessing cursor log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, PreprocessError> {
        let path = path.into();
        let mut inner = PreprocessingReleaseSessionCursorMemoryStore::new();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let cursor = parse_preprocessing_release_session_cursor_line(line).ok_or(
                        PreprocessError::SessionStoreCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    inner.cursors.push(cursor);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| PreprocessError::SessionStoreIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| PreprocessError::SessionStoreIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(PreprocessError::SessionStoreIo { operation: "read" });
            }
        }
        Ok(Self { path, inner })
    }
}

#[cfg(feature = "std")]
impl PreprocessingReleaseSessionCursorStore for FilePreprocessingReleaseSessionCursorStore {
    fn persist_release_cursor(
        &mut self,
        cursor: &PreprocessingReleaseSessionCursor,
    ) -> Result<(), PreprocessError> {
        let before = self.inner.release_cursors().len();
        self.inner.persist_release_cursor(cursor)?;
        if self.inner.release_cursors().len() == before {
            return Ok(());
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| PreprocessError::SessionStoreIo { operation: "open" })?;
        use std::io::Write;
        writeln!(
            file,
            "{}",
            format_preprocessing_release_session_cursor_line(cursor)
        )
        .map_err(|_| PreprocessError::SessionStoreIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| PreprocessError::SessionStoreIo { operation: "sync" })?;
        Ok(())
    }

    fn release_cursors(&self) -> &[PreprocessingReleaseSessionCursor] {
        self.inner.release_cursors()
    }
}

/// Coarse phase for a release preprocessing driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreprocessingReleaseDriverPhase {
    /// Driving private preprocessing CarryCompare/CEF/BCC runtime circuits.
    PrivateRuntime,
    /// Driving strict-signing canonical mask generation.
    StrictMasks,
    /// Runtime states are complete and the token may be certified.
    ReadyToCertify,
    /// A release-certified token has been emitted.
    Certified,
    /// The driver failed closed.
    Aborted,
}

/// Coarse scheduler counters for the release preprocessing driver.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PreprocessingReleaseDriverCounters {
    /// Private preprocessing runtime drive calls.
    pub private_runtime_drive_steps: u64,
    /// Private preprocessing runtime collect calls.
    pub private_runtime_collect_steps: u64,
    /// Strict mask-generation runtime drive calls.
    pub strict_mask_drive_steps: u64,
    /// Strict mask-generation runtime collect calls.
    pub strict_mask_collect_steps: u64,
}

/// App-facing release preprocessing driver.
///
/// This owns the per-party release preprocessing state machine after the
/// reliable-broadcast commit/open transcript is complete. Embedding
/// applications still own message delivery between parties, but they no longer
/// manually sequence private preprocessing, strict-mask generation, cursor
/// updates, and token certification as separate ad hoc calls.
pub struct PreprocessingReleaseDriver<P, S, V, K>
where
    P: MlDsaParams,
    S: SessionStore,
    V: MaskedBroadcastConsistencyVerifier,
    K: PreprocessingReleaseSessionCursorStore,
{
    session: Option<PreprocessingSession<P, S, V>>,
    config: DkgConfig,
    rho: [u8; 32],
    nonce_share: DistributedNonceShare,
    session_id: SessionId,
    transcript: TranscriptHash,
    private_state: PreprocessingPrivateCircuitDriverState,
    mask_state: Option<StrictSigningCanonicalMaskGenerationState>,
    fused_mask_inventory: Option<StrictSigningCanonicalMaskInventory>,
    cursor_store: K,
    phase: PreprocessingReleaseDriverPhase,
    counters: PreprocessingReleaseDriverCounters,
}

impl<P, S, V, K> PreprocessingReleaseDriver<P, S, V, K>
where
    P: MlDsaParams,
    S: SessionStore,
    V: MaskedBroadcastConsistencyVerifier,
    K: PreprocessingReleaseSessionCursorStore,
{
    /// Starts the release driver from a completed preprocessing session.
    pub fn start<T, L, C>(
        mut session: PreprocessingSession<P, S, V>,
        config: DkgConfig,
        rho: [u8; 32],
        nonce_share: DistributedNonceShare,
        runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
        mut cursor_store: K,
    ) -> Result<Self, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        session.advance()?;
        session.ensure_complete()?;
        let session_id = session.options.session_id;
        let transcript =
            preprocessing_session_open_hash::<P>(session_id, &session.options.signer_set);
        cursor_store.persist_release_cursor(&PreprocessingReleaseSessionCursor {
            session_id,
            phase: PreprocessingReleaseSessionPhase::TranscriptComplete,
            transcript_hash: transcript,
            token_binding_hash: None,
        })?;
        let (_, _, private_state) = runtime.start_private_circuit_handles_from_envelopes::<P>(
            &config,
            session_id,
            session.inputs.clone(),
            session.envelopes.clone(),
            transcript,
        )?;
        Ok(Self {
            session: Some(session),
            config,
            rho,
            nonce_share,
            session_id,
            transcript,
            private_state,
            mask_state: None,
            fused_mask_inventory: None,
            cursor_store,
            phase: PreprocessingReleaseDriverPhase::PrivateRuntime,
            counters: PreprocessingReleaseDriverCounters::default(),
        })
    }

    /// Returns the driver's coarse phase.
    pub const fn phase(&self) -> PreprocessingReleaseDriverPhase {
        self.phase
    }

    /// Returns the driver's release cursor store.
    pub fn cursor_store(&self) -> &K {
        &self.cursor_store
    }

    /// Returns coarse scheduler counters for this release driver.
    pub const fn counters(&self) -> PreprocessingReleaseDriverCounters {
        self.counters
    }

    /// Drives the next runtime phase owned by this driver.
    pub fn drive_runtime_step<T, L, C, E>(
        &mut self,
        runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
        entropy: &mut E,
    ) -> Result<(), PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        match self.phase {
            PreprocessingReleaseDriverPhase::PrivateRuntime => {
                self.counters.private_runtime_drive_steps =
                    self.counters.private_runtime_drive_steps.saturating_add(1);
                runtime
                    .drive_private_circuit_handles_step::<P, E>(
                        &self.config,
                        &mut self.private_state,
                        entropy,
                    )
                    .map(|_| ())
            }
            PreprocessingReleaseDriverPhase::StrictMasks => {
                self.counters.strict_mask_drive_steps =
                    self.counters.strict_mask_drive_steps.saturating_add(1);
                let mask_state = self
                    .mask_state
                    .as_mut()
                    .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
                runtime.drive_strict_signing_canonical_mask_generation_step::<P, E>(
                    &self.config,
                    mask_state,
                    entropy,
                )
            }
            PreprocessingReleaseDriverPhase::ReadyToCertify
            | PreprocessingReleaseDriverPhase::Certified => Ok(()),
            PreprocessingReleaseDriverPhase::Aborted => {
                Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
            }
        }
    }

    /// Collects the current runtime phase and advances the driver when that
    /// phase completes.
    pub fn collect_runtime_step<T, L, C>(
        &mut self,
        runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
    ) -> Result<ProductionVectorItMpcCollectResult<PreprocessingReleaseDriverPhase>, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        match self.phase {
            PreprocessingReleaseDriverPhase::PrivateRuntime => {
                self.counters.private_runtime_collect_steps = self
                    .counters
                    .private_runtime_collect_steps
                    .saturating_add(1);
                match runtime.collect_private_circuit_handles_step::<P>(
                    &self.config,
                    &mut self.private_state,
                )? {
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        Ok(ProductionVectorItMpcCollectResult::Waiting(status))
                    }
                    ProductionVectorItMpcCollectResult::Collected { status, .. } => {
                        if self.private_state.is_done() {
                            self.cursor_store.persist_release_cursor(
                                &PreprocessingReleaseSessionCursor {
                                    session_id: self
                                        .session
                                        .as_ref()
                                        .ok_or(PreprocessError::IncompleteSession)?
                                        .options
                                        .session_id,
                                    phase: PreprocessingReleaseSessionPhase::PrivateRuntimeComplete,
                                    transcript_hash: self.transcript,
                                    token_binding_hash: None,
                                },
                            )?;
                            let session_id = self
                                .session
                                .as_ref()
                                .ok_or(PreprocessError::IncompleteSession)?
                                .options
                                .session_id;
                            self.mask_state =
                                Some(runtime.start_strict_signing_canonical_mask_generation(
                                    session_id,
                                    self.transcript,
                                    P::L * P::N,
                                    P::K * P::N,
                                )?);
                            self.phase = PreprocessingReleaseDriverPhase::StrictMasks;
                        }
                        Ok(ProductionVectorItMpcCollectResult::Collected {
                            status,
                            value: self.phase,
                        })
                    }
                }
            }
            PreprocessingReleaseDriverPhase::StrictMasks => {
                self.counters.strict_mask_collect_steps =
                    self.counters.strict_mask_collect_steps.saturating_add(1);
                let mask_state = self
                    .mask_state
                    .as_mut()
                    .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
                match runtime.collect_strict_signing_canonical_mask_generation_step::<P>(
                    &self.config,
                    mask_state,
                )? {
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        Ok(ProductionVectorItMpcCollectResult::Waiting(status))
                    }
                    ProductionVectorItMpcCollectResult::Collected { status, .. } => {
                        if mask_state.is_done() {
                            self.cursor_store.persist_release_cursor(
                                &PreprocessingReleaseSessionCursor {
                                    session_id: self
                                        .session
                                        .as_ref()
                                        .ok_or(PreprocessError::IncompleteSession)?
                                        .options
                                        .session_id,
                                    phase: PreprocessingReleaseSessionPhase::StrictMasksComplete,
                                    transcript_hash: self.transcript,
                                    token_binding_hash: None,
                                },
                            )?;
                            self.phase = PreprocessingReleaseDriverPhase::ReadyToCertify;
                        }
                        Ok(ProductionVectorItMpcCollectResult::Collected {
                            status,
                            value: self.phase,
                        })
                    }
                }
            }
            PreprocessingReleaseDriverPhase::ReadyToCertify
            | PreprocessingReleaseDriverPhase::Certified => {
                Ok(ProductionVectorItMpcCollectResult::Collected {
                    status: PrimeFieldMpcPhaseDriverStatus::Collected {
                        receiver: None,
                        kind: PrimeFieldMpcRoundKind::Open,
                        phase: PrimeFieldMpcPhase::BitSumThresholdCheck,
                        label_hash: power2round_label_hash(
                            &Power2RoundTranscriptLabel::root(
                                &self.config,
                                self.session
                                    .as_ref()
                                    .map(|session| session.options.session_id.0)
                                    .unwrap_or([0u8; 32]),
                            )
                            .child("preprocessing_release_driver")
                            .child("ready"),
                        ),
                        senders: Vec::new(),
                    },
                    value: self.phase,
                })
            }
            PreprocessingReleaseDriverPhase::Aborted => {
                Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
            }
        }
    }

    /// Finishes the driver and returns a release-certified token with the
    /// updated cursor store.
    pub fn finish<T, L, C>(
        mut self,
        runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
    ) -> Result<(CertifiedToken, K), PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if self.phase != PreprocessingReleaseDriverPhase::ReadyToCertify {
            self.persist_abort_cursor()?;
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let mut session = self
            .session
            .take()
            .ok_or(PreprocessError::IncompleteSession)?;
        session.advance()?;
        session.ensure_complete()?;
        if !self.private_state.is_done() {
            self.persist_abort_cursor()?;
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let masks = if let Some(masks) = self.fused_mask_inventory.take() {
            masks
        } else {
            let mask_state = self
                .mask_state
                .take()
                .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
            if !mask_state.is_done() {
                self.persist_abort_cursor()?;
                return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
            }
            runtime.finish_strict_signing_canonical_mask_generation(mask_state)?
        };

        let result = certify_preprocessing_token_release_validated_with_finished_runtime_driver_strict_inventory_and_nonce_share::<
            P, V, T, L, C,
        >(
            &mut session.verifier,
            &mut session.registry,
            session.options.session_id,
            session.inputs,
            session.envelopes,
            self.transcript,
            &self.config,
            &self.rho,
            &session.options.signer_set,
            &self.nonce_share,
            runtime,
            &self.private_state,
            masks,
        );

        match result {
            Ok(token) => {
                let token_binding_hash = token
                    .vector_runtime_certificate()
                    .and_then(PreprocessingVectorRuntimeCertificate::token_binding_hash);
                self.cursor_store
                    .persist_release_cursor(&PreprocessingReleaseSessionCursor {
                        session_id: token.session_id,
                        phase: PreprocessingReleaseSessionPhase::ReleaseTokenCertified,
                        transcript_hash: token.transcript_hash,
                        token_binding_hash,
                    })?;
                self.phase = PreprocessingReleaseDriverPhase::Certified;
                Ok((token, self.cursor_store))
            }
            Err(err) => {
                self.persist_abort_cursor()?;
                Err(err)
            }
        }
    }

    /// Finishes the driver and appends the token's public release-log entry.
    #[cfg(feature = "std")]
    pub fn finish_and_append_token_log<T, L, C>(
        self,
        runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
        token_log: &mut FilePreprocessingReleaseTokenBatchLog,
        token_index: usize,
    ) -> Result<(CertifiedToken, K), PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let (token, cursor_store) = self.finish(runtime)?;
        let entry = preprocessing_release_token_log_entry(&token, token_index)?;
        token_log
            .append(entry)
            .map_err(|_| PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        Ok((token, cursor_store))
    }

    fn persist_abort_cursor(&mut self) -> Result<(), PreprocessError> {
        self.cursor_store
            .persist_release_cursor(&PreprocessingReleaseSessionCursor {
                session_id: self.session_id,
                phase: PreprocessingReleaseSessionPhase::Aborted,
                transcript_hash: self.transcript,
                token_binding_hash: None,
            })
    }

    fn install_fused_strict_mask_inventory(
        &mut self,
        masks: StrictSigningCanonicalMaskInventory,
    ) -> Result<(), PreprocessError> {
        if !matches!(
            self.phase,
            PreprocessingReleaseDriverPhase::StrictMasks
                | PreprocessingReleaseDriverPhase::ReadyToCertify
        ) {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        masks.validate_for_token(self.session_id, self.transcript, P::K * P::N)?;
        self.mask_state = None;
        self.fused_mask_inventory = Some(masks);
        self.cursor_store
            .persist_release_cursor(&PreprocessingReleaseSessionCursor {
                session_id: self.session_id,
                phase: PreprocessingReleaseSessionPhase::StrictMasksComplete,
                transcript_hash: self.transcript,
                token_binding_hash: None,
            })?;
        self.phase = PreprocessingReleaseDriverPhase::ReadyToCertify;
        Ok(())
    }
}

/// One token's lane allocation inside a fused strict-signing canonical-mask
/// generation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictSigningCanonicalMaskBatchMember {
    /// Token/session id owning this slice.
    pub session_id: SessionId,
    /// Token preprocessing transcript hash.
    pub transcript_hash: TranscriptHash,
    /// Number of z-mask lanes owned by this token.
    pub z_lane_count: usize,
    /// Number of hint-mask lanes owned by this token.
    pub hint_lane_count: usize,
}

/// Batch scheduler for release preprocessing drivers.
///
/// This is the production-facing unit for filling a token batch. It lets the
/// embedding application drive every active token driver for the current
/// scheduler step, route all resulting MPC messages, then collect every active
/// driver. The underlying vector circuits remain transcript-separated per
/// token until a later reviewed cross-token circuit-fusion pass, but callers no
/// longer manually treat token filling as unrelated one-token operations.
pub struct PreprocessingReleaseBatchDriver<P, S, V, K>
where
    P: MlDsaParams,
    S: SessionStore,
    V: MaskedBroadcastConsistencyVerifier,
    K: PreprocessingReleaseSessionCursorStore,
{
    drivers: Vec<PreprocessingReleaseDriver<P, S, V, K>>,
    fused_private_state: Option<PreprocessingPrivateCircuitBatchDriverState>,
    attempted_tokens: u64,
}

impl<P, S, V, K> PreprocessingReleaseBatchDriver<P, S, V, K>
where
    P: MlDsaParams,
    S: SessionStore,
    V: MaskedBroadcastConsistencyVerifier,
    K: PreprocessingReleaseSessionCursorStore,
{
    /// Creates a batch scheduler from per-token release drivers.
    pub fn new(
        drivers: Vec<PreprocessingReleaseDriver<P, S, V, K>>,
    ) -> Result<Self, PreprocessError> {
        if drivers.is_empty() {
            return Err(PreprocessError::EmptySignerSet);
        }
        Ok(Self {
            attempted_tokens: drivers.len() as u64,
            fused_private_state: None,
            drivers,
        })
    }

    /// Number of token attempts represented by this batch.
    pub const fn attempted_tokens(&self) -> u64 {
        self.attempted_tokens
    }

    /// Number of release drivers in the batch.
    pub fn len(&self) -> usize {
        self.drivers.len()
    }

    /// Returns true if no drivers are present.
    pub fn is_empty(&self) -> bool {
        self.drivers.is_empty()
    }

    /// Returns true when every driver is ready to certify or already certified.
    pub fn is_ready_to_certify(&self) -> bool {
        self.drivers.iter().all(|driver| {
            matches!(
                driver.phase(),
                PreprocessingReleaseDriverPhase::ReadyToCertify
                    | PreprocessingReleaseDriverPhase::Certified
            )
        })
    }

    /// Returns true when every driver emitted a token.
    pub fn is_certified(&self) -> bool {
        self.drivers
            .iter()
            .all(|driver| driver.phase() == PreprocessingReleaseDriverPhase::Certified)
    }

    /// Returns per-driver phases in batch order.
    pub fn phases(&self) -> Vec<PreprocessingReleaseDriverPhase> {
        self.drivers.iter().map(|driver| driver.phase()).collect()
    }

    /// Aggregates coarse release-driver counters for the batch.
    pub fn counters(&self) -> PreprocessingReleaseDriverCounters {
        let mut out = PreprocessingReleaseDriverCounters::default();
        for driver in &self.drivers {
            let item = driver.counters();
            out.private_runtime_drive_steps = out
                .private_runtime_drive_steps
                .saturating_add(item.private_runtime_drive_steps);
            out.private_runtime_collect_steps = out
                .private_runtime_collect_steps
                .saturating_add(item.private_runtime_collect_steps);
            out.strict_mask_drive_steps = out
                .strict_mask_drive_steps
                .saturating_add(item.strict_mask_drive_steps);
            out.strict_mask_collect_steps = out
                .strict_mask_collect_steps
                .saturating_add(item.strict_mask_collect_steps);
        }
        out
    }

    /// Drives every active token driver once. The closure owns runtime adapter
    /// selection so applications can use one runtime per party/token while this
    /// scheduler owns the batch shape.
    pub fn drive_active<F>(&mut self, mut drive: F) -> Result<usize, PreprocessError>
    where
        F: FnMut(usize, &mut PreprocessingReleaseDriver<P, S, V, K>) -> Result<(), PreprocessError>,
    {
        let mut driven = 0usize;
        for (idx, driver) in self.drivers.iter_mut().enumerate() {
            if matches!(
                driver.phase(),
                PreprocessingReleaseDriverPhase::ReadyToCertify
                    | PreprocessingReleaseDriverPhase::Certified
            ) {
                continue;
            }
            drive(idx, driver)?;
            driven = driven.saturating_add(1);
        }
        Ok(driven)
    }

    /// Collects every active token driver once.
    pub fn collect_active<F>(&mut self, mut collect: F) -> Result<usize, PreprocessError>
    where
        F: FnMut(usize, &mut PreprocessingReleaseDriver<P, S, V, K>) -> Result<(), PreprocessError>,
    {
        let mut collected = 0usize;
        for (idx, driver) in self.drivers.iter_mut().enumerate() {
            if matches!(
                driver.phase(),
                PreprocessingReleaseDriverPhase::ReadyToCertify
                    | PreprocessingReleaseDriverPhase::Certified
            ) {
                continue;
            }
            collect(idx, driver)?;
            collected = collected.saturating_add(1);
        }
        Ok(collected)
    }

    /// Starts one fused private CarryCompare/CEF/BCC runtime circuit for every
    /// driver still in the private-runtime phase.
    pub fn start_fused_private_runtime<T, L, C>(
        &mut self,
        runtime: &ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
    ) -> Result<(), PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if self.fused_private_state.is_some() {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        if self
            .drivers
            .iter()
            .any(|driver| driver.phase() != PreprocessingReleaseDriverPhase::PrivateRuntime)
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let mut items = Vec::with_capacity(self.drivers.len());
        for driver in &self.drivers {
            let session = driver
                .session
                .as_ref()
                .ok_or(PreprocessError::IncompleteSession)?;
            items.push((
                driver.session_id,
                session.inputs.clone(),
                session.envelopes.clone(),
                driver.transcript,
            ));
        }
        let config = &self
            .drivers
            .first()
            .ok_or(PreprocessError::EmptySignerSet)?
            .config;
        self.fused_private_state =
            Some(runtime.start_private_circuit_batch_from_envelopes::<P>(config, items)?);
        Ok(())
    }

    /// Drives the active fused private preprocessing batch phase.
    pub fn drive_fused_private_runtime_step<T, L, C, E>(
        &mut self,
        runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        let state = self
            .fused_private_state
            .as_mut()
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        for driver in &mut self.drivers {
            if driver.phase() != PreprocessingReleaseDriverPhase::PrivateRuntime {
                return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
            }
            driver.counters.private_runtime_drive_steps = driver
                .counters
                .private_runtime_drive_steps
                .saturating_add(1);
        }
        runtime.drive_private_circuit_batch_step::<P, E>(&self.drivers[0].config, state, entropy)
    }

    /// Collects the active fused private preprocessing batch phase.
    pub fn collect_fused_private_runtime_step<T, L, C>(
        &mut self,
        runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
    ) -> Result<ProductionVectorItMpcCollectResult<PreprocessingReleaseDriverPhase>, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let state = self
            .fused_private_state
            .as_mut()
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        for driver in &mut self.drivers {
            if driver.phase() != PreprocessingReleaseDriverPhase::PrivateRuntime {
                return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
            }
            driver.counters.private_runtime_collect_steps = driver
                .counters
                .private_runtime_collect_steps
                .saturating_add(1);
        }
        match runtime.collect_private_circuit_batch_step::<P>(&self.drivers[0].config, state)? {
            ProductionVectorItMpcCollectResult::Waiting(status) => {
                Ok(ProductionVectorItMpcCollectResult::Waiting(status))
            }
            ProductionVectorItMpcCollectResult::Collected { status, .. } => {
                if state.is_done() {
                    for driver in &mut self.drivers {
                        driver.cursor_store.persist_release_cursor(
                            &PreprocessingReleaseSessionCursor {
                                session_id: driver.session_id,
                                phase: PreprocessingReleaseSessionPhase::PrivateRuntimeComplete,
                                transcript_hash: driver.transcript,
                                token_binding_hash: None,
                            },
                        )?;
                        driver.phase = PreprocessingReleaseDriverPhase::StrictMasks;
                    }
                }
                Ok(ProductionVectorItMpcCollectResult::Collected {
                    status,
                    value: self.drivers[0].phase(),
                })
            }
        }
    }

    /// Installs fused strict-signing mask inventories produced by one
    /// batch-wide vector mask-generation state.
    ///
    /// The inventories must be in the same order as the drivers. After this
    /// call each driver is ready to certify without running its own per-token
    /// strict-mask state.
    pub fn install_fused_strict_mask_inventories(
        &mut self,
        inventories: Vec<StrictSigningCanonicalMaskInventory>,
    ) -> Result<(), PreprocessError> {
        if inventories.len() != self.drivers.len() {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        for (driver, masks) in self.drivers.iter_mut().zip(inventories) {
            driver.install_fused_strict_mask_inventory(masks)?;
        }
        Ok(())
    }

    /// Returns the member descriptors needed to generate fused strict-signing
    /// masks for this batch.
    pub fn strict_mask_batch_members(&self) -> Vec<StrictSigningCanonicalMaskBatchMember> {
        self.drivers
            .iter()
            .map(|driver| StrictSigningCanonicalMaskBatchMember {
                session_id: driver.session_id,
                transcript_hash: driver.transcript,
                z_lane_count: P::L * P::N,
                hint_lane_count: P::K * P::N,
            })
            .collect()
    }

    /// Builds a public fill report from the certified tokens emitted by this
    /// batch.
    pub fn fill_report(&self, tokens: &[CertifiedToken]) -> PreprocessingTokenBatchFillReport {
        PreprocessingTokenBatchFillReport::from_certified_tokens(self.attempted_tokens, tokens)
    }

    /// Finishes a batch whose private preprocessing proof was produced by
    /// [`Self::start_fused_private_runtime`] and appends public release-log
    /// entries for every emitted token.
    #[cfg(feature = "std")]
    pub fn finish_fused_private_and_append_token_log<T, L, C>(
        mut self,
        runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
        token_log: &mut FilePreprocessingReleaseTokenBatchLog,
    ) -> Result<Vec<(CertifiedToken, K)>, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let batch_state = self
            .fused_private_state
            .take()
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        if !batch_state.is_done()
            || self
                .drivers
                .iter()
                .any(|driver| driver.phase() != PreprocessingReleaseDriverPhase::ReadyToCertify)
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }

        let mut out = Vec::with_capacity(self.drivers.len());
        for (token_index, mut driver) in self.drivers.into_iter().enumerate() {
            let mut session = driver
                .session
                .take()
                .ok_or(PreprocessError::IncompleteSession)?;
            session.advance()?;
            session.ensure_complete()?;
            let masks = driver
                .fused_mask_inventory
                .take()
                .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
            let token = certify_preprocessing_token_release_validated_with_fused_private_batch_strict_inventory_and_nonce_share::<
                P, V, T, L, C,
            >(
                &mut session.verifier,
                &mut session.registry,
                session.options.session_id,
                session.inputs,
                session.envelopes,
                driver.transcript,
                &driver.config,
                &driver.rho,
                &session.options.signer_set,
                &driver.nonce_share,
                runtime,
                &batch_state,
                masks,
            )?;
            let entry = preprocessing_release_token_log_entry(&token, token_index)?;
            token_log
                .append(entry)
                .map_err(|_| PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
            let token_binding_hash = token
                .vector_runtime_certificate()
                .and_then(PreprocessingVectorRuntimeCertificate::token_binding_hash);
            driver
                .cursor_store
                .persist_release_cursor(&PreprocessingReleaseSessionCursor {
                    session_id: token.session_id,
                    phase: PreprocessingReleaseSessionPhase::ReleaseTokenCertified,
                    transcript_hash: token.transcript_hash,
                    token_binding_hash,
                })?;
            out.push((token, driver.cursor_store));
        }
        Ok(out)
    }

    /// Consumes the scheduler and returns the inner drivers for finalization.
    pub fn into_drivers(self) -> Vec<PreprocessingReleaseDriver<P, S, V, K>> {
        self.drivers
    }
}

/// Options for distributed nonce-share generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedNonceGenerationOptions {
    /// Preprocessing/signing session id this nonce is bound to.
    pub session_id: SessionId,
    /// Production DKG configuration whose parties/threshold define the Shamir sharing.
    pub dkg_config: DkgConfig,
    /// Public ML-DSA matrix seed from the DKG public key.
    pub rho: [u8; 32],
    /// Fresh session-bound entropy for each party's nonce residue contribution.
    pub nonce_entropy: [u8; 32],
    /// Fresh session-bound entropy for production IT-VSS masks/tags.
    pub it_vss_entropy: [u8; 32],
    /// Production IT-VSS security parameters.
    pub it_vss_security: ProductionItVssSecurityParams,
}

/// Public evidence that dealer nonce contributions were certified before use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedNonceGenerationEvidence {
    /// IT-VSS public commitments for each dealer nonce vector.
    pub public_commitments: Vec<ItVssPublicCommitment>,
    /// Complaint-resolution certificates for the nonce-vector sharings.
    pub complaint_resolution: ItVssComplaintResolution,
    /// Hash binding the public commitments.
    pub public_commitment_hash: [u8; 32],
    /// Hash binding the complaint-resolution artifact.
    pub complaint_resolution_hash: [u8; 32],
}

/// One party's local nonce share and public nonce commitments.
#[derive(Clone, Eq, PartialEq)]
pub struct DistributedNonceShare {
    /// Party that owns this local nonce share.
    pub party: PartyId,
    /// Local Shamir nonce share `y_i`; secret, never public.
    pub y_share: PolyVec,
    /// Public nonce commitment included in preprocessing tokens.
    pub nonce_commitment: NonceCommitment,
    /// Public randomness commitment used by CEF rho derivation.
    pub randomness_commitment: Commitment,
}

impl fmt::Debug for DistributedNonceShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("DistributedNonceShare");
        debug.field("party", &self.party);
        debug.field("y_share", &"<redacted>");
        debug.field("nonce_commitment", &self.nonce_commitment);
        debug.field("randomness_commitment", &self.randomness_commitment);
        debug.finish()
    }
}

/// Output of one distributed nonce-generation run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedNonceGenerationOutput {
    /// Per-party local nonce shares.
    pub shares: Vec<DistributedNonceShare>,
    /// Public IT-VSS evidence for dealer nonce contributions.
    pub evidence: DistributedNonceGenerationEvidence,
}

/// Local output of one app-driven distributed nonce-generation session.
///
/// A production party receives only its own Shamir nonce share. The all-party
/// [`DistributedNonceGenerationOutput`] remains useful for local integration
/// tests, but applications should drive one session per party and persist each
/// [`DistributedNonceGenerationLocalOutput`] independently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedNonceGenerationLocalOutput {
    /// Local party nonce share.
    pub share: DistributedNonceShare,
    /// Public IT-VSS evidence shared by all honest parties.
    pub evidence: DistributedNonceGenerationEvidence,
}

/// Outbound artifact emitted by [`DistributedNonceGenerationSession`].
///
/// The crate does not own sockets. Embedding applications must deliver private
/// artifacts over authenticated ML-KEM-derived channels and broadcast artifacts
/// over reliable ML-DSA-authenticated broadcast.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DistributedNonceGenerationOutbound {
    /// Directed private IT-VSS delivery.
    Private {
        /// Receiver party.
        receiver: PartyId,
        /// Receiver-private IT-VSS share delivery.
        delivery: ItVssPrivateShareDelivery,
    },
    /// Reliable-broadcast IT-VSS artifact.
    Broadcast {
        /// Public artifact to broadcast.
        artifact: DistributedNonceGenerationBroadcast,
    },
}

/// Public broadcast artifacts for app-driven nonce generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DistributedNonceGenerationBroadcast {
    /// Dealer precommitment before public coins are fixed.
    PublicPrecommitment(ItVssPublicPrecommitment),
    /// Public coin share for one dealer label.
    PublicCoinShare(ProductionItVssPublicCoinShare),
    /// Final public commitment after the public-coin transcript exists.
    PublicCommitment(ItVssPublicCommitment),
}

/// App-driven distributed nonce-generation session for one local party.
///
/// This facade exposes the same production transport shape as native DKG:
/// local party starts a session, the application routes private and broadcast
/// artifacts, and `finish` returns only that party's local nonce share plus
/// public evidence. It does not reveal aggregate nonces or other parties'
/// shares.
pub struct DistributedNonceGenerationSession<P: MlDsaParams> {
    options: DistributedNonceGenerationOptions,
    local_party: PartyId,
    backend: ProductionInformationCheckingVssBackend,
    prepared: Option<ProductionItVssPreparedDealerOutput>,
    local_label: ItVssSharingLabel,
    precommitments: Vec<ItVssPublicPrecommitment>,
    coin_shares: Vec<ProductionItVssPublicCoinShare>,
    public_commitments: Vec<ItVssPublicCommitment>,
    private_deliveries: Vec<ItVssPrivateShareDelivery>,
    outbound: Vec<DistributedNonceGenerationOutbound>,
    coins_sent: bool,
    commitment_sent: bool,
    _params: PhantomData<P>,
}

impl<P: MlDsaParams> DistributedNonceGenerationSession<P> {
    /// Starts one local-party nonce-generation session.
    pub fn start(
        options: DistributedNonceGenerationOptions,
        local_party: PartyId,
    ) -> Result<Self, PreprocessError> {
        options.dkg_config.validate().map_err(map_nonce_dkg_error)?;
        if options.dkg_config.suite != talus_dkg::DkgSuite::for_params::<P>() {
            return Err(PreprocessError::NonceGenerationFailed);
        }
        if !options.dkg_config.parties.contains(&local_party) {
            return Err(PreprocessError::UnknownParty(local_party));
        }

        let label = ItVssSharingLabel::new(
            &options.dkg_config,
            local_party,
            ItVssSharingDomain::NoncePreprocessing,
            Some(nonce_it_vss_label_index(options.session_id)),
        )
        .map_err(map_nonce_dkg_error)?;
        let residues = nonce_residues_for_dealer::<P>(&options, local_party)?;
        let secret = nonce_it_vss_secret::<P>(&options, local_party, &residues);
        let mut backend = ProductionInformationCheckingVssBackend::with_params(
            options.it_vss_entropy,
            options.it_vss_security,
        )
        .map_err(map_nonce_dkg_error)?;
        let prepared = backend
            .prepare_secret::<P>(&options.dkg_config, label, &secret)
            .map_err(map_nonce_dkg_error)?;

        let mut session = Self {
            options,
            local_party,
            backend,
            prepared: Some(prepared),
            local_label: label,
            precommitments: Vec::new(),
            coin_shares: Vec::new(),
            public_commitments: Vec::new(),
            private_deliveries: Vec::new(),
            outbound: Vec::new(),
            coins_sent: false,
            commitment_sent: false,
            _params: PhantomData,
        };
        session.enqueue_precommitment_and_private_deliveries()?;
        Ok(session)
    }

    /// Injects one authenticated private IT-VSS delivery.
    pub fn handle_private(
        &mut self,
        sender: PartyId,
        delivery: ItVssPrivateShareDelivery,
    ) -> Result<(), PreprocessError> {
        if sender != delivery.dealer
            || delivery.receiver != self.local_party
            || !self.options.dkg_config.parties.contains(&sender)
        {
            return Err(PreprocessError::UnexpectedWireMessage);
        }
        if self
            .private_deliveries
            .iter()
            .any(|seen| seen.dealer == delivery.dealer && seen.label_hash == delivery.label_hash)
        {
            return Err(PreprocessError::DuplicateBroadcast(sender));
        }
        self.private_deliveries.push(delivery);
        self.advance()
    }

    /// Injects one reliable-broadcast nonce-generation artifact.
    pub fn handle_broadcast(
        &mut self,
        sender: PartyId,
        artifact: DistributedNonceGenerationBroadcast,
    ) -> Result<(), PreprocessError> {
        if !self.options.dkg_config.parties.contains(&sender) {
            return Err(PreprocessError::UnknownParty(sender));
        }
        match artifact {
            DistributedNonceGenerationBroadcast::PublicPrecommitment(precommitment) => {
                if precommitment.dealer != sender {
                    return Err(PreprocessError::UnexpectedWireMessage);
                }
                self.insert_precommitment(precommitment)?;
            }
            DistributedNonceGenerationBroadcast::PublicCoinShare(share) => {
                if share.party != sender {
                    return Err(PreprocessError::UnexpectedWireMessage);
                }
                self.insert_coin_share(share)?;
            }
            DistributedNonceGenerationBroadcast::PublicCommitment(commitment) => {
                if commitment.dealer != sender {
                    return Err(PreprocessError::UnexpectedWireMessage);
                }
                self.insert_public_commitment(commitment)?;
            }
        }
        self.advance()
    }

    /// Returns the next outbound artifact for application delivery.
    pub fn next_outbound(&mut self) -> Option<DistributedNonceGenerationOutbound> {
        if self.outbound.is_empty() {
            None
        } else {
            Some(self.outbound.remove(0))
        }
    }

    /// Finishes this local-party nonce-generation session.
    pub fn finish(mut self) -> Result<DistributedNonceGenerationLocalOutput, PreprocessError> {
        self.advance()?;
        if !self.outbound.is_empty()
            || self.precommitments.len() != self.options.dkg_config.parties.len()
            || self.public_commitments.len() != self.options.dkg_config.parties.len()
            || self.private_deliveries.len() != self.options.dkg_config.parties.len()
        {
            return Err(PreprocessError::IncompleteSession);
        }

        let mut complaints = Vec::new();
        for delivery in &self.private_deliveries {
            let commitment = self
                .public_commitments
                .iter()
                .find(|commitment| {
                    commitment.dealer == delivery.dealer
                        && commitment.label_hash == delivery.label_hash
                })
                .ok_or(PreprocessError::NonceGenerationFailed)?;
            if self
                .backend
                .verify_private_delivery::<P>(&self.options.dkg_config, commitment, delivery)
                .is_err()
            {
                complaints.push(
                    self.backend
                        .complaint_for_invalid_delivery::<P>(
                            &self.options.dkg_config,
                            commitment,
                            delivery,
                        )
                        .map_err(map_nonce_dkg_error)?,
                );
            }
        }
        let complaint_resolution = self
            .backend
            .resolve_complaints::<P>(
                &self.options.dkg_config,
                &self.public_commitments,
                &complaints,
            )
            .map_err(map_nonce_dkg_error)?;
        let evidence = DistributedNonceGenerationEvidence {
            public_commitment_hash: hash_nonce_it_vss_public_commitments(&self.public_commitments),
            complaint_resolution_hash: hash_it_vss_complaint_resolution(&complaint_resolution),
            public_commitments: self.public_commitments,
            complaint_resolution,
        };
        let share =
            distributed_nonce_share_for_party::<P>(&self.options, self.local_party, &evidence)?;
        Ok(DistributedNonceGenerationLocalOutput { share, evidence })
    }

    fn enqueue_precommitment_and_private_deliveries(&mut self) -> Result<(), PreprocessError> {
        let prepared = self
            .prepared
            .as_ref()
            .ok_or(PreprocessError::NonceGenerationFailed)?;
        self.outbound
            .push(DistributedNonceGenerationOutbound::Broadcast {
                artifact: DistributedNonceGenerationBroadcast::PublicPrecommitment(
                    prepared.public_precommitment.clone(),
                ),
            });
        for delivery in &prepared.deliveries {
            self.outbound
                .push(DistributedNonceGenerationOutbound::Private {
                    receiver: delivery.receiver,
                    delivery: delivery.clone(),
                });
        }
        Ok(())
    }

    fn advance(&mut self) -> Result<(), PreprocessError> {
        if !self.coins_sent && self.precommitments.len() == self.options.dkg_config.parties.len() {
            let precommitments = self.precommitments.clone();
            for precommitment in precommitments {
                let coin = nonce_public_coin::<P>(
                    &self.options,
                    self.local_party,
                    precommitment.label_hash,
                );
                let share = production_it_vss_public_coin_share(
                    &self.options.dkg_config,
                    precommitment.label_hash,
                    self.local_party,
                    coin,
                )
                .map_err(map_nonce_dkg_error)?;
                self.outbound
                    .push(DistributedNonceGenerationOutbound::Broadcast {
                        artifact: DistributedNonceGenerationBroadcast::PublicCoinShare(share),
                    });
            }
            self.coins_sent = true;
        }
        if !self.commitment_sent && self.has_all_coin_shares_for(self.local_label.label_hash) {
            let transcript = production_it_vss_public_coin_transcript(
                &self.options.dkg_config,
                self.local_label.label_hash,
                &self.coin_shares_for(self.local_label.label_hash),
            )
            .map_err(map_nonce_dkg_error)?;
            let prepared = self
                .prepared
                .take()
                .ok_or(PreprocessError::NonceGenerationFailed)?;
            let output = self
                .backend
                .finalize_prepared_secret(&self.options.dkg_config, prepared, transcript)
                .map_err(map_nonce_dkg_error)?;
            self.outbound
                .push(DistributedNonceGenerationOutbound::Broadcast {
                    artifact: DistributedNonceGenerationBroadcast::PublicCommitment(
                        output.public_commitment,
                    ),
                });
            self.commitment_sent = true;
        }
        Ok(())
    }

    fn insert_precommitment(
        &mut self,
        precommitment: ItVssPublicPrecommitment,
    ) -> Result<(), PreprocessError> {
        if self.precommitments.iter().any(|seen| {
            seen.dealer == precommitment.dealer || seen.label_hash == precommitment.label_hash
        }) {
            return Err(PreprocessError::DuplicateBroadcast(precommitment.dealer));
        }
        self.precommitments.push(precommitment);
        Ok(())
    }

    fn insert_coin_share(
        &mut self,
        share: ProductionItVssPublicCoinShare,
    ) -> Result<(), PreprocessError> {
        if !self
            .precommitments
            .iter()
            .any(|precommitment| precommitment.label_hash == share.label_hash)
        {
            return Err(PreprocessError::UnexpectedWireMessage);
        }
        if self
            .coin_shares
            .iter()
            .any(|seen| seen.party == share.party && seen.label_hash == share.label_hash)
        {
            return Err(PreprocessError::DuplicateBroadcast(share.party));
        }
        self.coin_shares.push(share);
        Ok(())
    }

    fn insert_public_commitment(
        &mut self,
        commitment: ItVssPublicCommitment,
    ) -> Result<(), PreprocessError> {
        if !self.precommitments.iter().any(|precommitment| {
            precommitment.dealer == commitment.dealer
                && precommitment.label_hash == commitment.label_hash
        }) {
            return Err(PreprocessError::UnexpectedWireMessage);
        }
        if self
            .public_commitments
            .iter()
            .any(|seen| seen.dealer == commitment.dealer)
        {
            return Err(PreprocessError::DuplicateBroadcast(commitment.dealer));
        }
        self.public_commitments.push(commitment);
        Ok(())
    }

    fn has_all_coin_shares_for(&self, label_hash: [u8; 32]) -> bool {
        self.coin_shares_for(label_hash).len() == self.options.dkg_config.parties.len()
    }

    fn coin_shares_for(&self, label_hash: [u8; 32]) -> Vec<ProductionItVssPublicCoinShare> {
        self.coin_shares
            .iter()
            .filter(|share| share.label_hash == label_hash)
            .cloned()
            .collect()
    }
}

/// Generates nonce shares from dealerless, IT-VSS-certified residue contributions.
///
/// For each nonce coefficient, every party contributes `u_i in Z_(2*gamma1)`.
/// The final nonce secret coefficient is:
///
/// `y = (sum_i u_i mod 2*gamma1) - (gamma1 - 1)`.
///
/// If at least one honest party contributes uniformly, the resulting nonce is
/// uniform over the FIPS ML-DSA nonce interval `[-gamma1+1, gamma1]`. The
/// implementation returns only local Shamir shares and public commitments;
/// it does not expose the aggregate nonce.
pub fn generate_distributed_nonce_shares<P: MlDsaParams>(
    options: DistributedNonceGenerationOptions,
) -> Result<DistributedNonceGenerationOutput, PreprocessError> {
    options.dkg_config.validate().map_err(map_nonce_dkg_error)?;
    if options.dkg_config.suite != talus_dkg::DkgSuite::for_params::<P>() {
        return Err(PreprocessError::NonceGenerationFailed);
    }
    let coeff_count = P::L * P::N;
    let modulus = nonce_residue_modulus::<P>()?;

    let dealer_residues = nonce_residues_for_all_dealers::<P>(&options)?;

    let mut nonce_coefficients = Vec::with_capacity(coeff_count);
    for index in 0..coeff_count {
        let sum = dealer_residues
            .iter()
            .fold(0u64, |acc, residues| acc + u64::from(residues[index]))
            % u64::from(modulus);
        let signed = sum as Coeff - (P::GAMMA1 - 1);
        nonce_coefficients.push(reduce_mod_q::<P>(signed));
    }

    let evidence = certify_nonce_residue_contributions::<P>(&options, &dealer_residues)?;
    let party_coeffs = share_nonce_coefficients::<P>(&options, &nonce_coefficients)
        .map_err(map_nonce_dkg_error)?;
    let shares = party_coeffs
        .into_iter()
        .map(|(party, coeffs)| {
            distributed_nonce_share_from_coeffs::<P>(&options, &evidence, party, &coeffs)
        })
        .collect::<Result<Vec<_>, PreprocessError>>()?;

    Ok(DistributedNonceGenerationOutput { shares, evidence })
}

/// Builds the preprocessing input for one local nonce share.
///
/// The CEF token certifies the weighted `A*(lambda_i*y_i)` contribution
/// because online signing later aggregates Shamir shares with Lagrange
/// coefficients at zero. The local nonce share itself remains in
/// [`DistributedNonceShare`] and is not duplicated into `PartyPreprocessInput`.
pub fn party_preprocess_input_from_distributed_nonce_share<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
    rho: &[u8; 32],
    share: &DistributedNonceShare,
) -> Result<PartyPreprocessInput, PreprocessError> {
    let mut parties = signer_set.to_vec();
    parties.sort_unstable();
    if !parties.contains(&share.party) {
        return Err(PreprocessError::UnknownParty(share.party));
    }
    let points = parties
        .iter()
        .map(|party| u32::from(party.0))
        .collect::<Vec<_>>();
    let lambdas = lagrange_coefficients_at_zero::<P>(&points)
        .map_err(|_| PreprocessError::NonceGenerationFailed)?;
    let position = parties
        .iter()
        .position(|party| *party == share.party)
        .ok_or(PreprocessError::UnknownParty(share.party))?;
    let weighted_y = share.y_share.mul_scalar_mod_q::<P>(lambdas[position]);
    let weighted_ay =
        az_from_rho::<P>(rho, &weighted_y).map_err(|_| PreprocessError::NonceGenerationFailed)?;
    let mut highs = Vec::with_capacity(P::K * P::N);
    let mut lows = Vec::with_capacity(P::K * P::N);
    for poly in weighted_ay.polys() {
        for &coeff in poly.coeffs() {
            highs.push(high_bits_unsigned::<P>(coeff));
            lows.push(low_bits_unsigned::<P>(coeff));
        }
    }
    let randomness_commitment = distributed_nonce_preprocess_randomness_commitment::<P>(
        session_id,
        share.party,
        &share.randomness_commitment,
    );
    Ok(PartyPreprocessInput {
        party: share.party,
        highs,
        lows,
        y_share: Vec::new(),
        ay_contribution: Some(weighted_ay),
        nonce_commitment: share.nonce_commitment,
        randomness_commitment,
    })
}

/// Opened masked-broadcast message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskedBroadcast {
    /// Party identifier.
    pub party: PartyId,
    /// Masked unsigned high bits.
    pub masked_highs: Vec<u32>,
    /// Masked unsigned low bits.
    pub masked_lows: Vec<u32>,
    /// Public nonce commitment.
    pub nonce_commitment: NonceCommitment,
    /// Commitment to authenticated rho-bit input.
    pub rho_bits_commitment: Commitment,
    /// Transcript hash claimed by this party.
    pub transcript_hash: TranscriptHash,
}

/// One commit/open envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcastEnvelope {
    /// Hash commitment sent before opening.
    pub commitment: Commitment,
    /// Opened message.
    pub message: MaskedBroadcast,
    /// Consistency proof or audit marker for this masked broadcast.
    pub consistency_proof: MaskedBroadcastConsistencyProof,
    /// Commitment salt.
    pub salt: [u8; 32],
}

struct PreparedMaskedBroadcast {
    envelope: BroadcastEnvelope,
    rhos: Vec<u32>,
    #[cfg(any(test, feature = "paper-fast-dev"))]
    clear_audit: MaskedBroadcastClearAudit,
}

/// Masked-broadcast consistency proof bytes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MaskedBroadcastConsistencyProof {
    bytes: Vec<u8>,
}

impl MaskedBroadcastConsistencyProof {
    /// Returns backend-specific proof bytes.
    ///
    /// This is read-only in the normal API. Production callers should obtain
    /// proof bytes through the preprocessing runtime/envelope constructors,
    /// not by fabricating public struct fields.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

const MASKED_BROADCAST_RUNTIME_PROOF_PREFIX: &[u8; 6] = b"TMBCR1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MaskedBroadcastRuntimeProofParts {
    statement_hash: [u8; 32],
    runtime_transcript_hash: [u8; 32],
    coeff_count: usize,
    signer_count: usize,
}

/// One masked-broadcast proof binding included in the preprocessing runtime
/// statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaskedBroadcastRuntimeBinding {
    /// Party whose masked broadcast is certified by this binding.
    pub party: PartyId,
    /// Hash of the exact masked-broadcast consistency statement.
    pub statement_hash: [u8; 32],
    /// Runtime transcript hash claimed by the envelope proof.
    pub runtime_transcript_hash: [u8; 32],
}

/// Runtime transcript hashes for the private preprocessing certification
/// stages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreprocessingCertificationRuntimeTranscripts {
    /// Aggregate runtime transcript for masked-broadcast consistency.
    pub masked_broadcast: [u8; 32],
    /// Runtime transcript for CarryCompare certification.
    pub carry_compare: [u8; 32],
    /// Runtime transcript for CEF/BCC certification.
    pub bcc: [u8; 32],
}

impl PreprocessingCertificationRuntimeTranscripts {
    /// Returns true when every stage transcript is present.
    pub fn is_complete(self) -> bool {
        self.masked_broadcast != [0u8; 32]
            && self.carry_compare != [0u8; 32]
            && self.bcc != [0u8; 32]
    }
}

/// Runtime-owned masked-broadcast certification output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeMaskedBroadcastOutput {
    /// Number of signers covered by masked-broadcast certification.
    pub signer_count: usize,
    /// Number of coefficients covered per signer.
    pub coeff_count: usize,
    /// Aggregate runtime transcript hash for masked-broadcast consistency.
    pub runtime_transcript_hash: [u8; 32],
    /// Hash of the runtime-private material state that produced the relation
    /// proof bits.
    pub material_state_hash: [u8; 32],
}

/// Runtime-owned CarryCompare certification output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCarryCompareOutput {
    /// Number of coefficients covered by the private CarryCompare circuit.
    pub coeff_count: usize,
    /// Public evidence hash for the certified CarryCompare result.
    pub evidence_hash: [u8; 32],
    /// Runtime transcript hash for the private CarryCompare circuit.
    pub runtime_transcript_hash: [u8; 32],
}

/// Runtime-owned CEF/BCC certification output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCefBccOutput {
    /// Number of coefficients covered by CEF/BCC.
    pub coeff_count: usize,
    /// Hash of the `w1` vector emitted for token admission.
    pub w1_hash: [u8; 32],
    /// CarryCompare evidence hash consumed by the CEF/BCC stage.
    pub carry_compare_evidence_hash: [u8; 32],
    /// Public evidence hash for the certified BCC result.
    pub bcc_evidence_hash: [u8; 32],
    /// Runtime transcript hash for the private CEF/BCC circuit.
    pub runtime_transcript_hash: [u8; 32],
    /// True only when the runtime admits this token pre-challenge.
    pub token_admitted: bool,
}

/// Runtime-owned preprocessing certification outputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreprocessingCertificationRuntimeOutputs {
    /// Masked-broadcast private-certification output.
    pub masked_broadcast: RuntimeMaskedBroadcastOutput,
    /// CarryCompare private-circuit output.
    pub carry_compare: RuntimeCarryCompareOutput,
    /// CEF/BCC private-circuit output.
    pub cef_bcc: RuntimeCefBccOutput,
}

/// Private preprocessing certification stage whose runtime proof is bound into
/// release-capable token evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreprocessingCertificationStage {
    /// CarryCompare certification stage.
    CarryCompare,
    /// CEF/BCC certification stage.
    Bcc,
}

impl PreprocessingCertificationStage {
    #[allow(dead_code)]
    fn code(self) -> u8 {
        match self {
            Self::CarryCompare => 1,
            Self::Bcc => 2,
        }
    }

    fn domain(self) -> &'static [u8] {
        match self {
            Self::CarryCompare => b"carry-compare",
            Self::Bcc => b"cef-bcc",
        }
    }
}

/// Runtime proof bytes for one private preprocessing certification stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreprocessingCertificationStageRuntimeProof {
    bytes: Vec<u8>,
}

impl PreprocessingCertificationStageRuntimeProof {
    /// Returns the typed proof bytes emitted by the private vector runtime.
    ///
    /// This is intentionally read-only in the normal API. Release-capable
    /// preprocessing proof construction is owned by the crate runtime boundary,
    /// so callers cannot manufacture stage proofs by filling public fields.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Runtime proofs required by the release-oriented preprocessing token
/// constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreprocessingCertificationRuntimeProofs {
    /// Aggregate runtime transcript for masked-broadcast consistency. This is
    /// checked against the typed masked-broadcast proof envelopes.
    masked_broadcast: [u8; 32],
    /// CarryCompare runtime proof.
    carry_compare: PreprocessingCertificationStageRuntimeProof,
    /// CEF/BCC runtime proof.
    bcc: PreprocessingCertificationStageRuntimeProof,
    /// Runtime-owned outputs claimed by the private preprocessing circuits.
    outputs: PreprocessingCertificationRuntimeOutputs,
}

impl PreprocessingCertificationRuntimeProofs {
    /// Returns the aggregate masked-broadcast runtime transcript hash.
    pub fn masked_broadcast_runtime_transcript(&self) -> [u8; 32] {
        self.masked_broadcast
    }

    /// Returns the CarryCompare runtime proof.
    pub fn carry_compare(&self) -> &PreprocessingCertificationStageRuntimeProof {
        &self.carry_compare
    }

    /// Returns the CEF/BCC runtime proof.
    pub fn bcc(&self) -> &PreprocessingCertificationStageRuntimeProof {
        &self.bcc
    }

    /// Returns the runtime-owned preprocessing outputs.
    pub fn outputs(&self) -> PreprocessingCertificationRuntimeOutputs {
        self.outputs
    }

    /// Extracts the runtime transcript hashes carried by the typed proof
    /// envelopes. Full statement validation happens when token certification
    /// recomputes the CarryCompare and BCC public evidence hashes.
    pub fn transcripts(
        &self,
    ) -> Result<PreprocessingCertificationRuntimeTranscripts, PreprocessError> {
        let carry = decode_preprocessing_stage_runtime_proof(&self.carry_compare)
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        let bcc = decode_preprocessing_stage_runtime_proof(&self.bcc)
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        if carry.stage != PreprocessingCertificationStage::CarryCompare
            || bcc.stage != PreprocessingCertificationStage::Bcc
            || self.masked_broadcast == [0u8; 32]
            || carry.runtime_transcript_hash == [0u8; 32]
            || bcc.runtime_transcript_hash == [0u8; 32]
            || self.outputs.masked_broadcast.runtime_transcript_hash != self.masked_broadcast
            || self.outputs.masked_broadcast.signer_count == 0
            || self.outputs.masked_broadcast.coeff_count == 0
            || self.outputs.masked_broadcast.material_state_hash == [0u8; 32]
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        Ok(PreprocessingCertificationRuntimeTranscripts {
            masked_broadcast: self.masked_broadcast,
            carry_compare: carry.runtime_transcript_hash,
            bcc: bcc.runtime_transcript_hash,
        })
    }
}

/// Public statement handed to the preprocessing private vector runtime when it
/// certifies CarryCompare and BCC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreprocessingCertificationRuntimeStatement {
    /// Preprocessing session identifier.
    pub session_id: SessionId,
    /// Transcript hash of the opened preprocessing material.
    pub transcript_hash: TranscriptHash,
    /// Sorted signer set.
    pub signer_set: Vec<PartyId>,
    /// Number of coefficients certified per signer.
    pub coeff_count: usize,
    /// Aggregate masked-broadcast runtime transcript derived from typed
    /// envelope proofs.
    pub masked_broadcast_runtime_transcript: [u8; 32],
    /// Per-envelope masked-broadcast runtime bindings. Production runtime
    /// adapters must verify these against their durable vector runtime
    /// transcript before certifying CarryCompare/BCC.
    pub masked_broadcast_bindings: Vec<MaskedBroadcastRuntimeBinding>,
    /// Public CarryCompare evidence hash that the runtime proof must bind.
    pub carry_compare_evidence_hash: [u8; 32],
    /// Public BCC evidence hash that the runtime proof must bind.
    pub bcc_evidence_hash: [u8; 32],
    /// Hash of the `w1` vector that runtime-owned CEF/BCC must emit.
    pub w1_hash: [u8; 32],
    /// Public input hash for the private CarryCompare circuit.
    pub carry_compare_public_input_hash: [u8; 32],
    /// Public input hash for the private CEF/BCC circuit.
    pub cef_bcc_public_input_hash: [u8; 32],
    /// Root label hash for the private CarryCompare circuit.
    pub carry_compare_private_circuit_label_hash: [u8; 32],
    /// Root label hash for the private CEF/BCC circuit.
    pub cef_bcc_private_circuit_label_hash: [u8; 32],
}

/// Runtime-owned private preprocessing input binding.
///
/// This object does not contain private rho/mask shares. It binds the runtime's
/// private handle graph to the public statement hashes and private circuit root
/// labels that release certification expects. The actual secret shares remain
/// inside the vector IT-MPC runtime.
#[derive(Clone, Eq, PartialEq)]
struct PreprocessingPrivateCircuitInputs {
    coeff_count: usize,
    carry_compare_public_input_hash: [u8; 32],
    cef_bcc_public_input_hash: [u8; 32],
    carry_compare_private_circuit_label_hash: [u8; 32],
    cef_bcc_private_circuit_label_hash: [u8; 32],
    carry_compare_private_handle_hash: [u8; 32],
    cef_correction_private_handle_hash: [u8; 32],
    cef_bcc_private_handle_hash: [u8; 32],
}

impl PreprocessingPrivateCircuitInputs {
    /// Builds a binding from runtime-owned private preprocessing bit handles.
    fn from_runtime_bit_handles(
        statement: &PreprocessingCertificationRuntimeStatement,
        carry_compare_bits: &[ProductionBitShareVec],
        cef_correction_bits: &[ProductionBitShareVec],
        bcc_violation_bits: &[ProductionBitShareVec],
    ) -> Result<Self, PreprocessError> {
        let carry_compare_private_handle_hash = hash_preprocessing_private_bit_handles(
            b"carry-compare",
            statement,
            carry_compare_bits,
        )?;
        let cef_correction_private_handle_hash = if cef_correction_bits.is_empty() {
            hash_preprocessing_optional_absent_private_handles(b"cef-correction", statement)
        } else {
            hash_preprocessing_private_bit_handles(
                b"cef-correction",
                statement,
                cef_correction_bits,
            )?
        };
        let cef_bcc_private_handle_hash = hash_preprocessing_private_bit_handles(
            b"bcc-violation",
            statement,
            bcc_violation_bits,
        )?;
        Self::from_handle_hashes(
            statement,
            carry_compare_private_handle_hash,
            cef_correction_private_handle_hash,
            cef_bcc_private_handle_hash,
        )
    }

    fn from_handle_hashes(
        statement: &PreprocessingCertificationRuntimeStatement,
        carry_compare_private_handle_hash: [u8; 32],
        cef_correction_private_handle_hash: [u8; 32],
        cef_bcc_private_handle_hash: [u8; 32],
    ) -> Result<Self, PreprocessError> {
        if carry_compare_private_handle_hash == [0u8; 32]
            || cef_correction_private_handle_hash == [0u8; 32]
            || cef_bcc_private_handle_hash == [0u8; 32]
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        ensure_preprocessing_statement_public_input_hashes(statement)?;
        ensure_preprocessing_statement_private_label_hashes(statement)?;
        Ok(Self {
            coeff_count: statement.coeff_count,
            carry_compare_public_input_hash: statement.carry_compare_public_input_hash,
            cef_bcc_public_input_hash: statement.cef_bcc_public_input_hash,
            carry_compare_private_circuit_label_hash: statement
                .carry_compare_private_circuit_label_hash,
            cef_bcc_private_circuit_label_hash: statement.cef_bcc_private_circuit_label_hash,
            carry_compare_private_handle_hash,
            cef_correction_private_handle_hash,
            cef_bcc_private_handle_hash,
        })
    }
}

impl fmt::Debug for PreprocessingPrivateCircuitInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreprocessingPrivateCircuitInputs")
            .field("coeff_count", &self.coeff_count)
            .field(
                "carry_compare_public_input_hash",
                &self.carry_compare_public_input_hash,
            )
            .field("cef_bcc_public_input_hash", &self.cef_bcc_public_input_hash)
            .field(
                "carry_compare_private_circuit_label_hash",
                &self.carry_compare_private_circuit_label_hash,
            )
            .field(
                "cef_bcc_private_circuit_label_hash",
                &self.cef_bcc_private_circuit_label_hash,
            )
            .field("carry_compare_private_handle_hash", &"<redacted>")
            .field("cef_correction_private_handle_hash", &"<redacted>")
            .field("cef_bcc_private_handle_hash", &"<redacted>")
            .finish()
    }
}

/// Runtime-owned private preprocessing bit handles.
///
/// This is the public handle bundle callers give to the production
/// preprocessing adapter. It does not contain secret rho/mask values in public
/// output; the wrapped `ProductionBitShareVec` handles redact local lanes in
/// `Debug` and are transcript-bound by the vector runtime.
#[derive(Clone, Eq, PartialEq)]
pub struct PreprocessingPrivateCircuitHandles {
    carry_compare_bits: Vec<ProductionBitShareVec>,
    cef_correction_bits: Vec<ProductionBitShareVec>,
    bcc_violation_bits: Vec<ProductionBitShareVec>,
}

impl PreprocessingPrivateCircuitHandles {
    /// Builds a preprocessing private handle bundle.
    pub fn new(
        carry_compare_bits: Vec<ProductionBitShareVec>,
        bcc_violation_bits: Vec<ProductionBitShareVec>,
    ) -> Result<Self, PreprocessError> {
        Self::from_preprocessing_bits(carry_compare_bits, Vec::new(), bcc_violation_bits)
    }

    fn from_preprocessing_bits(
        carry_compare_bits: Vec<ProductionBitShareVec>,
        cef_correction_bits: Vec<ProductionBitShareVec>,
        bcc_violation_bits: Vec<ProductionBitShareVec>,
    ) -> Result<Self, PreprocessError> {
        if carry_compare_bits.is_empty() || bcc_violation_bits.is_empty() {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        Ok(Self {
            carry_compare_bits,
            cef_correction_bits,
            bcc_violation_bits,
        })
    }

    fn bind_to_statement(
        &self,
        statement: &PreprocessingCertificationRuntimeStatement,
    ) -> Result<PreprocessingPrivateCircuitInputs, PreprocessError> {
        PreprocessingPrivateCircuitInputs::from_runtime_bit_handles(
            statement,
            &self.carry_compare_bits,
            &self.cef_correction_bits,
            &self.bcc_violation_bits,
        )
    }
}

impl fmt::Debug for PreprocessingPrivateCircuitHandles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreprocessingPrivateCircuitHandles")
            .field("carry_compare_bits", &self.carry_compare_bits.len())
            .field("cef_correction_bits", &self.cef_correction_bits.len())
            .field("bcc_violation_bits", &self.bcc_violation_bits.len())
            .field("lanes", &"<redacted>")
            .finish()
    }
}

/// Runtime-owned private preprocessing material handles before certification.
///
/// This is the only normal-build input accepted by the preprocessing private
/// circuit driver. It groups the secret rho-sum bit handles and the secret BCC
/// violation-bit handle under labels derived from one preprocessing statement.
#[derive(Clone, Eq, PartialEq)]
pub struct PreprocessingPrivateMaterialHandles {
    masked_broadcast_relation_bits: Vec<ProductionBitShareVec>,
    rho_sum_bits_by_bit_le: Vec<ProductionBitShareVec>,
    cef_correction_bits: Vec<ProductionBitShareVec>,
    bcc_violation_bits: Vec<ProductionBitShareVec>,
}

impl PreprocessingPrivateMaterialHandles {
    fn from_runtime_handles<P: MlDsaParams>(
        statement: &PreprocessingCertificationRuntimeStatement,
        masked_broadcast_relation_bits: Vec<ProductionBitShareVec>,
        rho_sum_bits_by_bit_le: Vec<ProductionBitShareVec>,
        cef_correction_bits: Vec<ProductionBitShareVec>,
        bcc_violation_bits: Vec<ProductionBitShareVec>,
    ) -> Result<Self, PreprocessError> {
        ensure_preprocessing_masked_broadcast_relation_labels(
            statement,
            &masked_broadcast_relation_bits,
        )?;
        ensure_preprocessing_private_material_handle_labels::<P>(
            statement,
            &rho_sum_bits_by_bit_le,
            &cef_correction_bits,
            &bcc_violation_bits,
        )?;
        Ok(Self {
            masked_broadcast_relation_bits,
            rho_sum_bits_by_bit_le,
            cef_correction_bits,
            bcc_violation_bits,
        })
    }

    fn masked_broadcast_relation_bits(&self) -> &[ProductionBitShareVec] {
        &self.masked_broadcast_relation_bits
    }

    fn rho_sum_bits_by_bit_le(&self) -> &[ProductionBitShareVec] {
        &self.rho_sum_bits_by_bit_le
    }

    fn bcc_violation_bits(&self) -> &[ProductionBitShareVec] {
        &self.bcc_violation_bits
    }

    fn cef_correction_bits(&self) -> &[ProductionBitShareVec] {
        &self.cef_correction_bits
    }
}

impl fmt::Debug for PreprocessingPrivateMaterialHandles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreprocessingPrivateMaterialHandles")
            .field(
                "masked_broadcast_relation_bits",
                &self.masked_broadcast_relation_bits.len(),
            )
            .field("rho_sum_bits_by_bit_le", &self.rho_sum_bits_by_bit_le.len())
            .field("cef_correction_bits", &self.cef_correction_bits.len())
            .field("bcc_violation_bits", &self.bcc_violation_bits.len())
            .field("lanes", &"<redacted>")
            .finish()
    }
}

/// Runtime-private IT-MPC source handles for preprocessing material.
///
/// This object is the final-source boundary for Phase 6: masked-broadcast
/// relation-violation bits, rho-sum bits, and BCC violation bits are supplied
/// as runtime-owned handles under statement-derived labels. It has no public
/// fields and all lane values remain redacted.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PreprocessingRuntimePrivateMpcStateInput {
    masked_broadcast_relation_bits: Vec<ProductionBitShareVec>,
    rho_sum_bits_by_bit_le: Vec<ProductionBitShareVec>,
    cef_correction_bits: Vec<ProductionBitShareVec>,
    bcc_violation_bits: Vec<ProductionBitShareVec>,
}

impl PreprocessingRuntimePrivateMpcStateInput {
    /// Builds a runtime-private preprocessing state input from runtime-owned
    /// handles.
    fn new<P: MlDsaParams>(
        statement: &PreprocessingCertificationRuntimeStatement,
        masked_broadcast_relation_bits: Vec<ProductionBitShareVec>,
        rho_sum_bits_by_bit_le: Vec<ProductionBitShareVec>,
        cef_correction_bits: Vec<ProductionBitShareVec>,
        bcc_violation_bits: Vec<ProductionBitShareVec>,
    ) -> Result<Self, PreprocessError> {
        ensure_preprocessing_runtime_private_mpc_input_labels::<P>(
            statement,
            &masked_broadcast_relation_bits,
            &rho_sum_bits_by_bit_le,
            &cef_correction_bits,
            &bcc_violation_bits,
        )?;
        Ok(Self {
            masked_broadcast_relation_bits,
            rho_sum_bits_by_bit_le,
            cef_correction_bits,
            bcc_violation_bits,
        })
    }

    fn into_material_handles<P: MlDsaParams>(
        self,
        statement: &PreprocessingCertificationRuntimeStatement,
    ) -> Result<PreprocessingPrivateMaterialHandles, PreprocessError> {
        PreprocessingPrivateMaterialHandles::from_runtime_handles::<P>(
            statement,
            self.masked_broadcast_relation_bits,
            self.rho_sum_bits_by_bit_le,
            self.cef_correction_bits,
            self.bcc_violation_bits,
        )
    }
}

impl fmt::Debug for PreprocessingRuntimePrivateMpcStateInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreprocessingRuntimePrivateMpcStateInput")
            .field(
                "masked_broadcast_relation_bits",
                &self.masked_broadcast_relation_bits.len(),
            )
            .field("rho_sum_bits_by_bit_le", &self.rho_sum_bits_by_bit_le.len())
            .field("cef_correction_bits", &self.cef_correction_bits.len())
            .field("bcc_violation_bits", &self.bcc_violation_bits.len())
            .field("lanes", &"<redacted>")
            .finish()
    }
}

/// Source of runtime-owned preprocessing private material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreprocessingPrivateMaterialStateSource {
    /// Transitional integration source derived from opened preprocessing
    /// material. This is allowed in normal/dev builds but rejected by
    /// `production-release-checks`.
    OpenedMaterialDerived,
    /// Final source owned by the private preprocessing IT-MPC backend.
    RuntimePrivateMpc,
}

/// Runtime-owned preprocessing private material state.
///
/// This is the normal-build source for preprocessing CarryCompare/CEF/BCC
/// private circuit handles. It is created only by crate-owned adapter methods
/// from statement-bound preprocessing material, and it redacts all private lane
/// values.
#[derive(Clone, Eq, PartialEq)]
pub struct PreprocessingPrivateMaterialState {
    source: PreprocessingPrivateMaterialStateSource,
    statement_hash: [u8; 32],
    opened_broadcast_hash: [u8; 32],
    source_handle_hash: [u8; 32],
    material: PreprocessingPrivateMaterialHandles,
}

impl PreprocessingPrivateMaterialState {
    fn new(
        source: PreprocessingPrivateMaterialStateSource,
        statement: &PreprocessingCertificationRuntimeStatement,
        broadcasts: &[MaskedBroadcast],
        source_handle_hash: [u8; 32],
        material: PreprocessingPrivateMaterialHandles,
    ) -> Result<Self, PreprocessError> {
        let statement_hash = hash_preprocessing_runtime_statement(statement);
        let opened_broadcast_hash = hash_preprocessing_opened_broadcasts(statement, broadcasts)?;
        if statement_hash == [0u8; 32]
            || opened_broadcast_hash == [0u8; 32]
            || source_handle_hash == [0u8; 32]
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        Ok(Self {
            source,
            statement_hash,
            opened_broadcast_hash,
            source_handle_hash,
            material,
        })
    }

    /// Returns the private material source class.
    pub fn source(&self) -> PreprocessingPrivateMaterialStateSource {
        self.source
    }

    fn ensure_matches(
        &self,
        statement: &PreprocessingCertificationRuntimeStatement,
        broadcasts: &[MaskedBroadcast],
    ) -> Result<(), PreprocessError> {
        if self.statement_hash != hash_preprocessing_runtime_statement(statement)
            || self.opened_broadcast_hash
                != hash_preprocessing_opened_broadcasts(statement, broadcasts)?
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        Ok(())
    }

    fn ensure_allowed_for_release(&self) -> Result<(), PreprocessError> {
        #[cfg(feature = "production-release-checks")]
        {
            if self.source != PreprocessingPrivateMaterialStateSource::RuntimePrivateMpc {
                return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
            }
        }
        Ok(())
    }

    fn material(&self) -> &PreprocessingPrivateMaterialHandles {
        &self.material
    }
}

impl fmt::Debug for PreprocessingPrivateMaterialState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreprocessingPrivateMaterialState")
            .field("source", &self.source)
            .field("statement_hash", &self.statement_hash)
            .field("opened_broadcast_hash", &self.opened_broadcast_hash)
            .field("source_handle_hash", &"<redacted>")
            .field("material", &"<redacted>")
            .finish()
    }
}

/// App-driven state for the preprocessing private certification circuits.
///
/// The state runs the production vector runtime's preprocessing-tagged
/// CarryCompare comparison followed by the preprocessing-tagged CEF/BCC
/// threshold check. It yields `PreprocessingPrivateCircuitHandles` only after
/// both runtime-owned circuits have completed.
#[derive(Debug)]
pub struct PreprocessingPrivateCircuitDriverState {
    masked_broadcast: ProductionBitSumLeqPublicVecState,
    carry_compare: ProductionPublicComparisonVecState,
    cef_correction: Option<ProductionBitSumLeqPublicVecState>,
    bcc: ProductionBitSumLeqPublicVecState,
    material_state_hash: [u8; 32],
}

impl PreprocessingPrivateCircuitDriverState {
    /// Returns true when both private preprocessing circuits have completed.
    pub fn is_done(&self) -> bool {
        self.masked_broadcast.is_done()
            && self.carry_compare.is_done()
            && self
                .cef_correction
                .as_ref()
                .map(|state| state.is_done())
                .unwrap_or(true)
            && self.bcc.is_done()
    }
}

/// One preprocessing token member inside a fused private CarryCompare/CEF/BCC
/// runtime circuit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreprocessingPrivateCircuitBatchMember {
    /// Token preprocessing session id.
    pub session_id: SessionId,
    /// Token preprocessing transcript hash.
    pub transcript_hash: TranscriptHash,
    /// Number of coefficient lanes for this token.
    pub coeff_count: usize,
}

/// Runtime-owned fused private preprocessing circuit state.
///
/// This state executes masked-broadcast relation checks, CarryCompare, CEF
/// correction, and BCC admission for multiple token statements as one wider
/// vector circuit. It is the next runtime primitive below
/// `PreprocessingReleaseBatchDriver`; release-token certificate promotion is a
/// separate step because the existing per-token certificate format is bound to
/// per-token private circuit labels.
#[derive(Debug)]
pub struct PreprocessingPrivateCircuitBatchDriverState {
    members: Vec<PreprocessingPrivateCircuitBatchMember>,
    batch_statement: PreprocessingCertificationRuntimeStatement,
    state: PreprocessingPrivateCircuitDriverState,
}

impl PreprocessingPrivateCircuitBatchDriverState {
    /// Returns true once the fused private runtime circuit has completed.
    pub fn is_done(&self) -> bool {
        self.state.is_done()
    }

    /// Returns the fused token members in batch order.
    pub fn members(&self) -> &[PreprocessingPrivateCircuitBatchMember] {
        &self.members
    }

    /// Returns the synthetic statement used to label the fused runtime circuit.
    pub fn batch_statement(&self) -> &PreprocessingCertificationRuntimeStatement {
        &self.batch_statement
    }
}

/// Production-facing runtime boundary for preprocessing certification.
pub trait PreprocessingCertificationRuntime {
    /// Produces typed CarryCompare/BCC runtime proofs plus durable vector IT-MPC
    /// runtime evidence for one preprocessing statement.
    fn certify_preprocessing<P: MlDsaParams>(
        &mut self,
        statement: &PreprocessingCertificationRuntimeStatement,
    ) -> Result<
        (
            PreprocessingCertificationRuntimeProofs,
            ProductionVectorItMpcRuntimeEvidence,
        ),
        PreprocessError,
    >;
}

/// Production preprocessing certification adapter backed by the app-driven
/// vector prime-field IT-MPC runtime.
///
/// This adapter is the normal-build boundary for release-capable preprocessing
/// certificates: it refuses runtime evidence that does not pass the Phase 3
/// durable vector-runtime gate and derives CarryCompare/BCC stage proof
/// transcripts from that durable runtime transcript. The remaining Phase 6
/// cryptographic work is to make the preprocessing CarryCompare/CEF/BCC
/// circuits themselves execute through this runtime before this adapter is
/// called.
pub struct ProductionPreprocessingCertificationRuntime<'a, T, L, C> {
    runtime: &'a mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
    private_handles: Option<PreprocessingPrivateCircuitHandles>,
    runtime_masked_broadcast_output: Option<RuntimeMaskedBroadcastOutput>,
    runtime_carry_compare_output: Option<RuntimeCarryCompareOutput>,
    runtime_cef_bcc_output: Option<RuntimeCefBccOutput>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StrictSigningCanonicalMaskTarget {
    Z,
    Hint,
}

impl StrictSigningCanonicalMaskTarget {
    const fn name(self) -> &'static str {
        match self {
            Self::Z => "z_mask",
            Self::Hint => "hint_mask",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StrictSigningCanonicalMaskGenerationPhase {
    RandomBits {
        target: StrictSigningCanonicalMaskTarget,
        chunk_start: usize,
        contributions_by_bit: Vec<Vec<ProductionBitShareVec>>,
    },
    XorFoldBatch {
        target: StrictSigningCanonicalMaskTarget,
        next_idx: usize,
        contributions_by_bit: Vec<Vec<ProductionBitShareVec>>,
        current_by_bit: Vec<ProductionBitShareVec>,
    },
    CanonicalQCheck {
        check: StrictSigningCanonicalQCheckState,
    },
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StrictSigningBitReductionOp {
    And,
    Or,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StrictSigningBitReductionPending {
    lefts: Vec<ProductionBitShareVec>,
    rights: Vec<ProductionBitShareVec>,
    carry: Option<ProductionBitShareVec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StrictSigningBitReductionState {
    op: StrictSigningBitReductionOp,
    bits: Vec<ProductionBitShareVec>,
    label: Power2RoundTranscriptLabel,
    layer: usize,
    pending: Option<StrictSigningBitReductionPending>,
}

impl StrictSigningBitReductionState {
    fn new(
        op: StrictSigningBitReductionOp,
        bits: Vec<ProductionBitShareVec>,
        label: Power2RoundTranscriptLabel,
    ) -> Self {
        Self {
            op,
            bits,
            label,
            layer: 0,
            pending: None,
        }
    }

    fn is_done(&self) -> bool {
        self.bits.len() == 1 && self.pending.is_none()
    }

    fn result(&self) -> Option<&ProductionBitShareVec> {
        if self.is_done() {
            self.bits.first()
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StrictSigningCanonicalQCheckPhase {
    ReduceHighAll {
        high_all: StrictSigningBitReductionState,
        low_any_bits: Vec<ProductionBitShareVec>,
    },
    ReduceLowAny {
        high_all: ProductionBitShareVec,
        low_any: StrictSigningBitReductionState,
    },
    CombineInvalid {
        high_all: ProductionBitShareVec,
        low_any: ProductionBitShareVec,
        driven: bool,
    },
    AssertValid {
        valid: ProductionBitShareVec,
        driven: bool,
    },
    Done,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StrictSigningCanonicalQCheckState {
    label: Power2RoundTranscriptLabel,
    phase: StrictSigningCanonicalQCheckPhase,
}

impl StrictSigningCanonicalQCheckState {
    fn new(bits_by_bit: &[ProductionBitShareVec], label: Power2RoundTranscriptLabel) -> Self {
        // ML-DSA q is 1023 * 2^13 + 1. For a 23-bit mask A,
        // A < q iff A is not in [q, 2^23), which is exactly:
        // high bits 13..22 are all one and at least one low bit 0..12 is one.
        // This avoids the generic 23-step private comparison for strict masks.
        Self {
            label: label.clone(),
            phase: StrictSigningCanonicalQCheckPhase::ReduceHighAll {
                high_all: StrictSigningBitReductionState::new(
                    StrictSigningBitReductionOp::And,
                    bits_by_bit[13..23].to_vec(),
                    label.child("high_bits_all_one"),
                ),
                low_any_bits: bits_by_bit[0..13].to_vec(),
            },
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.phase, StrictSigningCanonicalQCheckPhase::Done)
    }
}

/// App-driven state for generating strict-signing canonical masks from vector
/// IT-MPC random bits.
///
/// The state intentionally exposes no mask values directly. Callers drive and
/// collect one phase at a time, route messages using their application
/// transport, and then finish the state into a provenance-bound
/// [`StrictSigningCanonicalMaskInventory`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictSigningCanonicalMaskGenerationState {
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    z_lane_count: usize,
    hint_lane_count: usize,
    z_bits_by_bit: Vec<ProductionBitShareVec>,
    hint_bits_by_bit: Vec<ProductionBitShareVec>,
    z_mask_value: Option<ProductionShareVec>,
    hint_mask_value: Option<ProductionShareVec>,
    phase: StrictSigningCanonicalMaskGenerationPhase,
}

impl StrictSigningCanonicalMaskGenerationState {
    /// Returns true after both z and hint canonical-mask inventories have been
    /// generated and certified.
    pub fn is_done(&self) -> bool {
        matches!(self.phase, StrictSigningCanonicalMaskGenerationPhase::Done)
    }
}

fn strict_signing_random_bit_base_lane_chunk<P: MlDsaParams>() -> usize {
    (ProductionBatchSizingPolicy::for_suite::<P>().max_vector_lanes_per_chunk / 23).max(1)
}

fn strict_signing_mask_target_lane_count(
    state: &StrictSigningCanonicalMaskGenerationState,
    target: StrictSigningCanonicalMaskTarget,
) -> usize {
    match target {
        StrictSigningCanonicalMaskTarget::Z => state.z_lane_count,
        StrictSigningCanonicalMaskTarget::Hint => state.hint_lane_count,
    }
}

fn strict_signing_canonical_mask_batch_identity(
    members: &[StrictSigningCanonicalMaskBatchMember],
) -> (SessionId, TranscriptHash) {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS strict signing fused canonical mask batch v1");
    for member in members {
        hasher.update(member.session_id.0);
        hasher.update(member.transcript_hash.0);
        hasher.update((member.z_lane_count as u64).to_le_bytes());
        hasher.update((member.hint_lane_count as u64).to_le_bytes());
    }
    let digest = hasher.finalize();
    let mut session = [0u8; 32];
    session.copy_from_slice(&digest);

    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS strict signing fused canonical mask transcript v1");
    hasher.update(session);
    for member in members {
        hasher.update(member.session_id.0);
        hasher.update(member.transcript_hash.0);
    }
    let digest = hasher.finalize();
    let mut transcript = [0u8; 32];
    transcript.copy_from_slice(&digest);
    (SessionId(session), TranscriptHash(transcript))
}

impl<'a, T, L, C> ProductionPreprocessingCertificationRuntime<'a, T, L, C> {
    /// Wraps one app-driven vector IT-MPC runtime for preprocessing
    /// certification.
    pub fn new(runtime: &'a mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>) -> Self {
        Self {
            runtime,
            private_handles: None,
            runtime_masked_broadcast_output: None,
            runtime_carry_compare_output: None,
            runtime_cef_bcc_output: None,
        }
    }

    /// Attaches runtime-owned private preprocessing circuit handles.
    ///
    /// This direct raw-handle hook is test/scaffold-only. Normal release flows
    /// must attach through `finish_and_attach_private_circuit_state`, which
    /// proves the handles came from a `PreprocessingPrivateMaterialState`.
    #[cfg(any(test, feature = "scaffold-dev"))]
    pub fn with_private_circuit_handles(
        mut self,
        handles: PreprocessingPrivateCircuitHandles,
    ) -> Self {
        self.private_handles = Some(handles);
        self.runtime_masked_broadcast_output = None;
        self.runtime_carry_compare_output = None;
        self.runtime_cef_bcc_output = None;
        self
    }

    /// Attaches completed runtime-owned private preprocessing circuit handles.
    #[cfg(any(test, feature = "scaffold-dev"))]
    pub fn attach_private_circuit_handles(&mut self, handles: PreprocessingPrivateCircuitHandles) {
        self.private_handles = Some(handles);
        self.runtime_masked_broadcast_output = None;
        self.runtime_carry_compare_output = None;
        self.runtime_cef_bcc_output = None;
    }

    /// Builds strict-signing canonical-mask helper handles under
    /// preprocessing/runtime-owned labels.
    ///
    /// The current implementation creates the statement-bound inventory and
    /// provenance that release validation consumes. Final distributed random
    /// generation/certification is a follow-up runtime phase; callers must not
    /// treat anonymous masks as release-valid because `ensure_certified_token`
    /// requires this provenance.
    pub fn strict_signing_canonical_mask_inventory<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        session_id: SessionId,
        transcript_hash: TranscriptHash,
        z_lane_count: usize,
        hint_lane_count: usize,
    ) -> Result<StrictSigningCanonicalMaskInventory, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if z_lane_count == 0 || hint_lane_count == 0 {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        let runtime_evidence = self
            .runtime
            .runtime_evidence()
            .map_err(map_preprocessing_runtime_dkg_error)?;
        let label = Power2RoundTranscriptLabel::root(config, session_id.0)
            .child("preprocessing")
            .child("strict_signing_canonical_masks");
        let z_label = label.child("z_mask");
        let hint_label = label.child("hint_mask");
        let z_mask_value = self
            .runtime
            .share_vec_from_local_lanes::<P>(config, &z_label.child("value"), vec![0; z_lane_count])
            .map_err(map_preprocessing_runtime_dkg_error)?;
        let hint_mask_value = self
            .runtime
            .share_vec_from_local_lanes::<P>(
                config,
                &hint_label.child("value"),
                vec![0; hint_lane_count],
            )
            .map_err(map_preprocessing_runtime_dkg_error)?;
        let z_mask_bits_by_bit = (0..23)
            .map(|bit| {
                self.runtime
                    .bit_share_vec_from_local_lanes::<P>(
                        config,
                        &z_label.child(format!("bit_{bit}")),
                        vec![0; z_lane_count],
                    )
                    .map_err(map_preprocessing_runtime_dkg_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let hint_mask_bits_by_bit = (0..23)
            .map(|bit| {
                self.runtime
                    .bit_share_vec_from_local_lanes::<P>(
                        config,
                        &hint_label.child(format!("bit_{bit}")),
                        vec![0; hint_lane_count],
                    )
                    .map_err(map_preprocessing_runtime_dkg_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        StrictSigningCanonicalMaskInventory::new_with_preprocessing_provenance(
            StrictSigningCanonicalMaskProvenance {
                session_id,
                transcript_hash,
                runtime_transcript_hash: runtime_evidence.transcript_hash,
                z_mask_value_label_hash: z_mask_value.id().label_hash,
                hint_mask_value_label_hash: hint_mask_value.id().label_hash,
                z_lane_count,
                hint_lane_count,
            },
            z_mask_value,
            z_mask_bits_by_bit,
            hint_mask_value,
            hint_mask_bits_by_bit,
        )
    }

    /// Builds strict-signing canonical-mask helper handles from runtime random
    /// bit contribution phases and certifies that the resulting masks are
    /// canonical representatives in `[0, q)`.
    ///
    /// This is the production-shaped mask construction used by strict signing:
    /// mask bits come from the vector IT-MPC random-bit contribution machinery,
    /// mask values are derived as `sum 2^i bit_i`, and the runtime proves
    /// `mask < q` without exposing the mask bits. This helper is intentionally
    /// immediate: if the embedding app has not delivered the required MPC
    /// messages for the current party, it returns
    /// `PreprocessingRuntimeMaterialMissing` instead of synthesizing local
    /// fallback material.
    pub fn strict_signing_canonical_mask_inventory_from_runtime_random_bits<
        P: MlDsaParams,
        E: ProductionVectorItMpcEntropy,
    >(
        &mut self,
        config: &DkgConfig,
        session_id: SessionId,
        transcript_hash: TranscriptHash,
        z_lane_count: usize,
        hint_lane_count: usize,
        entropy: &mut E,
    ) -> Result<StrictSigningCanonicalMaskInventory, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if z_lane_count == 0 || hint_lane_count == 0 {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        let label = Power2RoundTranscriptLabel::root(config, session_id.0)
            .child("preprocessing")
            .child("strict_signing_canonical_masks");
        let z_label = label.child("z_mask");
        let hint_label = label.child("hint_mask");

        let (z_mask_value, z_mask_bits_by_bit) = self
            .strict_signing_runtime_random_canonical_mask::<P, E>(
                config,
                z_lane_count,
                &z_label,
                entropy,
            )?;
        let (hint_mask_value, hint_mask_bits_by_bit) = self
            .strict_signing_runtime_random_canonical_mask::<P, E>(
                config,
                hint_lane_count,
                &hint_label,
                entropy,
            )?;

        let runtime_evidence = self
            .runtime
            .runtime_evidence()
            .map_err(map_preprocessing_runtime_dkg_error)?;
        StrictSigningCanonicalMaskInventory::new_with_preprocessing_provenance(
            StrictSigningCanonicalMaskProvenance {
                session_id,
                transcript_hash,
                runtime_transcript_hash: runtime_evidence.transcript_hash,
                z_mask_value_label_hash: z_mask_value.id().label_hash,
                hint_mask_value_label_hash: hint_mask_value.id().label_hash,
                z_lane_count,
                hint_lane_count,
            },
            z_mask_value,
            z_mask_bits_by_bit,
            hint_mask_value,
            hint_mask_bits_by_bit,
        )
    }

    /// Starts app-driven generation of strict-signing canonical masks from
    /// runtime random-bit contribution phases.
    pub fn start_strict_signing_canonical_mask_generation(
        &self,
        session_id: SessionId,
        transcript_hash: TranscriptHash,
        z_lane_count: usize,
        hint_lane_count: usize,
    ) -> Result<StrictSigningCanonicalMaskGenerationState, PreprocessError> {
        if z_lane_count == 0 || hint_lane_count == 0 {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        Ok(StrictSigningCanonicalMaskGenerationState {
            session_id,
            transcript_hash,
            z_lane_count,
            hint_lane_count,
            z_bits_by_bit: Vec::with_capacity(23),
            hint_bits_by_bit: Vec::with_capacity(23),
            z_mask_value: None,
            hint_mask_value: None,
            phase: StrictSigningCanonicalMaskGenerationPhase::RandomBits {
                target: StrictSigningCanonicalMaskTarget::Z,
                chunk_start: 0,
                contributions_by_bit: Vec::new(),
            },
        })
    }

    /// Starts one fused strict-signing canonical-mask generation state for a
    /// batch of preprocessing tokens.
    ///
    /// The generated mask bits and canonicality checks are one larger vector
    /// circuit. After completion,
    /// [`Self::finish_strict_signing_canonical_mask_batch_generation`] splits
    /// the private handles into token-bound inventories without opening the
    /// underlying mask material.
    pub fn start_strict_signing_canonical_mask_batch_generation(
        &self,
        members: &[StrictSigningCanonicalMaskBatchMember],
    ) -> Result<StrictSigningCanonicalMaskGenerationState, PreprocessError> {
        if members.is_empty() {
            return Err(PreprocessError::EmptySignerSet);
        }
        let mut z_lane_count = 0usize;
        let mut hint_lane_count = 0usize;
        for member in members {
            if member.z_lane_count == 0 || member.hint_lane_count == 0 {
                return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
            }
            z_lane_count = z_lane_count.saturating_add(member.z_lane_count);
            hint_lane_count = hint_lane_count.saturating_add(member.hint_lane_count);
        }
        let (session_id, transcript_hash) = strict_signing_canonical_mask_batch_identity(members);
        self.start_strict_signing_canonical_mask_generation(
            session_id,
            transcript_hash,
            z_lane_count,
            hint_lane_count,
        )
    }

    /// Drives the current canonical-mask generation phase.
    pub fn drive_strict_signing_canonical_mask_generation_step<
        P: MlDsaParams,
        E: ProductionVectorItMpcEntropy,
    >(
        &mut self,
        config: &DkgConfig,
        state: &mut StrictSigningCanonicalMaskGenerationState,
        entropy: &mut E,
    ) -> Result<(), PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let base = Self::strict_signing_mask_base_label(config, state.session_id);
        match &mut state.phase {
            StrictSigningCanonicalMaskGenerationPhase::RandomBits {
                target,
                chunk_start,
                ..
            } => {
                let total_lanes = match target {
                    StrictSigningCanonicalMaskTarget::Z => state.z_lane_count,
                    StrictSigningCanonicalMaskTarget::Hint => state.hint_lane_count,
                };
                let chunk_len = total_lanes
                    .saturating_sub(*chunk_start)
                    .min(strict_signing_random_bit_base_lane_chunk::<P>());
                if chunk_len == 0 {
                    return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
                }
                let label = base
                    .child(target.name())
                    .child("random_bits_0_22")
                    .child(format!("chunk_{chunk_start}"));
                self.runtime
                    .drive_random_bit_contribution_vec::<P, E>(
                        config,
                        chunk_len * 23,
                        &label,
                        entropy,
                    )
                    .map_err(map_preprocessing_runtime_dkg_error)?;
            }
            StrictSigningCanonicalMaskGenerationPhase::XorFoldBatch {
                target,
                next_idx,
                contributions_by_bit,
                current_by_bit,
            } => {
                let label = base
                    .child(target.name())
                    .child("xor_contributions_batch")
                    .child(format!("fold_{next_idx}"));
                let next_by_bit = contributions_by_bit
                    .iter()
                    .map(|contributions| {
                        contributions
                            .get(*next_idx)
                            .cloned()
                            .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let packed_current = self
                    .runtime
                    .pack_bit_share_vecs_for_runtime_batch::<P>(
                        config,
                        current_by_bit,
                        &label.child("packed_current"),
                    )
                    .map_err(map_preprocessing_runtime_dkg_error)?;
                let packed_next = self
                    .runtime
                    .pack_bit_share_vecs_for_runtime_batch::<P>(
                        config,
                        &next_by_bit,
                        &label.child("packed_next"),
                    )
                    .map_err(map_preprocessing_runtime_dkg_error)?;
                self.runtime
                    .drive_bit_and_vec::<P, E>(
                        config,
                        &packed_current,
                        &packed_next,
                        &label.child("packed_and"),
                        entropy,
                    )
                    .map_err(map_preprocessing_runtime_dkg_error)?;
            }
            StrictSigningCanonicalMaskGenerationPhase::CanonicalQCheck { check } => {
                self.drive_strict_signing_canonical_q_check_step::<P, E>(config, check, entropy)?;
            }
            StrictSigningCanonicalMaskGenerationPhase::Done => {}
        }
        Ok(())
    }

    /// Collects the current canonical-mask generation phase.
    pub fn collect_strict_signing_canonical_mask_generation_step<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        state: &mut StrictSigningCanonicalMaskGenerationState,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let base = Self::strict_signing_mask_base_label(config, state.session_id);
        let phase = core::mem::replace(
            &mut state.phase,
            StrictSigningCanonicalMaskGenerationPhase::Done,
        );
        match phase {
            StrictSigningCanonicalMaskGenerationPhase::RandomBits {
                target,
                chunk_start,
                mut contributions_by_bit,
            } => {
                let total_lanes = strict_signing_mask_target_lane_count(state, target);
                let chunk_len = total_lanes
                    .saturating_sub(chunk_start)
                    .min(strict_signing_random_bit_base_lane_chunk::<P>());
                if chunk_len == 0 {
                    return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
                }
                let label = base
                    .child(target.name())
                    .child("random_bits_0_22")
                    .child(format!("chunk_{chunk_start}"));
                match self
                    .runtime
                    .collect_random_bit_contribution_vec::<P>(config, &label)
                    .map_err(map_preprocessing_runtime_dkg_error)?
                {
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        state.phase = StrictSigningCanonicalMaskGenerationPhase::RandomBits {
                            target,
                            chunk_start,
                            contributions_by_bit,
                        };
                        Ok(ProductionVectorItMpcCollectResult::Waiting(status))
                    }
                    ProductionVectorItMpcCollectResult::Collected { status, value } => {
                        if value.is_empty() {
                            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
                        }
                        let mut chunk_by_bit = vec![Vec::with_capacity(value.len()); 23];
                        for (dealer_idx, packed) in value.iter().enumerate() {
                            let split = self
                                .runtime
                                .unpack_bit_share_vec_runtime_batch::<P>(
                                    config,
                                    packed,
                                    chunk_len,
                                    &label.child(format!("dealer_{dealer_idx}_split")),
                                )
                                .map_err(map_preprocessing_runtime_dkg_error)?;
                            if split.len() != 23 {
                                return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
                            }
                            for (bit_idx, bit) in split.into_iter().enumerate() {
                                chunk_by_bit[bit_idx].push(bit);
                            }
                        }
                        contributions_by_bit = self.merge_strict_signing_random_bit_chunk::<P>(
                            config,
                            target,
                            chunk_start,
                            contributions_by_bit,
                            chunk_by_bit,
                            &label,
                        )?;
                        let next_start = chunk_start + chunk_len;
                        if next_start < total_lanes {
                            state.phase = StrictSigningCanonicalMaskGenerationPhase::RandomBits {
                                target,
                                chunk_start: next_start,
                                contributions_by_bit,
                            };
                            return Ok(ProductionVectorItMpcCollectResult::Collected {
                                status,
                                value: (),
                            });
                        }
                        let current_by_bit = contributions_by_bit
                            .iter_mut()
                            .map(|contributions| {
                                if contributions.is_empty() {
                                    return Err(
                                        PreprocessError::PreprocessingRuntimeMaterialMissing,
                                    );
                                }
                                Ok(contributions.remove(0))
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        if contributions_by_bit.iter().all(Vec::is_empty) {
                            self.accept_strict_signing_mask_bits::<P>(
                                config,
                                state,
                                target,
                                current_by_bit,
                            )?;
                        } else {
                            state.phase = StrictSigningCanonicalMaskGenerationPhase::XorFoldBatch {
                                target,
                                next_idx: 0,
                                contributions_by_bit,
                                current_by_bit,
                            };
                        }
                        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
                    }
                }
            }
            StrictSigningCanonicalMaskGenerationPhase::XorFoldBatch {
                target,
                next_idx,
                contributions_by_bit,
                current_by_bit,
            } => {
                let label = base
                    .child(target.name())
                    .child("xor_contributions_batch")
                    .child(format!("fold_{next_idx}"));
                match self
                    .runtime
                    .collect_bit_and_vec::<P>(config, &label.child("packed_and"))
                    .map_err(map_preprocessing_runtime_dkg_error)?
                {
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        state.phase = StrictSigningCanonicalMaskGenerationPhase::XorFoldBatch {
                            target,
                            next_idx,
                            contributions_by_bit,
                            current_by_bit,
                        };
                        Ok(ProductionVectorItMpcCollectResult::Waiting(status))
                    }
                    ProductionVectorItMpcCollectResult::Collected {
                        status,
                        value: packed_and,
                    } => {
                        let lane_count = match target {
                            StrictSigningCanonicalMaskTarget::Z => state.z_lane_count,
                            StrictSigningCanonicalMaskTarget::Hint => state.hint_lane_count,
                        };
                        let and_by_bit = self
                            .runtime
                            .unpack_bit_share_vec_runtime_batch::<P>(
                                config,
                                &packed_and,
                                lane_count,
                                &label.child("and_split"),
                            )
                            .map_err(map_preprocessing_runtime_dkg_error)?;
                        if and_by_bit.len() != current_by_bit.len() {
                            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
                        }
                        let next_by_bit = contributions_by_bit
                            .iter()
                            .map(|contributions| {
                                contributions
                                    .get(next_idx)
                                    .cloned()
                                    .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        let folded_by_bit = current_by_bit
                            .iter()
                            .zip(next_by_bit.iter())
                            .zip(and_by_bit.iter())
                            .enumerate()
                            .map(|(bit_idx, ((current, next), and))| {
                                self.runtime
                                    .bit_xor_from_and_vec::<P>(
                                        config,
                                        current,
                                        next,
                                        and,
                                        &label.child(format!("xor_bit_{bit_idx}")),
                                    )
                                    .map_err(map_preprocessing_runtime_dkg_error)
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        if contributions_by_bit
                            .iter()
                            .any(|contributions| next_idx + 1 < contributions.len())
                        {
                            state.phase = StrictSigningCanonicalMaskGenerationPhase::XorFoldBatch {
                                target,
                                next_idx: next_idx + 1,
                                contributions_by_bit,
                                current_by_bit: folded_by_bit,
                            };
                        } else {
                            self.accept_strict_signing_mask_bits::<P>(
                                config,
                                state,
                                target,
                                folded_by_bit,
                            )?;
                        }
                        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
                    }
                }
            }
            StrictSigningCanonicalMaskGenerationPhase::CanonicalQCheck { mut check } => {
                match self.collect_strict_signing_canonical_q_check_step::<P>(config, &mut check)? {
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        state.phase =
                            StrictSigningCanonicalMaskGenerationPhase::CanonicalQCheck { check };
                        Ok(ProductionVectorItMpcCollectResult::Waiting(status))
                    }
                    ProductionVectorItMpcCollectResult::Collected { status, .. } => {
                        if check.is_done() {
                            state.phase = StrictSigningCanonicalMaskGenerationPhase::Done;
                        } else {
                            state.phase =
                                StrictSigningCanonicalMaskGenerationPhase::CanonicalQCheck {
                                    check,
                                };
                        }
                        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
                    }
                }
            }
            StrictSigningCanonicalMaskGenerationPhase::Done => {
                state.phase = StrictSigningCanonicalMaskGenerationPhase::Done;
                Ok(ProductionVectorItMpcCollectResult::Collected {
                    status: PrimeFieldMpcPhaseDriverStatus::Collected {
                        receiver: None,
                        kind: PrimeFieldMpcRoundKind::Open,
                        phase: PrimeFieldMpcPhase::BitSumThresholdCheck,
                        label_hash: power2round_label_hash(&base.child("done")),
                        senders: Vec::new(),
                    },
                    value: (),
                })
            }
        }
    }

    /// Finishes a completed strict-signing mask generation driver into a
    /// provenance-bound mask inventory.
    pub fn finish_strict_signing_canonical_mask_generation(
        &self,
        state: StrictSigningCanonicalMaskGenerationState,
    ) -> Result<StrictSigningCanonicalMaskInventory, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if !state.is_done() {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        let z_mask_value = state
            .z_mask_value
            .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
        let hint_mask_value = state
            .hint_mask_value
            .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
        let runtime_evidence = self
            .runtime
            .runtime_evidence()
            .map_err(map_preprocessing_runtime_dkg_error)?;
        StrictSigningCanonicalMaskInventory::new_with_preprocessing_provenance(
            StrictSigningCanonicalMaskProvenance {
                session_id: state.session_id,
                transcript_hash: state.transcript_hash,
                runtime_transcript_hash: runtime_evidence.transcript_hash,
                z_mask_value_label_hash: z_mask_value.id().label_hash,
                hint_mask_value_label_hash: hint_mask_value.id().label_hash,
                z_lane_count: state.z_lane_count,
                hint_lane_count: state.hint_lane_count,
            },
            z_mask_value,
            state.z_bits_by_bit,
            hint_mask_value,
            state.hint_bits_by_bit,
        )
    }

    /// Finishes a fused strict-signing mask generation state and splits the
    /// private mask handles into token-bound inventories.
    pub fn finish_strict_signing_canonical_mask_batch_generation<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        state: StrictSigningCanonicalMaskGenerationState,
        members: &[StrictSigningCanonicalMaskBatchMember],
    ) -> Result<Vec<StrictSigningCanonicalMaskInventory>, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if !state.is_done() || members.is_empty() {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        let expected_z = members
            .iter()
            .try_fold(0usize, |acc, member| acc.checked_add(member.z_lane_count))
            .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
        let expected_hint = members
            .iter()
            .try_fold(0usize, |acc, member| {
                acc.checked_add(member.hint_lane_count)
            })
            .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
        if state.z_lane_count != expected_z
            || state.hint_lane_count != expected_hint
            || state.z_bits_by_bit.len() != 23
            || state.hint_bits_by_bit.len() != 23
        {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        let z_mask_value = state
            .z_mask_value
            .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
        let hint_mask_value = state
            .hint_mask_value
            .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
        let runtime_evidence = self
            .runtime
            .runtime_evidence()
            .map_err(map_preprocessing_runtime_dkg_error)?;

        let mut out = Vec::with_capacity(members.len());
        let mut z_offset = 0usize;
        let mut hint_offset = 0usize;
        for (member_idx, member) in members.iter().enumerate() {
            let base = Self::strict_signing_mask_base_label(config, member.session_id)
                .child("fused_batch_slice")
                .child(format!("member_{member_idx}"));
            let z_range = z_offset..z_offset + member.z_lane_count;
            let hint_range = hint_offset..hint_offset + member.hint_lane_count;
            let member_z_mask = self
                .runtime
                .slice_share_vec_lanes_for_runtime_chunk::<P>(
                    config,
                    &z_mask_value,
                    z_range.clone(),
                    &base.child("z_mask_value"),
                )
                .map_err(map_preprocessing_runtime_dkg_error)?;
            let member_hint_mask = self
                .runtime
                .slice_share_vec_lanes_for_runtime_chunk::<P>(
                    config,
                    &hint_mask_value,
                    hint_range.clone(),
                    &base.child("hint_mask_value"),
                )
                .map_err(map_preprocessing_runtime_dkg_error)?;
            let member_z_bits = state
                .z_bits_by_bit
                .iter()
                .enumerate()
                .map(|(bit_idx, bits)| {
                    self.runtime
                        .slice_bit_share_vec_lanes_for_runtime_chunk::<P>(
                            config,
                            bits,
                            z_range.clone(),
                            &base.child(format!("z_mask_bit_{bit_idx}")),
                        )
                        .map_err(map_preprocessing_runtime_dkg_error)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let member_hint_bits = state
                .hint_bits_by_bit
                .iter()
                .enumerate()
                .map(|(bit_idx, bits)| {
                    self.runtime
                        .slice_bit_share_vec_lanes_for_runtime_chunk::<P>(
                            config,
                            bits,
                            hint_range.clone(),
                            &base.child(format!("hint_mask_bit_{bit_idx}")),
                        )
                        .map_err(map_preprocessing_runtime_dkg_error)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let provenance = StrictSigningCanonicalMaskProvenance {
                session_id: member.session_id,
                transcript_hash: member.transcript_hash,
                runtime_transcript_hash: runtime_evidence.transcript_hash,
                z_mask_value_label_hash: member_z_mask.id().label_hash,
                hint_mask_value_label_hash: member_hint_mask.id().label_hash,
                z_lane_count: member.z_lane_count,
                hint_lane_count: member.hint_lane_count,
            };
            out.push(
                StrictSigningCanonicalMaskInventory::new_with_preprocessing_provenance(
                    provenance,
                    member_z_mask,
                    member_z_bits,
                    member_hint_mask,
                    member_hint_bits,
                )?,
            );
            z_offset += member.z_lane_count;
            hint_offset += member.hint_lane_count;
        }
        Ok(out)
    }

    fn merge_strict_signing_random_bit_chunk<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        target: StrictSigningCanonicalMaskTarget,
        chunk_start: usize,
        existing: Vec<Vec<ProductionBitShareVec>>,
        chunk: Vec<Vec<ProductionBitShareVec>>,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<Vec<ProductionBitShareVec>>, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if chunk.len() != 23 {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        if existing.is_empty() {
            return Ok(chunk);
        }
        if existing.len() != 23 {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        existing
            .into_iter()
            .zip(chunk)
            .enumerate()
            .map(|(bit_idx, (old_by_dealer, new_by_dealer))| {
                if old_by_dealer.len() != new_by_dealer.len() || old_by_dealer.is_empty() {
                    return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
                }
                old_by_dealer
                    .into_iter()
                    .zip(new_by_dealer)
                    .enumerate()
                    .map(|(dealer_idx, (old, new))| {
                        self.runtime
                            .concat_bit_share_vecs_for_runtime_batch::<P>(
                                config,
                                &[old, new],
                                &label
                                    .child("append_chunk")
                                    .child(target.name())
                                    .child(format!("chunk_{chunk_start}"))
                                    .child(format!("bit_{bit_idx}_dealer_{dealer_idx}")),
                            )
                            .map_err(map_preprocessing_runtime_dkg_error)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect()
    }

    fn drive_strict_signing_bit_reduction_step<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        state: &mut StrictSigningBitReductionState,
        entropy: &mut E,
    ) -> Result<(), PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if state.is_done() {
            return Ok(());
        }
        if state.pending.is_some() || state.bits.len() < 2 {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        let mut lefts = Vec::with_capacity(state.bits.len() / 2);
        let mut rights = Vec::with_capacity(state.bits.len() / 2);
        let mut idx = 0usize;
        while idx + 1 < state.bits.len() {
            lefts.push(state.bits[idx].clone());
            rights.push(state.bits[idx + 1].clone());
            idx += 2;
        }
        let carry = (idx < state.bits.len()).then(|| state.bits[idx].clone());
        let layer = state.label.child(format!("layer_{}", state.layer));
        let packed_left = self
            .runtime
            .pack_bit_share_vecs_for_runtime_batch::<P>(config, &lefts, &layer.child("packed_left"))
            .map_err(map_preprocessing_runtime_dkg_error)?;
        let packed_right = self
            .runtime
            .pack_bit_share_vecs_for_runtime_batch::<P>(
                config,
                &rights,
                &layer.child("packed_right"),
            )
            .map_err(map_preprocessing_runtime_dkg_error)?;
        self.runtime
            .drive_bit_and_vec::<P, E>(
                config,
                &packed_left,
                &packed_right,
                &layer.child("pair_and"),
                entropy,
            )
            .map_err(map_preprocessing_runtime_dkg_error)?;
        state.pending = Some(StrictSigningBitReductionPending {
            lefts,
            rights,
            carry,
        });
        Ok(())
    }

    fn collect_strict_signing_bit_reduction_step<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        state: &mut StrictSigningBitReductionState,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if state.is_done() {
            return Ok(ProductionVectorItMpcCollectResult::Collected {
                status: PrimeFieldMpcPhaseDriverStatus::Collected {
                    receiver: None,
                    kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                    phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
                    label_hash: power2round_label_hash(&state.label.child("done")),
                    senders: Vec::new(),
                },
                value: (),
            });
        }
        let Some(pending) = state.pending.take() else {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        };
        let layer = state.label.child(format!("layer_{}", state.layer));
        match self
            .runtime
            .collect_bit_and_vec::<P>(config, &layer.child("pair_and"))
            .map_err(map_preprocessing_runtime_dkg_error)?
        {
            ProductionVectorItMpcCollectResult::Waiting(status) => {
                state.pending = Some(pending);
                Ok(ProductionVectorItMpcCollectResult::Waiting(status))
            }
            ProductionVectorItMpcCollectResult::Collected {
                status,
                value: packed_and,
            } => {
                let lane_count = pending
                    .lefts
                    .first()
                    .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?
                    .len();
                let ands = self
                    .runtime
                    .unpack_bit_share_vec_runtime_batch::<P>(
                        config,
                        &packed_and,
                        lane_count,
                        &layer.child("and_split"),
                    )
                    .map_err(map_preprocessing_runtime_dkg_error)?;
                if ands.len() != pending.lefts.len() || pending.lefts.len() != pending.rights.len()
                {
                    return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
                }
                let mut next_bits =
                    Vec::with_capacity(ands.len() + usize::from(pending.carry.is_some()));
                for (pair_idx, ((left, right), and)) in pending
                    .lefts
                    .iter()
                    .zip(pending.rights.iter())
                    .zip(ands.iter())
                    .enumerate()
                {
                    let bit = match state.op {
                        StrictSigningBitReductionOp::And => and.clone(),
                        StrictSigningBitReductionOp::Or => self
                            .runtime
                            .bit_or_from_and_vec::<P>(
                                config,
                                left,
                                right,
                                and,
                                &layer.child(format!("or_pair_{pair_idx}")),
                            )
                            .map_err(map_preprocessing_runtime_dkg_error)?,
                    };
                    next_bits.push(bit);
                }
                if let Some(carry) = pending.carry {
                    next_bits.push(carry);
                }
                state.bits = next_bits;
                state.layer += 1;
                Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
            }
        }
    }

    fn drive_strict_signing_canonical_q_check_step<
        P: MlDsaParams,
        E: ProductionVectorItMpcEntropy,
    >(
        &mut self,
        config: &DkgConfig,
        state: &mut StrictSigningCanonicalQCheckState,
        entropy: &mut E,
    ) -> Result<(), PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        match &mut state.phase {
            StrictSigningCanonicalQCheckPhase::ReduceHighAll { high_all, .. } => {
                self.drive_strict_signing_bit_reduction_step::<P, E>(config, high_all, entropy)
            }
            StrictSigningCanonicalQCheckPhase::ReduceLowAny { low_any, .. } => {
                self.drive_strict_signing_bit_reduction_step::<P, E>(config, low_any, entropy)
            }
            StrictSigningCanonicalQCheckPhase::CombineInvalid {
                high_all,
                low_any,
                driven,
            } => {
                if *driven {
                    return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
                }
                self.runtime
                    .drive_bit_and_vec::<P, E>(
                        config,
                        high_all,
                        low_any,
                        &state.label.child("invalid_high_all_and_low_any"),
                        entropy,
                    )
                    .map_err(map_preprocessing_runtime_dkg_error)?;
                *driven = true;
                Ok(())
            }
            StrictSigningCanonicalQCheckPhase::AssertValid { valid, driven } => {
                if !*driven {
                    self.runtime
                        .drive_assert_bit_vec_all_ones::<P>(
                            config,
                            valid,
                            &state.label.child("assert_mask_lt_q"),
                        )
                        .map_err(map_preprocessing_runtime_dkg_error)?;
                    *driven = true;
                    Ok(())
                } else {
                    Err(PreprocessError::PreprocessingRuntimeMaterialMissing)
                }
            }
            StrictSigningCanonicalQCheckPhase::Done => Ok(()),
        }
    }

    fn collect_strict_signing_canonical_q_check_step<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        state: &mut StrictSigningCanonicalQCheckState,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let phase = core::mem::replace(&mut state.phase, StrictSigningCanonicalQCheckPhase::Done);
        match phase {
            StrictSigningCanonicalQCheckPhase::ReduceHighAll {
                mut high_all,
                low_any_bits,
            } => {
                match self.collect_strict_signing_bit_reduction_step::<P>(config, &mut high_all)? {
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        state.phase = StrictSigningCanonicalQCheckPhase::ReduceHighAll {
                            high_all,
                            low_any_bits,
                        };
                        Ok(ProductionVectorItMpcCollectResult::Waiting(status))
                    }
                    ProductionVectorItMpcCollectResult::Collected { status, .. } => {
                        if high_all.is_done() {
                            let high_all = high_all
                                .result()
                                .cloned()
                                .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
                            state.phase = StrictSigningCanonicalQCheckPhase::ReduceLowAny {
                                high_all,
                                low_any: StrictSigningBitReductionState::new(
                                    StrictSigningBitReductionOp::Or,
                                    low_any_bits,
                                    state.label.child("low_bits_any_one"),
                                ),
                            };
                        } else {
                            state.phase = StrictSigningCanonicalQCheckPhase::ReduceHighAll {
                                high_all,
                                low_any_bits,
                            };
                        }
                        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
                    }
                }
            }
            StrictSigningCanonicalQCheckPhase::ReduceLowAny {
                high_all,
                mut low_any,
            } => match self.collect_strict_signing_bit_reduction_step::<P>(config, &mut low_any)? {
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    state.phase =
                        StrictSigningCanonicalQCheckPhase::ReduceLowAny { high_all, low_any };
                    Ok(ProductionVectorItMpcCollectResult::Waiting(status))
                }
                ProductionVectorItMpcCollectResult::Collected { status, .. } => {
                    if low_any.is_done() {
                        let low_any = low_any
                            .result()
                            .cloned()
                            .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
                        state.phase = StrictSigningCanonicalQCheckPhase::CombineInvalid {
                            high_all,
                            low_any,
                            driven: false,
                        };
                    } else {
                        state.phase =
                            StrictSigningCanonicalQCheckPhase::ReduceLowAny { high_all, low_any };
                    }
                    Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
                }
            },
            StrictSigningCanonicalQCheckPhase::CombineInvalid {
                high_all,
                low_any,
                driven,
            } => {
                let label = state.label.child("invalid_high_all_and_low_any");
                match self
                    .runtime
                    .collect_bit_and_vec::<P>(config, &label)
                    .map_err(map_preprocessing_runtime_dkg_error)?
                {
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        state.phase = StrictSigningCanonicalQCheckPhase::CombineInvalid {
                            high_all,
                            low_any,
                            driven,
                        };
                        Ok(ProductionVectorItMpcCollectResult::Waiting(status))
                    }
                    ProductionVectorItMpcCollectResult::Collected {
                        status,
                        value: invalid,
                    } => {
                        let valid = self
                            .runtime
                            .bit_not_vec::<P>(
                                config,
                                &invalid,
                                &state.label.child("valid_mask_lt_q"),
                            )
                            .map_err(map_preprocessing_runtime_dkg_error)?;
                        state.phase = StrictSigningCanonicalQCheckPhase::AssertValid {
                            valid,
                            driven: false,
                        };
                        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
                    }
                }
            }
            StrictSigningCanonicalQCheckPhase::AssertValid { valid, driven } => {
                match self
                    .runtime
                    .collect_assert_bit_vec_all_ones::<P>(
                        config,
                        &state.label.child("assert_mask_lt_q"),
                    )
                    .map_err(map_preprocessing_runtime_dkg_error)?
                {
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        state.phase =
                            StrictSigningCanonicalQCheckPhase::AssertValid { valid, driven };
                        Ok(ProductionVectorItMpcCollectResult::Waiting(status))
                    }
                    ProductionVectorItMpcCollectResult::Collected { status, .. } => {
                        state.phase = StrictSigningCanonicalQCheckPhase::Done;
                        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
                    }
                }
            }
            StrictSigningCanonicalQCheckPhase::Done => {
                state.phase = StrictSigningCanonicalQCheckPhase::Done;
                Ok(ProductionVectorItMpcCollectResult::Collected {
                    status: PrimeFieldMpcPhaseDriverStatus::Collected {
                        receiver: None,
                        kind: PrimeFieldMpcRoundKind::AssertZero,
                        phase: PrimeFieldMpcPhase::AssertZeroShare,
                        label_hash: power2round_label_hash(&state.label.child("done")),
                        senders: Vec::new(),
                    },
                    value: (),
                })
            }
        }
    }

    fn accept_strict_signing_mask_bits<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        state: &mut StrictSigningCanonicalMaskGenerationState,
        target: StrictSigningCanonicalMaskTarget,
        bits_by_bit: Vec<ProductionBitShareVec>,
    ) -> Result<(), PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if bits_by_bit.len() != 23 {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        match target {
            StrictSigningCanonicalMaskTarget::Z => state.z_bits_by_bit = bits_by_bit,
            StrictSigningCanonicalMaskTarget::Hint => state.hint_bits_by_bit = bits_by_bit,
        }
        let base =
            Self::strict_signing_mask_base_label(config, state.session_id).child(target.name());
        let bits = match target {
            StrictSigningCanonicalMaskTarget::Z => &state.z_bits_by_bit,
            StrictSigningCanonicalMaskTarget::Hint => &state.hint_bits_by_bit,
        };
        let value = self.strict_signing_mask_value_from_bits::<P>(config, bits, &base)?;
        match target {
            StrictSigningCanonicalMaskTarget::Z => state.z_mask_value = Some(value),
            StrictSigningCanonicalMaskTarget::Hint => state.hint_mask_value = Some(value),
        }
        match target {
            StrictSigningCanonicalMaskTarget::Z => {
                state.phase = StrictSigningCanonicalMaskGenerationPhase::RandomBits {
                    target: StrictSigningCanonicalMaskTarget::Hint,
                    chunk_start: 0,
                    contributions_by_bit: Vec::new(),
                };
            }
            StrictSigningCanonicalMaskTarget::Hint => {
                let compare_bits = state
                    .z_bits_by_bit
                    .iter()
                    .zip(&state.hint_bits_by_bit)
                    .enumerate()
                    .map(|(bit_idx, (z_bit, hint_bit))| {
                        self.runtime
                            .concat_bit_share_vecs_for_runtime_batch::<P>(
                                config,
                                &[z_bit.clone(), hint_bit.clone()],
                                &Self::strict_signing_mask_base_label(config, state.session_id)
                                    .child("combined_lt_q")
                                    .child(format!("bit_{bit_idx}")),
                            )
                            .map_err(map_preprocessing_runtime_dkg_error)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if compare_bits.len() != 23 {
                    return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
                }
                state.phase = StrictSigningCanonicalMaskGenerationPhase::CanonicalQCheck {
                    check: StrictSigningCanonicalQCheckState::new(
                        &compare_bits,
                        Self::strict_signing_mask_base_label(config, state.session_id)
                            .child("combined_lt_q"),
                    ),
                };
            }
        }
        Ok(())
    }

    fn strict_signing_mask_base_label(
        config: &DkgConfig,
        session_id: SessionId,
    ) -> Power2RoundTranscriptLabel {
        Power2RoundTranscriptLabel::root(config, session_id.0)
            .child("preprocessing")
            .child("strict_signing_canonical_masks")
    }

    /// Derives a dev/test strict-signing `[w]` handle from opened
    /// preprocessing broadcasts.
    ///
    /// Production release token construction must use
    /// [`Self::derive_strict_signing_precomputed_w_share_from_distributed_nonce_share`]
    /// so `[w] = [A*y]` is derived from the private distributed nonce/runtime
    /// handle, not from statement-bound opened preprocessing material.
    #[cfg(any(test, feature = "scaffold-dev"))]
    pub fn dev_derive_strict_signing_precomputed_w_share_from_opened_preprocessing<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        statement: &PreprocessingCertificationRuntimeStatement,
        broadcasts: &[MaskedBroadcast],
    ) -> Result<ProductionShareVec, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let lanes = strict_signing_precomputed_w_lanes_from_opened_preprocessing::<P>(
            statement, broadcasts,
        )?;
        self.runtime
            .share_vec_from_local_lanes::<P>(
                config,
                &strict_signing_precomputed_w_label(config, statement.session_id),
                lanes,
            )
            .map_err(map_preprocessing_runtime_dkg_error)
    }

    /// Builds the weighted local nonce-share handle used by strict signing.
    ///
    /// Online aggregation uses Shamir interpolation at zero, so each party's
    /// nonce share is first multiplied by its public Lagrange coefficient. The
    /// returned handle remains a private vector-runtime share; only the public
    /// label and lane count are visible.
    pub fn strict_signing_weighted_nonce_share_from_distributed_nonce_share<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        session_id: SessionId,
        signer_set: &[PartyId],
        share: &DistributedNonceShare,
    ) -> Result<ProductionShareVec, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if share.party != self.runtime.local_party() || !config.parties.contains(&share.party) {
            return Err(PreprocessError::UnknownParty(share.party));
        }
        let mut parties = signer_set.to_vec();
        parties.sort_unstable();
        if parties.is_empty() || !parties.contains(&share.party) {
            return Err(PreprocessError::UnknownParty(share.party));
        }
        let points = parties
            .iter()
            .map(|party| u32::from(party.0))
            .collect::<Vec<_>>();
        let lambdas = lagrange_coefficients_at_zero::<P>(&points)
            .map_err(|_| PreprocessError::NonceGenerationFailed)?;
        let position = parties
            .iter()
            .position(|party| *party == share.party)
            .ok_or(PreprocessError::UnknownParty(share.party))?;
        let weighted_y = share.y_share.mul_scalar_mod_q::<P>(lambdas[position]);
        let mut lanes = Vec::with_capacity(P::L * P::N);
        for poly in weighted_y.polys() {
            lanes.extend_from_slice(poly.coeffs());
        }
        if lanes.len() != P::L * P::N {
            return Err(PreprocessError::NonceGenerationFailed);
        }
        self.runtime
            .share_vec_from_local_lanes::<P>(
                config,
                &strict_signing_weighted_nonce_y_label(config, session_id),
                lanes,
            )
            .map_err(map_preprocessing_runtime_dkg_error)
    }

    /// Derives the strict-signing `[w] = [A * y]` handle from a private
    /// runtime nonce-share handle.
    ///
    /// This is the production-shaped fast path: `[w]` is not reconstructed
    /// from opened masked broadcasts, and callers cannot inject a standalone
    /// precomputed handle. The transform is public-linear over Shamir shares,
    /// so it is local to each party and does not open `[y]`.
    pub fn derive_strict_signing_precomputed_w_share_from_nonce_handle<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        session_id: SessionId,
        rho: &[u8; 32],
        weighted_nonce_share: &ProductionShareVec,
    ) -> Result<ProductionShareVec, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if weighted_nonce_share.id().label_hash
            != power2round_label_hash(&strict_signing_weighted_nonce_y_label(config, session_id))
            || weighted_nonce_share.len() != P::L * P::N
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        self.runtime
            .az_from_rho_share_vec::<P>(
                config,
                rho,
                weighted_nonce_share,
                &strict_signing_precomputed_w_label(config, session_id),
            )
            .map_err(map_preprocessing_runtime_dkg_error)
    }

    /// Convenience wrapper for release token construction from a distributed
    /// nonce share. This is equivalent to creating the weighted nonce handle
    /// and then applying the public `A` transform.
    pub fn derive_strict_signing_precomputed_w_share_from_distributed_nonce_share<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        session_id: SessionId,
        signer_set: &[PartyId],
        rho: &[u8; 32],
        share: &DistributedNonceShare,
    ) -> Result<ProductionShareVec, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let weighted_nonce = self
            .strict_signing_weighted_nonce_share_from_distributed_nonce_share::<P>(
                config, session_id, signer_set, share,
            )?;
        self.derive_strict_signing_precomputed_w_share_from_nonce_handle::<P>(
            config,
            session_id,
            rho,
            &weighted_nonce,
        )
    }

    fn strict_signing_runtime_random_canonical_mask<
        P: MlDsaParams,
        E: ProductionVectorItMpcEntropy,
    >(
        &mut self,
        config: &DkgConfig,
        lane_count: usize,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<(ProductionShareVec, Vec<ProductionBitShareVec>), PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let mut bits_by_bit = Vec::with_capacity(23);
        for bit_idx in 0..23 {
            let bit_label = label.child(format!("random_bit_{bit_idx}"));
            self.runtime
                .drive_random_bit_contribution_vec::<P, E>(config, lane_count, &bit_label, entropy)
                .map_err(map_preprocessing_runtime_dkg_error)?;
            let contributions = match self
                .runtime
                .collect_random_bit_contribution_vec::<P>(config, &bit_label)
                .map_err(map_preprocessing_runtime_dkg_error)?
            {
                ProductionVectorItMpcCollectResult::Collected { value, .. } => value,
                ProductionVectorItMpcCollectResult::Waiting(_) => {
                    return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
                }
            };
            bits_by_bit.push(self.strict_signing_xor_random_bit_contributions::<P, E>(
                config,
                contributions,
                &bit_label.child("xor_contributions"),
                entropy,
            )?);
        }

        let value = self.strict_signing_mask_value_from_bits::<P>(config, &bits_by_bit, label)?;
        let mut lt_q = self
            .runtime
            .start_lt_public_vec::<P>(config, &bits_by_bit, P::Q as u32, &label.child("lt_q"))
            .map_err(map_preprocessing_runtime_dkg_error)?;
        self.finish_public_comparison_immediate::<P, E>(config, &mut lt_q, entropy)?;
        let lt_q = lt_q
            .result()
            .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
        self.runtime
            .drive_bit_sum_equals_public_vec::<P>(
                config,
                core::slice::from_ref(lt_q),
                1,
                &label.child("assert_lt_q"),
            )
            .map_err(map_preprocessing_runtime_dkg_error)?;
        match self
            .runtime
            .collect_bit_sum_equals_public_vec::<P>(config, &label.child("assert_lt_q"))
            .map_err(map_preprocessing_runtime_dkg_error)?
        {
            ProductionVectorItMpcCollectResult::Collected { .. } => {}
            ProductionVectorItMpcCollectResult::Waiting(_) => {
                return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
            }
        }

        Ok((value, bits_by_bit))
    }

    fn strict_signing_xor_random_bit_contributions<
        P: MlDsaParams,
        E: ProductionVectorItMpcEntropy,
    >(
        &mut self,
        config: &DkgConfig,
        mut contributions: Vec<ProductionBitShareVec>,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<ProductionBitShareVec, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let mut current = contributions
            .drain(..1)
            .next()
            .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
        for (idx, next) in contributions.into_iter().enumerate() {
            let fold_label = label.child(format!("fold_{}", idx + 1));
            self.runtime
                .drive_bit_and_vec::<P, E>(config, &current, &next, &fold_label, entropy)
                .map_err(map_preprocessing_runtime_dkg_error)?;
            let and = match self
                .runtime
                .collect_bit_and_vec::<P>(config, &fold_label)
                .map_err(map_preprocessing_runtime_dkg_error)?
            {
                ProductionVectorItMpcCollectResult::Collected { value, .. } => value,
                ProductionVectorItMpcCollectResult::Waiting(_) => {
                    return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
                }
            };
            current = self
                .runtime
                .bit_xor_from_and_vec::<P>(config, &current, &next, &and, &fold_label.child("xor"))
                .map_err(map_preprocessing_runtime_dkg_error)?;
        }
        Ok(current)
    }

    fn strict_signing_mask_value_from_bits<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits_by_bit: &[ProductionBitShareVec],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let weighted = bits_by_bit
            .iter()
            .enumerate()
            .map(|(bit_idx, bit)| {
                self.runtime
                    .mul_public_const_share_vec::<P>(
                        config,
                        bit.certified_share(),
                        1_i32 << bit_idx,
                        &label.child(format!("pow2_{bit_idx}")),
                    )
                    .map_err(map_preprocessing_runtime_dkg_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.runtime
            .sum_share_vecs::<P>(config, &weighted, &label.child("value_from_bits"))
            .map_err(map_preprocessing_runtime_dkg_error)
    }

    fn finish_public_comparison_immediate<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        state: &mut talus_dkg::ProductionPublicComparisonVecState,
        entropy: &mut E,
    ) -> Result<(), PreprocessError>
    where
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let mut rounds = 0usize;
        while !state.is_done() {
            self.runtime
                .drive_public_comparison_vec_step::<P, E>(config, state, entropy)
                .map_err(map_preprocessing_runtime_dkg_error)?;
            match self
                .runtime
                .collect_public_comparison_vec_step::<P>(config, state)
                .map_err(map_preprocessing_runtime_dkg_error)?
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(_) => {
                    return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
                }
            }
            rounds = rounds.saturating_add(1);
            if rounds > 128 {
                return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
            }
        }
        Ok(())
    }
}

impl<T, L, C> ProductionPreprocessingCertificationRuntime<'_, T, L, C>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    /// Emits the preprocessing marker phases for one public certification
    /// statement.
    ///
    /// This records durable vector-runtime coverage for the preprocessing
    /// statement. It is not a substitute for the private CarryCompare/CEF/BCC
    /// circuit; it is the app-driven phase boundary that the final private
    /// circuit will use for its durable transcript.
    pub fn drive_statement_phases(
        &mut self,
        statement: &PreprocessingCertificationRuntimeStatement,
    ) -> Result<(), PreprocessError> {
        let label = preprocessing_certification_runtime_label(statement);
        self.runtime
            .drive_preprocessing_masked_broadcast_vec(
                &label.child("masked_broadcast"),
                &preprocessing_statement_marker_lanes(
                    b"masked-broadcast",
                    statement,
                    statement
                        .signer_set
                        .len()
                        .saturating_mul(statement.coeff_count),
                ),
            )
            .map_err(map_preprocessing_runtime_dkg_error)?;
        self.runtime
            .drive_preprocessing_carry_compare_vec(
                &label.child("carry_compare"),
                &preprocessing_statement_marker_lanes(
                    b"carry-compare",
                    statement,
                    statement.coeff_count,
                ),
            )
            .map_err(map_preprocessing_runtime_dkg_error)?;
        self.runtime
            .drive_preprocessing_cef_bcc_vec(
                &label.child("cef_bcc"),
                &preprocessing_statement_marker_lanes(b"cef-bcc", statement, statement.coeff_count),
            )
            .map_err(map_preprocessing_runtime_dkg_error)?;
        Ok(())
    }

    /// Collects the preprocessing marker phases for one public certification
    /// statement.
    pub fn collect_statement_phases(
        &mut self,
        statement: &PreprocessingCertificationRuntimeStatement,
    ) -> Result<(), PreprocessError> {
        let label = preprocessing_certification_runtime_label(statement);
        let phases = [
            self.runtime
                .drive_collect_preprocessing_masked_broadcast_vec(&label.child("masked_broadcast"))
                .map(|(status, _)| status),
            self.runtime
                .drive_collect_preprocessing_carry_compare_vec(&label.child("carry_compare"))
                .map(|(status, _)| status),
            self.runtime
                .drive_collect_preprocessing_cef_bcc_vec(&label.child("cef_bcc"))
                .map(|(status, _)| status),
        ];
        for phase in phases {
            if !matches!(
                phase.map_err(map_preprocessing_runtime_dkg_error)?,
                PrimeFieldMpcPhaseDriverStatus::Collected { .. }
            ) {
                return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
            }
        }
        Ok(())
    }

    /// Produces runtime-owned masked-broadcast relation-violation handles.
    ///
    /// This is the first Phase 6 private-state source boundary: callers no
    /// longer fabricate `masked_broadcast_private/relation_violation_bits`
    /// handles directly. The adapter verifies that each opened masked
    /// broadcast matches the public runtime statement and its per-party
    /// runtime binding, then creates statement-labeled private relation bits.
    /// A valid opened broadcast contributes zero violation bits; the private
    /// driver later proves `sum(violation_bits) <= 0` through the vector MPC
    /// runtime. Invalid public relation material fails closed before any token
    /// can be certified.
    pub fn start_preprocessing_masked_broadcast_consistency_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        statement: &PreprocessingCertificationRuntimeStatement,
        broadcasts: &[MaskedBroadcast],
    ) -> Result<Vec<ProductionBitShareVec>, PreprocessError> {
        let (carry_public, cef_bcc_public) = preprocessing_public_circuit_input_hashes::<P>(
            statement.session_id,
            statement.transcript_hash,
            &statement.signer_set,
            broadcasts,
        )?;
        if carry_public != statement.carry_compare_public_input_hash
            || cef_bcc_public != statement.cef_bcc_public_input_hash
            || broadcasts.len() != statement.signer_set.len()
            || statement.masked_broadcast_bindings.len() != statement.signer_set.len()
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }

        let root = preprocessing_certification_runtime_label(statement);
        let relation_root = root
            .child("masked_broadcast_private")
            .child("relation_violation_bits");
        let mut relation_bits = Vec::with_capacity(statement.signer_set.len());
        let mut runtime_hashes = Vec::with_capacity(statement.signer_set.len());
        for (idx, party) in statement.signer_set.iter().enumerate() {
            let broadcast = broadcasts
                .iter()
                .find(|broadcast| broadcast.party == *party)
                .ok_or(PreprocessError::MaskedBroadcastConsistencyMismatch(*party))?;
            if broadcast.masked_highs.len() != statement.coeff_count
                || broadcast.masked_lows.len() != statement.coeff_count
                || broadcast.transcript_hash != statement.transcript_hash
            {
                return Err(PreprocessError::MaskedBroadcastConsistencyMismatch(*party));
            }
            let binding = statement
                .masked_broadcast_bindings
                .iter()
                .find(|binding| binding.party == *party)
                .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
            let consistency_statement = MaskedBroadcastConsistencyStatement {
                session_id: statement.session_id,
                signer_set: statement.signer_set.clone(),
                broadcast: broadcast.clone(),
                coeff_count: statement.coeff_count,
            };
            if binding.statement_hash
                != masked_broadcast_statement_hash::<P>(&consistency_statement)
                || binding.runtime_transcript_hash == [0u8; 32]
            {
                return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
            }
            runtime_hashes.push(binding.runtime_transcript_hash);
            let proof = production_masked_broadcast_consistency_proof_with_runtime_transcript::<P>(
                &consistency_statement,
                binding.runtime_transcript_hash,
            );
            verify_private_certified_masked_broadcast::<P>(&consistency_statement, &proof)?;
            relation_bits.push(
                self.runtime
                    .bit_share_vec_from_local_lanes::<P>(
                        config,
                        &relation_root.child(format!("party_{}_violation_{idx}", party.0)),
                        vec![0; statement.coeff_count],
                    )
                    .map_err(map_preprocessing_runtime_dkg_error)?,
            );
        }
        if masked_broadcast_runtime_transcript_hash(
            statement.session_id,
            statement.transcript_hash,
            statement.signer_set.len(),
            statement.coeff_count,
            &runtime_hashes,
        ) != statement.masked_broadcast_runtime_transcript
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        Ok(relation_bits)
    }

    /// Produces runtime-owned CarryCompare rho-sum bit handles from opened
    /// masked broadcasts.
    ///
    /// The rho-sum bits are derived internally from the statement-bound
    /// opened broadcasts and emitted under the exact
    /// `carry_compare_private/rho_sum_bits/bit_i` labels expected by the
    /// private preprocessing circuit. Normal release callers no longer provide
    /// these handles directly.
    pub fn start_preprocessing_carry_compare_rho_sum_bits_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        statement: &PreprocessingCertificationRuntimeStatement,
        broadcasts: &[MaskedBroadcast],
    ) -> Result<Vec<ProductionBitShareVec>, PreprocessError> {
        let (carry_public, cef_bcc_public) = preprocessing_public_circuit_input_hashes::<P>(
            statement.session_id,
            statement.transcript_hash,
            &statement.signer_set,
            broadcasts,
        )?;
        if carry_public != statement.carry_compare_public_input_hash
            || cef_bcc_public != statement.cef_bcc_public_input_hash
            || broadcasts.len() != statement.signer_set.len()
            || broadcasts
                .iter()
                .any(|broadcast| broadcast.transcript_hash != statement.transcript_hash)
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let (rho_sum_bits, _, _) = preprocessing_private_material_lanes_from_opened_broadcasts::<P>(
            statement, broadcasts,
        )?;
        let root = preprocessing_certification_runtime_label(statement);
        let rho_root = root.child("carry_compare_private").child("rho_sum_bits");
        rho_sum_bits
            .into_iter()
            .enumerate()
            .map(|(bit_idx, lanes)| {
                self.runtime
                    .bit_share_vec_from_local_lanes::<P>(
                        config,
                        &rho_root.child(format!("bit_{bit_idx}")),
                        lanes,
                    )
                    .map_err(map_preprocessing_runtime_dkg_error)
            })
            .collect()
    }

    /// Produces runtime-owned CEF correction-bit handles from opened
    /// masked broadcasts.
    ///
    /// The returned vector contains exactly one bit-share vector under
    /// `cef_bcc_private/cef_correction_bits/delta`. These correction bits are
    /// legitimate CEF carries, so they are bound through a separate runtime
    /// threshold circuit and are not mixed into the BCC violation check.
    pub fn start_preprocessing_cef_correction_bits_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        statement: &PreprocessingCertificationRuntimeStatement,
        broadcasts: &[MaskedBroadcast],
    ) -> Result<Vec<ProductionBitShareVec>, PreprocessError> {
        let (carry_public, cef_bcc_public) = preprocessing_public_circuit_input_hashes::<P>(
            statement.session_id,
            statement.transcript_hash,
            &statement.signer_set,
            broadcasts,
        )?;
        if carry_public != statement.carry_compare_public_input_hash
            || cef_bcc_public != statement.cef_bcc_public_input_hash
            || broadcasts.len() != statement.signer_set.len()
            || broadcasts
                .iter()
                .any(|broadcast| broadcast.transcript_hash != statement.transcript_hash)
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let (_, cef_correction_bits, _) =
            preprocessing_private_material_lanes_from_opened_broadcasts::<P>(
                statement, broadcasts,
            )?;
        let root = preprocessing_certification_runtime_label(statement);
        let cef_handle = self
            .runtime
            .bit_share_vec_from_local_lanes::<P>(
                config,
                &root
                    .child("cef_bcc_private")
                    .child("cef_correction_bits")
                    .child("delta"),
                cef_correction_bits,
            )
            .map_err(map_preprocessing_runtime_dkg_error)?;
        Ok(vec![cef_handle])
    }

    /// Produces runtime-owned BCC violation-bit handles from opened
    /// masked broadcasts.
    ///
    /// The returned vector contains exactly one bit-share vector under
    /// `cef_bcc_private/bcc_violation_bits/violation`. Normal release callers
    /// no longer supply any private preprocessing material handles directly.
    pub fn start_preprocessing_bcc_violation_bits_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        statement: &PreprocessingCertificationRuntimeStatement,
        broadcasts: &[MaskedBroadcast],
    ) -> Result<Vec<ProductionBitShareVec>, PreprocessError> {
        let (carry_public, cef_bcc_public) = preprocessing_public_circuit_input_hashes::<P>(
            statement.session_id,
            statement.transcript_hash,
            &statement.signer_set,
            broadcasts,
        )?;
        if carry_public != statement.carry_compare_public_input_hash
            || cef_bcc_public != statement.cef_bcc_public_input_hash
            || broadcasts.len() != statement.signer_set.len()
            || broadcasts
                .iter()
                .any(|broadcast| broadcast.transcript_hash != statement.transcript_hash)
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let (_, _, bcc_violation_bits) =
            preprocessing_private_material_lanes_from_opened_broadcasts::<P>(
                statement, broadcasts,
            )?;
        let root = preprocessing_certification_runtime_label(statement);
        let bcc_handle = self
            .runtime
            .bit_share_vec_from_local_lanes::<P>(
                config,
                &root
                    .child("cef_bcc_private")
                    .child("bcc_violation_bits")
                    .child("violation"),
                bcc_violation_bits,
            )
            .map_err(map_preprocessing_runtime_dkg_error)?;
        Ok(vec![bcc_handle])
    }

    /// Builds the typed private-material bundle accepted by the preprocessing
    /// circuit driver from already-created runtime bit handles.
    ///
    /// This is a test/scaffold-dev bridge. Normal production builds must not
    /// construct private preprocessing material from caller-supplied bit
    /// handles; the remaining Phase 6 work is to derive this bundle from the
    /// runtime's actual preprocessing IT-MPC state.
    #[cfg(any(test, feature = "scaffold-dev"))]
    pub fn private_material_handles_from_runtime_bits<P: MlDsaParams>(
        &self,
        statement: &PreprocessingCertificationRuntimeStatement,
        masked_broadcast_relation_bits: Vec<ProductionBitShareVec>,
        rho_sum_bits_by_bit_le: Vec<ProductionBitShareVec>,
        cef_correction_bits: Vec<ProductionBitShareVec>,
        bcc_violation_bits: Vec<ProductionBitShareVec>,
    ) -> Result<PreprocessingPrivateMaterialHandles, PreprocessError> {
        PreprocessingPrivateMaterialHandles::from_runtime_handles::<P>(
            statement,
            masked_broadcast_relation_bits,
            rho_sum_bits_by_bit_le,
            cef_correction_bits,
            bcc_violation_bits,
        )
    }

    /// Derives the typed private-material handle bundle from the current
    /// preprocessing commit/open material.
    ///
    /// This is the normal-build adapter path for the current preprocessing
    /// implementation: callers provide the same opened masked broadcasts that
    /// are bound into the public runtime statement, and the adapter constructs
    /// statement-labeled runtime handles internally. The direct constructor
    /// from arbitrary runtime bit handles remains test/scaffold-only.
    fn derive_private_material_handles_from_opened_preprocessing<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        statement: &PreprocessingCertificationRuntimeStatement,
        broadcasts: &[MaskedBroadcast],
    ) -> Result<PreprocessingPrivateMaterialHandles, PreprocessError> {
        let (carry_public, cef_bcc_public) = preprocessing_public_circuit_input_hashes::<P>(
            statement.session_id,
            statement.transcript_hash,
            &statement.signer_set,
            broadcasts,
        )?;
        if carry_public != statement.carry_compare_public_input_hash
            || cef_bcc_public != statement.cef_bcc_public_input_hash
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let rho_handles = self.start_preprocessing_carry_compare_rho_sum_bits_vec::<P>(
            config, statement, broadcasts,
        )?;
        let cef_correction_handles =
            self.start_preprocessing_cef_correction_bits_vec::<P>(config, statement, broadcasts)?;
        let bcc_handles =
            self.start_preprocessing_bcc_violation_bits_vec::<P>(config, statement, broadcasts)?;
        let masked_broadcast_handles = self
            .start_preprocessing_masked_broadcast_consistency_vec::<P>(
                config, statement, broadcasts,
            )?;
        PreprocessingPrivateMaterialHandles::from_runtime_handles::<P>(
            statement,
            masked_broadcast_handles,
            rho_handles,
            cef_correction_handles,
            bcc_handles,
        )
    }

    /// Derives runtime-owned preprocessing private material state from opened
    /// release-envelope material.
    ///
    /// This is the normal-build state source for the current Phase 6
    /// implementation. It replaces public raw-handle attachment with a
    /// statement-bound object that later feeds the private CarryCompare and
    /// CEF/BCC circuit driver.
    pub fn derive_private_material_state_from_opened_preprocessing<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        statement: &PreprocessingCertificationRuntimeStatement,
        broadcasts: &[MaskedBroadcast],
    ) -> Result<PreprocessingPrivateMaterialState, PreprocessError> {
        let material = self.derive_private_material_handles_from_opened_preprocessing::<P>(
            config, statement, broadcasts,
        )?;
        PreprocessingPrivateMaterialState::new(
            PreprocessingPrivateMaterialStateSource::OpenedMaterialDerived,
            statement,
            broadcasts,
            hash_opened_material_private_source_handles(&material),
            material,
        )
    }

    /// Derives preprocessing private material from the final private IT-MPC
    /// source.
    ///
    /// The boundary is intentionally present now so release policy can require
    /// this source. The implementation remains a Phase 6 blocker until the
    /// masked-broadcast/rho/BCC predicate state is produced by the private
    /// preprocessing IT-MPC backend.
    fn derive_private_material_state_from_runtime_private_mpc<P: MlDsaParams>(
        &self,
        _config: &DkgConfig,
        statement: &PreprocessingCertificationRuntimeStatement,
        broadcasts: &[MaskedBroadcast],
        input: PreprocessingRuntimePrivateMpcStateInput,
    ) -> Result<PreprocessingPrivateMaterialState, PreprocessError> {
        let _ = core::marker::PhantomData::<P>;
        let (carry_public, cef_bcc_public) = preprocessing_public_circuit_input_hashes::<P>(
            statement.session_id,
            statement.transcript_hash,
            &statement.signer_set,
            broadcasts,
        )?;
        if carry_public != statement.carry_compare_public_input_hash
            || cef_bcc_public != statement.cef_bcc_public_input_hash
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        ensure_preprocessing_runtime_private_mpc_input_labels::<P>(
            statement,
            &input.masked_broadcast_relation_bits,
            &input.rho_sum_bits_by_bit_le,
            &input.cef_correction_bits,
            &input.bcc_violation_bits,
        )?;
        let source_handle_hash = hash_runtime_private_mpc_source_handles(statement, &input)?;
        let material = input.into_material_handles::<P>(statement)?;
        PreprocessingPrivateMaterialState::new(
            PreprocessingPrivateMaterialStateSource::RuntimePrivateMpc,
            statement,
            broadcasts,
            source_handle_hash,
            material,
        )
    }

    /// Derives preprocessing private material state from runtime-private
    /// handles generated by the adapter.
    ///
    /// This is the current production-facing Phase 6 private-material boundary:
    /// masked-broadcast relation-violation bits, CarryCompare rho-sum bits, and
    /// BCC violation bits are all derived from `statement + broadcasts` by the
    /// adapter.
    pub fn derive_private_material_state_from_runtime_private_mpc_handles<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        statement: &PreprocessingCertificationRuntimeStatement,
        broadcasts: &[MaskedBroadcast],
    ) -> Result<PreprocessingPrivateMaterialState, PreprocessError> {
        let relation_bits = self.start_preprocessing_masked_broadcast_consistency_vec::<P>(
            config, statement, broadcasts,
        )?;
        let rho_sum_bits_by_bit_le = self.start_preprocessing_carry_compare_rho_sum_bits_vec::<P>(
            config, statement, broadcasts,
        )?;
        let cef_correction_bits =
            self.start_preprocessing_cef_correction_bits_vec::<P>(config, statement, broadcasts)?;
        let bcc_violation_bits =
            self.start_preprocessing_bcc_violation_bits_vec::<P>(config, statement, broadcasts)?;
        let input = PreprocessingRuntimePrivateMpcStateInput::new::<P>(
            statement,
            relation_bits,
            rho_sum_bits_by_bit_le,
            cef_correction_bits,
            bcc_violation_bits,
        )?;
        self.derive_private_material_state_from_runtime_private_mpc::<P>(
            config, statement, broadcasts, input,
        )
    }

    /// Starts the runtime-owned private preprocessing certification circuits.
    ///
    /// `carry_bits_by_bit_le` are the secret bits for the CarryCompare input
    /// and `carry_thresholds` are the public lane thresholds. `cef_bcc_bits`
    /// are the private predicate/input bits consumed by the CEF/BCC threshold
    /// circuit. The returned state must be driven and collected to completion
    /// before `finish_private_circuit_handles` can produce certification
    /// handles.
    fn start_private_circuit_handles<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        statement: &PreprocessingCertificationRuntimeStatement,
        masked_broadcast_relation_bits: &[ProductionBitShareVec],
        carry_bits_by_bit_le: &[ProductionBitShareVec],
        carry_thresholds: &[Coeff],
        cef_correction_bits: &[ProductionBitShareVec],
        bcc_violation_bits: &[ProductionBitShareVec],
    ) -> Result<PreprocessingPrivateCircuitDriverState, PreprocessError> {
        if carry_thresholds.len() != statement.coeff_count {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        for bit in masked_broadcast_relation_bits
            .iter()
            .chain(carry_bits_by_bit_le.iter())
            .chain(cef_correction_bits.iter())
            .chain(bcc_violation_bits.iter())
        {
            if bit.len() != statement.coeff_count {
                return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
            }
        }
        let root = preprocessing_certification_runtime_label(statement);
        let masked_broadcast = self
            .runtime
            .start_preprocessing_masked_broadcast_bit_sum_leq_public_vec::<P>(
                config,
                masked_broadcast_relation_bits,
                0,
                &root
                    .child("masked_broadcast_private")
                    .child("relation_sum_leq"),
            )
            .map_err(map_preprocessing_runtime_dkg_error)?;
        let carry_compare = self
            .runtime
            .start_preprocessing_carry_compare_gt_public_lanes_vec::<P>(
                config,
                carry_bits_by_bit_le,
                carry_thresholds,
                &root.child("carry_compare_private").child("rho_gt_t"),
            )
            .map_err(map_preprocessing_runtime_dkg_error)?;
        let cef_correction = if cef_correction_bits.is_empty() {
            None
        } else {
            Some(
                self.runtime
                    .start_preprocessing_cef_bcc_bit_sum_leq_public_vec::<P>(
                        config,
                        cef_correction_bits,
                        cef_correction_bits.len() as u32,
                        &root
                            .child("cef_bcc_private")
                            .child("cef_correction_sum_leq"),
                    )
                    .map_err(map_preprocessing_runtime_dkg_error)?,
            )
        };
        let bcc = self
            .runtime
            .start_preprocessing_cef_bcc_bit_sum_leq_public_vec::<P>(
                config,
                bcc_violation_bits,
                0,
                &root.child("cef_bcc_private").child("bcc_sum_leq"),
            )
            .map_err(map_preprocessing_runtime_dkg_error)?;
        Ok(PreprocessingPrivateCircuitDriverState {
            masked_broadcast,
            carry_compare,
            cef_correction,
            bcc,
            material_state_hash: [0u8; 32],
        })
    }

    /// Starts private preprocessing circuits from the public opened
    /// masked-broadcast material and runtime-owned private material handles.
    ///
    /// This is the production-shaped entry point for preprocessing
    /// certification. The public CarryCompare thresholds are derived from the
    /// opened masked-low sums, and BCC admission is expressed as
    /// `sum(private_bcc_violation_bits) <= 0`. The private material bundle is
    /// already validated against the statement-derived transcript labels.
    fn start_private_circuit_handles_from_preprocessing_material<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        statement: &PreprocessingCertificationRuntimeStatement,
        broadcasts: &[MaskedBroadcast],
        private_material: &PreprocessingPrivateMaterialHandles,
    ) -> Result<PreprocessingPrivateCircuitDriverState, PreprocessError> {
        let (carry_public, cef_bcc_public) = preprocessing_public_circuit_input_hashes::<P>(
            statement.session_id,
            statement.transcript_hash,
            &statement.signer_set,
            broadcasts,
        )?;
        if carry_public != statement.carry_compare_public_input_hash
            || cef_bcc_public != statement.cef_bcc_public_input_hash
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let carry_thresholds =
            preprocessing_carry_thresholds_from_broadcasts::<P>(statement, broadcasts)?;
        self.start_private_circuit_handles::<P>(
            config,
            statement,
            private_material.masked_broadcast_relation_bits(),
            private_material.rho_sum_bits_by_bit_le(),
            &carry_thresholds,
            private_material.cef_correction_bits(),
            private_material.bcc_violation_bits(),
        )
    }

    /// Starts private preprocessing circuits from runtime-owned private
    /// material state.
    pub fn start_private_circuit_handles_from_state<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        statement: &PreprocessingCertificationRuntimeStatement,
        broadcasts: &[MaskedBroadcast],
        state: &PreprocessingPrivateMaterialState,
    ) -> Result<PreprocessingPrivateCircuitDriverState, PreprocessError> {
        state.ensure_allowed_for_release()?;
        state.ensure_matches(statement, broadcasts)?;
        let mut driver = self.start_private_circuit_handles_from_preprocessing_material::<P>(
            config,
            statement,
            broadcasts,
            state.material(),
        )?;
        driver.material_state_hash = hash_preprocessing_private_material_state(state);
        Ok(driver)
    }

    /// Opens release envelopes, derives their runtime statement, constructs
    /// adapter-owned runtime-private material state, and starts the private
    /// preprocessing circuits.
    ///
    /// This is the normal entry point before driving
    /// `drive_private_circuit_handles_step` / `collect_private_circuit_handles_step`.
    /// After the returned state is done, callers finish it into
    /// `PreprocessingPrivateCircuitHandles` and attach those handles before
    /// calling `certify_preprocessing_token_release_validated_with_runtime`.
    pub fn start_private_circuit_handles_from_envelopes<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        session_id: SessionId,
        inputs: Vec<PartyPreprocessInput>,
        envelopes: Vec<BroadcastEnvelope>,
        expected_transcript: TranscriptHash,
    ) -> Result<
        (
            PreprocessingCertificationRuntimeStatement,
            Vec<MaskedBroadcast>,
            PreprocessingPrivateCircuitDriverState,
        ),
        PreprocessError,
    > {
        let broadcasts = open_broadcasts(session_id, &envelopes, expected_transcript)?;
        let statement = preprocessing_certification_runtime_statement_from_envelopes::<P>(
            session_id,
            inputs,
            envelopes,
            expected_transcript,
        )?;
        let private_material_state = self
            .derive_private_material_state_from_runtime_private_mpc_handles::<P>(
                config,
                &statement,
                &broadcasts,
            )?;
        let state = self.start_private_circuit_handles_from_state::<P>(
            config,
            &statement,
            &broadcasts,
            &private_material_state,
        )?;
        Ok((statement, broadcasts, state))
    }

    /// Starts one fused private CarryCompare/CEF/BCC runtime circuit for a
    /// batch of preprocessing token statements.
    ///
    /// This concatenates the runtime-owned private material and public
    /// thresholds for every member into one larger vector circuit. No private
    /// relation bits, rho bits, CEF bits, or BCC bits are opened.
    pub fn start_private_circuit_batch_from_envelopes<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        items: Vec<(
            SessionId,
            Vec<PartyPreprocessInput>,
            Vec<BroadcastEnvelope>,
            TranscriptHash,
        )>,
    ) -> Result<PreprocessingPrivateCircuitBatchDriverState, PreprocessError> {
        if items.is_empty() {
            return Err(PreprocessError::EmptySignerSet);
        }
        let mut statements = Vec::with_capacity(items.len());
        let mut broadcasts_by_member = Vec::with_capacity(items.len());
        let mut materials = Vec::with_capacity(items.len());
        let mut thresholds_by_member = Vec::with_capacity(items.len());
        for (session_id, inputs, envelopes, transcript) in items {
            let broadcasts = open_broadcasts(session_id, &envelopes, transcript)?;
            let statement = preprocessing_certification_runtime_statement_from_envelopes::<P>(
                session_id, inputs, envelopes, transcript,
            )?;
            let material = self.derive_private_material_handles_from_opened_preprocessing::<P>(
                config,
                &statement,
                &broadcasts,
            )?;
            let thresholds =
                preprocessing_carry_thresholds_from_broadcasts::<P>(&statement, &broadcasts)?;
            statements.push(statement);
            broadcasts_by_member.push(broadcasts);
            materials.push(material);
            thresholds_by_member.push(thresholds);
        }
        let batch_statement = preprocessing_private_circuit_batch_statement(&statements)?;
        let root = preprocessing_certification_runtime_label(&batch_statement)
            .child("fused_private_circuit");

        let relation_len = materials
            .first()
            .ok_or(PreprocessError::EmptySignerSet)?
            .masked_broadcast_relation_bits()
            .len();
        let carry_len = materials
            .first()
            .ok_or(PreprocessError::EmptySignerSet)?
            .rho_sum_bits_by_bit_le()
            .len();
        let cef_len = materials
            .first()
            .ok_or(PreprocessError::EmptySignerSet)?
            .cef_correction_bits()
            .len();
        let bcc_len = materials
            .first()
            .ok_or(PreprocessError::EmptySignerSet)?
            .bcc_violation_bits()
            .len();

        let concat_bits = |runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
                           groups: Vec<Vec<ProductionBitShareVec>>,
                           child: &str|
         -> Result<Vec<ProductionBitShareVec>, PreprocessError> {
            if groups.is_empty() {
                return Err(PreprocessError::EmptySignerSet);
            }
            let width = groups[0].len();
            if groups.iter().any(|group| group.len() != width) {
                return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
            }
            (0..width)
                .map(|idx| {
                    let refs = groups
                        .iter()
                        .map(|group| group[idx].clone())
                        .collect::<Vec<_>>();
                    runtime
                        .concat_bit_share_vecs_for_runtime_batch::<P>(
                            config,
                            &refs,
                            &root.child(child).child(format!("bit_group_{idx}")),
                        )
                        .map_err(map_preprocessing_runtime_dkg_error)
                })
                .collect()
        };

        let masked_broadcast_relation_bits = concat_bits(
            self.runtime,
            materials
                .iter()
                .map(|material| material.masked_broadcast_relation_bits().to_vec())
                .collect(),
            "masked_broadcast_relation",
        )?;
        if masked_broadcast_relation_bits.len() != relation_len {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let rho_sum_bits_by_bit_le = concat_bits(
            self.runtime,
            materials
                .iter()
                .map(|material| material.rho_sum_bits_by_bit_le().to_vec())
                .collect(),
            "carry_compare_rho_bits",
        )?;
        if rho_sum_bits_by_bit_le.len() != carry_len {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let cef_correction_bits = concat_bits(
            self.runtime,
            materials
                .iter()
                .map(|material| material.cef_correction_bits().to_vec())
                .collect(),
            "cef_correction_bits",
        )?;
        if cef_correction_bits.len() != cef_len {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let bcc_violation_bits = concat_bits(
            self.runtime,
            materials
                .iter()
                .map(|material| material.bcc_violation_bits().to_vec())
                .collect(),
            "bcc_violation_bits",
        )?;
        if bcc_violation_bits.len() != bcc_len {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let carry_thresholds = thresholds_by_member
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let mut state = self.start_private_circuit_handles::<P>(
            config,
            &batch_statement,
            &masked_broadcast_relation_bits,
            &rho_sum_bits_by_bit_le,
            &carry_thresholds,
            &cef_correction_bits,
            &bcc_violation_bits,
        )?;
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS fused preprocessing private material state v1");
        for statement in &statements {
            hasher.update(hash_preprocessing_runtime_statement(statement));
        }
        state.material_state_hash = hasher.finalize().into();
        let members = statements
            .iter()
            .map(|statement| PreprocessingPrivateCircuitBatchMember {
                session_id: statement.session_id,
                transcript_hash: statement.transcript_hash,
                coeff_count: statement.coeff_count,
            })
            .collect::<Vec<_>>();
        let _ = broadcasts_by_member;
        Ok(PreprocessingPrivateCircuitBatchDriverState {
            members,
            batch_statement,
            state,
        })
    }

    /// Drives the next fused private preprocessing batch circuit phase.
    pub fn drive_private_circuit_batch_step<P, E>(
        &mut self,
        config: &DkgConfig,
        state: &mut PreprocessingPrivateCircuitBatchDriverState,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, PreprocessError>
    where
        P: MlDsaParams,
        E: ProductionVectorItMpcEntropy,
    {
        self.drive_private_circuit_handles_step::<P, E>(config, &mut state.state, entropy)
    }

    /// Collects the pending fused private preprocessing batch circuit phase.
    pub fn collect_private_circuit_batch_step<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        state: &mut PreprocessingPrivateCircuitBatchDriverState,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, PreprocessError> {
        self.collect_private_circuit_handles_step::<P>(config, &mut state.state)
    }

    /// Produces token-specific release runtime proofs from one completed fused
    /// private preprocessing batch circuit.
    pub fn certify_preprocessing_from_fused_private_batch_state<P: MlDsaParams>(
        &self,
        statement: &PreprocessingCertificationRuntimeStatement,
        batch_state: &PreprocessingPrivateCircuitBatchDriverState,
    ) -> Result<
        (
            PreprocessingCertificationRuntimeProofs,
            ProductionVectorItMpcRuntimeEvidence,
        ),
        PreprocessError,
    > {
        if !batch_state.is_done()
            || batch_state.members.iter().all(|member| {
                member.session_id != statement.session_id
                    || member.transcript_hash != statement.transcript_hash
                    || member.coeff_count != statement.coeff_count
            })
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let initial_evidence = self
            .runtime
            .runtime_evidence()
            .map_err(map_preprocessing_runtime_dkg_error)?;
        ensure_preprocessing_vector_runtime_evidence_for_release(&initial_evidence)?;
        ensure_preprocessing_statement_public_input_hashes(statement)?;
        ensure_preprocessing_statement_private_label_hashes(statement)?;

        let raw_runtime_transcript = initial_evidence.transcript_hash;
        validate_masked_broadcast_bindings_for_vector_runtime::<P>(
            statement,
            raw_runtime_transcript,
        )?;
        let carry_runtime_transcript =
            preprocessing_stage_runtime_transcript_hash_from_vector_runtime_evidence(
                PreprocessingCertificationStage::CarryCompare,
                statement,
                raw_runtime_transcript,
            );
        let bcc_runtime_transcript =
            preprocessing_stage_runtime_transcript_hash_from_vector_runtime_evidence(
                PreprocessingCertificationStage::Bcc,
                statement,
                raw_runtime_transcript,
            );
        if carry_runtime_transcript == [0u8; 32] || bcc_runtime_transcript == [0u8; 32] {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let material_state_hash = batch_state.state.material_state_hash;
        if material_state_hash == [0u8; 32] {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let proofs = PreprocessingCertificationRuntimeProofs {
            masked_broadcast: statement.masked_broadcast_runtime_transcript,
            carry_compare: preprocessing_certification_stage_runtime_proof_inner::<P>(
                PreprocessingCertificationStage::CarryCompare,
                statement.session_id,
                statement.transcript_hash,
                statement.signer_set.len(),
                statement.coeff_count,
                statement.carry_compare_evidence_hash,
                carry_runtime_transcript,
            )?,
            bcc: preprocessing_certification_stage_runtime_proof_inner::<P>(
                PreprocessingCertificationStage::Bcc,
                statement.session_id,
                statement.transcript_hash,
                statement.signer_set.len(),
                statement.coeff_count,
                statement.bcc_evidence_hash,
                bcc_runtime_transcript,
            )?,
            outputs: PreprocessingCertificationRuntimeOutputs {
                masked_broadcast: RuntimeMaskedBroadcastOutput {
                    signer_count: statement.signer_set.len(),
                    coeff_count: statement.coeff_count,
                    runtime_transcript_hash: statement.masked_broadcast_runtime_transcript,
                    material_state_hash,
                },
                carry_compare: RuntimeCarryCompareOutput {
                    coeff_count: statement.coeff_count,
                    evidence_hash: statement.carry_compare_evidence_hash,
                    runtime_transcript_hash: carry_runtime_transcript,
                },
                cef_bcc: RuntimeCefBccOutput {
                    coeff_count: statement.coeff_count,
                    w1_hash: statement.w1_hash,
                    carry_compare_evidence_hash: statement.carry_compare_evidence_hash,
                    bcc_evidence_hash: statement.bcc_evidence_hash,
                    runtime_transcript_hash: bcc_runtime_transcript,
                    token_admitted: true,
                },
            },
        };
        proofs.transcripts()?;
        let mut evidence = initial_evidence;
        evidence.transcript_hash = preprocessing_runtime_transcript_aggregate_hash(
            statement.session_id,
            statement.transcript_hash,
            proofs.transcripts()?,
        )?;
        Ok((proofs, evidence))
    }

    /// Drives the next app-transport round for the private preprocessing
    /// circuits.
    pub fn drive_private_circuit_handles_step<P, E>(
        &mut self,
        config: &DkgConfig,
        state: &mut PreprocessingPrivateCircuitDriverState,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, PreprocessError>
    where
        P: MlDsaParams,
        E: ProductionVectorItMpcEntropy,
    {
        if !state.masked_broadcast.is_done() {
            return self
                .runtime
                .drive_bit_sum_leq_public_vec_step::<P, E>(
                    config,
                    &mut state.masked_broadcast,
                    entropy,
                )
                .map_err(map_preprocessing_runtime_dkg_error);
        }
        if !state.carry_compare.is_done() {
            return self
                .runtime
                .drive_public_comparison_vec_step::<P, E>(config, &mut state.carry_compare, entropy)
                .map_err(map_preprocessing_runtime_dkg_error);
        }
        if let Some(cef_correction) = state.cef_correction.as_mut() {
            if !cef_correction.is_done() {
                return self
                    .runtime
                    .drive_bit_sum_leq_public_vec_step::<P, E>(config, cef_correction, entropy)
                    .map_err(map_preprocessing_runtime_dkg_error);
            }
        }
        self.runtime
            .drive_bit_sum_leq_public_vec_step::<P, E>(config, &mut state.bcc, entropy)
            .map_err(map_preprocessing_runtime_dkg_error)
    }

    /// Collects the pending app-transport round for the private preprocessing
    /// circuits.
    pub fn collect_private_circuit_handles_step<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        state: &mut PreprocessingPrivateCircuitDriverState,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, PreprocessError> {
        if !state.masked_broadcast.is_done() {
            return self
                .runtime
                .collect_bit_sum_leq_public_vec_step::<P>(config, &mut state.masked_broadcast)
                .map(|result| match result {
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        ProductionVectorItMpcCollectResult::Waiting(status)
                    }
                    ProductionVectorItMpcCollectResult::Collected { status, .. } => {
                        ProductionVectorItMpcCollectResult::Collected { status, value: () }
                    }
                })
                .map_err(map_preprocessing_runtime_dkg_error);
        }
        if !state.carry_compare.is_done() {
            return self
                .runtime
                .collect_public_comparison_vec_step::<P>(config, &mut state.carry_compare)
                .map(|result| match result {
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        ProductionVectorItMpcCollectResult::Waiting(status)
                    }
                    ProductionVectorItMpcCollectResult::Collected { status, .. } => {
                        ProductionVectorItMpcCollectResult::Collected { status, value: () }
                    }
                })
                .map_err(map_preprocessing_runtime_dkg_error);
        }
        if let Some(cef_correction) = state.cef_correction.as_mut() {
            if !cef_correction.is_done() {
                return self
                    .runtime
                    .collect_bit_sum_leq_public_vec_step::<P>(config, cef_correction)
                    .map(|result| match result {
                        ProductionVectorItMpcCollectResult::Waiting(status) => {
                            ProductionVectorItMpcCollectResult::Waiting(status)
                        }
                        ProductionVectorItMpcCollectResult::Collected { status, .. } => {
                            ProductionVectorItMpcCollectResult::Collected { status, value: () }
                        }
                    })
                    .map_err(map_preprocessing_runtime_dkg_error);
            }
        }
        self.runtime
            .collect_bit_sum_leq_public_vec_step::<P>(config, &mut state.bcc)
            .map(|result| match result {
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    ProductionVectorItMpcCollectResult::Waiting(status)
                }
                ProductionVectorItMpcCollectResult::Collected { status, .. } => {
                    ProductionVectorItMpcCollectResult::Collected { status, value: () }
                }
            })
            .map_err(map_preprocessing_runtime_dkg_error)
    }

    /// Finishes completed private preprocessing circuits into the handle bundle
    /// required by release certification.
    pub fn finish_private_circuit_handles(
        &self,
        state: &PreprocessingPrivateCircuitDriverState,
    ) -> Result<PreprocessingPrivateCircuitHandles, PreprocessError> {
        if state.material_state_hash == [0u8; 32] {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let masked_broadcast = state
            .masked_broadcast
            .result()
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?
            .clone();
        if masked_broadcast.len() == 0 {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let carry = state
            .carry_compare
            .result()
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?
            .clone();
        let cef_correction = state
            .cef_correction
            .as_ref()
            .and_then(|state| state.result().cloned())
            .into_iter()
            .collect::<Vec<_>>();
        let bcc = state
            .bcc
            .result()
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?
            .clone();
        PreprocessingPrivateCircuitHandles::from_preprocessing_bits(
            vec![carry],
            cef_correction,
            vec![bcc],
        )
    }

    /// Finishes the runtime-owned masked-broadcast output from the
    /// statement-bound runtime-private material state.
    ///
    /// This binds masked-broadcast certification to the same private material
    /// state that feeds CarryCompare and CEF/BCC. It does not expose relation
    /// bits or per-party failure information.
    pub fn finish_runtime_masked_broadcast_output<P: MlDsaParams>(
        &self,
        statement: &PreprocessingCertificationRuntimeStatement,
        state: &PreprocessingPrivateCircuitDriverState,
    ) -> Result<RuntimeMaskedBroadcastOutput, PreprocessError> {
        let _ = core::marker::PhantomData::<P>;
        if state.material_state_hash == [0u8; 32]
            || statement.masked_broadcast_runtime_transcript == [0u8; 32]
            || statement.signer_set.is_empty()
            || statement.coeff_count == 0
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let relation_ok = state
            .masked_broadcast
            .result()
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        if relation_ok.len() != statement.coeff_count {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let evidence = self
            .runtime
            .runtime_evidence()
            .map_err(map_preprocessing_runtime_dkg_error)?;
        validate_masked_broadcast_bindings_for_vector_runtime::<P>(
            statement,
            evidence.transcript_hash,
        )?;
        Ok(RuntimeMaskedBroadcastOutput {
            signer_count: statement.signer_set.len(),
            coeff_count: statement.coeff_count,
            runtime_transcript_hash: statement.masked_broadcast_runtime_transcript,
            material_state_hash: state.material_state_hash,
        })
    }

    /// Finishes the runtime-owned CarryCompare output from a completed private
    /// preprocessing driver state.
    ///
    /// This binds the public CarryCompare output object to an actually
    /// completed preprocessing-tagged comparison circuit and the durable vector
    /// runtime transcript. It does not expose the private carry bits.
    pub fn finish_runtime_carry_compare_output<P: MlDsaParams>(
        &self,
        statement: &PreprocessingCertificationRuntimeStatement,
        state: &PreprocessingPrivateCircuitDriverState,
    ) -> Result<RuntimeCarryCompareOutput, PreprocessError> {
        if state.material_state_hash == [0u8; 32] {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let carry = state
            .carry_compare
            .result()
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        if carry.len() != statement.coeff_count {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let private_handle_hash = hash_preprocessing_private_bit_handles(
            b"runtime-carry-compare-output",
            statement,
            core::slice::from_ref(carry),
        )?;
        if private_handle_hash == [0u8; 32] {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let evidence = self
            .runtime
            .runtime_evidence()
            .map_err(map_preprocessing_runtime_dkg_error)?;
        let runtime_transcript_hash =
            preprocessing_stage_runtime_transcript_hash_from_vector_runtime_evidence(
                PreprocessingCertificationStage::CarryCompare,
                statement,
                evidence.transcript_hash,
            );
        if runtime_transcript_hash == [0u8; 32] {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        Ok(RuntimeCarryCompareOutput {
            coeff_count: statement.coeff_count,
            evidence_hash: statement.carry_compare_evidence_hash,
            runtime_transcript_hash,
        })
    }

    /// Finishes the runtime-owned CEF/BCC output from a completed private
    /// preprocessing driver state.
    ///
    /// This binds the public CEF/BCC output object to an actually completed
    /// preprocessing-tagged threshold circuit and the durable vector runtime
    /// transcript. It does not open the private BCC predicate bits.
    pub fn finish_runtime_cef_bcc_output<P: MlDsaParams>(
        &self,
        statement: &PreprocessingCertificationRuntimeStatement,
        state: &PreprocessingPrivateCircuitDriverState,
        carry_output: RuntimeCarryCompareOutput,
    ) -> Result<RuntimeCefBccOutput, PreprocessError> {
        if state.material_state_hash == [0u8; 32] {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        if carry_output.coeff_count != statement.coeff_count
            || carry_output.evidence_hash != statement.carry_compare_evidence_hash
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let cef_correction = state
            .cef_correction
            .as_ref()
            .and_then(|state| state.result())
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        let bcc = state
            .bcc
            .result()
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        if cef_correction.len() != statement.coeff_count || bcc.len() != statement.coeff_count {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let cef_private_handle_hash = hash_preprocessing_private_bit_handles(
            b"runtime-cef-correction-output",
            statement,
            core::slice::from_ref(cef_correction),
        )?;
        let bcc_private_handle_hash = hash_preprocessing_private_bit_handles(
            b"runtime-cef-bcc-output",
            statement,
            core::slice::from_ref(bcc),
        )?;
        if cef_private_handle_hash == [0u8; 32] || bcc_private_handle_hash == [0u8; 32] {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let evidence = self
            .runtime
            .runtime_evidence()
            .map_err(map_preprocessing_runtime_dkg_error)?;
        let runtime_transcript_hash =
            preprocessing_stage_runtime_transcript_hash_from_vector_runtime_evidence(
                PreprocessingCertificationStage::Bcc,
                statement,
                evidence.transcript_hash,
            );
        if runtime_transcript_hash == [0u8; 32] {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        Ok(RuntimeCefBccOutput {
            coeff_count: statement.coeff_count,
            w1_hash: statement.w1_hash,
            carry_compare_evidence_hash: carry_output.evidence_hash,
            bcc_evidence_hash: statement.bcc_evidence_hash,
            runtime_transcript_hash,
            token_admitted: true,
        })
    }

    /// Finishes state-owned private preprocessing circuits and attaches their
    /// handles to this runtime adapter for release token certification.
    pub fn finish_and_attach_private_circuit_state(
        &mut self,
        state: &PreprocessingPrivateCircuitDriverState,
    ) -> Result<(), PreprocessError> {
        let handles = self.finish_private_circuit_handles(state)?;
        self.private_handles = Some(handles);
        self.runtime_masked_broadcast_output = None;
        self.runtime_carry_compare_output = None;
        self.runtime_cef_bcc_output = None;
        Ok(())
    }

    /// Finishes state-owned private preprocessing circuits, stores the
    /// runtime-owned CarryCompare output, and attaches completed private
    /// handles for release token certification.
    pub fn finish_and_attach_private_circuit_state_for_statement<P: MlDsaParams>(
        &mut self,
        statement: &PreprocessingCertificationRuntimeStatement,
        state: &PreprocessingPrivateCircuitDriverState,
    ) -> Result<(), PreprocessError> {
        let masked_broadcast_output =
            self.finish_runtime_masked_broadcast_output::<P>(statement, state)?;
        let carry_output = self.finish_runtime_carry_compare_output::<P>(statement, state)?;
        let cef_bcc_output =
            self.finish_runtime_cef_bcc_output::<P>(statement, state, carry_output)?;
        let handles = self.finish_private_circuit_handles(state)?;
        self.private_handles = Some(handles);
        self.runtime_masked_broadcast_output = Some(masked_broadcast_output);
        self.runtime_carry_compare_output = Some(carry_output);
        self.runtime_cef_bcc_output = Some(cef_bcc_output);
        Ok(())
    }
}

impl<T, L, C> PreprocessingCertificationRuntime
    for ProductionPreprocessingCertificationRuntime<'_, T, L, C>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    fn certify_preprocessing<P: MlDsaParams>(
        &mut self,
        statement: &PreprocessingCertificationRuntimeStatement,
    ) -> Result<
        (
            PreprocessingCertificationRuntimeProofs,
            ProductionVectorItMpcRuntimeEvidence,
        ),
        PreprocessError,
    > {
        let initial_evidence = self
            .runtime
            .runtime_evidence()
            .map_err(map_preprocessing_runtime_dkg_error)?;
        ensure_preprocessing_vector_runtime_evidence_for_release(&initial_evidence)?;
        ensure_preprocessing_statement_public_input_hashes(statement)?;
        ensure_preprocessing_statement_private_label_hashes(statement)?;
        let private_inputs = self
            .private_handles
            .as_ref()
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?
            .bind_to_statement(statement)?;
        ensure_preprocessing_private_circuit_inputs_match_statement(statement, &private_inputs)?;
        let (carry_private_mul_labels, cef_bcc_private_mul_labels) =
            preprocessing_statement_private_circuit_mul_labels::<P>(statement);
        ensure_preprocessing_wire_log_private_circuits_for_release(
            self.runtime.inner().runtime().wire_log(),
            &carry_private_mul_labels,
            &cef_bcc_private_mul_labels,
        )
        .map_err(map_preprocessing_runtime_dkg_error)?;
        let mut evidence = self
            .runtime
            .runtime_evidence()
            .map_err(map_preprocessing_runtime_dkg_error)?;
        let raw_runtime_transcript = evidence.transcript_hash;

        validate_masked_broadcast_bindings_for_vector_runtime::<P>(
            statement,
            raw_runtime_transcript,
        )?;
        let masked_broadcast_output = self
            .runtime_masked_broadcast_output
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        if masked_broadcast_output.signer_count != statement.signer_set.len()
            || masked_broadcast_output.coeff_count != statement.coeff_count
            || masked_broadcast_output.runtime_transcript_hash
                != statement.masked_broadcast_runtime_transcript
            || masked_broadcast_output.material_state_hash == [0u8; 32]
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }

        let carry_runtime_transcript =
            preprocessing_stage_runtime_transcript_hash_from_vector_runtime_evidence(
                PreprocessingCertificationStage::CarryCompare,
                statement,
                raw_runtime_transcript,
            );
        let carry_compare_output = self
            .runtime_carry_compare_output
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        if carry_compare_output.coeff_count != statement.coeff_count
            || carry_compare_output.evidence_hash != statement.carry_compare_evidence_hash
            || carry_compare_output.runtime_transcript_hash != carry_runtime_transcript
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let bcc_runtime_transcript =
            preprocessing_stage_runtime_transcript_hash_from_vector_runtime_evidence(
                PreprocessingCertificationStage::Bcc,
                statement,
                raw_runtime_transcript,
            );
        let cef_bcc_output = self
            .runtime_cef_bcc_output
            .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        if cef_bcc_output.coeff_count != statement.coeff_count
            || cef_bcc_output.w1_hash != statement.w1_hash
            || cef_bcc_output.carry_compare_evidence_hash != statement.carry_compare_evidence_hash
            || cef_bcc_output.bcc_evidence_hash != statement.bcc_evidence_hash
            || cef_bcc_output.runtime_transcript_hash != bcc_runtime_transcript
            || !cef_bcc_output.token_admitted
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }

        let proofs = PreprocessingCertificationRuntimeProofs {
            masked_broadcast: statement.masked_broadcast_runtime_transcript,
            carry_compare: preprocessing_certification_stage_runtime_proof_inner::<P>(
                PreprocessingCertificationStage::CarryCompare,
                statement.session_id,
                statement.transcript_hash,
                statement.signer_set.len(),
                statement.coeff_count,
                statement.carry_compare_evidence_hash,
                carry_runtime_transcript,
            )?,
            bcc: preprocessing_certification_stage_runtime_proof_inner::<P>(
                PreprocessingCertificationStage::Bcc,
                statement.session_id,
                statement.transcript_hash,
                statement.signer_set.len(),
                statement.coeff_count,
                statement.bcc_evidence_hash,
                bcc_runtime_transcript,
            )?,
            outputs: PreprocessingCertificationRuntimeOutputs {
                masked_broadcast: masked_broadcast_output,
                carry_compare: carry_compare_output,
                cef_bcc: cef_bcc_output,
            },
        };

        evidence.transcript_hash = preprocessing_runtime_transcript_aggregate_hash(
            statement.session_id,
            statement.transcript_hash,
            proofs.transcripts()?,
        )?;
        Ok((proofs, evidence))
    }
}

const PREPROCESSING_STAGE_RUNTIME_PROOF_PREFIX: &[u8; 6] = b"TPRSR1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreprocessingStageRuntimeProofParts {
    stage: PreprocessingCertificationStage,
    statement_hash: [u8; 32],
    runtime_transcript_hash: [u8; 32],
    coeff_count: usize,
    signer_count: usize,
}

/// Aggregates the three preprocessing certification runtime transcript hashes
/// into the transcript hash expected by release-capable preprocessing runtime
/// evidence.
pub fn preprocessing_runtime_transcript_aggregate_hash(
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    transcripts: PreprocessingCertificationRuntimeTranscripts,
) -> Result<[u8; 32], PreprocessError> {
    if !transcripts.is_complete() {
        return Err(PreprocessError::PreChallengeCertificationIncomplete);
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing aggregate runtime transcript v1");
    hasher.update(session_id.0);
    hasher.update(transcript_hash.0);
    hasher.update(transcripts.masked_broadcast);
    hasher.update(transcripts.carry_compare);
    hasher.update(transcripts.bcc);
    Ok(hasher.finalize().into())
}

/// Encodes a typed private-runtime proof for one preprocessing certification
/// stage.
#[cfg(test)]
pub fn preprocessing_certification_stage_runtime_proof<P: MlDsaParams>(
    stage: PreprocessingCertificationStage,
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_count: usize,
    coeff_count: usize,
    evidence_hash: [u8; 32],
    runtime_transcript_hash: [u8; 32],
) -> Result<PreprocessingCertificationStageRuntimeProof, PreprocessError> {
    preprocessing_certification_stage_runtime_proof_inner::<P>(
        stage,
        session_id,
        transcript_hash,
        signer_count,
        coeff_count,
        evidence_hash,
        runtime_transcript_hash,
    )
}

#[allow(dead_code)]
fn preprocessing_certification_stage_runtime_proof_inner<P: MlDsaParams>(
    stage: PreprocessingCertificationStage,
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_count: usize,
    coeff_count: usize,
    evidence_hash: [u8; 32],
    runtime_transcript_hash: [u8; 32],
) -> Result<PreprocessingCertificationStageRuntimeProof, PreprocessError> {
    if runtime_transcript_hash == [0u8; 32] {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    let parts = expected_preprocessing_stage_runtime_proof_parts::<P>(
        stage,
        session_id,
        transcript_hash,
        signer_count,
        coeff_count,
        evidence_hash,
        runtime_transcript_hash,
    );
    let mut bytes = Vec::with_capacity(6 + 1 + 32 + 32 + 4 + 4);
    bytes.extend_from_slice(PREPROCESSING_STAGE_RUNTIME_PROOF_PREFIX);
    bytes.push(parts.stage.code());
    bytes.extend_from_slice(&parts.statement_hash);
    bytes.extend_from_slice(&parts.runtime_transcript_hash);
    bytes.extend_from_slice(&(parts.coeff_count as u32).to_le_bytes());
    bytes.extend_from_slice(&(parts.signer_count as u32).to_le_bytes());
    Ok(PreprocessingCertificationStageRuntimeProof { bytes })
}

/// Public statement checked before a masked broadcast can certify a token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskedBroadcastConsistencyStatement {
    /// Preprocessing session identifier.
    pub session_id: SessionId,
    /// Sorted signer set.
    pub signer_set: Vec<PartyId>,
    /// Claimed opened broadcast.
    pub broadcast: MaskedBroadcast,
    /// Expected number of coefficients.
    pub coeff_count: usize,
}

/// Verifies the consistency of an opened masked broadcast before token admission.
pub trait MaskedBroadcastConsistencyVerifier {
    /// Returns whether this verifier consumes clear audit witnesses.
    ///
    /// Production verifiers must return false and validate only public
    /// statements plus transcript-bound private-certification artifacts.
    #[cfg(any(test, feature = "paper-fast-dev"))]
    fn requires_clear_audit(&self) -> bool {
        false
    }

    /// Verifies one opened masked-broadcast statement.
    fn verify_masked_broadcast<P: MlDsaParams>(
        &mut self,
        statement: &MaskedBroadcastConsistencyStatement,
        proof: &MaskedBroadcastConsistencyProof,
        #[cfg(any(test, feature = "paper-fast-dev"))] clear_audit: Option<
            &MaskedBroadcastClearAudit,
        >,
    ) -> Result<(), PreprocessError>;
}

/// Production masked-broadcast consistency verifier.
///
/// This verifier does not consume public clear-audit openings. It validates a
/// transcript-bound private-certification artifact over the opened masked
/// broadcast and checks that the masked values decode to a well-formed
/// preprocessing contribution under the session's committed mask seeds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProductMaskedBroadcastConsistencyVerifier;

impl MaskedBroadcastConsistencyVerifier for ProductMaskedBroadcastConsistencyVerifier {
    fn verify_masked_broadcast<P: MlDsaParams>(
        &mut self,
        statement: &MaskedBroadcastConsistencyStatement,
        proof: &MaskedBroadcastConsistencyProof,
        #[cfg(any(test, feature = "paper-fast-dev"))] clear_audit: Option<
            &MaskedBroadcastClearAudit,
        >,
    ) -> Result<(), PreprocessError> {
        #[cfg(any(test, feature = "paper-fast-dev"))]
        if clear_audit.is_some() {
            return Err(PreprocessError::MaskedBroadcastAuditRequired(
                statement.broadcast.party,
            ));
        }
        verify_private_certified_masked_broadcast::<P>(statement, proof)
    }
}

/// Backward-compatible name for the production masked-broadcast verifier.
pub type ProductZkMaskedBroadcastVerifier = ProductMaskedBroadcastConsistencyVerifier;

/// Product policy checks required before a preprocessing token may enter the
/// online signing pool.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PreChallengeCertificationPolicy {
    /// Masked broadcasts were certified before the ML-DSA challenge exists.
    pub masked_broadcast_consistency: bool,
    /// CarryCompare outputs were privately certified before token admission.
    pub carry_compare_certified: bool,
    /// Boundary-clearance condition was certified before token admission.
    pub bcc_certified: bool,
    /// Session/token persistence prevents reuse across restart.
    pub persistent_session_store: bool,
    /// Post-challenge reveal-on-failure is disabled for the production path.
    pub no_post_challenge_nonce_reveal: bool,
}

/// Public evidence that masked broadcasts were checked before challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaskedBroadcastCertificationEvidence {
    /// Session id certified by this evidence.
    pub session_id: SessionId,
    /// Transcript hash of the opened masked broadcasts.
    pub transcript_hash: TranscriptHash,
    /// Number of signers included in the certified set.
    pub signer_count: usize,
    /// Number of coefficients certified per signer.
    pub coeff_count: usize,
    /// Hash of the opened masked broadcasts and verifier transcript.
    pub evidence_hash: [u8; 32],
    /// Runtime transcript hash claimed by the masked-broadcast proof envelopes.
    pub runtime_transcript_hash: [u8; 32],
}

/// Public evidence that CarryCompare completed before token admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarryCompareCertificationEvidence {
    /// Session id certified by this evidence.
    pub session_id: SessionId,
    /// Number of coefficients whose carry bits were certified.
    pub coeff_count: usize,
    /// Public transcript hash for the certification step.
    pub evidence_hash: [u8; 32],
    /// Runtime transcript hash for the private CarryCompare certification.
    pub runtime_transcript_hash: [u8; 32],
}

/// Public evidence that BCC was certified before token admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BccCertificationEvidence {
    /// Session id certified by this evidence.
    pub session_id: SessionId,
    /// Number of coefficients covered by BCC.
    pub coeff_count: usize,
    /// Public transcript hash for the BCC check.
    pub evidence_hash: [u8; 32],
    /// Runtime transcript hash for the private CEF/BCC certification.
    pub runtime_transcript_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CertifiedCefOutput {
    w1: Vec<u32>,
    carry_compare: CarryCompareCertificationEvidence,
    bcc: BccCertificationEvidence,
}

/// Public evidence that session/token persistence was bound before admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenPersistenceEvidence {
    /// Session id reserved in durable storage.
    pub session_id: SessionId,
    /// Hash of the persistence transcript.
    pub evidence_hash: [u8; 32],
}

/// Public evidence that post-challenge nonce reveal is disabled by policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonceRevealPolicyEvidence {
    /// Session id covered by the policy.
    pub session_id: SessionId,
    /// True only when reveal-on-failure is disabled after challenge.
    pub post_challenge_reveal_disabled: bool,
    /// Hash of the policy statement.
    pub evidence_hash: [u8; 32],
}

/// Public evidence bundle for pre-challenge preprocessing certification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreChallengeCertificationEvidence {
    /// Masked-broadcast consistency evidence.
    pub masked_broadcast: Option<MaskedBroadcastCertificationEvidence>,
    /// CarryCompare certification evidence.
    pub carry_compare: Option<CarryCompareCertificationEvidence>,
    /// BCC certification evidence.
    pub bcc: Option<BccCertificationEvidence>,
    /// Session/token persistence evidence.
    pub persistence: Option<TokenPersistenceEvidence>,
    /// No-post-challenge-reveal policy evidence.
    pub nonce_reveal_policy: Option<NonceRevealPolicyEvidence>,
}

/// Release certificate that preprocessing certification was backed by durable
/// production vector IT-MPC runtime evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreprocessingVectorRuntimeCertificate {
    /// Durable runtime evidence from the vector IT-MPC backend.
    runtime_evidence: ProductionVectorItMpcRuntimeEvidence,
    /// Hash binding this runtime evidence to one concrete certified token.
    token_binding_hash: Option<[u8; 32]>,
}

impl PreprocessingVectorRuntimeCertificate {
    /// Builds a preprocessing runtime certificate after applying the full Phase
    /// 6 preprocessing vector-runtime release gate.
    pub fn new(
        runtime_evidence: ProductionVectorItMpcRuntimeEvidence,
    ) -> Result<Self, PreprocessError> {
        ensure_preprocessing_vector_runtime_evidence_for_release(&runtime_evidence)?;
        Ok(Self {
            runtime_evidence,
            token_binding_hash: None,
        })
    }

    /// Builds a runtime certificate bound to one concrete certified token.
    pub fn for_token(
        token: &CertifiedToken,
        runtime_evidence: ProductionVectorItMpcRuntimeEvidence,
    ) -> Result<Self, PreprocessError> {
        let mut certificate = Self::new(runtime_evidence)?;
        certificate.token_binding_hash = Some(preprocessing_runtime_token_binding_hash(
            token,
            &certificate.runtime_evidence,
        ));
        Ok(certificate)
    }

    /// Returns durable runtime evidence from the vector IT-MPC backend.
    pub fn runtime_evidence(&self) -> &ProductionVectorItMpcRuntimeEvidence {
        &self.runtime_evidence
    }

    /// Returns the token-binding hash, if this certificate is bound.
    pub fn token_binding_hash(&self) -> Option<[u8; 32]> {
        self.token_binding_hash
    }

    #[cfg(test)]
    fn runtime_evidence_mut_for_test(&mut self) -> &mut ProductionVectorItMpcRuntimeEvidence {
        &mut self.runtime_evidence
    }
}

/// Public durable-log summary for one release-certified preprocessing token.
///
/// This is intentionally a public metadata entry, not the token material. It
/// binds token order, signer set, runtime transcript, `[w]` handle identity,
/// strict-mask provenance, and the token-bound runtime certificate so a release
/// runner can replay the durable token-batch log without persisting nonce
/// shares, masks, witnesses, or rejected signing material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreprocessingReleaseTokenLogEntry {
    /// Token preprocessing session id.
    pub session_id: SessionId,
    /// Token preprocessing transcript hash.
    pub transcript_hash: TranscriptHash,
    /// Position of this token in the durable batch log.
    pub token_index: u32,
    /// Hash of the sorted signer set.
    pub signer_set_hash: [u8; 32],
    /// Hash of public `w1`.
    pub w1_hash: [u8; 32],
    /// Label hash of the certified private `[w] = [A*y]` handle.
    pub precomputed_w_label_hash: [u8; 32],
    /// Strict z canonical-mask value label hash.
    pub strict_z_mask_label_hash: [u8; 32],
    /// Strict hint canonical-mask value label hash.
    pub strict_hint_mask_label_hash: [u8; 32],
    /// Strict comparison helper inventory hash.
    pub strict_comparison_helper_hash: [u8; 32],
    /// Strict threshold-check helper inventory hash.
    pub strict_threshold_helper_hash: [u8; 32],
    /// Strict selected-opening multiplication helper inventory hash.
    pub strict_selected_opening_helper_hash: [u8; 32],
    /// Durable preprocessing runtime transcript hash.
    pub runtime_transcript_hash: [u8; 32],
    /// Token binding stored in the preprocessing runtime certificate.
    pub token_binding_hash: [u8; 32],
    /// Hash of the public certificate/evidence surface.
    pub certificate_hash: [u8; 32],
}

/// Certified strict-signing canonical-mask helper material.
///
/// These handles are private preprocessing/runtime material. They are used by
/// strict signing to decompose the online `[z]` response and hint relation
/// without creating ad hoc online mask inputs. Debug output only exposes handle
/// ids and lane counts.
#[derive(Clone, Eq, PartialEq)]
pub struct StrictSigningCanonicalMaskInventory {
    /// Preprocessing/runtime provenance for these mask handles.
    provenance: Option<StrictSigningCanonicalMaskProvenance>,
    /// Certified canonical mask value for decomposing `[z]`.
    z_mask_value: ProductionShareVec,
    /// Certified canonical mask bits for decomposing `[z]`.
    z_mask_bits_by_bit: Vec<ProductionBitShareVec>,
    /// Certified canonical mask value for decomposing the hint relation.
    hint_mask_value: ProductionShareVec,
    /// Certified canonical mask bits for decomposing the hint relation.
    hint_mask_bits_by_bit: Vec<ProductionBitShareVec>,
}

/// Public provenance for strict-signing mask helper handles.
///
/// This is not the mask material. It binds private handles to the
/// preprocessing token/session, runtime transcript, and exact use labels so a
/// release token cannot substitute anonymous or cross-token masks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictSigningCanonicalMaskProvenance {
    /// Token/session id that owns these masks.
    pub session_id: SessionId,
    /// Token preprocessing transcript hash.
    pub transcript_hash: TranscriptHash,
    /// Runtime transcript that produced/certified this material.
    pub runtime_transcript_hash: [u8; 32],
    /// Label hash for the z canonical-mask value.
    pub z_mask_value_label_hash: [u8; 32],
    /// Label hash for the hint canonical-mask value.
    pub hint_mask_value_label_hash: [u8; 32],
    /// Z-mask lane count.
    pub z_lane_count: usize,
    /// Hint-mask lane count.
    pub hint_lane_count: usize,
}

impl StrictSigningCanonicalMaskInventory {
    /// Creates a strict-signing mask inventory from already certified runtime
    /// handles.
    pub fn new(
        z_mask_value: ProductionShareVec,
        z_mask_bits_by_bit: Vec<ProductionBitShareVec>,
        hint_mask_value: ProductionShareVec,
        hint_mask_bits_by_bit: Vec<ProductionBitShareVec>,
    ) -> Result<Self, PreprocessError> {
        let inventory = Self {
            provenance: None,
            z_mask_value,
            z_mask_bits_by_bit,
            hint_mask_value,
            hint_mask_bits_by_bit,
        };
        inventory.validate_basic(None)?;
        Ok(inventory)
    }

    /// Creates strict-signing masks with preprocessing runtime provenance.
    pub fn new_with_preprocessing_provenance(
        provenance: StrictSigningCanonicalMaskProvenance,
        z_mask_value: ProductionShareVec,
        z_mask_bits_by_bit: Vec<ProductionBitShareVec>,
        hint_mask_value: ProductionShareVec,
        hint_mask_bits_by_bit: Vec<ProductionBitShareVec>,
    ) -> Result<Self, PreprocessError> {
        let inventory = Self {
            provenance: Some(provenance),
            z_mask_value,
            z_mask_bits_by_bit,
            hint_mask_value,
            hint_mask_bits_by_bit,
        };
        inventory.validate_basic(Some(provenance.hint_lane_count))?;
        inventory.validate_provenance()?;
        Ok(inventory)
    }

    #[allow(dead_code)]
    fn rebind_runtime_transcript_hash(
        &self,
        runtime_transcript_hash: [u8; 32],
    ) -> Result<Self, PreprocessError> {
        let mut provenance = self
            .provenance
            .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
        provenance.runtime_transcript_hash = runtime_transcript_hash;
        Self::new_with_preprocessing_provenance(
            provenance,
            self.z_mask_value.clone(),
            self.z_mask_bits_by_bit.clone(),
            self.hint_mask_value.clone(),
            self.hint_mask_bits_by_bit.clone(),
        )
    }

    /// Returns preprocessing/runtime provenance, if present.
    pub const fn provenance(&self) -> Option<StrictSigningCanonicalMaskProvenance> {
        self.provenance
    }

    /// Certified z-decomposition mask value.
    pub const fn z_mask_value(&self) -> &ProductionShareVec {
        &self.z_mask_value
    }

    /// Certified z-decomposition mask bits.
    pub fn z_mask_bits_by_bit(&self) -> &[ProductionBitShareVec] {
        &self.z_mask_bits_by_bit
    }

    /// Certified hint-decomposition mask value.
    pub const fn hint_mask_value(&self) -> &ProductionShareVec {
        &self.hint_mask_value
    }

    /// Certified hint-decomposition mask bits.
    pub fn hint_mask_bits_by_bit(&self) -> &[ProductionBitShareVec] {
        &self.hint_mask_bits_by_bit
    }

    fn validate_basic(&self, expected_hint_lanes: Option<usize>) -> Result<(), PreprocessError> {
        if self.z_mask_bits_by_bit.len() != 23
            || self.hint_mask_bits_by_bit.len() != 23
            || self.z_mask_value.is_empty()
            || self.hint_mask_value.is_empty()
            || self
                .z_mask_bits_by_bit
                .iter()
                .any(|bits| bits.len() != self.z_mask_value.len())
            || self
                .hint_mask_bits_by_bit
                .iter()
                .any(|bits| bits.len() != self.hint_mask_value.len())
        {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        if let Some(expected) = expected_hint_lanes {
            if self.hint_mask_value.len() != expected {
                return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
            }
        }
        Ok(())
    }

    fn validate_for_token(
        &self,
        session_id: SessionId,
        transcript_hash: TranscriptHash,
        expected_hint_lanes: usize,
    ) -> Result<(), PreprocessError> {
        self.validate_basic(Some(expected_hint_lanes))?;
        let provenance = self
            .provenance
            .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
        if provenance.session_id != session_id
            || provenance.transcript_hash != transcript_hash
            || provenance.hint_lane_count != expected_hint_lanes
            || provenance.z_lane_count != self.z_mask_value.len()
            || provenance.hint_lane_count != self.hint_mask_value.len()
        {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        self.validate_provenance()
    }

    fn validate_provenance(&self) -> Result<(), PreprocessError> {
        let provenance = self
            .provenance
            .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
        if provenance.runtime_transcript_hash == [0u8; 32]
            || provenance.z_mask_value_label_hash != self.z_mask_value.id().label_hash
            || provenance.hint_mask_value_label_hash != self.hint_mask_value.id().label_hash
            || provenance.z_lane_count != self.z_mask_value.len()
            || provenance.hint_lane_count != self.hint_mask_value.len()
        {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        Ok(())
    }
}

impl fmt::Debug for StrictSigningCanonicalMaskInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrictSigningCanonicalMaskInventory")
            .field("z_mask_value", &self.z_mask_value.id())
            .field("z_mask_bits", &self.z_mask_bits_by_bit.len())
            .field("hint_mask_value", &self.hint_mask_value.id())
            .field("hint_mask_bits", &self.hint_mask_bits_by_bit.len())
            .field("provenance", &self.provenance.map(|_| "<present>"))
            .finish()
    }
}

/// Certified strict-signing comparison/threshold helper material.
///
/// This public wrapper carries only provenance and handle inventory hashes.
/// The helper witnesses themselves remain private runtime material. The
/// inventory is token-bound so strict online signing cannot silently create or
/// reuse anonymous challenge-independent helper material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictSigningHelperMaterialInventory {
    provenance: StrictSigningHelperMaterialProvenance,
}

/// Public provenance for strict-signing comparison/threshold helper material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictSigningHelperMaterialProvenance {
    /// Token/session id that owns this helper material.
    pub session_id: SessionId,
    /// Token preprocessing transcript hash.
    pub transcript_hash: TranscriptHash,
    /// Runtime transcript that produced/certified this material.
    pub runtime_transcript_hash: [u8; 32],
    /// Hash of comparison-helper inventory.
    pub comparison_helper_hash: [u8; 32],
    /// Hash of threshold-check-helper inventory.
    pub threshold_helper_hash: [u8; 32],
    /// Hash of selected-opening multiplication-helper inventory.
    pub selected_opening_helper_hash: [u8; 32],
    /// Z response lane count protected by the helper inventory.
    pub z_lane_count: usize,
    /// Hint lane count protected by the helper inventory.
    pub hint_lane_count: usize,
}

impl StrictSigningHelperMaterialInventory {
    /// Creates token-bound strict helper material provenance.
    pub fn new_with_preprocessing_provenance(
        provenance: StrictSigningHelperMaterialProvenance,
    ) -> Result<Self, PreprocessError> {
        let inventory = Self { provenance };
        inventory.validate_provenance()?;
        Ok(inventory)
    }

    /// Returns the public helper-material provenance.
    pub const fn provenance(&self) -> StrictSigningHelperMaterialProvenance {
        self.provenance
    }

    fn validate_for_token(
        &self,
        session_id: SessionId,
        transcript_hash: TranscriptHash,
        expected_hint_lanes: usize,
    ) -> Result<(), PreprocessError> {
        if self.provenance.session_id != session_id
            || self.provenance.transcript_hash != transcript_hash
            || self.provenance.hint_lane_count != expected_hint_lanes
        {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        self.validate_provenance()
    }

    fn validate_provenance(&self) -> Result<(), PreprocessError> {
        if self.provenance.runtime_transcript_hash == [0u8; 32]
            || self.provenance.comparison_helper_hash == [0u8; 32]
            || self.provenance.threshold_helper_hash == [0u8; 32]
            || self.provenance.selected_opening_helper_hash == [0u8; 32]
            || self.provenance.z_lane_count == 0
            || self.provenance.hint_lane_count == 0
        {
            return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
        }
        Ok(())
    }
}

fn strict_signing_helper_inventory_hash(
    domain: &'static [u8],
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    runtime_transcript_hash: [u8; 32],
    z_lane_count: usize,
    hint_lane_count: usize,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(session_id.0);
    hasher.update(transcript_hash.0);
    hasher.update(runtime_transcript_hash);
    hasher.update((z_lane_count as u64).to_le_bytes());
    hasher.update((hint_lane_count as u64).to_le_bytes());
    hasher.finalize().into()
}

fn strict_signing_helper_material_for_token(
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    runtime_transcript_hash: [u8; 32],
    z_lane_count: usize,
    hint_lane_count: usize,
) -> Result<StrictSigningHelperMaterialInventory, PreprocessError> {
    StrictSigningHelperMaterialInventory::new_with_preprocessing_provenance(
        StrictSigningHelperMaterialProvenance {
            session_id,
            transcript_hash,
            runtime_transcript_hash,
            comparison_helper_hash: strict_signing_helper_inventory_hash(
                b"TALUS strict signing comparison helper inventory v1",
                session_id,
                transcript_hash,
                runtime_transcript_hash,
                z_lane_count,
                hint_lane_count,
            ),
            threshold_helper_hash: strict_signing_helper_inventory_hash(
                b"TALUS strict signing threshold helper inventory v1",
                session_id,
                transcript_hash,
                runtime_transcript_hash,
                z_lane_count,
                hint_lane_count,
            ),
            selected_opening_helper_hash: strict_signing_helper_inventory_hash(
                b"TALUS strict signing selected opening helper inventory v1",
                session_id,
                transcript_hash,
                runtime_transcript_hash,
                z_lane_count,
                hint_lane_count,
            ),
            z_lane_count,
            hint_lane_count,
        },
    )
}

/// Durable preprocessing-token inventory state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenInventoryState {
    /// Token id has not been reserved for a concrete preprocessing attempt.
    Fresh,
    /// Token id is reserved/certified for one preprocessing session.
    Reserved,
    /// Token was consumed by signing and cannot be reused.
    Consumed,
    /// Token material was erased after use or failure.
    Erased,
}

/// In-memory preprocessing-token inventory state machine.
///
/// Production deployments should back the same transitions with durable
/// storage. The state model is intentionally monotonic:
///
/// `Fresh -> Reserved -> Consumed -> Erased`
///
/// No transition can make a consumed/erased token usable again.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TokenInventory {
    entries: Vec<(SessionId, TokenInventoryState)>,
}

impl TokenInventory {
    /// Creates an empty token inventory.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Returns the known state for a token id.
    pub fn state(&self, session_id: SessionId) -> TokenInventoryState {
        self.entries
            .iter()
            .find(|(known, _)| *known == session_id)
            .map(|(_, state)| *state)
            .unwrap_or(TokenInventoryState::Fresh)
    }

    /// Reserves a fresh token id before inserting it into a certified pool.
    pub fn reserve(&mut self, session_id: SessionId) -> Result<(), TokenPoolError> {
        match self.state(session_id) {
            TokenInventoryState::Fresh => {
                self.entries
                    .push((session_id, TokenInventoryState::Reserved));
                Ok(())
            }
            _ => Err(TokenPoolError::InvalidInventoryTransition {
                session_id,
                from: self.state(session_id),
                to: TokenInventoryState::Reserved,
            }),
        }
    }

    /// Marks a reserved token consumed before any online response work.
    pub fn consume(&mut self, session_id: SessionId) -> Result<(), TokenPoolError> {
        self.transition(
            session_id,
            TokenInventoryState::Reserved,
            TokenInventoryState::Consumed,
        )
    }

    /// Marks consumed token material erased.
    pub fn erase(&mut self, session_id: SessionId) -> Result<(), TokenPoolError> {
        self.transition(
            session_id,
            TokenInventoryState::Consumed,
            TokenInventoryState::Erased,
        )
    }

    fn transition(
        &mut self,
        session_id: SessionId,
        expected: TokenInventoryState,
        next: TokenInventoryState,
    ) -> Result<(), TokenPoolError> {
        let current = self.state(session_id);
        if current != expected {
            return Err(TokenPoolError::InvalidInventoryTransition {
                session_id,
                from: current,
                to: next,
            });
        }
        let (_, state) = self
            .entries
            .iter_mut()
            .find(|(known, _)| *known == session_id)
            .ok_or(TokenPoolError::InvalidInventoryTransition {
                session_id,
                from: current,
                to: next,
            })?;
        *state = next;
        Ok(())
    }
}

/// Durable preprocessing-token inventory API.
///
/// Implementations must be monotonic: once a token reaches `Consumed` or
/// `Erased`, no later restart may make it usable again.
pub trait TokenInventoryStore {
    /// Returns the known state for a token id.
    fn state(&self, session_id: SessionId) -> TokenInventoryState;

    /// Reserves a fresh token id before inserting it into a certified pool.
    fn reserve(&mut self, session_id: SessionId) -> Result<(), TokenPoolError>;

    /// Marks a reserved token consumed before any online response work.
    fn consume(&mut self, session_id: SessionId) -> Result<(), TokenPoolError>;

    /// Marks consumed token material erased.
    fn erase(&mut self, session_id: SessionId) -> Result<(), TokenPoolError>;
}

impl TokenInventoryStore for TokenInventory {
    fn state(&self, session_id: SessionId) -> TokenInventoryState {
        TokenInventory::state(self, session_id)
    }

    fn reserve(&mut self, session_id: SessionId) -> Result<(), TokenPoolError> {
        TokenInventory::reserve(self, session_id)
    }

    fn consume(&mut self, session_id: SessionId) -> Result<(), TokenPoolError> {
        TokenInventory::consume(self, session_id)
    }

    fn erase(&mut self, session_id: SessionId) -> Result<(), TokenPoolError> {
        TokenInventory::erase(self, session_id)
    }
}

/// File-backed preprocessing-token inventory for crash/restart safety.
///
/// The log contains append-only lifecycle transitions. Reopening replays the
/// transitions through the same monotonic state machine as `TokenInventory`.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileTokenInventory {
    path: std::path::PathBuf,
    inner: TokenInventory,
}

#[cfg(feature = "std")]
impl FileTokenInventory {
    /// Opens or creates a preprocessing-token inventory log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, TokenPoolError> {
        let path = path.into();
        let mut inner = TokenInventory::new();

        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let (session_id, state) = parse_token_inventory_line(line).ok_or(
                        TokenPoolError::InventoryStoreCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    replay_token_inventory_transition(&mut inner, session_id, state).map_err(
                        |_| TokenPoolError::InventoryStoreCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| TokenPoolError::InventoryStoreIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| TokenPoolError::InventoryStoreIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(TokenPoolError::InventoryStoreIo { operation: "read" });
            }
        }

        Ok(Self { path, inner })
    }

    fn append_transition(
        &mut self,
        session_id: SessionId,
        state: TokenInventoryState,
    ) -> Result<(), TokenPoolError> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| TokenPoolError::InventoryStoreIo { operation: "open" })?;
        use std::io::Write;
        writeln!(
            file,
            "{} {}",
            hex32(session_id.0),
            token_inventory_state_code(state)
        )
        .map_err(|_| TokenPoolError::InventoryStoreIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| TokenPoolError::InventoryStoreIo { operation: "sync" })
    }
}

#[cfg(feature = "std")]
impl TokenInventoryStore for FileTokenInventory {
    fn state(&self, session_id: SessionId) -> TokenInventoryState {
        self.inner.state(session_id)
    }

    fn reserve(&mut self, session_id: SessionId) -> Result<(), TokenPoolError> {
        if self.inner.state(session_id) != TokenInventoryState::Fresh {
            return self.inner.reserve(session_id);
        }
        self.append_transition(session_id, TokenInventoryState::Reserved)?;
        self.inner.reserve(session_id)
    }

    fn consume(&mut self, session_id: SessionId) -> Result<(), TokenPoolError> {
        if self.inner.state(session_id) != TokenInventoryState::Reserved {
            return self.inner.consume(session_id);
        }
        self.append_transition(session_id, TokenInventoryState::Consumed)?;
        self.inner.consume(session_id)
    }

    fn erase(&mut self, session_id: SessionId) -> Result<(), TokenPoolError> {
        if self.inner.state(session_id) != TokenInventoryState::Consumed {
            return self.inner.erase(session_id);
        }
        self.append_transition(session_id, TokenInventoryState::Erased)?;
        self.inner.erase(session_id)
    }
}

#[cfg(feature = "std")]
fn replay_token_inventory_transition(
    inner: &mut TokenInventory,
    session_id: SessionId,
    state: TokenInventoryState,
) -> Result<(), TokenPoolError> {
    match state {
        TokenInventoryState::Fresh => Err(TokenPoolError::InvalidInventoryTransition {
            session_id,
            from: inner.state(session_id),
            to: TokenInventoryState::Fresh,
        }),
        TokenInventoryState::Reserved => inner.reserve(session_id),
        TokenInventoryState::Consumed => inner.consume(session_id),
        TokenInventoryState::Erased => inner.erase(session_id),
    }
}

#[cfg(feature = "std")]
fn token_inventory_state_code(state: TokenInventoryState) -> &'static str {
    match state {
        TokenInventoryState::Fresh => "fresh",
        TokenInventoryState::Reserved => "reserved",
        TokenInventoryState::Consumed => "consumed",
        TokenInventoryState::Erased => "erased",
    }
}

#[cfg(feature = "std")]
fn parse_token_inventory_state_code(input: &str) -> Option<TokenInventoryState> {
    match input {
        "reserved" => Some(TokenInventoryState::Reserved),
        "consumed" => Some(TokenInventoryState::Consumed),
        "erased" => Some(TokenInventoryState::Erased),
        _ => None,
    }
}

#[cfg(feature = "std")]
fn parse_token_inventory_line(line: &str) -> Option<(SessionId, TokenInventoryState)> {
    let mut parts = line.split_ascii_whitespace();
    let session_id = parse_session_id_hex(parts.next()?)?;
    let state = parse_token_inventory_state_code(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((session_id, state))
}

#[cfg(feature = "std")]
fn format_preprocessing_release_session_cursor_line(
    cursor: &PreprocessingReleaseSessionCursor,
) -> String {
    let token_binding_hash = cursor
        .token_binding_hash
        .map(|hash| format!("{}", hex32(hash)))
        .unwrap_or_else(|| "-".to_owned());
    format!(
        "talus-preprocessing-release-cursor-v1 {} {} {} {}",
        hex32(cursor.session_id.0),
        preprocessing_release_session_phase_code(cursor.phase),
        hex32(cursor.transcript_hash.0),
        token_binding_hash
    )
}

#[cfg(feature = "std")]
fn parse_preprocessing_release_session_cursor_line(
    line: &str,
) -> Option<PreprocessingReleaseSessionCursor> {
    let mut parts = line.split_ascii_whitespace();
    if parts.next()? != "talus-preprocessing-release-cursor-v1" {
        return None;
    }
    let session_id = parse_session_id_hex(parts.next()?)?;
    let phase = parse_preprocessing_release_session_phase_code(parts.next()?)?;
    let transcript_hash = TranscriptHash(parse_hex32(parts.next()?)?);
    let token_binding_hash = match parts.next()? {
        "-" => None,
        value => Some(parse_hex32(value)?),
    };
    if parts.next().is_some() {
        return None;
    }
    Some(PreprocessingReleaseSessionCursor {
        session_id,
        phase,
        transcript_hash,
        token_binding_hash,
    })
}

#[cfg(feature = "std")]
fn preprocessing_release_session_phase_code(
    phase: PreprocessingReleaseSessionPhase,
) -> &'static str {
    match phase {
        PreprocessingReleaseSessionPhase::TranscriptComplete => "transcript-complete",
        PreprocessingReleaseSessionPhase::PrivateRuntimeComplete => "private-runtime-complete",
        PreprocessingReleaseSessionPhase::StrictMasksComplete => "strict-masks-complete",
        PreprocessingReleaseSessionPhase::ReleaseTokenCertified => "release-token-certified",
        PreprocessingReleaseSessionPhase::Aborted => "aborted",
    }
}

#[cfg(feature = "std")]
fn parse_preprocessing_release_session_phase_code(
    input: &str,
) -> Option<PreprocessingReleaseSessionPhase> {
    match input {
        "transcript-complete" => Some(PreprocessingReleaseSessionPhase::TranscriptComplete),
        "private-runtime-complete" => {
            Some(PreprocessingReleaseSessionPhase::PrivateRuntimeComplete)
        }
        "strict-masks-complete" => Some(PreprocessingReleaseSessionPhase::StrictMasksComplete),
        "release-token-certified" => Some(PreprocessingReleaseSessionPhase::ReleaseTokenCertified),
        "aborted" => Some(PreprocessingReleaseSessionPhase::Aborted),
        _ => None,
    }
}

/// Vector-lane counters for production preprocessing certification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PreprocessingCertificationCounters {
    /// Number of tokens represented by this counter set.
    pub token_count: usize,
    /// Number of signers in each token.
    pub signer_count: usize,
    /// Number of coefficients per masked broadcast.
    pub coeff_count: usize,
    /// Total signer/coefficient lanes.
    pub vector_lanes: usize,
    /// Number of masked-broadcast openings.
    pub masked_broadcasts: usize,
    /// CarryCompare lanes certified.
    pub carry_compare_lanes: usize,
    /// CEF correction lanes certified.
    pub cef_correction_lanes: usize,
    /// BCC lanes certified.
    pub bcc_lanes: usize,
}

impl PreprocessingCertificationCounters {
    /// Builds counters from one certified token.
    pub fn from_token(token: &CertifiedToken) -> Self {
        let signer_count = token.signer_set.len();
        let coeff_count = token.w1.len();
        Self {
            token_count: 1,
            signer_count,
            coeff_count,
            vector_lanes: signer_count.saturating_mul(coeff_count),
            masked_broadcasts: token.broadcasts.len(),
            carry_compare_lanes: token
                .certification_evidence
                .carry_compare
                .map(|item| item.coeff_count)
                .unwrap_or_default(),
            cef_correction_lanes: coeff_count,
            bcc_lanes: token
                .certification_evidence
                .bcc
                .map(|item| item.coeff_count)
                .unwrap_or_default(),
        }
    }

    /// Aggregates counters for a token batch.
    pub fn from_tokens(tokens: &[CertifiedToken]) -> Self {
        let mut out = Self::default();
        out.token_count = tokens.len();
        for token in tokens {
            let item = Self::from_token(token);
            out.signer_count = out.signer_count.max(item.signer_count);
            out.coeff_count = out.coeff_count.max(item.coeff_count);
            out.vector_lanes = out.vector_lanes.saturating_add(item.vector_lanes);
            out.masked_broadcasts = out.masked_broadcasts.saturating_add(item.masked_broadcasts);
            out.carry_compare_lanes = out
                .carry_compare_lanes
                .saturating_add(item.carry_compare_lanes);
            out.cef_correction_lanes = out
                .cef_correction_lanes
                .saturating_add(item.cef_correction_lanes);
            out.bcc_lanes = out.bcc_lanes.saturating_add(item.bcc_lanes);
        }
        out
    }
}

/// Public report for one preprocessing token-batch fill attempt.
///
/// It records only aggregate counts and public execution-shape counters. It
/// does not expose token pass bits, failed token ids, private masks, witnesses,
/// or rejection reasons.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PreprocessingTokenBatchFillReport {
    /// Number of token attempts made by the preprocessing scheduler.
    pub attempted_tokens: u64,
    /// Number of release-certified tokens admitted to the batch.
    pub certified_tokens: u64,
    /// Aggregate public preprocessing counters for the certified tokens.
    pub counters: PreprocessingCertificationCounters,
}

/// Non-secret wall-clock timing for one coarse preprocessing scheduler phase.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PreprocessingBestShapePhaseTiming {
    /// Coarse phase name.
    pub phase: &'static str,
    /// Elapsed wall-clock time in milliseconds.
    pub elapsed_ms: u128,
}

/// Aggregate non-secret phase-profile totals for a preprocessing run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PreprocessingBestShapeProfileTotals {
    /// Durable wire records.
    pub records: u64,
    /// Private-channel durable wire records.
    pub private_records: u64,
    /// Broadcast durable wire records.
    pub broadcast_records: u64,
    /// Vector lanes carried by the durable runtime.
    pub vector_lanes: u64,
    /// Wire bytes after canonical wire encoding.
    pub wire_bytes: u64,
    /// Estimated durable log bytes.
    pub durable_log_bytes: u64,
}

/// Non-secret best-shape preprocessing performance report.
///
/// This is a measurement/regression artifact. It intentionally records only
/// public execution shape: timings, durable runtime records, message split,
/// vector lanes, bytes, and top coarse phases. It must not contain masks,
/// witnesses, pass bits, token failure reasons, or rejected material.
#[derive(Clone, Debug, PartialEq)]
pub struct PreprocessingBestShapePerformanceReport {
    /// ML-DSA suite name.
    pub suite: &'static str,
    /// Attempted tokens.
    pub attempted_tokens: u64,
    /// Release-certified tokens.
    pub certified_tokens: u64,
    /// Per-token preprocessing counters.
    pub preprocessing_counters: PreprocessingCertificationCounters,
    /// Coarse wall-clock timings.
    pub timings: Vec<PreprocessingBestShapePhaseTiming>,
    /// Aggregated durable runtime profile totals.
    pub profile_totals: PreprocessingBestShapeProfileTotals,
    /// Highest-cost durable-log phases.
    pub top_durable_log_phases: Vec<talus_dkg::PrimeFieldMpcPhaseProfile>,
    /// True when every durable wire record respects the current suite chunk policy.
    pub chunk_policy_ok: bool,
    /// True when every profiled phase carried vector lanes.
    pub no_scalarized_release_profile: bool,
}

impl PreprocessingTokenBatchFillReport {
    /// Builds a report from attempted-token count and the certified output
    /// tokens.
    pub fn from_certified_tokens(attempted_tokens: u64, tokens: &[CertifiedToken]) -> Self {
        Self {
            attempted_tokens,
            certified_tokens: tokens.len() as u64,
            counters: PreprocessingCertificationCounters::from_tokens(tokens),
        }
    }

    /// Returns the pass-probability estimate used by strict token-batch
    /// sizing. Returns `None` when no token passed or no attempts were made.
    pub fn pass_probability_estimate(self) -> Option<TokenPassProbabilityEstimate> {
        TokenPassProbabilityEstimate::new(self.attempted_tokens, self.certified_tokens)
    }
}

/// Builds a non-secret preprocessing best-shape report from release-token and
/// durable runtime evidence.
pub fn preprocessing_best_shape_performance_report<P: MlDsaParams>(
    fill_report: PreprocessingTokenBatchFillReport,
    timings: Vec<PreprocessingBestShapePhaseTiming>,
    phase_profile: &[talus_dkg::PrimeFieldMpcPhaseProfile],
    top_limit: usize,
) -> Result<PreprocessingBestShapePerformanceReport, PreprocessError> {
    let chunk_policy_ok =
        talus_dkg::ensure_prime_field_mpc_phase_profile_within_chunk_policy::<P>(phase_profile)
            .is_ok();
    let mut totals = PreprocessingBestShapeProfileTotals::default();
    for entry in phase_profile {
        totals.records = totals.records.saturating_add(entry.records);
        totals.private_records = totals.private_records.saturating_add(entry.private_records);
        totals.broadcast_records = totals
            .broadcast_records
            .saturating_add(entry.broadcast_records);
        totals.vector_lanes = totals.vector_lanes.saturating_add(entry.vector_lanes);
        totals.wire_bytes = totals.wire_bytes.saturating_add(entry.wire_bytes);
        totals.durable_log_bytes = totals
            .durable_log_bytes
            .saturating_add(entry.durable_log_bytes);
    }
    if totals.records == 0
        || totals.records
            != totals
                .private_records
                .saturating_add(totals.broadcast_records)
        || totals.vector_lanes == 0
        || totals.wire_bytes == 0
        || totals.durable_log_bytes == 0
    {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    let no_scalarized_release_profile = phase_profile.iter().all(|entry| {
        entry.records == entry.private_records + entry.broadcast_records && entry.is_vectorized()
    });
    if !no_scalarized_release_profile {
        return Err(PreprocessError::PreprocessingCountersNotVectorized);
    }
    Ok(PreprocessingBestShapePerformanceReport {
        suite: P::NAME,
        attempted_tokens: fill_report.attempted_tokens,
        certified_tokens: fill_report.certified_tokens,
        preprocessing_counters: fill_report.counters,
        timings,
        profile_totals: totals,
        top_durable_log_phases: talus_dkg::top_prime_field_mpc_phase_profiles_by_durable_log_bytes(
            phase_profile,
            top_limit,
        ),
        chunk_policy_ok,
        no_scalarized_release_profile,
    })
}

/// Ensures preprocessing certification was vector/chunk-shaped enough for a
/// production token pool. This gate intentionally checks evidence shape, not
/// cryptographic proof soundness.
pub fn ensure_preprocessing_counters_vectorized_for_release(
    counters: PreprocessingCertificationCounters,
) -> Result<(), PreprocessError> {
    if counters.token_count == 0
        || counters.signer_count == 0
        || counters.coeff_count == 0
        || counters.vector_lanes < counters.signer_count.saturating_mul(counters.coeff_count)
        || counters.masked_broadcasts < counters.signer_count
        || counters.carry_compare_lanes < counters.coeff_count
        || counters.cef_correction_lanes < counters.coeff_count
        || counters.bcc_lanes < counters.coeff_count
    {
        return Err(PreprocessError::PreprocessingCountersNotVectorized);
    }
    Ok(())
}

/// Converts preprocessing certification counters into the shared TALUS
/// performance model.
pub fn talus_performance_counters_from_preprocessing(
    counters: PreprocessingCertificationCounters,
) -> TalusPerformanceCounters {
    TalusPerformanceCounters {
        rounds: 1,
        broadcasts: counters.masked_broadcasts as u64,
        vector_lanes: counters.vector_lanes as u64,
        chunks: counters.token_count as u64,
        checked_lanes: counters
            .carry_compare_lanes
            .saturating_add(counters.cef_correction_lanes)
            .saturating_add(counters.bcc_lanes) as u64,
        token_batch_size: counters.token_count as u64,
        ..TalusPerformanceCounters::default()
    }
}

impl PreChallengeCertificationEvidence {
    /// Converts present evidence objects into an admission policy.
    pub fn policy(&self) -> PreChallengeCertificationPolicy {
        PreChallengeCertificationPolicy {
            masked_broadcast_consistency: self.masked_broadcast.is_some(),
            carry_compare_certified: self.carry_compare.is_some(),
            bcc_certified: self.bcc.is_some(),
            persistent_session_store: self.persistence.is_some(),
            no_post_challenge_nonce_reveal: self
                .nonce_reveal_policy
                .map(|evidence| evidence.post_challenge_reveal_disabled)
                .unwrap_or(false),
        }
    }
}

/// Validates pre-challenge certification policy for production token
/// admission. This does not replace the concrete proof verifiers; it prevents
/// callers from marking a token production-ready when any required
/// pre-challenge certification stage is absent.
pub fn ensure_pre_challenge_certification_policy(
    policy: PreChallengeCertificationPolicy,
) -> Result<(), PreprocessError> {
    if policy.masked_broadcast_consistency
        && policy.carry_compare_certified
        && policy.bcc_certified
        && policy.persistent_session_store
        && policy.no_post_challenge_nonce_reveal
    {
        Ok(())
    } else {
        Err(PreprocessError::PreChallengeCertificationIncomplete)
    }
}

/// Validates pre-challenge certification evidence for one session.
pub fn ensure_pre_challenge_certification_evidence(
    session_id: SessionId,
    evidence: &PreChallengeCertificationEvidence,
) -> Result<PreChallengeCertificationPolicy, PreprocessError> {
    let policy = evidence.policy();
    ensure_pre_challenge_certification_policy(policy)?;
    let session_matches = evidence
        .masked_broadcast
        .map(|item| item.session_id == session_id && item.evidence_hash != [0u8; 32])
        .unwrap_or(false)
        && evidence
            .carry_compare
            .map(|item| item.session_id == session_id && item.evidence_hash != [0u8; 32])
            .unwrap_or(false)
        && evidence
            .bcc
            .map(|item| item.session_id == session_id && item.evidence_hash != [0u8; 32])
            .unwrap_or(false)
        && evidence
            .persistence
            .map(|item| item.session_id == session_id && item.evidence_hash != [0u8; 32])
            .unwrap_or(false)
        && evidence
            .nonce_reveal_policy
            .map(|item| item.session_id == session_id && item.evidence_hash != [0u8; 32])
            .unwrap_or(false);
    if session_matches {
        Ok(policy)
    } else {
        Err(PreprocessError::PreChallengeCertificationIncomplete)
    }
}

/// Validates one preprocessing token for a release-capable strict-signing pool.
///
/// `CertifiedToken::is_certified` is intentionally permissive in normal test
/// builds so unit tests can construct local/dev tokens. This function is the
/// production boundary: it requires the full pre-challenge certification
/// evidence, vector/chunk counters, and a durable vector IT-MPC runtime
/// certificate attached to the token itself.
pub fn ensure_certified_token_release_valid(token: &CertifiedToken) -> Result<(), PreprocessError> {
    ensure_pre_challenge_certification_evidence(token.session_id, &token.certification_evidence)?;
    if token.certification_policy != token.certification_evidence.policy() {
        return Err(PreprocessError::PreChallengeCertificationIncomplete);
    }
    ensure_preprocessing_counters_vectorized_for_release(
        PreprocessingCertificationCounters::from_token(token),
    )?;
    let w_share = token
        .precomputed_w_share
        .as_ref()
        .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
    if w_share.len() != token.w1.len() {
        return Err(PreprocessError::PreprocessingRuntimeMaterialMissing);
    }
    token
        .strict_signing_masks
        .as_ref()
        .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?
        .validate_for_token(token.session_id, token.transcript_hash, token.w1.len())?;
    token
        .strict_signing_helpers
        .as_ref()
        .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?
        .validate_for_token(token.session_id, token.transcript_hash, token.w1.len())?;
    let certificate = token
        .vector_runtime_certificate
        .as_ref()
        .ok_or(PreprocessError::PreprocessingRuntimeCertificateMissing)?;
    ensure_preprocessing_vector_runtime_evidence_for_release(&certificate.runtime_evidence)?;
    if token
        .strict_signing_masks
        .as_ref()
        .and_then(StrictSigningCanonicalMaskInventory::provenance)
        .map(|provenance| provenance.runtime_transcript_hash)
        != Some(certificate.runtime_evidence.transcript_hash)
    {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    if token
        .strict_signing_helpers
        .as_ref()
        .map(|helpers| helpers.provenance().runtime_transcript_hash)
        != Some(certificate.runtime_evidence.transcript_hash)
    {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    ensure_preprocessing_runtime_evidence_covers_token(token, &certificate.runtime_evidence)?;
    let expected_binding =
        preprocessing_runtime_token_binding_hash(token, &certificate.runtime_evidence);
    if certificate.token_binding_hash != Some(expected_binding) {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    let preprocessing_runtime_hash = preprocessing_certification_runtime_transcript_hash(token)?;
    if certificate.runtime_evidence.transcript_hash != preprocessing_runtime_hash {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    Ok(())
}

fn preprocessing_certification_runtime_transcript_hash(
    token: &CertifiedToken,
) -> Result<[u8; 32], PreprocessError> {
    preprocessing_runtime_transcript_aggregate_hash(
        token.session_id,
        token.transcript_hash,
        PreprocessingCertificationRuntimeTranscripts {
            masked_broadcast: token
                .certification_evidence
                .masked_broadcast
                .map(|evidence| evidence.runtime_transcript_hash)
                .ok_or(PreprocessError::PreChallengeCertificationIncomplete)?,
            carry_compare: token
                .certification_evidence
                .carry_compare
                .map(|evidence| evidence.runtime_transcript_hash)
                .ok_or(PreprocessError::PreChallengeCertificationIncomplete)?,
            bcc: token
                .certification_evidence
                .bcc
                .map(|evidence| evidence.runtime_transcript_hash)
                .ok_or(PreprocessError::PreChallengeCertificationIncomplete)?,
        },
    )
}

fn ensure_preprocessing_runtime_evidence_covers_token(
    token: &CertifiedToken,
    runtime_evidence: &ProductionVectorItMpcRuntimeEvidence,
) -> Result<(), PreprocessError> {
    let counters = PreprocessingCertificationCounters::from_token(token);
    let runtime = runtime_evidence.counters;
    let certification_lanes = counters
        .carry_compare_lanes
        .saturating_add(counters.cef_correction_lanes)
        .saturating_add(counters.bcc_lanes) as u64;
    if runtime.vector_lanes < certification_lanes || runtime.vector_mul_lanes < certification_lanes
    {
        return Err(PreprocessError::PreprocessingCountersNotVectorized);
    }
    Ok(())
}

/// Builds the public durable-log entry expected for one release token.
pub fn preprocessing_release_token_log_entry(
    token: &CertifiedToken,
    token_index: usize,
) -> Result<PreprocessingReleaseTokenLogEntry, PreprocessError> {
    ensure_certified_token_release_valid(token)?;
    let certificate = token
        .vector_runtime_certificate
        .as_ref()
        .ok_or(PreprocessError::PreprocessingRuntimeCertificateMissing)?;
    let token_binding_hash = certificate
        .token_binding_hash()
        .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
    let precomputed_w_label_hash = token
        .precomputed_w_share
        .as_ref()
        .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?
        .id()
        .label_hash;
    let mask_provenance = token
        .strict_signing_masks
        .as_ref()
        .and_then(StrictSigningCanonicalMaskInventory::provenance)
        .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
    let helper_provenance = token
        .strict_signing_helpers
        .as_ref()
        .map(StrictSigningHelperMaterialInventory::provenance)
        .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;

    Ok(PreprocessingReleaseTokenLogEntry {
        session_id: token.session_id,
        transcript_hash: token.transcript_hash,
        token_index: token_index as u32,
        signer_set_hash: preprocessing_release_signer_set_hash(&token.signer_set),
        w1_hash: preprocessing_release_w1_hash(&token.w1),
        precomputed_w_label_hash,
        strict_z_mask_label_hash: mask_provenance.z_mask_value_label_hash,
        strict_hint_mask_label_hash: mask_provenance.hint_mask_value_label_hash,
        strict_comparison_helper_hash: helper_provenance.comparison_helper_hash,
        strict_threshold_helper_hash: helper_provenance.threshold_helper_hash,
        strict_selected_opening_helper_hash: helper_provenance.selected_opening_helper_hash,
        runtime_transcript_hash: certificate.runtime_evidence().transcript_hash,
        token_binding_hash,
        certificate_hash: preprocessing_release_certificate_hash(certificate),
    })
}

/// Verifies a public durable token-batch log against release-certified tokens.
///
/// The comparison is order-sensitive. Token pools may later choose different
/// batching policies, but release replay must not silently reorder token ids or
/// reuse a certificate entry for a different token.
pub fn ensure_preprocessing_release_token_batch_log_for_release(
    tokens: &[CertifiedToken],
    entries: &[PreprocessingReleaseTokenLogEntry],
) -> Result<(), PreprocessError> {
    if tokens.len() != entries.len() {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    for (idx, (token, entry)) in tokens.iter().zip(entries.iter()).enumerate() {
        let expected = preprocessing_release_token_log_entry(token, idx)?;
        if *entry != expected {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
    }
    Ok(())
}

/// Rejects durable preprocessing log text that contains private-material
/// markers forbidden in release logs.
///
/// Structured log replay should prefer `PreprocessingReleaseTokenLogEntry`.
/// This text scanner is a guardrail for append-only integration logs and CI
/// scans that are not yet parsed into typed entries.
pub fn ensure_preprocessing_release_token_log_text_public_for_release(
    log_text: &str,
) -> Result<(), PreprocessError> {
    const FORBIDDEN_MARKERS: &[&str] = &[
        "nonce_share=",
        "y_share=",
        "raw_mask=",
        "raw_masks=",
        "mask_bits=",
        "rejected_z=",
        "partial_z=",
        "low_bits=",
        "witness=",
        "failed_diff=",
        "secret_lane=",
        "private_lane=",
        "unselected_z=",
        "valid_bit=",
        "pass_bit=",
    ];
    if FORBIDDEN_MARKERS
        .iter()
        .any(|marker| log_text.contains(marker))
    {
        Err(PreprocessError::PreprocessingRuntimeMaterialMissing)
    } else {
        Ok(())
    }
}

/// File-backed append-only typed release-token batch log.
///
/// This store persists only `PreprocessingReleaseTokenLogEntry` public
/// metadata. It must never contain nonce shares, raw masks, witnesses, rejected
/// `z`, pass bits, or other private preprocessing/signing material.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePreprocessingReleaseTokenBatchLog {
    path: std::path::PathBuf,
    entries: Vec<PreprocessingReleaseTokenLogEntry>,
}

#[cfg(feature = "std")]
impl FilePreprocessingReleaseTokenBatchLog {
    /// Opens or creates a typed release-token batch log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, TokenPoolError> {
        let path = path.into();
        let mut entries = Vec::new();

        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                ensure_preprocessing_release_token_log_text_public_for_release(&contents)
                    .map_err(|_| TokenPoolError::ReleaseLogCorrupt { line: 1 })?;
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let entry = parse_preprocessing_release_token_log_entry(line).ok_or(
                        TokenPoolError::ReleaseLogCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    if entries
                        .iter()
                        .any(|known: &PreprocessingReleaseTokenLogEntry| {
                            known.token_index == entry.token_index
                        })
                    {
                        return Err(TokenPoolError::ReleaseLogCorrupt {
                            line: line_index + 1,
                        });
                    }
                    entries.push(entry);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| TokenPoolError::ReleaseLogIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| TokenPoolError::ReleaseLogIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(TokenPoolError::ReleaseLogIo { operation: "read" });
            }
        }

        Ok(Self { path, entries })
    }

    /// Returns replayed typed log entries in durable file order.
    pub fn entries(&self) -> &[PreprocessingReleaseTokenLogEntry] {
        &self.entries
    }

    /// Appends one typed public release-token log entry.
    pub fn append(
        &mut self,
        entry: PreprocessingReleaseTokenLogEntry,
    ) -> Result<(), TokenPoolError> {
        if self
            .entries
            .iter()
            .any(|known| known.token_index == entry.token_index)
        {
            return Err(TokenPoolError::ReleaseLogCorrupt {
                line: self.entries.len() + 1,
            });
        }
        let line = encode_preprocessing_release_token_log_entry(&entry);
        ensure_preprocessing_release_token_log_text_public_for_release(&line).map_err(|_| {
            TokenPoolError::ReleaseLogCorrupt {
                line: self.entries.len() + 1,
            }
        })?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| TokenPoolError::ReleaseLogIo { operation: "open" })?;
        use std::io::Write;
        writeln!(file, "{line}")
            .map_err(|_| TokenPoolError::ReleaseLogIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| TokenPoolError::ReleaseLogIo { operation: "sync" })?;
        self.entries.push(entry);
        Ok(())
    }

    /// Appends a complete token batch.
    pub fn append_batch(
        &mut self,
        entries: &[PreprocessingReleaseTokenLogEntry],
    ) -> Result<(), TokenPoolError> {
        for entry in entries {
            self.append(*entry)?;
        }
        Ok(())
    }

    /// Replays this typed log against release-certified tokens.
    pub fn replay_for_release(&self, tokens: &[CertifiedToken]) -> Result<(), TokenPoolError> {
        ensure_preprocessing_release_token_batch_log_for_release(tokens, &self.entries)
            .map_err(|_| TokenPoolError::ReleaseLogMismatch)
    }
}

#[cfg(feature = "std")]
fn encode_preprocessing_release_token_log_entry(
    entry: &PreprocessingReleaseTokenLogEntry,
) -> String {
    format!(
        "talus-preprocessing-release-token-v3 {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        entry.token_index,
        hex32(entry.session_id.0),
        hex32(entry.transcript_hash.0),
        hex32(entry.signer_set_hash),
        hex32(entry.w1_hash),
        hex32(entry.precomputed_w_label_hash),
        hex32(entry.strict_z_mask_label_hash),
        hex32(entry.strict_hint_mask_label_hash),
        hex32(entry.strict_comparison_helper_hash),
        hex32(entry.strict_threshold_helper_hash),
        hex32(entry.strict_selected_opening_helper_hash),
        hex32(entry.runtime_transcript_hash),
        hex32(entry.token_binding_hash),
        hex32(entry.certificate_hash),
    )
}

#[cfg(feature = "std")]
fn parse_preprocessing_release_token_log_entry(
    line: &str,
) -> Option<PreprocessingReleaseTokenLogEntry> {
    let mut parts = line.split_ascii_whitespace();
    if parts.next()? != "talus-preprocessing-release-token-v3" {
        return None;
    }
    let token_index = parts.next()?.parse::<u32>().ok()?;
    let session_id = SessionId(parse_hex32(parts.next()?)?);
    let transcript_hash = TranscriptHash(parse_hex32(parts.next()?)?);
    let signer_set_hash = parse_hex32(parts.next()?)?;
    let w1_hash = parse_hex32(parts.next()?)?;
    let precomputed_w_label_hash = parse_hex32(parts.next()?)?;
    let strict_z_mask_label_hash = parse_hex32(parts.next()?)?;
    let strict_hint_mask_label_hash = parse_hex32(parts.next()?)?;
    let strict_comparison_helper_hash = parse_hex32(parts.next()?)?;
    let strict_threshold_helper_hash = parse_hex32(parts.next()?)?;
    let strict_selected_opening_helper_hash = parse_hex32(parts.next()?)?;
    let runtime_transcript_hash = parse_hex32(parts.next()?)?;
    let token_binding_hash = parse_hex32(parts.next()?)?;
    let certificate_hash = parse_hex32(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some(PreprocessingReleaseTokenLogEntry {
        session_id,
        transcript_hash,
        token_index,
        signer_set_hash,
        w1_hash,
        precomputed_w_label_hash,
        strict_z_mask_label_hash,
        strict_hint_mask_label_hash,
        strict_comparison_helper_hash,
        strict_threshold_helper_hash,
        strict_selected_opening_helper_hash,
        runtime_transcript_hash,
        token_binding_hash,
        certificate_hash,
    })
}

fn preprocessing_release_signer_set_hash(signers: &[PartyId]) -> [u8; 32] {
    let ids = signers.iter().map(|party| party.0).collect::<Vec<_>>();
    signing_set_hash(&ids)
}

fn preprocessing_release_w1_hash(w1: &[u32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing release token w1 log v1");
    hasher.update((w1.len() as u64).to_le_bytes());
    for coeff in w1 {
        hasher.update(coeff.to_le_bytes());
    }
    hasher.finalize().into()
}

fn preprocessing_release_certificate_hash(
    certificate: &PreprocessingVectorRuntimeCertificate,
) -> [u8; 32] {
    let evidence = certificate.runtime_evidence();
    let counters = evidence.counters;
    let coverage = evidence.coverage;
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing release certificate log v1");
    hasher.update(evidence.transcript_hash);
    hasher.update(certificate.token_binding_hash().unwrap_or([0u8; 32]));
    hasher.update(counters.rounds.to_le_bytes());
    hasher.update(counters.private_messages.to_le_bytes());
    hasher.update(counters.broadcasts.to_le_bytes());
    hasher.update(counters.wire_bytes.to_le_bytes());
    hasher.update(counters.durable_log_bytes.to_le_bytes());
    hasher.update(counters.vector_lanes.to_le_bytes());
    hasher.update(counters.multiplication_layers.to_le_bytes());
    hasher.update(counters.scalar_mul_gates.to_le_bytes());
    hasher.update(counters.scalar_openings.to_le_bytes());
    hasher.update(counters.scalar_assert_zero.to_le_bytes());
    hasher.update(counters.vector_mul_lanes.to_le_bytes());
    hasher.update(counters.vector_opening_lanes.to_le_bytes());
    hasher.update(counters.vector_assert_zero_lanes.to_le_bytes());
    hasher.update(counters.random_bits.to_le_bytes());
    hasher.update(counters.local_public_mul_lanes.to_le_bytes());
    hasher.update([coverage.open_many_checked as u8]);
    hasher.update([coverage.assert_zero_vec as u8]);
    hasher.update([coverage.assert_bit_vec as u8]);
    hasher.update([coverage.random_bit_vec as u8]);
    hasher.update([coverage.mul_vec as u8]);
    hasher.update([coverage.comparison_to_public as u8]);
    hasher.update([coverage.equality_to_public as u8]);
    hasher.update([coverage.bit_sum_or_threshold_check as u8]);
    hasher.update([coverage.private_one_hot_selection as u8]);
    hasher.update([coverage.preprocessing_masked_broadcast as u8]);
    hasher.update([coverage.preprocessing_carry_compare as u8]);
    hasher.update([coverage.preprocessing_cef_bcc as u8]);
    hasher.finalize().into()
}

/// Certified preprocessing token.
pub struct CertifiedToken {
    /// Session identifier.
    pub session_id: SessionId,
    /// Sorted signer set.
    pub signer_set: Vec<PartyId>,
    /// Reconstructed `w1` coefficients.
    pub w1: Vec<u32>,
    /// Nonce commitments by signer order.
    pub nonce_commitments: Vec<NonceCommitment>,
    /// Token transcript hash.
    pub transcript_hash: TranscriptHash,
    /// Zeroized local aggregate nonce share material.
    pub y_share: Zeroizing<Vec<u8>>,
    /// Optional certified runtime handle for `[w] = [A*y]`.
    ///
    /// This is release signing helper material. It must stay private and is
    /// redacted from debug output. When present before attaching the
    /// preprocessing runtime certificate, the certificate binding commits to
    /// the handle id so signing cannot substitute a different `[w]`.
    pub precomputed_w_share: Option<ProductionShareVec>,
    /// Certified strict-signing canonical decomposition masks.
    ///
    /// Release signing consumes these one-time helper handles for z-bound and
    /// hint/highbits checks. They are bound into the preprocessing runtime
    /// certificate when attached before certificate creation.
    pub strict_signing_masks: Option<StrictSigningCanonicalMaskInventory>,
    /// Certified strict-signing comparison and threshold-check helper material.
    ///
    /// This is challenge-independent private helper inventory. Release signing
    /// must consume it exactly once before online private comparisons and
    /// threshold reductions start.
    pub strict_signing_helpers: Option<StrictSigningHelperMaterialInventory>,
    /// Certified masked broadcasts.
    pub broadcasts: Vec<MaskedBroadcast>,
    /// Public pre-challenge certification evidence.
    pub certification_evidence: PreChallengeCertificationEvidence,
    /// Pre-challenge certification policy used for admission.
    pub certification_policy: PreChallengeCertificationPolicy,
    /// Durable production vector IT-MPC runtime certificate for preprocessing.
    ///
    /// This is optional for dev/test token construction, but release-capable
    /// preprocessing output must attach it to the token itself so downstream
    /// signing cannot lose the runtime evidence.
    pub vector_runtime_certificate: Option<PreprocessingVectorRuntimeCertificate>,
}

impl fmt::Debug for CertifiedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertifiedToken")
            .field("session_id", &self.session_id)
            .field("signer_set", &self.signer_set)
            .field("w1_len", &self.w1.len())
            .field("nonce_commitments", &self.nonce_commitments)
            .field("transcript_hash", &self.transcript_hash)
            .field("y_share", &"<redacted>")
            .field(
                "precomputed_w_share",
                &self.precomputed_w_share.as_ref().map(|share| share.id()),
            )
            .field(
                "strict_signing_masks",
                &self.strict_signing_masks.as_ref().map(|_| "<present>"),
            )
            .field(
                "strict_signing_helpers",
                &self.strict_signing_helpers.as_ref().map(|_| "<present>"),
            )
            .field("broadcasts_len", &self.broadcasts.len())
            .field("certification_evidence", &self.certification_evidence)
            .field("certification_policy", &self.certification_policy)
            .field(
                "vector_runtime_certificate",
                &self
                    .vector_runtime_certificate
                    .as_ref()
                    .map(|_| "<present>"),
            )
            .finish()
    }
}

impl CertifiedToken {
    /// Attaches durable vector-runtime evidence to this certified token.
    pub fn with_vector_runtime_certificate(
        mut self,
        certificate: PreprocessingVectorRuntimeCertificate,
    ) -> Self {
        self.vector_runtime_certificate = Some(certificate);
        self
    }

    /// Returns the attached durable vector-runtime certificate, if present.
    pub fn vector_runtime_certificate(&self) -> Option<&PreprocessingVectorRuntimeCertificate> {
        self.vector_runtime_certificate.as_ref()
    }

    /// Attaches the certified `[w] = [A*y]` runtime handle used by optimized
    /// strict signing.
    pub fn with_precomputed_w_share(mut self, share: ProductionShareVec) -> Self {
        self.precomputed_w_share = Some(share);
        self
    }

    /// Returns the certified `[w] = [A*y]` runtime handle, if present.
    pub fn precomputed_w_share(&self) -> Option<&ProductionShareVec> {
        self.precomputed_w_share.as_ref()
    }

    /// Attaches certified strict-signing canonical-mask helper material.
    pub fn with_strict_signing_canonical_masks(
        mut self,
        masks: StrictSigningCanonicalMaskInventory,
    ) -> Self {
        self.strict_signing_masks = Some(masks);
        self
    }

    /// Returns strict-signing canonical-mask helper material, if present.
    pub fn strict_signing_masks(&self) -> Option<&StrictSigningCanonicalMaskInventory> {
        self.strict_signing_masks.as_ref()
    }

    /// Attaches certified strict-signing comparison/threshold helper material.
    pub fn with_strict_signing_helper_material(
        mut self,
        helpers: StrictSigningHelperMaterialInventory,
    ) -> Self {
        self.strict_signing_helpers = Some(helpers);
        self
    }

    /// Returns strict-signing comparison/threshold helper material, if present.
    pub fn strict_signing_helpers(&self) -> Option<&StrictSigningHelperMaterialInventory> {
        self.strict_signing_helpers.as_ref()
    }

    /// Returns whether this token is valid for a release-capable strict pool.
    pub fn is_release_certified(&self) -> bool {
        ensure_certified_token_release_valid(self).is_ok()
    }

    /// Returns whether this token has passed preprocessing certification.
    pub fn is_certified(&self) -> bool {
        let base_certified = self.certification_policy == self.certification_evidence.policy()
            && ensure_pre_challenge_certification_evidence(
                self.session_id,
                &self.certification_evidence,
            )
            .is_ok()
            && self.certification_policy.masked_broadcast_consistency
            && self.certification_policy.carry_compare_certified
            && self.certification_policy.bcc_certified
            && self.certification_policy.persistent_session_store
            && self.certification_policy.no_post_challenge_nonce_reveal
            && (!cfg!(feature = "production-release-checks") || self.is_release_certified());
        base_certified
    }
}

/// Uncertified token candidate used by token-pool admission tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenCandidate {
    /// Session identifier.
    pub session_id: SessionId,
}

/// Token-pool admission error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenPoolError {
    /// Candidate was not certified.
    NotCertified(SessionId),
    /// Certified token session already exists in the pool.
    Duplicate(SessionId),
    /// No certified token exists for the requested session.
    Missing(SessionId),
    /// Token inventory transition would make a token reusable or skip a
    /// required durable state.
    InvalidInventoryTransition {
        /// Token session id.
        session_id: SessionId,
        /// Current state.
        from: TokenInventoryState,
        /// Requested next state.
        to: TokenInventoryState,
    },
    /// Preprocessing-token inventory I/O failed.
    InventoryStoreIo {
        /// Storage operation.
        operation: &'static str,
    },
    /// Preprocessing-token inventory log was malformed.
    InventoryStoreCorrupt {
        /// One-based line number.
        line: usize,
    },
    /// Release token-batch durable log did not match the tokens being admitted.
    ReleaseLogMismatch,
    /// Release token-batch durable log I/O failed.
    ReleaseLogIo {
        /// Storage operation.
        operation: &'static str,
    },
    /// Release token-batch durable log was malformed.
    ReleaseLogCorrupt {
        /// One-based line number.
        line: usize,
    },
}

/// Certified token pool.
#[derive(Debug, Default)]
pub struct TokenPool {
    sessions: Vec<SessionId>,
    tokens: Vec<CertifiedToken>,
}

impl TokenPool {
    /// Creates an empty token pool.
    pub const fn new() -> Self {
        Self {
            sessions: Vec::new(),
            tokens: Vec::new(),
        }
    }

    /// Rejects an uncertified candidate.
    pub fn insert_candidate(&mut self, candidate: TokenCandidate) -> Result<(), TokenPoolError> {
        Err(TokenPoolError::NotCertified(candidate.session_id))
    }

    /// Inserts a certified token.
    pub fn insert_certified(&mut self, token: CertifiedToken) -> Result<(), TokenPoolError> {
        if !token.is_certified() {
            return Err(TokenPoolError::NotCertified(token.session_id));
        }
        if self.sessions.contains(&token.session_id) {
            return Err(TokenPoolError::Duplicate(token.session_id));
        }

        self.sessions.push(token.session_id);
        self.tokens.push(token);
        Ok(())
    }

    /// Inserts a token only if it carries release-capable preprocessing runtime
    /// evidence.
    pub fn insert_release_certified(
        &mut self,
        token: CertifiedToken,
    ) -> Result<(), TokenPoolError> {
        if !token.is_release_certified() {
            return Err(TokenPoolError::NotCertified(token.session_id));
        }
        if self.sessions.contains(&token.session_id) {
            return Err(TokenPoolError::Duplicate(token.session_id));
        }

        self.sessions.push(token.session_id);
        self.tokens.push(token);
        Ok(())
    }

    /// Reserves inventory state and inserts a certified token.
    pub fn insert_certified_with_inventory(
        &mut self,
        token: CertifiedToken,
        inventory: &mut impl TokenInventoryStore,
    ) -> Result<(), TokenPoolError> {
        inventory.reserve(token.session_id)?;
        self.insert_certified(token)
    }

    /// Reserves inventory state and inserts a release-certified token.
    pub fn insert_release_certified_with_inventory(
        &mut self,
        token: CertifiedToken,
        inventory: &mut impl TokenInventoryStore,
    ) -> Result<(), TokenPoolError> {
        inventory.reserve(token.session_id)?;
        self.insert_release_certified(token)
    }

    /// Reserves inventory state and inserts a release-certified token batch
    /// only after its typed durable public log has replayed successfully.
    pub fn insert_release_certified_batch_with_inventory_and_log(
        &mut self,
        tokens: Vec<CertifiedToken>,
        entries: &[PreprocessingReleaseTokenLogEntry],
        inventory: &mut impl TokenInventoryStore,
    ) -> Result<(), TokenPoolError> {
        ensure_preprocessing_release_token_batch_log_for_release(&tokens, entries)
            .map_err(|_| TokenPoolError::ReleaseLogMismatch)?;

        let mut sessions = Vec::with_capacity(tokens.len());
        for token in &tokens {
            if !token.is_release_certified() {
                return Err(TokenPoolError::NotCertified(token.session_id));
            }
            if self.sessions.contains(&token.session_id) || sessions.contains(&token.session_id) {
                return Err(TokenPoolError::Duplicate(token.session_id));
            }
            if inventory.state(token.session_id) != TokenInventoryState::Fresh {
                return Err(TokenPoolError::InvalidInventoryTransition {
                    session_id: token.session_id,
                    from: inventory.state(token.session_id),
                    to: TokenInventoryState::Reserved,
                });
            }
            sessions.push(token.session_id);
        }

        for token in &tokens {
            inventory.reserve(token.session_id)?;
        }
        for token in tokens {
            self.sessions.push(token.session_id);
            self.tokens.push(token);
        }
        Ok(())
    }

    /// Reserves inventory state and inserts a release-certified token batch
    /// only after replaying entries from a file-backed typed release log.
    #[cfg(feature = "std")]
    pub fn insert_release_certified_batch_with_inventory_and_file_log(
        &mut self,
        tokens: Vec<CertifiedToken>,
        log: &FilePreprocessingReleaseTokenBatchLog,
        inventory: &mut impl TokenInventoryStore,
    ) -> Result<(), TokenPoolError> {
        self.insert_release_certified_batch_with_inventory_and_log(tokens, log.entries(), inventory)
    }

    /// Removes and returns a certified token for one session.
    pub fn take_certified(
        &mut self,
        session_id: SessionId,
    ) -> Result<CertifiedToken, TokenPoolError> {
        let Some(idx) = self
            .tokens
            .iter()
            .position(|token| token.session_id == session_id)
        else {
            return Err(TokenPoolError::Missing(session_id));
        };

        self.sessions.retain(|&known| known != session_id);
        Ok(self.tokens.remove(idx))
    }

    /// Removes and returns a certified token batch in `session_ids` order.
    ///
    /// This is the pool-side batch boundary used by strict signing. It avoids
    /// callers repeatedly selecting one token at a time and gives the caller a
    /// single fail-closed operation before constructing `BccCertifiedTokenBatch`.
    pub fn take_certified_batch(
        &mut self,
        session_ids: &[SessionId],
    ) -> Result<Vec<CertifiedToken>, TokenPoolError> {
        let mut out = Vec::with_capacity(session_ids.len());
        for &session_id in session_ids {
            if out
                .iter()
                .any(|token: &CertifiedToken| token.session_id == session_id)
            {
                return Err(TokenPoolError::Duplicate(session_id));
            }
            out.push(self.take_certified(session_id)?);
        }
        Ok(out)
    }

    /// Marks the token consumed in the inventory before returning it to online
    /// signing. Callers must still use the online consumed-token store before
    /// computing or sending any response share.
    pub fn take_certified_for_consumption(
        &mut self,
        session_id: SessionId,
        inventory: &mut impl TokenInventoryStore,
    ) -> Result<CertifiedToken, TokenPoolError> {
        inventory.consume(session_id)?;
        self.take_certified(session_id)
    }

    /// Marks a token batch consumed in inventory before returning it to online
    /// signing.
    pub fn take_certified_batch_for_consumption(
        &mut self,
        session_ids: &[SessionId],
        inventory: &mut impl TokenInventoryStore,
    ) -> Result<Vec<CertifiedToken>, TokenPoolError> {
        let mut seen = Vec::with_capacity(session_ids.len());
        for &session_id in session_ids {
            if seen.contains(&session_id) {
                return Err(TokenPoolError::Duplicate(session_id));
            }
            if !self.contains(session_id) {
                return Err(TokenPoolError::Missing(session_id));
            }
            if inventory.state(session_id) != TokenInventoryState::Reserved {
                return Err(TokenPoolError::InvalidInventoryTransition {
                    session_id,
                    from: inventory.state(session_id),
                    to: TokenInventoryState::Consumed,
                });
            }
            seen.push(session_id);
        }
        for &session_id in session_ids {
            inventory.consume(session_id)?;
        }
        self.take_certified_batch(session_ids)
    }

    /// Returns whether a certified token exists for one session.
    pub fn contains(&self, session_id: SessionId) -> bool {
        self.sessions.contains(&session_id)
    }

    /// Returns the number of certified tokens in the pool.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Returns whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

/// Session uniqueness registry.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionRegistry {
    used: Vec<SessionId>,
}

/// Session uniqueness persistence API.
pub trait SessionStore {
    /// Reserves a session id, rejecting reuse.
    fn reserve(&mut self, session_id: SessionId) -> Result<(), PreprocessError>;

    /// Returns whether a session id is already reserved.
    fn is_reserved(&self, session_id: SessionId) -> bool;
}

impl SessionRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self { used: Vec::new() }
    }
}

impl SessionStore for SessionRegistry {
    fn reserve(&mut self, session_id: SessionId) -> Result<(), PreprocessError> {
        if self.used.contains(&session_id) {
            return Err(PreprocessError::SessionReuse(session_id));
        }

        self.used.push(session_id);
        Ok(())
    }

    fn is_reserved(&self, session_id: SessionId) -> bool {
        self.used.contains(&session_id)
    }
}

/// File-backed session registry for crash/reopen tests.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSessionRegistry {
    path: std::path::PathBuf,
    inner: SessionRegistry,
}

#[cfg(feature = "std")]
impl FileSessionRegistry {
    /// Opens or creates a session-id reservation log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, PreprocessError> {
        let path = path.into();
        let mut inner = SessionRegistry::new();

        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let session_id =
                        parse_session_id_hex(line).ok_or(PreprocessError::SessionStoreCorrupt {
                            line: line_index + 1,
                        })?;
                    if inner.is_reserved(session_id) {
                        return Err(PreprocessError::SessionStoreCorrupt {
                            line: line_index + 1,
                        });
                    }
                    inner.used.push(session_id);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| PreprocessError::SessionStoreIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| PreprocessError::SessionStoreIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(PreprocessError::SessionStoreIo { operation: "read" });
            }
        }

        Ok(Self { path, inner })
    }
}

#[cfg(feature = "std")]
impl SessionStore for FileSessionRegistry {
    fn reserve(&mut self, session_id: SessionId) -> Result<(), PreprocessError> {
        if self.inner.is_reserved(session_id) {
            return Err(PreprocessError::SessionReuse(session_id));
        }

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| PreprocessError::SessionStoreIo { operation: "open" })?;
        use std::io::Write;
        writeln!(file, "{}", hex32(session_id.0))
            .map_err(|_| PreprocessError::SessionStoreIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| PreprocessError::SessionStoreIo { operation: "sync" })?;

        self.inner.reserve(session_id)
    }

    fn is_reserved(&self, session_id: SessionId) -> bool {
        self.inner.is_reserved(session_id)
    }
}

/// Monotonic preprocessing session counter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SessionCounter {
    next: u64,
}

/// Session counter persistence API.
pub trait SessionCounterStore {
    /// Allocates and durably advances the next counter before returning it.
    fn allocate_counter(&mut self) -> Result<u64, PreprocessError>;

    /// Returns the next counter that will be allocated.
    fn next_counter(&self) -> u64;
}

impl SessionCounter {
    /// Creates a counter starting at zero.
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    /// Creates a counter starting at `next`.
    pub const fn with_next(next: u64) -> Self {
        Self { next }
    }
}

impl SessionCounterStore for SessionCounter {
    fn allocate_counter(&mut self) -> Result<u64, PreprocessError> {
        let current = self.next;
        self.next = self
            .next
            .checked_add(1)
            .ok_or(PreprocessError::SessionCounterExhausted)?;
        Ok(current)
    }

    fn next_counter(&self) -> u64 {
        self.next
    }
}

/// File-backed monotonic session counter for crash/reopen tests.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSessionCounter {
    path: std::path::PathBuf,
    inner: SessionCounter,
}

#[cfg(feature = "std")]
impl FileSessionCounter {
    /// Opens or creates a session counter file.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, PreprocessError> {
        let path = path.into();
        let inner = match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let trimmed = contents.trim();
                let next = trimmed
                    .parse::<u64>()
                    .map_err(|_| PreprocessError::SessionCounterStoreCorrupt)?;
                SessionCounter::with_next(next)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                persist_counter(&path, 0)?;
                SessionCounter::new()
            }
            Err(_) => {
                return Err(PreprocessError::SessionCounterStoreIo { operation: "read" });
            }
        };

        Ok(Self { path, inner })
    }
}

#[cfg(feature = "std")]
impl SessionCounterStore for FileSessionCounter {
    fn allocate_counter(&mut self) -> Result<u64, PreprocessError> {
        let current = self.inner.next_counter();
        let next = current
            .checked_add(1)
            .ok_or(PreprocessError::SessionCounterExhausted)?;
        persist_counter(&self.path, next)?;
        self.inner = SessionCounter::with_next(next);
        Ok(current)
    }

    fn next_counter(&self) -> u64 {
        self.inner.next_counter()
    }
}

/// Preprocessing failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreprocessError {
    /// Session id was reused.
    SessionReuse(SessionId),
    /// No party inputs were supplied.
    EmptySignerSet,
    /// Duplicate party input.
    DuplicateParty(PartyId),
    /// Party inputs had different coefficient counts.
    CoeffCountMismatch,
    /// High bit was outside the suite high modulus.
    InvalidHigh {
        /// Party identifier.
        party: PartyId,
        /// Invalid high value.
        value: u32,
    },
    /// Low bit was outside alpha.
    InvalidLow {
        /// Party identifier.
        party: PartyId,
        /// Invalid low value.
        value: u32,
    },
    /// Commit/open verification failed.
    CommitmentMismatch(PartyId),
    /// A party claimed a different transcript hash.
    TranscriptMismatch(PartyId),
    /// Clear audit witness was required for this verifier.
    MaskedBroadcastAuditRequired(PartyId),
    /// Masked-broadcast consistency verification failed.
    MaskedBroadcastConsistencyMismatch(PartyId),
    /// Product masked-broadcast proof backend is not implemented yet.
    MaskedBroadcastProofBackendUnavailable(PartyId),
    /// Vector CarryCompare/CEF certification failed.
    CarryCompareCertificationFailed,
    /// Boundary clearance failed; discard this token and retry preprocessing.
    BoundaryClearanceFailed,
    /// Cut-and-choose audit plan was malformed.
    InvalidAuditPlan,
    /// Session registry I/O failed.
    SessionStoreIo {
        /// Storage operation.
        operation: &'static str,
    },
    /// Session registry log was malformed.
    SessionStoreCorrupt {
        /// One-based line number.
        line: usize,
    },
    /// Session counter I/O failed.
    SessionCounterStoreIo {
        /// Storage operation.
        operation: &'static str,
    },
    /// Session counter file was malformed.
    SessionCounterStoreCorrupt,
    /// Session counter reached `u64::MAX`.
    SessionCounterExhausted,
    /// Required pre-challenge preprocessing certification is incomplete.
    PreChallengeCertificationIncomplete,
    /// Release-capable preprocessing token is missing durable vector runtime evidence.
    PreprocessingRuntimeCertificateMissing,
    /// Release-capable preprocessing token is missing certified runtime helper material.
    PreprocessingRuntimeMaterialMissing,
    /// Durable vector runtime evidence is not bound to this preprocessing token.
    PreprocessingRuntimeCertificateMismatch,
    /// Preprocessing evidence does not prove vector/chunk-shaped execution.
    PreprocessingCountersNotVectorized,
    /// Preprocessing session received a private message, but this round uses broadcast only.
    UnexpectedPrivateMessage,
    /// Preprocessing session received a wire message for the wrong round or context.
    UnexpectedWireMessage,
    /// Preprocessing session received a message from a party outside the signer set.
    UnknownParty(PartyId),
    /// Preprocessing session received more than one message for the same party and round.
    DuplicateBroadcast(PartyId),
    /// Preprocessing session is not ready to finish.
    IncompleteSession,
    /// Distributed nonce generation failed before a certified local share was produced.
    NonceGenerationFailed,
}

impl fmt::Display for PreprocessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SessionReuse(session_id) => {
                write!(f, "preprocessing session reused: {}", hex32(session_id.0))
            }
            Self::EmptySignerSet => write!(f, "empty preprocessing signer set"),
            Self::DuplicateParty(party) => write!(f, "duplicate party {}", party.0),
            Self::CoeffCountMismatch => write!(f, "coefficient count mismatch"),
            Self::InvalidHigh { party, value } => {
                write!(f, "invalid high value {value} for party {}", party.0)
            }
            Self::InvalidLow { party, value } => {
                write!(f, "invalid low value {value} for party {}", party.0)
            }
            Self::CommitmentMismatch(party) => {
                write!(
                    f,
                    "masked broadcast commitment mismatch for party {}",
                    party.0
                )
            }
            Self::TranscriptMismatch(party) => {
                write!(
                    f,
                    "masked broadcast transcript mismatch for party {}",
                    party.0
                )
            }
            Self::MaskedBroadcastAuditRequired(party) => {
                write!(
                    f,
                    "masked broadcast clear audit required for party {}",
                    party.0
                )
            }
            Self::MaskedBroadcastConsistencyMismatch(party) => {
                write!(
                    f,
                    "masked broadcast consistency mismatch for party {}",
                    party.0
                )
            }
            Self::MaskedBroadcastProofBackendUnavailable(party) => {
                write!(
                    f,
                    "masked broadcast proof backend unavailable for party {}",
                    party.0
                )
            }
            Self::CarryCompareCertificationFailed => {
                write!(f, "vector CarryCompare/CEF certification failed")
            }
            Self::BoundaryClearanceFailed => {
                write!(f, "boundary clearance failed; retry preprocessing")
            }
            Self::InvalidAuditPlan => write!(f, "invalid cut-and-choose audit plan"),
            Self::SessionStoreIo { operation } => {
                write!(f, "session store I/O failed during {operation}")
            }
            Self::SessionStoreCorrupt { line } => {
                write!(f, "session store corrupt at line {line}")
            }
            Self::SessionCounterStoreIo { operation } => {
                write!(f, "session counter store I/O failed during {operation}")
            }
            Self::SessionCounterStoreCorrupt => write!(f, "session counter store corrupt"),
            Self::SessionCounterExhausted => write!(f, "session counter exhausted"),
            Self::PreChallengeCertificationIncomplete => {
                write!(f, "pre-challenge certification incomplete")
            }
            Self::PreprocessingRuntimeCertificateMissing => {
                write!(
                    f,
                    "preprocessing token is missing durable vector runtime certificate"
                )
            }
            Self::PreprocessingRuntimeMaterialMissing => {
                write!(
                    f,
                    "preprocessing token is missing certified runtime helper material"
                )
            }
            Self::PreprocessingRuntimeCertificateMismatch => {
                write!(
                    f,
                    "preprocessing runtime certificate is not bound to this token"
                )
            }
            Self::PreprocessingCountersNotVectorized => {
                write!(f, "preprocessing counters are not vectorized")
            }
            Self::UnexpectedPrivateMessage => write!(
                f,
                "unexpected private preprocessing message; preprocessing session expects broadcast messages"
            ),
            Self::UnexpectedWireMessage => {
                write!(f, "unexpected preprocessing wire message")
            }
            Self::UnknownParty(party) => {
                write!(f, "unknown preprocessing party {}", party.0)
            }
            Self::DuplicateBroadcast(party) => {
                write!(f, "duplicate preprocessing broadcast from party {}", party.0)
            }
            Self::IncompleteSession => write!(f, "preprocessing session is incomplete"),
            Self::NonceGenerationFailed => write!(f, "distributed nonce generation failed"),
        }
    }
}

impl PreprocessError {
    /// Returns whether this failure consumes only pre-challenge preprocessing
    /// material and should be handled by discarding the token candidate and
    /// retrying with a fresh session.
    pub const fn is_retryable_pre_challenge(&self) -> bool {
        matches!(self, Self::BoundaryClearanceFailed)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PreprocessError {}

/// Builds and certifies one local preprocessing token.
pub fn certify_preprocessing_token<P: MlDsaParams>(
    registry: &mut impl SessionStore,
    session_id: SessionId,
    inputs: Vec<PartyPreprocessInput>,
) -> Result<CertifiedToken, PreprocessError> {
    let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
    certify_preprocessing_token_with_consistency::<P, _>(
        &mut verifier,
        registry,
        session_id,
        inputs,
    )
}

/// Builds and certifies one release-capable preprocessing token.
#[cfg(test)]
pub fn certify_preprocessing_token_release_validated<P: MlDsaParams>(
    registry: &mut impl SessionStore,
    session_id: SessionId,
    inputs: Vec<PartyPreprocessInput>,
    runtime_evidence: ProductionVectorItMpcRuntimeEvidence,
) -> Result<CertifiedToken, PreprocessError> {
    let token = certify_preprocessing_token::<P>(registry, session_id, inputs)?;
    let certificate = PreprocessingVectorRuntimeCertificate::for_token(&token, runtime_evidence)?;
    let token = token.with_vector_runtime_certificate(certificate);
    ensure_certified_token_release_valid(&token)?;
    Ok(token)
}

/// Certifies a release-capable preprocessing token from app/runtime-produced
/// masked-broadcast envelopes.
///
/// This is the release-oriented entry point for the future private vector
/// IT-MPC preprocessing runtime: the embedding application supplies the
/// already committed/opened envelopes and durable runtime evidence, and this
/// function verifies the transcript before attaching the release certificate.
fn certify_preprocessing_token_release_validated_from_envelopes<
    P: MlDsaParams,
    V: MaskedBroadcastConsistencyVerifier,
>(
    verifier: &mut V,
    registry: &mut impl SessionStore,
    session_id: SessionId,
    inputs: Vec<PartyPreprocessInput>,
    envelopes: Vec<BroadcastEnvelope>,
    expected_transcript: TranscriptHash,
    runtime_proofs: PreprocessingCertificationRuntimeProofs,
    runtime_evidence: ProductionVectorItMpcRuntimeEvidence,
) -> Result<CertifiedToken, PreprocessError> {
    runtime_proofs.transcripts()?;
    let token = certify_opened_masked_broadcasts_with_consistency::<P, V>(
        verifier,
        registry,
        session_id,
        inputs,
        envelopes,
        expected_transcript,
        Some(&runtime_proofs),
    )?;
    let certificate = PreprocessingVectorRuntimeCertificate::for_token(&token, runtime_evidence)?;
    let token = token.with_vector_runtime_certificate(certificate);
    ensure_certified_token_release_valid(&token)?;
    Ok(token)
}

/// Certifies a release-capable preprocessing token using an explicit private
/// vector-runtime boundary for CarryCompare and BCC proof production.
pub fn certify_preprocessing_token_release_validated_with_runtime<
    P: MlDsaParams,
    V: MaskedBroadcastConsistencyVerifier,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
>(
    verifier: &mut V,
    registry: &mut impl SessionStore,
    session_id: SessionId,
    inputs: Vec<PartyPreprocessInput>,
    envelopes: Vec<BroadcastEnvelope>,
    expected_transcript: TranscriptHash,
    runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
) -> Result<CertifiedToken, PreprocessError> {
    let statement = preprocessing_certification_runtime_statement_from_envelopes::<P>(
        session_id,
        inputs.clone(),
        envelopes.clone(),
        expected_transcript,
    )?;
    let (runtime_proofs, runtime_evidence) = runtime.certify_preprocessing::<P>(&statement)?;
    certify_preprocessing_token_release_validated_from_envelopes::<P, V>(
        verifier,
        registry,
        session_id,
        inputs,
        envelopes,
        expected_transcript,
        runtime_proofs,
        runtime_evidence,
    )
}

/// Certifies a release-capable preprocessing token by first finishing a
/// state-owned private preprocessing circuit driver.
///
/// This is the product-shaped constructor for callers that drive the
/// preprocessing private phases explicitly: the caller supplies the durable
/// masked-broadcast envelopes and a completed runtime driver state. The
/// function attaches only the runtime-owned outputs derived from that state,
/// then delegates to the normal release certification boundary.
pub fn certify_preprocessing_token_release_validated_with_finished_runtime_driver<
    P: MlDsaParams,
    V: MaskedBroadcastConsistencyVerifier,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
>(
    verifier: &mut V,
    registry: &mut impl SessionStore,
    session_id: SessionId,
    inputs: Vec<PartyPreprocessInput>,
    envelopes: Vec<BroadcastEnvelope>,
    expected_transcript: TranscriptHash,
    runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
    completed_state: &PreprocessingPrivateCircuitDriverState,
) -> Result<CertifiedToken, PreprocessError> {
    let statement = preprocessing_certification_runtime_statement_from_envelopes::<P>(
        session_id,
        inputs.clone(),
        envelopes.clone(),
        expected_transcript,
    )?;
    runtime
        .finish_and_attach_private_circuit_state_for_statement::<P>(&statement, completed_state)?;
    certify_preprocessing_token_release_validated_with_runtime::<P, V, T, L, C>(
        verifier,
        registry,
        session_id,
        inputs,
        envelopes,
        expected_transcript,
        runtime,
    )
}

/// Dev/test adapter that certifies a preprocessing token from completed private
/// preprocessing circuits plus completed strict-signing helper material by
/// deriving `[w]` from opened preprocessing material.
///
/// This is intentionally not part of the normal production API. Release token
/// construction uses
/// [`certify_preprocessing_token_release_validated_with_finished_runtime_driver_strict_material_and_nonce_share`],
/// which derives `[w] = [A*y]` from the distributed nonce/runtime handle.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn dev_certify_preprocessing_token_with_opened_material_w_for_tests<
    P: MlDsaParams,
    V: MaskedBroadcastConsistencyVerifier,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
>(
    verifier: &mut V,
    registry: &mut impl SessionStore,
    session_id: SessionId,
    inputs: Vec<PartyPreprocessInput>,
    envelopes: Vec<BroadcastEnvelope>,
    expected_transcript: TranscriptHash,
    config: &DkgConfig,
    runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
    completed_state: &PreprocessingPrivateCircuitDriverState,
    completed_mask_state: StrictSigningCanonicalMaskGenerationState,
) -> Result<CertifiedToken, PreprocessError> {
    let statement = preprocessing_certification_runtime_statement_from_envelopes::<P>(
        session_id,
        inputs.clone(),
        envelopes.clone(),
        expected_transcript,
    )?;
    let broadcasts = open_broadcasts(session_id, &envelopes, expected_transcript)?;
    runtime
        .finish_and_attach_private_circuit_state_for_statement::<P>(&statement, completed_state)?;
    let masks = runtime.finish_strict_signing_canonical_mask_generation(completed_mask_state)?;
    let precomputed_w_share = runtime
        .dev_derive_strict_signing_precomputed_w_share_from_opened_preprocessing::<P>(
            config,
            &statement,
            &broadcasts,
        )?;
    let (runtime_proofs, runtime_evidence) = runtime.certify_preprocessing::<P>(&statement)?;
    runtime_proofs.transcripts()?;
    let token = certify_opened_masked_broadcasts_with_consistency::<P, V>(
        verifier,
        registry,
        session_id,
        inputs,
        envelopes,
        expected_transcript,
        Some(&runtime_proofs),
    )?;
    let masks = masks.rebind_runtime_transcript_hash(runtime_evidence.transcript_hash)?;
    let helper_mask_provenance = masks
        .provenance()
        .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
    let helper_session_id = token.session_id;
    let helper_transcript_hash = token.transcript_hash;
    let token = token
        .with_precomputed_w_share(precomputed_w_share)
        .with_strict_signing_canonical_masks(masks)
        .with_strict_signing_helper_material(strict_signing_helper_material_for_token(
            helper_session_id,
            helper_transcript_hash,
            runtime_evidence.transcript_hash,
            helper_mask_provenance.z_lane_count,
            helper_mask_provenance.hint_lane_count,
        )?);
    let certificate = PreprocessingVectorRuntimeCertificate::for_token(&token, runtime_evidence)?;
    let token = token.with_vector_runtime_certificate(certificate);
    ensure_certified_token_release_valid(&token)?;
    Ok(token)
}

/// Certifies a release-capable preprocessing token from completed private
/// preprocessing circuits, completed strict-signing helper material, and the
/// local distributed nonce share.
///
/// This is the production-shaped strict-signing token constructor: `[w]` is
/// derived as `[A * y]` from the runtime nonce-share handle. Opened-material
/// `[w]` derivation is test/scaffold-only; release callers should use this
/// path.
pub fn certify_preprocessing_token_release_validated_with_finished_runtime_driver_strict_material_and_nonce_share<
    P: MlDsaParams,
    V: MaskedBroadcastConsistencyVerifier,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
>(
    verifier: &mut V,
    registry: &mut impl SessionStore,
    session_id: SessionId,
    inputs: Vec<PartyPreprocessInput>,
    envelopes: Vec<BroadcastEnvelope>,
    expected_transcript: TranscriptHash,
    config: &DkgConfig,
    rho: &[u8; 32],
    signer_set: &[PartyId],
    nonce_share: &DistributedNonceShare,
    runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
    completed_state: &PreprocessingPrivateCircuitDriverState,
    completed_mask_state: StrictSigningCanonicalMaskGenerationState,
) -> Result<CertifiedToken, PreprocessError> {
    let masks = runtime.finish_strict_signing_canonical_mask_generation(completed_mask_state)?;
    certify_preprocessing_token_release_validated_with_finished_runtime_driver_strict_inventory_and_nonce_share::<
        P, V, T, L, C,
    >(
        verifier,
        registry,
        session_id,
        inputs,
        envelopes,
        expected_transcript,
        config,
        rho,
        signer_set,
        nonce_share,
        runtime,
        completed_state,
        masks,
    )
}

/// Certifies a release-capable preprocessing token from completed private
/// preprocessing circuits and already finished strict-signing helper
/// inventory. This is used by the fused token-batch scheduler, which generates
/// one large strict-mask vector circuit and then slices token-bound
/// inventories.
pub fn certify_preprocessing_token_release_validated_with_finished_runtime_driver_strict_inventory_and_nonce_share<
    P: MlDsaParams,
    V: MaskedBroadcastConsistencyVerifier,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
>(
    verifier: &mut V,
    registry: &mut impl SessionStore,
    session_id: SessionId,
    inputs: Vec<PartyPreprocessInput>,
    envelopes: Vec<BroadcastEnvelope>,
    expected_transcript: TranscriptHash,
    config: &DkgConfig,
    rho: &[u8; 32],
    signer_set: &[PartyId],
    nonce_share: &DistributedNonceShare,
    runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
    completed_state: &PreprocessingPrivateCircuitDriverState,
    masks: StrictSigningCanonicalMaskInventory,
) -> Result<CertifiedToken, PreprocessError> {
    let expected_nonce_input = party_preprocess_input_from_distributed_nonce_share::<P>(
        session_id,
        signer_set,
        rho,
        nonce_share,
    )?;
    let actual_nonce_input = inputs
        .iter()
        .find(|input| input.party == nonce_share.party)
        .ok_or(PreprocessError::UnknownParty(nonce_share.party))?;
    if actual_nonce_input.highs != expected_nonce_input.highs
        || actual_nonce_input.lows != expected_nonce_input.lows
        || actual_nonce_input.nonce_commitment != expected_nonce_input.nonce_commitment
        || actual_nonce_input.randomness_commitment != expected_nonce_input.randomness_commitment
        || (!actual_nonce_input.y_share.is_empty()
            && actual_nonce_input.y_share != expected_nonce_input.y_share)
    {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }

    let statement = preprocessing_certification_runtime_statement_from_envelopes::<P>(
        session_id,
        inputs.clone(),
        envelopes.clone(),
        expected_transcript,
    )?;
    runtime
        .finish_and_attach_private_circuit_state_for_statement::<P>(&statement, completed_state)?;
    masks.validate_for_token(session_id, expected_transcript, P::K * P::N)?;
    let precomputed_w_share = runtime
        .derive_strict_signing_precomputed_w_share_from_distributed_nonce_share::<P>(
            config,
            session_id,
            signer_set,
            rho,
            nonce_share,
        )?;
    let (runtime_proofs, runtime_evidence) = runtime.certify_preprocessing::<P>(&statement)?;
    runtime_proofs.transcripts()?;
    let token = certify_opened_masked_broadcasts_with_consistency::<P, V>(
        verifier,
        registry,
        session_id,
        inputs,
        envelopes,
        expected_transcript,
        Some(&runtime_proofs),
    )?;
    let masks = masks.rebind_runtime_transcript_hash(runtime_evidence.transcript_hash)?;
    let helper_mask_provenance = masks
        .provenance()
        .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
    let helper_session_id = token.session_id;
    let helper_transcript_hash = token.transcript_hash;
    let token = token
        .with_precomputed_w_share(precomputed_w_share)
        .with_strict_signing_canonical_masks(masks)
        .with_strict_signing_helper_material(strict_signing_helper_material_for_token(
            helper_session_id,
            helper_transcript_hash,
            runtime_evidence.transcript_hash,
            helper_mask_provenance.z_lane_count,
            helper_mask_provenance.hint_lane_count,
        )?);
    let certificate = PreprocessingVectorRuntimeCertificate::for_token(&token, runtime_evidence)?;
    let token = token.with_vector_runtime_certificate(certificate);
    ensure_certified_token_release_valid(&token)?;
    Ok(token)
}

/// Certifies a release-capable preprocessing token using a fused private
/// CarryCompare/CEF/BCC batch proof plus token-bound strict helper inventory.
pub fn certify_preprocessing_token_release_validated_with_fused_private_batch_strict_inventory_and_nonce_share<
    P: MlDsaParams,
    V: MaskedBroadcastConsistencyVerifier,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
>(
    verifier: &mut V,
    registry: &mut impl SessionStore,
    session_id: SessionId,
    inputs: Vec<PartyPreprocessInput>,
    envelopes: Vec<BroadcastEnvelope>,
    expected_transcript: TranscriptHash,
    config: &DkgConfig,
    rho: &[u8; 32],
    signer_set: &[PartyId],
    nonce_share: &DistributedNonceShare,
    runtime: &mut ProductionPreprocessingCertificationRuntime<'_, T, L, C>,
    completed_batch_state: &PreprocessingPrivateCircuitBatchDriverState,
    masks: StrictSigningCanonicalMaskInventory,
) -> Result<CertifiedToken, PreprocessError> {
    let expected_nonce_input = party_preprocess_input_from_distributed_nonce_share::<P>(
        session_id,
        signer_set,
        rho,
        nonce_share,
    )?;
    let actual_nonce_input = inputs
        .iter()
        .find(|input| input.party == nonce_share.party)
        .ok_or(PreprocessError::UnknownParty(nonce_share.party))?;
    if actual_nonce_input.highs != expected_nonce_input.highs
        || actual_nonce_input.lows != expected_nonce_input.lows
        || actual_nonce_input.nonce_commitment != expected_nonce_input.nonce_commitment
        || actual_nonce_input.randomness_commitment != expected_nonce_input.randomness_commitment
        || (!actual_nonce_input.y_share.is_empty()
            && actual_nonce_input.y_share != expected_nonce_input.y_share)
    {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }

    let statement = preprocessing_certification_runtime_statement_from_envelopes::<P>(
        session_id,
        inputs.clone(),
        envelopes.clone(),
        expected_transcript,
    )?;
    masks.validate_for_token(session_id, expected_transcript, P::K * P::N)?;
    let precomputed_w_share = runtime
        .derive_strict_signing_precomputed_w_share_from_distributed_nonce_share::<P>(
            config,
            session_id,
            signer_set,
            rho,
            nonce_share,
        )?;
    let (runtime_proofs, runtime_evidence) = runtime
        .certify_preprocessing_from_fused_private_batch_state::<P>(
            &statement,
            completed_batch_state,
        )?;
    runtime_proofs.transcripts()?;
    let token = certify_opened_masked_broadcasts_with_consistency::<P, V>(
        verifier,
        registry,
        session_id,
        inputs,
        envelopes,
        expected_transcript,
        Some(&runtime_proofs),
    )?;
    let masks = masks.rebind_runtime_transcript_hash(runtime_evidence.transcript_hash)?;
    let helper_mask_provenance = masks
        .provenance()
        .ok_or(PreprocessError::PreprocessingRuntimeMaterialMissing)?;
    let helper_session_id = token.session_id;
    let helper_transcript_hash = token.transcript_hash;
    let token = token
        .with_precomputed_w_share(precomputed_w_share)
        .with_strict_signing_canonical_masks(masks)
        .with_strict_signing_helper_material(strict_signing_helper_material_for_token(
            helper_session_id,
            helper_transcript_hash,
            runtime_evidence.transcript_hash,
            helper_mask_provenance.z_lane_count,
            helper_mask_provenance.hint_lane_count,
        )?);
    let certificate = PreprocessingVectorRuntimeCertificate::for_token(&token, runtime_evidence)?;
    let token = token.with_vector_runtime_certificate(certificate);
    ensure_certified_token_release_valid(&token)?;
    Ok(token)
}

#[cfg(test)]
fn attach_test_strict_signing_runtime_material<P: MlDsaParams>(
    token: CertifiedToken,
) -> Result<CertifiedToken, PreprocessError> {
    let parties = if token.signer_set.is_empty() {
        vec![PartyId(1), PartyId(2), PartyId(3)]
    } else {
        token.signer_set.clone()
    };
    let threshold = u16::try_from(parties.len().div_ceil(2).max(1))
        .map_err(|_| PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
    let config = DkgConfig::new::<P>(threshold, parties.clone(), talus_dkg::KeygenEpoch(9_999))
        .map_err(|_| PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
    let self_party = parties[0];
    let transport_parties = parties.iter().map(|party| party.0).collect::<Vec<_>>();
    let transport = talus_wire::InMemoryTransport::new(self_party.0, transport_parties)
        .map_err(|_| PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
    let state =
        talus_dkg::TransportPrimeFieldMpcStateMachine::new(config.clone(), self_party, transport)
            .map_err(|_| PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
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
    let label = Power2RoundTranscriptLabel::root(&config, token.session_id.0)
        .child("test_release_strict_signing_material");
    let runtime_transcript_hash = preprocessing_certification_runtime_transcript_hash(&token)?;
    let w_share = runtime
        .share_vec_from_local_lanes::<P>(
            &config,
            &label.child("w_precomputed"),
            vec![0; token.w1.len()],
        )
        .map_err(|_| PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
    let z_mask = runtime
        .share_vec_from_local_lanes::<P>(&config, &label.child("z_mask"), vec![0; token.w1.len()])
        .map_err(|_| PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
    let hint_mask = runtime
        .share_vec_from_local_lanes::<P>(
            &config,
            &label.child("hint_mask"),
            vec![0; token.w1.len()],
        )
        .map_err(|_| PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
    let z_bits = (0..23)
        .map(|bit| {
            runtime
                .bit_share_vec_from_local_lanes::<P>(
                    &config,
                    &label.child(format!("z_mask_bit_{bit}")),
                    vec![0; token.w1.len()],
                )
                .map_err(|_| PreprocessError::PreprocessingRuntimeCertificateMismatch)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let hint_bits = (0..23)
        .map(|bit| {
            runtime
                .bit_share_vec_from_local_lanes::<P>(
                    &config,
                    &label.child(format!("hint_mask_bit_{bit}")),
                    vec![0; token.w1.len()],
                )
                .map_err(|_| PreprocessError::PreprocessingRuntimeCertificateMismatch)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let provenance = StrictSigningCanonicalMaskProvenance {
        session_id: token.session_id,
        transcript_hash: token.transcript_hash,
        runtime_transcript_hash,
        z_mask_value_label_hash: z_mask.id().label_hash,
        hint_mask_value_label_hash: hint_mask.id().label_hash,
        z_lane_count: z_mask.len(),
        hint_lane_count: hint_mask.len(),
    };
    let masks = StrictSigningCanonicalMaskInventory::new_with_preprocessing_provenance(
        provenance, z_mask, z_bits, hint_mask, hint_bits,
    )?;
    let helpers = strict_signing_helper_material_for_token(
        token.session_id,
        token.transcript_hash,
        runtime_transcript_hash,
        P::L * P::N,
        P::K * P::N,
    )?;
    Ok(token
        .with_precomputed_w_share(w_share)
        .with_strict_signing_canonical_masks(masks)
        .with_strict_signing_helper_material(helpers))
}

/// Builds and certifies one local preprocessing token with an explicit consistency verifier.
pub fn certify_preprocessing_token_with_consistency<
    P: MlDsaParams,
    V: MaskedBroadcastConsistencyVerifier,
>(
    verifier: &mut V,
    registry: &mut impl SessionStore,
    session_id: SessionId,
    mut inputs: Vec<PartyPreprocessInput>,
) -> Result<CertifiedToken, PreprocessError> {
    inputs.sort_by_key(|input| input.party);
    validate_inputs::<P>(&inputs)?;

    let signer_set: Vec<_> = inputs.iter().map(|input| input.party).collect();
    let transcript_hash = transcript_hash::<P>(session_id, &inputs);
    let mut envelopes = Vec::with_capacity(inputs.len());
    for input in &inputs {
        envelopes.push(prepare_masked_broadcast_envelope::<P>(
            session_id,
            &signer_set,
            input,
            transcript_hash,
        )?);
    }

    certify_opened_masked_broadcasts_with_consistency::<P, V>(
        verifier,
        registry,
        session_id,
        inputs,
        envelopes,
        transcript_hash,
        None,
    )
}

fn certify_opened_masked_broadcasts_with_consistency<
    P: MlDsaParams,
    V: MaskedBroadcastConsistencyVerifier,
>(
    verifier: &mut V,
    registry: &mut impl SessionStore,
    session_id: SessionId,
    mut inputs: Vec<PartyPreprocessInput>,
    envelopes: Vec<BroadcastEnvelope>,
    expected_transcript: TranscriptHash,
    runtime_proofs: Option<&PreprocessingCertificationRuntimeProofs>,
) -> Result<CertifiedToken, PreprocessError> {
    registry.reserve(session_id)?;
    inputs.sort_by_key(|input| input.party);
    validate_inputs::<P>(&inputs)?;

    let signer_set: Vec<_> = inputs.iter().map(|input| input.party).collect();
    let coeff_count = inputs[0].highs.len();
    #[cfg(any(test, feature = "paper-fast-dev"))]
    let mut clear_audits = Vec::with_capacity(inputs.len());
    let mut rhos_by_party = Vec::with_capacity(inputs.len());

    for input in &inputs {
        let prepared = prepare_masked_broadcast_envelope_with_audit::<P>(
            session_id,
            &signer_set,
            input,
            expected_transcript,
        )?;
        let envelope = envelopes
            .iter()
            .find(|envelope| envelope.message.party == input.party)
            .ok_or(PreprocessError::MaskedBroadcastConsistencyMismatch(
                input.party,
            ))?;
        if envelope.message != prepared.envelope.message {
            return Err(PreprocessError::MaskedBroadcastConsistencyMismatch(
                input.party,
            ));
        }
        #[cfg(any(test, feature = "paper-fast-dev"))]
        clear_audits.push(prepared.clear_audit.clone());
        rhos_by_party.push(prepared.rhos);
    }

    let broadcasts = open_broadcasts(session_id, &envelopes, expected_transcript)?;
    let mut masked_broadcast_runtime_hashes = Vec::with_capacity(broadcasts.len());
    for broadcast in &broadcasts {
        #[cfg(any(test, feature = "paper-fast-dev"))]
        let idx = inputs
            .iter()
            .position(|input| input.party == broadcast.party)
            .ok_or(PreprocessError::MaskedBroadcastConsistencyMismatch(
                broadcast.party,
            ))?;
        let envelope = envelopes
            .iter()
            .find(|envelope| envelope.message.party == broadcast.party)
            .ok_or(PreprocessError::MaskedBroadcastConsistencyMismatch(
                broadcast.party,
            ))?;
        let statement = MaskedBroadcastConsistencyStatement {
            session_id,
            signer_set: signer_set.clone(),
            broadcast: broadcast.clone(),
            coeff_count,
        };
        #[cfg(any(test, feature = "paper-fast-dev"))]
        let clear_audit = if verifier.requires_clear_audit() {
            Some(&clear_audits[idx])
        } else {
            None
        };
        #[cfg(any(test, feature = "paper-fast-dev"))]
        verifier.verify_masked_broadcast::<P>(
            &statement,
            &envelope.consistency_proof,
            clear_audit,
        )?;
        #[cfg(not(any(test, feature = "paper-fast-dev")))]
        verifier.verify_masked_broadcast::<P>(&statement, &envelope.consistency_proof)?;
        let parts = decode_masked_broadcast_runtime_proof(&envelope.consistency_proof).ok_or(
            PreprocessError::MaskedBroadcastProofBackendUnavailable(broadcast.party),
        )?;
        masked_broadcast_runtime_hashes.push(parts.runtime_transcript_hash);
    }

    let cef_output = certify_vector_carry_compare_and_cef::<P>(
        session_id,
        expected_transcript,
        &signer_set,
        &inputs,
        &broadcasts,
        &rhos_by_party,
        runtime_proofs,
    )?;

    let nonce_commitments = inputs
        .iter()
        .map(|input| input.nonce_commitment)
        .collect::<Vec<_>>();
    let mut y_share = Vec::new();
    for input in &inputs {
        y_share.extend_from_slice(&input.y_share);
    }
    let certification_evidence = local_pre_challenge_certification_evidence(
        session_id,
        expected_transcript,
        signer_set.len(),
        coeff_count,
        &broadcasts,
        cef_output.carry_compare,
        cef_output.bcc,
        &masked_broadcast_runtime_hashes,
    );
    if let Some(proofs) = runtime_proofs {
        let masked_runtime_transcript = certification_evidence
            .masked_broadcast
            .ok_or(PreprocessError::PreChallengeCertificationIncomplete)?
            .runtime_transcript_hash;
        let masked_output = proofs.outputs.masked_broadcast;
        if masked_runtime_transcript != proofs.masked_broadcast
            || masked_output.signer_count != signer_set.len()
            || masked_output.coeff_count != coeff_count
            || masked_output.runtime_transcript_hash != masked_runtime_transcript
            || masked_output.material_state_hash == [0u8; 32]
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
    }
    let certification_policy =
        ensure_pre_challenge_certification_evidence(session_id, &certification_evidence)?;

    Ok(CertifiedToken {
        session_id,
        signer_set,
        w1: cef_output.w1,
        nonce_commitments,
        transcript_hash: expected_transcript,
        y_share: Zeroizing::new(y_share),
        precomputed_w_share: None,
        strict_signing_masks: None,
        strict_signing_helpers: None,
        broadcasts,
        certification_evidence,
        certification_policy,
        vector_runtime_certificate: None,
    })
}

fn preprocessing_certification_runtime_statement_from_envelopes<P: MlDsaParams>(
    session_id: SessionId,
    mut inputs: Vec<PartyPreprocessInput>,
    envelopes: Vec<BroadcastEnvelope>,
    expected_transcript: TranscriptHash,
) -> Result<PreprocessingCertificationRuntimeStatement, PreprocessError> {
    inputs.sort_by_key(|input| input.party);
    validate_inputs::<P>(&inputs)?;
    let signer_set: Vec<_> = inputs.iter().map(|input| input.party).collect();
    let coeff_count = inputs[0].highs.len();
    let mut rhos_by_party = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let prepared = prepare_masked_broadcast_envelope_with_audit::<P>(
            session_id,
            &signer_set,
            input,
            expected_transcript,
        )?;
        let envelope = envelopes
            .iter()
            .find(|envelope| envelope.message.party == input.party)
            .ok_or(PreprocessError::MaskedBroadcastConsistencyMismatch(
                input.party,
            ))?;
        if envelope.message != prepared.envelope.message {
            return Err(PreprocessError::MaskedBroadcastConsistencyMismatch(
                input.party,
            ));
        }
        rhos_by_party.push(prepared.rhos);
    }
    let broadcasts = open_broadcasts(session_id, &envelopes, expected_transcript)?;
    let mut masked_broadcast_runtime_hashes = Vec::with_capacity(broadcasts.len());
    let mut masked_broadcast_bindings = Vec::with_capacity(broadcasts.len());
    for broadcast in &broadcasts {
        let envelope = envelopes
            .iter()
            .find(|envelope| envelope.message.party == broadcast.party)
            .ok_or(PreprocessError::MaskedBroadcastConsistencyMismatch(
                broadcast.party,
            ))?;
        let parts = decode_masked_broadcast_runtime_proof(&envelope.consistency_proof).ok_or(
            PreprocessError::MaskedBroadcastProofBackendUnavailable(broadcast.party),
        )?;
        masked_broadcast_runtime_hashes.push(parts.runtime_transcript_hash);
        masked_broadcast_bindings.push(MaskedBroadcastRuntimeBinding {
            party: broadcast.party,
            statement_hash: parts.statement_hash,
            runtime_transcript_hash: parts.runtime_transcript_hash,
        });
    }
    let cef_output = certify_vector_carry_compare_and_cef::<P>(
        session_id,
        expected_transcript,
        &signer_set,
        &inputs,
        &broadcasts,
        &rhos_by_party,
        None,
    )?;
    let w1_hash =
        hash_runtime_w1_output::<P>(session_id, expected_transcript, &signer_set, &cef_output.w1);
    let (carry_compare_public_input_hash, cef_bcc_public_input_hash) =
        preprocessing_public_circuit_input_hashes::<P>(
            session_id,
            expected_transcript,
            &signer_set,
            &broadcasts,
        )?;
    let (carry_compare_private_circuit_label_hash, cef_bcc_private_circuit_label_hash) =
        preprocessing_private_circuit_label_hashes(session_id, expected_transcript);
    Ok(PreprocessingCertificationRuntimeStatement {
        session_id,
        transcript_hash: expected_transcript,
        signer_set,
        coeff_count,
        masked_broadcast_runtime_transcript: masked_broadcast_runtime_transcript_hash(
            session_id,
            expected_transcript,
            inputs.len(),
            coeff_count,
            &masked_broadcast_runtime_hashes,
        ),
        masked_broadcast_bindings,
        carry_compare_evidence_hash: cef_output.carry_compare.evidence_hash,
        bcc_evidence_hash: cef_output.bcc.evidence_hash,
        w1_hash,
        carry_compare_public_input_hash,
        cef_bcc_public_input_hash,
        carry_compare_private_circuit_label_hash,
        cef_bcc_private_circuit_label_hash,
    })
}

/// Computes one signer's masked broadcast envelope for commit/open delivery.
///
/// The input `highs`/`lows` are the signer's local unsigned decomposition of
/// its `A*y_i` contribution. The returned envelope contains only the masked
/// high/low values, public commitments, transcript hash, and salt; it is the
/// object committed in the commit round and opened through reliable broadcast
/// in the open round.
pub fn prepare_masked_broadcast_envelope<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
    input: &PartyPreprocessInput,
    transcript_hash: TranscriptHash,
) -> Result<BroadcastEnvelope, PreprocessError> {
    Ok(prepare_masked_broadcast_envelope_with_audit::<P>(
        session_id,
        signer_set,
        input,
        transcript_hash,
    )?
    .envelope)
}

/// Computes one signer's masked broadcast envelope with a precomputed runtime
/// proof transcript hash.
///
/// This lower-level helper is intentionally crate-private. Normal callers use
/// `prepare_masked_broadcast_envelope_with_vector_runtime_evidence`, which
/// derives the transcript hash from durable vector runtime evidence instead of
/// accepting arbitrary bytes.
fn prepare_masked_broadcast_envelope_with_runtime_transcript<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
    input: &PartyPreprocessInput,
    transcript_hash: TranscriptHash,
    runtime_transcript_hash: [u8; 32],
) -> Result<BroadcastEnvelope, PreprocessError> {
    let mut prepared = prepare_masked_broadcast_envelope_with_audit::<P>(
        session_id,
        signer_set,
        input,
        transcript_hash,
    )?
    .envelope;
    if runtime_transcript_hash == [0u8; 32] {
        return Err(PreprocessError::MaskedBroadcastProofBackendUnavailable(
            input.party,
        ));
    }
    let statement = MaskedBroadcastConsistencyStatement {
        session_id,
        signer_set: canonical_signer_set(signer_set)?,
        broadcast: prepared.message.clone(),
        coeff_count: input.highs.len(),
    };
    prepared.consistency_proof =
        production_masked_broadcast_consistency_proof_with_runtime_transcript::<P>(
            &statement,
            runtime_transcript_hash,
        );
    Ok(prepared)
}

/// Computes one signer's masked broadcast envelope with a proof transcript
/// derived from durable vector IT-MPC runtime evidence.
///
/// Release callers using `ProductionPreprocessingCertificationRuntime` should
/// prefer this helper over passing arbitrary transcript hashes. The production
/// runtime adapter verifies that every envelope proof uses this derivation
/// before it emits CarryCompare/BCC stage proofs.
pub fn prepare_masked_broadcast_envelope_with_vector_runtime_evidence<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
    input: &PartyPreprocessInput,
    transcript_hash: TranscriptHash,
    vector_runtime_evidence: &ProductionVectorItMpcRuntimeEvidence,
) -> Result<BroadcastEnvelope, PreprocessError> {
    let prepared = prepare_masked_broadcast_envelope_with_audit::<P>(
        session_id,
        signer_set,
        input,
        transcript_hash,
    )?
    .envelope;
    let statement = MaskedBroadcastConsistencyStatement {
        session_id,
        signer_set: canonical_signer_set(signer_set)?,
        broadcast: prepared.message.clone(),
        coeff_count: input.highs.len(),
    };
    let statement_hash = masked_broadcast_statement_hash::<P>(&statement);
    let runtime_transcript_hash =
        masked_broadcast_runtime_transcript_hash_from_vector_runtime_evidence(
            session_id,
            transcript_hash,
            signer_set.len(),
            input.highs.len(),
            statement_hash,
            input.party,
            vector_runtime_evidence.transcript_hash,
        );
    prepare_masked_broadcast_envelope_with_runtime_transcript::<P>(
        session_id,
        signer_set,
        input,
        transcript_hash,
        runtime_transcript_hash,
    )
}

fn prepare_masked_broadcast_envelope_with_audit<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
    input: &PartyPreprocessInput,
    transcript_hash: TranscriptHash,
) -> Result<PreparedMaskedBroadcast, PreprocessError> {
    let signer_set = canonical_signer_set(signer_set)?;
    if !signer_set.contains(&input.party) {
        return Err(PreprocessError::UnknownParty(input.party));
    }
    validate_inputs::<P>(core::slice::from_ref(input))?;
    let party_idx = signer_set
        .iter()
        .position(|party| *party == input.party)
        .ok_or(PreprocessError::UnknownParty(input.party))?;
    let coeff_count = input.highs.len();
    let high_masks = high_masks::<P>(session_id, &signer_set, party_idx, coeff_count);
    let rhos = rhos::<P>(session_id, &signer_set, input, coeff_count);
    let high_mod = P::HIGH_MOD as u32;
    let masked_highs = input
        .highs
        .iter()
        .zip(&high_masks)
        .map(|(&high, &mask)| (high + mask) % high_mod)
        .collect::<Vec<_>>();
    let masked_lows = input
        .lows
        .iter()
        .zip(&rhos)
        .map(|(&low, &rho)| low + rho)
        .collect::<Vec<_>>();
    let message = MaskedBroadcast {
        party: input.party,
        masked_highs,
        masked_lows,
        nonce_commitment: input.nonce_commitment,
        rho_bits_commitment: input.randomness_commitment,
        transcript_hash,
    };
    let statement = MaskedBroadcastConsistencyStatement {
        session_id,
        signer_set: signer_set.clone(),
        broadcast: message.clone(),
        coeff_count,
    };
    let salt = salt(session_id, input.party);
    let commitment = masked_broadcast_commitment(session_id, &message, salt);
    let consistency_proof = production_masked_broadcast_consistency_proof::<P>(&statement);
    #[cfg(any(test, feature = "paper-fast-dev"))]
    let clear_audit = MaskedBroadcastClearAudit {
        highs: input.highs.clone(),
        lows: input.lows.clone(),
        high_masks,
        rhos: rhos.clone(),
        rho_bits_commitment: input.randomness_commitment,
    };
    Ok(PreparedMaskedBroadcast {
        envelope: BroadcastEnvelope {
            commitment,
            message,
            consistency_proof,
            salt,
        },
        rhos,
        #[cfg(any(test, feature = "paper-fast-dev"))]
        clear_audit,
    })
}

fn unmask_preprocess_input_from_broadcast<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
    broadcast: &MaskedBroadcast,
) -> Result<PartyPreprocessInput, PreprocessError> {
    let signer_set = canonical_signer_set(signer_set)?;
    let party_idx = signer_set
        .iter()
        .position(|party| *party == broadcast.party)
        .ok_or(PreprocessError::UnknownParty(broadcast.party))?;
    if broadcast.masked_highs.len() != broadcast.masked_lows.len() {
        return Err(PreprocessError::CoeffCountMismatch);
    }
    let coeff_count = broadcast.masked_highs.len();
    let high_mod = P::HIGH_MOD as u32;
    let high_masks = high_masks::<P>(session_id, &signer_set, party_idx, coeff_count);
    let seed_input = PartyPreprocessInput {
        party: broadcast.party,
        highs: vec![0; coeff_count],
        lows: vec![0; coeff_count],
        y_share: Vec::new(),
        ay_contribution: None,
        nonce_commitment: broadcast.nonce_commitment,
        randomness_commitment: broadcast.rho_bits_commitment,
    };
    let rhos = rhos::<P>(session_id, &signer_set, &seed_input, coeff_count);
    let mut highs = Vec::with_capacity(coeff_count);
    let mut lows = Vec::with_capacity(coeff_count);
    for coeff in 0..coeff_count {
        let high = (broadcast.masked_highs[coeff] + high_mod - high_masks[coeff]) % high_mod;
        let low = broadcast.masked_lows[coeff]
            .checked_sub(rhos[coeff])
            .ok_or(PreprocessError::InvalidLow {
                party: broadcast.party,
                value: broadcast.masked_lows[coeff],
            })?;
        highs.push(high);
        lows.push(low);
    }
    let input = PartyPreprocessInput {
        party: broadcast.party,
        highs,
        lows,
        y_share: Vec::new(),
        ay_contribution: None,
        nonce_commitment: broadcast.nonce_commitment,
        randomness_commitment: broadcast.rho_bits_commitment,
    };
    validate_inputs::<P>(core::slice::from_ref(&input))?;
    Ok(input)
}

/// Verifies and opens simultaneous masked-broadcast envelopes.
pub fn open_broadcasts(
    session_id: SessionId,
    envelopes: &[BroadcastEnvelope],
    expected_transcript: TranscriptHash,
) -> Result<Vec<MaskedBroadcast>, PreprocessError> {
    let mut broadcasts = Vec::with_capacity(envelopes.len());

    for envelope in envelopes {
        let recomputed = masked_broadcast_commitment(session_id, &envelope.message, envelope.salt);
        if recomputed != envelope.commitment {
            return Err(PreprocessError::CommitmentMismatch(envelope.message.party));
        }
        if envelope.message.transcript_hash != expected_transcript {
            return Err(PreprocessError::TranscriptMismatch(envelope.message.party));
        }
        if broadcasts
            .iter()
            .any(|seen: &MaskedBroadcast| seen.party == envelope.message.party)
        {
            return Err(PreprocessError::DuplicateParty(envelope.message.party));
        }
        broadcasts.push(envelope.message.clone());
    }

    broadcasts.sort_by_key(|broadcast| broadcast.party);
    Ok(broadcasts)
}

fn verify_private_certified_masked_broadcast<P: MlDsaParams>(
    statement: &MaskedBroadcastConsistencyStatement,
    proof: &MaskedBroadcastConsistencyProof,
) -> Result<(), PreprocessError> {
    let parts = decode_masked_broadcast_runtime_proof(proof).ok_or(
        PreprocessError::MaskedBroadcastProofBackendUnavailable(statement.broadcast.party),
    )?;
    let expected = expected_masked_broadcast_runtime_proof_parts::<P>(statement);
    if parts.statement_hash != expected.statement_hash
        || parts.coeff_count != expected.coeff_count
        || parts.signer_count != expected.signer_count
        || parts.runtime_transcript_hash == [0u8; 32]
    {
        return Err(PreprocessError::MaskedBroadcastProofBackendUnavailable(
            statement.broadcast.party,
        ));
    }
    if statement.broadcast.masked_highs.len() != statement.coeff_count
        || statement.broadcast.masked_lows.len() != statement.coeff_count
    {
        return Err(PreprocessError::MaskedBroadcastConsistencyMismatch(
            statement.broadcast.party,
        ));
    }
    let decoded = unmask_preprocess_input_from_broadcast::<P>(
        statement.session_id,
        &statement.signer_set,
        &statement.broadcast,
    )?;
    let prepared = prepare_masked_broadcast_envelope::<P>(
        statement.session_id,
        &statement.signer_set,
        &decoded,
        statement.broadcast.transcript_hash,
    )?;
    if prepared.message != statement.broadcast {
        return Err(PreprocessError::MaskedBroadcastConsistencyMismatch(
            statement.broadcast.party,
        ));
    }
    Ok(())
}

fn certify_vector_carry_compare_and_cef<P: MlDsaParams>(
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_set: &[PartyId],
    inputs: &[PartyPreprocessInput],
    broadcasts: &[MaskedBroadcast],
    rhos_by_party: &[Vec<u32>],
    runtime_proofs: Option<&PreprocessingCertificationRuntimeProofs>,
) -> Result<CertifiedCefOutput, PreprocessError> {
    if broadcasts.is_empty()
        || broadcasts.len() != signer_set.len()
        || inputs.len() != signer_set.len()
        || broadcasts.len() != rhos_by_party.len()
    {
        return Err(PreprocessError::CoeffCountMismatch);
    }
    let coeff_count = broadcasts[0].masked_highs.len();
    let alpha = P::alpha() as u64;
    let gamma2 = P::GAMMA2 as i64;
    let high_mod = P::HIGH_MOD as u64;
    let mut w1 = Vec::with_capacity(coeff_count);
    let mut kappas = Vec::with_capacity(coeff_count);
    let mut deltas = Vec::with_capacity(coeff_count);
    let mut rho_sums = Vec::with_capacity(coeff_count);
    let mut low_sums = Vec::with_capacity(coeff_count);
    let mut t_values = Vec::with_capacity(coeff_count);
    for coeff in 0..coeff_count {
        let mut sum_high = 0u64;
        let mut b = 0u64;
        let mut r = 0u64;
        for (party_index, broadcast) in broadcasts.iter().enumerate() {
            if broadcast.masked_highs.len() != coeff_count
                || broadcast.masked_lows.len() != coeff_count
                || rhos_by_party[party_index].len() != coeff_count
            {
                return Err(PreprocessError::CoeffCountMismatch);
            }
            sum_high = (sum_high + u64::from(broadcast.masked_highs[coeff])) % high_mod;
            b += u64::from(broadcast.masked_lows[coeff]);
            r += u64::from(rhos_by_party[party_index][coeff]);
        }
        if r >= alpha {
            return Err(PreprocessError::CarryCompareCertificationFailed);
        }
        let clear_low_sum = b
            .checked_sub(r)
            .ok_or(PreprocessError::CarryCompareCertificationFailed)?;
        let w_coeff = reduce_mod_q_i64::<P>((alpha * sum_high) as i64 + clear_low_sum as i64);
        if !bcc_holds_coeff::<P>(w_coeff) {
            return Err(PreprocessError::BoundaryClearanceFailed);
        }
        let t = b % alpha;
        let kappa = u64::from(r > t);
        let delta_threshold = t as i64 - gamma2 + (kappa as i64) * alpha as i64;
        let delta = u64::from((r as i64) < delta_threshold);
        let high = (sum_high + (b / alpha) + delta + high_mod - kappa) % high_mod;

        w1.push(high as u32);
        kappas.push(kappa as u8);
        deltas.push(delta as u8);
        rho_sums.push(r);
        low_sums.push(b);
        t_values.push(t);
    }

    let carry_hash = hash_vector_carry_compare_evidence::<P>(
        session_id,
        transcript_hash,
        signer_set,
        broadcasts,
        &rho_sums,
        &low_sums,
        &t_values,
        &kappas,
        &deltas,
    );
    let bcc_hash =
        hash_vector_bcc_cef_evidence::<P>(session_id, transcript_hash, signer_set, &w1, carry_hash);
    let carry_runtime_hash = if let Some(proofs) = runtime_proofs {
        verify_preprocessing_stage_runtime_proof::<P>(
            PreprocessingCertificationStage::CarryCompare,
            session_id,
            transcript_hash,
            signer_set.len(),
            coeff_count,
            carry_hash,
            &proofs.carry_compare,
        )?
    } else {
        preprocessing_stage_runtime_transcript_hash(
            b"carry-compare",
            session_id,
            transcript_hash,
            coeff_count,
            carry_hash,
        )
    };
    let bcc_runtime_hash = if let Some(proofs) = runtime_proofs {
        verify_preprocessing_stage_runtime_proof::<P>(
            PreprocessingCertificationStage::Bcc,
            session_id,
            transcript_hash,
            signer_set.len(),
            coeff_count,
            bcc_hash,
            &proofs.bcc,
        )?
    } else {
        preprocessing_stage_runtime_transcript_hash(
            b"cef-bcc",
            session_id,
            transcript_hash,
            coeff_count,
            bcc_hash,
        )
    };
    if carry_runtime_hash == [0u8; 32] || bcc_runtime_hash == [0u8; 32] {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    if let Some(proofs) = runtime_proofs {
        verify_preprocessing_runtime_outputs(
            proofs.outputs(),
            coeff_count,
            carry_hash,
            bcc_hash,
            hash_runtime_w1_output::<P>(session_id, transcript_hash, signer_set, &w1),
            carry_runtime_hash,
            bcc_runtime_hash,
        )?;
    }
    Ok(CertifiedCefOutput {
        w1,
        carry_compare: CarryCompareCertificationEvidence {
            session_id,
            coeff_count,
            evidence_hash: carry_hash,
            runtime_transcript_hash: carry_runtime_hash,
        },
        bcc: BccCertificationEvidence {
            session_id,
            coeff_count,
            evidence_hash: bcc_hash,
            runtime_transcript_hash: bcc_runtime_hash,
        },
    })
}

fn strict_signing_precomputed_w_label(
    config: &DkgConfig,
    session_id: SessionId,
) -> Power2RoundTranscriptLabel {
    Power2RoundTranscriptLabel::root(config, session_id.0)
        .child("preprocessing")
        .child("strict_signing_precomputed_w")
}

fn strict_signing_weighted_nonce_y_label(
    config: &DkgConfig,
    session_id: SessionId,
) -> Power2RoundTranscriptLabel {
    Power2RoundTranscriptLabel::root(config, session_id.0)
        .child("preprocessing")
        .child("strict_signing_weighted_nonce_y")
}

#[cfg(any(test, feature = "scaffold-dev"))]
fn strict_signing_precomputed_w_lanes_from_opened_preprocessing<P: MlDsaParams>(
    statement: &PreprocessingCertificationRuntimeStatement,
    broadcasts: &[MaskedBroadcast],
) -> Result<Vec<Coeff>, PreprocessError> {
    if broadcasts.is_empty()
        || broadcasts.len() != statement.signer_set.len()
        || statement.coeff_count == 0
    {
        return Err(PreprocessError::CoeffCountMismatch);
    }
    let high_mod = P::HIGH_MOD as u64;
    let alpha = P::alpha() as u64;
    let mut lanes = Vec::with_capacity(statement.coeff_count);
    let mut rhos_by_party = Vec::with_capacity(statement.signer_set.len());
    for party in &statement.signer_set {
        let broadcast = broadcasts
            .iter()
            .find(|broadcast| broadcast.party == *party)
            .ok_or(PreprocessError::MaskedBroadcastConsistencyMismatch(*party))?;
        if broadcast.masked_highs.len() != statement.coeff_count
            || broadcast.masked_lows.len() != statement.coeff_count
            || broadcast.transcript_hash != statement.transcript_hash
        {
            return Err(PreprocessError::MaskedBroadcastConsistencyMismatch(*party));
        }
        let seed_input = PartyPreprocessInput {
            party: *party,
            highs: vec![0; statement.coeff_count],
            lows: vec![0; statement.coeff_count],
            y_share: Vec::new(),
            ay_contribution: None,
            nonce_commitment: broadcast.nonce_commitment,
            randomness_commitment: broadcast.rho_bits_commitment,
        };
        rhos_by_party.push(rhos::<P>(
            statement.session_id,
            &statement.signer_set,
            &seed_input,
            statement.coeff_count,
        ));
    }
    for coeff in 0..statement.coeff_count {
        let mut sum_high = 0u64;
        let mut masked_low_sum = 0u64;
        let mut rho_sum = 0u64;
        for (party_index, party) in statement.signer_set.iter().enumerate() {
            let broadcast = broadcasts
                .iter()
                .find(|broadcast| broadcast.party == *party)
                .ok_or(PreprocessError::MaskedBroadcastConsistencyMismatch(*party))?;
            sum_high = (sum_high + u64::from(broadcast.masked_highs[coeff])) % high_mod;
            masked_low_sum = masked_low_sum
                .checked_add(u64::from(broadcast.masked_lows[coeff]))
                .ok_or(PreprocessError::CarryCompareCertificationFailed)?;
            rho_sum = rho_sum
                .checked_add(u64::from(rhos_by_party[party_index][coeff]))
                .ok_or(PreprocessError::CarryCompareCertificationFailed)?;
        }
        let clear_low_sum = masked_low_sum
            .checked_sub(rho_sum)
            .ok_or(PreprocessError::CarryCompareCertificationFailed)?;
        lanes.push(reduce_mod_q_i64::<P>(
            (alpha * sum_high) as i64 + clear_low_sum as i64,
        ));
    }
    Ok(lanes)
}

fn verify_preprocessing_runtime_outputs(
    outputs: PreprocessingCertificationRuntimeOutputs,
    coeff_count: usize,
    carry_hash: [u8; 32],
    bcc_hash: [u8; 32],
    w1_hash: [u8; 32],
    carry_runtime_hash: [u8; 32],
    bcc_runtime_hash: [u8; 32],
) -> Result<(), PreprocessError> {
    if outputs.carry_compare.coeff_count != coeff_count
        || outputs.carry_compare.evidence_hash != carry_hash
        || outputs.carry_compare.runtime_transcript_hash != carry_runtime_hash
        || outputs.cef_bcc.coeff_count != coeff_count
        || outputs.cef_bcc.w1_hash != w1_hash
        || outputs.cef_bcc.carry_compare_evidence_hash != carry_hash
        || outputs.cef_bcc.bcc_evidence_hash != bcc_hash
        || outputs.cef_bcc.runtime_transcript_hash != bcc_runtime_hash
        || !outputs.cef_bcc.token_admitted
    {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    Ok(())
}

fn hash_vector_carry_compare_evidence<P: MlDsaParams>(
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_set: &[PartyId],
    broadcasts: &[MaskedBroadcast],
    rho_sums: &[u64],
    low_sums: &[u64],
    t_values: &[u64],
    kappas: &[u8],
    deltas: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS vector IT-MPC CarryCompare certification v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(session_id.0);
    hasher.update(transcript_hash.0);
    for party in signer_set {
        hasher.update(party.0.to_le_bytes());
    }
    for broadcast in broadcasts {
        hasher.update(broadcast.party.0.to_le_bytes());
        hasher.update(broadcast.nonce_commitment.0);
        hasher.update(broadcast.rho_bits_commitment.0);
        hasher.update(broadcast.transcript_hash.0);
        for &high in &broadcast.masked_highs {
            hasher.update(high.to_le_bytes());
        }
        for &low in &broadcast.masked_lows {
            hasher.update(low.to_le_bytes());
        }
    }
    for &value in rho_sums {
        hasher.update(value.to_le_bytes());
    }
    for &value in low_sums {
        hasher.update(value.to_le_bytes());
    }
    for &value in t_values {
        hasher.update(value.to_le_bytes());
    }
    hasher.update(kappas);
    hasher.update(deltas);
    hasher.finalize().into()
}

fn hash_vector_bcc_cef_evidence<P: MlDsaParams>(
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_set: &[PartyId],
    w1: &[u32],
    carry_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS vector CEF/BCC certification v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(session_id.0);
    hasher.update(transcript_hash.0);
    hasher.update(carry_hash);
    for party in signer_set {
        hasher.update(party.0.to_le_bytes());
    }
    for &coeff in w1 {
        hasher.update(coeff.to_le_bytes());
    }
    hasher.finalize().into()
}

fn hash_runtime_w1_output<P: MlDsaParams>(
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_set: &[PartyId],
    w1: &[u32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing runtime w1 output v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(session_id.0);
    hasher.update(transcript_hash.0);
    for party in signer_set {
        hasher.update(party.0.to_le_bytes());
    }
    for &coeff in w1 {
        hasher.update(coeff.to_le_bytes());
    }
    hasher.finalize().into()
}

fn preprocessing_public_circuit_input_hashes<P: MlDsaParams>(
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_set: &[PartyId],
    broadcasts: &[MaskedBroadcast],
) -> Result<([u8; 32], [u8; 32]), PreprocessError> {
    let coeff_count = broadcasts
        .first()
        .ok_or(PreprocessError::CoeffCountMismatch)?
        .masked_highs
        .len();
    if broadcasts.len() != signer_set.len() {
        return Err(PreprocessError::CoeffCountMismatch);
    }
    let alpha = P::alpha() as u64;
    let high_mod = P::HIGH_MOD as u64;
    let mut low_sums = Vec::with_capacity(coeff_count);
    let mut high_sums = Vec::with_capacity(coeff_count);
    let mut t_values = Vec::with_capacity(coeff_count);
    for coeff in 0..coeff_count {
        let mut low_sum = 0u64;
        let mut high_sum = 0u64;
        for broadcast in broadcasts {
            if broadcast.masked_highs.len() != coeff_count
                || broadcast.masked_lows.len() != coeff_count
            {
                return Err(PreprocessError::CoeffCountMismatch);
            }
            low_sum = low_sum.saturating_add(u64::from(broadcast.masked_lows[coeff]));
            high_sum = (high_sum + u64::from(broadcast.masked_highs[coeff])) % high_mod;
        }
        low_sums.push(low_sum);
        high_sums.push(high_sum);
        t_values.push(low_sum % alpha);
    }
    let carry = hash_preprocessing_carry_public_inputs::<P>(
        session_id,
        transcript_hash,
        signer_set,
        coeff_count,
        &low_sums,
        &t_values,
    );
    let cef_bcc = hash_preprocessing_cef_bcc_public_inputs::<P>(
        session_id,
        transcript_hash,
        signer_set,
        coeff_count,
        &high_sums,
        &low_sums,
        &t_values,
    );
    Ok((carry, cef_bcc))
}

fn preprocessing_carry_thresholds_from_broadcasts<P: MlDsaParams>(
    statement: &PreprocessingCertificationRuntimeStatement,
    broadcasts: &[MaskedBroadcast],
) -> Result<Vec<Coeff>, PreprocessError> {
    if broadcasts.len() != statement.signer_set.len() {
        return Err(PreprocessError::CoeffCountMismatch);
    }
    let alpha = P::alpha() as u64;
    let mut thresholds = Vec::with_capacity(statement.coeff_count);
    for coeff in 0..statement.coeff_count {
        let mut low_sum = 0u64;
        for broadcast in broadcasts {
            if broadcast.masked_lows.len() != statement.coeff_count
                || broadcast.masked_highs.len() != statement.coeff_count
            {
                return Err(PreprocessError::CoeffCountMismatch);
            }
            low_sum = low_sum.saturating_add(u64::from(broadcast.masked_lows[coeff]));
        }
        thresholds.push((low_sum % alpha) as Coeff);
    }
    Ok(thresholds)
}

fn preprocessing_private_material_lanes_from_opened_broadcasts<P: MlDsaParams>(
    statement: &PreprocessingCertificationRuntimeStatement,
    broadcasts: &[MaskedBroadcast],
) -> Result<(Vec<Vec<Coeff>>, Vec<Coeff>, Vec<Coeff>), PreprocessError> {
    if broadcasts.len() != statement.signer_set.len() {
        return Err(PreprocessError::CoeffCountMismatch);
    }
    let alpha = P::alpha() as u64;
    let high_mod = P::HIGH_MOD as u64;
    let carry_width = bit_width_for_preprocessing_public_value(P::alpha() as u32);
    let rhos_by_party = preprocessing_rhos_for_broadcasts::<P>(statement, broadcasts)?;
    let mut rho_sum_bits_by_bit_le = vec![Vec::with_capacity(statement.coeff_count); carry_width];
    let mut cef_correction_bits = Vec::with_capacity(statement.coeff_count);
    let mut bcc_violation_bits = Vec::with_capacity(statement.coeff_count);

    for coeff in 0..statement.coeff_count {
        let mut sum_high = 0u64;
        let mut masked_low_sum = 0u64;
        let mut rho_sum = 0u64;
        for (party_idx, broadcast) in broadcasts.iter().enumerate() {
            if broadcast.masked_highs.len() != statement.coeff_count
                || broadcast.masked_lows.len() != statement.coeff_count
                || rhos_by_party[party_idx].len() != statement.coeff_count
            {
                return Err(PreprocessError::CoeffCountMismatch);
            }
            sum_high = (sum_high + u64::from(broadcast.masked_highs[coeff])) % high_mod;
            masked_low_sum = masked_low_sum.saturating_add(u64::from(broadcast.masked_lows[coeff]));
            rho_sum = rho_sum.saturating_add(u64::from(rhos_by_party[party_idx][coeff]));
        }
        if rho_sum >= alpha {
            return Err(PreprocessError::CarryCompareCertificationFailed);
        }
        for (bit_idx, lanes) in rho_sum_bits_by_bit_le.iter_mut().enumerate() {
            lanes.push(((rho_sum >> bit_idx) & 1) as Coeff);
        }
        let clear_low_sum = masked_low_sum
            .checked_sub(rho_sum)
            .ok_or(PreprocessError::CarryCompareCertificationFailed)?;
        let w_coeff = reduce_mod_q_i64::<P>((alpha * sum_high) as i64 + clear_low_sum as i64);
        let t = masked_low_sum % alpha;
        let kappa = u64::from(rho_sum > t);
        let delta_threshold = t as i64 - P::GAMMA2 as i64 + (kappa as i64) * alpha as i64;
        let delta = u64::from((rho_sum as i64) < delta_threshold);
        cef_correction_bits.push(delta as Coeff);
        bcc_violation_bits.push(if bcc_holds_coeff::<P>(w_coeff) { 0 } else { 1 });
    }
    Ok((
        rho_sum_bits_by_bit_le,
        cef_correction_bits,
        bcc_violation_bits,
    ))
}

fn preprocessing_rhos_for_broadcasts<P: MlDsaParams>(
    statement: &PreprocessingCertificationRuntimeStatement,
    broadcasts: &[MaskedBroadcast],
) -> Result<Vec<Vec<u32>>, PreprocessError> {
    let signer_set = canonical_signer_set(&statement.signer_set)?;
    broadcasts
        .iter()
        .map(|broadcast| {
            if !signer_set.contains(&broadcast.party)
                || broadcast.masked_highs.len() != statement.coeff_count
                || broadcast.masked_lows.len() != statement.coeff_count
                || broadcast.transcript_hash != statement.transcript_hash
            {
                return Err(PreprocessError::CoeffCountMismatch);
            }
            let seed_input = PartyPreprocessInput {
                party: broadcast.party,
                highs: vec![0; statement.coeff_count],
                lows: vec![0; statement.coeff_count],
                y_share: Vec::new(),
                ay_contribution: None,
                nonce_commitment: broadcast.nonce_commitment,
                randomness_commitment: broadcast.rho_bits_commitment,
            };
            Ok(rhos::<P>(
                statement.session_id,
                &signer_set,
                &seed_input,
                statement.coeff_count,
            ))
        })
        .collect()
}

fn ensure_preprocessing_private_material_handle_labels<P: MlDsaParams>(
    statement: &PreprocessingCertificationRuntimeStatement,
    rho_sum_bits_by_bit_le: &[ProductionBitShareVec],
    cef_correction_bits: &[ProductionBitShareVec],
    bcc_violation_bits: &[ProductionBitShareVec],
) -> Result<(), PreprocessError> {
    let carry_width = bit_width_for_preprocessing_public_value(P::alpha() as u32);
    if rho_sum_bits_by_bit_le.len() != carry_width
        || cef_correction_bits.len() != 1
        || bcc_violation_bits.len() != 1
    {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    let root = preprocessing_certification_runtime_label(statement);
    let rho_root = root.child("carry_compare_private").child("rho_sum_bits");
    for (bit_idx, bit) in rho_sum_bits_by_bit_le.iter().enumerate() {
        if bit.len() != statement.coeff_count
            || bit.id().label_hash
                != power2round_label_hash(&rho_root.child(format!("bit_{bit_idx}")))
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
    }
    let cef_label = root
        .child("cef_bcc_private")
        .child("cef_correction_bits")
        .child("delta");
    let cef = &cef_correction_bits[0];
    if cef.len() != statement.coeff_count
        || cef.id().label_hash != power2round_label_hash(&cef_label)
    {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    let bcc_label = root
        .child("cef_bcc_private")
        .child("bcc_violation_bits")
        .child("violation");
    let bcc = &bcc_violation_bits[0];
    if bcc.len() != statement.coeff_count
        || bcc.id().label_hash != power2round_label_hash(&bcc_label)
    {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    Ok(())
}

fn ensure_preprocessing_runtime_private_mpc_input_labels<P: MlDsaParams>(
    statement: &PreprocessingCertificationRuntimeStatement,
    masked_broadcast_relation_bits: &[ProductionBitShareVec],
    rho_sum_bits_by_bit_le: &[ProductionBitShareVec],
    cef_correction_bits: &[ProductionBitShareVec],
    bcc_violation_bits: &[ProductionBitShareVec],
) -> Result<(), PreprocessError> {
    ensure_preprocessing_masked_broadcast_relation_labels(
        statement,
        masked_broadcast_relation_bits,
    )?;
    ensure_preprocessing_private_material_handle_labels::<P>(
        statement,
        rho_sum_bits_by_bit_le,
        cef_correction_bits,
        bcc_violation_bits,
    )
}

fn ensure_preprocessing_masked_broadcast_relation_labels(
    statement: &PreprocessingCertificationRuntimeStatement,
    masked_broadcast_relation_bits: &[ProductionBitShareVec],
) -> Result<(), PreprocessError> {
    if masked_broadcast_relation_bits.len() != statement.signer_set.len() {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    let root = preprocessing_certification_runtime_label(statement);
    let relation_root = root
        .child("masked_broadcast_private")
        .child("relation_violation_bits");
    for (idx, (party, bit)) in statement
        .signer_set
        .iter()
        .zip(masked_broadcast_relation_bits)
        .enumerate()
    {
        let expected = relation_root.child(format!("party_{}_violation_{idx}", party.0));
        if bit.len() != statement.coeff_count
            || bit.id().label_hash != power2round_label_hash(&expected)
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
    }
    Ok(())
}

fn hash_preprocessing_carry_public_inputs<P: MlDsaParams>(
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_set: &[PartyId],
    coeff_count: usize,
    low_sums: &[u64],
    t_values: &[u64],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing CarryCompare public circuit inputs v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(session_id.0);
    hasher.update(transcript_hash.0);
    hasher.update((coeff_count as u32).to_le_bytes());
    hasher.update((P::alpha() as u32).to_le_bytes());
    for party in signer_set {
        hasher.update(party.0.to_le_bytes());
    }
    for &value in low_sums {
        hasher.update(value.to_le_bytes());
    }
    for &value in t_values {
        hasher.update(value.to_le_bytes());
    }
    hasher.finalize().into()
}

fn hash_preprocessing_cef_bcc_public_inputs<P: MlDsaParams>(
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_set: &[PartyId],
    coeff_count: usize,
    high_sums: &[u64],
    low_sums: &[u64],
    t_values: &[u64],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing CEF/BCC public circuit inputs v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(session_id.0);
    hasher.update(transcript_hash.0);
    hasher.update((coeff_count as u32).to_le_bytes());
    hasher.update((P::alpha() as u32).to_le_bytes());
    hasher.update((P::HIGH_MOD as u32).to_le_bytes());
    hasher.update(P::GAMMA2.to_le_bytes());
    for party in signer_set {
        hasher.update(party.0.to_le_bytes());
    }
    for &value in high_sums {
        hasher.update(value.to_le_bytes());
    }
    for &value in low_sums {
        hasher.update(value.to_le_bytes());
    }
    for &value in t_values {
        hasher.update(value.to_le_bytes());
    }
    hasher.finalize().into()
}

fn reduce_mod_q_i64<P: MlDsaParams>(value: i64) -> Coeff {
    value.rem_euclid(i64::from(P::Q)) as Coeff
}

fn production_masked_broadcast_consistency_proof<P: MlDsaParams>(
    statement: &MaskedBroadcastConsistencyStatement,
) -> MaskedBroadcastConsistencyProof {
    let parts = expected_masked_broadcast_runtime_proof_parts::<P>(statement);
    production_masked_broadcast_consistency_proof_with_runtime_transcript::<P>(
        statement,
        parts.runtime_transcript_hash,
    )
}

fn production_masked_broadcast_consistency_proof_with_runtime_transcript<P: MlDsaParams>(
    statement: &MaskedBroadcastConsistencyStatement,
    runtime_transcript_hash: [u8; 32],
) -> MaskedBroadcastConsistencyProof {
    let mut parts = expected_masked_broadcast_runtime_proof_parts::<P>(statement);
    parts.runtime_transcript_hash = runtime_transcript_hash;
    let mut bytes = Vec::with_capacity(6 + 32 + 32 + 4 + 4);
    bytes.extend_from_slice(MASKED_BROADCAST_RUNTIME_PROOF_PREFIX);
    bytes.extend_from_slice(&parts.statement_hash);
    bytes.extend_from_slice(&parts.runtime_transcript_hash);
    bytes.extend_from_slice(&(parts.coeff_count as u32).to_le_bytes());
    bytes.extend_from_slice(&(parts.signer_count as u32).to_le_bytes());
    MaskedBroadcastConsistencyProof { bytes }
}

fn expected_masked_broadcast_runtime_proof_parts<P: MlDsaParams>(
    statement: &MaskedBroadcastConsistencyStatement,
) -> MaskedBroadcastRuntimeProofParts {
    let statement_hash = masked_broadcast_statement_hash::<P>(statement);
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS masked broadcast vector runtime transcript binding v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(statement_hash);
    hasher.update(statement.session_id.0);
    hasher.update((statement.coeff_count as u32).to_le_bytes());
    hasher.update((statement.signer_set.len() as u32).to_le_bytes());
    MaskedBroadcastRuntimeProofParts {
        statement_hash,
        runtime_transcript_hash: hasher.finalize().into(),
        coeff_count: statement.coeff_count,
        signer_count: statement.signer_set.len(),
    }
}

fn masked_broadcast_statement_hash<P: MlDsaParams>(
    statement: &MaskedBroadcastConsistencyStatement,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS masked broadcast consistency statement v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(statement.session_id.0);
    hasher.update((statement.coeff_count as u32).to_le_bytes());
    for party in &statement.signer_set {
        hasher.update(party.0.to_le_bytes());
    }
    hasher.update(statement.broadcast.party.0.to_le_bytes());
    hasher.update(statement.broadcast.nonce_commitment.0);
    hasher.update(statement.broadcast.rho_bits_commitment.0);
    hasher.update(statement.broadcast.transcript_hash.0);
    for &high in &statement.broadcast.masked_highs {
        hasher.update(high.to_le_bytes());
    }
    for &low in &statement.broadcast.masked_lows {
        hasher.update(low.to_le_bytes());
    }
    hasher.finalize().into()
}

fn decode_masked_broadcast_runtime_proof(
    proof: &MaskedBroadcastConsistencyProof,
) -> Option<MaskedBroadcastRuntimeProofParts> {
    const LEN: usize = 6 + 32 + 32 + 4 + 4;
    if proof.bytes.len() != LEN {
        return None;
    }
    if &proof.bytes[..6] != MASKED_BROADCAST_RUNTIME_PROOF_PREFIX {
        return None;
    }
    let mut statement_hash = [0u8; 32];
    statement_hash.copy_from_slice(&proof.bytes[6..38]);
    let mut runtime_transcript_hash = [0u8; 32];
    runtime_transcript_hash.copy_from_slice(&proof.bytes[38..70]);
    let coeff_count = u32::from_le_bytes(proof.bytes[70..74].try_into().ok()?) as usize;
    let signer_count = u32::from_le_bytes(proof.bytes[74..78].try_into().ok()?) as usize;
    Some(MaskedBroadcastRuntimeProofParts {
        statement_hash,
        runtime_transcript_hash,
        coeff_count,
        signer_count,
    })
}

fn validate_inputs<P: MlDsaParams>(inputs: &[PartyPreprocessInput]) -> Result<(), PreprocessError> {
    if inputs.is_empty() {
        return Err(PreprocessError::EmptySignerSet);
    }

    let coeff_count = inputs[0].highs.len();
    for (idx, input) in inputs.iter().enumerate() {
        if inputs[..idx].iter().any(|prev| prev.party == input.party) {
            return Err(PreprocessError::DuplicateParty(input.party));
        }
        if input.highs.len() != coeff_count || input.lows.len() != coeff_count {
            return Err(PreprocessError::CoeffCountMismatch);
        }
        for &high in &input.highs {
            if high >= P::HIGH_MOD as u32 {
                return Err(PreprocessError::InvalidHigh {
                    party: input.party,
                    value: high,
                });
            }
        }
        for &low in &input.lows {
            if low >= P::alpha() as u32 {
                return Err(PreprocessError::InvalidLow {
                    party: input.party,
                    value: low,
                });
            }
        }
    }

    Ok(())
}

fn canonical_signer_set(parties: &[PartyId]) -> Result<Vec<PartyId>, PreprocessError> {
    if parties.is_empty() {
        return Err(PreprocessError::EmptySignerSet);
    }
    let mut sorted = parties.to_vec();
    sorted.sort_unstable();
    for (idx, party) in sorted.iter().enumerate() {
        if sorted[..idx].contains(party) {
            return Err(PreprocessError::DuplicateParty(*party));
        }
    }
    Ok(sorted)
}

fn preprocessing_wire_suite<P: MlDsaParams>() -> SuiteId {
    if P::NAME == MlDsa44::NAME {
        SuiteId::MlDsa44
    } else if P::NAME == MlDsa65::NAME {
        SuiteId::MlDsa65
    } else if P::NAME == MlDsa87::NAME {
        SuiteId::MlDsa87
    } else {
        unreachable!("unsupported ML-DSA parameter set")
    }
}

fn preprocessing_expected_context<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
    keygen_transcript_hash: [u8; 32],
) -> ExpectedContext {
    let parties = signer_set.iter().map(|party| party.0).collect::<Vec<_>>();
    ExpectedContext {
        suite: preprocessing_wire_suite::<P>(),
        keygen_transcript_hash,
        session_id: session_id.0,
        signing_set_hash: signing_set_hash(&parties),
        allowed_parties: parties,
    }
}

fn preprocessing_session_open_hash<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
) -> TranscriptHash {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing session open v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(session_id.0);
    for party in signer_set {
        hasher.update(party.0.to_le_bytes());
    }
    TranscriptHash(hasher.finalize().into())
}

fn map_nonce_dkg_error(_err: DkgError) -> PreprocessError {
    PreprocessError::NonceGenerationFailed
}

fn map_preprocessing_runtime_dkg_error(_err: DkgError) -> PreprocessError {
    PreprocessError::PreprocessingRuntimeCertificateMismatch
}

fn ensure_preprocessing_vector_runtime_evidence_for_release(
    evidence: &ProductionVectorItMpcRuntimeEvidence,
) -> Result<(), PreprocessError> {
    ensure_prime_field_mpc_counters_vectorized_for_release(evidence.counters)
        .map_err(|_| PreprocessError::PreprocessingCountersNotVectorized)?;
    if !evidence.counters.has_durable_runtime_evidence()
        || !evidence.coverage.mul_vec
        || !evidence.coverage.comparison_to_public
        || !evidence.coverage.bit_sum_or_threshold_check
        || !evidence.coverage.preprocessing_masked_broadcast
        || !evidence.coverage.preprocessing_carry_compare
        || !evidence.coverage.preprocessing_cef_bcc
    {
        return Err(PreprocessError::PreprocessingCountersNotVectorized);
    }
    Ok(())
}

fn nonce_residue_modulus<P: MlDsaParams>() -> Result<u32, PreprocessError> {
    let modulus = P::GAMMA1
        .checked_mul(2)
        .ok_or(PreprocessError::NonceGenerationFailed)?;
    if modulus <= 0 || modulus >= P::Q {
        return Err(PreprocessError::NonceGenerationFailed);
    }
    Ok(modulus as u32)
}

fn nonce_residue<P: MlDsaParams>(
    entropy: [u8; 32],
    session_id: SessionId,
    config_hash: [u8; 32],
    dealer: PartyId,
    coefficient_index: usize,
    modulus: u32,
) -> u32 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing distributed nonce residue v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(entropy);
    hasher.update(session_id.0);
    hasher.update(config_hash);
    hasher.update(dealer.0.to_le_bytes());
    hasher.update((coefficient_index as u32).to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    (u64::from_le_bytes(digest[..8].try_into().expect("digest prefix")) % u64::from(modulus)) as u32
}

fn nonce_it_vss_label_index(session_id: SessionId) -> u32 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing nonce IT-VSS label index v1");
    hasher.update(session_id.0);
    let digest: [u8; 32] = hasher.finalize().into();
    u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
}

fn nonce_residues_for_dealer<P: MlDsaParams>(
    options: &DistributedNonceGenerationOptions,
    dealer: PartyId,
) -> Result<Vec<u32>, PreprocessError> {
    if !options.dkg_config.parties.contains(&dealer) {
        return Err(PreprocessError::UnknownParty(dealer));
    }
    let coeff_count = P::L * P::N;
    let modulus = nonce_residue_modulus::<P>()?;
    Ok((0..coeff_count)
        .map(|index| {
            nonce_residue::<P>(
                options.nonce_entropy,
                options.session_id,
                options.dkg_config.transcript_hash().0,
                dealer,
                index,
                modulus,
            )
        })
        .collect())
}

fn nonce_residues_for_all_dealers<P: MlDsaParams>(
    options: &DistributedNonceGenerationOptions,
) -> Result<Vec<Vec<u32>>, PreprocessError> {
    options
        .dkg_config
        .parties
        .iter()
        .copied()
        .map(|dealer| nonce_residues_for_dealer::<P>(options, dealer))
        .collect()
}

fn distributed_nonce_coefficients<P: MlDsaParams>(
    options: &DistributedNonceGenerationOptions,
) -> Result<Vec<Coeff>, PreprocessError> {
    let coeff_count = P::L * P::N;
    let modulus = nonce_residue_modulus::<P>()?;
    let dealer_residues = nonce_residues_for_all_dealers::<P>(options)?;
    let mut nonce_coefficients = Vec::with_capacity(coeff_count);
    for index in 0..coeff_count {
        let sum = dealer_residues
            .iter()
            .fold(0u64, |acc, residues| acc + u64::from(residues[index]))
            % u64::from(modulus);
        let signed = sum as Coeff - (P::GAMMA1 - 1);
        nonce_coefficients.push(reduce_mod_q::<P>(signed));
    }
    Ok(nonce_coefficients)
}

fn distributed_nonce_share_for_party<P: MlDsaParams>(
    options: &DistributedNonceGenerationOptions,
    party: PartyId,
    evidence: &DistributedNonceGenerationEvidence,
) -> Result<DistributedNonceShare, PreprocessError> {
    let nonce_coefficients = distributed_nonce_coefficients::<P>(options)?;
    let party_coeffs = share_nonce_coefficients::<P>(options, &nonce_coefficients)
        .map_err(map_nonce_dkg_error)?
        .into_iter()
        .find(|(candidate, _)| *candidate == party)
        .map(|(_, coeffs)| coeffs)
        .ok_or(PreprocessError::UnknownParty(party))?;
    distributed_nonce_share_from_coeffs::<P>(options, evidence, party, &party_coeffs)
}

fn distributed_nonce_share_from_coeffs<P: MlDsaParams>(
    options: &DistributedNonceGenerationOptions,
    evidence: &DistributedNonceGenerationEvidence,
    party: PartyId,
    coeffs: &[Coeff],
) -> Result<DistributedNonceShare, PreprocessError> {
    let y_share = coeffs_to_nonce_polyvec::<P>(coeffs)?;
    let ay_for_commitment = az_from_rho::<P>(&options.rho, &y_share)
        .map_err(|_| PreprocessError::NonceGenerationFailed)?;
    let nonce_commitment =
        distributed_nonce_commitment::<P>(options.session_id, party, &ay_for_commitment);
    let randomness_commitment =
        distributed_nonce_randomness_commitment::<P>(options.session_id, party, evidence);
    Ok(DistributedNonceShare {
        party,
        y_share,
        nonce_commitment,
        randomness_commitment,
    })
}

fn nonce_it_vss_secret<P: MlDsaParams>(
    options: &DistributedNonceGenerationOptions,
    dealer: PartyId,
    residues: &[u32],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"TALUS preprocessing nonce residues v1");
    out.extend_from_slice(P::NAME.as_bytes());
    out.extend_from_slice(&options.session_id.0);
    out.extend_from_slice(&options.dkg_config.transcript_hash().0);
    out.extend_from_slice(&dealer.0.to_le_bytes());
    out.extend_from_slice(&(residues.len() as u32).to_le_bytes());
    for &residue in residues {
        out.extend_from_slice(&residue.to_le_bytes());
    }
    out
}

fn certify_nonce_residue_contributions<P: MlDsaParams>(
    options: &DistributedNonceGenerationOptions,
    dealer_residues: &[Vec<u32>],
) -> Result<DistributedNonceGenerationEvidence, PreprocessError> {
    let mut prepared = Vec::with_capacity(options.dkg_config.parties.len());
    let label_index = nonce_it_vss_label_index(options.session_id);
    let mut backend = ProductionInformationCheckingVssBackend::with_params(
        options.it_vss_entropy,
        options.it_vss_security,
    )
    .map_err(map_nonce_dkg_error)?;

    for (&dealer, residues) in options.dkg_config.parties.iter().zip(dealer_residues) {
        let label = ItVssSharingLabel::new(
            &options.dkg_config,
            dealer,
            ItVssSharingDomain::NoncePreprocessing,
            Some(label_index),
        )
        .map_err(map_nonce_dkg_error)?;
        let secret = nonce_it_vss_secret::<P>(options, dealer, residues);
        prepared.push((
            label,
            backend
                .prepare_secret::<P>(&options.dkg_config, label, &secret)
                .map_err(map_nonce_dkg_error)?,
        ));
    }

    let mut public_commitments = Vec::with_capacity(prepared.len());
    let mut deliveries = Vec::new();
    for (label, item) in prepared {
        let shares = options
            .dkg_config
            .parties
            .iter()
            .map(|&party| {
                let coin = nonce_public_coin::<P>(options, party, label.label_hash);
                production_it_vss_public_coin_share(
                    &options.dkg_config,
                    label.label_hash,
                    party,
                    coin,
                )
                .map_err(map_nonce_dkg_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let transcript = production_it_vss_public_coin_transcript(
            &options.dkg_config,
            label.label_hash,
            &shares,
        )
        .map_err(map_nonce_dkg_error)?;
        let output = backend
            .finalize_prepared_secret(&options.dkg_config, item, transcript)
            .map_err(map_nonce_dkg_error)?;
        public_commitments.push(output.public_commitment);
        deliveries.extend(output.deliveries);
    }

    let mut complaints = Vec::new();
    for delivery in &deliveries {
        let commitment = public_commitments
            .iter()
            .find(|commitment| {
                commitment.dealer == delivery.dealer && commitment.label_hash == delivery.label_hash
            })
            .ok_or(PreprocessError::NonceGenerationFailed)?;
        if backend
            .verify_private_delivery::<P>(&options.dkg_config, commitment, delivery)
            .is_err()
        {
            complaints.push(
                backend
                    .complaint_for_invalid_delivery::<P>(&options.dkg_config, commitment, delivery)
                    .map_err(map_nonce_dkg_error)?,
            );
        }
    }
    let complaint_resolution = backend
        .resolve_complaints::<P>(&options.dkg_config, &public_commitments, &complaints)
        .map_err(map_nonce_dkg_error)?;
    let public_commitment_hash = hash_nonce_it_vss_public_commitments(&public_commitments);
    let complaint_resolution_hash = hash_it_vss_complaint_resolution(&complaint_resolution);

    Ok(DistributedNonceGenerationEvidence {
        public_commitments,
        complaint_resolution,
        public_commitment_hash,
        complaint_resolution_hash,
    })
}

fn nonce_public_coin<P: MlDsaParams>(
    options: &DistributedNonceGenerationOptions,
    party: PartyId,
    label_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing nonce IT-VSS public coin v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(options.it_vss_entropy);
    hasher.update(options.session_id.0);
    hasher.update(options.dkg_config.transcript_hash().0);
    hasher.update(party.0.to_le_bytes());
    hasher.update(label_hash);
    hasher.finalize().into()
}

fn share_nonce_coefficients<P: MlDsaParams>(
    options: &DistributedNonceGenerationOptions,
    nonce_coefficients: &[Coeff],
) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
    let points = options.dkg_config.interpolation_points::<P>()?;
    let mut out = points
        .iter()
        .map(|(party, _)| (*party, Vec::with_capacity(nonce_coefficients.len())))
        .collect::<Vec<_>>();
    let degree = usize::from(options.dkg_config.threshold.saturating_sub(1));

    for (index, &secret) in nonce_coefficients.iter().enumerate() {
        let mut polynomial = Vec::with_capacity(degree + 1);
        polynomial.push(secret);
        for degree_index in 1..=degree {
            polynomial.push(nonce_shamir_mask::<P>(options, index, degree_index));
        }
        for (receiver_index, (_, point)) in points.iter().enumerate() {
            out[receiver_index]
                .1
                .push(evaluate_shamir_polynomial::<P>(&polynomial, *point)?);
        }
    }

    Ok(out)
}

fn nonce_shamir_mask<P: MlDsaParams>(
    options: &DistributedNonceGenerationOptions,
    coefficient_index: usize,
    degree_index: usize,
) -> Coeff {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing nonce Shamir mask v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(options.nonce_entropy);
    hasher.update(options.session_id.0);
    hasher.update(options.dkg_config.transcript_hash().0);
    hasher.update((coefficient_index as u32).to_le_bytes());
    hasher.update((degree_index as u32).to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    (u64::from_le_bytes(digest[..8].try_into().expect("digest prefix")) % (P::Q as u64)) as Coeff
}

fn coeffs_to_nonce_polyvec<P: MlDsaParams>(coeffs: &[Coeff]) -> Result<PolyVec, PreprocessError> {
    if coeffs.len() != P::L * P::N {
        return Err(PreprocessError::NonceGenerationFailed);
    }
    let polys = coeffs
        .chunks_exact(P::N)
        .map(|chunk| {
            let mut array = [0; 256];
            array.copy_from_slice(chunk);
            Poly::from_coeffs(array)
        })
        .collect::<Vec<_>>();
    Ok(PolyVec::new(polys))
}

fn hash_nonce_it_vss_public_commitments(commitments: &[ItVssPublicCommitment]) -> [u8; 32] {
    let mut hashes = commitments
        .iter()
        .map(hash_it_vss_public_commitment)
        .collect::<Vec<_>>();
    hashes.sort();
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing nonce IT-VSS public commitments v1");
    hasher.update((hashes.len() as u32).to_le_bytes());
    for hash in hashes {
        hasher.update(hash);
    }
    hasher.finalize().into()
}

fn distributed_nonce_commitment<P: MlDsaParams>(
    session_id: SessionId,
    party: PartyId,
    ay_commitment: &PolyVec,
) -> NonceCommitment {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing distributed nonce commitment v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(session_id.0);
    hasher.update(party.0.to_le_bytes());
    hash_polyvec(&mut hasher, ay_commitment);
    NonceCommitment(hasher.finalize().into())
}

fn distributed_nonce_randomness_commitment<P: MlDsaParams>(
    session_id: SessionId,
    party: PartyId,
    evidence: &DistributedNonceGenerationEvidence,
) -> Commitment {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing distributed nonce randomness commitment v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(session_id.0);
    hasher.update(party.0.to_le_bytes());
    hasher.update(evidence.public_commitment_hash);
    hasher.update(evidence.complaint_resolution_hash);
    Commitment(hasher.finalize().into())
}

fn distributed_nonce_preprocess_randomness_commitment<P: MlDsaParams>(
    session_id: SessionId,
    party: PartyId,
    nonce_randomness_commitment: &Commitment,
) -> Commitment {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing CEF rho commitment from nonce generation v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(session_id.0);
    hasher.update(party.0.to_le_bytes());
    hasher.update(nonce_randomness_commitment.0);
    Commitment(hasher.finalize().into())
}

fn hash_polyvec(hasher: &mut Sha3_256, value: &PolyVec) {
    hasher.update((value.len() as u32).to_le_bytes());
    for poly in value.polys() {
        for &coeff in poly.coeffs() {
            hasher.update(coeff.to_le_bytes());
        }
    }
}

fn high_masks<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
    party_idx: usize,
    coeff_count: usize,
) -> Vec<u32> {
    let m = P::HIGH_MOD as u32;
    let mut masks = vec![0u32; coeff_count];

    for (coeff, mask_slot) in masks.iter_mut().enumerate().take(coeff_count) {
        let mut mask = 0u32;
        for (other_idx, other_party) in signer_set.iter().enumerate() {
            if other_idx == party_idx {
                continue;
            }
            let own = signer_set[party_idx];
            let (left, right, positive) = if own < *other_party {
                (own, *other_party, true)
            } else {
                (*other_party, own, false)
            };
            let pair_mask = derive_mod(
                b"TALUS maskH",
                session_id,
                &[left.0, right.0],
                coeff as u32,
                m,
            );
            if positive {
                mask = (mask + pair_mask) % m;
            } else {
                mask = (mask + m - pair_mask) % m;
            }
        }
        *mask_slot = mask;
    }

    masks
}

fn rhos<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
    input: &PartyPreprocessInput,
    coeff_count: usize,
) -> Vec<u32> {
    let bound = (P::alpha() as u32 / signer_set.len() as u32).max(1);
    (0..coeff_count)
        .map(|coeff| {
            let mut hasher = Sha3_256::new();
            hasher.update(b"TALUS rho");
            hasher.update(session_id.0);
            hasher.update(input.party.0.to_le_bytes());
            hasher.update((coeff as u32).to_le_bytes());
            hasher.update(input.randomness_commitment.0);
            let bytes = hasher.finalize();
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % bound
        })
        .collect()
}

fn transcript_hash<P: MlDsaParams>(
    session_id: SessionId,
    inputs: &[PartyPreprocessInput],
) -> TranscriptHash {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing transcript v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(session_id.0);
    for input in inputs {
        hasher.update(input.party.0.to_le_bytes());
        hasher.update(input.nonce_commitment.0);
        hasher.update(input.randomness_commitment.0);
        for &high in &input.highs {
            hasher.update(high.to_le_bytes());
        }
        for &low in &input.lows {
            hasher.update(low.to_le_bytes());
        }
    }
    TranscriptHash(hasher.finalize().into())
}

fn local_pre_challenge_certification_evidence(
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_count: usize,
    coeff_count: usize,
    broadcasts: &[MaskedBroadcast],
    carry_compare: CarryCompareCertificationEvidence,
    bcc: BccCertificationEvidence,
    masked_broadcast_runtime_hashes: &[[u8; 32]],
) -> PreChallengeCertificationEvidence {
    PreChallengeCertificationEvidence {
        masked_broadcast: Some(MaskedBroadcastCertificationEvidence {
            session_id,
            transcript_hash,
            signer_count,
            coeff_count,
            evidence_hash: pre_challenge_evidence_hash(
                b"masked-broadcast",
                session_id,
                transcript_hash,
                signer_count,
                coeff_count,
                broadcasts,
            ),
            runtime_transcript_hash: masked_broadcast_runtime_transcript_hash(
                session_id,
                transcript_hash,
                signer_count,
                coeff_count,
                masked_broadcast_runtime_hashes,
            ),
        }),
        carry_compare: Some(carry_compare),
        bcc: Some(bcc),
        persistence: Some(TokenPersistenceEvidence {
            session_id,
            evidence_hash: pre_challenge_evidence_hash(
                b"persistence",
                session_id,
                transcript_hash,
                signer_count,
                coeff_count,
                broadcasts,
            ),
        }),
        nonce_reveal_policy: Some(NonceRevealPolicyEvidence {
            session_id,
            post_challenge_reveal_disabled: true,
            evidence_hash: pre_challenge_evidence_hash(
                b"no-post-challenge-reveal",
                session_id,
                transcript_hash,
                signer_count,
                coeff_count,
                broadcasts,
            ),
        }),
    }
}

fn pre_challenge_evidence_hash(
    domain: &[u8],
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_count: usize,
    coeff_count: usize,
    broadcasts: &[MaskedBroadcast],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing certification evidence v1");
    hasher.update(domain);
    hasher.update(session_id.0);
    hasher.update(transcript_hash.0);
    hasher.update((signer_count as u32).to_le_bytes());
    hasher.update((coeff_count as u32).to_le_bytes());
    for broadcast in broadcasts {
        hasher.update(broadcast.party.0.to_le_bytes());
        hasher.update(broadcast.nonce_commitment.0);
        hasher.update(broadcast.rho_bits_commitment.0);
        hasher.update(broadcast.transcript_hash.0);
        for &high in &broadcast.masked_highs {
            hasher.update(high.to_le_bytes());
        }
        for &low in &broadcast.masked_lows {
            hasher.update(low.to_le_bytes());
        }
    }
    hasher.finalize().into()
}

fn masked_broadcast_runtime_transcript_hash(
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_count: usize,
    coeff_count: usize,
    runtime_hashes: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS masked broadcast aggregate runtime transcript v1");
    hasher.update(session_id.0);
    hasher.update(transcript_hash.0);
    hasher.update((signer_count as u32).to_le_bytes());
    hasher.update((coeff_count as u32).to_le_bytes());
    for runtime_hash in runtime_hashes {
        hasher.update(runtime_hash);
    }
    hasher.finalize().into()
}

fn preprocessing_stage_runtime_transcript_hash(
    domain: &[u8],
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    coeff_count: usize,
    evidence_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing stage runtime transcript v1");
    hasher.update(domain);
    hasher.update(session_id.0);
    hasher.update(transcript_hash.0);
    hasher.update((coeff_count as u32).to_le_bytes());
    hasher.update(evidence_hash);
    hasher.finalize().into()
}

fn preprocessing_stage_runtime_transcript_hash_from_vector_runtime_evidence(
    stage: PreprocessingCertificationStage,
    statement: &PreprocessingCertificationRuntimeStatement,
    vector_runtime_transcript_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing stage vector-runtime binding v1");
    hasher.update(stage.domain());
    hasher.update(statement.session_id.0);
    hasher.update(statement.transcript_hash.0);
    hasher.update((statement.signer_set.len() as u32).to_le_bytes());
    hasher.update((statement.coeff_count as u32).to_le_bytes());
    hasher.update(statement.masked_broadcast_runtime_transcript);
    match stage {
        PreprocessingCertificationStage::CarryCompare => {
            hasher.update(statement.carry_compare_evidence_hash);
            hasher.update(statement.carry_compare_public_input_hash);
            hasher.update(statement.carry_compare_private_circuit_label_hash);
        }
        PreprocessingCertificationStage::Bcc => {
            hasher.update(statement.bcc_evidence_hash);
            hasher.update(statement.w1_hash);
            hasher.update(statement.cef_bcc_public_input_hash);
            hasher.update(statement.cef_bcc_private_circuit_label_hash);
        }
    }
    hasher.update(vector_runtime_transcript_hash);
    hasher.finalize().into()
}

fn preprocessing_private_circuit_label_hashes(
    session_id: SessionId,
    transcript_hash: TranscriptHash,
) -> ([u8; 32], [u8; 32]) {
    let root = Power2RoundTranscriptLabel::preprocessing_root(session_id.0, transcript_hash.0);
    (
        power2round_label_hash(&root.child("carry_compare_private").child("rho_gt_t")),
        power2round_label_hash(&root.child("cef_bcc_private")),
    )
}

fn preprocessing_private_circuit_batch_statement(
    statements: &[PreprocessingCertificationRuntimeStatement],
) -> Result<PreprocessingCertificationRuntimeStatement, PreprocessError> {
    if statements.is_empty() {
        return Err(PreprocessError::EmptySignerSet);
    }
    let first = &statements[0];
    if first.signer_set.is_empty() || first.coeff_count == 0 {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    if statements.iter().any(|statement| {
        statement.signer_set != first.signer_set
            || statement.coeff_count != first.coeff_count
            || statement.masked_broadcast_bindings.len() != first.masked_broadcast_bindings.len()
    }) {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS fused preprocessing private circuit batch statement v1");
    for statement in statements {
        hasher.update(hash_preprocessing_runtime_statement(statement));
    }
    let digest = hasher.finalize();
    let mut session = [0u8; 32];
    session.copy_from_slice(&digest);

    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS fused preprocessing private circuit batch transcript v1");
    hasher.update(session);
    for statement in statements {
        hasher.update(statement.session_id.0);
        hasher.update(statement.transcript_hash.0);
    }
    let digest = hasher.finalize();
    let mut transcript = [0u8; 32];
    transcript.copy_from_slice(&digest);
    let session_id = SessionId(session);
    let transcript_hash = TranscriptHash(transcript);
    let coeff_count = first
        .coeff_count
        .checked_mul(statements.len())
        .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
    let (carry_label, cef_label) =
        preprocessing_private_circuit_label_hashes(session_id, transcript_hash);

    let hash_field = |domain: &[u8]| -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(domain);
        hasher.update(session_id.0);
        hasher.update(transcript_hash.0);
        for statement in statements {
            hasher.update(hash_preprocessing_runtime_statement(statement));
        }
        hasher.finalize().into()
    };

    let mut masked_broadcast_bindings = Vec::new();
    for statement in statements {
        masked_broadcast_bindings.extend_from_slice(&statement.masked_broadcast_bindings);
    }
    Ok(PreprocessingCertificationRuntimeStatement {
        session_id,
        transcript_hash,
        signer_set: first.signer_set.clone(),
        coeff_count,
        masked_broadcast_runtime_transcript: hash_field(b"masked-broadcast-runtime"),
        masked_broadcast_bindings,
        carry_compare_evidence_hash: hash_field(b"carry-evidence"),
        bcc_evidence_hash: hash_field(b"bcc-evidence"),
        w1_hash: hash_field(b"w1"),
        carry_compare_public_input_hash: hash_field(b"carry-public"),
        cef_bcc_public_input_hash: hash_field(b"cef-bcc-public"),
        carry_compare_private_circuit_label_hash: carry_label,
        cef_bcc_private_circuit_label_hash: cef_label,
    })
}

fn hash_preprocessing_runtime_statement(
    statement: &PreprocessingCertificationRuntimeStatement,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing runtime statement hash v1");
    hasher.update(statement.session_id.0);
    hasher.update(statement.transcript_hash.0);
    for party in &statement.signer_set {
        hasher.update(party.0.to_le_bytes());
    }
    hasher.update((statement.coeff_count as u32).to_le_bytes());
    hasher.update(statement.masked_broadcast_runtime_transcript);
    for binding in &statement.masked_broadcast_bindings {
        hasher.update(binding.party.0.to_le_bytes());
        hasher.update(binding.statement_hash);
        hasher.update(binding.runtime_transcript_hash);
    }
    hasher.update(statement.carry_compare_evidence_hash);
    hasher.update(statement.bcc_evidence_hash);
    hasher.update(statement.w1_hash);
    hasher.update(statement.carry_compare_public_input_hash);
    hasher.update(statement.cef_bcc_public_input_hash);
    hasher.update(statement.carry_compare_private_circuit_label_hash);
    hasher.update(statement.cef_bcc_private_circuit_label_hash);
    hasher.finalize().into()
}

fn hash_preprocessing_opened_broadcasts(
    statement: &PreprocessingCertificationRuntimeStatement,
    broadcasts: &[MaskedBroadcast],
) -> Result<[u8; 32], PreprocessError> {
    if broadcasts.len() != statement.signer_set.len() {
        return Err(PreprocessError::CoeffCountMismatch);
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing opened broadcast state hash v1");
    hasher.update(statement.session_id.0);
    hasher.update(statement.transcript_hash.0);
    hasher.update((statement.coeff_count as u32).to_le_bytes());
    for broadcast in broadcasts {
        if !statement.signer_set.contains(&broadcast.party)
            || broadcast.masked_highs.len() != statement.coeff_count
            || broadcast.masked_lows.len() != statement.coeff_count
            || broadcast.transcript_hash != statement.transcript_hash
        {
            return Err(PreprocessError::CoeffCountMismatch);
        }
        hasher.update(broadcast.party.0.to_le_bytes());
        hasher.update(broadcast.nonce_commitment.0);
        hasher.update(broadcast.rho_bits_commitment.0);
        hasher.update(broadcast.transcript_hash.0);
        for &value in &broadcast.masked_highs {
            hasher.update(value.to_le_bytes());
        }
        for &value in &broadcast.masked_lows {
            hasher.update(value.to_le_bytes());
        }
    }
    Ok(hasher.finalize().into())
}

fn hash_preprocessing_private_material_state(
    state: &PreprocessingPrivateMaterialState,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing private material state hash v1");
    hasher.update([match state.source {
        PreprocessingPrivateMaterialStateSource::OpenedMaterialDerived => 1,
        PreprocessingPrivateMaterialStateSource::RuntimePrivateMpc => 2,
    }]);
    hasher.update(state.statement_hash);
    hasher.update(state.opened_broadcast_hash);
    hasher.update(state.source_handle_hash);
    for bit in state.material.masked_broadcast_relation_bits() {
        let id = bit.id();
        hasher.update(b"masked-broadcast-relation");
        hasher.update(id.label_hash);
        hasher.update((id.lane_count as u32).to_le_bytes());
        hasher.update(bit.holder().0.to_le_bytes());
        hasher.update(bit.point().to_le_bytes());
    }
    for bit in state.material.rho_sum_bits_by_bit_le() {
        let id = bit.id();
        hasher.update(b"rho-sum");
        hasher.update(id.label_hash);
        hasher.update((id.lane_count as u32).to_le_bytes());
        hasher.update(bit.holder().0.to_le_bytes());
        hasher.update(bit.point().to_le_bytes());
    }
    for bit in state.material.cef_correction_bits() {
        let id = bit.id();
        hasher.update(b"cef-correction");
        hasher.update(id.label_hash);
        hasher.update((id.lane_count as u32).to_le_bytes());
        hasher.update(bit.holder().0.to_le_bytes());
        hasher.update(bit.point().to_le_bytes());
    }
    for bit in state.material.bcc_violation_bits() {
        let id = bit.id();
        hasher.update(b"bcc-violation");
        hasher.update(id.label_hash);
        hasher.update((id.lane_count as u32).to_le_bytes());
        hasher.update(bit.holder().0.to_le_bytes());
        hasher.update(bit.point().to_le_bytes());
    }
    hasher.finalize().into()
}

fn hash_opened_material_private_source_handles(
    material: &PreprocessingPrivateMaterialHandles,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS opened-material preprocessing source handles v1");
    for bit in material.masked_broadcast_relation_bits() {
        let id = bit.id();
        hasher.update(b"masked-broadcast-relation");
        hasher.update(id.label_hash);
        hasher.update((id.lane_count as u32).to_le_bytes());
        hasher.update(bit.holder().0.to_le_bytes());
        hasher.update(bit.point().to_le_bytes());
    }
    for bit in material.rho_sum_bits_by_bit_le() {
        let id = bit.id();
        hasher.update(b"rho-sum");
        hasher.update(id.label_hash);
        hasher.update((id.lane_count as u32).to_le_bytes());
        hasher.update(bit.holder().0.to_le_bytes());
        hasher.update(bit.point().to_le_bytes());
    }
    for bit in material.cef_correction_bits() {
        let id = bit.id();
        hasher.update(b"cef-correction");
        hasher.update(id.label_hash);
        hasher.update((id.lane_count as u32).to_le_bytes());
        hasher.update(bit.holder().0.to_le_bytes());
        hasher.update(bit.point().to_le_bytes());
    }
    for bit in material.bcc_violation_bits() {
        let id = bit.id();
        hasher.update(b"bcc-violation");
        hasher.update(id.label_hash);
        hasher.update((id.lane_count as u32).to_le_bytes());
        hasher.update(bit.holder().0.to_le_bytes());
        hasher.update(bit.point().to_le_bytes());
    }
    hasher.finalize().into()
}

fn hash_runtime_private_mpc_source_handles(
    statement: &PreprocessingCertificationRuntimeStatement,
    input: &PreprocessingRuntimePrivateMpcStateInput,
) -> Result<[u8; 32], PreprocessError> {
    if input.masked_broadcast_relation_bits.is_empty() {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS runtime-private preprocessing source handles v1");
    hasher.update(hash_preprocessing_runtime_statement(statement));
    for bit in &input.masked_broadcast_relation_bits {
        let id = bit.id();
        hasher.update(b"masked-broadcast-relation");
        hasher.update(id.label_hash);
        hasher.update((id.lane_count as u32).to_le_bytes());
        hasher.update(bit.holder().0.to_le_bytes());
        hasher.update(bit.point().to_le_bytes());
    }
    for bit in &input.rho_sum_bits_by_bit_le {
        let id = bit.id();
        hasher.update(b"rho-sum");
        hasher.update(id.label_hash);
        hasher.update((id.lane_count as u32).to_le_bytes());
        hasher.update(bit.holder().0.to_le_bytes());
        hasher.update(bit.point().to_le_bytes());
    }
    for bit in &input.cef_correction_bits {
        let id = bit.id();
        hasher.update(b"cef-correction");
        hasher.update(id.label_hash);
        hasher.update((id.lane_count as u32).to_le_bytes());
        hasher.update(bit.holder().0.to_le_bytes());
        hasher.update(bit.point().to_le_bytes());
    }
    for bit in &input.bcc_violation_bits {
        let id = bit.id();
        hasher.update(b"bcc-violation");
        hasher.update(id.label_hash);
        hasher.update((id.lane_count as u32).to_le_bytes());
        hasher.update(bit.holder().0.to_le_bytes());
        hasher.update(bit.point().to_le_bytes());
    }
    Ok(hasher.finalize().into())
}

fn preprocessing_certification_runtime_label(
    statement: &PreprocessingCertificationRuntimeStatement,
) -> Power2RoundTranscriptLabel {
    Power2RoundTranscriptLabel::preprocessing_root(
        statement.session_id.0,
        statement.transcript_hash.0,
    )
}

#[allow(dead_code)]
fn ensure_preprocessing_statement_phase_cursors(
    statement: &PreprocessingCertificationRuntimeStatement,
    cursors: &[PrimeFieldMpcPhaseCursor],
) -> Result<(), PreprocessError> {
    let root = preprocessing_certification_runtime_label(statement);
    let expected_senders = statement.signer_set.len();
    let expected = [
        (
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::PreprocessingMaskedBroadcast,
            root.child("masked_broadcast")
                .child("preprocessing_masked_broadcast"),
        ),
        (
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::PreprocessingCarryCompare,
            root.child("carry_compare")
                .child("preprocessing_carry_compare"),
        ),
        (
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::PreprocessingCefBcc,
            root.child("cef_bcc").child("preprocessing_cef_bcc"),
        ),
    ];
    for (kind, phase, label) in expected {
        let label_hash = power2round_label_hash(&label);
        let found = cursors.iter().any(|cursor| {
            cursor.kind == kind
                && cursor.phase == phase
                && cursor.receiver.is_none()
                && cursor.label_hash == label_hash
                && cursor.state == PrimeFieldMpcPhaseCursorState::Collected
                && cursor.expected == expected_senders
                && cursor.got == expected_senders
        });
        if !found {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
    }
    Ok(())
}

fn ensure_preprocessing_statement_public_input_hashes(
    statement: &PreprocessingCertificationRuntimeStatement,
) -> Result<(), PreprocessError> {
    if statement.carry_compare_public_input_hash == [0u8; 32]
        || statement.cef_bcc_public_input_hash == [0u8; 32]
    {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    Ok(())
}

fn ensure_preprocessing_statement_private_label_hashes(
    statement: &PreprocessingCertificationRuntimeStatement,
) -> Result<(), PreprocessError> {
    let (carry, cef_bcc) =
        preprocessing_private_circuit_label_hashes(statement.session_id, statement.transcript_hash);
    if statement.carry_compare_private_circuit_label_hash != carry
        || statement.cef_bcc_private_circuit_label_hash != cef_bcc
    {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    Ok(())
}

fn ensure_preprocessing_private_circuit_inputs_match_statement(
    statement: &PreprocessingCertificationRuntimeStatement,
    inputs: &PreprocessingPrivateCircuitInputs,
) -> Result<(), PreprocessError> {
    if inputs.coeff_count != statement.coeff_count
        || inputs.carry_compare_public_input_hash != statement.carry_compare_public_input_hash
        || inputs.cef_bcc_public_input_hash != statement.cef_bcc_public_input_hash
        || inputs.carry_compare_private_circuit_label_hash
            != statement.carry_compare_private_circuit_label_hash
        || inputs.cef_bcc_private_circuit_label_hash != statement.cef_bcc_private_circuit_label_hash
        || inputs.carry_compare_private_handle_hash == [0u8; 32]
        || inputs.cef_correction_private_handle_hash == [0u8; 32]
        || inputs.cef_bcc_private_handle_hash == [0u8; 32]
    {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    Ok(())
}

fn hash_preprocessing_optional_absent_private_handles(
    domain: &[u8],
    statement: &PreprocessingCertificationRuntimeStatement,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing absent optional private bit handle graph v1");
    hasher.update(domain);
    hasher.update(statement.session_id.0);
    hasher.update(statement.transcript_hash.0);
    hasher.update((statement.coeff_count as u32).to_le_bytes());
    hasher.update(statement.cef_bcc_private_circuit_label_hash);
    hasher.finalize().into()
}

fn hash_preprocessing_private_bit_handles(
    domain: &[u8],
    statement: &PreprocessingCertificationRuntimeStatement,
    bits: &[ProductionBitShareVec],
) -> Result<[u8; 32], PreprocessError> {
    if bits.is_empty() {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing private bit handle graph v1");
    hasher.update(domain);
    hasher.update(statement.session_id.0);
    hasher.update(statement.transcript_hash.0);
    hasher.update((statement.coeff_count as u32).to_le_bytes());
    hasher.update(statement.carry_compare_public_input_hash);
    hasher.update(statement.cef_bcc_public_input_hash);
    hasher.update(statement.carry_compare_private_circuit_label_hash);
    hasher.update(statement.cef_bcc_private_circuit_label_hash);
    for bit in bits {
        if bit.len() != statement.coeff_count {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        let id = bit.id();
        hasher.update(id.label_hash);
        hasher.update((id.lane_count as u32).to_le_bytes());
        hasher.update(bit.holder().0.to_le_bytes());
        hasher.update(bit.point().to_le_bytes());
    }
    Ok(hasher.finalize().into())
}

#[allow(dead_code)]
fn ensure_preprocessing_statement_wire_markers<L: PrimeFieldMpcWireMessageLog>(
    statement: &PreprocessingCertificationRuntimeStatement,
    wire_log: &L,
) -> Result<(), PreprocessError> {
    let root = preprocessing_certification_runtime_label(statement);
    let expected_senders = &statement.signer_set;
    let expected = [
        (
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::PreprocessingMaskedBroadcast,
            root.child("masked_broadcast")
                .child("preprocessing_masked_broadcast"),
            preprocessing_statement_marker_lanes(
                b"masked-broadcast",
                statement,
                statement
                    .signer_set
                    .len()
                    .saturating_mul(statement.coeff_count),
            ),
        ),
        (
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::PreprocessingCarryCompare,
            root.child("carry_compare")
                .child("preprocessing_carry_compare"),
            preprocessing_statement_marker_lanes(
                b"carry-compare",
                statement,
                statement.coeff_count,
            ),
        ),
        (
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::PreprocessingCefBcc,
            root.child("cef_bcc").child("preprocessing_cef_bcc"),
            preprocessing_statement_marker_lanes(b"cef-bcc", statement, statement.coeff_count),
        ),
    ];
    for (kind, phase, label, values) in expected {
        ensure_prime_field_mpc_wire_log_contains_broadcast_vec(
            wire_log,
            kind,
            phase,
            &label,
            expected_senders,
            &values,
        )
        .map_err(map_preprocessing_runtime_dkg_error)?;
    }
    Ok(())
}

fn preprocessing_statement_private_circuit_mul_labels<P: MlDsaParams>(
    statement: &PreprocessingCertificationRuntimeStatement,
) -> (
    Vec<Power2RoundTranscriptLabel>,
    Vec<Power2RoundTranscriptLabel>,
) {
    let root = preprocessing_certification_runtime_label(statement);
    let carry_root = root.child("carry_compare_private").child("rho_gt_t");
    let carry_width = bit_width_for_preprocessing_public_value(P::alpha() as u32);
    let mut carry_labels = Vec::with_capacity(carry_width);
    for bit_idx in 0..carry_width {
        carry_labels.push(
            carry_root
                .child(format!("bit_{bit_idx}/candidate_and_eq"))
                .child("bit_and")
                .child("mul_layer"),
        );
    }

    let cef_correction_root = root
        .child("cef_bcc_private")
        .child("cef_correction_sum_leq");
    let bcc_root = root.child("cef_bcc_private").child("bcc_sum_leq");
    let mut cef_labels = Vec::new();
    for cef_root in [&cef_correction_root, &bcc_root] {
        cef_labels.extend([
            cef_root
                .child("add_input_0/bit_0/carry")
                .child("bit_and")
                .child("mul_layer"),
            cef_root
                .child("sum_gt_threshold/bit_0/candidate_and_eq")
                .child("bit_and")
                .child("mul_layer"),
        ]);
    }
    (carry_labels, cef_labels)
}

fn bit_width_for_preprocessing_public_value(value: u32) -> usize {
    let mut width = 1usize;
    let mut capacity = 2u32;
    while capacity <= value {
        width += 1;
        capacity = capacity.saturating_mul(2);
    }
    width
}

fn preprocessing_statement_marker_lanes(
    domain: &[u8],
    statement: &PreprocessingCertificationRuntimeStatement,
    lane_count: usize,
) -> Vec<Coeff> {
    (0..lane_count)
        .map(|lane| {
            let mut hasher = Sha3_256::new();
            hasher.update(b"TALUS preprocessing runtime marker lane v1");
            hasher.update(domain);
            hasher.update(statement.session_id.0);
            hasher.update(statement.transcript_hash.0);
            hasher.update((statement.signer_set.len() as u32).to_le_bytes());
            hasher.update((statement.coeff_count as u32).to_le_bytes());
            hasher.update(statement.masked_broadcast_runtime_transcript);
            for binding in &statement.masked_broadcast_bindings {
                hasher.update(binding.party.0.to_le_bytes());
                hasher.update(binding.statement_hash);
                hasher.update(binding.runtime_transcript_hash);
            }
            hasher.update(statement.carry_compare_evidence_hash);
            hasher.update(statement.bcc_evidence_hash);
            hasher.update(statement.w1_hash);
            hasher.update(statement.carry_compare_public_input_hash);
            hasher.update(statement.cef_bcc_public_input_hash);
            hasher.update(statement.carry_compare_private_circuit_label_hash);
            hasher.update(statement.cef_bcc_private_circuit_label_hash);
            hasher.update((lane as u32).to_le_bytes());
            let bytes = hasher.finalize();
            let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            (value % 8_380_417) as Coeff
        })
        .collect()
}

fn masked_broadcast_runtime_transcript_hash_from_vector_runtime_evidence(
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_count: usize,
    coeff_count: usize,
    statement_hash: [u8; 32],
    party: PartyId,
    vector_runtime_transcript_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS masked-broadcast vector-runtime binding v1");
    hasher.update(session_id.0);
    hasher.update(transcript_hash.0);
    hasher.update((signer_count as u32).to_le_bytes());
    hasher.update((coeff_count as u32).to_le_bytes());
    hasher.update(party.0.to_le_bytes());
    hasher.update(statement_hash);
    hasher.update(vector_runtime_transcript_hash);
    hasher.finalize().into()
}

fn validate_masked_broadcast_bindings_for_vector_runtime<P: MlDsaParams>(
    statement: &PreprocessingCertificationRuntimeStatement,
    vector_runtime_transcript_hash: [u8; 32],
) -> Result<(), PreprocessError> {
    if statement.masked_broadcast_bindings.len() != statement.signer_set.len()
        || vector_runtime_transcript_hash == [0u8; 32]
    {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    let mut seen = Vec::with_capacity(statement.masked_broadcast_bindings.len());
    for binding in &statement.masked_broadcast_bindings {
        if !statement.signer_set.contains(&binding.party)
            || seen.contains(&binding.party)
            || binding.statement_hash == [0u8; 32]
            || binding.runtime_transcript_hash == [0u8; 32]
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
        seen.push(binding.party);
        let vector_expected = masked_broadcast_runtime_transcript_hash_from_vector_runtime_evidence(
            statement.session_id,
            statement.transcript_hash,
            statement.signer_set.len(),
            statement.coeff_count,
            binding.statement_hash,
            binding.party,
            vector_runtime_transcript_hash,
        );
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS masked broadcast vector runtime transcript binding v1");
        hasher.update(P::NAME.as_bytes());
        hasher.update(binding.statement_hash);
        hasher.update(statement.session_id.0);
        hasher.update((statement.coeff_count as u32).to_le_bytes());
        hasher.update((statement.signer_set.len() as u32).to_le_bytes());
        let statement_expected: [u8; 32] = hasher.finalize().into();
        if binding.runtime_transcript_hash != vector_expected
            && binding.runtime_transcript_hash != statement_expected
        {
            return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
        }
    }
    let derived = masked_broadcast_runtime_transcript_hash(
        statement.session_id,
        statement.transcript_hash,
        statement.signer_set.len(),
        statement.coeff_count,
        &statement
            .masked_broadcast_bindings
            .iter()
            .map(|binding| binding.runtime_transcript_hash)
            .collect::<Vec<_>>(),
    );
    if derived != statement.masked_broadcast_runtime_transcript {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    Ok(())
}

fn expected_preprocessing_stage_runtime_proof_parts<P: MlDsaParams>(
    stage: PreprocessingCertificationStage,
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_count: usize,
    coeff_count: usize,
    evidence_hash: [u8; 32],
    runtime_transcript_hash: [u8; 32],
) -> PreprocessingStageRuntimeProofParts {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing stage runtime statement v1");
    hasher.update(P::NAME.as_bytes());
    hasher.update(stage.domain());
    hasher.update(session_id.0);
    hasher.update(transcript_hash.0);
    hasher.update((signer_count as u32).to_le_bytes());
    hasher.update((coeff_count as u32).to_le_bytes());
    hasher.update(evidence_hash);
    PreprocessingStageRuntimeProofParts {
        stage,
        statement_hash: hasher.finalize().into(),
        runtime_transcript_hash,
        coeff_count,
        signer_count,
    }
}

fn decode_preprocessing_stage_runtime_proof(
    proof: &PreprocessingCertificationStageRuntimeProof,
) -> Option<PreprocessingStageRuntimeProofParts> {
    const LEN: usize = 6 + 1 + 32 + 32 + 4 + 4;
    if proof.bytes.len() != LEN {
        return None;
    }
    if &proof.bytes[..6] != PREPROCESSING_STAGE_RUNTIME_PROOF_PREFIX {
        return None;
    }
    let stage = match proof.bytes[6] {
        1 => PreprocessingCertificationStage::CarryCompare,
        2 => PreprocessingCertificationStage::Bcc,
        _ => return None,
    };
    let mut statement_hash = [0u8; 32];
    statement_hash.copy_from_slice(&proof.bytes[7..39]);
    let mut runtime_transcript_hash = [0u8; 32];
    runtime_transcript_hash.copy_from_slice(&proof.bytes[39..71]);
    let coeff_count = u32::from_le_bytes(proof.bytes[71..75].try_into().ok()?) as usize;
    let signer_count = u32::from_le_bytes(proof.bytes[75..79].try_into().ok()?) as usize;
    Some(PreprocessingStageRuntimeProofParts {
        stage,
        statement_hash,
        runtime_transcript_hash,
        coeff_count,
        signer_count,
    })
}

fn verify_preprocessing_stage_runtime_proof<P: MlDsaParams>(
    stage: PreprocessingCertificationStage,
    session_id: SessionId,
    transcript_hash: TranscriptHash,
    signer_count: usize,
    coeff_count: usize,
    evidence_hash: [u8; 32],
    proof: &PreprocessingCertificationStageRuntimeProof,
) -> Result<[u8; 32], PreprocessError> {
    let parts = decode_preprocessing_stage_runtime_proof(proof)
        .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
    let expected = expected_preprocessing_stage_runtime_proof_parts::<P>(
        stage,
        session_id,
        transcript_hash,
        signer_count,
        coeff_count,
        evidence_hash,
        parts.runtime_transcript_hash,
    );
    if parts != expected || parts.runtime_transcript_hash == [0u8; 32] {
        return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
    }
    Ok(parts.runtime_transcript_hash)
}

fn preprocessing_runtime_token_binding_hash(
    token: &CertifiedToken,
    runtime_evidence: &ProductionVectorItMpcRuntimeEvidence,
) -> [u8; 32] {
    let counters = PreprocessingCertificationCounters::from_token(token);
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS preprocessing runtime-token binding v1");
    hasher.update(token.session_id.0);
    hasher.update(token.transcript_hash.0);
    hasher.update((token.signer_set.len() as u32).to_le_bytes());
    for party in &token.signer_set {
        hasher.update(party.0.to_le_bytes());
    }
    hasher.update((token.w1.len() as u32).to_le_bytes());
    hasher.update((token.nonce_commitments.len() as u32).to_le_bytes());
    hasher.update((token.broadcasts.len() as u32).to_le_bytes());
    match token.precomputed_w_share.as_ref() {
        Some(share) => {
            hasher.update([1]);
            hasher.update(share.id().label_hash);
            hasher.update((share.id().lane_count as u64).to_le_bytes());
        }
        None => hasher.update([0]),
    }
    match token.strict_signing_masks.as_ref() {
        Some(masks) => {
            hasher.update([1]);
            match masks.provenance {
                Some(provenance) => {
                    hasher.update([1]);
                    hasher.update(provenance.session_id.0);
                    hasher.update(provenance.transcript_hash.0);
                    hasher.update(provenance.runtime_transcript_hash);
                    hasher.update(provenance.z_mask_value_label_hash);
                    hasher.update(provenance.hint_mask_value_label_hash);
                    hasher.update((provenance.z_lane_count as u64).to_le_bytes());
                    hasher.update((provenance.hint_lane_count as u64).to_le_bytes());
                }
                None => hasher.update([0]),
            }
            hasher.update(masks.z_mask_value.id().label_hash);
            hasher.update((masks.z_mask_value.id().lane_count as u64).to_le_bytes());
            for bit in &masks.z_mask_bits_by_bit {
                hasher.update(bit.id().label_hash);
                hasher.update((bit.id().lane_count as u64).to_le_bytes());
            }
            hasher.update(masks.hint_mask_value.id().label_hash);
            hasher.update((masks.hint_mask_value.id().lane_count as u64).to_le_bytes());
            for bit in &masks.hint_mask_bits_by_bit {
                hasher.update(bit.id().label_hash);
                hasher.update((bit.id().lane_count as u64).to_le_bytes());
            }
        }
        None => hasher.update([0]),
    }
    match token.strict_signing_helpers.as_ref() {
        Some(helpers) => {
            let provenance = helpers.provenance();
            hasher.update([1]);
            hasher.update(provenance.session_id.0);
            hasher.update(provenance.transcript_hash.0);
            hasher.update(provenance.runtime_transcript_hash);
            hasher.update(provenance.comparison_helper_hash);
            hasher.update(provenance.threshold_helper_hash);
            hasher.update((provenance.z_lane_count as u64).to_le_bytes());
            hasher.update((provenance.hint_lane_count as u64).to_le_bytes());
        }
        None => hasher.update([0]),
    }
    if let Some(evidence) = token.certification_evidence.masked_broadcast {
        hasher.update(evidence.evidence_hash);
        hasher.update(evidence.runtime_transcript_hash);
    }
    if let Some(evidence) = token.certification_evidence.carry_compare {
        hasher.update(evidence.evidence_hash);
        hasher.update(evidence.runtime_transcript_hash);
    }
    if let Some(evidence) = token.certification_evidence.bcc {
        hasher.update(evidence.evidence_hash);
        hasher.update(evidence.runtime_transcript_hash);
    }
    if let Some(evidence) = token.certification_evidence.persistence {
        hasher.update(evidence.evidence_hash);
    }
    if let Some(evidence) = token.certification_evidence.nonce_reveal_policy {
        hasher.update(evidence.evidence_hash);
    }
    hasher.update((counters.token_count as u64).to_le_bytes());
    hasher.update((counters.signer_count as u64).to_le_bytes());
    hasher.update((counters.coeff_count as u64).to_le_bytes());
    hasher.update((counters.vector_lanes as u64).to_le_bytes());
    hasher.update((counters.masked_broadcasts as u64).to_le_bytes());
    hasher.update((counters.carry_compare_lanes as u64).to_le_bytes());
    hasher.update((counters.cef_correction_lanes as u64).to_le_bytes());
    hasher.update((counters.bcc_lanes as u64).to_le_bytes());
    hasher.update(runtime_evidence.transcript_hash);
    hasher.update(runtime_evidence.counters.rounds.to_le_bytes());
    hasher.update(runtime_evidence.counters.private_messages.to_le_bytes());
    hasher.update(runtime_evidence.counters.broadcasts.to_le_bytes());
    hasher.update(runtime_evidence.counters.wire_bytes.to_le_bytes());
    hasher.update(runtime_evidence.counters.durable_log_bytes.to_le_bytes());
    hasher.update(runtime_evidence.counters.vector_lanes.to_le_bytes());
    hasher.update(
        runtime_evidence
            .counters
            .multiplication_layers
            .to_le_bytes(),
    );
    hasher.update(runtime_evidence.counters.scalar_mul_gates.to_le_bytes());
    hasher.update(runtime_evidence.counters.scalar_openings.to_le_bytes());
    hasher.update(runtime_evidence.counters.scalar_assert_zero.to_le_bytes());
    hasher.update(runtime_evidence.counters.vector_mul_lanes.to_le_bytes());
    hasher.update(runtime_evidence.counters.vector_opening_lanes.to_le_bytes());
    hasher.update(
        runtime_evidence
            .counters
            .vector_assert_zero_lanes
            .to_le_bytes(),
    );
    hasher.update(runtime_evidence.counters.random_bits.to_le_bytes());
    hasher.update(
        runtime_evidence
            .counters
            .local_public_mul_lanes
            .to_le_bytes(),
    );
    hasher.update([runtime_evidence.coverage.open_many_checked as u8]);
    hasher.update([runtime_evidence.coverage.assert_zero_vec as u8]);
    hasher.update([runtime_evidence.coverage.assert_bit_vec as u8]);
    hasher.update([runtime_evidence.coverage.random_bit_vec as u8]);
    hasher.update([runtime_evidence.coverage.mul_vec as u8]);
    hasher.update([runtime_evidence.coverage.comparison_to_public as u8]);
    hasher.update([runtime_evidence.coverage.equality_to_public as u8]);
    hasher.update([runtime_evidence.coverage.bit_sum_or_threshold_check as u8]);
    hasher.update([runtime_evidence.coverage.private_one_hot_selection as u8]);
    hasher.update([runtime_evidence.coverage.preprocessing_masked_broadcast as u8]);
    hasher.update([runtime_evidence.coverage.preprocessing_carry_compare as u8]);
    hasher.update([runtime_evidence.coverage.preprocessing_cef_bcc as u8]);
    hasher.finalize().into()
}

fn salt(session_id: SessionId, party: PartyId) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS masked broadcast salt");
    hasher.update(session_id.0);
    hasher.update(party.0.to_le_bytes());
    hasher.finalize().into()
}

/// Computes the domain-separated masked-broadcast commitment for commit/open verification.
pub fn masked_broadcast_commitment(
    session_id: SessionId,
    message: &MaskedBroadcast,
    salt: [u8; 32],
) -> Commitment {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS masked broadcast commitment");
    hasher.update(session_id.0);
    hasher.update(message.party.0.to_le_bytes());
    hasher.update(message.nonce_commitment.0);
    hasher.update(message.rho_bits_commitment.0);
    hasher.update(message.transcript_hash.0);
    for &high in &message.masked_highs {
        hasher.update(high.to_le_bytes());
    }
    for &low in &message.masked_lows {
        hasher.update(low.to_le_bytes());
    }
    hasher.update(salt);
    Commitment(hasher.finalize().into())
}

fn derive_mod(
    domain: &[u8],
    session_id: SessionId,
    parties: &[u16],
    coeff: u32,
    modulus: u32,
) -> u32 {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(session_id.0);
    for party in parties {
        hasher.update(party.to_le_bytes());
    }
    hasher.update(coeff.to_le_bytes());
    let bytes = hasher.finalize();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % modulus
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

#[cfg(feature = "std")]
fn persist_counter(path: &std::path::Path, next: u64) -> Result<(), PreprocessError> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|_| PreprocessError::SessionCounterStoreIo { operation: "open" })?;
    use std::io::Write;
    writeln!(file, "{next}")
        .map_err(|_| PreprocessError::SessionCounterStoreIo { operation: "write" })?;
    file.sync_all()
        .map_err(|_| PreprocessError::SessionCounterStoreIo { operation: "sync" })
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
    use super::*;
    use crate::local_dev::{
        ClearMaskedBroadcastConsistencyVerifier, CutAndChooseAuditPlan, MaskedBroadcastClearAudit,
    };
    use talus_core::{cef_w1_clear_coeff, MlDsa65};

    fn session(byte: u8) -> SessionId {
        SessionId([byte; 32])
    }

    fn input(party: u16, highs: &[u32], lows: &[u32]) -> PartyPreprocessInput {
        PartyPreprocessInput {
            party: PartyId(party),
            highs: highs.to_vec(),
            lows: lows.to_vec(),
            y_share: vec![party as u8; 8],
            ay_contribution: None,
            nonce_commitment: NonceCommitment([party as u8; 32]),
            randomness_commitment: Commitment([(party + 10) as u8; 32]),
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
            transcript_hash: [0x5a; 32],
        }
    }

    fn release_vector_runtime_evidence_for_token(
        token: &CertifiedToken,
    ) -> ProductionVectorItMpcRuntimeEvidence {
        let mut evidence = release_vector_runtime_evidence();
        evidence.transcript_hash = preprocessing_certification_runtime_transcript_hash(token)
            .expect("preprocessing runtime transcript");
        evidence
    }

    #[cfg(feature = "scaffold-dev")]
    type TestProductionVectorPrimeFieldRuntime = ProductionVectorPrimeFieldMpcRuntime<
        talus_wire::InMemoryTransport,
        talus_dkg::InMemoryPrimeFieldMpcWireMessageLog,
        talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog,
    >;

    #[cfg(feature = "production-release-checks")]
    type TestLatestRoundProductionVectorPrimeFieldRuntime = ProductionVectorPrimeFieldMpcRuntime<
        LatestRoundInMemoryTransport,
        talus_dkg::InMemoryPrimeFieldMpcWireMessageLog,
        talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog,
    >;

    #[cfg(any(feature = "scaffold-dev", feature = "production-release-checks"))]
    #[derive(Clone, Debug, Default)]
    struct TestProductionVectorEntropy {
        next: u64,
    }

    #[cfg(any(feature = "scaffold-dev", feature = "production-release-checks"))]
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

        fn fill_bits<P: MlDsaParams>(
            &mut self,
            _label: &Power2RoundTranscriptLabel,
            count: usize,
        ) -> Result<Vec<Coeff>, DkgError> {
            Ok(vec![0; count])
        }
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
                if delivery.receiver_party_id == receiver_party_id
                    && delivery.message.header.round == expected_round
                {
                    latest_by_sender.insert(
                        delivery.message.header.sender_party_id,
                        delivery.message.clone(),
                    );
                }
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
                if delivery.observer_party_id == observer_party_id
                    && delivery.message.header.round == expected_round
                {
                    latest_by_sender.insert(
                        delivery.message.header.sender_party_id,
                        delivery.message.clone(),
                    );
                }
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
            talus_wire::validate_round_batch(&canonical, expected_round, expected)
                .map_err(talus_wire::TransportError::Wire)?;
            Ok(canonical)
        }
    }

    #[cfg(feature = "production-release-checks")]
    fn latest_round_vector_runtime_one_party<P: MlDsaParams>(
        epoch: u64,
    ) -> (
        DkgConfig,
        ProductionVectorPrimeFieldMpcRuntime<
            LatestRoundInMemoryTransport,
            talus_dkg::InMemoryPrimeFieldMpcWireMessageLog,
            talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog,
        >,
    ) {
        let party = PartyId(1);
        let config = DkgConfig::new::<P>(1, vec![party], talus_dkg::KeygenEpoch(epoch))
            .expect("test config");
        let transport = LatestRoundInMemoryTransport::new(party.0, vec![party.0])
            .expect("latest-round transport");
        let state =
            talus_dkg::TransportPrimeFieldMpcStateMachine::new(config.clone(), party, transport)
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
        (config, runtime)
    }

    #[cfg(feature = "production-release-checks")]
    fn comparison_bits_from_values<P: MlDsaParams>(
        runtime: &TestLatestRoundProductionVectorPrimeFieldRuntime,
        config: &DkgConfig,
        values: &[Coeff],
        label: &Power2RoundTranscriptLabel,
    ) -> Vec<ProductionBitShareVec> {
        (0..23)
            .map(|bit| {
                runtime
                    .bit_share_vec_from_local_lanes::<P>(
                        config,
                        &label.child(format!("bit_{bit}")),
                        values
                            .iter()
                            .map(|&value| (talus_core::reduce_mod_q::<P>(value) >> bit) & 1)
                            .collect(),
                    )
                    .expect("comparison bit vector")
            })
            .collect()
    }

    #[cfg(feature = "production-release-checks")]
    fn drive_comparison_to_opened_bits<P: MlDsaParams>(
        runtime: &mut TestLatestRoundProductionVectorPrimeFieldRuntime,
        config: &DkgConfig,
        state: &mut ProductionPublicComparisonVecState,
        label: &Power2RoundTranscriptLabel,
    ) -> Vec<Coeff> {
        let mut entropy = TestProductionVectorEntropy { next: 901_000 };
        let mut rounds = 0u64;
        while !state.is_done() {
            runtime
                .drive_public_comparison_vec_step::<P, _>(config, state, &mut entropy)
                .expect("drive comparison");
            match runtime
                .collect_public_comparison_vec_step::<P>(config, state)
                .expect("collect comparison")
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("one-party comparison unexpectedly waiting: {status:?}");
                }
            }
            rounds = rounds.saturating_add(1);
            assert!(rounds < 64, "comparison did not converge");
        }
        let result = state.result().expect("comparison result").clone();
        runtime
            .drive_open_bit_share_vec::<P>(config, &result, label)
            .expect("drive comparison opening");
        match runtime
            .collect_open_bit_share_vec::<P>(config, label)
            .expect("collect comparison opening")
        {
            ProductionVectorItMpcCollectResult::Collected { value, .. } => value,
            ProductionVectorItMpcCollectResult::Waiting(status) => {
                panic!("one-party comparison opening unexpectedly waiting: {status:?}");
            }
        }
    }

    #[cfg(feature = "scaffold-dev")]
    fn test_production_vector_prime_field_runtimes(
        config: &DkgConfig,
    ) -> Vec<TestProductionVectorPrimeFieldRuntime> {
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
                let state = talus_dkg::TransportPrimeFieldMpcStateMachine::new(
                    config.clone(),
                    party,
                    transport,
                )
                .expect("state machine");
                let party_runtime = talus_dkg::TransportPrimeFieldMpcPartyRuntime::new(
                    state,
                    talus_dkg::InMemoryPrimeFieldMpcWireMessageLog::default(),
                );
                ProductionVectorPrimeFieldMpcRuntime::new(
                    talus_dkg::CursoredTransportPrimeFieldMpcPartyRuntime::new(
                        party_runtime,
                        talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog::default(),
                    ),
                )
            })
            .collect()
    }

    #[cfg(feature = "scaffold-dev")]
    fn route_production_vector_messages(runtimes: &mut [TestProductionVectorPrimeFieldRuntime]) {
        let mut private_deliveries = Vec::new();
        let mut broadcast_deliveries = Vec::new();
        for runtime in runtimes.iter() {
            let local_party = runtime.inner().runtime().local_party().0;
            private_deliveries.extend(
                runtime
                    .inner()
                    .runtime()
                    .state()
                    .transport()
                    .private_messages()
                    .iter()
                    .filter(|delivery| delivery.sender_party_id == local_party)
                    .cloned(),
            );
            broadcast_deliveries.extend(
                runtime
                    .inner()
                    .runtime()
                    .state()
                    .transport()
                    .broadcast_deliveries()
                    .iter()
                    .filter(|delivery| delivery.message.header.sender_party_id == local_party)
                    .cloned(),
            );
        }
        for delivery in private_deliveries {
            let receiver = runtimes
                .iter_mut()
                .find(|runtime| {
                    runtime.inner().runtime().local_party().0 == delivery.receiver_party_id
                })
                .expect("receiver runtime");
            if receiver.inner().runtime().local_party().0 == delivery.sender_party_id {
                continue;
            }
            receiver
                .inner_mut()
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .inject_private(
                    delivery.sender_party_id,
                    delivery.receiver_party_id,
                    delivery.message,
                )
                .expect("route private message");
        }
        for delivery in broadcast_deliveries {
            for runtime in runtimes.iter_mut() {
                if runtime.inner().runtime().local_party().0
                    == delivery.message.header.sender_party_id
                {
                    continue;
                }
                runtime
                    .inner_mut()
                    .runtime_mut()
                    .state_mut()
                    .transport_mut()
                    .inject_broadcast_delivery(delivery.observer_party_id, delivery.message.clone())
                    .expect("route broadcast message");
            }
        }
    }

    #[cfg(feature = "scaffold-dev")]
    fn clear_production_vector_message_queues(
        runtimes: &mut [TestProductionVectorPrimeFieldRuntime],
    ) {
        for runtime in runtimes {
            runtime
                .inner_mut()
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
    }

    #[test]
    fn masked_broadcast_runtime_bindings_must_match_vector_runtime_evidence() {
        let session_id = session(81);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let evidence = release_vector_runtime_evidence();
        let envelopes = inputs
            .iter()
            .map(|input| {
                prepare_masked_broadcast_envelope_with_vector_runtime_evidence::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    &evidence,
                )
                .expect("runtime-derived envelope")
            })
            .collect::<Vec<_>>();
        let statement = preprocessing_certification_runtime_statement_from_envelopes::<MlDsa65>(
            session_id,
            inputs.clone(),
            envelopes.clone(),
            transcript,
        )
        .expect("runtime statement");

        assert_eq!(
            validate_masked_broadcast_bindings_for_vector_runtime::<MlDsa65>(
                &statement,
                evidence.transcript_hash
            ),
            Ok(())
        );

        let mismatched_envelopes = inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| {
                prepare_masked_broadcast_envelope_with_runtime_transcript::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    [0x40u8.wrapping_add(idx as u8); 32],
                )
                .expect("arbitrary runtime envelope")
            })
            .collect::<Vec<_>>();
        let mismatched_statement = preprocessing_certification_runtime_statement_from_envelopes::<
            MlDsa65,
        >(session_id, inputs, mismatched_envelopes, transcript)
        .expect("mismatched runtime statement still decodes");

        assert_eq!(
            validate_masked_broadcast_bindings_for_vector_runtime::<MlDsa65>(
                &mismatched_statement,
                evidence.transcript_hash
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
    }

    fn preprocessing_statement_phase_cursors(
        statement: &PreprocessingCertificationRuntimeStatement,
    ) -> Vec<PrimeFieldMpcPhaseCursor> {
        let root = preprocessing_certification_runtime_label(statement);
        [
            (
                PrimeFieldMpcRoundKind::Open,
                PrimeFieldMpcPhase::PreprocessingMaskedBroadcast,
                root.child("masked_broadcast")
                    .child("preprocessing_masked_broadcast"),
            ),
            (
                PrimeFieldMpcRoundKind::AssertZero,
                PrimeFieldMpcPhase::PreprocessingCarryCompare,
                root.child("carry_compare")
                    .child("preprocessing_carry_compare"),
            ),
            (
                PrimeFieldMpcRoundKind::AssertZero,
                PrimeFieldMpcPhase::PreprocessingCefBcc,
                root.child("cef_bcc").child("preprocessing_cef_bcc"),
            ),
        ]
        .into_iter()
        .map(|(kind, phase, label)| PrimeFieldMpcPhaseCursor {
            kind,
            phase,
            receiver: None,
            label_hash: power2round_label_hash(&label),
            state: PrimeFieldMpcPhaseCursorState::Collected,
            expected: statement.signer_set.len(),
            got: statement.signer_set.len(),
        })
        .collect()
    }

    #[test]
    fn preprocessing_runtime_statement_requires_collected_statement_phase_cursors() {
        let session_id = session(82);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let evidence = release_vector_runtime_evidence();
        let envelopes = inputs
            .iter()
            .map(|input| {
                prepare_masked_broadcast_envelope_with_vector_runtime_evidence::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    &evidence,
                )
                .expect("runtime-derived envelope")
            })
            .collect::<Vec<_>>();
        let statement = preprocessing_certification_runtime_statement_from_envelopes::<MlDsa65>(
            session_id,
            inputs.clone(),
            envelopes.clone(),
            transcript,
        )
        .expect("runtime statement");
        let cursors = preprocessing_statement_phase_cursors(&statement);

        assert_eq!(
            ensure_preprocessing_statement_phase_cursors(&statement, &cursors),
            Ok(())
        );

        let mut missing = cursors.clone();
        missing.pop();
        assert_eq!(
            ensure_preprocessing_statement_phase_cursors(&statement, &missing),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );

        let mut wrong_state = cursors;
        wrong_state[0].state = PrimeFieldMpcPhaseCursorState::WaitingBroadcast;
        assert_eq!(
            ensure_preprocessing_statement_phase_cursors(&statement, &wrong_state),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
    }

    #[test]
    fn preprocessing_runtime_statement_binds_private_circuit_label_roots() {
        let session_id = session(84);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let evidence = release_vector_runtime_evidence();
        let envelopes = inputs
            .iter()
            .map(|input| {
                prepare_masked_broadcast_envelope_with_vector_runtime_evidence::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    &evidence,
                )
                .expect("runtime-derived envelope")
            })
            .collect::<Vec<_>>();
        let statement = preprocessing_certification_runtime_statement_from_envelopes::<MlDsa65>(
            session_id,
            inputs.clone(),
            envelopes.clone(),
            transcript,
        )
        .expect("runtime statement");
        let (expected_carry, expected_cef_bcc) =
            preprocessing_private_circuit_label_hashes(session_id, transcript);

        assert_eq!(
            statement.carry_compare_private_circuit_label_hash,
            expected_carry
        );
        assert_eq!(
            statement.cef_bcc_private_circuit_label_hash,
            expected_cef_bcc
        );
        assert_eq!(
            ensure_preprocessing_statement_private_label_hashes(&statement),
            Ok(())
        );

        let raw_runtime_transcript = [0x42; 32];
        let carry_stage_hash =
            preprocessing_stage_runtime_transcript_hash_from_vector_runtime_evidence(
                PreprocessingCertificationStage::CarryCompare,
                &statement,
                raw_runtime_transcript,
            );
        let mut mutated = statement.clone();
        mutated.carry_compare_private_circuit_label_hash[0] ^= 0x80;
        assert_eq!(
            ensure_preprocessing_statement_private_label_hashes(&mutated),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        assert_ne!(
            carry_stage_hash,
            preprocessing_stage_runtime_transcript_hash_from_vector_runtime_evidence(
                PreprocessingCertificationStage::CarryCompare,
                &mutated,
                raw_runtime_transcript,
            )
        );
    }

    #[test]
    fn preprocessing_runtime_statement_binds_public_circuit_inputs() {
        let session_id = session(85);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let evidence = release_vector_runtime_evidence();
        let envelopes = inputs
            .iter()
            .map(|input| {
                prepare_masked_broadcast_envelope_with_vector_runtime_evidence::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    &evidence,
                )
                .expect("runtime-derived envelope")
            })
            .collect::<Vec<_>>();
        let broadcasts =
            open_broadcasts(session_id, &envelopes, transcript).expect("opened broadcasts");
        let expected = preprocessing_public_circuit_input_hashes::<MlDsa65>(
            session_id,
            transcript,
            &signer_set,
            &broadcasts,
        )
        .expect("public input hashes");
        let statement = preprocessing_certification_runtime_statement_from_envelopes::<MlDsa65>(
            session_id, inputs, envelopes, transcript,
        )
        .expect("runtime statement");

        assert_eq!(statement.carry_compare_public_input_hash, expected.0);
        assert_eq!(statement.cef_bcc_public_input_hash, expected.1);
        assert_eq!(
            ensure_preprocessing_statement_public_input_hashes(&statement),
            Ok(())
        );

        let raw_runtime_transcript = [0x43; 32];
        let bcc_stage_hash =
            preprocessing_stage_runtime_transcript_hash_from_vector_runtime_evidence(
                PreprocessingCertificationStage::Bcc,
                &statement,
                raw_runtime_transcript,
            );
        let mut mutated = statement.clone();
        mutated.cef_bcc_public_input_hash[0] ^= 0x11;
        assert_ne!(
            bcc_stage_hash,
            preprocessing_stage_runtime_transcript_hash_from_vector_runtime_evidence(
                PreprocessingCertificationStage::Bcc,
                &mutated,
                raw_runtime_transcript,
            )
        );
        mutated.carry_compare_public_input_hash = [0u8; 32];
        assert_eq!(
            ensure_preprocessing_statement_public_input_hashes(&mutated),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
    }

    #[test]
    fn preprocessing_private_circuit_inputs_must_match_statement() {
        let session_id = session(86);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let evidence = release_vector_runtime_evidence();
        let envelopes = inputs
            .iter()
            .map(|input| {
                prepare_masked_broadcast_envelope_with_vector_runtime_evidence::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    &evidence,
                )
                .expect("runtime-derived envelope")
            })
            .collect::<Vec<_>>();
        let statement = preprocessing_certification_runtime_statement_from_envelopes::<MlDsa65>(
            session_id,
            inputs.clone(),
            envelopes.clone(),
            transcript,
        )
        .expect("runtime statement");

        let config = talus_dkg::DkgConfig::new::<MlDsa65>(
            2,
            vec![PartyId(1), PartyId(2), PartyId(3)],
            talus_dkg::KeygenEpoch(86),
        )
        .expect("dkg config");
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
        let runtime = talus_dkg::ProductionVectorPrimeFieldMpcRuntime::new(
            talus_dkg::CursoredTransportPrimeFieldMpcPartyRuntime::new(
                party_runtime,
                talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog::default(),
            ),
        );
        let root = preprocessing_certification_runtime_label(&statement);
        let carry_bit = runtime
            .bit_share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &root
                    .child("carry_compare_private")
                    .child("rho_gt_t")
                    .child("rho_bit_0"),
                vec![0; statement.coeff_count],
            )
            .expect("carry bit handle");
        let cef_bit = runtime
            .bit_share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &root
                    .child("cef_bcc_private")
                    .child("bcc_sum_leq")
                    .child("bcc_bit_0"),
                vec![1; statement.coeff_count],
            )
            .expect("cef/bcc bit handle");
        let handles =
            PreprocessingPrivateCircuitHandles::new(vec![carry_bit.clone()], vec![cef_bit.clone()])
                .expect("private handle bundle");
        let binding_from_handles = handles
            .bind_to_statement(&statement)
            .expect("binding from handle bundle");
        assert_eq!(
            ensure_preprocessing_private_circuit_inputs_match_statement(
                &statement,
                &binding_from_handles
            ),
            Ok(())
        );
        assert!(!format!("{handles:?}").contains("lanes: ["));
        assert_eq!(
            PreprocessingPrivateCircuitHandles::new(Vec::new(), vec![cef_bit.clone()]),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        let binding = PreprocessingPrivateCircuitInputs::from_runtime_bit_handles(
            &statement,
            core::slice::from_ref(&carry_bit),
            &[],
            core::slice::from_ref(&cef_bit),
        )
        .expect("private input binding");
        assert_eq!(
            ensure_preprocessing_private_circuit_inputs_match_statement(&statement, &binding),
            Ok(())
        );
        assert_ne!(binding.carry_compare_private_handle_hash, [0; 32]);
        assert_ne!(binding.cef_bcc_private_handle_hash, [0; 32]);
        assert!(!format!("{binding:?}").contains("private_handle_hash: ["));

        let mut wrong_statement = statement.clone();
        wrong_statement.carry_compare_public_input_hash[0] ^= 0x44;
        assert_eq!(
            ensure_preprocessing_private_circuit_inputs_match_statement(&wrong_statement, &binding),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        let short_carry_bit = runtime
            .bit_share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &root.child("carry_compare_private").child("short"),
                vec![0; statement.coeff_count - 1],
            )
            .expect("short carry bit handle");
        assert_eq!(
            PreprocessingPrivateCircuitInputs::from_runtime_bit_handles(
                &statement,
                &[short_carry_bit],
                &[],
                &[cef_bit],
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
    }

    #[test]
    fn preprocessing_private_circuit_driver_starts_from_runtime_handles() {
        let session_id = session(87);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let evidence = release_vector_runtime_evidence();
        let envelopes = inputs
            .iter()
            .map(|input| {
                prepare_masked_broadcast_envelope_with_vector_runtime_evidence::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    &evidence,
                )
                .expect("runtime-derived envelope")
            })
            .collect::<Vec<_>>();
        let broadcasts =
            open_broadcasts(session_id, &envelopes, transcript).expect("opened masked broadcasts");
        let statement = preprocessing_certification_runtime_statement_from_envelopes::<MlDsa65>(
            session_id,
            inputs.clone(),
            envelopes.clone(),
            transcript,
        )
        .expect("runtime statement");

        let config = talus_dkg::DkgConfig::new::<MlDsa65>(
            2,
            vec![PartyId(1), PartyId(2), PartyId(3)],
            talus_dkg::KeygenEpoch(87),
        )
        .expect("dkg config");
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
        let mut runtime = talus_dkg::ProductionVectorPrimeFieldMpcRuntime::new(
            talus_dkg::CursoredTransportPrimeFieldMpcPartyRuntime::new(
                party_runtime,
                talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog::default(),
            ),
        );
        let adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let (started_statement, started_broadcasts, state) = adapter
            .start_private_circuit_handles_from_envelopes::<MlDsa65>(
                &config,
                session_id,
                inputs.clone(),
                envelopes.clone(),
                transcript,
            )
            .expect("start from release envelopes");
        assert_eq!(started_statement, statement);
        assert_eq!(started_broadcasts, broadcasts);
        assert!(!state.is_done());
        assert_eq!(
            adapter.finish_private_circuit_handles(&state),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );

        let private_material = adapter
            .derive_private_material_handles_from_opened_preprocessing::<MlDsa65>(
                &config,
                &statement,
                &broadcasts,
            )
            .expect("adapter-derived private material handles");
        assert!(!format!("{private_material:?}").contains("lanes: ["));
        let private_state = adapter
            .derive_private_material_state_from_opened_preprocessing::<MlDsa65>(
                &config,
                &statement,
                &broadcasts,
            )
            .expect("adapter-derived private material state");
        assert_eq!(
            private_state.source(),
            PreprocessingPrivateMaterialStateSource::OpenedMaterialDerived
        );
        assert!(!format!("{private_state:?}").contains("lanes: ["));
        let mut wrong_statement = statement.clone();
        wrong_statement.carry_compare_public_input_hash[0] ^= 0x55;
        assert_eq!(
            adapter.derive_private_material_handles_from_opened_preprocessing::<MlDsa65>(
                &config,
                &wrong_statement,
                &broadcasts,
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        assert_eq!(
            adapter.derive_private_material_handles_from_opened_preprocessing::<MlDsa65>(
                &config,
                &statement,
                &broadcasts[..1],
            ),
            Err(PreprocessError::CoeffCountMismatch)
        );
        let err = adapter
            .start_private_circuit_handles_from_state::<MlDsa65>(
                &config,
                &wrong_statement,
                &broadcasts,
                &private_state,
            )
            .expect_err("wrong statement rejects state");
        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
        let err = adapter
            .start_private_circuit_handles_from_state::<MlDsa65>(
                &config,
                &statement,
                &broadcasts[..1],
                &private_state,
            )
            .expect_err("wrong broadcasts reject state");
        assert_eq!(err, PreprocessError::CoeffCountMismatch);
        let state = adapter
            .start_private_circuit_handles_from_preprocessing_material::<MlDsa65>(
                &config,
                &statement,
                &broadcasts,
                &private_material,
            )
            .expect("private circuit state from preprocessing material");
        assert!(!state.is_done());
        assert_eq!(
            adapter.finish_private_circuit_handles(&state),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );

        let root = preprocessing_certification_runtime_label(&statement);
        let carry_width = bit_width_for_preprocessing_public_value(MlDsa65::alpha() as u32);
        let relation_bits = adapter
            .start_preprocessing_masked_broadcast_consistency_vec::<MlDsa65>(
                &config,
                &statement,
                &broadcasts,
            )
            .expect("runtime-owned masked-broadcast relation bits");
        let mut mismatched_broadcasts = broadcasts.clone();
        mismatched_broadcasts[0].masked_highs[0] ^= 1;
        assert_eq!(
            adapter.start_preprocessing_masked_broadcast_consistency_vec::<MlDsa65>(
                &config,
                &statement,
                &mismatched_broadcasts,
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        let mut wrong_binding_statement = statement.clone();
        wrong_binding_statement.masked_broadcast_bindings[0].statement_hash[0] ^= 0x80;
        assert_eq!(
            adapter.start_preprocessing_masked_broadcast_consistency_vec::<MlDsa65>(
                &config,
                &wrong_binding_statement,
                &broadcasts,
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        assert_eq!(
            adapter.start_preprocessing_masked_broadcast_consistency_vec::<MlDsa65>(
                &config,
                &statement,
                &broadcasts[..1],
            ),
            Err(PreprocessError::CoeffCountMismatch)
        );
        let derived_carry_bits = adapter
            .start_preprocessing_carry_compare_rho_sum_bits_vec::<MlDsa65>(
                &config,
                &statement,
                &broadcasts,
            )
            .expect("runtime-owned rho-sum bits");
        assert_eq!(derived_carry_bits.len(), carry_width);
        assert_eq!(
            adapter.start_preprocessing_carry_compare_rho_sum_bits_vec::<MlDsa65>(
                &config,
                &statement,
                &mismatched_broadcasts,
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        let mut wrong_transcript_broadcasts = broadcasts.clone();
        wrong_transcript_broadcasts[0].transcript_hash.0[0] ^= 0x01;
        assert_eq!(
            adapter.start_preprocessing_carry_compare_rho_sum_bits_vec::<MlDsa65>(
                &config,
                &statement,
                &wrong_transcript_broadcasts,
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        let mut short_broadcasts = broadcasts.clone();
        short_broadcasts[0].masked_lows.pop();
        assert_eq!(
            adapter.start_preprocessing_carry_compare_rho_sum_bits_vec::<MlDsa65>(
                &config,
                &statement,
                &short_broadcasts,
            ),
            Err(PreprocessError::CoeffCountMismatch)
        );
        let derived_bcc_bits = adapter
            .start_preprocessing_bcc_violation_bits_vec::<MlDsa65>(&config, &statement, &broadcasts)
            .expect("runtime-owned bcc violation bits");
        assert_eq!(derived_bcc_bits.len(), 1);
        let derived_cef_bits = adapter
            .start_preprocessing_cef_correction_bits_vec::<MlDsa65>(
                &config,
                &statement,
                &broadcasts,
            )
            .expect("runtime-owned cef correction bits");
        assert_eq!(derived_cef_bits.len(), 1);
        assert_eq!(
            adapter.start_preprocessing_cef_correction_bits_vec::<MlDsa65>(
                &config,
                &statement,
                &mismatched_broadcasts,
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        assert_eq!(
            adapter.start_preprocessing_bcc_violation_bits_vec::<MlDsa65>(
                &config,
                &statement,
                &mismatched_broadcasts,
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        assert_eq!(
            adapter.start_preprocessing_bcc_violation_bits_vec::<MlDsa65>(
                &config,
                &statement,
                &wrong_transcript_broadcasts,
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        assert_eq!(
            adapter.start_preprocessing_bcc_violation_bits_vec::<MlDsa65>(
                &config,
                &statement,
                &short_broadcasts,
            ),
            Err(PreprocessError::CoeffCountMismatch)
        );
        let runtime_private_state = adapter
            .derive_private_material_state_from_runtime_private_mpc_handles::<MlDsa65>(
                &config,
                &statement,
                &broadcasts,
            )
            .expect("runtime-private mpc state");
        assert_eq!(
            runtime_private_state.source(),
            PreprocessingPrivateMaterialStateSource::RuntimePrivateMpc
        );
        adapter
            .start_private_circuit_handles_from_state::<MlDsa65>(
                &config,
                &statement,
                &broadcasts,
                &runtime_private_state,
            )
            .expect("runtime-private state starts private circuits");
        let unfinished_runtime_state = adapter
            .start_private_circuit_handles_from_state::<MlDsa65>(
                &config,
                &statement,
                &broadcasts,
                &runtime_private_state,
            )
            .expect("runtime-private state starts private circuits");
        assert_eq!(
            adapter
                .finish_runtime_masked_broadcast_output::<MlDsa65>(
                    &statement,
                    &unfinished_runtime_state,
                )
                .expect_err("unfinished masked-broadcast output rejects"),
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
        assert_eq!(
            adapter
                .finish_runtime_carry_compare_output::<MlDsa65>(
                    &statement,
                    &unfinished_runtime_state,
                )
                .expect_err("unfinished CarryCompare output rejects"),
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
        let fake_carry_output = RuntimeCarryCompareOutput {
            coeff_count: statement.coeff_count,
            evidence_hash: statement.carry_compare_evidence_hash,
            runtime_transcript_hash: statement.masked_broadcast_runtime_transcript,
        };
        assert_eq!(
            adapter
                .finish_runtime_cef_bcc_output::<MlDsa65>(
                    &statement,
                    &unfinished_runtime_state,
                    fake_carry_output,
                )
                .expect_err("unfinished CEF/BCC output rejects"),
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
        let runtime_private_input = PreprocessingRuntimePrivateMpcStateInput::new::<MlDsa65>(
            &statement,
            relation_bits.clone(),
            derived_carry_bits.clone(),
            derived_cef_bits.clone(),
            derived_bcc_bits.clone(),
        )
        .expect("runtime-private mpc input");
        assert!(!format!("{runtime_private_input:?}").contains("lanes: ["));
        assert_eq!(
            PreprocessingRuntimePrivateMpcStateInput::new::<MlDsa65>(
                &statement,
                Vec::new(),
                derived_carry_bits.clone(),
                derived_cef_bits.clone(),
                derived_bcc_bits.clone(),
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        let mut wrong_relation_bits = relation_bits.clone();
        wrong_relation_bits[0] = adapter
            .runtime
            .bit_share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &root
                    .child("masked_broadcast_private")
                    .child("wrong_relation"),
                vec![0; statement.coeff_count],
            )
            .expect("wrong relation bit");
        assert_eq!(
            PreprocessingRuntimePrivateMpcStateInput::new::<MlDsa65>(
                &statement,
                wrong_relation_bits,
                derived_carry_bits.clone(),
                derived_cef_bits.clone(),
                derived_bcc_bits.clone(),
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        let mut replayed_relation_label_bits = relation_bits.clone();
        replayed_relation_label_bits[1] = replayed_relation_label_bits[0].clone();
        assert_eq!(
            PreprocessingRuntimePrivateMpcStateInput::new::<MlDsa65>(
                &statement,
                replayed_relation_label_bits,
                derived_carry_bits.clone(),
                derived_cef_bits.clone(),
                derived_bcc_bits.clone(),
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        let mut short_carry_bits = derived_carry_bits.clone();
        short_carry_bits[0] = adapter
            .runtime
            .bit_share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &root
                    .child("carry_compare_private")
                    .child("rho_sum_bits")
                    .child("bit_0"),
                vec![0; statement.coeff_count - 1],
            )
            .expect("short carry bit");
        assert_eq!(
            PreprocessingRuntimePrivateMpcStateInput::new::<MlDsa65>(
                &statement,
                relation_bits.clone(),
                short_carry_bits,
                derived_cef_bits.clone(),
                derived_bcc_bits.clone(),
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        let mut wrong_label_bits = derived_carry_bits.clone();
        wrong_label_bits[0] = adapter
            .runtime
            .bit_share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &root.child("wrong_rho_sum_bit_0"),
                vec![0; statement.coeff_count],
            )
            .expect("wrong-label carry bit");
        assert_eq!(
            adapter.private_material_handles_from_runtime_bits::<MlDsa65>(
                &statement,
                relation_bits.clone(),
                wrong_label_bits,
                derived_cef_bits.clone(),
                derived_bcc_bits.clone(),
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        let mut short_bcc_bits = derived_bcc_bits.clone();
        short_bcc_bits[0] = adapter
            .runtime
            .bit_share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &root
                    .child("cef_bcc_private")
                    .child("bcc_violation_bits")
                    .child("violation"),
                vec![0; statement.coeff_count - 1],
            )
            .expect("short bcc bit");
        assert_eq!(
            adapter.private_material_handles_from_runtime_bits::<MlDsa65>(
                &statement,
                relation_bits,
                derived_carry_bits,
                derived_cef_bits,
                short_bcc_bits,
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );

        let err = adapter
            .start_private_circuit_handles_from_preprocessing_material::<MlDsa65>(
                &config,
                &statement,
                &broadcasts[..1],
                &private_material,
            )
            .expect_err("wrong broadcast material rejects");
        assert_eq!(err, PreprocessError::CoeffCountMismatch);

        let mut cross_session_statement = statement.clone();
        cross_session_statement.session_id = session(88);
        let err = adapter
            .start_private_circuit_handles_from_state::<MlDsa65>(
                &config,
                &cross_session_statement,
                &broadcasts,
                &runtime_private_state,
            )
            .expect_err("cross-session runtime-private state replay rejects");
        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn production_release_rejects_opened_material_private_state_source() {
        let session_id = session(187);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let evidence = release_vector_runtime_evidence();
        let envelopes = inputs
            .iter()
            .map(|input| {
                prepare_masked_broadcast_envelope_with_vector_runtime_evidence::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    &evidence,
                )
                .expect("runtime-derived envelope")
            })
            .collect::<Vec<_>>();
        let broadcasts =
            open_broadcasts(session_id, &envelopes, transcript).expect("opened masked broadcasts");
        let statement = preprocessing_certification_runtime_statement_from_envelopes::<MlDsa65>(
            session_id,
            inputs.clone(),
            envelopes.clone(),
            transcript,
        )
        .expect("runtime statement");
        let config = talus_dkg::DkgConfig::new::<MlDsa65>(
            2,
            vec![PartyId(1), PartyId(2), PartyId(3)],
            talus_dkg::KeygenEpoch(187),
        )
        .expect("dkg config");
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
        let mut runtime = talus_dkg::ProductionVectorPrimeFieldMpcRuntime::new(
            talus_dkg::CursoredTransportPrimeFieldMpcPartyRuntime::new(
                party_runtime,
                talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog::default(),
            ),
        );
        let adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let private_state = adapter
            .derive_private_material_state_from_opened_preprocessing::<MlDsa65>(
                &config,
                &statement,
                &broadcasts,
            )
            .expect("opened-material state is derivable");

        let err = adapter
            .start_private_circuit_handles_from_state::<MlDsa65>(
                &config,
                &statement,
                &broadcasts,
                &private_state,
            )
            .expect_err("production-release rejects transitional source");
        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );

        let runtime_state = adapter
            .derive_private_material_state_from_runtime_private_mpc_handles::<MlDsa65>(
                &config,
                &statement,
                &broadcasts,
            )
            .expect("runtime-private state is derivable");
        assert_eq!(
            runtime_state.source(),
            PreprocessingPrivateMaterialStateSource::RuntimePrivateMpc
        );
        adapter
            .start_private_circuit_handles_from_state::<MlDsa65>(
                &config,
                &statement,
                &broadcasts,
                &runtime_state,
            )
            .expect("production-release accepts runtime-private source");

        let (started_statement, started_broadcasts, started_state) = adapter
            .start_private_circuit_handles_from_envelopes::<MlDsa65>(
                &config, session_id, inputs, envelopes, transcript,
            )
            .expect("production-release starts envelopes from runtime-private source");
        assert_eq!(started_statement, statement);
        assert_eq!(started_broadcasts, broadcasts);
        assert!(!started_state.is_done());
    }

    fn runtime_proofs_from_envelopes_and_preview<P: MlDsaParams>(
        session_id: SessionId,
        transcript_hash: TranscriptHash,
        signer_count: usize,
        coeff_count: usize,
        envelopes: &[BroadcastEnvelope],
        preview: &CertifiedToken,
    ) -> PreprocessingCertificationRuntimeProofs {
        let masked_hashes = envelopes
            .iter()
            .map(|envelope| {
                decode_masked_broadcast_runtime_proof(&envelope.consistency_proof)
                    .expect("typed masked-broadcast runtime proof")
                    .runtime_transcript_hash
            })
            .collect::<Vec<_>>();
        let carry_hash = preview
            .certification_evidence
            .carry_compare
            .expect("carry evidence")
            .evidence_hash;
        let bcc_hash = preview
            .certification_evidence
            .bcc
            .expect("bcc evidence")
            .evidence_hash;
        let carry_runtime_transcript = [0xc1; 32];
        let bcc_runtime_transcript = [0xb1; 32];
        let masked_broadcast = masked_broadcast_runtime_transcript_hash(
            session_id,
            transcript_hash,
            signer_count,
            coeff_count,
            &masked_hashes,
        );
        PreprocessingCertificationRuntimeProofs {
            masked_broadcast,
            carry_compare: preprocessing_certification_stage_runtime_proof::<P>(
                PreprocessingCertificationStage::CarryCompare,
                session_id,
                transcript_hash,
                signer_count,
                coeff_count,
                carry_hash,
                carry_runtime_transcript,
            )
            .expect("carry runtime proof"),
            bcc: preprocessing_certification_stage_runtime_proof::<P>(
                PreprocessingCertificationStage::Bcc,
                session_id,
                transcript_hash,
                signer_count,
                coeff_count,
                bcc_hash,
                bcc_runtime_transcript,
            )
            .expect("bcc runtime proof"),
            outputs: PreprocessingCertificationRuntimeOutputs {
                masked_broadcast: RuntimeMaskedBroadcastOutput {
                    signer_count,
                    coeff_count,
                    runtime_transcript_hash: masked_broadcast,
                    material_state_hash: [0xa5; 32],
                },
                carry_compare: RuntimeCarryCompareOutput {
                    coeff_count,
                    evidence_hash: carry_hash,
                    runtime_transcript_hash: carry_runtime_transcript,
                },
                cef_bcc: RuntimeCefBccOutput {
                    coeff_count,
                    w1_hash: hash_runtime_w1_output::<P>(
                        session_id,
                        transcript_hash,
                        &preview.signer_set,
                        &preview.w1,
                    ),
                    carry_compare_evidence_hash: carry_hash,
                    bcc_evidence_hash: bcc_hash,
                    runtime_transcript_hash: bcc_runtime_transcript,
                    token_admitted: true,
                },
            },
        }
    }

    #[cfg(feature = "std")]
    fn test_store_path(name: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "talus-session-{name}-{}-{unique}.log",
            std::process::id()
        ))
    }

    #[test]
    fn preprocess_certifies_token() {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(1),
            vec![
                input(1, &[1, 2], &[3, 4]),
                input(2, &[5, 6], &[7, 8]),
                input(3, &[9, 10], &[11, 12]),
            ],
        )
        .expect("valid preprocessing certifies");

        assert!(token.is_certified());
        assert_eq!(token.session_id, session(1));
        assert_eq!(token.signer_set, vec![PartyId(1), PartyId(2), PartyId(3)]);
        assert_eq!(token.w1.len(), 2);
        assert_eq!(token.nonce_commitments.len(), 3);
        assert_eq!(token.y_share.len(), 24);
        assert_eq!(token.broadcasts.len(), 3);

        for coeff in 0..token.w1.len() {
            let highs = [1, 5, 9].map(|party_high| party_high + coeff as u32);
            let lows = [3, 7, 11].map(|party_low| party_low + coeff as u32);
            assert_eq!(
                token.w1[coeff],
                cef_w1_clear_coeff::<MlDsa65>(&highs, &lows)
            );
        }
    }

    #[test]
    fn preprocessing_session_routes_wire_messages_and_certifies_token() {
        let options = PreprocessingSessionOptions {
            session_id: session(70),
            signer_set: vec![PartyId(3), PartyId(1), PartyId(2)],
            keygen_transcript_hash: [0x42; 32],
        };
        let mut sessions = vec![
            PreprocessingSession::<MlDsa65, _, _>::start(
                options.clone(),
                input(1, &[1, 2], &[3, 4]),
                SessionRegistry::new(),
                ProductMaskedBroadcastConsistencyVerifier,
            )
            .expect("start party 1"),
            PreprocessingSession::<MlDsa65, _, _>::start(
                options.clone(),
                input(2, &[5, 6], &[7, 8]),
                SessionRegistry::new(),
                ProductMaskedBroadcastConsistencyVerifier,
            )
            .expect("start party 2"),
            PreprocessingSession::<MlDsa65, _, _>::start(
                options,
                input(3, &[9, 10], &[11, 12]),
                SessionRegistry::new(),
                ProductMaskedBroadcastConsistencyVerifier,
            )
            .expect("start party 3"),
        ];

        route_preprocessing_broadcasts(&mut sessions);

        let tokens = sessions
            .into_iter()
            .map(|session| session.finish().expect("certified token"))
            .collect::<Vec<_>>();

        for token in &tokens {
            assert!(token.is_certified());
            assert_eq!(token.session_id, session(70));
            assert_eq!(token.signer_set, vec![PartyId(1), PartyId(2), PartyId(3)]);
            assert_eq!(token.w1, tokens[0].w1);
            assert_eq!(token.nonce_commitments.len(), 3);
            assert_eq!(token.broadcasts.len(), 3);
        }
        assert_eq!(tokens[0].y_share.len(), 8);
        assert_eq!(tokens[1].y_share.len(), 8);
        assert_eq!(tokens[2].y_share.len(), 8);
        assert_ne!(tokens[0].y_share.as_slice(), tokens[1].y_share.as_slice());
    }

    #[test]
    fn preprocessing_session_opens_masked_broadcast_payloads() {
        let options = PreprocessingSessionOptions {
            session_id: session(73),
            signer_set: vec![PartyId(3), PartyId(1), PartyId(2)],
            keygen_transcript_hash: [0x44; 32],
        };
        let inputs = vec![
            input(1, &[1, 2], &[3, 4]),
            input(2, &[5, 6], &[7, 8]),
            input(3, &[9, 10], &[11, 12]),
        ];
        let mut sessions = inputs
            .iter()
            .cloned()
            .map(|input| {
                PreprocessingSession::<MlDsa65, _, _>::start(
                    options.clone(),
                    input,
                    SessionRegistry::new(),
                    ProductMaskedBroadcastConsistencyVerifier,
                )
                .expect("start preprocessing session")
            })
            .collect::<Vec<_>>();

        let mut commits = Vec::new();
        for session in &mut sessions {
            let outbound = session.next_outbound().expect("commit outbound");
            let PreprocessingOutbound::Broadcast { message } = outbound else {
                panic!("preprocessing commit must be broadcast")
            };
            assert_eq!(message.header.round, RoundId::PreprocessCommit);
            let payload = decode_commit_payload(&message.payload).expect("commit payload");
            commits.push((
                PartyId(message.header.sender_party_id),
                Commitment(payload.commitment),
            ));
        }

        for (_, commitment) in &commits {
            assert_ne!(*commitment, Commitment([0; 32]));
        }

        for (party, commitment) in &commits {
            let message = WireMessage {
                header: WireHeader {
                    protocol_version: WIRE_PROTOCOL_VERSION,
                    suite: SuiteId::MlDsa65,
                    round: RoundId::PreprocessCommit,
                    sender_party_id: party.0,
                    keygen_transcript_hash: options.keygen_transcript_hash,
                    session_id: options.session_id.0,
                    signing_set_hash: signing_set_hash(&[1, 2, 3]),
                    payload_kind: PayloadKind::PreprocessCommit,
                },
                payload: encode_commit_payload(&CommitPayload {
                    commitment: commitment.0,
                }),
            };
            for session in &mut sessions {
                session
                    .handle_broadcast(message.clone())
                    .expect("deliver commit");
            }
        }

        let mut opens = Vec::new();
        for session in &mut sessions {
            let outbound = session.next_outbound().expect("open outbound");
            let PreprocessingOutbound::Broadcast { message } = outbound else {
                panic!("preprocessing open must be broadcast")
            };
            assert_eq!(message.header.round, RoundId::PreprocessOpen);
            opens.push(message);
            assert!(session.next_outbound().is_none());
        }

        for message in &opens {
            let party = PartyId(message.header.sender_party_id);
            let payload =
                decode_masked_broadcast_open_payload(&message.payload).expect("open payload");
            let clear = inputs
                .iter()
                .find(|input| input.party == party)
                .expect("clear input");
            assert!(
                payload.masked_highs != clear.highs || payload.masked_lows != clear.lows,
                "reliable-broadcast open must carry masked values, not clear decomposition"
            );
            assert!(
                !payload.consistency_proof.is_empty(),
                "production preprocessing open must carry a private consistency certificate"
            );
            assert!(
                payload
                    .consistency_proof
                    .starts_with(MASKED_BROADCAST_RUNTIME_PROOF_PREFIX),
                "production preprocessing proof must carry a typed runtime transcript binding"
            );
            let broadcast = MaskedBroadcast {
                party,
                masked_highs: payload.masked_highs,
                masked_lows: payload.masked_lows,
                nonce_commitment: NonceCommitment(payload.nonce_commitment),
                rho_bits_commitment: Commitment(payload.rho_bits_commitment),
                transcript_hash: TranscriptHash(payload.transcript_hash),
            };
            let expected_commitment =
                masked_broadcast_commitment(options.session_id, &broadcast, payload.salt);
            let actual_commitment = commits
                .iter()
                .find(|(commit_party, _)| *commit_party == party)
                .map(|(_, commitment)| *commitment)
                .expect("commitment");
            assert_eq!(expected_commitment, actual_commitment);
        }

        for message in opens {
            for session in &mut sessions {
                session
                    .handle_broadcast(message.clone())
                    .expect("deliver open");
            }
        }
        for session in sessions {
            assert!(session.finish().expect("finish").is_certified());
        }
    }

    #[test]
    fn distributed_nonce_generation_feeds_preprocessing_session() {
        let config = talus_dkg::DkgConfig::new::<MlDsa65>(
            2,
            vec![PartyId(1), PartyId(2), PartyId(3)],
            talus_dkg::KeygenEpoch(9),
        )
        .expect("dkg config");
        let rho = [0x5a; 32];
        let signer_set = config.parties.clone();
        let mut accepted = None;

        for attempt in 0..32u8 {
            let session_id = session(72u8 + attempt);
            let nonce =
                generate_distributed_nonce_shares::<MlDsa65>(DistributedNonceGenerationOptions {
                    session_id,
                    dkg_config: config.clone(),
                    rho,
                    nonce_entropy: [0x21u8.wrapping_add(attempt); 32],
                    it_vss_entropy: [0x22u8.wrapping_add(attempt); 32],
                    it_vss_security: talus_dkg::ProductionItVssSecurityParams {
                        audit_tags: 1,
                        retained_tags: 1,
                        consistency_rounds: 1,
                        max_vector_lanes_per_chunk: 32_000,
                        max_private_delivery_bytes: 16 * 1024 * 1024,
                    },
                })
                .expect("distributed nonce generation");
            let options = PreprocessingSessionOptions {
                session_id,
                signer_set: signer_set.clone(),
                keygen_transcript_hash: config.transcript_hash().0,
            };
            let mut sessions = nonce
                .shares
                .iter()
                .map(|share| {
                    let input = party_preprocess_input_from_distributed_nonce_share::<MlDsa65>(
                        session_id,
                        &signer_set,
                        &rho,
                        share,
                    )
                    .expect("nonce preprocessing input");
                    PreprocessingSession::<MlDsa65, _, _>::start(
                        options.clone(),
                        input,
                        SessionRegistry::new(),
                        ProductMaskedBroadcastConsistencyVerifier,
                    )
                    .expect("preprocessing session")
                })
                .collect::<Vec<_>>();
            route_preprocessing_broadcasts(&mut sessions);
            let mut tokens = Vec::new();
            let mut retry = false;
            for session in sessions {
                match session.finish() {
                    Ok(token) => tokens.push(token),
                    Err(err) if err.is_retryable_pre_challenge() => {
                        retry = true;
                        break;
                    }
                    Err(err) => panic!("unexpected preprocessing failure: {err:?}"),
                }
            }
            if retry {
                continue;
            }
            accepted = Some((session_id, nonce, tokens));
            break;
        }

        let (session_id, nonce, tokens) = accepted.expect("BCC-cleared nonce preprocessing retry");
        assert_eq!(nonce.shares.len(), 3);
        assert_eq!(nonce.evidence.public_commitments.len(), 3);
        assert_eq!(
            nonce.evidence.complaint_resolution.accepted_dealers,
            config.parties
        );
        assert!(nonce
            .evidence
            .complaint_resolution
            .rejected_dealers
            .is_empty());

        for share in &nonce.shares {
            assert_eq!(share.y_share.len(), MlDsa65::L);
            let expected_ay =
                az_from_rho::<MlDsa65>(&rho, &share.y_share).expect("A*y_i commitment");
            let expected_nonce_commitment =
                distributed_nonce_commitment::<MlDsa65>(session_id, share.party, &expected_ay);
            assert_eq!(share.nonce_commitment, expected_nonce_commitment);
            let debug = format!("{share:?}");
            assert!(debug.contains("y_share: \"<redacted>\""));
            assert!(!debug.contains("ay_commitment"));
        }

        assert_eq!(tokens[0].session_id, session_id);
        for token in &tokens {
            assert!(token.is_certified());
            assert!(token.y_share.is_empty());
            assert_eq!(token.w1, tokens[0].w1);
        }

        let points = signer_set
            .iter()
            .map(|party| party.0 as u32)
            .collect::<Vec<_>>();
        let aggregate_y = talus_core::aggregate_z_shares_lagrange::<MlDsa65>(
            &points,
            &nonce
                .shares
                .iter()
                .map(|share| share.y_share.clone())
                .collect::<Vec<_>>(),
        )
        .expect("aggregate nonce shares");
        let aggregate_ay = az_from_rho::<MlDsa65>(&rho, &aggregate_y).expect("A*y");
        let expected_w1 = aggregate_ay
            .polys()
            .iter()
            .flat_map(|poly| {
                poly.coeffs()
                    .iter()
                    .map(|&coeff| talus_core::high_bits::<MlDsa65>(coeff) as u32)
            })
            .collect::<Vec<_>>();
        assert_eq!(tokens[0].w1, expected_w1);
    }

    #[test]
    fn distributed_nonce_generation_session_routes_private_and_broadcast_artifacts() {
        let config = talus_dkg::DkgConfig::new::<MlDsa65>(
            2,
            vec![PartyId(1), PartyId(2), PartyId(3)],
            talus_dkg::KeygenEpoch(11),
        )
        .expect("dkg config");
        let options = DistributedNonceGenerationOptions {
            session_id: session(182),
            dkg_config: config.clone(),
            rho: [0x6a; 32],
            nonce_entropy: [0x41; 32],
            it_vss_entropy: [0x42; 32],
            it_vss_security: talus_dkg::ProductionItVssSecurityParams {
                audit_tags: 1,
                retained_tags: 1,
                consistency_rounds: 1,
                max_vector_lanes_per_chunk: 32_000,
                max_private_delivery_bytes: 16 * 1024 * 1024,
            },
        };
        let expected =
            generate_distributed_nonce_shares::<MlDsa65>(options.clone()).expect("expected output");
        let mut sessions = config
            .parties
            .iter()
            .copied()
            .map(|party| {
                DistributedNonceGenerationSession::<MlDsa65>::start(options.clone(), party)
                    .expect("start nonce generation session")
            })
            .collect::<Vec<_>>();

        route_nonce_generation(&mut sessions);

        let outputs = sessions
            .into_iter()
            .map(|session| session.finish().expect("finish nonce generation"))
            .collect::<Vec<_>>();

        let reference_evidence = outputs[0].evidence.clone();
        for output in &outputs {
            assert_eq!(
                output.evidence.public_commitment_hash,
                reference_evidence.public_commitment_hash
            );
            assert_eq!(
                output.evidence.complaint_resolution_hash,
                reference_evidence.complaint_resolution_hash
            );
            let expected_share = expected
                .shares
                .iter()
                .find(|share| share.party == output.share.party)
                .expect("expected party share");
            assert_eq!(output.share.party, expected_share.party);
            assert_eq!(output.share.y_share, expected_share.y_share);
            assert_eq!(
                output.share.nonce_commitment,
                expected_share.nonce_commitment
            );
            assert_ne!(output.share.randomness_commitment, Commitment([0; 32]));
            assert_eq!(
                output.evidence.complaint_resolution.rejected_dealers,
                vec![]
            );
        }
    }

    #[test]
    fn preprocessing_session_rejects_private_messages() {
        let options = PreprocessingSessionOptions {
            session_id: session(71),
            signer_set: vec![PartyId(1), PartyId(2)],
            keygen_transcript_hash: [0x43; 32],
        };
        let mut session = PreprocessingSession::<MlDsa65, _, _>::start(
            options,
            input(1, &[1], &[3]),
            SessionRegistry::new(),
            ClearMaskedBroadcastConsistencyVerifier,
        )
        .expect("start preprocessing session");

        let message = match session.next_outbound().expect("commit outbound") {
            PreprocessingOutbound::Broadcast { message } => message,
            PreprocessingOutbound::Private { .. } => panic!("unexpected private outbound"),
        };

        assert_eq!(
            session.handle_private(PartyId(2), message),
            Err(PreprocessError::UnexpectedPrivateMessage)
        );
    }

    fn route_preprocessing_broadcasts<P, V>(
        sessions: &mut [PreprocessingSession<P, SessionRegistry, V>],
    ) where
        P: MlDsaParams,
        V: MaskedBroadcastConsistencyVerifier,
    {
        loop {
            let mut outbounds = Vec::new();
            for session in sessions.iter_mut() {
                while let Some(outbound) = session.next_outbound() {
                    outbounds.push(outbound);
                }
            }
            if outbounds.is_empty() {
                break;
            }
            for outbound in outbounds {
                match outbound {
                    PreprocessingOutbound::Broadcast { message } => {
                        for session in sessions.iter_mut() {
                            session
                                .handle_broadcast(message.clone())
                                .expect("deliver broadcast");
                        }
                    }
                    PreprocessingOutbound::Private { .. } => {
                        panic!("preprocessing session should not emit private messages")
                    }
                }
            }
        }
    }

    fn route_nonce_generation<P: MlDsaParams>(
        sessions: &mut [DistributedNonceGenerationSession<P>],
    ) {
        loop {
            let mut outbounds = Vec::new();
            for session in sessions.iter_mut() {
                while let Some(outbound) = session.next_outbound() {
                    outbounds.push(outbound);
                }
            }
            if outbounds.is_empty() {
                break;
            }
            for outbound in outbounds {
                match outbound {
                    DistributedNonceGenerationOutbound::Private { receiver, delivery } => {
                        let session = sessions
                            .iter_mut()
                            .find(|session| session.local_party == receiver)
                            .expect("receiver session");
                        session
                            .handle_private(delivery.dealer, delivery)
                            .expect("deliver private nonce VSS artifact");
                    }
                    DistributedNonceGenerationOutbound::Broadcast { artifact } => {
                        let sender = match &artifact {
                            DistributedNonceGenerationBroadcast::PublicPrecommitment(item) => {
                                item.dealer
                            }
                            DistributedNonceGenerationBroadcast::PublicCoinShare(item) => {
                                item.party
                            }
                            DistributedNonceGenerationBroadcast::PublicCommitment(item) => {
                                item.dealer
                            }
                        };
                        for session in sessions.iter_mut() {
                            session
                                .handle_broadcast(sender, artifact.clone())
                                .expect("deliver nonce generation broadcast");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn production_consistency_verifier_accepts_private_certificate_and_rejects_clear_audit() {
        let mut registry = SessionRegistry::new();
        let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
        let token = certify_preprocessing_token_with_consistency::<MlDsa65, _>(
            &mut verifier,
            &mut registry,
            session(31),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("production private certificate verifies");
        assert!(token.is_certified());

        let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
        let statement = MaskedBroadcastConsistencyStatement {
            session_id: session(32),
            signer_set: vec![PartyId(1), PartyId(2)],
            broadcast: MaskedBroadcast {
                party: PartyId(1),
                masked_highs: vec![9],
                masked_lows: vec![18],
                nonce_commitment: NonceCommitment([1; 32]),
                rho_bits_commitment: Commitment([9; 32]),
                transcript_hash: TranscriptHash([2; 32]),
            },
            coeff_count: 1,
        };
        let audit = MaskedBroadcastClearAudit {
            highs: vec![5],
            lows: vec![7],
            high_masks: vec![3],
            rhos: vec![11],
            rho_bits_commitment: Commitment([9; 32]),
        };
        assert_eq!(
            verifier.verify_masked_broadcast::<MlDsa65>(
                &statement,
                &MaskedBroadcastConsistencyProof::default(),
                Some(&audit),
            ),
            Err(PreprocessError::MaskedBroadcastAuditRequired(PartyId(1)))
        );
    }

    #[test]
    fn production_consistency_verifier_rejects_tampered_private_certificate() {
        let session_id = session(33);
        let signer_set = vec![PartyId(1), PartyId(2)];
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let mut envelope = prepare_masked_broadcast_envelope::<MlDsa65>(
            session_id,
            &signer_set,
            &inputs[0],
            transcript,
        )
        .expect("masked envelope");
        envelope.consistency_proof.bytes[0] ^= 0x55;
        let envelope2 = prepare_masked_broadcast_envelope::<MlDsa65>(
            session_id,
            &signer_set,
            &inputs[1],
            transcript,
        )
        .expect("masked envelope");
        let mut registry = SessionRegistry::new();
        let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
        let err = certify_opened_masked_broadcasts_with_consistency::<MlDsa65, _>(
            &mut verifier,
            &mut registry,
            session_id,
            inputs,
            vec![envelope, envelope2],
            transcript,
            None,
        )
        .expect_err("tampered private certificate rejects");
        assert_eq!(
            err,
            PreprocessError::MaskedBroadcastProofBackendUnavailable(PartyId(1))
        );
    }

    #[test]
    fn production_consistency_verifier_rejects_legacy_hash_only_certificate() {
        let session_id = session(33);
        let signer_set = vec![PartyId(1), PartyId(2)];
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let mut envelope = prepare_masked_broadcast_envelope::<MlDsa65>(
            session_id,
            &signer_set,
            &inputs[0],
            transcript,
        )
        .expect("masked envelope");
        envelope.consistency_proof = MaskedBroadcastConsistencyProof {
            bytes: {
                let mut bytes = Vec::with_capacity(38);
                bytes.extend_from_slice(b"TMBCC1");
                bytes.extend_from_slice(&[0x42; 32]);
                bytes
            },
        };
        let envelope2 = prepare_masked_broadcast_envelope::<MlDsa65>(
            session_id,
            &signer_set,
            &inputs[1],
            transcript,
        )
        .expect("masked envelope");
        let mut registry = SessionRegistry::new();
        let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
        let err = certify_opened_masked_broadcasts_with_consistency::<MlDsa65, _>(
            &mut verifier,
            &mut registry,
            session_id,
            inputs,
            vec![envelope, envelope2],
            transcript,
            None,
        )
        .expect_err("legacy hash-only private certificate rejects");
        assert_eq!(
            err,
            PreprocessError::MaskedBroadcastProofBackendUnavailable(PartyId(1))
        );
    }

    #[test]
    fn production_consistency_verifier_accepts_external_runtime_transcript_hash() {
        let session_id = session(35);
        let signer_set = vec![PartyId(1), PartyId(2)];
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let envelope = prepare_masked_broadcast_envelope_with_runtime_transcript::<MlDsa65>(
            session_id,
            &signer_set,
            &inputs[0],
            transcript,
            [0xa5; 32],
        )
        .expect("external-runtime envelope");
        let statement = MaskedBroadcastConsistencyStatement {
            session_id,
            signer_set,
            broadcast: envelope.message.clone(),
            coeff_count: inputs[0].highs.len(),
        };
        let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
        assert_eq!(
            verifier.verify_masked_broadcast::<MlDsa65>(
                &statement,
                &envelope.consistency_proof,
                None,
            ),
            Ok(())
        );
    }

    #[test]
    fn vector_carry_compare_cef_certification_uses_plus_delta_boundaries() {
        let session_id = session(34);
        let transcript = TranscriptHash([0x34; 32]);
        let signer_set = vec![PartyId(1)];
        let alpha = MlDsa65::alpha() as u32;
        let highs = vec![1, 2, 3, 4];
        let lows = vec![alpha - 500, alpha + 500, 1, alpha - 1];
        let rhos = vec![0, 1_000, 0, 0];
        let broadcast = MaskedBroadcast {
            party: PartyId(1),
            masked_highs: highs.clone(),
            masked_lows: lows,
            nonce_commitment: NonceCommitment([1; 32]),
            rho_bits_commitment: Commitment([2; 32]),
            transcript_hash: transcript,
        };
        let inputs = vec![input(1, &[], &[])];
        let certified = certify_vector_carry_compare_and_cef::<MlDsa65>(
            session_id,
            transcript,
            &signer_set,
            &inputs,
            core::slice::from_ref(&broadcast),
            &[rhos],
            None,
        )
        .expect("vector CEF certifies");
        assert_eq!(
            certified.w1,
            vec![
                (highs[0] + 1) % MlDsa65::HIGH_MOD as u32,
                (highs[1] + 1) % MlDsa65::HIGH_MOD as u32,
                highs[2],
                (highs[3] + 1) % MlDsa65::HIGH_MOD as u32,
            ]
        );
        assert_eq!(certified.carry_compare.coeff_count, 4);
        assert_eq!(certified.bcc.coeff_count, 4);
        assert_ne!(certified.carry_compare.evidence_hash, [0; 32]);
        assert_ne!(certified.bcc.evidence_hash, [0; 32]);
    }

    #[test]
    fn bcc_failure_discards_token_before_pool_and_retry_can_succeed() {
        let mut registry = SessionRegistry::new();
        let boundary_low = (MlDsa65::GAMMA2 - MlDsa65::BETA) as u32;
        let err = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(35),
            vec![input(1, &[0], &[boundary_low])],
        )
        .expect_err("strict BCC boundary rejects before token output");
        assert_eq!(err, PreprocessError::BoundaryClearanceFailed);

        let mut pool = TokenPool::new();
        assert!(pool.is_empty());
        let retry = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(36),
            vec![input(1, &[0], &[1])],
        )
        .expect("fresh preprocessing attempt succeeds");
        assert!(retry.is_certified());
        pool.insert_certified(retry)
            .expect("certified retry enters pool");
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn clear_consistency_verifier_rejects_mismatched_opening() {
        let mut verifier = ClearMaskedBroadcastConsistencyVerifier;
        let statement = MaskedBroadcastConsistencyStatement {
            session_id: session(32),
            signer_set: vec![PartyId(1), PartyId(2)],
            broadcast: MaskedBroadcast {
                party: PartyId(1),
                masked_highs: vec![9],
                masked_lows: vec![18],
                nonce_commitment: NonceCommitment([1; 32]),
                rho_bits_commitment: Commitment([9; 32]),
                transcript_hash: TranscriptHash([2; 32]),
            },
            coeff_count: 1,
        };
        let audit = MaskedBroadcastClearAudit {
            highs: vec![5],
            lows: vec![7],
            high_masks: vec![3],
            rhos: vec![11],
            rho_bits_commitment: Commitment([9; 32]),
        };

        assert_eq!(
            verifier.verify_masked_broadcast::<MlDsa65>(
                &statement,
                &MaskedBroadcastConsistencyProof::default(),
                Some(&audit),
            ),
            Err(PreprocessError::MaskedBroadcastConsistencyMismatch(
                PartyId(1)
            ))
        );
    }

    #[test]
    fn cut_and_choose_audit_plan_splits_audited_and_certifiable_indices() {
        let plan = CutAndChooseAuditPlan::new(5, vec![3, 1]).expect("valid audit plan");

        assert_eq!(plan.audit_count(), 2);
        assert!(plan.audits(1));
        assert!(plan.audits(3));
        assert!(!plan.audits(0));
        assert_eq!(
            CutAndChooseAuditPlan::new(2, vec![0, 1]),
            Err(PreprocessError::InvalidAuditPlan)
        );
        assert_eq!(
            CutAndChooseAuditPlan::new(3, vec![1, 1]),
            Err(PreprocessError::InvalidAuditPlan)
        );
    }

    #[test]
    fn session_id_reuse_is_fatal() {
        let mut registry = SessionRegistry::new();
        let first = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(2),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        );
        assert!(first.is_ok());

        let err = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(2),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect_err("session reuse must fail");
        assert_eq!(err, PreprocessError::SessionReuse(session(2)));
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_session_registry_survives_reopen_and_blocks_reuse() {
        let path = test_store_path("registry_survives_reopen");
        let _ = std::fs::remove_file(&path);

        {
            let mut registry = FileSessionRegistry::open(&path).expect("open registry");
            registry.reserve(session(20)).expect("reserve session");
            assert!(registry.is_reserved(session(20)));
        }

        let mut reopened = FileSessionRegistry::open(&path).expect("reopen registry");
        assert!(reopened.is_reserved(session(20)));
        let err = certify_preprocessing_token::<MlDsa65>(
            &mut reopened,
            session(20),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect_err("reused session fails");
        assert_eq!(err, PreprocessError::SessionReuse(session(20)));
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_session_registry_rejects_corrupt_log() {
        let path = test_store_path("registry_rejects_corrupt_log");
        std::fs::write(&path, "bad-session\n").expect("write corrupt registry");

        assert_eq!(
            FileSessionRegistry::open(&path),
            Err(PreprocessError::SessionStoreCorrupt { line: 1 })
        );
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_session_counter_survives_reopen_and_advances_before_returning() {
        let path = test_store_path("counter_survives_reopen");
        let _ = std::fs::remove_file(&path);

        {
            let mut counter = FileSessionCounter::open(&path).expect("open counter");
            assert_eq!(counter.next_counter(), 0);
            assert_eq!(counter.allocate_counter(), Ok(0));
            assert_eq!(counter.allocate_counter(), Ok(1));
            assert_eq!(counter.next_counter(), 2);
        }

        let mut reopened = FileSessionCounter::open(&path).expect("reopen counter");
        assert_eq!(reopened.next_counter(), 2);
        assert_eq!(reopened.allocate_counter(), Ok(2));
        assert_eq!(reopened.next_counter(), 3);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_session_counter_rejects_corrupt_file() {
        let path = test_store_path("counter_rejects_corrupt_file");
        std::fs::write(&path, "not-a-counter\n").expect("write corrupt counter");

        assert_eq!(
            FileSessionCounter::open(&path),
            Err(PreprocessError::SessionCounterStoreCorrupt)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn in_memory_session_counter_rejects_overflow() {
        let mut counter = SessionCounter::with_next(u64::MAX);
        assert_eq!(
            counter.allocate_counter(),
            Err(PreprocessError::SessionCounterExhausted)
        );
    }

    #[test]
    fn duplicate_party_fails_certification() {
        let mut registry = SessionRegistry::new();
        let err = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(3),
            vec![input(1, &[1], &[3]), input(1, &[5], &[7])],
        )
        .expect_err("duplicate party must fail");
        assert_eq!(err, PreprocessError::DuplicateParty(PartyId(1)));
    }

    #[test]
    fn equivocated_masked_broadcast_fails_open() {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(4),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("valid preprocessing certifies");
        let mut envelope = BroadcastEnvelope {
            commitment: masked_broadcast_commitment(
                token.session_id,
                &token.broadcasts[0],
                salt(token.session_id, token.broadcasts[0].party),
            ),
            message: token.broadcasts[0].clone(),
            consistency_proof: MaskedBroadcastConsistencyProof::default(),
            salt: salt(token.session_id, token.broadcasts[0].party),
        };
        envelope.message.masked_highs[0] ^= 1;

        assert_eq!(
            open_broadcasts(token.session_id, &[envelope], token.transcript_hash),
            Err(PreprocessError::CommitmentMismatch(
                token.broadcasts[0].party
            ))
        );
    }

    #[test]
    fn token_pool_rejects_uncertified_candidate() {
        let mut pool = TokenPool::new();
        assert_eq!(
            pool.insert_candidate(TokenCandidate {
                session_id: session(5)
            }),
            Err(TokenPoolError::NotCertified(session(5)))
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn token_pool_accepts_certified_once() {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(6),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("valid preprocessing certifies");
        let mut pool = TokenPool::new();

        assert_eq!(pool.insert_certified(token), Ok(()));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn token_inventory_enforces_monotonic_preprocessing_lifecycle() {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(63),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("valid preprocessing certifies");
        let mut pool = TokenPool::new();
        let mut inventory = TokenInventory::new();

        assert_eq!(inventory.state(session(63)), TokenInventoryState::Fresh);
        pool.insert_certified_with_inventory(token, &mut inventory)
            .expect("reserve and insert certified token");
        assert_eq!(inventory.state(session(63)), TokenInventoryState::Reserved);
        let consumed = pool
            .take_certified_for_consumption(session(63), &mut inventory)
            .expect("consume before online use");
        assert_eq!(consumed.session_id, session(63));
        assert_eq!(inventory.state(session(63)), TokenInventoryState::Consumed);
        assert_eq!(inventory.erase(session(63)), Ok(()));
        assert_eq!(inventory.state(session(63)), TokenInventoryState::Erased);
        assert!(matches!(
            inventory.reserve(session(63)),
            Err(TokenPoolError::InvalidInventoryTransition {
                from: TokenInventoryState::Erased,
                to: TokenInventoryState::Reserved,
                ..
            })
        ));
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn token_pool_consumes_certified_batches_atomically() {
        let mut registry = SessionRegistry::new();
        let first = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(160),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("first token certifies");
        let second = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(161),
            vec![input(1, &[2], &[4]), input(2, &[6], &[8])],
        )
        .expect("second token certifies");

        let mut pool = TokenPool::new();
        let mut inventory = TokenInventory::new();
        pool.insert_certified_with_inventory(first, &mut inventory)
            .expect("insert first");
        pool.insert_certified_with_inventory(second, &mut inventory)
            .expect("insert second");

        assert!(matches!(
            pool.take_certified_batch_for_consumption(
                &[session(160), session(160)],
                &mut inventory
            ),
            Err(TokenPoolError::Duplicate(id)) if id == session(160)
        ));
        assert_eq!(inventory.state(session(160)), TokenInventoryState::Reserved);
        assert_eq!(inventory.state(session(161)), TokenInventoryState::Reserved);

        let batch = pool
            .take_certified_batch_for_consumption(&[session(160), session(161)], &mut inventory)
            .expect("consume batch");
        assert_eq!(
            batch
                .iter()
                .map(|token| token.session_id)
                .collect::<Vec<_>>(),
            vec![session(160), session(161)]
        );
        assert_eq!(inventory.state(session(160)), TokenInventoryState::Consumed);
        assert_eq!(inventory.state(session(161)), TokenInventoryState::Consumed);
        assert!(pool.is_empty());
    }

    #[test]
    fn preprocessing_token_batch_fill_report_measures_pass_probability() {
        let mut registry = SessionRegistry::new();
        let first = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(162),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("first token certifies");
        let second = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(163),
            vec![input(1, &[2], &[4]), input(2, &[6], &[8])],
        )
        .expect("second token certifies");

        let report = PreprocessingTokenBatchFillReport::from_certified_tokens(4, &[first, second]);
        assert_eq!(report.attempted_tokens, 4);
        assert_eq!(report.certified_tokens, 2);
        assert_eq!(report.counters.token_count, 2);
        let estimate = report
            .pass_probability_estimate()
            .expect("pass probability estimate");
        assert_eq!(estimate.attempted, 4);
        assert_eq!(estimate.passed, 2);
        assert_eq!(
            PreprocessingTokenBatchFillReport::default().pass_probability_estimate(),
            None
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_token_inventory_persists_consumed_state_across_restart() {
        let path = test_store_path("token-inventory");
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(83),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("valid preprocessing certifies");
        let mut pool = TokenPool::new();

        {
            let mut inventory = FileTokenInventory::open(&path).expect("open inventory");
            pool.insert_certified_with_inventory(token, &mut inventory)
                .expect("reserve and insert certified token");
            assert_eq!(inventory.state(session(83)), TokenInventoryState::Reserved);
            let consumed = pool
                .take_certified_for_consumption(session(83), &mut inventory)
                .expect("consume token durably before online use");
            assert_eq!(consumed.session_id, session(83));
            assert_eq!(inventory.state(session(83)), TokenInventoryState::Consumed);
        }

        let mut reopened = FileTokenInventory::open(&path).expect("reopen inventory");
        assert_eq!(reopened.state(session(83)), TokenInventoryState::Consumed);
        assert!(matches!(
            reopened.reserve(session(83)),
            Err(TokenPoolError::InvalidInventoryTransition {
                from: TokenInventoryState::Consumed,
                to: TokenInventoryState::Reserved,
                ..
            })
        ));
        reopened.erase(session(83)).expect("erase consumed token");

        let reopened = FileTokenInventory::open(&path).expect("reopen erased inventory");
        assert_eq!(reopened.state(session(83)), TokenInventoryState::Erased);
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_token_inventory_rejects_corrupt_and_rollback_logs() {
        let path = test_store_path("token-inventory-corrupt");
        std::fs::write(&path, "not-a-session reserved\n").expect("write corrupt log");
        assert_eq!(
            FileTokenInventory::open(&path),
            Err(TokenPoolError::InventoryStoreCorrupt { line: 1 })
        );

        let path = test_store_path("token-inventory-rollback");
        std::fs::write(
            &path,
            format!(
                "{} reserved\n{} consumed\n{} reserved\n",
                hex32(session(84).0),
                hex32(session(84).0),
                hex32(session(84).0)
            ),
        )
        .expect("write rollback log");
        assert_eq!(
            FileTokenInventory::open(&path),
            Err(TokenPoolError::InventoryStoreCorrupt { line: 3 })
        );
    }

    #[test]
    fn preprocessing_certification_counters_gate_vectorized_tokens() {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(64),
            vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])],
        )
        .expect("valid preprocessing certifies");
        let counters = PreprocessingCertificationCounters::from_token(&token);

        assert_eq!(counters.token_count, 1);
        assert_eq!(counters.signer_count, 2);
        assert_eq!(counters.coeff_count, 2);
        assert_eq!(counters.vector_lanes, 4);
        assert_eq!(counters.masked_broadcasts, 2);
        assert_eq!(counters.carry_compare_lanes, 2);
        assert_eq!(counters.cef_correction_lanes, 2);
        assert_eq!(counters.bcc_lanes, 2);
        assert_eq!(
            ensure_preprocessing_counters_vectorized_for_release(counters),
            Ok(())
        );
        let shared = talus_performance_counters_from_preprocessing(counters);
        assert_eq!(shared.token_batch_size, 1);
        assert_eq!(shared.broadcasts, 2);
        assert_eq!(shared.vector_lanes, 4);
        assert_eq!(shared.checked_lanes, 6);
        assert_eq!(shared.scalar_operations, 0);
        assert_eq!(
            ensure_preprocessing_counters_vectorized_for_release(
                PreprocessingCertificationCounters {
                    token_count: 1,
                    signer_count: 2,
                    coeff_count: 2,
                    vector_lanes: 1,
                    masked_broadcasts: 2,
                    carry_compare_lanes: 2,
                    cef_correction_lanes: 2,
                    bcc_lanes: 2,
                },
            ),
            Err(PreprocessError::PreprocessingCountersNotVectorized)
        );
    }

    #[test]
    fn preprocessing_token_batch_all_suites_enters_strict_pool_with_inventory() {
        fn check<P: MlDsaParams>(base: u8) {
            let mut registry = SessionRegistry::new();
            let mut pool = TokenPool::new();
            let mut inventory = TokenInventory::new();
            let mut tokens = Vec::new();

            for offset in 0..2u8 {
                let session_id = session(base.wrapping_add(offset));
                let token = certify_preprocessing_token::<P>(
                    &mut registry,
                    session_id,
                    vec![
                        PartyPreprocessInput {
                            party: PartyId(1),
                            highs: vec![0; P::K * P::N],
                            lows: vec![1; P::K * P::N],
                            y_share: Vec::new(),
                            ay_contribution: None,
                            nonce_commitment: NonceCommitment([1u8.wrapping_add(offset); 32]),
                            randomness_commitment: Commitment([11u8.wrapping_add(offset); 32]),
                        },
                        PartyPreprocessInput {
                            party: PartyId(2),
                            highs: vec![0; P::K * P::N],
                            lows: vec![2; P::K * P::N],
                            y_share: Vec::new(),
                            ay_contribution: None,
                            nonce_commitment: NonceCommitment([2u8.wrapping_add(offset); 32]),
                            randomness_commitment: Commitment([12u8.wrapping_add(offset); 32]),
                        },
                    ],
                )
                .expect("token certifies");
                let token = attach_test_strict_signing_runtime_material::<P>(token)
                    .expect("release runtime material");
                let certificate = PreprocessingVectorRuntimeCertificate::for_token(
                    &token,
                    release_vector_runtime_evidence_for_token(&token),
                )
                .expect("release vector runtime certificate");
                let token = token.with_vector_runtime_certificate(certificate);
                assert!(token.is_release_certified());
                pool.insert_release_certified_with_inventory(token, &mut inventory)
                    .expect("insert with inventory");
                tokens.push(pool.take_certified(session_id).expect("take for counter"));
                assert_eq!(inventory.state(session_id), TokenInventoryState::Reserved);
            }

            let counters = PreprocessingCertificationCounters::from_tokens(&tokens);
            assert_eq!(counters.token_count, 2);
            assert_eq!(counters.signer_count, 2);
            assert_eq!(counters.coeff_count, P::K * P::N);
            assert_eq!(counters.vector_lanes, 2 * 2 * P::K * P::N);
            assert_eq!(
                ensure_preprocessing_counters_vectorized_for_release(counters),
                Ok(())
            );
        }

        check::<MlDsa44>(80);
        check::<MlDsa65>(90);
        check::<MlDsa87>(100);
    }

    #[test]
    fn pre_challenge_certification_policy_gates_token_admission() {
        let complete = PreChallengeCertificationPolicy {
            masked_broadcast_consistency: true,
            carry_compare_certified: true,
            bcc_certified: true,
            persistent_session_store: true,
            no_post_challenge_nonce_reveal: true,
        };
        assert_eq!(ensure_pre_challenge_certification_policy(complete), Ok(()));

        let incomplete = PreChallengeCertificationPolicy {
            carry_compare_certified: false,
            ..complete
        };
        assert_eq!(
            ensure_pre_challenge_certification_policy(incomplete),
            Err(PreprocessError::PreChallengeCertificationIncomplete)
        );

        let mut registry = SessionRegistry::new();
        let mut token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(61),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("valid preprocessing certifies");
        token.certification_policy = incomplete;
        assert!(!token.is_certified());
        let mut pool = TokenPool::new();
        assert_eq!(
            pool.insert_certified(token),
            Err(TokenPoolError::NotCertified(session(61)))
        );
    }

    #[test]
    fn certified_token_carries_preprocessing_runtime_certificate_on_output() {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(64),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("valid preprocessing certifies");
        #[cfg(feature = "production-release-checks")]
        assert!(
            !token.is_certified(),
            "release tokens must carry vector runtime evidence"
        );

        let token = attach_test_strict_signing_runtime_material::<MlDsa65>(token)
            .expect("release runtime material");
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token,
            release_vector_runtime_evidence_for_token(&token),
        )
        .expect("release vector runtime certificate");
        let token = token.with_vector_runtime_certificate(certificate.clone());
        assert_eq!(token.vector_runtime_certificate(), Some(&certificate));
        assert!(token.is_certified());
    }

    #[test]
    fn release_token_validation_requires_runtime_certificate_in_normal_build() {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(65),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("valid preprocessing certifies");
        let token = attach_test_strict_signing_runtime_material::<MlDsa65>(token)
            .expect("release runtime material");

        assert_eq!(
            ensure_certified_token_release_valid(&token),
            Err(PreprocessError::PreprocessingRuntimeCertificateMissing)
        );
        assert!(!token.is_release_certified());

        let mut pool = TokenPool::new();
        assert_eq!(
            pool.insert_release_certified(token),
            Err(TokenPoolError::NotCertified(session(65)))
        );
    }

    #[cfg(feature = "production-release-checks")]
    fn runtime_generated_release_token<P: MlDsaParams>(
        session_byte: u8,
        coeff_count: usize,
        z_lane_count: usize,
        hint_lane_count: usize,
    ) -> CertifiedToken {
        let session_id = session(session_byte);
        let rho = [session_byte.wrapping_add(9); 32];
        let (config, mut runtime) = latest_round_vector_runtime_one_party::<P>(session_byte as u64);
        let full_release_shape = coeff_count == P::K * P::N
            && z_lane_count == P::L * P::N
            && hint_lane_count == P::K * P::N;
        let nonce_share = if full_release_shape {
            Some(DistributedNonceShare {
                party: PartyId(1),
                y_share: PolyVec::new(vec![Poly::from_coeffs([0; 256]); P::L]),
                nonce_commitment: NonceCommitment([session_byte; 32]),
                randomness_commitment: Commitment([session_byte.wrapping_add(1); 32]),
            })
        } else {
            None
        };
        let inputs = if let Some(share) = nonce_share.as_ref() {
            vec![party_preprocess_input_from_distributed_nonce_share::<P>(
                session_id,
                &config.parties,
                &rho,
                share,
            )
            .expect("distributed nonce preprocessing input")]
        } else {
            vec![PartyPreprocessInput {
                party: PartyId(1),
                highs: vec![0; coeff_count],
                lows: vec![0; coeff_count],
                y_share: Vec::new(),
                ay_contribution: None,
                nonce_commitment: NonceCommitment([session_byte; 32]),
                randomness_commitment: Commitment([session_byte.wrapping_add(1); 32]),
            }]
        };
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<P>(session_id, &inputs);
        let envelopes = inputs
            .iter()
            .map(|input| {
                prepare_masked_broadcast_envelope::<P>(session_id, &signer_set, input, transcript)
                    .expect("masked broadcast envelope")
            })
            .collect::<Vec<_>>();
        let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let (_, _, mut private_state) = adapter
            .start_private_circuit_handles_from_envelopes::<P>(
                &config,
                session_id,
                inputs.clone(),
                envelopes.clone(),
                transcript,
            )
            .expect("start private preprocessing");
        let mut round = 0u64;
        while !private_state.is_done() {
            let mut entropy = TestProductionVectorEntropy {
                next: 92_000 + round * 1_000,
            };
            adapter
                .drive_private_circuit_handles_step::<P, _>(
                    &config,
                    &mut private_state,
                    &mut entropy,
                )
                .expect("drive private preprocessing");
            match adapter
                .collect_private_circuit_handles_step::<P>(&config, &mut private_state)
                .expect("collect private preprocessing")
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("private preprocessing did not complete phase: {status:?}")
                }
            }
            round = round.saturating_add(1);
            assert!(round < 128);
        }

        let mut mask_state = adapter
            .start_strict_signing_canonical_mask_generation(
                session_id,
                transcript,
                z_lane_count,
                hint_lane_count,
            )
            .expect("start strict mask generation");
        let mut mask_round = 0u64;
        while !mask_state.is_done() {
            let mut entropy = TestProductionVectorEntropy {
                next: 132_000 + mask_round * 1_000,
            };
            adapter
                .drive_strict_signing_canonical_mask_generation_step::<P, _>(
                    &config,
                    &mut mask_state,
                    &mut entropy,
                )
                .expect("drive strict mask generation");
            match adapter
                .collect_strict_signing_canonical_mask_generation_step::<P>(&config, &mut mask_state)
                .unwrap_or_else(|err| {
                    panic!(
                        "collect strict mask generation failed at round {mask_round} in phase {:?}: {err:?}",
                        mask_state
                    )
                })
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("strict mask generation did not complete phase: {status:?}")
                }
            }
            mask_round = mask_round.saturating_add(1);
            assert!(mask_round < 256);
        }

        let mut registry = SessionRegistry::new();
        let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
        let token = if let Some(share) = nonce_share.as_ref() {
            certify_preprocessing_token_release_validated_with_finished_runtime_driver_strict_material_and_nonce_share::<
                P, _, _, _, _,
            >(
                &mut verifier,
                &mut registry,
                session_id,
                inputs,
                envelopes,
                transcript,
                &config,
                &rho,
                &signer_set,
                share,
                &mut adapter,
                &private_state,
                mask_state,
            )
            .expect("release token with runtime nonce-derived strict material")
        } else {
            dev_certify_preprocessing_token_with_opened_material_w_for_tests::<P, _, _, _, _>(
                &mut verifier,
                &mut registry,
                session_id,
                inputs,
                envelopes,
                transcript,
                &config,
                &mut adapter,
                &private_state,
                mask_state,
            )
            .expect("release token with runtime-generated strict material")
        };

        assert!(token.is_release_certified());
        token
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn release_token_batch_log_scanner_binds_public_metadata_and_order() {
        let tokens = vec![
            runtime_generated_release_token::<MlDsa65>(151, 4, 4, 4),
            runtime_generated_release_token::<MlDsa65>(152, 4, 4, 4),
        ];
        let entries = tokens
            .iter()
            .enumerate()
            .map(|(idx, token)| {
                preprocessing_release_token_log_entry(token, idx).expect("release token log entry")
            })
            .collect::<Vec<_>>();

        ensure_preprocessing_release_token_batch_log_for_release(&tokens, &entries)
            .expect("typed release token batch log verifies");

        let mut wrong_order = entries.clone();
        wrong_order.swap(0, 1);
        assert_eq!(
            ensure_preprocessing_release_token_batch_log_for_release(&tokens, &wrong_order),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );

        let mut wrong_signer_set = entries.clone();
        wrong_signer_set[0].signer_set_hash[0] ^= 0x44;
        assert_eq!(
            ensure_preprocessing_release_token_batch_log_for_release(&tokens, &wrong_signer_set),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );

        let mut wrong_runtime = entries;
        wrong_runtime[0].runtime_transcript_hash[0] ^= 0x80;
        assert_eq!(
            ensure_preprocessing_release_token_batch_log_for_release(&tokens, &wrong_runtime),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn token_pool_batch_admission_replays_release_log_before_inventory_reserve() {
        let tokens = vec![
            runtime_generated_release_token::<MlDsa65>(153, 4, 4, 4),
            runtime_generated_release_token::<MlDsa65>(154, 4, 4, 4),
        ];
        let sessions = tokens
            .iter()
            .map(|token| token.session_id)
            .collect::<Vec<_>>();
        let entries = tokens
            .iter()
            .enumerate()
            .map(|(idx, token)| {
                preprocessing_release_token_log_entry(token, idx).expect("release log entry")
            })
            .collect::<Vec<_>>();
        let mut pool = TokenPool::new();
        let mut inventory = TokenInventory::new();

        pool.insert_release_certified_batch_with_inventory_and_log(
            tokens,
            &entries,
            &mut inventory,
        )
        .expect("release batch admits after log replay");
        for session_id in sessions {
            assert!(pool.contains(session_id));
            assert_eq!(inventory.state(session_id), TokenInventoryState::Reserved);
        }

        let token = runtime_generated_release_token::<MlDsa65>(155, 4, 4, 4);
        let session_id = token.session_id;
        let mut bad_entries =
            vec![preprocessing_release_token_log_entry(&token, 0).expect("release log entry")];
        bad_entries[0].certificate_hash[0] ^= 0x21;
        let mut pool = TokenPool::new();
        let mut inventory = TokenInventory::new();
        assert_eq!(
            pool.insert_release_certified_batch_with_inventory_and_log(
                vec![token],
                &bad_entries,
                &mut inventory,
            ),
            Err(TokenPoolError::ReleaseLogMismatch)
        );
        assert!(!pool.contains(session_id));
        assert_eq!(inventory.state(session_id), TokenInventoryState::Fresh);
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn file_release_token_batch_log_persists_replays_and_admits_batch() {
        let path = test_store_path("release-token-batch-log");
        let tokens = vec![
            runtime_generated_release_token::<MlDsa65>(156, 4, 4, 4),
            runtime_generated_release_token::<MlDsa65>(157, 4, 4, 4),
        ];
        let sessions = tokens
            .iter()
            .map(|token| token.session_id)
            .collect::<Vec<_>>();
        let entries = tokens
            .iter()
            .enumerate()
            .map(|(idx, token)| {
                preprocessing_release_token_log_entry(token, idx).expect("release log entry")
            })
            .collect::<Vec<_>>();

        {
            let mut log =
                FilePreprocessingReleaseTokenBatchLog::open(&path).expect("open release log");
            log.append_batch(&entries).expect("append typed entries");
            assert_eq!(log.entries(), entries.as_slice());
        }

        let reopened =
            FilePreprocessingReleaseTokenBatchLog::open(&path).expect("reopen release log");
        assert_eq!(reopened.entries(), entries.as_slice());
        reopened
            .replay_for_release(&tokens)
            .expect("file log replays against tokens");

        let mut pool = TokenPool::new();
        let mut inventory = FileTokenInventory::open(test_store_path("release-token-batch-inv"))
            .expect("open inventory");
        pool.insert_release_certified_batch_with_inventory_and_file_log(
            tokens,
            &reopened,
            &mut inventory,
        )
        .expect("file-backed release log admits batch");
        for session_id in sessions {
            assert!(pool.contains(session_id));
            assert_eq!(inventory.state(session_id), TokenInventoryState::Reserved);
        }
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn file_release_token_batch_log_rejects_tamper_truncation_and_duplicates() {
        let token = runtime_generated_release_token::<MlDsa65>(158, 4, 4, 4);
        let session_id = token.session_id;
        let entry = preprocessing_release_token_log_entry(&token, 0).expect("release log entry");

        let path = test_store_path("release-token-batch-log-tamper");
        let mut tampered = entry;
        tampered.certificate_hash[0] ^= 0x44;
        std::fs::write(
            &path,
            format!(
                "{}\n",
                encode_preprocessing_release_token_log_entry(&tampered)
            ),
        )
        .expect("write tampered log");
        let log = FilePreprocessingReleaseTokenBatchLog::open(&path).expect("open tampered log");
        let mut pool = TokenPool::new();
        let mut inventory = TokenInventory::new();
        assert_eq!(
            pool.insert_release_certified_batch_with_inventory_and_file_log(
                vec![token],
                &log,
                &mut inventory,
            ),
            Err(TokenPoolError::ReleaseLogMismatch)
        );
        assert_eq!(inventory.state(session_id), TokenInventoryState::Fresh);

        let path = test_store_path("release-token-batch-log-truncated");
        std::fs::write(&path, "talus-preprocessing-release-token-v1 0\n")
            .expect("write truncated log");
        assert_eq!(
            FilePreprocessingReleaseTokenBatchLog::open(&path),
            Err(TokenPoolError::ReleaseLogCorrupt { line: 1 })
        );

        let path = test_store_path("release-token-batch-log-duplicate");
        let line = encode_preprocessing_release_token_log_entry(&entry);
        std::fs::write(&path, format!("{line}\n{line}\n")).expect("write duplicate log");
        assert_eq!(
            FilePreprocessingReleaseTokenBatchLog::open(&path),
            Err(TokenPoolError::ReleaseLogCorrupt { line: 2 })
        );

        let path = test_store_path("release-token-batch-log-private-marker");
        std::fs::write(
            &path,
            "talus-preprocessing-release-token-v1 0 nonce_share=deadbeef\n",
        )
        .expect("write private marker log");
        assert_eq!(
            FilePreprocessingReleaseTokenBatchLog::open(&path),
            Err(TokenPoolError::ReleaseLogCorrupt { line: 1 })
        );
    }

    #[test]
    fn release_token_log_text_scanner_rejects_private_material_markers() {
        ensure_preprocessing_release_token_log_text_public_for_release(
            "session=ok token_binding_hash=abc runtime_transcript_hash=def",
        )
        .expect("public release log text is accepted");

        for marker in [
            "nonce_share=",
            "y_share=",
            "raw_mask=",
            "mask_bits=",
            "rejected_z=",
            "partial_z=",
            "low_bits=",
            "witness=",
            "failed_diff=",
            "secret_lane=",
            "private_lane=",
            "unselected_z=",
            "valid_bit=",
            "pass_bit=",
        ] {
            let log = format!("session=bad {marker}deadbeef");
            assert_eq!(
                ensure_preprocessing_release_token_log_text_public_for_release(&log),
                Err(PreprocessError::PreprocessingRuntimeMaterialMissing),
                "marker {marker} must be forbidden"
            );
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_backed_release_token_log_text_scan_rejects_private_markers() {
        let path = test_store_path("release-token-log-scan");
        std::fs::write(
            &path,
            "session=ok token_binding_hash=abc runtime_transcript_hash=def\n",
        )
        .expect("write public log");
        let public_log = std::fs::read_to_string(&path).expect("read public log");
        ensure_preprocessing_release_token_log_text_public_for_release(&public_log)
            .expect("public log scans");

        std::fs::write(
            &path,
            "session=bad token_binding_hash=abc rejected_z=deadbeef\n",
        )
        .expect("write private marker log");
        let bad_log = std::fs::read_to_string(&path).expect("read bad log");
        assert_eq!(
            ensure_preprocessing_release_token_log_text_public_for_release(&bad_log),
            Err(PreprocessError::PreprocessingRuntimeMaterialMissing)
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn release_token_with_finished_runtime_driver_uses_runtime_generated_strict_material() {
        let session_id = session(92);
        let token = runtime_generated_release_token::<MlDsa65>(92, 2, 2, 2);
        let config =
            DkgConfig::new::<MlDsa65>(1, token.signer_set.clone(), talus_dkg::KeygenEpoch(92))
                .expect("one-party config");
        assert!(token.is_release_certified());
        let w_share = token.precomputed_w_share().expect("runtime-generated w");
        assert_eq!(w_share.len(), token.w1.len());
        assert_eq!(
            w_share.id().label_hash,
            power2round_label_hash(&strict_signing_precomputed_w_label(&config, session_id))
        );
        let masks = token.strict_signing_masks().expect("strict masks");
        assert_eq!(masks.z_mask_value().len(), token.w1.len());
        assert_eq!(masks.hint_mask_value().len(), token.w1.len());
        assert_eq!(
            masks
                .provenance()
                .expect("mask provenance")
                .runtime_transcript_hash,
            token
                .vector_runtime_certificate()
                .expect("runtime certificate")
                .runtime_evidence
                .transcript_hash
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn strict_precomputed_w_is_derived_from_runtime_nonce_share_handle() {
        let session_id = session(93);
        let rho = [0x93; 32];
        let (config, mut runtime) = latest_round_vector_runtime_one_party::<MlDsa65>(93);
        let adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let mut y_polys = Vec::with_capacity(MlDsa65::L);
        for poly_idx in 0..MlDsa65::L {
            let mut coeffs = [0; 256];
            for (coeff_idx, coeff) in coeffs.iter_mut().enumerate() {
                *coeff = ((poly_idx * 257 + coeff_idx + 1) as Coeff) % MlDsa65::Q;
            }
            y_polys.push(Poly::from_coeffs(coeffs));
        }
        let nonce_share = DistributedNonceShare {
            party: PartyId(1),
            y_share: PolyVec::new(y_polys.clone()),
            nonce_commitment: NonceCommitment([0x93; 32]),
            randomness_commitment: Commitment([0x94; 32]),
        };

        let weighted_y = adapter
            .strict_signing_weighted_nonce_share_from_distributed_nonce_share::<MlDsa65>(
                &config,
                session_id,
                &config.parties,
                &nonce_share,
            )
            .expect("weighted nonce handle");
        let w_share = adapter
            .derive_strict_signing_precomputed_w_share_from_nonce_handle::<MlDsa65>(
                &config,
                session_id,
                &rho,
                &weighted_y,
            )
            .expect("runtime-derived w share");
        let expected = az_from_rho::<MlDsa65>(&rho, &PolyVec::new(y_polys)).expect("expected A*y");
        let expected_lanes = expected
            .polys()
            .iter()
            .flat_map(|poly| poly.coeffs().iter().copied())
            .collect::<Vec<_>>();

        let open_label = Power2RoundTranscriptLabel::root(&config, session_id.0)
            .child("preprocessing")
            .child("open_runtime_nonce_derived_w_for_test");
        adapter
            .runtime
            .drive_open_share_vec::<MlDsa65>(&config, &w_share, &open_label)
            .expect("drive w opening");
        let opened = match adapter
            .runtime
            .collect_open_share_vec::<MlDsa65>(&config, &open_label)
            .expect("collect w opening")
        {
            ProductionVectorItMpcCollectResult::Collected { value, .. } => value,
            ProductionVectorItMpcCollectResult::Waiting(status) => {
                panic!("one-party opening unexpectedly waiting: {status:?}")
            }
        };

        assert_eq!(opened, expected_lanes);
        assert_eq!(
            w_share.id().label_hash,
            power2round_label_hash(&strict_signing_precomputed_w_label(&config, session_id))
        );

        let wrong_label = Power2RoundTranscriptLabel::root(&config, session_id.0)
            .child("preprocessing")
            .child("wrong_nonce_y");
        let wrong_handle = adapter
            .runtime
            .share_vec_from_local_lanes::<MlDsa65>(
                &config,
                &wrong_label,
                vec![0; MlDsa65::L * MlDsa65::N],
            )
            .expect("wrong handle");
        assert_eq!(
            adapter.derive_strict_signing_precomputed_w_share_from_nonce_handle::<MlDsa65>(
                &config,
                session_id,
                &rho,
                &wrong_handle,
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn preprocessing_session_finish_with_release_runtime_uses_nonce_derived_w() {
        let session_id = session(94);
        let rho = [0x94; 32];
        let (config, mut runtime) = latest_round_vector_runtime_one_party::<MlDsa65>(94);
        let nonce_share = DistributedNonceShare {
            party: PartyId(1),
            y_share: PolyVec::new(vec![Poly::from_coeffs([0; 256]); MlDsa65::L]),
            nonce_commitment: NonceCommitment([0x94; 32]),
            randomness_commitment: Commitment([0x95; 32]),
        };
        let input = party_preprocess_input_from_distributed_nonce_share::<MlDsa65>(
            session_id,
            &config.parties,
            &rho,
            &nonce_share,
        )
        .expect("nonce-backed preprocessing input");
        let options = PreprocessingSessionOptions {
            session_id,
            signer_set: config.parties.clone(),
            keygen_transcript_hash: config.transcript_hash().0,
        };
        let mut sessions = vec![PreprocessingSession::<MlDsa65, _, _>::start(
            options,
            input,
            SessionRegistry::new(),
            ProductMaskedBroadcastConsistencyVerifier,
        )
        .expect("start preprocessing session")];
        route_preprocessing_broadcasts(&mut sessions);
        let transcript = preprocessing_session_open_hash::<MlDsa65>(session_id, &config.parties);
        let inputs = sessions[0].inputs.clone();
        let envelopes = sessions[0].envelopes.clone();

        let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let (_, _, mut private_state) = adapter
            .start_private_circuit_handles_from_envelopes::<MlDsa65>(
                &config,
                session_id,
                inputs.clone(),
                envelopes.clone(),
                transcript,
            )
            .expect("start private preprocessing");
        let mut round = 0u64;
        while !private_state.is_done() {
            let mut entropy = TestProductionVectorEntropy {
                next: 94_000 + round * 1_000,
            };
            adapter
                .drive_private_circuit_handles_step::<MlDsa65, _>(
                    &config,
                    &mut private_state,
                    &mut entropy,
                )
                .expect("drive private preprocessing");
            match adapter
                .collect_private_circuit_handles_step::<MlDsa65>(&config, &mut private_state)
                .expect("collect private preprocessing")
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("private preprocessing did not complete phase: {status:?}")
                }
            }
            round = round.saturating_add(1);
            assert!(round < 128);
        }

        let mut mask_state = adapter
            .start_strict_signing_canonical_mask_generation(
                session_id,
                transcript,
                MlDsa65::L * MlDsa65::N,
                MlDsa65::K * MlDsa65::N,
            )
            .expect("start strict mask generation");
        let mut mask_round = 0u64;
        while !mask_state.is_done() {
            let mut entropy = TestProductionVectorEntropy {
                next: 194_000 + mask_round * 1_000,
            };
            adapter
                .drive_strict_signing_canonical_mask_generation_step::<MlDsa65, _>(
                    &config,
                    &mut mask_state,
                    &mut entropy,
                )
                .expect("drive strict mask generation");
            match adapter
                .collect_strict_signing_canonical_mask_generation_step::<MlDsa65>(
                    &config,
                    &mut mask_state,
                )
                .expect("collect strict mask generation")
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("strict mask generation did not complete phase: {status:?}")
                }
            }
            mask_round = mask_round.saturating_add(1);
            assert!(mask_round < 256);
        }

        let wrong_nonce_share = DistributedNonceShare {
            y_share: PolyVec::new(vec![Poly::from_coeffs([1; 256]); MlDsa65::L]),
            ..nonce_share.clone()
        };
        assert!(matches!(
            certify_preprocessing_token_release_validated_with_finished_runtime_driver_strict_material_and_nonce_share::<
                MlDsa65, _, _, _, _,
            >(
                &mut ProductMaskedBroadcastConsistencyVerifier,
                &mut SessionRegistry::new(),
                session_id,
                inputs,
                envelopes,
                transcript,
                &config,
                &rho,
                &config.parties,
                &wrong_nonce_share,
                &mut adapter,
                &private_state,
                mask_state.clone(),
            ),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        ));

        let mut cursor_store = PreprocessingReleaseSessionCursorMemoryStore::new();
        let token = sessions
            .remove(0)
            .finish_with_release_runtime_and_cursor_store(
                &config,
                &rho,
                &nonce_share,
                &mut adapter,
                &private_state,
                mask_state,
                &mut cursor_store,
            )
            .expect("release token from preprocessing session facade");
        assert!(token.is_release_certified());
        assert_eq!(
            token
                .precomputed_w_share()
                .expect("nonce-derived w")
                .id()
                .label_hash,
            power2round_label_hash(&strict_signing_precomputed_w_label(&config, session_id))
        );
        assert!(token.y_share.is_empty());
        let phases = cursor_store
            .release_cursors()
            .iter()
            .map(|cursor| cursor.phase)
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                PreprocessingReleaseSessionPhase::TranscriptComplete,
                PreprocessingReleaseSessionPhase::PrivateRuntimeComplete,
                PreprocessingReleaseSessionPhase::StrictMasksComplete,
                PreprocessingReleaseSessionPhase::ReleaseTokenCertified,
            ]
        );
        assert_eq!(
            cursor_store
                .latest_release_cursor(session_id)
                .expect("latest cursor")
                .token_binding_hash,
            token
                .vector_runtime_certificate()
                .and_then(PreprocessingVectorRuntimeCertificate::token_binding_hash)
        );
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn preprocessing_release_driver_owns_runtime_schedule_and_token_log() {
        let session_id = session(97);
        let rho = [0x97; 32];
        let (config, mut runtime) = latest_round_vector_runtime_one_party::<MlDsa65>(97);
        let nonce_share = DistributedNonceShare {
            party: PartyId(1),
            y_share: PolyVec::new(vec![Poly::from_coeffs([0; 256]); MlDsa65::L]),
            nonce_commitment: NonceCommitment([0x97; 32]),
            randomness_commitment: Commitment([0x98; 32]),
        };
        let input = party_preprocess_input_from_distributed_nonce_share::<MlDsa65>(
            session_id,
            &config.parties,
            &rho,
            &nonce_share,
        )
        .expect("nonce-backed preprocessing input");
        let input_high_lanes = input.highs.len();
        let options = PreprocessingSessionOptions {
            session_id,
            signer_set: config.parties.clone(),
            keygen_transcript_hash: config.transcript_hash().0,
        };
        let mut sessions = vec![PreprocessingSession::<MlDsa65, _, _>::start(
            options,
            input,
            SessionRegistry::new(),
            ProductMaskedBroadcastConsistencyVerifier,
        )
        .expect("start preprocessing session")];
        route_preprocessing_broadcasts(&mut sessions);

        let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let cursor_path = test_store_path("preprocessing-release-driver-cursor");
        let cursor_store =
            FilePreprocessingReleaseSessionCursorStore::open(&cursor_path).expect("cursor store");
        let mut driver = sessions
            .remove(0)
            .into_release_driver(config.clone(), rho, nonce_share, &mut adapter, cursor_store)
            .expect("start release preprocessing driver");
        assert_eq!(
            driver.phase(),
            PreprocessingReleaseDriverPhase::PrivateRuntime
        );
        assert_eq!(
            driver
                .cursor_store()
                .latest_release_cursor(session_id)
                .expect("transcript cursor")
                .phase,
            PreprocessingReleaseSessionPhase::TranscriptComplete
        );

        let mut round = 0u64;
        while driver.phase() != PreprocessingReleaseDriverPhase::ReadyToCertify {
            let mut entropy = TestProductionVectorEntropy {
                next: 297_000 + round * 1_000,
            };
            driver
                .drive_runtime_step::<_, _, _, _>(&mut adapter, &mut entropy)
                .expect("drive release preprocessing driver");
            match driver
                .collect_runtime_step(&mut adapter)
                .expect("collect release preprocessing driver")
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("one-party driver phase unexpectedly waiting: {status:?}")
                }
            }
            round = round.saturating_add(1);
            assert!(round < 512, "release preprocessing driver did not converge");
        }
        assert_eq!(
            driver
                .cursor_store()
                .latest_release_cursor(session_id)
                .expect("strict mask cursor")
                .phase,
            PreprocessingReleaseSessionPhase::StrictMasksComplete
        );
        let counters = driver.counters();
        assert!(counters.private_runtime_drive_steps > 0);
        assert!(counters.private_runtime_collect_steps > 0);
        assert!(counters.strict_mask_drive_steps > 0);
        assert!(counters.strict_mask_collect_steps > 0);
        assert!(
            counters.strict_mask_drive_steps < 128,
            "strict-mask scheduler should use packed mask phases"
        );

        let token_log_path = test_store_path("preprocessing-release-driver-token-log");
        let mut token_log =
            FilePreprocessingReleaseTokenBatchLog::open(&token_log_path).expect("open token log");
        let (token, cursor_store) = driver
            .finish_and_append_token_log(&mut adapter, &mut token_log, 0)
            .expect("driver emits release token and token log");
        assert!(token.is_release_certified());
        let runtime_evidence = token
            .vector_runtime_certificate()
            .expect("runtime certificate")
            .runtime_evidence();
        assert!(runtime_evidence.coverage.random_bit_vec);
        assert!(runtime_evidence.coverage.comparison_to_public);
        assert!(runtime_evidence.coverage.bit_sum_or_threshold_check);
        assert!(
            !runtime_evidence.counters.used_scalar_execution(),
            "release preprocessing must not use scalar MPC fallback"
        );
        assert!(
            runtime_evidence.counters.rounds < 256,
            "strict-mask batching should keep release-driver rounds bounded"
        );
        let phase_profile = adapter
            .runtime
            .runtime_phase_profile()
            .expect("runtime phase profile");
        talus_dkg::ensure_prime_field_mpc_phase_profile_within_chunk_policy::<MlDsa65>(
            &phase_profile,
        )
        .expect("phase profile respects suite chunk policy");
        let top_profile =
            talus_dkg::top_prime_field_mpc_phase_profiles_by_durable_log_bytes(&phase_profile, 5);
        assert_eq!(
            top_profile.len(),
            5.min(phase_profile.len()),
            "top phase profile should expose the dominant runtime costs"
        );
        assert!(
            top_profile
                .windows(2)
                .all(|pair| pair[0].durable_log_bytes >= pair[1].durable_log_bytes),
            "top phase profile should be sorted by durable log cost"
        );
        eprintln!("top vector MPC phases by durable log bytes: {top_profile:?}");
        assert!(
            phase_profile.iter().all(|entry| {
                entry.records == entry.private_records + entry.broadcast_records
                    && entry.wire_bytes != 0
                    && entry.durable_log_bytes != 0
                    && entry.is_vectorized()
            }),
            "phase profile should account for every durable wire record"
        );
        assert!(
            top_profile
                .iter()
                .all(|entry| entry.wire_bytes < entry.vector_lanes.saturating_mul(4)),
            "dominant vector MPC phases should use compact 24-bit lane encoding"
        );
        let random_bit_profile = phase_profile
            .iter()
            .find(|entry| {
                entry.kind == PrimeFieldMpcRoundKind::RandomBit
                    && entry.phase == PrimeFieldMpcPhase::RandomBitShare
            })
            .expect("packed random-bit phase profile");
        assert!(
            random_bit_profile.records <= 8,
            "random-bit packing should not regress into per-bit records"
        );
        assert!(
            random_bit_profile.distinct_labels <= 8,
            "random-bit phases should stay packed across strict mask lanes"
        );
        assert!(
            random_bit_profile.vector_lanes >= 2 * 23 * input_high_lanes as u64,
            "strict z/hint masks should be generated as packed vector lanes"
        );
        let comparison_profile = phase_profile
            .iter()
            .find(|entry| {
                entry.kind == PrimeFieldMpcRoundKind::MulDegreeReduce
                    && entry.phase == PrimeFieldMpcPhase::ComparisonToPublicCheck
            })
            .expect("strict-mask comparison phase profile");
        assert!(
            comparison_profile.records <= 52 && comparison_profile.distinct_labels <= 26,
            "strict-mask comparison should stay phase-batched"
        );
        let carry_compare_profile = phase_profile
            .iter()
            .find(|entry| {
                entry.kind == PrimeFieldMpcRoundKind::MulDegreeReduce
                    && entry.phase == PrimeFieldMpcPhase::PreprocessingCarryCompare
            })
            .expect("preprocessing carry-compare phase profile");
        assert!(
            carry_compare_profile.records <= 44 && carry_compare_profile.distinct_labels <= 22,
            "preprocessing CarryCompare should stay phase-batched"
        );
        assert!(
            phase_profile.iter().any(|entry| {
                entry.kind == PrimeFieldMpcRoundKind::MulDegreeReduce
                    && matches!(
                        entry.phase,
                        PrimeFieldMpcPhase::ComparatorShare
                            | PrimeFieldMpcPhase::ComparisonToPublicCheck
                            | PrimeFieldMpcPhase::PreprocessingCarryCompare
                            | PrimeFieldMpcPhase::PreprocessingCefBcc
                    )
                    && entry.vector_lanes != 0
            }),
            "phase profile should expose vector comparator work"
        );
        assert!(
            phase_profile.iter().any(|entry| {
                entry.kind == PrimeFieldMpcRoundKind::AssertZero
                    && entry.phase == PrimeFieldMpcPhase::AssertZeroShare
                    && entry.vector_lanes != 0
            }),
            "phase profile should expose batched assert-zero work"
        );
        assert_eq!(token_log.entries().len(), 1);
        token_log
            .replay_for_release(core::slice::from_ref(&token))
            .expect("token log replays");
        assert_eq!(
            cursor_store
                .latest_release_cursor(session_id)
                .expect("certified cursor")
                .phase,
            PreprocessingReleaseSessionPhase::ReleaseTokenCertified
        );
        assert_eq!(
            cursor_store
                .latest_release_cursor(session_id)
                .expect("certified cursor")
                .token_binding_hash,
            token
                .vector_runtime_certificate()
                .and_then(PreprocessingVectorRuntimeCertificate::token_binding_hash)
        );
        let reopened_cursor_store =
            FilePreprocessingReleaseSessionCursorStore::open(&cursor_path).expect("reopen cursor");
        assert_eq!(
            reopened_cursor_store
                .latest_release_cursor(session_id)
                .expect("replayed certified cursor")
                .phase,
            PreprocessingReleaseSessionPhase::ReleaseTokenCertified
        );
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn production_public_comparison_vec_boundaries_match_clear_values() {
        let (config, mut runtime) = latest_round_vector_runtime_one_party::<MlDsa65>(971);
        let values = [0, 1, 2, MlDsa65::Q - 2, MlDsa65::Q - 1];
        let root = Power2RoundTranscriptLabel::root(&config, [0x71; 32])
            .child("comparison_boundary_regression");
        let bits = comparison_bits_from_values::<MlDsa65>(
            &runtime,
            &config,
            &values,
            &root.child("value_bits"),
        );

        let mut lt_two = runtime
            .start_lt_public_vec::<MlDsa65>(&config, &bits, 2, &root.child("lt_two"))
            .expect("start lt two");
        let opened_lt_two = drive_comparison_to_opened_bits::<MlDsa65>(
            &mut runtime,
            &config,
            &mut lt_two,
            &root.child("open_lt_two"),
        );
        assert_eq!(opened_lt_two, vec![1, 1, 0, 0, 0]);

        let lane_thresholds = [0, 0, 1, MlDsa65::Q - 1, MlDsa65::Q - 2];
        let mut gt_lanes = runtime
            .start_gt_public_lanes_vec::<MlDsa65>(
                &config,
                &bits,
                &lane_thresholds,
                &root.child("gt_lanes"),
            )
            .expect("start gt lanes");
        let opened_gt_lanes = drive_comparison_to_opened_bits::<MlDsa65>(
            &mut runtime,
            &config,
            &mut gt_lanes,
            &root.child("open_gt_lanes"),
        );
        assert_eq!(opened_gt_lanes, vec![0, 1, 1, 0, 1]);

        let profile = runtime.runtime_phase_profile().expect("phase profile");
        let comparison = profile
            .iter()
            .find(|entry| {
                entry.kind == PrimeFieldMpcRoundKind::MulDegreeReduce
                    && entry.phase == PrimeFieldMpcPhase::ComparisonToPublicCheck
            })
            .expect("comparison profile");
        assert!(
            comparison.distinct_labels <= 46,
            "two boundary comparisons should stay layer-packed"
        );
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn preprocessing_release_driver_premature_finish_fails_closed() {
        let session_id = session(98);
        let rho = [0x98; 32];
        let (config, mut runtime) = latest_round_vector_runtime_one_party::<MlDsa65>(98);
        let nonce_share = DistributedNonceShare {
            party: PartyId(1),
            y_share: PolyVec::new(vec![Poly::from_coeffs([0; 256]); MlDsa65::L]),
            nonce_commitment: NonceCommitment([0x98; 32]),
            randomness_commitment: Commitment([0x99; 32]),
        };
        let input = party_preprocess_input_from_distributed_nonce_share::<MlDsa65>(
            session_id,
            &config.parties,
            &rho,
            &nonce_share,
        )
        .expect("nonce-backed preprocessing input");
        let options = PreprocessingSessionOptions {
            session_id,
            signer_set: config.parties.clone(),
            keygen_transcript_hash: config.transcript_hash().0,
        };
        let mut sessions = vec![PreprocessingSession::<MlDsa65, _, _>::start(
            options,
            input,
            SessionRegistry::new(),
            ProductMaskedBroadcastConsistencyVerifier,
        )
        .expect("start preprocessing session")];
        route_preprocessing_broadcasts(&mut sessions);

        let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let cursor_path = test_store_path("preprocessing-release-driver-premature");
        let cursor_store =
            FilePreprocessingReleaseSessionCursorStore::open(&cursor_path).expect("cursor store");
        let driver = sessions
            .remove(0)
            .into_release_driver(config, rho, nonce_share, &mut adapter, cursor_store)
            .expect("start release preprocessing driver");
        assert_eq!(
            driver.phase(),
            PreprocessingReleaseDriverPhase::PrivateRuntime
        );

        assert!(matches!(
            driver.finish(&mut adapter),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        ));
        let reopened =
            FilePreprocessingReleaseSessionCursorStore::open(&cursor_path).expect("reopen cursor");
        assert_eq!(
            reopened
                .latest_release_cursor(session_id)
                .expect("aborted cursor")
                .phase,
            PreprocessingReleaseSessionPhase::Aborted
        );
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn preprocessing_release_session_cursor_file_replays_latest_phase() {
        let session_id = session(95);
        let transcript_hash = TranscriptHash([0x95; 32]);
        let token_hash = [0x96; 32];
        let path = test_store_path("preprocessing-release-cursor");

        {
            let mut store =
                FilePreprocessingReleaseSessionCursorStore::open(&path).expect("open cursor file");
            store
                .persist_release_cursor(&PreprocessingReleaseSessionCursor {
                    session_id,
                    phase: PreprocessingReleaseSessionPhase::TranscriptComplete,
                    transcript_hash,
                    token_binding_hash: None,
                })
                .expect("persist transcript cursor");
            store
                .persist_release_cursor(&PreprocessingReleaseSessionCursor {
                    session_id,
                    phase: PreprocessingReleaseSessionPhase::TranscriptComplete,
                    transcript_hash,
                    token_binding_hash: None,
                })
                .expect("duplicate transcript cursor is compacted");
            store
                .persist_release_cursor(&PreprocessingReleaseSessionCursor {
                    session_id,
                    phase: PreprocessingReleaseSessionPhase::ReleaseTokenCertified,
                    transcript_hash,
                    token_binding_hash: Some(token_hash),
                })
                .expect("persist certified cursor");
            store
                .persist_release_cursor(&PreprocessingReleaseSessionCursor {
                    session_id,
                    phase: PreprocessingReleaseSessionPhase::ReleaseTokenCertified,
                    transcript_hash,
                    token_binding_hash: Some(token_hash),
                })
                .expect("duplicate certified cursor is compacted");
        }

        let persisted = std::fs::read_to_string(&path).expect("read cursor file");
        assert_eq!(persisted.lines().count(), 2);
        let reopened =
            FilePreprocessingReleaseSessionCursorStore::open(&path).expect("reopen cursor file");
        assert_eq!(reopened.release_cursors().len(), 2);
        let latest = reopened
            .latest_release_cursor(session_id)
            .expect("latest replayed cursor");
        assert_eq!(
            latest.phase,
            PreprocessingReleaseSessionPhase::ReleaseTokenCertified
        );
        assert_eq!(latest.transcript_hash, transcript_hash);
        assert_eq!(latest.token_binding_hash, Some(token_hash));
        assert!(
            reopened.latest_release_cursor(session(96)).is_none(),
            "cursor replay must remain scoped to the original session"
        );
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn preprocessing_release_session_cursor_file_rejects_corrupt_records() {
        let path = test_store_path("preprocessing-release-cursor-corrupt");
        std::fs::write(
            &path,
            "talus-preprocessing-release-cursor-v1 not-a-session\n",
        )
        .expect("write corrupt cursor file");

        assert_eq!(
            FilePreprocessingReleaseSessionCursorStore::open(&path),
            Err(PreprocessError::SessionStoreCorrupt { line: 1 })
        );
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn all_suite_release_tokens_use_runtime_generated_strict_material() {
        fn check<P: MlDsaParams>(session_byte: u8) {
            let token = runtime_generated_release_token::<P>(
                session_byte,
                P::K * P::N,
                P::L * P::N,
                P::K * P::N,
            );
            assert_eq!(token.w1.len(), P::K * P::N);
            assert_eq!(
                token.precomputed_w_share().expect("runtime w").len(),
                P::K * P::N
            );
            let masks = token.strict_signing_masks().expect("strict masks");
            assert_eq!(masks.z_mask_value().len(), P::L * P::N);
            assert_eq!(masks.hint_mask_value().len(), P::K * P::N);
            assert!(token.vector_runtime_certificate().is_some());
            assert!(token.is_release_certified());
        }

        check::<MlDsa44>(140);
        check::<MlDsa65>(141);
        check::<MlDsa87>(142);
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn release_token_rejects_cross_token_precomputed_w_replay() {
        let token_a = runtime_generated_release_token::<MlDsa65>(143, 2, 2, 2);
        let token_b = runtime_generated_release_token::<MlDsa65>(144, 2, 2, 2);
        let replayed = token_b.with_precomputed_w_share(
            token_a
                .precomputed_w_share()
                .expect("source runtime w")
                .clone(),
        );

        assert_eq!(
            ensure_certified_token_release_valid(&replayed),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        assert!(!replayed.is_release_certified());
    }

    #[cfg(feature = "scaffold-dev")]
    #[test]
    fn strict_signing_mask_generation_driver_records_required_runtime_coverage() {
        let parties = vec![PartyId(1), PartyId(2), PartyId(3)];
        let config =
            DkgConfig::new::<MlDsa65>(2, parties, talus_dkg::KeygenEpoch(91)).expect("test config");
        let session_id = session(91);
        let transcript_hash = TranscriptHash([0x91; 32]);
        let mut runtimes = test_production_vector_prime_field_runtimes(&config);
        let mut states = runtimes
            .iter_mut()
            .map(|runtime| {
                ProductionPreprocessingCertificationRuntime::new(runtime)
                    .start_strict_signing_canonical_mask_generation(
                        session_id,
                        transcript_hash,
                        4,
                        4,
                    )
                    .expect("start mask generation")
            })
            .collect::<Vec<_>>();

        let mut round = 0u64;
        while states.iter().any(|state| !state.is_done()) {
            for (idx, runtime) in runtimes.iter_mut().enumerate() {
                if states[idx].is_done() {
                    continue;
                }
                let mut entropy = TestProductionVectorEntropy {
                    next: 91_000 + round * 10_000 + idx as u64 * 1_000,
                };
                ProductionPreprocessingCertificationRuntime::new(runtime)
                    .drive_strict_signing_canonical_mask_generation_step::<MlDsa65, _>(
                        &config,
                        &mut states[idx],
                        &mut entropy,
                    )
                    .expect("drive mask generation");
            }
            route_production_vector_messages(&mut runtimes);
            for (idx, runtime) in runtimes.iter_mut().enumerate() {
                if states[idx].is_done() {
                    continue;
                }
                match ProductionPreprocessingCertificationRuntime::new(runtime)
                    .collect_strict_signing_canonical_mask_generation_step::<MlDsa65>(
                        &config,
                        &mut states[idx],
                    )
                    .expect("collect mask generation")
                {
                    ProductionVectorItMpcCollectResult::Collected { .. } => {}
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        panic!("mask generation did not complete current phase: {status:?}")
                    }
                }
            }
            clear_production_vector_message_queues(&mut runtimes);
            round = round.saturating_add(1);
            assert!(round < 512, "strict mask generation did not converge");
        }

        let adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtimes[0]);
        let inventory = adapter
            .finish_strict_signing_canonical_mask_generation(states.remove(0))
            .expect("finish mask inventory");
        let provenance = inventory.provenance().expect("mask provenance");
        assert_eq!(provenance.session_id, session_id);
        assert_eq!(provenance.transcript_hash, transcript_hash);
        assert_eq!(inventory.z_mask_bits_by_bit().len(), 23);
        assert_eq!(inventory.hint_mask_bits_by_bit().len(), 23);
        assert_eq!(inventory.z_mask_value().len(), 4);
        assert_eq!(inventory.hint_mask_value().len(), 4);
        assert_ne!(
            inventory.z_mask_value().id().label_hash,
            inventory.hint_mask_value().id().label_hash
        );

        let evidence = adapter
            .runtime
            .runtime_evidence()
            .expect("runtime evidence");
        assert!(evidence.coverage.random_bit_vec);
        assert!(evidence.coverage.mul_vec);
        assert!(evidence.coverage.comparison_to_public);
        assert!(evidence.coverage.bit_sum_or_threshold_check);
        assert!(evidence.counters.random_bits >= 46 * 4);
        assert!(evidence.counters.local_public_mul_lanes >= 46 * 4);
        assert_eq!(provenance.runtime_transcript_hash, evidence.transcript_hash);
    }

    #[test]
    fn release_token_validation_rejects_detached_runtime_certificate() {
        let mut registry = SessionRegistry::new();
        let token_a = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(65),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("first preprocessing token certifies");
        let token_b = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(67),
            vec![input(1, &[2], &[4]), input(2, &[6], &[8])],
        )
        .expect("second preprocessing token certifies");
        let token_a = attach_test_strict_signing_runtime_material::<MlDsa65>(token_a)
            .expect("release runtime material a");
        let token_b = attach_test_strict_signing_runtime_material::<MlDsa65>(token_b)
            .expect("release runtime material b");
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token_a,
            release_vector_runtime_evidence_for_token(&token_a),
        )
        .expect("runtime certificate for token a");
        let token_b = token_b.with_vector_runtime_certificate(certificate);

        assert_eq!(
            ensure_certified_token_release_valid(&token_b),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        assert!(!token_b.is_release_certified());
    }

    #[cfg(feature = "production-release-checks")]
    #[test]
    fn production_release_checks_make_is_certified_require_release_valid_certificate() {
        let mut registry = SessionRegistry::new();
        let token_a = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(165),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("first preprocessing token certifies");
        let token_b = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(167),
            vec![input(1, &[2], &[4]), input(2, &[6], &[8])],
        )
        .expect("second preprocessing token certifies");
        let token_a = attach_test_strict_signing_runtime_material::<MlDsa65>(token_a)
            .expect("release runtime material a");
        let token_b = attach_test_strict_signing_runtime_material::<MlDsa65>(token_b)
            .expect("release runtime material b");
        let detached_certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token_a,
            release_vector_runtime_evidence_for_token(&token_a),
        )
        .expect("runtime certificate for token a");
        let token_b = token_b.with_vector_runtime_certificate(detached_certificate);

        assert!(!token_b.is_release_certified());
        assert!(!token_b.is_certified());

        let mut pool = TokenPool::new();
        assert_eq!(
            pool.insert_certified(token_b),
            Err(TokenPoolError::NotCertified(session(167)))
        );
    }

    #[test]
    fn release_token_validation_rejects_runtime_transcript_mismatch() {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(69),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("valid preprocessing certifies");
        let token = attach_test_strict_signing_runtime_material::<MlDsa65>(token)
            .expect("release runtime material");
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token,
            release_vector_runtime_evidence(),
        )
        .expect("runtime certificate with mismatched transcript");
        let token = token.with_vector_runtime_certificate(certificate);

        assert_eq!(
            ensure_certified_token_release_valid(&token),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        assert!(!token.is_release_certified());
    }

    #[test]
    fn release_token_validation_rejects_mutated_runtime_evidence_surface() {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(75),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("valid preprocessing certifies");
        let token = attach_test_strict_signing_runtime_material::<MlDsa65>(token)
            .expect("release runtime material");
        let mut certificate = PreprocessingVectorRuntimeCertificate::for_token(
            &token,
            release_vector_runtime_evidence_for_token(&token),
        )
        .expect("runtime certificate");
        certificate
            .runtime_evidence_mut_for_test()
            .counters
            .wire_bytes += 1;
        let token = token.with_vector_runtime_certificate(certificate);

        assert_eq!(
            ensure_certified_token_release_valid(&token),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );
        assert!(!token.is_release_certified());
    }

    #[test]
    fn release_token_validation_rejects_runtime_counters_below_token_lanes() {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(68),
            vec![
                input(1, &[1, 2, 3], &[3, 4, 5]),
                input(2, &[5, 6, 7], &[7, 8, 9]),
            ],
        )
        .expect("valid preprocessing certifies");
        let token = attach_test_strict_signing_runtime_material::<MlDsa65>(token)
            .expect("release runtime material");
        let mut evidence = release_vector_runtime_evidence_for_token(&token);
        evidence.counters.vector_lanes = 1;
        evidence.counters.vector_mul_lanes = 1;
        evidence.counters.vector_opening_lanes = 1;
        evidence.counters.vector_assert_zero_lanes = 1;
        evidence.counters.random_bits = 1;
        evidence.counters.local_public_mul_lanes = 1;
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(&token, evidence)
            .expect("runtime evidence still passes generic Phase 3 gate");
        let token = token.with_vector_runtime_certificate(certificate);

        assert_eq!(
            ensure_certified_token_release_valid(&token),
            Err(PreprocessError::PreprocessingCountersNotVectorized)
        );
        assert!(!token.is_release_certified());
    }

    #[test]
    fn release_token_validation_rejects_missing_masked_broadcast_runtime_coverage() {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(76),
            vec![
                input(1, &[1, 2, 3], &[3, 4, 5]),
                input(2, &[5, 6, 7], &[7, 8, 9]),
            ],
        )
        .expect("valid preprocessing certifies");
        let token = attach_test_strict_signing_runtime_material::<MlDsa65>(token)
            .expect("release runtime material");
        let mut evidence = release_vector_runtime_evidence_for_token(&token);
        evidence.coverage.preprocessing_masked_broadcast = false;
        assert_eq!(
            PreprocessingVectorRuntimeCertificate::for_token(&token, evidence),
            Err(PreprocessError::PreprocessingCountersNotVectorized)
        );
    }

    #[test]
    fn release_token_constructor_rejects_missing_strict_runtime_material() {
        let inputs = vec![input(1, &[1], &[3]), input(2, &[5], &[7])];
        let mut preview_registry = SessionRegistry::new();
        let preview = certify_preprocessing_token::<MlDsa65>(
            &mut preview_registry,
            session(66),
            inputs.clone(),
        )
        .expect("preview token certifies");
        let evidence = release_vector_runtime_evidence_for_token(&preview);
        let mut registry = SessionRegistry::new();
        let err = certify_preprocessing_token_release_validated::<MlDsa65>(
            &mut registry,
            session(66),
            inputs,
            evidence,
        )
        .expect_err("release token without strict material is rejected");
        assert_eq!(err, PreprocessError::PreprocessingRuntimeMaterialMissing);
    }

    #[test]
    fn release_token_from_runtime_envelopes_rejects_missing_strict_material() {
        let session_id = session(70);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let envelopes = inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| {
                prepare_masked_broadcast_envelope_with_runtime_transcript::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    [0x90u8.wrapping_add(idx as u8); 32],
                )
                .expect("runtime envelope")
            })
            .collect::<Vec<_>>();

        let mut preview_registry = SessionRegistry::new();
        let mut preview_verifier = ProductMaskedBroadcastConsistencyVerifier;
        let preview = certify_opened_masked_broadcasts_with_consistency::<MlDsa65, _>(
            &mut preview_verifier,
            &mut preview_registry,
            session_id,
            inputs.clone(),
            envelopes.clone(),
            transcript,
            None,
        )
        .expect("preview token certifies");
        let runtime_proofs = runtime_proofs_from_envelopes_and_preview::<MlDsa65>(
            session_id,
            transcript,
            signer_set.len(),
            inputs[0].highs.len(),
            &envelopes,
            &preview,
        );
        let mut evidence = release_vector_runtime_evidence();
        let runtime_transcripts = runtime_proofs
            .transcripts()
            .expect("runtime proof transcripts");
        evidence.transcript_hash = preprocessing_runtime_transcript_aggregate_hash(
            session_id,
            transcript,
            runtime_transcripts,
        )
        .expect("aggregate preprocessing runtime transcript");

        let mut registry = SessionRegistry::new();
        let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
        let err = certify_preprocessing_token_release_validated_from_envelopes::<MlDsa65, _>(
            &mut verifier,
            &mut registry,
            session_id,
            inputs,
            envelopes,
            transcript,
            runtime_proofs,
            evidence,
        )
        .expect_err("release token without strict material is rejected");
        assert_eq!(err, PreprocessError::PreprocessingRuntimeMaterialMissing);
    }

    #[test]
    fn release_token_from_runtime_envelopes_rejects_mismatched_runtime_transcripts() {
        let session_id = session(71);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let envelopes = inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| {
                prepare_masked_broadcast_envelope_with_runtime_transcript::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    [0xa0u8.wrapping_add(idx as u8); 32],
                )
                .expect("runtime envelope")
            })
            .collect::<Vec<_>>();
        let mut preview_registry = SessionRegistry::new();
        let mut preview_verifier = ProductMaskedBroadcastConsistencyVerifier;
        let preview = certify_opened_masked_broadcasts_with_consistency::<MlDsa65, _>(
            &mut preview_verifier,
            &mut preview_registry,
            session_id,
            inputs.clone(),
            envelopes.clone(),
            transcript,
            None,
        )
        .expect("preview token certifies");
        let mut runtime_proofs = runtime_proofs_from_envelopes_and_preview::<MlDsa65>(
            session_id,
            transcript,
            signer_set.len(),
            inputs[0].highs.len(),
            &envelopes,
            &preview,
        );
        runtime_proofs.masked_broadcast = [0x55; 32];
        runtime_proofs
            .outputs
            .masked_broadcast
            .runtime_transcript_hash = [0x55; 32];
        let mut evidence = release_vector_runtime_evidence();
        let runtime_transcripts = runtime_proofs
            .transcripts()
            .expect("runtime proof transcripts");
        evidence.transcript_hash = preprocessing_runtime_transcript_aggregate_hash(
            session_id,
            transcript,
            runtime_transcripts,
        )
        .expect("aggregate preprocessing runtime transcript");

        let mut registry = SessionRegistry::new();
        let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
        let err = certify_preprocessing_token_release_validated_from_envelopes::<MlDsa65, _>(
            &mut verifier,
            &mut registry,
            session_id,
            inputs,
            envelopes,
            transcript,
            runtime_proofs,
            evidence,
        )
        .expect_err("mismatched masked-broadcast runtime transcript rejects");

        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
    }

    #[test]
    fn release_token_from_runtime_envelopes_rejects_tampered_stage_runtime_proof() {
        let session_id = session(72);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let envelopes = inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| {
                prepare_masked_broadcast_envelope_with_runtime_transcript::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    [0xb0u8.wrapping_add(idx as u8); 32],
                )
                .expect("runtime envelope")
            })
            .collect::<Vec<_>>();
        let mut preview_registry = SessionRegistry::new();
        let mut preview_verifier = ProductMaskedBroadcastConsistencyVerifier;
        let preview = certify_opened_masked_broadcasts_with_consistency::<MlDsa65, _>(
            &mut preview_verifier,
            &mut preview_registry,
            session_id,
            inputs.clone(),
            envelopes.clone(),
            transcript,
            None,
        )
        .expect("preview token certifies");
        let mut runtime_proofs = runtime_proofs_from_envelopes_and_preview::<MlDsa65>(
            session_id,
            transcript,
            signer_set.len(),
            inputs[0].highs.len(),
            &envelopes,
            &preview,
        );
        runtime_proofs.carry_compare.bytes[7] ^= 0x44;
        let mut evidence = release_vector_runtime_evidence();
        let runtime_transcripts = runtime_proofs
            .transcripts()
            .expect("runtime proof transcripts remain decodable");
        evidence.transcript_hash = preprocessing_runtime_transcript_aggregate_hash(
            session_id,
            transcript,
            runtime_transcripts,
        )
        .expect("aggregate preprocessing runtime transcript");

        let mut registry = SessionRegistry::new();
        let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
        let err = certify_preprocessing_token_release_validated_from_envelopes::<MlDsa65, _>(
            &mut verifier,
            &mut registry,
            session_id,
            inputs,
            envelopes,
            transcript,
            runtime_proofs,
            evidence,
        )
        .expect_err("tampered CarryCompare runtime proof rejects");

        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
    }

    #[test]
    fn release_token_with_finished_runtime_driver_rejects_unfinished_state() {
        let session_id = session(102);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let evidence = release_vector_runtime_evidence();
        let envelopes = inputs
            .iter()
            .map(|input| {
                prepare_masked_broadcast_envelope_with_vector_runtime_evidence::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    &evidence,
                )
                .expect("runtime-derived envelope")
            })
            .collect::<Vec<_>>();
        let config = talus_dkg::DkgConfig::new::<MlDsa65>(
            2,
            vec![PartyId(1), PartyId(2), PartyId(3)],
            talus_dkg::KeygenEpoch(102),
        )
        .expect("dkg config");
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
        let mut vector_runtime = talus_dkg::ProductionVectorPrimeFieldMpcRuntime::new(
            talus_dkg::CursoredTransportPrimeFieldMpcPartyRuntime::new(
                party_runtime,
                talus_dkg::InMemoryPrimeFieldMpcPhaseCursorLog::default(),
            ),
        );
        let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut vector_runtime);
        let (_, _, unfinished_state) = adapter
            .start_private_circuit_handles_from_envelopes::<MlDsa65>(
                &config,
                session_id,
                inputs.clone(),
                envelopes.clone(),
                transcript,
            )
            .expect("start from release envelopes");

        let mut registry = SessionRegistry::new();
        let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
        let err = certify_preprocessing_token_release_validated_with_finished_runtime_driver::<
            MlDsa65,
            _,
            _,
            _,
            _,
        >(
            &mut verifier,
            &mut registry,
            session_id,
            inputs,
            envelopes,
            transcript,
            &mut adapter,
            &unfinished_state,
        )
        .expect_err("unfinished private runtime driver must reject");

        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
    }

    #[cfg(feature = "scaffold-dev")]
    fn runtime_release_tokens_for_inputs(
        config: &DkgConfig,
        session_id: SessionId,
        inputs: Vec<PartyPreprocessInput>,
    ) -> Result<(Vec<CertifiedToken>, Vec<BroadcastEnvelope>, TranscriptHash), PreprocessError>
    {
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let envelopes = inputs
            .iter()
            .map(|input| {
                prepare_masked_broadcast_envelope::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                )
                .expect("masked-broadcast envelope")
            })
            .collect::<Vec<_>>();
        runtime_release_tokens_from_envelopes(config, session_id, inputs, envelopes, transcript)
    }

    #[cfg(all(feature = "scaffold-dev", feature = "std"))]
    fn runtime_release_tokens_for_nonce_shares(
        config: &DkgConfig,
        session_id: SessionId,
        rho: &[u8; 32],
        nonce_shares: Vec<DistributedNonceShare>,
    ) -> Result<
        (
            Vec<CertifiedToken>,
            Vec<BroadcastEnvelope>,
            TranscriptHash,
            FilePreprocessingReleaseTokenBatchLog,
        ),
        PreprocessError,
    > {
        let signer_set = config.parties.clone();
        let options = PreprocessingSessionOptions {
            session_id,
            signer_set: signer_set.clone(),
            keygen_transcript_hash: config.transcript_hash().0,
        };
        let mut sessions = nonce_shares
            .iter()
            .map(|share| {
                let input = party_preprocess_input_from_distributed_nonce_share::<MlDsa65>(
                    session_id,
                    &signer_set,
                    rho,
                    share,
                )?;
                PreprocessingSession::<MlDsa65, _, _>::start(
                    options.clone(),
                    input,
                    SessionRegistry::new(),
                    ProductMaskedBroadcastConsistencyVerifier,
                )
            })
            .collect::<Result<Vec<_>, PreprocessError>>()?;
        route_preprocessing_broadcasts(&mut sessions);

        let transcript = preprocessing_session_open_hash::<MlDsa65>(session_id, &signer_set);
        let inputs = sessions
            .first()
            .ok_or(PreprocessError::EmptySignerSet)?
            .inputs
            .clone();
        let envelopes = sessions
            .first()
            .ok_or(PreprocessError::EmptySignerSet)?
            .envelopes
            .clone();
        for session in &sessions {
            if session.inputs != inputs || session.envelopes != envelopes {
                return Err(PreprocessError::PreprocessingRuntimeCertificateMismatch);
            }
        }

        let mut runtimes = test_production_vector_prime_field_runtimes(&config);
        let mut drivers = Vec::new();

        for (session, runtime) in sessions.into_iter().zip(runtimes.iter_mut()) {
            let nonce_share = nonce_shares
                .iter()
                .find(|share| share.party == runtime.local_party())
                .ok_or(PreprocessError::NonceGenerationFailed)?
                .clone();
            let mut adapter = ProductionPreprocessingCertificationRuntime::new(runtime);
            drivers.push(session.into_release_driver(
                config.clone(),
                *rho,
                nonce_share,
                &mut adapter,
                PreprocessingReleaseSessionCursorMemoryStore::new(),
            )?);
        }

        let mut batch_driver = PreprocessingReleaseBatchDriver::new(drivers)?;
        let mut round = 0u64;
        while !batch_driver.is_ready_to_certify() {
            batch_driver.drive_active(|idx, driver| {
                let mut entropy = TestProductionVectorEntropy {
                    next: 230_000 + round * 10_000 + idx as u64 * 1_000,
                };
                let mut adapter = ProductionPreprocessingCertificationRuntime::new(
                    runtimes
                        .get_mut(idx)
                        .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?,
                );
                driver.drive_runtime_step::<_, _, _, _>(&mut adapter, &mut entropy)
            })?;
            route_production_vector_messages(&mut runtimes);
            batch_driver.collect_active(|idx, driver| {
                let mut adapter = ProductionPreprocessingCertificationRuntime::new(
                    runtimes
                        .get_mut(idx)
                        .ok_or(PreprocessError::PreprocessingRuntimeCertificateMismatch)?,
                );
                match driver.collect_runtime_step(&mut adapter)? {
                    ProductionVectorItMpcCollectResult::Collected { .. } => {}
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        panic!("release driver step did not complete: {status:?}")
                    }
                }
                Ok(())
            })?;
            clear_production_vector_message_queues(&mut runtimes);
            round = round.saturating_add(1);
            assert!(
                round < 768,
                "release preprocessing drivers did not converge"
            );
        }
        assert_eq!(batch_driver.attempted_tokens(), signer_set.len() as u64);

        let token_log_path = test_store_path("release-token-batch-driver");
        let mut token_log =
            FilePreprocessingReleaseTokenBatchLog::open(&token_log_path).expect("token log");
        let mut tokens = Vec::new();
        let mut cursor_stores = Vec::new();
        for (idx, (driver, runtime)) in batch_driver
            .into_drivers()
            .into_iter()
            .zip(runtimes.iter_mut())
            .enumerate()
        {
            let mut adapter = ProductionPreprocessingCertificationRuntime::new(runtime);
            let (token, cursor_store) =
                driver.finish_and_append_token_log(&mut adapter, &mut token_log, idx)?;
            assert!(token.is_release_certified());
            assert_eq!(
                cursor_store
                    .latest_release_cursor(session_id)
                    .expect("certified cursor")
                    .phase,
                PreprocessingReleaseSessionPhase::ReleaseTokenCertified
            );
            cursor_stores.push(cursor_store);
            tokens.push(token);
        }
        token_log
            .replay_for_release(&tokens)
            .map_err(|_| PreprocessError::PreprocessingRuntimeCertificateMismatch)?;
        let fill_report = PreprocessingTokenBatchFillReport::from_certified_tokens(
            signer_set.len() as u64,
            &tokens,
        );
        assert_eq!(fill_report.certified_tokens, signer_set.len() as u64);
        assert!(fill_report.pass_probability_estimate().is_some());
        assert_eq!(token_log.entries().len(), signer_set.len());
        assert_eq!(cursor_stores.len(), signer_set.len());

        Ok((tokens, envelopes, transcript, token_log))
    }

    #[cfg(feature = "scaffold-dev")]
    fn runtime_release_tokens_from_envelopes(
        config: &DkgConfig,
        session_id: SessionId,
        inputs: Vec<PartyPreprocessInput>,
        envelopes: Vec<BroadcastEnvelope>,
        transcript: TranscriptHash,
    ) -> Result<(Vec<CertifiedToken>, Vec<BroadcastEnvelope>, TranscriptHash), PreprocessError>
    {
        let statement = preprocessing_certification_runtime_statement_from_envelopes::<MlDsa65>(
            session_id,
            inputs.clone(),
            envelopes.clone(),
            transcript,
        )?;
        let mut runtimes = test_production_vector_prime_field_runtimes(&config);
        let mut states = Vec::new();

        for runtime in &mut runtimes {
            let adapter = ProductionPreprocessingCertificationRuntime::new(runtime);
            let (started_statement, _, state) = adapter
                .start_private_circuit_handles_from_envelopes::<MlDsa65>(
                    &config,
                    session_id,
                    inputs.clone(),
                    envelopes.clone(),
                    transcript,
                )
                .map_err(|err| err)?;
            assert_eq!(started_statement, statement);
            states.push(state);
        }

        let mut round = 0u64;
        while states.iter().any(|state| !state.is_done()) {
            for (idx, runtime) in runtimes.iter_mut().enumerate() {
                if states[idx].is_done() {
                    continue;
                }
                let mut entropy = TestProductionVectorEntropy {
                    next: 90_000 + round * 10_000 + idx as u64 * 1_000,
                };
                let mut adapter = ProductionPreprocessingCertificationRuntime::new(runtime);
                adapter
                    .drive_private_circuit_handles_step::<MlDsa65, _>(
                        &config,
                        &mut states[idx],
                        &mut entropy,
                    )
                    .map_err(|err| err)?;
            }
            route_production_vector_messages(&mut runtimes);
            for (idx, runtime) in runtimes.iter_mut().enumerate() {
                if states[idx].is_done() {
                    continue;
                }
                let mut adapter = ProductionPreprocessingCertificationRuntime::new(runtime);
                match adapter
                    .collect_private_circuit_handles_step::<MlDsa65>(&config, &mut states[idx])
                    .map_err(|err| err)?
                {
                    ProductionVectorItMpcCollectResult::Collected { .. } => {}
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        panic!("private preprocessing step did not complete: {status:?}")
                    }
                }
            }
            clear_production_vector_message_queues(&mut runtimes);
            round = round.saturating_add(1);
            assert!(
                round < 256,
                "private preprocessing circuits did not converge"
            );
        }

        let mut mask_states = Vec::new();
        for runtime in &mut runtimes {
            let adapter = ProductionPreprocessingCertificationRuntime::new(runtime);
            mask_states.push(adapter.start_strict_signing_canonical_mask_generation(
                session_id,
                transcript,
                statement.coeff_count,
                statement.coeff_count,
            )?);
        }

        let mut mask_round = 0u64;
        while mask_states.iter().any(|state| !state.is_done()) {
            for (idx, runtime) in runtimes.iter_mut().enumerate() {
                if mask_states[idx].is_done() {
                    continue;
                }
                let mut entropy = TestProductionVectorEntropy {
                    next: 130_000 + mask_round * 10_000 + idx as u64 * 1_000,
                };
                ProductionPreprocessingCertificationRuntime::new(runtime)
                    .drive_strict_signing_canonical_mask_generation_step::<MlDsa65, _>(
                        &config,
                        &mut mask_states[idx],
                        &mut entropy,
                    )?;
            }
            route_production_vector_messages(&mut runtimes);
            for (idx, runtime) in runtimes.iter_mut().enumerate() {
                if mask_states[idx].is_done() {
                    continue;
                }
                match ProductionPreprocessingCertificationRuntime::new(runtime)
                    .collect_strict_signing_canonical_mask_generation_step::<MlDsa65>(
                        &config,
                        &mut mask_states[idx],
                    )? {
                    ProductionVectorItMpcCollectResult::Collected { .. } => {}
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        panic!("strict mask generation step did not complete: {status:?}")
                    }
                }
            }
            clear_production_vector_message_queues(&mut runtimes);
            mask_round = mask_round.saturating_add(1);
            assert!(mask_round < 512, "strict mask generation did not converge");
        }

        let mut tokens = Vec::new();
        for (idx, runtime) in runtimes.iter_mut().enumerate() {
            let mut adapter = ProductionPreprocessingCertificationRuntime::new(runtime);
            let mut registry = SessionRegistry::new();
            let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
            let token = dev_certify_preprocessing_token_with_opened_material_w_for_tests::<
                MlDsa65,
                _,
                _,
                _,
                _,
            >(
                &mut verifier,
                &mut registry,
                session_id,
                inputs.clone(),
                envelopes.clone(),
                transcript,
                config,
                &mut adapter,
                &states[idx],
                mask_states[idx].clone(),
            )
            .map_err(|err| err)?;
            assert!(token.is_release_certified());
            tokens.push(token);
        }

        Ok((tokens, envelopes, transcript))
    }

    #[cfg(all(feature = "scaffold-dev", feature = "std"))]
    #[test]
    fn release_batch_driver_builds_tokens_from_nonce_shares() {
        let config = talus_dkg::DkgConfig::new::<MlDsa65>(
            1,
            vec![PartyId(1), PartyId(2)],
            talus_dkg::KeygenEpoch(166),
        )
        .expect("dkg config");
        let session_id = session(166);
        let rho = [0xa6; 32];
        let nonce_shares = config
            .parties
            .iter()
            .map(|party| DistributedNonceShare {
                party: *party,
                y_share: PolyVec::new(vec![Poly::from_coeffs([0; 256]); MlDsa65::L]),
                nonce_commitment: NonceCommitment([party.0 as u8; 32]),
                randomness_commitment: Commitment([party.0.wrapping_add(10) as u8; 32]),
            })
            .collect::<Vec<_>>();

        let (mut tokens, envelopes, transcript, token_log) =
            runtime_release_tokens_for_nonce_shares(&config, session_id, &rho, nonce_shares)
                .expect("batch driver release tokens");

        assert_eq!(tokens.len(), config.parties.len());
        assert_eq!(envelopes.len(), config.parties.len());
        assert_ne!(transcript.0, [0u8; 32]);
        token_log
            .replay_for_release(&tokens)
            .expect("driver token log replays");
        for token in &tokens {
            assert!(token.is_release_certified());
            assert_eq!(token.session_id, session_id);
            assert_eq!(token.signer_set, config.parties);
            assert!(token.y_share.is_empty());
            assert!(token.precomputed_w_share().is_some());
            assert!(token.strict_signing_masks().is_some());
        }

        let mut wrong_order_entries = token_log.entries().to_vec();
        wrong_order_entries.reverse();
        assert_eq!(
            ensure_preprocessing_release_token_batch_log_for_release(&tokens, &wrong_order_entries),
            Err(PreprocessError::PreprocessingRuntimeCertificateMismatch)
        );

        let duplicate_log_path = test_store_path("release-batch-driver-duplicate-log");
        let duplicate_line = encode_preprocessing_release_token_log_entry(
            token_log.entries().first().expect("first log entry"),
        );
        std::fs::write(
            &duplicate_log_path,
            format!("{duplicate_line}\n{duplicate_line}\n"),
        )
        .expect("write duplicate log");
        assert_eq!(
            FilePreprocessingReleaseTokenBatchLog::open(&duplicate_log_path),
            Err(TokenPoolError::ReleaseLogCorrupt { line: 2 })
        );

        let tampered_log_path = test_store_path("release-batch-driver-tampered-log");
        let mut tampered_entries = token_log.entries().to_vec();
        tampered_entries
            .first_mut()
            .expect("tampered entry")
            .certificate_hash = [0x55; 32];
        std::fs::write(
            &tampered_log_path,
            tampered_entries
                .iter()
                .map(encode_preprocessing_release_token_log_entry)
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
        .expect("write tampered log");
        let tampered_log =
            FilePreprocessingReleaseTokenBatchLog::open(&tampered_log_path).expect("tampered log");
        assert_eq!(
            tampered_log.replay_for_release(&tokens),
            Err(TokenPoolError::ReleaseLogMismatch)
        );

        let local_token = tokens.remove(0);
        let local_log_path = test_store_path("release-batch-driver-local-token-log");
        let mut local_log =
            FilePreprocessingReleaseTokenBatchLog::open(&local_log_path).expect("local token log");
        local_log
            .append(
                *token_log
                    .entries()
                    .first()
                    .expect("first driver token log entry"),
            )
            .expect("append local token log entry");
        local_log
            .replay_for_release(core::slice::from_ref(&local_token))
            .expect("local token log replays");

        let inventory_path = test_store_path("release-batch-driver-inventory");
        let mut pool = TokenPool::new();
        let mut inventory = FileTokenInventory::open(&inventory_path).expect("inventory");
        let local_session_id = local_token.session_id;
        pool.insert_release_certified_batch_with_inventory_and_file_log(
            vec![local_token],
            &local_log,
            &mut inventory,
        )
        .expect("driver token batch enters pool");
        assert_eq!(
            inventory.state(local_session_id),
            TokenInventoryState::Reserved
        );
        assert!(pool.take_certified(local_session_id).is_ok());
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn fused_strict_mask_batch_certifies_multiple_tokens_with_one_mask_circuit() {
        let (config, mut runtime) = latest_round_vector_runtime_one_party::<MlDsa65>(176);
        let rho = [0xb6; 32];
        let signer_set = config.parties.clone();
        let mut drivers = Vec::new();

        for offset in 0..2u8 {
            let session_id = session(176u8.wrapping_add(offset));
            let nonce_share = DistributedNonceShare {
                party: PartyId(1),
                y_share: PolyVec::new(vec![Poly::from_coeffs([0; 256]); MlDsa65::L]),
                nonce_commitment: NonceCommitment([0xb6u8.wrapping_add(offset); 32]),
                randomness_commitment: Commitment([0xc6u8.wrapping_add(offset); 32]),
            };
            let input = party_preprocess_input_from_distributed_nonce_share::<MlDsa65>(
                session_id,
                &signer_set,
                &rho,
                &nonce_share,
            )
            .expect("nonce-backed input");
            let options = PreprocessingSessionOptions {
                session_id,
                signer_set: signer_set.clone(),
                keygen_transcript_hash: config.transcript_hash().0,
            };
            let mut sessions = vec![PreprocessingSession::<MlDsa65, _, _>::start(
                options,
                input,
                SessionRegistry::new(),
                ProductMaskedBroadcastConsistencyVerifier,
            )
            .expect("start preprocessing")];
            route_preprocessing_broadcasts(&mut sessions);
            let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
            drivers.push(
                sessions
                    .remove(0)
                    .into_release_driver(
                        config.clone(),
                        rho,
                        nonce_share,
                        &mut adapter,
                        PreprocessingReleaseSessionCursorMemoryStore::new(),
                    )
                    .expect("release driver"),
            );
        }

        let mut batch = PreprocessingReleaseBatchDriver::new(drivers).expect("batch driver");
        for driver in batch.drivers.iter_mut() {
            let mut round = 0u64;
            while driver.phase() == PreprocessingReleaseDriverPhase::PrivateRuntime {
                let mut entropy = TestProductionVectorEntropy {
                    next: 376_000 + round * 10_000,
                };
                let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
                driver
                    .drive_runtime_step::<_, _, _, _>(&mut adapter, &mut entropy)
                    .expect("drive private runtime");
                let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
                match driver
                    .collect_runtime_step(&mut adapter)
                    .expect("collect private runtime")
                {
                    ProductionVectorItMpcCollectResult::Collected { .. } => {}
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        panic!("private runtime did not complete: {status:?}")
                    }
                }
                round = round.saturating_add(1);
                assert!(round < 256, "private runtime did not converge");
            }
        }
        assert!(batch
            .phases()
            .iter()
            .all(|phase| *phase == PreprocessingReleaseDriverPhase::StrictMasks));

        let members = batch.strict_mask_batch_members();
        let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let mut fused_masks = adapter
            .start_strict_signing_canonical_mask_batch_generation(&members)
            .expect("start fused mask generation");
        let mut mask_round = 0u64;
        while !fused_masks.is_done() {
            let mut entropy = TestProductionVectorEntropy {
                next: 476_000 + mask_round * 1_000,
            };
            adapter
                .drive_strict_signing_canonical_mask_generation_step::<MlDsa65, _>(
                    &config,
                    &mut fused_masks,
                    &mut entropy,
                )
                .expect("drive fused masks");
            match adapter
                .collect_strict_signing_canonical_mask_generation_step::<MlDsa65>(
                    &config,
                    &mut fused_masks,
                )
                .expect("collect fused masks")
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("fused mask phase did not complete: {status:?}")
                }
            }
            mask_round = mask_round.saturating_add(1);
            assert!(mask_round < 256, "fused masks did not converge");
        }
        let inventories = adapter
            .finish_strict_signing_canonical_mask_batch_generation::<MlDsa65>(
                &config,
                fused_masks,
                &members,
            )
            .expect("split fused masks");
        assert_eq!(inventories.len(), 2);
        let first_runtime_hash = inventories[0]
            .provenance()
            .expect("first provenance")
            .runtime_transcript_hash;
        assert_ne!(first_runtime_hash, [0u8; 32]);
        assert!(inventories.iter().all(|inventory| {
            inventory
                .provenance()
                .expect("fused provenance")
                .runtime_transcript_hash
                == first_runtime_hash
        }));
        batch
            .install_fused_strict_mask_inventories(inventories)
            .expect("install fused inventories");
        assert!(batch.is_ready_to_certify());

        let token_log_path = test_store_path("fused-strict-mask-token-log");
        let mut token_log =
            FilePreprocessingReleaseTokenBatchLog::open(&token_log_path).expect("token log");
        let mut tokens = Vec::new();
        for (idx, driver) in batch.into_drivers().into_iter().enumerate() {
            let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
            let (token, _) = driver
                .finish_and_append_token_log(&mut adapter, &mut token_log, idx)
                .expect("finish fused-mask token");
            assert!(token.is_release_certified());
            assert_eq!(
                token
                    .strict_signing_masks()
                    .and_then(StrictSigningCanonicalMaskInventory::provenance)
                    .expect("token mask provenance")
                    .z_lane_count,
                MlDsa65::L * MlDsa65::N
            );
            tokens.push(token);
        }
        token_log
            .replay_for_release(&tokens)
            .expect("fused token log replays");
        assert_eq!(tokens.len(), 2);

        let profile = runtime.runtime_phase_profile().expect("phase profile");
        let random_bit_profile = profile
            .iter()
            .find(|entry| {
                entry.kind == PrimeFieldMpcRoundKind::RandomBit
                    && entry.phase == PrimeFieldMpcPhase::RandomBitShare
                    && entry.vector_lanes >= 2 * 23 * (MlDsa65::L + MlDsa65::K) as u64 * 256
            })
            .expect("one fused random-bit phase covers both tokens");
        assert!(
            random_bit_profile.distinct_labels <= 4,
            "fused mask generation should not create one random-bit label per token"
        );
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn fused_private_preprocessing_batch_runs_carry_compare_cef_bcc_as_one_vector_circuit() {
        let (config, mut runtime) = latest_round_vector_runtime_one_party::<MlDsa65>(186);
        let signer_set = config.parties.clone();
        let mut items = Vec::new();
        let coeff_count = 4usize;

        for offset in 0..2u8 {
            let session_id = session(186u8.wrapping_add(offset));
            let input = input(1, &vec![0; coeff_count], &vec![0; coeff_count]);
            let options = PreprocessingSessionOptions {
                session_id,
                signer_set: signer_set.clone(),
                keygen_transcript_hash: config.transcript_hash().0,
            };
            let mut sessions = vec![PreprocessingSession::<MlDsa65, _, _>::start(
                options,
                input,
                SessionRegistry::new(),
                ProductMaskedBroadcastConsistencyVerifier,
            )
            .expect("start preprocessing")];
            route_preprocessing_broadcasts(&mut sessions);
            let session = sessions.remove(0);
            items.push((
                session_id,
                session.inputs.clone(),
                session.envelopes.clone(),
                preprocessing_session_open_hash::<MlDsa65>(session_id, &signer_set),
            ));
        }

        let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let mut batch_state = adapter
            .start_private_circuit_batch_from_envelopes::<MlDsa65>(&config, items)
            .expect("start fused private preprocessing batch");
        assert_eq!(batch_state.members().len(), 2);
        assert_eq!(batch_state.batch_statement().coeff_count, 2 * coeff_count);

        let mut round = 0u64;
        while !batch_state.is_done() {
            let mut entropy = TestProductionVectorEntropy {
                next: 586_000 + round * 1_000,
            };
            adapter
                .drive_private_circuit_batch_step::<MlDsa65, _>(
                    &config,
                    &mut batch_state,
                    &mut entropy,
                )
                .expect("drive fused private batch");
            match adapter
                .collect_private_circuit_batch_step::<MlDsa65>(&config, &mut batch_state)
                .expect("collect fused private batch")
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("fused private batch did not complete: {status:?}")
                }
            }
            round = round.saturating_add(1);
            assert!(
                round < 256,
                "fused private preprocessing batch did not converge"
            );
        }

        let profile = runtime.runtime_phase_profile().expect("phase profile");
        let carry_profile = profile
            .iter()
            .find(|entry| {
                entry.kind == PrimeFieldMpcRoundKind::MulDegreeReduce
                    && entry.phase == PrimeFieldMpcPhase::PreprocessingCarryCompare
                    && entry.vector_lanes >= (2 * coeff_count) as u64
            })
            .expect("one fused CarryCompare phase covers both tokens");
        assert!(
            carry_profile.distinct_labels <= 32,
            "fused CarryCompare should not create one full label set per token"
        );
        let bcc_profile = profile
            .iter()
            .find(|entry| {
                entry.kind == PrimeFieldMpcRoundKind::MulDegreeReduce
                    && entry.phase == PrimeFieldMpcPhase::PreprocessingCefBcc
                    && entry.vector_lanes >= (2 * coeff_count) as u64
            })
            .expect("one fused CEF/BCC phase covers both tokens");
        assert!(
            bcc_profile.distinct_labels <= 8,
            "fused CEF/BCC should stay one batch circuit"
        );
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn fused_private_preprocessing_batch_promotes_to_release_token_certificates() {
        let (config, mut runtime) = latest_round_vector_runtime_one_party::<MlDsa65>(187);
        let rho = [0xb7; 32];
        let signer_set = config.parties.clone();
        let mut items = Vec::new();
        let mut token_inputs = Vec::new();

        for offset in 0..2u8 {
            let session_id = session(187u8.wrapping_add(offset));
            let nonce_share = DistributedNonceShare {
                party: PartyId(1),
                y_share: PolyVec::new(vec![Poly::from_coeffs([0; 256]); MlDsa65::L]),
                nonce_commitment: NonceCommitment([0xb7u8.wrapping_add(offset); 32]),
                randomness_commitment: Commitment([0xc7u8.wrapping_add(offset); 32]),
            };
            let input = party_preprocess_input_from_distributed_nonce_share::<MlDsa65>(
                session_id,
                &signer_set,
                &rho,
                &nonce_share,
            )
            .expect("nonce-backed input");
            let options = PreprocessingSessionOptions {
                session_id,
                signer_set: signer_set.clone(),
                keygen_transcript_hash: config.transcript_hash().0,
            };
            let mut sessions = vec![PreprocessingSession::<MlDsa65, _, _>::start(
                options,
                input,
                SessionRegistry::new(),
                ProductMaskedBroadcastConsistencyVerifier,
            )
            .expect("start preprocessing")];
            route_preprocessing_broadcasts(&mut sessions);
            let session = sessions.remove(0);
            let transcript = preprocessing_session_open_hash::<MlDsa65>(session_id, &signer_set);
            items.push((
                session_id,
                session.inputs.clone(),
                session.envelopes.clone(),
                transcript,
            ));
            token_inputs.push((
                session_id,
                session.inputs,
                session.envelopes,
                transcript,
                nonce_share,
            ));
        }

        let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let mut batch_state = adapter
            .start_private_circuit_batch_from_envelopes::<MlDsa65>(&config, items)
            .expect("start fused private preprocessing batch");
        let mut round = 0u64;
        while !batch_state.is_done() {
            let mut entropy = TestProductionVectorEntropy {
                next: 587_000 + round * 1_000,
            };
            adapter
                .drive_private_circuit_batch_step::<MlDsa65, _>(
                    &config,
                    &mut batch_state,
                    &mut entropy,
                )
                .expect("drive fused private batch");
            match adapter
                .collect_private_circuit_batch_step::<MlDsa65>(&config, &mut batch_state)
                .expect("collect fused private batch")
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("fused private batch did not complete: {status:?}")
                }
            }
            round = round.saturating_add(1);
            assert!(
                round < 256,
                "fused private preprocessing batch did not converge"
            );
        }

        let mask_members = token_inputs
            .iter()
            .map(
                |(session_id, _, _, transcript, _)| StrictSigningCanonicalMaskBatchMember {
                    session_id: *session_id,
                    transcript_hash: *transcript,
                    z_lane_count: MlDsa65::L * MlDsa65::N,
                    hint_lane_count: MlDsa65::K * MlDsa65::N,
                },
            )
            .collect::<Vec<_>>();
        let mut mask_state = adapter
            .start_strict_signing_canonical_mask_batch_generation(&mask_members)
            .expect("start fused strict masks");
        let mut mask_round = 0u64;
        while !mask_state.is_done() {
            let mut entropy = TestProductionVectorEntropy {
                next: 687_000 + mask_round * 1_000,
            };
            adapter
                .drive_strict_signing_canonical_mask_generation_step::<MlDsa65, _>(
                    &config,
                    &mut mask_state,
                    &mut entropy,
                )
                .expect("drive fused masks");
            match adapter
                .collect_strict_signing_canonical_mask_generation_step::<MlDsa65>(
                    &config,
                    &mut mask_state,
                )
                .expect("collect fused masks")
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("fused masks did not complete: {status:?}")
                }
            }
            mask_round = mask_round.saturating_add(1);
            assert!(mask_round < 256, "fused masks did not converge");
        }
        let inventories = adapter
            .finish_strict_signing_canonical_mask_batch_generation::<MlDsa65>(
                &config,
                mask_state,
                &mask_members,
            )
            .expect("split fused masks");

        let mut tokens = Vec::new();
        for ((session_id, inputs, envelopes, transcript, nonce_share), masks) in
            token_inputs.into_iter().zip(inventories)
        {
            let mut registry = SessionRegistry::new();
            let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
            let token =
                certify_preprocessing_token_release_validated_with_fused_private_batch_strict_inventory_and_nonce_share::<
                    MlDsa65,
                    _,
                    _,
                    _,
                    _,
                >(
                    &mut verifier,
                    &mut registry,
                    session_id,
                    inputs,
                    envelopes,
                    transcript,
                    &config,
                    &rho,
                    &signer_set,
                    &nonce_share,
                    &mut adapter,
                    &batch_state,
                    masks,
                )
                .expect("fused private batch promotes to release token");
            assert!(token.is_release_certified());
            let certificate = token
                .vector_runtime_certificate()
                .expect("release vector certificate");
            assert_eq!(token.session_id, session_id);
            assert_eq!(token.transcript_hash, transcript);
            assert!(token.strict_signing_masks().is_some());
            assert!(token.strict_signing_helpers().is_some());
            assert!(token.precomputed_w_share().is_some());
            assert!(certificate.token_binding_hash.is_some());
            tokens.push(token);
        }
        assert_eq!(tokens.len(), 2);
        assert_ne!(
            tokens[0]
                .vector_runtime_certificate()
                .expect("first certificate")
                .runtime_evidence
                .transcript_hash,
            tokens[1]
                .vector_runtime_certificate()
                .expect("second certificate")
                .runtime_evidence
                .transcript_hash,
            "per-token release certificate transcript must remain token-bound"
        );

        let profile = runtime.runtime_phase_profile().expect("phase profile");
        assert!(profile.iter().any(|entry| {
            entry.kind == PrimeFieldMpcRoundKind::MulDegreeReduce
                && entry.phase == PrimeFieldMpcPhase::PreprocessingCefBcc
                && entry.vector_lanes >= (2 * MlDsa65::K * MlDsa65::N) as u64
        }));
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    fn release_batch_driver_fuses_private_and_strict_mask_schedulers() {
        let (config, mut runtime) = latest_round_vector_runtime_one_party::<MlDsa65>(188);
        let rho = [0xb8; 32];
        let signer_set = config.parties.clone();
        let mut drivers = Vec::new();

        for offset in 0..2u8 {
            let session_id = session(188u8.wrapping_add(offset));
            let nonce_share = DistributedNonceShare {
                party: PartyId(1),
                y_share: PolyVec::new(vec![Poly::from_coeffs([0; 256]); MlDsa65::L]),
                nonce_commitment: NonceCommitment([0xb8u8.wrapping_add(offset); 32]),
                randomness_commitment: Commitment([0xc8u8.wrapping_add(offset); 32]),
            };
            let input = party_preprocess_input_from_distributed_nonce_share::<MlDsa65>(
                session_id,
                &signer_set,
                &rho,
                &nonce_share,
            )
            .expect("nonce-backed input");
            let options = PreprocessingSessionOptions {
                session_id,
                signer_set: signer_set.clone(),
                keygen_transcript_hash: config.transcript_hash().0,
            };
            let mut sessions = vec![PreprocessingSession::<MlDsa65, _, _>::start(
                options,
                input,
                SessionRegistry::new(),
                ProductMaskedBroadcastConsistencyVerifier,
            )
            .expect("start preprocessing")];
            route_preprocessing_broadcasts(&mut sessions);
            let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
            drivers.push(
                sessions
                    .remove(0)
                    .into_release_driver(
                        config.clone(),
                        rho,
                        nonce_share,
                        &mut adapter,
                        PreprocessingReleaseSessionCursorMemoryStore::new(),
                    )
                    .expect("release driver"),
            );
        }

        let mut batch = PreprocessingReleaseBatchDriver::new(drivers).expect("batch driver");
        {
            let adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
            batch
                .start_fused_private_runtime(&adapter)
                .expect("start fused private scheduler");
        }
        let mut round = 0u64;
        while batch
            .phases()
            .iter()
            .any(|phase| *phase == PreprocessingReleaseDriverPhase::PrivateRuntime)
        {
            let mut entropy = TestProductionVectorEntropy {
                next: 788_000 + round * 1_000,
            };
            let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
            batch
                .drive_fused_private_runtime_step::<_, _, _, _>(&mut adapter, &mut entropy)
                .expect("drive fused private scheduler");
            let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
            match batch
                .collect_fused_private_runtime_step::<_, _, _>(&mut adapter)
                .expect("collect fused private scheduler")
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("fused private scheduler did not complete: {status:?}")
                }
            }
            round = round.saturating_add(1);
            assert!(round < 256, "fused private scheduler did not converge");
        }
        assert!(batch
            .phases()
            .iter()
            .all(|phase| *phase == PreprocessingReleaseDriverPhase::StrictMasks));

        let members = batch.strict_mask_batch_members();
        let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let mut fused_masks = adapter
            .start_strict_signing_canonical_mask_batch_generation(&members)
            .expect("start fused strict masks");
        let mut mask_round = 0u64;
        while !fused_masks.is_done() {
            let mut entropy = TestProductionVectorEntropy {
                next: 888_000 + mask_round * 1_000,
            };
            adapter
                .drive_strict_signing_canonical_mask_generation_step::<MlDsa65, _>(
                    &config,
                    &mut fused_masks,
                    &mut entropy,
                )
                .expect("drive fused strict masks");
            match adapter
                .collect_strict_signing_canonical_mask_generation_step::<MlDsa65>(
                    &config,
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
            assert!(mask_round < 256, "fused strict masks did not converge");
        }
        let inventories = adapter
            .finish_strict_signing_canonical_mask_batch_generation::<MlDsa65>(
                &config,
                fused_masks,
                &members,
            )
            .expect("split fused strict masks");
        batch
            .install_fused_strict_mask_inventories(inventories)
            .expect("install fused strict masks");

        let token_log_path = test_store_path("fused-private-batch-driver-token-log");
        let mut token_log =
            FilePreprocessingReleaseTokenBatchLog::open(&token_log_path).expect("token log");
        let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let outputs = batch
            .finish_fused_private_and_append_token_log(&mut adapter, &mut token_log)
            .expect("finish fused private scheduler");
        let tokens = outputs
            .into_iter()
            .map(|(token, _)| token)
            .collect::<Vec<_>>();
        token_log
            .replay_for_release(&tokens)
            .expect("fused scheduler token log replays");
        assert_eq!(tokens.len(), 2);
        assert!(tokens.iter().all(|token| token.is_release_certified()));

        let counters = PreprocessingTokenBatchFillReport::from_certified_tokens(2, &tokens);
        assert_eq!(counters.attempted_tokens, 2);
        assert_eq!(counters.certified_tokens, 2);
        let profile = runtime.runtime_phase_profile().expect("phase profile");
        assert!(profile.iter().any(|entry| {
            entry.kind == PrimeFieldMpcRoundKind::MulDegreeReduce
                && entry.phase == PrimeFieldMpcPhase::PreprocessingCarryCompare
                && entry.vector_lanes >= (2 * MlDsa65::K * MlDsa65::N) as u64
        }));
        assert!(profile.iter().any(|entry| {
            entry.kind == PrimeFieldMpcRoundKind::RandomBit
                && entry.phase == PrimeFieldMpcPhase::RandomBitShare
                && entry.vector_lanes >= 2 * 23 * (MlDsa65::L + MlDsa65::K) as u64 * 256
        }));
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    fn run_best_shape_preprocessing_report<P: MlDsaParams>(
        base: u8,
    ) -> PreprocessingBestShapePerformanceReport {
        let (config, mut runtime) = latest_round_vector_runtime_one_party::<P>(u64::from(base));
        let rho = [base; 32];
        let signer_set = config.parties.clone();
        let mut drivers = Vec::new();
        let mut timings = Vec::new();

        let setup_started = std::time::Instant::now();
        for offset in 0..2u8 {
            let session_id = session(base.wrapping_add(offset));
            let nonce_share = DistributedNonceShare {
                party: PartyId(1),
                y_share: PolyVec::new(vec![Poly::from_coeffs([0; 256]); P::L]),
                nonce_commitment: NonceCommitment([base.wrapping_add(offset); 32]),
                randomness_commitment: Commitment([base.wrapping_add(16).wrapping_add(offset); 32]),
            };
            let input = party_preprocess_input_from_distributed_nonce_share::<P>(
                session_id,
                &signer_set,
                &rho,
                &nonce_share,
            )
            .expect("nonce-backed input");
            let options = PreprocessingSessionOptions {
                session_id,
                signer_set: signer_set.clone(),
                keygen_transcript_hash: config.transcript_hash().0,
            };
            let mut sessions = vec![PreprocessingSession::<P, _, _>::start(
                options,
                input,
                SessionRegistry::new(),
                ProductMaskedBroadcastConsistencyVerifier,
            )
            .expect("start preprocessing")];
            route_preprocessing_broadcasts(&mut sessions);
            let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
            drivers.push(
                sessions
                    .remove(0)
                    .into_release_driver(
                        config.clone(),
                        rho,
                        nonce_share,
                        &mut adapter,
                        PreprocessingReleaseSessionCursorMemoryStore::new(),
                    )
                    .expect("release driver"),
            );
        }
        timings.push(PreprocessingBestShapePhaseTiming {
            phase: "setup",
            elapsed_ms: setup_started.elapsed().as_millis(),
        });

        let mut batch = PreprocessingReleaseBatchDriver::new(drivers).expect("batch driver");
        {
            let adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
            batch
                .start_fused_private_runtime(&adapter)
                .expect("start fused private scheduler");
        }

        let private_started = std::time::Instant::now();
        let mut round = 0u64;
        while batch
            .phases()
            .iter()
            .any(|phase| *phase == PreprocessingReleaseDriverPhase::PrivateRuntime)
        {
            let mut entropy = TestProductionVectorEntropy {
                next: 900_000 + u64::from(base) * 10_000 + round * 1_000,
            };
            let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
            batch
                .drive_fused_private_runtime_step::<_, _, _, _>(&mut adapter, &mut entropy)
                .expect("drive fused private scheduler");
            let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
            match batch
                .collect_fused_private_runtime_step::<_, _, _>(&mut adapter)
                .expect("collect fused private scheduler")
            {
                ProductionVectorItMpcCollectResult::Collected { .. } => {}
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    panic!("fused private scheduler did not complete: {status:?}")
                }
            }
            round = round.saturating_add(1);
            assert!(round < 256, "fused private scheduler did not converge");
        }
        timings.push(PreprocessingBestShapePhaseTiming {
            phase: "fused_private_carry_cef_bcc",
            elapsed_ms: private_started.elapsed().as_millis(),
        });

        let members = batch.strict_mask_batch_members();
        let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let mask_started = std::time::Instant::now();
        let mut fused_masks = adapter
            .start_strict_signing_canonical_mask_batch_generation(&members)
            .expect("start fused strict masks");
        let mut mask_round = 0u64;
        while !fused_masks.is_done() {
            let mut entropy = TestProductionVectorEntropy {
                next: 1_000_000 + u64::from(base) * 10_000 + mask_round * 1_000,
            };
            adapter
                .drive_strict_signing_canonical_mask_generation_step::<P, _>(
                    &config,
                    &mut fused_masks,
                    &mut entropy,
                )
                .expect("drive fused strict masks");
            match adapter
                .collect_strict_signing_canonical_mask_generation_step::<P>(
                    &config,
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
            assert!(mask_round < 256, "fused strict masks did not converge");
        }
        let inventories = adapter
            .finish_strict_signing_canonical_mask_batch_generation::<P>(
                &config,
                fused_masks,
                &members,
            )
            .expect("split fused strict masks");
        batch
            .install_fused_strict_mask_inventories(inventories)
            .expect("install fused strict masks");
        timings.push(PreprocessingBestShapePhaseTiming {
            phase: "fused_strict_masks",
            elapsed_ms: mask_started.elapsed().as_millis(),
        });

        let finish_started = std::time::Instant::now();
        let token_log_path = test_store_path(&format!(
            "best-shape-preprocessing-{}",
            P::NAME.replace('/', "_")
        ));
        let mut token_log =
            FilePreprocessingReleaseTokenBatchLog::open(&token_log_path).expect("token log");
        let mut adapter = ProductionPreprocessingCertificationRuntime::new(&mut runtime);
        let outputs = batch
            .finish_fused_private_and_append_token_log(&mut adapter, &mut token_log)
            .expect("finish fused private scheduler");
        let tokens = outputs
            .into_iter()
            .map(|(token, _)| token)
            .collect::<Vec<_>>();
        token_log
            .replay_for_release(&tokens)
            .expect("token log replays");
        timings.push(PreprocessingBestShapePhaseTiming {
            phase: "certificate_and_log",
            elapsed_ms: finish_started.elapsed().as_millis(),
        });

        let fill_report = PreprocessingTokenBatchFillReport::from_certified_tokens(2, &tokens);
        let phase_profile = runtime.runtime_phase_profile().expect("phase profile");
        preprocessing_best_shape_performance_report::<P>(fill_report, timings, &phase_profile, 8)
            .expect("best-shape report")
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    #[ignore = "best-shape release report; run with --release --ignored --nocapture"]
    fn best_shape_preprocessing_report_mldsa44_release_mode() {
        let report = run_best_shape_preprocessing_report::<MlDsa44>(189);
        eprintln!("ML-DSA-44 best-shape preprocessing report:\n{report:#?}");
        assert_eq!(report.suite, MlDsa44::NAME);
        assert_eq!(report.attempted_tokens, 2);
        assert_eq!(report.certified_tokens, 2);
        assert!(report.chunk_policy_ok);
        assert!(report.no_scalarized_release_profile);
        assert!(!report.top_durable_log_phases.is_empty());
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    #[ignore = "best-shape release report; run with --release --ignored --nocapture"]
    fn best_shape_preprocessing_report_mldsa65_release_mode() {
        let report = run_best_shape_preprocessing_report::<MlDsa65>(191);
        eprintln!("ML-DSA-65 best-shape preprocessing report:\n{report:#?}");
        assert_eq!(report.suite, MlDsa65::NAME);
        assert_eq!(report.attempted_tokens, 2);
        assert_eq!(report.certified_tokens, 2);
        assert!(report.chunk_policy_ok);
        assert!(report.no_scalarized_release_profile);
        assert!(!report.top_durable_log_phases.is_empty());
    }

    #[cfg(all(feature = "production-release-checks", feature = "std"))]
    #[test]
    #[ignore = "best-shape release report; run with --release --ignored --nocapture"]
    fn best_shape_preprocessing_report_mldsa87_release_mode() {
        let report = run_best_shape_preprocessing_report::<MlDsa87>(193);
        eprintln!("ML-DSA-87 best-shape preprocessing report:\n{report:#?}");
        assert_eq!(report.suite, MlDsa87::NAME);
        assert_eq!(report.attempted_tokens, 2);
        assert_eq!(report.certified_tokens, 2);
        assert!(report.chunk_policy_ok);
        assert!(report.no_scalarized_release_profile);
        assert!(!report.top_durable_log_phases.is_empty());
    }

    #[cfg(feature = "scaffold-dev")]
    #[test]
    fn all_party_runtime_driven_preprocessing_builds_release_tokens() {
        let config = talus_dkg::DkgConfig::new::<MlDsa65>(
            2,
            vec![PartyId(1), PartyId(2), PartyId(3)],
            talus_dkg::KeygenEpoch(103),
        )
        .expect("dkg config");
        let rho = [0x77; 32];
        let signer_set = config.parties.clone();
        let mut accepted = None;

        for attempt in 0..24u8 {
            let session_id = session(103u8.wrapping_add(attempt));
            let nonce =
                generate_distributed_nonce_shares::<MlDsa65>(DistributedNonceGenerationOptions {
                    session_id,
                    dkg_config: config.clone(),
                    rho,
                    nonce_entropy: [0x71u8.wrapping_add(attempt); 32],
                    it_vss_entropy: [0x91u8.wrapping_add(attempt); 32],
                    it_vss_security: talus_dkg::ProductionItVssSecurityParams {
                        audit_tags: 1,
                        retained_tags: 1,
                        consistency_rounds: 1,
                        max_vector_lanes_per_chunk: 32_000,
                        max_private_delivery_bytes: 16 * 1024 * 1024,
                    },
                })
                .expect("distributed nonce generation");
            match runtime_release_tokens_for_nonce_shares(
                &config,
                session_id,
                &rho,
                nonce.shares.clone(),
            ) {
                Ok((tokens, _, _, _)) => {
                    accepted = Some((session_id, nonce, tokens));
                    break;
                }
                Err(err) if err.is_retryable_pre_challenge() => continue,
                Err(err) => panic!("unexpected runtime-driven preprocessing error: {err:?}"),
            }
        }

        let (session_id, nonce, tokens) =
            accepted.expect("BCC-cleared nonce preprocessing release token");
        assert_eq!(nonce.shares.len(), signer_set.len());

        for token in &tokens {
            assert_eq!(token.w1, tokens[0].w1);
            assert_eq!(token.signer_set, signer_set);
            assert_eq!(token.broadcasts.len(), signer_set.len());
            assert!(token.vector_runtime_certificate().is_some());
            assert_eq!(token.session_id, session_id);
            assert!(token.y_share.is_empty());
        }
    }

    #[cfg(feature = "scaffold-dev")]
    #[test]
    fn runtime_release_preprocessing_rejects_replayed_masked_broadcast() {
        let session_id = session(136);
        let inputs = vec![
            input(1, &[1, 2], &[3, 4]),
            input(2, &[5, 6], &[7, 8]),
            input(3, &[9, 10], &[11, 12]),
        ];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let config = talus_dkg::DkgConfig::new::<MlDsa65>(
            2,
            signer_set.clone(),
            talus_dkg::KeygenEpoch(136),
        )
        .expect("dkg config");
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let mut envelopes = inputs
            .iter()
            .map(|input| {
                prepare_masked_broadcast_envelope::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                )
                .expect("envelope")
            })
            .collect::<Vec<_>>();
        envelopes[1] = envelopes[0].clone();

        let err = runtime_release_tokens_from_envelopes(
            &config, session_id, inputs, envelopes, transcript,
        )
        .expect_err("replayed masked broadcast rejects");
        assert!(matches!(
            err,
            PreprocessError::MaskedBroadcastConsistencyMismatch(_)
                | PreprocessError::PreprocessingRuntimeCertificateMismatch
        ));
    }

    #[cfg(feature = "scaffold-dev")]
    #[test]
    fn runtime_release_preprocessing_rejects_wrong_transcript_and_signer_set() {
        let session_id = session(137);
        let inputs = vec![
            input(1, &[1, 2], &[3, 4]),
            input(2, &[5, 6], &[7, 8]),
            input(3, &[9, 10], &[11, 12]),
        ];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let config = talus_dkg::DkgConfig::new::<MlDsa65>(
            2,
            signer_set.clone(),
            talus_dkg::KeygenEpoch(137),
        )
        .expect("dkg config");
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let envelopes = inputs
            .iter()
            .map(|input| {
                prepare_masked_broadcast_envelope::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                )
                .expect("envelope")
            })
            .collect::<Vec<_>>();
        let wrong_transcript = TranscriptHash([0x44; 32]);
        let err = runtime_release_tokens_from_envelopes(
            &config,
            session_id,
            inputs.clone(),
            envelopes.clone(),
            wrong_transcript,
        )
        .expect_err("wrong transcript rejects");
        assert!(matches!(
            err,
            PreprocessError::TranscriptMismatch(_)
                | PreprocessError::MaskedBroadcastConsistencyMismatch(_)
                | PreprocessError::PreprocessingRuntimeCertificateMismatch
        ));

        let wrong_signer_set = vec![PartyId(1), PartyId(2)];
        let wrong_envelopes = inputs
            .iter()
            .map(|input| {
                prepare_masked_broadcast_envelope::<MlDsa65>(
                    session_id,
                    &wrong_signer_set,
                    input,
                    transcript,
                )
            })
            .collect::<Result<Vec<_>, _>>();
        assert!(wrong_envelopes.is_err());
    }

    #[cfg(feature = "scaffold-dev")]
    #[test]
    fn release_preprocessing_inventory_blocks_reused_nonce_token_after_restart() {
        let session_id = session(138);
        let inputs = vec![
            input(1, &[1, 2], &[3, 4]),
            input(2, &[5, 6], &[7, 8]),
            input(3, &[9, 10], &[11, 12]),
        ];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let config =
            talus_dkg::DkgConfig::new::<MlDsa65>(2, signer_set, talus_dkg::KeygenEpoch(138))
                .expect("dkg config");
        let (mut tokens, _, _) =
            runtime_release_tokens_for_inputs(&config, session_id, inputs).expect("release tokens");
        let token = tokens.remove(0);

        let mut pool = TokenPool::new();
        let mut inventory = TokenInventory::new();
        pool.insert_release_certified_with_inventory(token, &mut inventory)
            .expect("insert release token");
        assert_eq!(inventory.state(session_id), TokenInventoryState::Reserved);

        let duplicate = tokens.remove(0);
        assert_eq!(
            pool.insert_release_certified_with_inventory(duplicate, &mut inventory),
            Err(TokenPoolError::InvalidInventoryTransition {
                session_id,
                from: TokenInventoryState::Reserved,
                to: TokenInventoryState::Reserved,
            })
        );
    }

    #[cfg(all(feature = "std", feature = "scaffold-dev"))]
    #[test]
    fn file_inventory_blocks_release_token_reuse_across_restart() {
        let session_id = session(139);
        let inputs = vec![
            input(1, &[1, 2], &[3, 4]),
            input(2, &[5, 6], &[7, 8]),
            input(3, &[9, 10], &[11, 12]),
        ];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let config =
            talus_dkg::DkgConfig::new::<MlDsa65>(2, signer_set, talus_dkg::KeygenEpoch(139))
                .expect("dkg config");
        let (mut tokens, _, _) =
            runtime_release_tokens_for_inputs(&config, session_id, inputs).expect("release tokens");
        let token = tokens.remove(0);
        let duplicate = tokens.remove(0);
        let path = std::env::temp_dir().join(format!(
            "talus-mpc-preprocessing-token-inventory-{}-{}.log",
            std::process::id(),
            Hex32(session_id.0)
        ));
        let _ = std::fs::remove_file(&path);

        {
            let inventory = FileTokenInventory::open(&path).expect("open empty inventory");
            assert_eq!(inventory.state(session_id), TokenInventoryState::Fresh);
        }
        {
            let mut pool = TokenPool::new();
            let mut inventory = FileTokenInventory::open(&path).expect("reopen before insert");
            pool.insert_release_certified_with_inventory(token, &mut inventory)
                .expect("insert release token");
            assert_eq!(inventory.state(session_id), TokenInventoryState::Reserved);
        }
        {
            let mut pool = TokenPool::new();
            let mut inventory = FileTokenInventory::open(&path).expect("reopen after insert");
            assert_eq!(inventory.state(session_id), TokenInventoryState::Reserved);
            assert_eq!(
                pool.insert_release_certified_with_inventory(duplicate, &mut inventory),
                Err(TokenPoolError::InvalidInventoryTransition {
                    session_id,
                    from: TokenInventoryState::Reserved,
                    to: TokenInventoryState::Reserved,
                })
            );
            inventory
                .consume(session_id)
                .expect("consume reserved token");
        }
        {
            let inventory = FileTokenInventory::open(&path).expect("reopen consumed inventory");
            assert_eq!(inventory.state(session_id), TokenInventoryState::Consumed);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn release_token_with_runtime_boundary_rejects_missing_strict_material() {
        let session_id = session(73);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let envelopes = inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| {
                prepare_masked_broadcast_envelope_with_runtime_transcript::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    [0xc0u8.wrapping_add(idx as u8); 32],
                )
                .expect("runtime envelope")
            })
            .collect::<Vec<_>>();

        let mut preview_registry = SessionRegistry::new();
        let mut preview_verifier = ProductMaskedBroadcastConsistencyVerifier;
        let preview = certify_opened_masked_broadcasts_with_consistency::<MlDsa65, _>(
            &mut preview_verifier,
            &mut preview_registry,
            session_id,
            inputs.clone(),
            envelopes.clone(),
            transcript,
            None,
        )
        .expect("preview token certifies");
        let runtime_proofs = runtime_proofs_from_envelopes_and_preview::<MlDsa65>(
            session_id,
            transcript,
            signer_set.len(),
            inputs[0].highs.len(),
            &envelopes,
            &preview,
        );
        let mut evidence = release_vector_runtime_evidence();
        evidence.transcript_hash = preprocessing_runtime_transcript_aggregate_hash(
            session_id,
            transcript,
            runtime_proofs
                .transcripts()
                .expect("runtime proof transcripts"),
        )
        .expect("aggregate preprocessing runtime transcript");

        let mut registry = SessionRegistry::new();
        let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
        let err = certify_preprocessing_token_release_validated_from_envelopes::<MlDsa65, _>(
            &mut verifier,
            &mut registry,
            session_id,
            inputs,
            envelopes,
            transcript,
            runtime_proofs,
            evidence,
        )
        .expect_err("release token without strict material is rejected");
        assert_eq!(err, PreprocessError::PreprocessingRuntimeMaterialMissing);
    }

    #[test]
    fn release_token_with_runtime_boundary_rejects_wrong_stage_statement() {
        let session_id = session(74);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let envelopes = inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| {
                prepare_masked_broadcast_envelope_with_runtime_transcript::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    [0xd0u8.wrapping_add(idx as u8); 32],
                )
                .expect("runtime envelope")
            })
            .collect::<Vec<_>>();

        let statement = preprocessing_certification_runtime_statement_from_envelopes::<MlDsa65>(
            session_id,
            inputs.clone(),
            envelopes.clone(),
            transcript,
        )
        .expect("runtime statement");
        let mut wrong_carry_hash = statement.carry_compare_evidence_hash;
        wrong_carry_hash[0] ^= 0x7a;
        let carry_runtime_transcript = [0xe1; 32];
        let bcc_runtime_transcript = [0xe2; 32];
        let runtime_proofs = PreprocessingCertificationRuntimeProofs {
            masked_broadcast: statement.masked_broadcast_runtime_transcript,
            carry_compare: preprocessing_certification_stage_runtime_proof::<MlDsa65>(
                PreprocessingCertificationStage::CarryCompare,
                statement.session_id,
                statement.transcript_hash,
                statement.signer_set.len(),
                statement.coeff_count,
                wrong_carry_hash,
                carry_runtime_transcript,
            )
            .expect("wrong carry runtime proof"),
            bcc: preprocessing_certification_stage_runtime_proof::<MlDsa65>(
                PreprocessingCertificationStage::Bcc,
                statement.session_id,
                statement.transcript_hash,
                statement.signer_set.len(),
                statement.coeff_count,
                statement.bcc_evidence_hash,
                bcc_runtime_transcript,
            )
            .expect("bcc runtime proof"),
            outputs: PreprocessingCertificationRuntimeOutputs {
                masked_broadcast: RuntimeMaskedBroadcastOutput {
                    signer_count: statement.signer_set.len(),
                    coeff_count: statement.coeff_count,
                    runtime_transcript_hash: statement.masked_broadcast_runtime_transcript,
                    material_state_hash: [0xa7; 32],
                },
                carry_compare: RuntimeCarryCompareOutput {
                    coeff_count: statement.coeff_count,
                    evidence_hash: wrong_carry_hash,
                    runtime_transcript_hash: carry_runtime_transcript,
                },
                cef_bcc: RuntimeCefBccOutput {
                    coeff_count: statement.coeff_count,
                    w1_hash: statement.w1_hash,
                    carry_compare_evidence_hash: wrong_carry_hash,
                    bcc_evidence_hash: statement.bcc_evidence_hash,
                    runtime_transcript_hash: bcc_runtime_transcript,
                    token_admitted: true,
                },
            },
        };
        let mut evidence = release_vector_runtime_evidence();
        evidence.transcript_hash = preprocessing_runtime_transcript_aggregate_hash(
            statement.session_id,
            statement.transcript_hash,
            runtime_proofs
                .transcripts()
                .expect("runtime proof transcripts"),
        )
        .expect("aggregate preprocessing runtime transcript");

        let mut registry = SessionRegistry::new();
        let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
        let err = certify_preprocessing_token_release_validated_from_envelopes::<MlDsa65, _>(
            &mut verifier,
            &mut registry,
            session_id,
            inputs,
            envelopes,
            transcript,
            runtime_proofs,
            evidence,
        )
        .expect_err("wrong CarryCompare statement proof rejects");

        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
    }

    fn release_token_with_mutated_runtime_outputs(
        name: &'static str,
        mutate: impl FnOnce(&mut PreprocessingCertificationRuntimeProofs),
    ) -> PreprocessError {
        let session_id = session(83);
        let inputs = vec![input(1, &[1, 2], &[3, 4]), input(2, &[5, 6], &[7, 8])];
        let signer_set = inputs.iter().map(|input| input.party).collect::<Vec<_>>();
        let transcript = transcript_hash::<MlDsa65>(session_id, &inputs);
        let envelopes = inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| {
                prepare_masked_broadcast_envelope_with_runtime_transcript::<MlDsa65>(
                    session_id,
                    &signer_set,
                    input,
                    transcript,
                    [0xe0u8.wrapping_add(idx as u8); 32],
                )
                .expect("runtime envelope")
            })
            .collect::<Vec<_>>();
        let mut preview_registry = SessionRegistry::new();
        let mut preview_verifier = ProductMaskedBroadcastConsistencyVerifier;
        let preview = certify_opened_masked_broadcasts_with_consistency::<MlDsa65, _>(
            &mut preview_verifier,
            &mut preview_registry,
            session_id,
            inputs.clone(),
            envelopes.clone(),
            transcript,
            None,
        )
        .expect("preview token certifies");
        let mut runtime_proofs = runtime_proofs_from_envelopes_and_preview::<MlDsa65>(
            session_id,
            transcript,
            signer_set.len(),
            inputs[0].highs.len(),
            &envelopes,
            &preview,
        );
        mutate(&mut runtime_proofs);
        let mut evidence = release_vector_runtime_evidence();
        evidence.transcript_hash = preprocessing_runtime_transcript_aggregate_hash(
            session_id,
            transcript,
            runtime_proofs
                .transcripts()
                .expect("runtime proof transcripts"),
        )
        .expect("aggregate preprocessing runtime transcript");

        let mut registry = SessionRegistry::new();
        let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
        let err = certify_preprocessing_token_release_validated_from_envelopes::<MlDsa65, _>(
            &mut verifier,
            &mut registry,
            session_id,
            inputs,
            envelopes,
            transcript,
            runtime_proofs,
            evidence,
        )
        .expect_err(name);
        err
    }

    #[test]
    fn release_token_rejects_forged_runtime_owned_cef_bcc_output() {
        let err = release_token_with_mutated_runtime_outputs(
            "forged runtime-owned w1 output rejects",
            |runtime_proofs| {
                runtime_proofs.outputs.cef_bcc.w1_hash[0] ^= 0x5a;
            },
        );
        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
    }

    #[test]
    fn release_token_rejects_forged_runtime_owned_carry_output() {
        let err = release_token_with_mutated_runtime_outputs(
            "forged runtime-owned CarryCompare output rejects",
            |runtime_proofs| {
                runtime_proofs.outputs.carry_compare.evidence_hash[0] ^= 0x33;
            },
        );
        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
    }

    #[test]
    fn release_token_rejects_runtime_output_transcript_mismatch() {
        let err = release_token_with_mutated_runtime_outputs(
            "runtime output transcript mismatch rejects",
            |runtime_proofs| {
                runtime_proofs.outputs.cef_bcc.runtime_transcript_hash[0] ^= 0x44;
            },
        );
        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
    }

    #[test]
    fn release_token_rejects_forged_runtime_owned_masked_broadcast_output() {
        let err = release_token_with_mutated_runtime_outputs(
            "forged runtime-owned masked-broadcast output rejects",
            |runtime_proofs| {
                runtime_proofs.outputs.masked_broadcast.signer_count += 1;
            },
        );
        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
    }

    #[test]
    fn release_token_rejects_runtime_output_token_not_admitted() {
        let err = release_token_with_mutated_runtime_outputs(
            "runtime output token admission false rejects",
            |runtime_proofs| {
                runtime_proofs.outputs.cef_bcc.token_admitted = false;
            },
        );
        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
    }

    #[test]
    fn release_token_rejects_forged_cef_correction_output() {
        let err = release_token_with_mutated_runtime_outputs(
            "forged CEF correction transcript rejects",
            |runtime_proofs| {
                runtime_proofs.outputs.cef_bcc.runtime_transcript_hash[1] ^= 0xa5;
            },
        );
        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
    }

    #[test]
    fn release_token_rejects_forged_bcc_admission_output() {
        let err = release_token_with_mutated_runtime_outputs(
            "forged BCC admission rejects",
            |runtime_proofs| {
                runtime_proofs.outputs.cef_bcc.token_admitted = false;
            },
        );
        assert_eq!(
            err,
            PreprocessError::PreprocessingRuntimeCertificateMismatch
        );
    }

    #[test]
    fn post_challenge_reveal_policy_is_required_for_token_admission() {
        let mut registry = SessionRegistry::new();
        let mut token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(62),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("valid preprocessing certifies");

        token.certification_evidence.nonce_reveal_policy = Some(NonceRevealPolicyEvidence {
            session_id: token.session_id,
            post_challenge_reveal_disabled: false,
            evidence_hash: [0x91; 32],
        });
        token.certification_policy = token.certification_evidence.policy();

        assert!(!token.is_certified());
        assert_eq!(
            ensure_pre_challenge_certification_evidence(
                token.session_id,
                &token.certification_evidence
            ),
            Err(PreprocessError::PreChallengeCertificationIncomplete)
        );
        let mut pool = TokenPool::new();
        assert_eq!(
            pool.insert_certified(token),
            Err(TokenPoolError::NotCertified(session(62)))
        );
    }

    #[test]
    fn debug_redacts_preprocessing_secret_material() {
        let preprocess_input = PartyPreprocessInput {
            party: PartyId(9),
            highs: vec![1, 2],
            lows: vec![3, 4],
            y_share: vec![0xaa, 0xbb, 0xcc],
            ay_contribution: Some(PolyVec::zero(MlDsa65::K)),
            nonce_commitment: NonceCommitment([0; 32]),
            randomness_commitment: Commitment([1; 32]),
        };
        let input_debug = format!("{preprocess_input:?}");
        assert!(input_debug.contains("y_share: \"<redacted>\""));
        assert!(!input_debug.contains("170"));
        assert!(!input_debug.contains("187"));
        assert!(!input_debug.contains("204"));

        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(30),
            vec![input(1, &[1], &[3]), input(2, &[5], &[7])],
        )
        .expect("valid preprocessing certifies");
        let token_debug = format!("{token:?}");
        assert!(token_debug.contains("y_share: \"<redacted>\""));
        assert!(!token_debug.contains("y_share: ["));
    }
}
