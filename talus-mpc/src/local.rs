#![doc = "Internal implementation for production-facing TALUS preprocessing APIs."]

use core::fmt;
use core::marker::PhantomData;

use sha3::{Digest, Sha3_256};
use talus_core::{
    az_from_rho, bcc_holds_coeff, high_bits_unsigned, lagrange_coefficients_at_zero,
    low_bits_unsigned, reduce_mod_q, Coeff, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Poly, PolyVec,
    TalusPerformanceCounters,
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
    ProductionItVssSecurityParams, ProductionPublicComparisonVecState,
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
        ay_contribution: None,
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
    let certificate = token
        .vector_runtime_certificate
        .as_ref()
        .ok_or(PreprocessError::PreprocessingRuntimeCertificateMissing)?;
    ensure_preprocessing_vector_runtime_evidence_for_release(&certificate.runtime_evidence)?;
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
    let mut carry_labels = Vec::with_capacity(carry_width.saturating_mul(3));
    for bit_idx in 0..carry_width {
        for step in ["candidate", "comparison_update", "eq_update"] {
            carry_labels.push(
                carry_root
                    .child(format!("bit_{bit_idx}/{step}"))
                    .child("bit_and")
                    .child("mul_layer"),
            );
        }
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
                .child("sum_gt_threshold/bit_0/candidate")
                .child("bit_and")
                .child("mul_layer"),
            cef_root
                .child("sum_gt_threshold/bit_0/comparison_update")
                .child("bit_and")
                .child("mul_layer"),
            cef_root
                .child("sum_gt_threshold/bit_0/eq_update")
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
    if value.len() != 64 {
        return None;
    }

    let mut bytes = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Some(SessionId(bytes))
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

    #[cfg(feature = "scaffold-dev")]
    #[derive(Clone, Debug, Default)]
    struct TestProductionVectorEntropy {
        next: u64,
    }

    #[cfg(feature = "scaffold-dev")]
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

    fn route_preprocessing_broadcasts<V>(
        sessions: &mut [PreprocessingSession<MlDsa65, SessionRegistry, V>],
    ) where
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
        let mut evidence = release_vector_runtime_evidence();
        evidence.transcript_hash = token
            .certification_evidence
            .masked_broadcast
            .expect("masked-broadcast evidence")
            .runtime_transcript_hash;
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
    fn release_token_validation_rejects_runtime_opening_lanes_below_masked_broadcast_lanes() {
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
        let mut evidence = release_vector_runtime_evidence_for_token(&token);
        let counters = PreprocessingCertificationCounters::from_token(&token);
        evidence.counters.vector_lanes = (counters.vector_lanes
            + counters.carry_compare_lanes
            + counters.cef_correction_lanes
            + counters.bcc_lanes) as u64;
        evidence.counters.vector_opening_lanes = counters.vector_lanes as u64 - 1;
        let certificate = PreprocessingVectorRuntimeCertificate::for_token(&token, evidence)
            .expect("generic Phase 3 evidence still passes");
        let token = token.with_vector_runtime_certificate(certificate);

        assert_eq!(
            ensure_certified_token_release_valid(&token),
            Err(PreprocessError::PreprocessingCountersNotVectorized)
        );
        assert!(!token.is_release_certified());
    }

    #[test]
    fn release_token_constructor_attaches_runtime_certificate_to_pool_output() {
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
        let token = certify_preprocessing_token_release_validated::<MlDsa65>(
            &mut registry,
            session(66),
            inputs,
            evidence,
        )
        .expect("release token certifies");

        assert!(token.vector_runtime_certificate().is_some());
        assert!(token.is_release_certified());
        assert_eq!(ensure_certified_token_release_valid(&token), Ok(()));

        let mut pool = TokenPool::new();
        let mut inventory = TokenInventory::new();
        pool.insert_release_certified_with_inventory(token, &mut inventory)
            .expect("release token enters release pool");
        assert_eq!(inventory.state(session(66)), TokenInventoryState::Reserved);
    }

    #[test]
    fn release_token_from_runtime_envelopes_attaches_certificate() {
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
        let token = certify_preprocessing_token_release_validated_from_envelopes::<MlDsa65, _>(
            &mut verifier,
            &mut registry,
            session_id,
            inputs,
            envelopes,
            transcript,
            runtime_proofs,
            evidence,
        )
        .expect("release token from envelopes certifies");

        assert!(token.is_release_certified());
        assert!(token.vector_runtime_certificate().is_some());
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

        let mut tokens = Vec::new();
        for (idx, runtime) in runtimes.iter_mut().enumerate() {
            let mut adapter = ProductionPreprocessingCertificationRuntime::new(runtime);
            let mut registry = SessionRegistry::new();
            let mut verifier = ProductMaskedBroadcastConsistencyVerifier;
            let token =
                certify_preprocessing_token_release_validated_with_finished_runtime_driver::<
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
                    &mut adapter,
                    &states[idx],
                )
                .map_err(|err| err)?;
            assert!(token.is_release_certified());
            tokens.push(token);
        }

        Ok((tokens, envelopes, transcript))
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
            let inputs = nonce
                .shares
                .iter()
                .map(|share| {
                    party_preprocess_input_from_distributed_nonce_share::<MlDsa65>(
                        session_id,
                        &signer_set,
                        &rho,
                        share,
                    )
                    .expect("nonce-backed preprocessing input")
                })
                .collect::<Vec<_>>();
            match runtime_release_tokens_for_inputs(&config, session_id, inputs) {
                Ok((tokens, _, _)) => {
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
    fn release_token_with_runtime_boundary_attaches_certificate() {
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
        let token = certify_preprocessing_token_release_validated_from_envelopes::<MlDsa65, _>(
            &mut verifier,
            &mut registry,
            session_id,
            inputs,
            envelopes,
            transcript,
            runtime_proofs,
            evidence,
        )
        .expect("release token certifies through internal runtime boundary");

        assert!(token.is_release_certified());
        assert!(token.vector_runtime_certificate().is_some());
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
