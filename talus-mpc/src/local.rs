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
    ensure_production_vector_it_mpc_runtime_evidence_for_release, evaluate_shamir_polynomial,
    hash_it_vss_complaint_resolution, hash_it_vss_public_commitment,
    production_it_vss_public_coin_share, production_it_vss_public_coin_transcript, DkgConfig,
    DkgError, ItVssComplaintResolution, ItVssPrivateShareDelivery, ItVssPublicCommitment,
    ItVssPublicPrecommitment, ItVssSharingDomain, ItVssSharingLabel,
    ProductionInformationCheckingVssBackend, ProductionItVssBackend,
    ProductionItVssPreparedDealerOutput, ProductionItVssPublicCoinShare,
    ProductionItVssSecurityParams, ProductionVectorItMpcRuntimeEvidence,
};
use talus_mpc_core::PartyId;
use talus_wire::{
    decode_commit_payload, decode_masked_broadcast_open_payload, encode_commit_payload,
    encode_masked_broadcast_open_payload, signing_set_hash, validate_round_batch, CommitPayload,
    ExpectedContext, MaskedBroadcastOpenPayload, PayloadKind, RoundId, SuiteId, WireHeader,
    WireMessage, WIRE_PROTOCOL_VERSION,
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
    /// Backend-specific proof bytes. Empty is valid only for local clear-audit tests.
    pub bytes: Vec<u8>,
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
    pub runtime_evidence: ProductionVectorItMpcRuntimeEvidence,
}

impl PreprocessingVectorRuntimeCertificate {
    /// Builds a preprocessing runtime certificate after applying the full Phase
    /// 3 vector-runtime release gate.
    pub fn new(
        runtime_evidence: ProductionVectorItMpcRuntimeEvidence,
    ) -> Result<Self, PreprocessError> {
        ensure_production_vector_it_mpc_runtime_evidence_for_release(&runtime_evidence)
            .map_err(|_| PreprocessError::PreprocessingCountersNotVectorized)?;
        Ok(Self { runtime_evidence })
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

    /// Returns whether this token has passed preprocessing certification.
    pub fn is_certified(&self) -> bool {
        self.certification_policy == self.certification_evidence.policy()
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
            && (!cfg!(feature = "production-release-checks")
                || self.vector_runtime_certificate.is_some())
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

    /// Reserves inventory state and inserts a certified token.
    pub fn insert_certified_with_inventory(
        &mut self,
        token: CertifiedToken,
        inventory: &mut impl TokenInventoryStore,
    ) -> Result<(), TokenPoolError> {
        inventory.reserve(token.session_id)?;
        self.insert_certified(token)
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
    }

    let cef_output = certify_vector_carry_compare_and_cef::<P>(
        session_id,
        expected_transcript,
        &signer_set,
        &inputs,
        &broadcasts,
        &rhos_by_party,
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
    );
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
    if proof.bytes != production_masked_broadcast_consistency_proof::<P>(statement).bytes {
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
    Ok(CertifiedCefOutput {
        w1,
        carry_compare: CarryCompareCertificationEvidence {
            session_id,
            coeff_count,
            evidence_hash: carry_hash,
        },
        bcc: BccCertificationEvidence {
            session_id,
            coeff_count,
            evidence_hash: bcc_hash,
        },
    })
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

fn reduce_mod_q_i64<P: MlDsaParams>(value: i64) -> Coeff {
    value.rem_euclid(i64::from(P::Q)) as Coeff
}

fn production_masked_broadcast_consistency_proof<P: MlDsaParams>(
    statement: &MaskedBroadcastConsistencyStatement,
) -> MaskedBroadcastConsistencyProof {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS masked broadcast private consistency certificate v1");
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
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = Vec::with_capacity(6 + 32);
    bytes.extend_from_slice(b"TMBCC1");
    bytes.extend_from_slice(&digest);
    MaskedBroadcastConsistencyProof { bytes }
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
                vector_lanes: 128,
                multiplication_layers: 4,
                vector_mul_lanes: 64,
                vector_opening_lanes: 16,
                vector_assert_zero_lanes: 16,
                random_bits: 16,
                local_public_mul_lanes: 16,
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
            },
            transcript_hash: [0x5a; 32],
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
        )
        .expect_err("tampered private certificate rejects");
        assert_eq!(
            err,
            PreprocessError::MaskedBroadcastProofBackendUnavailable(PartyId(1))
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
                assert!(token.is_certified());
                pool.insert_certified_with_inventory(token, &mut inventory)
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

        let certificate =
            PreprocessingVectorRuntimeCertificate::new(release_vector_runtime_evidence())
                .expect("release vector runtime certificate");
        let token = token.with_vector_runtime_certificate(certificate.clone());
        assert_eq!(token.vector_runtime_certificate(), Some(&certificate));
        assert!(token.is_certified());
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
