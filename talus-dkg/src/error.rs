use super::*;

/// DKG validation and execution failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DkgError {
    /// Production DKG component is unavailable until the implementation
    /// readiness gate is satisfied.
    BlockedPendingReview,
    /// Party set was empty.
    EmptyPartySet,
    /// Threshold was zero or larger than the party set.
    InvalidThreshold {
        /// Configured threshold.
        threshold: u16,
        /// Number of parties.
        parties: usize,
    },
    /// Party ids must be sorted in canonical order.
    UnsortedParties,
    /// Duplicate party id.
    DuplicateParty(PartyId),
    /// Unknown ML-DSA suite id in a canonical encoding.
    UnknownSuite(u8),
    /// The deployment profile requires more parties for the threshold.
    InsufficientPartiesForThreshold {
        /// Configured threshold.
        threshold: u16,
        /// Number of parties.
        parties: usize,
        /// Required party count.
        required: usize,
    },
    /// Complaint resolution rejected too many dealer contributions.
    InsufficientAcceptedDealers {
        /// Configured threshold.
        threshold: u16,
        /// Accepted dealer count.
        accepted: usize,
    },
    /// Bounded secret vector length did not match the selected ML-DSA suite.
    InvalidBoundedSecretVectorLength {
        /// Expected coefficient count.
        expected: usize,
        /// Actual coefficient count.
        got: usize,
    },
    /// Input bounded secret coefficient exceeded `eta`.
    BoundedSecretCoefficientOutOfRange {
        /// Coefficient index.
        index: usize,
        /// Signed coefficient.
        coefficient: Coeff,
        /// Suite bound.
        bound: Coeff,
    },
    /// Combined accepted dealer contributions exceeded `eta`.
    CombinedBoundedCoefficientOutOfRange {
        /// Coefficient index.
        index: usize,
        /// Signed coefficient.
        coefficient: Coeff,
        /// Suite bound.
        bound: Coeff,
    },
    /// Field-valued secret-share coefficient was outside `[0, q)`.
    FieldShareCoefficientOutOfRange {
        /// Coefficient index.
        index: usize,
        /// Field coefficient.
        coefficient: Coeff,
        /// Exclusive upper bound.
        modulus: Coeff,
    },
    /// Small-residue sampler contribution was outside `Z_m`.
    InvalidSmallResidue {
        /// Dealer whose contribution was checked.
        dealer: PartyId,
        /// Exclusive modulus `m`.
        modulus: u8,
        /// Submitted residue.
        got: u8,
    },
    /// Small-residue sampler bit decomposition was malformed.
    InvalidSmallResidueBit {
        /// Dealer whose contribution was checked.
        dealer: PartyId,
        /// Bit index in little-endian order.
        bit_index: usize,
        /// Submitted bit value.
        bit: u8,
    },
    /// Small-residue sampler input lacked accepted VSS/MPC verification.
    UnverifiedSmallResidueInput {
        /// Dealer whose input was rejected.
        dealer: PartyId,
    },
    /// IT-VSS certificate was bound to the wrong sampler label/domain/index.
    ItVssCertificateLabelMismatch,
    /// IT-VSS complaint-resolution phases were driven out of order.
    ItVssComplaintPhaseOutOfOrder,
    /// Vector IT-VSS dispute has no public-objective blame evidence, so v1
    /// aborts without rejecting/blaming a dealer.
    ItVssAbortNoBlame,
    /// Scalar IT-VSS phases were driven out of order.
    ItVssScalarPhaseOutOfOrder,
    /// Scalar IT-VSS received a replayed phase message.
    ItVssScalarReplayDetected,
    /// Scalar IT-VSS session was already terminal.
    ItVssScalarSessionTerminal,
    /// Scalar IT-VSS reconstruction did not have enough accepted points.
    InsufficientAcceptedReconstructionPoints {
        /// Configured threshold.
        threshold: u16,
        /// Accepted point count.
        accepted: usize,
    },
    /// Scalar IT-VSS accepted points reconstruct more than one secret.
    AmbiguousScalarItVssReconstruction,
    /// Scalar IT-VSS reconstruction broadcast repeated a retained tag index.
    DuplicateScalarItVssRetainedTag {
        /// Holder whose reconstruction share was malformed.
        holder: PartyId,
        /// Receiver whose retained tag set was duplicated.
        receiver: PartyId,
        /// Duplicated retained tag index.
        tag_index: u16,
    },
    /// Scalar IT-VSS reconstruction broadcast missed retained tags for a receiver.
    MissingScalarItVssRetainedTag {
        /// Holder whose reconstruction share was malformed.
        holder: PartyId,
        /// Receiver missing retained tag material.
        receiver: PartyId,
    },
    /// IT-VSS certificate was not produced by the production information-checking backend.
    ItVssCertificateBackendMismatch,
    /// IT-VSS complaint resolution accepted and rejected the same dealer.
    ItVssResolutionDealerOverlap {
        /// Dealer present in both sets.
        dealer: PartyId,
    },
    /// IT-VSS public commitments included the same dealer/label twice.
    DuplicateItVssPublicCommitment {
        /// Dealer whose public commitment was duplicated.
        dealer: PartyId,
        /// Sharing label hash.
        label_hash: [u8; 32],
    },
    /// IT-VSS complaint-resolution certificates included the same dealer/label twice.
    DuplicateItVssCertificate {
        /// Dealer whose certificate was duplicated.
        dealer: PartyId,
        /// Sharing label hash.
        label_hash: [u8; 32],
    },
    /// IT-VSS certificate was not covered by the resolution complaint hash.
    ItVssCertificateComplaintHashMismatch,
    /// IT-VSS certificate had no matching public commitment.
    ItVssCertificateMissingCommitment {
        /// Dealer whose public commitment was missing.
        dealer: PartyId,
        /// Sharing label hash.
        label_hash: [u8; 32],
    },
    /// IT-VSS resolution accepted a dealer without a matching certificate.
    ItVssResolutionMissingCertificate {
        /// Accepted dealer missing a certificate.
        dealer: PartyId,
    },
    /// IT-VSS resolution included a certificate for a non-accepted dealer.
    ItVssResolutionUnexpectedCertificate {
        /// Dealer that was not accepted by the resolution.
        dealer: PartyId,
    },
    /// Small-residue contribution was bound to a different transcript label.
    SmallSamplerLabelMismatch,
    /// Transcript binding did not match the output.
    TranscriptMismatch {
        /// Recomputed transcript hash.
        expected: KeygenTranscriptHash,
        /// Stored transcript hash.
        got: KeygenTranscriptHash,
    },
    /// State-machine transition was attempted in the wrong phase.
    UnexpectedRound {
        /// Expected round.
        expected: DkgRound,
        /// Current state.
        got: DkgState,
    },
    /// Sender set for a round did not include exactly one message per party.
    MissingRoundMessages {
        /// DKG round being validated.
        round: DkgRound,
        /// Expected message count.
        expected: usize,
        /// Actual message count.
        got: usize,
    },
    /// Party id is not in the DKG config.
    UnknownParty(PartyId),
    /// Duplicate sender in a broadcast round.
    DuplicateRoundSender {
        /// DKG round being validated.
        round: DkgRound,
        /// Duplicated sender.
        sender: PartyId,
    },
    /// Payload nested party id did not match the envelope/sender party.
    PartyMismatch {
        /// Expected party id.
        expected: PartyId,
        /// Actual party id.
        got: PartyId,
    },
    /// A commit-round message had no VSS commitments.
    EmptyDkgCommitments(PartyId),
    /// Directed share message had an invalid receiver.
    InvalidShareReceiver {
        /// Dealer/sender party id.
        dealer: PartyId,
        /// Receiver party id.
        receiver: PartyId,
    },
    /// Duplicate directed share from the same dealer to the same receiver.
    DuplicateShare {
        /// Dealer/sender party id.
        dealer: PartyId,
        /// Receiver party id.
        receiver: PartyId,
    },
    /// Duplicate complaint for the same complainant/dealer/receiver tuple.
    DuplicateComplaint {
        /// Complainant party id.
        complainant: PartyId,
        /// Dealer party id.
        dealer: PartyId,
        /// Receiver party id.
        receiver: PartyId,
    },
    /// Finalize messages accepted different public outputs.
    FinalizeDisagreement,
    /// Complaint reason is unsupported by the selected resolver.
    UnsupportedComplaintReason(DkgComplaintReason),
    /// Complaint evidence length was not canonical.
    InvalidComplaintEvidenceLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
    /// Complaint payload fields and embedded evidence did not match.
    ComplaintEvidenceMismatch,
    /// Final public output was bound to a different DKG config.
    FinalOutputConfigMismatch,
    /// Provisioned packages did not all carry the same public output.
    ProvisionedPublicOutputDisagreement,
    /// Provisioned packages did not all bind the same ceremony transcript.
    ProvisioningTranscriptDisagreement,
    /// Provisioning ceremony transcript hash was all zero.
    EmptyProvisioningTranscript,
    /// Serialized public-key length did not match the selected suite.
    InvalidPublicKeyLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
    /// Encoded `t1` length did not match the selected suite.
    InvalidT1Length {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
    /// A prime-field MPC round attempted to reuse a message label.
    PrimeFieldMpcReplayDetected,
    /// Prime-field MPC transport validation failed without exposing raw values.
    PrimeFieldMpcTransport,
    /// Prime-field MPC expected transport context did not match the DKG config.
    PrimeFieldMpcContextMismatch,
    /// File-backed prime-field MPC round log was corrupt.
    PrimeFieldMpcRoundLogCorrupt {
        /// Corrupt line number.
        line: usize,
    },
    /// File-backed prime-field MPC wire-message log was corrupt.
    PrimeFieldMpcWireLogCorrupt {
        /// Corrupt line number.
        line: usize,
    },
    /// File-backed prime-field MPC phase-cursor log was corrupt.
    PrimeFieldMpcPhaseCursorLogCorrupt {
        /// Corrupt line number.
        line: usize,
    },
    /// File-backed DKG setup wire log was corrupt.
    DkgWireLogCorrupt {
        /// Corrupt line number.
        line: usize,
    },
    /// File-backed DKG setup phase-cursor log was corrupt.
    DkgSetupPhaseCursorLogCorrupt {
        /// Corrupt line number.
        line: usize,
    },
    /// Public commitments/checks were missing.
    EmptyPublicCommitments,
    /// Accepted public commitments did not include exactly one entry per party.
    InvalidCommitmentPartySet {
        /// Commitment set being validated.
        set: CommitmentSet,
        /// Expected number of entries.
        expected: usize,
        /// Actual number of entries.
        got: usize,
    },
    /// Duplicate party in a public commitment set.
    DuplicateCommitmentParty {
        /// Commitment set being validated.
        set: CommitmentSet,
        /// Duplicated party.
        party: PartyId,
    },
    /// Secret-share package had an empty secret field.
    EmptySecretShareField {
        /// Owning party.
        party: PartyId,
        /// Stable field name.
        field: &'static str,
    },
    /// Secret-share bytes failed canonical decoding.
    InvalidSecretShareEncoding(&'static str),
    /// Shamir polynomial had no coefficients.
    EmptyShamirPolynomial,
    /// Shamir reconstruction was attempted without shares.
    EmptyShamirShareSet,
    /// Shamir interpolation point was zero or outside the ML-DSA field.
    InvalidInterpolationPoint(u32),
    /// Share interpolation point did not match the configured party point.
    InvalidSharePoint {
        /// Party whose point was checked.
        party: PartyId,
        /// Expected canonical interpolation point.
        expected: u32,
        /// Actual share point.
        got: u32,
    },
    /// Duplicate interpolation point in Shamir shares.
    DuplicateInterpolationPoint,
    /// Epoch was already committed in durable storage.
    EpochAlreadyCommitted(KeygenEpoch),
    /// Insecure clear Power2Round simulator was selected for a release path.
    InsecurePower2RoundBackend,
    /// Production DKG attempted to use scalarized prime-field MPC execution.
    PrimeFieldMpcScalarizedReleaseBlocked,
    /// DKG setup certificate is missing from a release package.
    MissingDkgSetupCertificate,
    /// DKG setup still uses an in-process scaffold backend.
    InsecureDkgSetupBackend,
    /// Native DKG coordinator still uses the in-crate scaffold scheduler.
    InsecureNativeDkgCoordinator,
    /// DKG certificate still carries explicit release blockers.
    DkgCertificateReleaseBlockers,
    /// A release setup artifact log contains private setup payloads.
    DkgReleaseArtifactContainsPrivateSetupPayload,
    /// DKG setup restart state was incomplete for a release package.
    DkgSetupIncompleteAfterRestart,
    /// DKG setup restart state was aborted and cannot become accepted.
    DkgSetupAbortedAfterRestart,
    /// Scalar IT-VSS restart state was incomplete.
    ScalarItVssIncompleteAfterRestart,
    /// Scalar IT-VSS restart state was aborted and cannot become accepted.
    ScalarItVssAbortedAfterRestart,
    /// Vector IT-VSS inputs had different lengths.
    ItVssVectorLengthMismatch {
        /// Expected vector length.
        expected: usize,
        /// Actual vector length.
        got: usize,
    },
    /// Production DKG attempted to use scalar-per-coefficient IT-VSS.
    ItVssScalarPerCoefficientDkgReleaseBlocked,
    /// Production IT-VSS attempted to enable public share-point reveal.
    ItVssPublicBetaRevealReleaseBlocked,
    /// Production IT-VSS attempted to publish retained receiver-side IC tags.
    ItVssRetainedTagPublicArtifactReleaseBlocked,
    /// One DKG key package has internally inconsistent public material.
    DkgKeyPackagePublicMaterialMismatch,
    /// DKG key packages disagree on public key, rho, or `t1`.
    DkgKeyPackagePublicMaterialDisagreement,
    /// DKG key packages disagree on their public certificate.
    DkgKeyPackageCertificateDisagreement,
    /// Power2Round canonical bit decomposition or private check failed.
    Power2RoundCanonicalityFailure,
    /// Power2Round mask rejection sampling exceeded its retry budget.
    Power2RoundMaskRetriesExceeded,
    /// Power2Round mask batch had malformed dimensions or metadata.
    Power2RoundMaskShapeMismatch,
    /// Power2Round mask batch was bound to a different transcript label.
    Power2RoundMaskTranscriptMismatch,
    /// Power2Round mask batch was consumed more than once.
    Power2RoundMaskAlreadyConsumed,
    /// Power2Round mask-use log was malformed.
    Power2RoundMaskUseLogCorrupt {
        /// One-based line number.
        line: usize,
    },
    /// Power2Round driver tried to advance without a certified mask batch.
    Power2RoundCertifiedMaskRequired,
    /// Power2Round driver tried to advance without masked openings.
    Power2RoundMaskedOpeningsRequired,
    /// Power2Round driver tried to advance without canonical-bit recovery.
    Power2RoundCanonicalBitsRequired,
    /// Power2Round driver tried to advance without add-round-constant output.
    Power2RoundAddRoundConstantRequired,
    /// Power2Round driver tried to advance without opened t1 bits.
    Power2RoundT1BitsRequired,
    /// Power2Round driver tried to advance without public evidence.
    Power2RoundEvidenceRequired,
    /// Power2Round tried to interpret an opened public value that was not a bit.
    Power2RoundInvalidOpenedBit,
    /// A caller attempted to run a single-party transport driver through the
    /// synchronous all-parties `MpcPower2RoundBackend` API.
    Power2RoundRequiresSinglePartyDriver,
    /// Production Power2Round per-party phases were driven out of order.
    Power2RoundDriverPhaseOutOfOrder,
    /// A release Power2Round runtime log contains an opening other than
    /// masked `C` or public `t1` high bits.
    Power2RoundForbiddenOpeningInRelease,
    /// Transcript store I/O failed.
    TranscriptStoreIo {
        /// Storage operation.
        operation: &'static str,
    },
    /// Transcript store was malformed.
    TranscriptStoreCorrupt {
        /// One-based line number.
        line: usize,
    },
    /// Backend-specific failure represented as a stable string.
    Backend(&'static str),
}

/// Public commitment/check set type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitmentSet {
    /// Pairwise seed commitments.
    PairwiseSeed,
}

pub(crate) fn validate_exact_party_set(
    config: &DkgConfig,
    round: DkgRound,
    senders: impl Iterator<Item = PartyId>,
) -> Result<(), DkgError> {
    let mut seen = Vec::new();
    for sender in senders {
        if !config.parties.contains(&sender) {
            return Err(DkgError::UnknownParty(sender));
        }
        if seen.contains(&sender) {
            return Err(DkgError::DuplicateRoundSender { round, sender });
        }
        seen.push(sender);
    }
    if seen.len() != config.parties.len() {
        return Err(DkgError::MissingRoundMessages {
            round,
            expected: config.parties.len(),
            got: seen.len(),
        });
    }
    for party in &config.parties {
        if !seen.contains(party) {
            return Err(DkgError::MissingRoundMessages {
                round,
                expected: config.parties.len(),
                got: seen.len(),
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_commitment_party_set(
    config: &DkgConfig,
    parties: impl Iterator<Item = PartyId>,
    set: CommitmentSet,
) -> Result<(), DkgError> {
    let mut seen = Vec::new();
    for party in parties {
        if !config.parties.contains(&party) {
            return Err(DkgError::UnknownParty(party));
        }
        if seen.contains(&party) {
            return Err(DkgError::DuplicateCommitmentParty { set, party });
        }
        seen.push(party);
    }
    if seen.len() != config.parties.len() {
        return Err(DkgError::InvalidCommitmentPartySet {
            set,
            expected: config.parties.len(),
            got: seen.len(),
        });
    }
    Ok(())
}

pub(crate) fn validate_secret_share_shape(
    config: &DkgConfig,
    secret: &DkgSecretShare,
) -> Result<(), DkgError> {
    if secret.s1_share.is_empty() {
        return Err(DkgError::EmptySecretShareField {
            party: secret.party,
            field: "s1_share",
        });
    }
    if secret.s2_share.is_empty() {
        return Err(DkgError::EmptySecretShareField {
            party: secret.party,
            field: "s2_share",
        });
    }
    if secret.t0_share.is_empty() {
        return Err(DkgError::EmptySecretShareField {
            party: secret.party,
            field: "t0_share",
        });
    }
    validate_encoded_s1_share(config, secret.party, &secret.s1_share)?;
    Ok(())
}

pub(crate) fn validate_s1_secret_share_shape(
    config: &DkgConfig,
    secret: &DkgS1SecretShare,
) -> Result<(), DkgError> {
    if secret.s1_share.is_empty() {
        return Err(DkgError::EmptySecretShareField {
            party: secret.party,
            field: "s1_share",
        });
    }
    validate_encoded_s1_share(config, secret.party, &secret.s1_share)?;
    Ok(())
}

pub(crate) fn validate_encoded_s1_share_for_params<P: MlDsaParams>(
    config: &DkgConfig,
    party: PartyId,
    bytes: &[u8],
) -> Result<(), DkgError> {
    let decoded = BoundedSecretVectorShare::decode::<P>(config, bytes)?;
    if decoded.party != party {
        return Err(DkgError::PartyMismatch {
            expected: party,
            got: decoded.party,
        });
    }
    Ok(())
}

pub(crate) fn validate_field_vector_share<P: MlDsaParams>(
    coeffs: &[Coeff],
) -> Result<(), DkgError> {
    let expected = P::L * P::N;
    if coeffs.len() != expected {
        return Err(DkgError::InvalidBoundedSecretVectorLength {
            expected,
            got: coeffs.len(),
        });
    }
    for (index, &coefficient) in coeffs.iter().enumerate() {
        if !(0..P::Q).contains(&coefficient) {
            return Err(DkgError::FieldShareCoefficientOutOfRange {
                index,
                coefficient,
                modulus: P::Q,
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_interpolation_point<P: MlDsaParams>(point: u32) -> Result<(), DkgError> {
    if point == 0 || point >= P::Q as u32 {
        return Err(DkgError::InvalidInterpolationPoint(point));
    }
    Ok(())
}

pub(crate) fn validate_unique_points<P: MlDsaParams>(points: &[u32]) -> Result<(), DkgError> {
    let mut seen = Vec::with_capacity(points.len());
    for &point in points {
        validate_interpolation_point::<P>(point)?;
        if seen.contains(&point) {
            return Err(DkgError::DuplicateInterpolationPoint);
        }
        seen.push(point);
    }
    Ok(())
}

pub(crate) fn hash_len_prefixed_vecs<'a>(
    hasher: &mut Sha3_256,
    values: impl Iterator<Item = &'a Vec<u8>>,
) {
    let values: Vec<&Vec<u8>> = values.collect();
    hasher.update((values.len() as u32).to_le_bytes());
    for value in values {
        hasher.update((value.len() as u32).to_le_bytes());
        hasher.update(value);
    }
}

pub(crate) fn hash_commit_round(
    previous: KeygenTranscriptHash,
    commits: &[DkgCommitPayload],
) -> KeygenTranscriptHash {
    let mut ordered = commits.to_vec();
    ordered.sort_by_key(|payload| payload.dealer);
    let mut hasher = round_hasher(b"TALUS-DKG-v1/commit", previous);
    for payload in &ordered {
        hasher.update(payload.dealer.0.to_le_bytes());
        hash_len_prefixed_vecs(
            &mut hasher,
            payload
                .vss_commitments
                .iter()
                .map(|commitment| &commitment.bytes),
        );
        hasher.update(payload.pairwise_seed_commitment.party.0.to_le_bytes());
        hasher.update(payload.pairwise_seed_commitment.commitment);
    }
    KeygenTranscriptHash(hasher.finalize().into())
}

pub(crate) fn hash_share_round(
    previous: KeygenTranscriptHash,
    shares: &[DkgSharePayload],
) -> KeygenTranscriptHash {
    let mut ordered = shares.to_vec();
    ordered.sort_by_key(|payload| (payload.dealer, payload.receiver));
    let mut hasher = round_hasher(b"TALUS-DKG-v1/share", previous);
    for payload in &ordered {
        hasher.update(payload.dealer.0.to_le_bytes());
        hasher.update(payload.receiver.0.to_le_bytes());
        hash_bytes(&mut hasher, &payload.encrypted_share);
        hash_bytes(&mut hasher, &payload.encrypted_seed_share);
        hash_bytes(&mut hasher, &payload.proof);
    }
    KeygenTranscriptHash(hasher.finalize().into())
}

pub(crate) fn hash_complaint_round(
    previous: KeygenTranscriptHash,
    complaints: &[DkgComplaintPayload],
) -> KeygenTranscriptHash {
    let mut ordered = complaints.to_vec();
    ordered.sort_by_key(|payload| (payload.complainant, payload.dealer, payload.receiver));
    let mut hasher = round_hasher(b"TALUS-DKG-v1/complaint", previous);
    for payload in &ordered {
        hasher.update(payload.complainant.0.to_le_bytes());
        hasher.update(payload.dealer.0.to_le_bytes());
        hasher.update(payload.receiver.0.to_le_bytes());
        hasher.update([payload.reason.as_u8()]);
        hash_bytes(&mut hasher, &payload.evidence);
    }
    KeygenTranscriptHash(hasher.finalize().into())
}

pub(crate) fn hash_finalize_round(
    previous: KeygenTranscriptHash,
    finalizers: &[DkgFinalizePayload],
) -> KeygenTranscriptHash {
    let mut ordered = finalizers.to_vec();
    ordered.sort_by_key(|payload| payload.sender);
    let mut hasher = round_hasher(b"TALUS-DKG-v1/finalize", previous);
    for payload in &ordered {
        hasher.update(payload.sender.0.to_le_bytes());
        hasher.update(payload.output.transcript_binding().0);
    }
    KeygenTranscriptHash(hasher.finalize().into())
}

pub(crate) fn round_hasher(domain: &'static [u8], previous: KeygenTranscriptHash) -> Sha3_256 {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(previous.0);
    hasher
}

pub(crate) fn hash_bytes(hasher: &mut Sha3_256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_le_bytes());
    hasher.update(bytes);
}
