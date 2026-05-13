#![forbid(unsafe_code)]
#![doc = "TALUS-MPC protocol state machines."]
//!
//! Normal builds expose only the strict production-facing TALUS-MPC API:
//! BCC-certified preprocessing tokens, strict no-rejected-`z` signing
//! sessions, and app-supplied transport/runtime boundaries.
//!
//! Paper-fast signing, clear partial `z_i` payloads, public exact `A*secret`
//! verifier paths, clear masked-broadcast audits, scaffold runtime-handle
//! constructors, and local witness helpers are test/dev artifacts only. They
//! are available only under `cfg(test)` or explicit non-production dev
//! features, and `production-release-checks` refuses to build with those
//! features enabled.

#[cfg(all(feature = "production-release-checks", feature = "paper-fast-dev"))]
compile_error!(
    "production-release-checks must not be built with paper-fast-dev insecure primitives"
);
#[cfg(all(feature = "production-release-checks", feature = "scaffold-dev"))]
compile_error!("production-release-checks must not be built with scaffold-dev insecure primitives");

mod local;
#[cfg(any(test, feature = "paper-fast-dev"))]
mod local_dev;
pub mod online;
#[cfg(any(test, feature = "paper-fast-dev"))]
mod online_dev;

/// Production preprocessing API.
///
/// The implementation currently lives in an internal module for incremental
/// refactoring, but normal callers should use this module or the crate-root
/// re-exports. Clear audit harnesses and paper-compatible helpers are exposed
/// only through `dev_backends`.
pub mod preprocessing {
    pub use crate::local::{
        certify_preprocessing_token,
        certify_preprocessing_token_release_validated_with_finished_runtime_driver,
        certify_preprocessing_token_release_validated_with_runtime,
        certify_preprocessing_token_with_consistency, ensure_certified_token_release_valid,
        ensure_pre_challenge_certification_evidence, ensure_pre_challenge_certification_policy,
        ensure_preprocessing_counters_vectorized_for_release, generate_distributed_nonce_shares,
        masked_broadcast_commitment, open_broadcasts,
        party_preprocess_input_from_distributed_nonce_share, prepare_masked_broadcast_envelope,
        prepare_masked_broadcast_envelope_with_vector_runtime_evidence,
        preprocessing_runtime_transcript_aggregate_hash,
        talus_performance_counters_from_preprocessing, BccCertificationEvidence, BroadcastEnvelope,
        CarryCompareCertificationEvidence, CertifiedToken, Commitment,
        DistributedNonceGenerationBroadcast, DistributedNonceGenerationEvidence,
        DistributedNonceGenerationLocalOutput, DistributedNonceGenerationOptions,
        DistributedNonceGenerationOutbound, DistributedNonceGenerationOutput,
        DistributedNonceGenerationSession, DistributedNonceShare, MaskedBroadcast,
        MaskedBroadcastCertificationEvidence, MaskedBroadcastConsistencyProof,
        MaskedBroadcastConsistencyStatement, MaskedBroadcastConsistencyVerifier,
        MaskedBroadcastRuntimeBinding, NonceCommitment, NonceRevealPolicyEvidence,
        PartyPreprocessInput, PreChallengeCertificationEvidence, PreChallengeCertificationPolicy,
        PreprocessError, PreprocessingCertificationCounters,
        PreprocessingCertificationRuntimeProofs, PreprocessingCertificationRuntimeStatement,
        PreprocessingCertificationRuntimeTranscripts, PreprocessingCertificationStage,
        PreprocessingCertificationStageRuntimeProof, PreprocessingOutbound,
        PreprocessingPrivateCircuitDriverState, PreprocessingPrivateCircuitHandles,
        PreprocessingPrivateMaterialHandles, PreprocessingPrivateMaterialState,
        PreprocessingPrivateMaterialStateSource, PreprocessingSession, PreprocessingSessionOptions,
        PreprocessingVectorRuntimeCertificate, ProductMaskedBroadcastConsistencyVerifier,
        ProductZkMaskedBroadcastVerifier, ProductionPreprocessingCertificationRuntime,
        SessionCounter, SessionCounterStore, SessionId, SessionRegistry, SessionStore,
        TokenCandidate, TokenInventory, TokenInventoryState, TokenInventoryStore,
        TokenPersistenceEvidence, TokenPool, TokenPoolError, TranscriptHash,
    };

    #[cfg(feature = "std")]
    pub use crate::local::{FileSessionCounter, FileSessionRegistry, FileTokenInventory};
}

pub use preprocessing::{
    certify_preprocessing_token,
    certify_preprocessing_token_release_validated_with_finished_runtime_driver,
    certify_preprocessing_token_release_validated_with_runtime,
    certify_preprocessing_token_with_consistency, ensure_certified_token_release_valid,
    ensure_pre_challenge_certification_evidence, ensure_pre_challenge_certification_policy,
    ensure_preprocessing_counters_vectorized_for_release, generate_distributed_nonce_shares,
    masked_broadcast_commitment, open_broadcasts,
    party_preprocess_input_from_distributed_nonce_share, prepare_masked_broadcast_envelope,
    prepare_masked_broadcast_envelope_with_vector_runtime_evidence,
    preprocessing_runtime_transcript_aggregate_hash, talus_performance_counters_from_preprocessing,
    BccCertificationEvidence, BroadcastEnvelope, CarryCompareCertificationEvidence, CertifiedToken,
    Commitment, DistributedNonceGenerationBroadcast, DistributedNonceGenerationEvidence,
    DistributedNonceGenerationLocalOutput, DistributedNonceGenerationOptions,
    DistributedNonceGenerationOutbound, DistributedNonceGenerationOutput,
    DistributedNonceGenerationSession, DistributedNonceShare, MaskedBroadcast,
    MaskedBroadcastCertificationEvidence, MaskedBroadcastConsistencyProof,
    MaskedBroadcastConsistencyStatement, MaskedBroadcastConsistencyVerifier,
    MaskedBroadcastRuntimeBinding, NonceCommitment, NonceRevealPolicyEvidence,
    PartyPreprocessInput, PreChallengeCertificationEvidence, PreChallengeCertificationPolicy,
    PreprocessError, PreprocessingCertificationCounters, PreprocessingCertificationRuntimeProofs,
    PreprocessingCertificationRuntimeStatement, PreprocessingCertificationRuntimeTranscripts,
    PreprocessingCertificationStage, PreprocessingCertificationStageRuntimeProof,
    PreprocessingOutbound, PreprocessingPrivateCircuitDriverState,
    PreprocessingPrivateCircuitHandles, PreprocessingPrivateMaterialHandles,
    PreprocessingPrivateMaterialState, PreprocessingPrivateMaterialStateSource,
    PreprocessingSession, PreprocessingSessionOptions, PreprocessingVectorRuntimeCertificate,
    ProductMaskedBroadcastConsistencyVerifier, ProductZkMaskedBroadcastVerifier,
    ProductionPreprocessingCertificationRuntime, SessionCounter, SessionCounterStore, SessionId,
    SessionRegistry, SessionStore, TokenCandidate, TokenInventory, TokenInventoryState,
    TokenInventoryStore, TokenPersistenceEvidence, TokenPool, TokenPoolError, TranscriptHash,
};

pub use online::{
    compute_challenge_material, sign_strict_no_rejected_z, strict_build_selected_signature_output,
    strict_candidate_metadata, strict_candidate_metadata_batch, strict_candidate_priority,
    strict_collect_selected_h_opening, strict_collect_selected_share_products,
    strict_collect_selected_z_opening, strict_drive_selected_h_opening,
    strict_drive_selected_share_products, strict_drive_selected_z_opening,
    strict_encode_selected_signature, strict_polyvec_to_runtime_lanes,
    strict_prepare_runtime_z_share, strict_production_signing_backend, strict_runtime_az_share,
    strict_runtime_hint_approx_share, strict_signature_hash, strict_signing_request_hash,
    strict_signing_session_id, talus_performance_counters_from_strict_signing,
    validate_sign_request, validate_strict_sign_request, BccCertifiedTokenBatch, ChallengeMaterial,
    ConsumedBccCertifiedTokenBatch, ConsumedTokenStore, DirectStrictSigningComponentRuntime,
    FinalSignature, FinalVerifier, FipsFinalVerifier, NoopStrictSigningRuntimeObserver,
    OnlineError, ProductionStrictLiveVectorMpcArtifactSource,
    ProductionStrictRuntimeSelectedOpeningArtifactBackend,
    ProductionStrictRuntimeSelectedOpeningBackend, ProductionStrictSigningBackend,
    ProductionStrictSigningVectorMpcRuntimeBackend, ProductionVectorHintCheckBackend,
    ProductionVectorPrivateSelectionBackend, ProductionVectorResponseBoundCheckBackend,
    ProductionVectorResponsePreparationBackend, ProductionVectorSelectedOpeningBackend,
    SignRequest, SigningCounters, StrictCandidateMetadata, StrictCandidatePriority,
    StrictHintCheckBackend, StrictHintCheckEvidence, StrictPolynomialShareProvider,
    StrictPolynomialSigningShare, StrictPreparedResponseBatch, StrictPrivateSelectionBackend,
    StrictPrivateSelectionEvidence, StrictPrivateSigningBackend, StrictProductionSigningBackend,
    StrictResponseBoundCheckBackend, StrictResponseBoundEvidence, StrictResponseCheckCounters,
    StrictResponseCheckPhase, StrictResponseCheckPhaseDriver, StrictResponsePreparationBackend,
    StrictRuntimeAllBitsTrueState, StrictRuntimeCandidateHandle, StrictRuntimeCandidateShareInput,
    StrictRuntimeHintBitsCheckState, StrictRuntimeHintWeightCheckState,
    StrictRuntimePrioritySelectionState, StrictRuntimeSelectedOpeningArtifact,
    StrictRuntimeSelectedOpeningArtifactSource, StrictRuntimeValidBitState,
    StrictRuntimeZBoundCheckState, StrictSelectedOpeningBackend, StrictSelectedOpeningEvidence,
    StrictSelectedSignature, StrictSignRequest, StrictSigningCursorMemoryStore,
    StrictSigningCursorPhase, StrictSigningDistributedRuntime, StrictSigningEvidence,
    StrictSigningOutbound, StrictSigningPhase, StrictSigningPhaseDriver, StrictSigningRuntime,
    StrictSigningRuntimeCertificateSource, StrictSigningRuntimeObserver, StrictSigningRuntimeSlot,
    StrictSigningRuntimeSlotProgress, StrictSigningRuntimeStep, StrictSigningSession,
    StrictSigningSessionCursor, StrictSigningSessionId, StrictSigningSessionPhase,
    StrictSigningSessionStore, StrictSigningVectorRuntimeCertificate, StrictVectorCandidateHandle,
    TokenConsumptionStore, ONLINE_PROTOCOL_VERSION, STRICT_RESPONSE_CHECK_PHASES,
    STRICT_SIGNING_PHASES, STRICT_SIGNING_RUNTIME_SLOTS,
};

#[cfg(any(test, feature = "scaffold-dev"))]
pub use online::ProductionStrictVectorMpcArtifactSource;
#[cfg(feature = "std")]
pub use preprocessing::{FileSessionCounter, FileSessionRegistry, FileTokenInventory};

/// Test/dev-only compatibility backends and paper-fast helpers.
///
/// This module is intentionally absent from normal production builds. Anything
/// here may expose clear partial `z_i`, exact public `A*secret` images, or
/// clear audit witnesses and must not be used by production callers.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub mod dev_backends {
    pub use crate::local_dev::{
        ClearMaskedBroadcastConsistencyVerifier, CutAndChooseAuditPlan, MaskedBroadcastClearAudit,
    };
    pub use crate::online_dev::{
        assemble_polynomial_response, compute_polynomial_partial, encode_final_signature_candidate,
        encode_final_signature_candidate_from_public_key, encode_final_signature_candidate_with_az,
        sign_polynomial_with_retry, sign_polynomial_with_token, sign_with_retry, sign_with_token,
        CommitmentBackedPartialVerifier, DkgBackedPolynomialShareProvider,
        LocalStrictHintCheckBackend, LocalStrictPolynomialSigningBackend,
        LocalStrictPrivateSelectionBackend, LocalStrictResponseBoundCheckBackend,
        LocalStrictSelectedOpeningBackend, LocalStrictSelectionCandidate,
        NoopPolynomialPartialVerifier, OnlineServices, PartialSignature, PartialSigner,
        PolynomialAggregation, PolynomialOnlineServices, PolynomialPartialCommitment,
        PolynomialPartialSignature, PolynomialResponse, PolynomialShareProvider,
        PolynomialSigningShare, RetryPolicy, SignatureAssembler,
    };
}

#[cfg(feature = "std")]
pub use online::{FileConsumedTokenStore, FileStrictSigningSessionStore};

/// Crate status marker for docs/tests.
///
/// This is not a security claim. It exists to make normal builds stop
/// advertising themselves as a scaffold while production blockers remain
/// tracked in the roadmap.
pub const CRATE_STATUS: &str = "production-boundaries-in-progress";

#[cfg(test)]
mod production_api_scan_tests {
    const DEV_CFG: &str = "#[cfg(any(test, feature = \"paper-fast-dev\"))]";

    #[test]
    fn production_api_does_not_export_clear_partial_or_public_linear_image_paths() {
        let lib = include_str!("lib.rs");
        assert!(
            !lib.contains("\npub mod local;"),
            "normal API must not expose the internal preprocessing implementation as `local`"
        );
        assert!(
            lib.contains("pub mod preprocessing"),
            "normal API must expose production preprocessing under an explicit name"
        );
        assert_ne!(
            crate::CRATE_STATUS,
            "scaffold",
            "crate status must not advertise the normal API as scaffold"
        );
        let production_exports = lib
            .split(DEV_CFG)
            .next()
            .expect("source always has a prefix before dev cfg");

        for forbidden in [
            "CommitmentBackedPartialVerifier",
            "PartialSignature",
            "PolynomialPartialSignature",
            "PolynomialPartialCommitment",
            "ClearMaskedBroadcastConsistencyVerifier",
            "MaskedBroadcastClearAudit",
            "CutAndChooseAuditPlan",
            "NoopStrictSigningDistributedRuntime",
            "preprocessing_certification_stage_runtime_proof",
            "certify_preprocessing_token_release_validated_from_envelopes",
            "certify_preprocessing_token_release_validated,",
            "prepare_masked_broadcast_envelope_with_runtime_transcript",
            "finish_release_validated",
        ] {
            assert!(
                !production_exports.contains(forbidden),
                "`{forbidden}` must not be exported by the normal production API"
            );
        }
    }

    #[test]
    fn insecure_online_and_preprocessing_declarations_are_dev_only() {
        let online = include_str!("online.rs");
        for needle in [
            "pub struct PartialSignature",
            "pub struct PolynomialPartialSignature",
            "pub struct PolynomialPartialCommitment",
            "pub struct CommitmentBackedPartialVerifier",
            "pub trait PartialSigner",
            "pub trait SignatureAssembler",
            "pub fn sign_with_token",
            "pub fn sign_polynomial_with_token",
            "pub fn sign_with_retry",
            "pub fn sign_polynomial_with_retry",
        ] {
            assert!(
                !online.contains(needle),
                "`{needle}` must not appear in the normal production online module"
            );
        }

        let online_dev = include_str!("online_dev.rs");
        for needle in [
            "pub struct PartialSignature",
            "pub struct PolynomialPartialSignature",
            "pub struct PolynomialPartialCommitment",
            "pub struct CommitmentBackedPartialVerifier",
            "pub trait PartialSigner",
            "pub trait SignatureAssembler",
            "pub fn sign_with_token",
            "pub fn sign_polynomial_with_token",
            "pub fn sign_with_retry",
            "pub fn sign_polynomial_with_retry",
        ] {
            assert!(
                online_dev.contains(needle),
                "`{needle}` must live in the gated online_dev module"
            );
        }

        let local = include_str!("local.rs");
        for needle in [
            "pub ay_commitment: PolyVec",
            "pub struct MaskedBroadcastClearAudit",
            "pub struct ClearMaskedBroadcastConsistencyVerifier",
            "pub struct CutAndChooseAuditPlan",
            "pub carry_compare: PreprocessingCertificationStageRuntimeProof",
            "pub bcc: PreprocessingCertificationStageRuntimeProof",
        ] {
            assert!(
                !local.contains(needle),
                "`{needle}` must not appear in the normal production local module"
            );
        }
        assert!(
            !local.contains("pub fn derive_private_material_handles_from_opened_preprocessing"),
            "normal API must not expose loose opened-material handle derivation"
        );
        assert!(
            local.contains(
                "#[cfg(any(test, feature = \"scaffold-dev\"))]\n    pub fn with_private_circuit_handles"
            ),
            "raw private-handle attachment must be test/scaffold-dev only"
        );
        assert!(
            local.contains(
                "#[cfg(any(test, feature = \"scaffold-dev\"))]\n    pub fn attach_private_circuit_handles"
            ),
            "raw private-handle mutation must be test/scaffold-dev only"
        );
        assert!(
            local.contains("pub fn start_private_circuit_handles_from_state"),
            "normal API must start preprocessing private circuits from runtime-owned state"
        );
        assert!(
            local.contains("pub fn finish_and_attach_private_circuit_state"),
            "normal API must attach private circuit handles through state-owned completion"
        );

        let stage_runtime_proof = local
            .split("pub struct PreprocessingCertificationStageRuntimeProof")
            .nth(1)
            .expect("stage runtime proof type exists")
            .split("impl PreprocessingCertificationStageRuntimeProof")
            .next()
            .expect("stage runtime proof impl follows type");
        assert!(
            !stage_runtime_proof.contains("pub bytes: Vec<u8>"),
            "preprocessing stage runtime proof bytes must be opaque"
        );

        let masked_broadcast_proof = local
            .split("pub struct MaskedBroadcastConsistencyProof")
            .nth(1)
            .expect("masked broadcast consistency proof type exists")
            .split("impl MaskedBroadcastConsistencyProof")
            .next()
            .expect("masked broadcast proof impl follows type");
        assert!(
            !masked_broadcast_proof.contains("pub bytes: Vec<u8>"),
            "masked-broadcast consistency proof bytes must be opaque"
        );

        let runtime_proofs = local
            .split("pub struct PreprocessingCertificationRuntimeProofs")
            .nth(1)
            .expect("runtime proofs type exists")
            .split("impl PreprocessingCertificationRuntimeProofs")
            .next()
            .expect("runtime proofs impl follows type");
        for needle in [
            "pub masked_broadcast: [u8; 32]",
            "pub carry_compare: PreprocessingCertificationStageRuntimeProof",
            "pub bcc: PreprocessingCertificationStageRuntimeProof",
        ] {
            assert!(
                !runtime_proofs.contains(needle),
                "preprocessing runtime proof bundle fields must be opaque"
            );
        }

        let preprocessing_runtime_certificate = local
            .split("pub struct PreprocessingVectorRuntimeCertificate")
            .nth(1)
            .expect("preprocessing runtime certificate type exists")
            .split("impl PreprocessingVectorRuntimeCertificate")
            .next()
            .expect("preprocessing runtime certificate impl follows type");
        for needle in [
            "pub runtime_evidence: ProductionVectorItMpcRuntimeEvidence",
            "pub token_binding_hash: Option<[u8; 32]>",
        ] {
            assert!(
                !preprocessing_runtime_certificate.contains(needle),
                "preprocessing runtime certificate fields must be opaque"
            );
        }

        let local_dev = include_str!("local_dev.rs");
        for needle in [
            "pub struct MaskedBroadcastClearAudit",
            "pub struct ClearMaskedBroadcastConsistencyVerifier",
            "pub struct CutAndChooseAuditPlan",
        ] {
            assert!(
                local_dev.contains(needle),
                "`{needle}` must live in the gated local_dev module"
            );
        }
    }

    #[test]
    fn strict_signing_evidence_has_no_rejected_candidate_fields() {
        let online = include_str!("online.rs");
        let evidence = online
            .split("pub struct StrictSigningEvidence")
            .nth(1)
            .expect("strict evidence type exists")
            .split("pub struct StrictSelectedSignature")
            .next()
            .expect("selected-signature follows strict evidence");

        for forbidden in [
            "valid_bit",
            "validity",
            "failure",
            "reason",
            "rejected",
            "z_share",
            "partial",
            "hint",
            "mask",
            "witness",
        ] {
            assert!(
                !evidence.contains(forbidden),
                "StrictSigningEvidence must not expose `{forbidden}`"
            );
        }

        let strict_runtime_certificate = online
            .split("pub struct StrictSigningVectorRuntimeCertificate")
            .nth(1)
            .expect("strict signing runtime certificate type exists")
            .split("impl StrictSigningVectorRuntimeCertificate")
            .next()
            .expect("strict signing runtime certificate impl follows type");
        assert!(
            !strict_runtime_certificate
                .contains("pub runtime_evidence: ProductionVectorItMpcRuntimeEvidence"),
            "strict signing runtime certificate fields must be opaque"
        );
    }

    #[test]
    fn distributed_runtime_boundary_does_not_duplicate_strict_crypto_logic() {
        let online = include_str!("online.rs");
        let runtime_region = online
            .split("pub trait StrictSigningDistributedRuntime")
            .nth(1)
            .expect("distributed runtime trait exists")
            .split("/// Durable strict signing cursor persistence API.")
            .next()
            .expect("cursor API follows distributed runtime section");

        for forbidden in [
            "strict_response_polyvec",
            "strict_aggregate_response_lagrange",
            "z_bound_holds",
            "public_approx_from_az",
            "compute_talus_hint_polyvec",
            "signature_encode",
            ".select_candidate(",
            ".open_selected(",
        ] {
            assert!(
                !runtime_region.contains(forbidden),
                "distributed runtime boundary must not duplicate strict crypto logic `{forbidden}`"
            );
        }

        assert!(
            runtime_region.contains("pub struct DirectStrictSigningComponentRuntime"),
            "direct component-stack signing must use an explicit rejecting runtime adapter"
        );
        assert!(
            runtime_region
                .contains("fn accepts_runtime_messages(&self) -> bool {\n        false\n    }"),
            "direct component-stack adapter must reject distributed runtime messages"
        );
    }
}
