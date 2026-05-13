#![doc = "Test/dev-only paper-fast online signing helpers."]

//! This module contains TALUS-paper-compatible helpers that expose clear
//! partial `z_i` responses and exact public `A*secret` images. It is compiled
//! only for tests or the explicit `paper-fast-dev` feature and must never be
//! part of production builds.

use core::{fmt, marker::PhantomData};

use sha3::{Digest, Sha3_256};
use talus_core::{
    aggregate_z_shares, aggregate_z_shares_lagrange, az_from_rho, compute_talus_hint_polyvec,
    infinity_norm, mul_challenge_polyvec, partial_z_share, public_approx_from_az,
    public_key_decode, sample_in_ball, signature_encode, z_bound_holds, MlDsaParams, PolyError,
    PolyVec,
};
use talus_dkg::{DkgConfig, DkgKeyPackage, DkgSecretShare};
use talus_mpc_core::PartyId;
use zeroize::Zeroize;

use crate::local::{SessionId, TokenPool};
use crate::online::{
    compute_challenge_material, polyvec_from_dkg_s1_share, strict_candidate_metadata,
    strict_signature_hash, validate_sign_request, ChallengeMaterial,
    ConsumedBccCertifiedTokenBatch, FinalSignature, FinalVerifier, OnlineError, SignRequest,
    SigningCounters, StrictHintCheckBackend, StrictHintCheckEvidence,
    StrictPrivateSelectionBackend, StrictPrivateSelectionEvidence, StrictPrivateSigningBackend,
    StrictResponseBoundCheckBackend, StrictResponseBoundEvidence, StrictResponseCheckPhaseDriver,
    StrictSelectedOpeningBackend, StrictSelectedOpeningEvidence, StrictSelectedSignature,
    StrictSignRequest, StrictSigningEvidence, StrictSigningPhaseDriver, TokenConsumptionStore,
};

/// Partial signing response placeholder.
///
/// This clear-`z_i` paper-fast shape is compiled only for tests and explicit
/// development builds. It is not part of the normal production API.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialSignature {
    /// Session id.
    pub session_id: SessionId,
    /// Party id.
    pub party: PartyId,
    /// Partial `z_i` representation supplied by the current adapter layer.
    pub z_share: Vec<u8>,
    /// Challenge seed bound into the response.
    pub challenge: Vec<u8>,
}

/// Typed polynomial partial signing response.
///
/// This contains clear `z_i = y_i + c*s1_i` material and is therefore
/// test/dev-only.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolynomialPartialSignature {
    /// Session id.
    pub session_id: SessionId,
    /// Party id.
    pub party: PartyId,
    /// Partial response share `z_i = y_i + c*s1_i`.
    pub z_share: PolyVec,
    /// Challenge seed bound into the response.
    pub challenge: Vec<u8>,
}

/// Aggregated polynomial response material before FIPS signature encoding.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolynomialResponse {
    /// Challenge seed `ctilde`.
    pub ctilde: Vec<u8>,
    /// Aggregated response vector `z`.
    pub z: PolyVec,
}

/// One party's typed online signing shares.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Eq, PartialEq)]
pub struct PolynomialSigningShare {
    /// Party id.
    pub party: PartyId,
    /// Local nonce share `y_i`.
    pub y_share: PolyVec,
    /// Local secret-key share `s1_i`.
    pub s1_share: PolyVec,
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl fmt::Debug for PolynomialSigningShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolynomialSigningShare")
            .field("party", &self.party)
            .field("y_share", &"<redacted>")
            .field("s1_share", &"<redacted>")
            .finish()
    }
}

/// Public commitments used to verify one typed online partial.
///
/// These are the TALUS-paper-compatible exact `A*y_i` / `A*s1_i` images. They
/// are test/dev-only because exact public `A*secret` images are not hiding for
/// ML-DSA parameter shapes.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolynomialPartialCommitment {
    /// Party id.
    pub party: PartyId,
    /// Public commitment to local nonce product `A*y_i`.
    pub ay_commitment: PolyVec,
    /// Public commitment to local secret share product `A*s1_i`.
    pub as1_commitment: PolyVec,
}

/// Aggregation mode for typed polynomial partial responses.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolynomialAggregation {
    /// Additive shares, used by deterministic local tests and simple adapters.
    Additive,
    /// Shamir-style shares interpolated at zero with party ids as points.
    LagrangeAtZero,
}

/// Retry policy for online signing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Maximum number of attempts.
    pub max_attempts: usize,
}

/// Deterministic partial-response adapter for the current non-polynomial shell.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub trait PartialSigner {
    /// Produces one partial response from local nonce-share material.
    fn sign_partial(
        &self,
        session_id: SessionId,
        party: PartyId,
        challenge: &ChallengeMaterial,
        y_share: &[u8],
    ) -> Result<PartialSignature, OnlineError>;
}

/// Deterministic final-assembly adapter for the current non-polynomial shell.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub trait SignatureAssembler {
    /// Assembles a final signature candidate from partial responses.
    fn assemble(
        &self,
        request: &SignRequest,
        challenge: &ChallengeMaterial,
        partials: &[PartialSignature],
    ) -> Result<FinalSignature, OnlineError>;
}

/// Source for typed per-party polynomial signing shares.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub trait PolynomialShareProvider {
    /// Returns the local online signing shares for `party` in `session_id`.
    fn signing_share(
        &self,
        session_id: SessionId,
        party: PartyId,
    ) -> Result<PolynomialSigningShare, OnlineError>;
}
/// Polynomial share provider backed by imported DKG secret-share packages.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Eq, PartialEq)]
pub struct DkgBackedPolynomialShareProvider<P: MlDsaParams> {
    session_id: SessionId,
    dkg_config: DkgConfig,
    y_shares: Vec<(PartyId, PolyVec)>,
    dkg_secret_shares: Vec<DkgSecretShare>,
    _params: PhantomData<P>,
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl<P: MlDsaParams> DkgBackedPolynomialShareProvider<P> {
    /// Creates a provider for one preprocessing/signing session.
    pub fn new(
        session_id: SessionId,
        dkg_config: DkgConfig,
        y_shares: Vec<(PartyId, PolyVec)>,
        dkg_secret_shares: Vec<DkgSecretShare>,
    ) -> Self {
        Self {
            session_id,
            dkg_config,
            y_shares,
            dkg_secret_shares,
            _params: PhantomData,
        }
    }

    /// Creates a provider from native DKG key packages. Only retained `s1`
    /// material is imported; `s2`, `t`, and `t0` remain absent from key
    /// packages.
    pub fn from_key_packages(
        session_id: SessionId,
        dkg_config: DkgConfig,
        y_shares: Vec<(PartyId, PolyVec)>,
        key_packages: Vec<DkgKeyPackage>,
    ) -> Self {
        let dkg_secret_shares = key_packages
            .into_iter()
            .map(|package| DkgSecretShare {
                party: package.party,
                s1_share: package.s1_share.s1_share,
                s2_share: vec![0],
                t0_share: vec![0],
                pairwise_seed_shares: package.s1_share.pairwise_seed_shares,
            })
            .collect();
        Self::new(session_id, dkg_config, y_shares, dkg_secret_shares)
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl<P: MlDsaParams> fmt::Debug for DkgBackedPolynomialShareProvider<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgBackedPolynomialShareProvider")
            .field("session_id", &self.session_id)
            .field("dkg_config", &self.dkg_config)
            .field("y_shares", &"<redacted>")
            .field("dkg_secret_shares", &"<redacted>")
            .finish()
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl<P: MlDsaParams> PolynomialShareProvider for DkgBackedPolynomialShareProvider<P> {
    fn signing_share(
        &self,
        session_id: SessionId,
        party: PartyId,
    ) -> Result<PolynomialSigningShare, OnlineError> {
        if session_id != self.session_id {
            return Err(OnlineError::SessionMismatch);
        }

        let y_share = self
            .y_shares
            .iter()
            .find(|(candidate, _)| *candidate == party)
            .map(|(_, share)| share.clone())
            .ok_or(OnlineError::PartialSignerFailed(party))?;
        let secret = self
            .dkg_secret_shares
            .iter()
            .find(|secret| secret.party == party)
            .ok_or(OnlineError::PartialSignerFailed(party))?;
        let s1_share = polyvec_from_dkg_s1_share::<P>(&self.dkg_config, secret)?;

        Ok(PolynomialSigningShare {
            party,
            y_share,
            s1_share,
        })
    }
}

/// Verifier for typed online partial responses before aggregation.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub trait PolynomialPartialVerifier {
    /// Verifies `partial` against public commitments.
    fn verify_partial<P: MlDsaParams>(
        &self,
        public_key: &[u8],
        session_id: SessionId,
        challenge: &ChallengeMaterial,
        partial: &PolynomialPartialSignature,
    ) -> Result<(), OnlineError>;
}

/// No-op typed partial verifier used only by scaffolding tests that do not yet
/// model public `A*y_i` and `A*s1_i` commitments.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoopPolynomialPartialVerifier;

#[cfg(any(test, feature = "paper-fast-dev"))]
impl PolynomialPartialVerifier for NoopPolynomialPartialVerifier {
    fn verify_partial<P: MlDsaParams>(
        &self,
        _public_key: &[u8],
        _session_id: SessionId,
        _challenge: &ChallengeMaterial,
        _partial: &PolynomialPartialSignature,
    ) -> Result<(), OnlineError> {
        Ok(())
    }
}

/// Commitment-backed typed partial verifier.
///
/// Test/dev-only attack-demonstration verifier for the paper-compatible public
/// linear-image check. It is intentionally absent from normal production
/// builds.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommitmentBackedPartialVerifier {
    commitments: Vec<PolynomialPartialCommitment>,
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl CommitmentBackedPartialVerifier {
    /// Creates a verifier from public per-party commitments.
    pub fn new(commitments: Vec<PolynomialPartialCommitment>) -> Self {
        Self { commitments }
    }

    fn commitment(&self, party: PartyId) -> Result<&PolynomialPartialCommitment, OnlineError> {
        self.commitments
            .iter()
            .find(|commitment| commitment.party == party)
            .ok_or(OnlineError::PublicCommitmentMissing(party))
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl PolynomialPartialVerifier for CommitmentBackedPartialVerifier {
    fn verify_partial<P: MlDsaParams>(
        &self,
        public_key: &[u8],
        session_id: SessionId,
        challenge: &ChallengeMaterial,
        partial: &PolynomialPartialSignature,
    ) -> Result<(), OnlineError> {
        if partial.session_id != session_id || partial.challenge != challenge.ctilde {
            return Err(OnlineError::Blame(partial.party));
        }
        if challenge.ctilde.len() != P::CTILDE_LEN {
            return Err(OnlineError::Polynomial(PolyError::ChallengeLength {
                expected: P::CTILDE_LEN,
                got: challenge.ctilde.len(),
            }));
        }

        let commitment = self.commitment(partial.party)?;
        validate_public_commitment_len::<P>(partial.party, &commitment.ay_commitment)?;
        validate_public_commitment_len::<P>(partial.party, &commitment.as1_commitment)?;

        let public_key = public_key_decode::<P>(public_key)?;
        let az = az_from_rho::<P>(&public_key.rho, &partial.z_share)?;
        let challenge_poly = sample_in_ball::<P>(&challenge.ctilde);
        let c_as1 = mul_challenge_polyvec::<P>(&challenge_poly, &commitment.as1_commitment);
        let expected = commitment.ay_commitment.add_mod_q::<P>(&c_as1);

        if az == expected {
            Ok(())
        } else {
            Err(OnlineError::Blame(partial.party))
        }
    }
}

/// Online signing service adapters.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub struct OnlineServices<'a, PS, SA, FV> {
    /// Public key transcript hash `tr`.
    pub tr: &'a [u8; 64],
    /// Partial signer.
    pub partial_signer: &'a PS,
    /// Final assembler.
    pub assembler: &'a SA,
    /// Independent final verifier.
    pub verifier: &'a FV,
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl<PS, SA, FV> fmt::Debug for OnlineServices<'_, PS, SA, FV> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnlineServices")
            .field("tr", &"<redacted>")
            .field("partial_signer", &"<adapter>")
            .field("assembler", &"<adapter>")
            .field("verifier", &"<adapter>")
            .finish()
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl<'a, PS, SA, FV> Clone for OnlineServices<'a, PS, SA, FV> {
    fn clone(&self) -> Self {
        *self
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl<'a, PS, SA, FV> Copy for OnlineServices<'a, PS, SA, FV> {}

/// Typed polynomial online signing service adapters.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub struct PolynomialOnlineServices<'a, SP, PV, FV> {
    /// Public key transcript hash `tr`.
    pub tr: &'a [u8; 64],
    /// Serialized FIPS public key.
    pub public_key: &'a [u8],
    /// Typed response aggregation mode.
    pub aggregation: PolynomialAggregation,
    /// Typed polynomial share provider.
    pub share_provider: &'a SP,
    /// Typed partial verifier.
    pub partial_verifier: &'a PV,
    /// Independent final verifier.
    pub verifier: &'a FV,
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl<SP, PV, FV> fmt::Debug for PolynomialOnlineServices<'_, SP, PV, FV> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolynomialOnlineServices")
            .field("tr", &"<redacted>")
            .field("public_key_len", &self.public_key.len())
            .field("aggregation", &self.aggregation)
            .field("share_provider", &"<adapter>")
            .field("partial_verifier", &"<adapter>")
            .field("verifier", &"<adapter>")
            .finish()
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl<'a, SP, PV, FV> Clone for PolynomialOnlineServices<'a, SP, PV, FV> {
    fn clone(&self) -> Self {
        *self
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl<'a, SP, PV, FV> Copy for PolynomialOnlineServices<'a, SP, PV, FV> {}

/// Local strict private signing backend for tests and development.
///
/// This backend executes the strict no-rejected-z phase order without clear
/// partial-response transport. It still evaluates the private circuit locally
/// and is therefore dev/test-only.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub struct LocalStrictPolynomialSigningBackend<SP> {
    /// Public key bytes for final candidate encoding.
    pub public_key: Vec<u8>,
    /// Aggregation mode.
    pub aggregation: PolynomialAggregation,
    /// Local share provider.
    pub share_provider: SP,
    /// Phase driver used for tests/diagnostics.
    pub driver: StrictSigningPhaseDriver,
    /// Inner private response-check phase driver used for tests/diagnostics.
    pub response_driver: StrictResponseCheckPhaseDriver,
    /// Last public strict-signing evidence emitted by this local harness.
    pub last_evidence: Option<StrictSigningEvidence>,
}

/// Local dev/test response-bound checker.
///
/// This keeps local predicate results inside the gated dev module. Production
/// implementations must keep the corresponding bits inside the MPC backend.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Default, Eq, PartialEq)]
pub struct LocalStrictResponseBoundCheckBackend {
    local_results: Vec<bool>,
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl fmt::Debug for LocalStrictResponseBoundCheckBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalStrictResponseBoundCheckBackend")
            .field("result_count", &self.local_results.len())
            .finish()
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl LocalStrictResponseBoundCheckBackend {
    /// Creates an empty local bound checker.
    pub const fn new() -> Self {
        Self {
            local_results: Vec::new(),
        }
    }

    fn take_local_results(&mut self) -> Vec<bool> {
        core::mem::take(&mut self.local_results)
    }
}

/// Local dev/test hint checker.
///
/// This keeps local predicate results inside the gated dev module. Production
/// implementations must keep the corresponding bits inside the MPC backend.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Default, Eq, PartialEq)]
pub struct LocalStrictHintCheckBackend {
    local_results: Vec<bool>,
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl fmt::Debug for LocalStrictHintCheckBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalStrictHintCheckBackend")
            .field("result_count", &self.local_results.len())
            .finish()
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl LocalStrictHintCheckBackend {
    /// Creates an empty local hint checker.
    pub const fn new() -> Self {
        Self {
            local_results: Vec::new(),
        }
    }

    fn take_local_results(&mut self) -> Vec<bool> {
        core::mem::take(&mut self.local_results)
    }
}

/// Local strict candidate after private predicates have been evaluated.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Eq, PartialEq)]
pub struct LocalStrictSelectionCandidate {
    /// Public priority for this candidate.
    pub priority: crate::online::StrictCandidatePriority,
    /// Final signature candidate.
    pub signature: FinalSignature,
    pass: bool,
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl fmt::Debug for LocalStrictSelectionCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalStrictSelectionCandidate")
            .field("priority", &self.priority)
            .field("signature_len", &self.signature.bytes.len())
            .finish()
    }
}

/// Local dev/test private selection backend.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Default, Eq, PartialEq)]
pub struct LocalStrictPrivateSelectionBackend {
    local_selected: Option<crate::online::StrictCandidatePriority>,
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl fmt::Debug for LocalStrictPrivateSelectionBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalStrictPrivateSelectionBackend")
            .field("selected", &self.local_selected.is_some())
            .finish()
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl LocalStrictPrivateSelectionBackend {
    /// Creates an empty local selector.
    pub const fn new() -> Self {
        Self {
            local_selected: None,
        }
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl StrictPrivateSelectionBackend for LocalStrictPrivateSelectionBackend {
    type Candidate = LocalStrictSelectionCandidate;

    fn select_candidate(
        &mut self,
        metadata: &[crate::online::StrictCandidateMetadata],
        mut candidates: Vec<Self::Candidate>,
        driver: &mut StrictResponseCheckPhaseDriver,
    ) -> Result<(Self::Candidate, StrictPrivateSelectionEvidence), OnlineError> {
        if metadata.len() != candidates.len() {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        driver.accept_private_pass_bits(candidates.len())?;
        let selected = candidates
            .iter()
            .filter(|candidate| candidate.pass)
            .map(|candidate| candidate.priority)
            .min();
        driver.accept_priority_selection(selected.is_some())?;
        let selected_priority = selected.ok_or(OnlineError::GenericBatchFailure)?;
        candidates.sort_by_key(|candidate| candidate.priority);
        let candidate = candidates
            .into_iter()
            .find(|candidate| candidate.pass && candidate.priority == selected_priority)
            .ok_or(OnlineError::GenericBatchFailure)?;
        self.local_selected = Some(selected_priority);
        Ok((
            candidate,
            StrictPrivateSelectionEvidence {
                token_count: metadata.len(),
                selected_priority,
            },
        ))
    }
}

/// Local dev/test selected-opening backend.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Default, Eq, PartialEq)]
pub struct LocalStrictSelectedOpeningBackend {
    opened_hash: Option<[u8; 32]>,
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl fmt::Debug for LocalStrictSelectedOpeningBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalStrictSelectedOpeningBackend")
            .field("opened", &self.opened_hash.is_some())
            .finish()
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl LocalStrictSelectedOpeningBackend {
    /// Creates an empty local selected opener.
    pub const fn new() -> Self {
        Self { opened_hash: None }
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl StrictSelectedOpeningBackend for LocalStrictSelectedOpeningBackend {
    type Candidate = LocalStrictSelectionCandidate;

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

#[cfg(any(test, feature = "paper-fast-dev"))]
impl<P: MlDsaParams> StrictHintCheckBackend<P> for LocalStrictHintCheckBackend {
    type ResponseVector = PolynomialResponse;

    fn check_hints(
        &mut self,
        metadata: &[crate::online::StrictCandidateMetadata],
        responses: Vec<Self::ResponseVector>,
        public_key: &[u8],
        w1_vectors: &[&[u32]],
        driver: &mut StrictResponseCheckPhaseDriver,
    ) -> Result<(Vec<Self::ResponseVector>, StrictHintCheckEvidence), OnlineError> {
        if metadata.len() != responses.len() || responses.len() != w1_vectors.len() {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        self.local_results.clear();
        let decoded = public_key_decode::<P>(public_key)?;
        for (response, w1) in responses.iter().zip(w1_vectors) {
            let ok = match az_from_rho::<P>(&decoded.rho, &response.z) {
                Ok(az) => public_approx_from_az::<P>(&az, &response.ctilde, &decoded.t1)
                    .map_err(OnlineError::from)
                    .and_then(|approx| {
                        compute_talus_hint_polyvec::<P>(&approx, w1).map_err(OnlineError::from)
                    })
                    .and_then(|hints| {
                        signature_encode::<P>(&response.ctilde, &response.z, &hints)
                            .map_err(OnlineError::from)
                    })
                    .is_ok(),
                Err(_) => false,
            };
            self.local_results.push(ok);
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

#[cfg(any(test, feature = "paper-fast-dev"))]
impl<P: MlDsaParams> StrictResponseBoundCheckBackend<P> for LocalStrictResponseBoundCheckBackend {
    type ResponseVector = PolyVec;

    fn check_response_bounds(
        &mut self,
        metadata: &[crate::online::StrictCandidateMetadata],
        responses: Vec<Self::ResponseVector>,
        driver: &mut StrictResponseCheckPhaseDriver,
    ) -> Result<(Vec<Self::ResponseVector>, StrictResponseBoundEvidence), OnlineError> {
        if metadata.len() != responses.len() {
            return Err(OnlineError::StrictResponseCheckShapeMismatch);
        }
        self.local_results.clear();
        self.local_results
            .extend(responses.iter().map(z_bound_holds::<P>));
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

#[cfg(any(test, feature = "paper-fast-dev"))]
impl<SP> LocalStrictPolynomialSigningBackend<SP> {
    /// Creates a local strict backend.
    pub fn new(
        public_key: Vec<u8>,
        aggregation: PolynomialAggregation,
        share_provider: SP,
    ) -> Self {
        Self {
            public_key,
            aggregation,
            share_provider,
            driver: StrictSigningPhaseDriver::new(),
            response_driver: StrictResponseCheckPhaseDriver::new(),
            last_evidence: None,
        }
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl<P, SP> StrictPrivateSigningBackend<P> for LocalStrictPolynomialSigningBackend<SP>
where
    P: MlDsaParams,
    SP: PolynomialShareProvider,
{
    fn sign_consumed_batch(
        &mut self,
        request: &StrictSignRequest,
        tr: &[u8; 64],
        batch: ConsumedBccCertifiedTokenBatch,
    ) -> Result<StrictSelectedSignature, OnlineError> {
        self.driver = StrictSigningPhaseDriver::new();
        self.response_driver = StrictResponseCheckPhaseDriver::new();
        let token_count = batch.len();
        self.driver.accept_consumed_batch(token_count)?;

        let mut candidates = Vec::with_capacity(token_count);
        for token in batch.tokens() {
            let metadata = strict_candidate_metadata::<P>(request, token, tr);
            let challenge = ChallengeMaterial {
                mu: metadata.mu,
                encoded_w1: Vec::new(),
                ctilde: metadata.ctilde.clone(),
            };
            candidates.push((token, metadata, challenge));
        }
        self.response_driver.accept_metadata(candidates.len())?;
        self.driver.accept_challenges(candidates.len())?;

        let mut responses = Vec::with_capacity(candidates.len());
        for (token, metadata, challenge) in &candidates {
            let mut partials = Vec::with_capacity(token.signer_set.len());
            for &party in &token.signer_set {
                let share = self.share_provider.signing_share(token.session_id, party)?;
                if share.party != party {
                    return Err(OnlineError::Blame(party));
                }
                partials.push(compute_polynomial_partial::<P>(
                    token.session_id,
                    party,
                    challenge,
                    &share.y_share,
                    &share.s1_share,
                )?);
            }
            responses.push((token, metadata, challenge, partials));
        }
        self.response_driver
            .accept_shared_responses(responses.len())?;
        self.driver.accept_private_responses(responses.len())?;

        let mut assembled = Vec::with_capacity(responses.len());
        for (token, metadata, challenge, partials) in responses {
            let response = match self.aggregation {
                PolynomialAggregation::Additive => assemble_polynomial_response::<P>(
                    token.session_id,
                    &token.signer_set,
                    challenge,
                    &partials,
                ),
                PolynomialAggregation::LagrangeAtZero => {
                    assemble_polynomial_response_lagrange::<P>(
                        token.session_id,
                        &token.signer_set,
                        challenge,
                        &partials,
                    )
                }
            };
            assembled.push((token, metadata, response));
        }

        let response_vectors: Vec<PolyVec> = assembled
            .iter()
            .map(|(_, _, response)| {
                response
                    .as_ref()
                    .map(|response| response.z.clone())
                    .unwrap_or_else(|_| PolyVec::zero(P::L))
            })
            .collect();
        let metadata: Vec<_> = assembled
            .iter()
            .map(|(_, metadata, _)| (*metadata).clone())
            .collect();
        let mut bound_checker = LocalStrictResponseBoundCheckBackend::new();
        let (_response_vectors, bound_evidence) = <LocalStrictResponseBoundCheckBackend as StrictResponseBoundCheckBackend<
            P,
        >>::check_response_bounds(
            &mut bound_checker,
            &metadata,
            response_vectors,
            &mut self.response_driver,
        )?;
        bound_evidence.validate_for_batch::<P>(token_count)?;
        let bound_results = bound_checker.take_local_results();

        let hint_responses: Vec<PolynomialResponse> = assembled
            .iter()
            .map(|(_, metadata, response)| {
                response
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|_| PolynomialResponse {
                        ctilde: metadata.ctilde.clone(),
                        z: PolyVec::zero(P::L),
                    })
            })
            .collect();
        let w1_vectors: Vec<&[u32]> = assembled
            .iter()
            .map(|(token, _, _)| token.w1.as_slice())
            .collect();
        let mut hint_checker = LocalStrictHintCheckBackend::new();
        let (_hint_responses, hint_evidence) =
            <LocalStrictHintCheckBackend as StrictHintCheckBackend<P>>::check_hints(
                &mut hint_checker,
                &metadata,
                hint_responses,
                &self.public_key,
                &w1_vectors,
                &mut self.response_driver,
            )?;
        hint_evidence.validate_for_batch::<P>(token_count)?;
        let hint_results = hint_checker.take_local_results();

        let mut selection_candidates = Vec::new();
        for (((token, metadata, response), bound_ok), hint_ok) in
            assembled.into_iter().zip(bound_results).zip(hint_results)
        {
            let priority = metadata.priority;
            let signature = response
                .ok()
                .and_then(|response| {
                    encode_final_signature_candidate_with_az::<P>(
                        &response,
                        &self.public_key,
                        &token.w1,
                    )
                    .ok()
                })
                .unwrap_or_else(|| FinalSignature { bytes: Vec::new() });
            selection_candidates.push(LocalStrictSelectionCandidate {
                priority,
                signature,
                pass: bound_ok && hint_ok,
            });
        }
        let mut selector = LocalStrictPrivateSelectionBackend::new();
        let (selected, selection_evidence) = selector.select_candidate(
            &metadata,
            selection_candidates,
            &mut self.response_driver,
        )?;
        selection_evidence.validate_for_batch(token_count)?;
        self.driver.accept_private_checks(token_count)?;
        self.driver.accept_private_selection(true)?;

        let mut selected_opener = LocalStrictSelectedOpeningBackend::new();
        let (signature, opening_evidence) = selected_opener.open_selected(
            &selection_evidence,
            selected,
            &mut self.response_driver,
        )?;
        opening_evidence.validate_for_selection(&selection_evidence)?;
        let selected_priority = opening_evidence.selected_priority;
        self.driver.accept_selected_opening()?;
        let evidence = StrictSigningEvidence {
            token_count,
            response_check_counters: self.response_driver.counters()?,
            selected_priority,
            signature_hash: opening_evidence.signature_hash,
            transcript_hash: local_strict_transcript_hash(
                request,
                token_count,
                selected_priority,
                &signature,
            ),
        };
        self.last_evidence = Some(evidence.clone());
        Ok(StrictSelectedSignature {
            evidence,
            signature,
            vector_runtime_certificate: None,
        })
    }
}

#[cfg(any(test, feature = "paper-fast-dev"))]
fn local_strict_transcript_hash(
    request: &StrictSignRequest,
    token_count: usize,
    selected_priority: crate::online::StrictCandidatePriority,
    signature: &FinalSignature,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-MPC-v1/local-strict-transcript");
    hasher.update(request.protocol_version.to_le_bytes());
    hasher.update((request.suite.len() as u64).to_le_bytes());
    hasher.update(request.suite.as_bytes());
    hasher.update((request.signing_set.len() as u64).to_le_bytes());
    for party in &request.signing_set {
        hasher.update(party.0.to_le_bytes());
    }
    hasher.update((token_count as u64).to_le_bytes());
    hasher.update(selected_priority.0);
    hasher.update(strict_signature_hash(signature));
    hasher.finalize().into()
}

/// Computes one typed polynomial partial response.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub fn compute_polynomial_partial<P: MlDsaParams>(
    session_id: SessionId,
    party: PartyId,
    challenge: &ChallengeMaterial,
    y_share: &PolyVec,
    s1_share: &PolyVec,
) -> Result<PolynomialPartialSignature, OnlineError> {
    let z_share = partial_z_share::<P>(&challenge.ctilde, y_share, s1_share)?;
    Ok(PolynomialPartialSignature {
        session_id,
        party,
        z_share,
        challenge: challenge.ctilde.clone(),
    })
}

/// Validates and aggregates typed polynomial partial responses.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub fn assemble_polynomial_response<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
    challenge: &ChallengeMaterial,
    partials: &[PolynomialPartialSignature],
) -> Result<PolynomialResponse, OnlineError> {
    if partials.len() != signer_set.len() {
        return Err(OnlineError::PartialCountMismatch {
            expected: signer_set.len(),
            got: partials.len(),
        });
    }

    let mut z_shares = Vec::with_capacity(partials.len());
    for (&expected_party, partial) in signer_set.iter().zip(partials) {
        if partial.session_id != session_id
            || partial.party != expected_party
            || partial.challenge != challenge.ctilde
        {
            return Err(OnlineError::Blame(expected_party));
        }
        z_shares.push(partial.z_share.clone());
    }

    let z = aggregate_z_shares::<P>(&z_shares)?;
    if !z_bound_holds::<P>(&z) {
        return Err(OnlineError::ZNormExceeded {
            norm: infinity_norm::<P>(&z),
            bound: P::GAMMA1 - P::BETA,
        });
    }

    Ok(PolynomialResponse {
        ctilde: challenge.ctilde.clone(),
        z,
    })
}

/// Validates and aggregates Shamir-style typed partial responses at zero using
/// party ids as interpolation points.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub fn assemble_polynomial_response_lagrange<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
    challenge: &ChallengeMaterial,
    partials: &[PolynomialPartialSignature],
) -> Result<PolynomialResponse, OnlineError> {
    if partials.len() != signer_set.len() {
        return Err(OnlineError::PartialCountMismatch {
            expected: signer_set.len(),
            got: partials.len(),
        });
    }

    let mut points = Vec::with_capacity(partials.len());
    let mut z_shares = Vec::with_capacity(partials.len());
    for (&expected_party, partial) in signer_set.iter().zip(partials) {
        if partial.session_id != session_id
            || partial.party != expected_party
            || partial.challenge != challenge.ctilde
        {
            return Err(OnlineError::Blame(expected_party));
        }
        points.push(u32::from(expected_party.0));
        z_shares.push(partial.z_share.clone());
    }

    let z = aggregate_z_shares_lagrange::<P>(&points, &z_shares)?;
    if !z_bound_holds::<P>(&z) {
        return Err(OnlineError::ZNormExceeded {
            norm: infinity_norm::<P>(&z),
            bound: P::GAMMA1 - P::BETA,
        });
    }

    Ok(PolynomialResponse {
        ctilde: challenge.ctilde.clone(),
        z,
    })
}

/// Computes public TALUS hints and encodes a final FIPS signature candidate.
///
/// The returned candidate is not safe to output until an independent FIPS
/// verifier accepts it.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub fn encode_final_signature_candidate<P: MlDsaParams>(
    response: &PolynomialResponse,
    public_approx: &PolyVec,
    w1: &[u32],
) -> Result<FinalSignature, OnlineError> {
    if !z_bound_holds::<P>(&response.z) {
        return Err(OnlineError::ZNormExceeded {
            norm: infinity_norm::<P>(&response.z),
            bound: P::GAMMA1 - P::BETA,
        });
    }

    let hints = compute_talus_hint_polyvec::<P>(public_approx, w1)?;
    let bytes = signature_encode::<P>(&response.ctilde, &response.z, &hints)?;
    Ok(FinalSignature { bytes })
}

/// Encodes a final FIPS signature candidate from decoded public key bytes and
/// externally computed `A*z`.
///
/// This is the current boundary before the `ExpandA/NTT` adapter lands: callers
/// provide `az`, while this helper decodes `t1`, computes
/// `w'_approx = az - c*t1*2^d`, computes hints, and encodes the candidate.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub fn encode_final_signature_candidate_from_public_key<P: MlDsaParams>(
    response: &PolynomialResponse,
    public_key: &[u8],
    az: &PolyVec,
    w1: &[u32],
) -> Result<FinalSignature, OnlineError> {
    let public_key = public_key_decode::<P>(public_key)?;
    let public_approx = public_approx_from_az::<P>(az, &response.ctilde, &public_key.t1)?;
    encode_final_signature_candidate::<P>(response, &public_approx, w1)
}

/// Encodes a final FIPS signature candidate by deriving `A*z` from the public
/// key seed and typed response.
///
/// The returned candidate is still gated by independent final verification
/// before any signing API may output it.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub fn encode_final_signature_candidate_with_az<P: MlDsaParams>(
    response: &PolynomialResponse,
    public_key: &[u8],
    w1: &[u32],
) -> Result<FinalSignature, OnlineError> {
    let public_key = public_key_decode::<P>(public_key)?;
    let az = az_from_rho::<P>(&public_key.rho, &response.z)?;
    let public_approx = public_approx_from_az::<P>(&az, &response.ctilde, &public_key.t1)?;
    encode_final_signature_candidate::<P>(response, &public_approx, w1)
}

/// Consumes a certified token and produces a verified final signature.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub fn sign_with_token<
    P: MlDsaParams,
    PS: PartialSigner,
    SA: SignatureAssembler,
    FV: FinalVerifier,
    CS: TokenConsumptionStore,
>(
    pool: &mut TokenPool,
    consumed: &mut CS,
    counters: &mut SigningCounters,
    request: &SignRequest,
    services: OnlineServices<'_, PS, SA, FV>,
) -> Result<FinalSignature, OnlineError> {
    counters.attempts += 1;
    if consumed.is_consumed(request.session_id) {
        return Err(OnlineError::TokenAlreadyConsumed(request.session_id));
    }

    let mut token = pool.take_certified(request.session_id)?;
    validate_sign_request::<P>(request, &token)?;

    let challenge = compute_challenge_material::<P>(request, &token, services.tr);
    consumed.persist_consumed(token.session_id)?;
    counters.tokens_consumed += 1;

    let mut partials = Vec::with_capacity(token.signer_set.len());
    for &party in &token.signer_set {
        let partial = services.partial_signer.sign_partial(
            token.session_id,
            party,
            &challenge,
            token.y_share.as_slice(),
        )?;
        if partial.session_id != token.session_id
            || partial.party != party
            || partial.challenge != challenge.ctilde
        {
            return Err(OnlineError::Blame(party));
        }
        partials.push(partial);
    }
    token.y_share.zeroize();

    let signature = services
        .assembler
        .assemble(request, &challenge, &partials)?;
    if !services.verifier.verify_final(request, &signature) {
        counters.final_verify_failures += 1;
        return Err(OnlineError::FinalVerifyFailed);
    }

    counters.signatures_returned += 1;
    Ok(signature)
}

/// Consumes a certified token and produces a verified final signature using
/// typed polynomial `y_i` and `s1_i` shares.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub fn sign_polynomial_with_token<
    P: MlDsaParams,
    SP: PolynomialShareProvider,
    PV: PolynomialPartialVerifier,
    FV: FinalVerifier,
    CS: TokenConsumptionStore,
>(
    pool: &mut TokenPool,
    consumed: &mut CS,
    counters: &mut SigningCounters,
    request: &SignRequest,
    services: PolynomialOnlineServices<'_, SP, PV, FV>,
) -> Result<FinalSignature, OnlineError> {
    counters.attempts += 1;
    if consumed.is_consumed(request.session_id) {
        return Err(OnlineError::TokenAlreadyConsumed(request.session_id));
    }

    let mut token = pool.take_certified(request.session_id)?;
    validate_sign_request::<P>(request, &token)?;

    let challenge = compute_challenge_material::<P>(request, &token, services.tr);
    consumed.persist_consumed(token.session_id)?;
    counters.tokens_consumed += 1;

    let mut partials = Vec::with_capacity(token.signer_set.len());
    for &party in &token.signer_set {
        let share = services
            .share_provider
            .signing_share(token.session_id, party)?;
        if share.party != party {
            return Err(OnlineError::Blame(party));
        }

        let partial = compute_polynomial_partial::<P>(
            token.session_id,
            party,
            &challenge,
            &share.y_share,
            &share.s1_share,
        )?;
        services.partial_verifier.verify_partial::<P>(
            services.public_key,
            token.session_id,
            &challenge,
            &partial,
        )?;
        partials.push(partial);
    }
    token.y_share.zeroize();

    let response = match services.aggregation {
        PolynomialAggregation::Additive => assemble_polynomial_response::<P>(
            token.session_id,
            &token.signer_set,
            &challenge,
            &partials,
        )?,
        PolynomialAggregation::LagrangeAtZero => assemble_polynomial_response_lagrange::<P>(
            token.session_id,
            &token.signer_set,
            &challenge,
            &partials,
        )?,
    };
    let signature =
        encode_final_signature_candidate_with_az::<P>(&response, services.public_key, &token.w1)?;
    if !services.verifier.verify_final(request, &signature) {
        counters.final_verify_failures += 1;
        return Err(OnlineError::FinalVerifyFailed);
    }

    counters.signatures_returned += 1;
    Ok(signature)
}

/// Runs online signing attempts until a verified signature is returned or the
/// retry policy is exhausted.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub fn sign_with_retry<
    P: MlDsaParams,
    PS: PartialSigner,
    SA: SignatureAssembler,
    FV: FinalVerifier,
    CS: TokenConsumptionStore,
>(
    pool: &mut TokenPool,
    consumed: &mut CS,
    counters: &mut SigningCounters,
    requests: &[SignRequest],
    services: OnlineServices<'_, PS, SA, FV>,
    policy: RetryPolicy,
) -> Result<FinalSignature, OnlineError> {
    for request in requests.iter().take(policy.max_attempts) {
        match sign_with_token::<P, _, _, _, _>(pool, consumed, counters, request, services) {
            Ok(signature) => return Ok(signature),
            Err(OnlineError::FinalVerifyFailed) => continue,
            Err(err) => return Err(err),
        }
    }

    counters.retry_exhausted += 1;
    Err(OnlineError::RetryExhausted)
}

/// Runs typed polynomial online signing attempts until a verified signature is
/// returned or the retry policy is exhausted.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub fn sign_polynomial_with_retry<
    P: MlDsaParams,
    SP: PolynomialShareProvider,
    PV: PolynomialPartialVerifier,
    FV: FinalVerifier,
    CS: TokenConsumptionStore,
>(
    pool: &mut TokenPool,
    consumed: &mut CS,
    counters: &mut SigningCounters,
    requests: &[SignRequest],
    services: PolynomialOnlineServices<'_, SP, PV, FV>,
    policy: RetryPolicy,
) -> Result<FinalSignature, OnlineError> {
    for request in requests.iter().take(policy.max_attempts) {
        match sign_polynomial_with_token::<P, _, _, _, _>(
            pool, consumed, counters, request, services,
        ) {
            Ok(signature) => return Ok(signature),
            Err(OnlineError::FinalVerifyFailed) => continue,
            Err(err) => return Err(err),
        }
    }

    counters.retry_exhausted += 1;
    Err(OnlineError::RetryExhausted)
}
#[cfg(any(test, feature = "paper-fast-dev"))]
fn validate_public_commitment_len<P: MlDsaParams>(
    party: PartyId,
    commitment: &PolyVec,
) -> Result<(), OnlineError> {
    if commitment.len() != P::K {
        return Err(OnlineError::PublicCommitmentLength {
            party,
            expected: P::K,
            got: commitment.len(),
        });
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    #![cfg_attr(feature = "production-release-checks", allow(unused_imports))]

    use super::*;
    use crate::local::{
        certify_preprocessing_token, CertifiedToken, Commitment, NonceCommitment,
        PartyPreprocessInput, SessionRegistry, TranscriptHash,
    };
    #[cfg(feature = "std")]
    use crate::online::FileConsumedTokenStore;
    use crate::online::{
        sign_strict_no_rejected_z, BccCertifiedTokenBatch, ConsumedTokenStore, FipsFinalVerifier,
        StrictCandidatePriority, StrictSelectedOpeningBackend, StrictSigningPhase,
        ONLINE_PROTOCOL_VERSION,
    };
    use core::cell::{Cell, RefCell};
    use fips204::traits::{KeyGen, SerDes, Signer};
    use std::rc::Rc;
    use talus_core::{
        MlDsa65, NttError, Poly, PolyVec, PublicKeyDecodeError, SignatureEncodingError,
    };
    use talus_dkg::{
        BoundedSecretVectorShare, DkgError, DkgKeyPackage, DkgS1SecretShare, KeygenEpoch,
        Power2RoundBackendId, Power2RoundEvidence, PublicKeyAssemblyCertificate, PublicT1,
    };

    struct TestPartialSigner;

    impl PartialSigner for TestPartialSigner {
        fn sign_partial(
            &self,
            _session_id: SessionId,
            party: PartyId,
            challenge: &ChallengeMaterial,
            y_share: &[u8],
        ) -> Result<PartialSignature, OnlineError> {
            if y_share.is_empty() {
                return Err(OnlineError::PartialSignerFailed(party));
            }
            Ok(PartialSignature {
                session_id: SessionId([8; 32]),
                party,
                z_share: challenge.ctilde[..8].to_vec(),
                challenge: challenge.ctilde.clone(),
            })
        }
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

    #[derive(Clone, Default)]
    struct RecordingPartialSigner {
        observed_z_shares: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl PartialSigner for RecordingPartialSigner {
        fn sign_partial(
            &self,
            session_id: SessionId,
            party: PartyId,
            challenge: &ChallengeMaterial,
            y_share: &[u8],
        ) -> Result<PartialSignature, OnlineError> {
            let mut z_share = Vec::new();
            z_share.extend_from_slice(&challenge.ctilde[..8]);
            z_share.extend_from_slice(&(party.0).to_le_bytes().as_slice());
            z_share.extend_from_slice(y_share);
            self.observed_z_shares.borrow_mut().push(z_share.clone());
            Ok(PartialSignature {
                session_id,
                party,
                z_share,
                challenge: challenge.ctilde.clone(),
            })
        }
    }

    #[derive(Clone, Default)]
    struct RecordingAssembler {
        observed_partial_z_shares: Rc<RefCell<Vec<Vec<u8>>>>,
        observed_candidate: Rc<RefCell<Option<Vec<u8>>>>,
    }

    impl SignatureAssembler for RecordingAssembler {
        fn assemble(
            &self,
            _request: &SignRequest,
            challenge: &ChallengeMaterial,
            partials: &[PartialSignature],
        ) -> Result<FinalSignature, OnlineError> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&challenge.ctilde);
            for partial in partials {
                self.observed_partial_z_shares
                    .borrow_mut()
                    .push(partial.z_share.clone());
                bytes.extend_from_slice(&partial.z_share);
            }
            *self.observed_candidate.borrow_mut() = Some(bytes.clone());
            Ok(FinalSignature { bytes })
        }
    }

    struct FailThenAcceptVerifier {
        calls: Cell<u32>,
    }

    impl FinalVerifier for FailThenAcceptVerifier {
        fn verify_final(&self, _request: &SignRequest, _signature: &FinalSignature) -> bool {
            let calls = self.calls.get();
            self.calls.set(calls + 1);
            calls != 0
        }
    }

    struct TestPolynomialShareProvider {
        shares: Vec<PolynomialSigningShare>,
        misbind_party: bool,
    }

    impl PolynomialShareProvider for TestPolynomialShareProvider {
        fn signing_share(
            &self,
            _session_id: SessionId,
            party: PartyId,
        ) -> Result<PolynomialSigningShare, OnlineError> {
            let Some(share) = self.shares.iter().find(|share| share.party == party) else {
                return Err(OnlineError::PartialSignerFailed(party));
            };

            let mut share = share.clone();
            if self.misbind_party {
                share.party = PartyId(share.party.0 + 100);
            }
            Ok(share)
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

    fn token_and_request() -> (CertifiedToken, SignRequest) {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(9),
            vec![input(1), input(2)],
        )
        .expect("test token certifies");
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

    fn token_and_request_for(byte: u8) -> (CertifiedToken, SignRequest) {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(byte),
            vec![input(1), input(2)],
        )
        .expect("test token certifies");
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

    fn poly_with_coeffs(coeffs: &[(usize, i32)]) -> Poly {
        let mut poly = Poly::zero();
        for &(index, coeff) in coeffs {
            poly.coeffs_mut()[index] = coeff;
        }
        poly
    }

    fn polyvec_with_const(value: i32) -> PolyVec {
        PolyVec::new(vec![poly_with_coeffs(&[(0, value)]); MlDsa65::L])
    }

    fn zero_polynomial_share_provider(signers: &[PartyId]) -> TestPolynomialShareProvider {
        TestPolynomialShareProvider {
            shares: signers
                .iter()
                .map(|&party| PolynomialSigningShare {
                    party,
                    y_share: PolyVec::zero(MlDsa65::L),
                    s1_share: PolyVec::zero(MlDsa65::L),
                })
                .collect(),
            misbind_party: false,
        }
    }

    fn dkg_config() -> DkgConfig {
        DkgConfig::new::<MlDsa65>(2, vec![PartyId(1), PartyId(2), PartyId(3)], KeygenEpoch(7))
            .expect("valid DKG config")
    }

    fn dkg_secret_share(config: &DkgConfig, party: PartyId, coeffs: Vec<i32>) -> DkgSecretShare {
        let point = config
            .interpolation_point::<MlDsa65>(party)
            .expect("configured party");
        let s1_share = BoundedSecretVectorShare::new::<MlDsa65>(config, party, point, coeffs)
            .expect("typed s1 share")
            .encode::<MlDsa65>(config)
            .expect("encoded s1 share");

        DkgSecretShare {
            party,
            s1_share,
            s2_share: vec![1],
            t0_share: vec![1],
            pairwise_seed_shares: vec![vec![1]],
        }
    }

    fn zero_dkg_secret_share(config: &DkgConfig, party: PartyId) -> DkgSecretShare {
        dkg_secret_share(config, party, vec![0; MlDsa65::L * MlDsa65::N])
    }

    fn dkg_key_package_from_secret(config: &DkgConfig, secret: DkgSecretShare) -> DkgKeyPackage {
        DkgKeyPackage {
            suite: config.suite,
            epoch: config.epoch,
            party: secret.party,
            threshold: config.threshold,
            rho: [0u8; 32],
            t1: PublicT1 {
                bytes: vec![0; config.suite.t1_len()],
                coeffs: Vec::new(),
            },
            public_key: vec![0; config.suite.public_key_len()],
            s1_share: DkgS1SecretShare {
                party: secret.party,
                s1_share: secret.s1_share,
                pairwise_seed_shares: secret.pairwise_seed_shares,
            },
            certificate: PublicKeyAssemblyCertificate {
                power2round: Power2RoundEvidence {
                    backend_id: Power2RoundBackendId::ProductionItMpc,
                    epoch: config.epoch,
                    suite: config.suite,
                    party_set_hash: [0u8; 32],
                    rho_hash: [0u8; 32],
                    output_t1_hash: [0u8; 32],
                    transcript_hash: [0u8; 32],
                },
                power2round_runtime: None,
                power2round_setup_input_hash: None,
                setup: None,
            },
        }
    }

    fn commitment_verifier_for(
        public_key: &[u8],
        shares: &[PolynomialSigningShare],
    ) -> CommitmentBackedPartialVerifier {
        let public_key = public_key_decode::<MlDsa65>(public_key).expect("decode test pk");
        CommitmentBackedPartialVerifier::new(
            shares
                .iter()
                .map(|share| PolynomialPartialCommitment {
                    party: share.party,
                    ay_commitment: az_from_rho::<MlDsa65>(&public_key.rho, &share.y_share)
                        .expect("A*y commitment"),
                    as1_commitment: az_from_rho::<MlDsa65>(&public_key.rho, &share.s1_share)
                        .expect("A*s1 commitment"),
                })
                .collect(),
        )
    }

    fn zero_w1_token_and_request() -> (CertifiedToken, SignRequest) {
        let (mut token, request) = token_and_request();
        token.w1.fill(0);
        (token, request)
    }

    #[cfg(feature = "std")]
    fn test_store_path(name: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "talus-consumed-{name}-{}-{unique}.log",
            std::process::id()
        ))
    }

    #[test]
    fn sign_request_validation_rejects_mismatch() {
        let (token, mut request) = token_and_request();
        request.protocol_version = 0;
        assert_eq!(
            validate_sign_request::<MlDsa65>(&request, &token),
            Err(OnlineError::BadProtocolVersion {
                expected: ONLINE_PROTOCOL_VERSION,
                got: 0,
            })
        );
    }

    #[test]
    fn challenge_material_is_stable_and_bound_to_w1() {
        let (mut token, request) = token_and_request();
        let tr = [0x42; 64];
        let first = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let second = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        assert_eq!(first, second);

        token.w1[0] ^= 1;
        let changed = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        assert_ne!(first.ctilde, changed.ctilde);
    }

    #[test]
    fn commitment_backed_partial_verifier_accepts_matching_commitment() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let share = PolynomialSigningShare {
            party: PartyId(1),
            y_share: polyvec_with_const(3),
            s1_share: polyvec_with_const(2),
        };
        let partial = compute_polynomial_partial::<MlDsa65>(
            token.session_id,
            share.party,
            &challenge,
            &share.y_share,
            &share.s1_share,
        )
        .expect("partial");
        let verifier = commitment_verifier_for(&public_key, &[share]);

        verifier
            .verify_partial::<MlDsa65>(&public_key, token.session_id, &challenge, &partial)
            .expect("partial verifies");
    }

    #[test]
    fn commitment_backed_partial_verifier_blames_bad_partial() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let share = PolynomialSigningShare {
            party: PartyId(1),
            y_share: polyvec_with_const(3),
            s1_share: polyvec_with_const(2),
        };
        let mut partial = compute_polynomial_partial::<MlDsa65>(
            token.session_id,
            share.party,
            &challenge,
            &share.y_share,
            &share.s1_share,
        )
        .expect("partial");
        partial.z_share.polys_mut()[0].coeffs_mut()[0] ^= 1;
        let verifier = commitment_verifier_for(&public_key, &[share]);

        assert_eq!(
            verifier
                .verify_partial::<MlDsa65>(&public_key, token.session_id, &challenge, &partial,),
            Err(OnlineError::Blame(PartyId(1)))
        );
    }

    #[test]
    fn commitment_backed_partial_verifier_rejects_missing_commitment() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let partial = PolynomialPartialSignature {
            session_id: token.session_id,
            party: PartyId(1),
            z_share: PolyVec::zero(MlDsa65::L),
            challenge: challenge.ctilde.clone(),
        };

        assert_eq!(
            CommitmentBackedPartialVerifier::default().verify_partial::<MlDsa65>(
                &public_key,
                token.session_id,
                &challenge,
                &partial,
            ),
            Err(OnlineError::PublicCommitmentMissing(PartyId(1)))
        );
    }

    #[test]
    fn commitment_backed_partial_verifier_rejects_bad_commitment_length() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let partial = PolynomialPartialSignature {
            session_id: token.session_id,
            party: PartyId(1),
            z_share: PolyVec::zero(MlDsa65::L),
            challenge: challenge.ctilde.clone(),
        };
        let verifier = CommitmentBackedPartialVerifier::new(vec![PolynomialPartialCommitment {
            party: PartyId(1),
            ay_commitment: PolyVec::zero(MlDsa65::K - 1),
            as1_commitment: PolyVec::zero(MlDsa65::K),
        }]);

        assert_eq!(
            verifier
                .verify_partial::<MlDsa65>(&public_key, token.session_id, &challenge, &partial,),
            Err(OnlineError::PublicCommitmentLength {
                party: PartyId(1),
                expected: MlDsa65::K,
                got: MlDsa65::K - 1,
            })
        );
    }

    #[test]
    fn dkg_s1_share_decodes_to_online_polyvec_shape() {
        let config = dkg_config();
        let mut coeffs = vec![0; MlDsa65::L * MlDsa65::N];
        coeffs[0] = 5;
        coeffs[MlDsa65::N] = 7;
        coeffs[MlDsa65::L * MlDsa65::N - 1] = MlDsa65::Q - 1;
        let secret = dkg_secret_share(&config, PartyId(2), coeffs);

        let s1 = polyvec_from_dkg_s1_share::<MlDsa65>(&config, &secret)
            .expect("decode DKG s1 into online polyvec");

        assert_eq!(s1.len(), MlDsa65::L);
        assert_eq!(s1.polys()[0].coeffs()[0], 5);
        assert_eq!(s1.polys()[1].coeffs()[0], 7);
        assert_eq!(
            s1.polys()[MlDsa65::L - 1].coeffs()[MlDsa65::N - 1],
            MlDsa65::Q - 1
        );
    }

    #[test]
    fn dkg_s1_share_decode_rejects_bad_party_binding() {
        let config = dkg_config();
        let mut secret = zero_dkg_secret_share(&config, PartyId(1));
        secret.party = PartyId(2);

        assert_eq!(
            polyvec_from_dkg_s1_share::<MlDsa65>(&config, &secret),
            Err(OnlineError::Dkg(DkgError::PartyMismatch {
                expected: PartyId(2),
                got: PartyId(1),
            }))
        );
    }

    #[test]
    fn dkg_backed_provider_returns_y_and_decoded_s1() {
        let config = dkg_config();
        let session_id = session(61);
        let mut coeffs = vec![0; MlDsa65::L * MlDsa65::N];
        coeffs[3] = 11;
        let secret = dkg_secret_share(&config, PartyId(2), coeffs);
        let y_share = polyvec_with_const(13);
        let provider = DkgBackedPolynomialShareProvider::<MlDsa65>::new(
            session_id,
            config,
            vec![(PartyId(2), y_share.clone())],
            vec![secret],
        );

        let share = provider
            .signing_share(session_id, PartyId(2))
            .expect("provider returns decoded share");

        assert_eq!(share.party, PartyId(2));
        assert_eq!(share.y_share, y_share);
        assert_eq!(share.s1_share.polys()[0].coeffs()[3], 11);
    }

    #[test]
    fn dkg_backed_provider_rejects_wrong_session() {
        let config = dkg_config();
        let provider = DkgBackedPolynomialShareProvider::<MlDsa65>::new(
            session(61),
            config.clone(),
            vec![(PartyId(1), PolyVec::zero(MlDsa65::L))],
            vec![zero_dkg_secret_share(&config, PartyId(1))],
        );

        assert_eq!(
            provider.signing_share(session(62), PartyId(1)),
            Err(OnlineError::SessionMismatch)
        );
    }

    #[test]
    fn polynomial_partial_computes_and_aggregates_z() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);

        let signer_set = vec![PartyId(1), PartyId(2)];
        let first = compute_polynomial_partial::<MlDsa65>(
            token.session_id,
            PartyId(1),
            &challenge,
            &polyvec_with_const(3),
            &PolyVec::zero(MlDsa65::L),
        )
        .expect("first partial");
        let second = compute_polynomial_partial::<MlDsa65>(
            token.session_id,
            PartyId(2),
            &challenge,
            &polyvec_with_const(4),
            &PolyVec::zero(MlDsa65::L),
        )
        .expect("second partial");

        let response = assemble_polynomial_response::<MlDsa65>(
            token.session_id,
            &signer_set,
            &challenge,
            &[first, second],
        )
        .expect("aggregate polynomial response");

        assert_eq!(response.ctilde, challenge.ctilde);
        for poly in response.z.polys() {
            assert_eq!(poly.coeffs()[0], 7);
        }
    }

    #[test]
    fn polynomial_lagrange_response_interpolates_at_zero() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let signer_set = vec![PartyId(1), PartyId(2)];
        let first = PolynomialPartialSignature {
            session_id: token.session_id,
            party: PartyId(1),
            z_share: polyvec_with_const(14),
            challenge: challenge.ctilde.clone(),
        };
        let second = PolynomialPartialSignature {
            session_id: token.session_id,
            party: PartyId(2),
            z_share: polyvec_with_const(17),
            challenge: challenge.ctilde.clone(),
        };

        let response = assemble_polynomial_response_lagrange::<MlDsa65>(
            token.session_id,
            &signer_set,
            &challenge,
            &[first, second],
        )
        .expect("lagrange aggregate");

        for poly in response.z.polys() {
            assert_eq!(poly.coeffs()[0], 11);
        }
    }

    #[test]
    fn polynomial_partial_blames_wrong_binding() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let mut partial = compute_polynomial_partial::<MlDsa65>(
            token.session_id,
            PartyId(1),
            &challenge,
            &polyvec_with_const(3),
            &PolyVec::zero(MlDsa65::L),
        )
        .expect("partial");
        partial.challenge[0] ^= 1;

        assert_eq!(
            assemble_polynomial_response::<MlDsa65>(
                token.session_id,
                &[PartyId(1)],
                &challenge,
                &[partial],
            ),
            Err(OnlineError::Blame(PartyId(1)))
        );
    }

    #[test]
    fn polynomial_response_rejects_norm_failure() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let partial = PolynomialPartialSignature {
            session_id: token.session_id,
            party: PartyId(1),
            z_share: polyvec_with_const(MlDsa65::GAMMA1 - MlDsa65::BETA),
            challenge: challenge.ctilde.clone(),
        };

        assert_eq!(
            assemble_polynomial_response::<MlDsa65>(
                token.session_id,
                &[PartyId(1)],
                &challenge,
                &[partial],
            ),
            Err(OnlineError::ZNormExceeded {
                norm: MlDsa65::GAMMA1 - MlDsa65::BETA,
                bound: MlDsa65::GAMMA1 - MlDsa65::BETA,
            })
        );
    }

    #[test]
    fn polynomial_response_rejects_partial_count_mismatch() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);

        assert_eq!(
            assemble_polynomial_response::<MlDsa65>(
                token.session_id,
                &[PartyId(1)],
                &challenge,
                &[],
            ),
            Err(OnlineError::PartialCountMismatch {
                expected: 1,
                got: 0,
            })
        );
    }

    #[test]
    fn final_signature_candidate_encodes_typed_response_and_hints() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let response = PolynomialResponse {
            ctilde: challenge.ctilde.clone(),
            z: PolyVec::zero(MlDsa65::L),
        };
        let public_approx = PolyVec::zero(MlDsa65::K);
        let w1 = vec![0u32; MlDsa65::K * MlDsa65::N];

        let signature = encode_final_signature_candidate::<MlDsa65>(&response, &public_approx, &w1)
            .expect("signature candidate encodes");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert_eq!(
            &signature.bytes[..MlDsa65::CTILDE_LEN],
            response.ctilde.as_slice()
        );
    }

    #[test]
    fn final_signature_candidate_rejects_hint_weight_failure() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let response = PolynomialResponse {
            ctilde: challenge.ctilde.clone(),
            z: PolyVec::zero(MlDsa65::L),
        };
        let mut public_approx = PolyVec::zero(MlDsa65::K);
        for coeff_index in 0..=MlDsa65::OMEGA {
            public_approx.polys_mut()[0].coeffs_mut()[coeff_index] = MlDsa65::alpha();
        }
        let w1 = vec![0u32; MlDsa65::K * MlDsa65::N];

        assert_eq!(
            encode_final_signature_candidate::<MlDsa65>(&response, &public_approx, &w1),
            Err(OnlineError::SignatureEncoding(
                SignatureEncodingError::HintWeight {
                    omega: MlDsa65::OMEGA,
                    got: MlDsa65::OMEGA + 1,
                }
            ))
        );
    }

    #[test]
    fn final_signature_candidate_from_public_key_decodes_t1_and_uses_az() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let response = PolynomialResponse {
            ctilde: challenge.ctilde.clone(),
            z: PolyVec::zero(MlDsa65::L),
        };
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let az = PolyVec::zero(MlDsa65::K);
        let w1 = vec![0u32; MlDsa65::K * MlDsa65::N];

        let signature = encode_final_signature_candidate_from_public_key::<MlDsa65>(
            &response,
            &public_key,
            &az,
            &w1,
        )
        .expect("signature candidate from pk");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert_eq!(
            &signature.bytes[..MlDsa65::CTILDE_LEN],
            response.ctilde.as_slice()
        );
    }

    #[test]
    fn final_signature_candidate_from_public_key_rejects_bad_key_length() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let response = PolynomialResponse {
            ctilde: challenge.ctilde.clone(),
            z: PolyVec::zero(MlDsa65::L),
        };

        assert_eq!(
            encode_final_signature_candidate_from_public_key::<MlDsa65>(
                &response,
                &[0u8; 31],
                &PolyVec::zero(MlDsa65::K),
                &vec![0u32; MlDsa65::K * MlDsa65::N],
            ),
            Err(OnlineError::PublicKeyDecode(
                PublicKeyDecodeError::PublicKeyLength {
                    expected: MlDsa65::PK_LEN,
                    got: 31,
                }
            ))
        );
    }

    #[test]
    fn final_signature_candidate_with_az_computes_public_approx_from_key_seed() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let response = PolynomialResponse {
            ctilde: challenge.ctilde.clone(),
            z: PolyVec::zero(MlDsa65::L),
        };
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let w1 = vec![0u32; MlDsa65::K * MlDsa65::N];

        let signature =
            encode_final_signature_candidate_with_az::<MlDsa65>(&response, &public_key, &w1)
                .expect("signature candidate computes A*z");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert_eq!(
            &signature.bytes[..MlDsa65::CTILDE_LEN],
            response.ctilde.as_slice()
        );
    }

    #[test]
    fn final_signature_candidate_with_az_rejects_bad_z_shape() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let response = PolynomialResponse {
            ctilde: challenge.ctilde.clone(),
            z: PolyVec::zero(MlDsa65::L - 1),
        };
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let w1 = vec![0u32; MlDsa65::K * MlDsa65::N];

        assert_eq!(
            encode_final_signature_candidate_with_az::<MlDsa65>(&response, &public_key, &w1),
            Err(OnlineError::Ntt(NttError::ZLength {
                expected: MlDsa65::L,
                got: MlDsa65::L - 1,
            }))
        );
    }

    #[test]
    fn fips_final_verifier_accepts_real_fips_signature() {
        let message = b"message".to_vec();
        let context = b"ctx".to_vec();
        let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&[0x41; 32]);
        let signature = sk
            .try_sign_with_seed(&[0x42; 32], &message, &context)
            .expect("fips signature");
        let verifier =
            FipsFinalVerifier::<MlDsa65>::new(pk.into_bytes().to_vec()).expect("verifier");
        let request = SignRequest {
            protocol_version: ONLINE_PROTOCOL_VERSION,
            suite: MlDsa65::NAME,
            session_id: session(50),
            signing_set: vec![PartyId(1)],
            message: message.clone(),
            external_mu: None,
            context: context.clone(),
            token_transcript_hash: TranscriptHash([0; 32]),
        };

        assert!(verifier.verify_final(
            &request,
            &FinalSignature {
                bytes: signature.to_vec()
            }
        ));

        let mut bad_signature = signature.to_vec();
        bad_signature[0] ^= 1;
        assert!(!verifier.verify_final(
            &request,
            &FinalSignature {
                bytes: bad_signature
            }
        ));
    }

    #[test]
    fn fips_final_verifier_rejects_external_mu_requests() {
        let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&[0x51; 32]);
        let signature = sk
            .try_sign_with_seed(&[0x52; 32], b"message", b"ctx")
            .expect("fips signature");
        let verifier =
            FipsFinalVerifier::<MlDsa65>::new(pk.into_bytes().to_vec()).expect("verifier");
        let request = SignRequest {
            protocol_version: ONLINE_PROTOCOL_VERSION,
            suite: MlDsa65::NAME,
            session_id: session(51),
            signing_set: vec![PartyId(1)],
            message: b"message".to_vec(),
            external_mu: Some([0u8; 64]),
            context: b"ctx".to_vec(),
            token_transcript_hash: TranscriptHash([0; 32]),
        };

        assert!(!verifier.verify_final(
            &request,
            &FinalSignature {
                bytes: signature.to_vec()
            }
        ));
    }

    #[test]
    fn signing_consumes_token_and_returns_verified_signature() {
        let (token, request) = token_and_request();
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];

        let signature = sign_with_token::<MlDsa65, _, _, _, _>(
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
        .expect("valid shell signing succeeds");

        assert!(!signature.bytes.is_empty());
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
        assert_eq!(counters.tokens_consumed, 1);
        assert_eq!(counters.signatures_returned, 1);
    }

    #[test]
    fn polynomial_signing_consumes_token_and_returns_verified_candidate() {
        let (token, request) = zero_w1_token_and_request();
        let share_provider = zero_polynomial_share_provider(&token.signer_set);
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let partial_verifier = commitment_verifier_for(&public_key, &share_provider.shares);

        let signature = sign_polynomial_with_token::<MlDsa65, _, _, _, _>(
            &mut pool,
            &mut consumed,
            &mut counters,
            &request,
            PolynomialOnlineServices {
                tr: &tr,
                public_key: &public_key,
                aggregation: PolynomialAggregation::Additive,
                partial_verifier: &partial_verifier,
                share_provider: &share_provider,
                verifier: &AcceptVerifier,
            },
        )
        .expect("typed signing succeeds");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
        assert_eq!(counters.tokens_consumed, 1);
        assert_eq!(counters.signatures_returned, 1);
    }

    #[cfg(not(feature = "production-release-checks"))]
    #[test]
    fn local_strict_backend_signs_without_clear_partial_transport() {
        let (token, request) = zero_w1_token_and_request();
        let share_provider = zero_polynomial_share_provider(&token.signer_set);
        let strict_request = StrictSignRequest {
            protocol_version: request.protocol_version,
            suite: request.suite,
            signing_set: request.signing_set.clone(),
            message: request.message.clone(),
            external_mu: request.external_mu,
            context: request.context.clone(),
        };
        let expected_session = token.session_id;
        let batch = BccCertifiedTokenBatch::new(vec![token], 1).expect("strict batch");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let mut backend = LocalStrictPolynomialSigningBackend::new(
            public_key,
            PolynomialAggregation::Additive,
            share_provider,
        );

        let signature = sign_strict_no_rejected_z::<MlDsa65, _, _, _>(
            &strict_request,
            &[0x42; 64],
            batch,
            &mut consumed,
            &mut counters,
            &mut backend,
            &AcceptVerifier,
        )
        .expect("strict local backend signs");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert!(consumed.is_consumed(expected_session));
        assert_eq!(counters.tokens_consumed, 1);
        assert_eq!(counters.signatures_returned, 1);
        assert_eq!(
            backend.driver.next_phase(),
            Some(StrictSigningPhase::FinalVerify)
        );
        let evidence = backend.last_evidence.expect("strict evidence");
        assert_eq!(evidence.token_count, 1);
        assert_eq!(evidence.signature_hash, strict_signature_hash(&signature));
        assert_ne!(evidence.transcript_hash, [0u8; 32]);
        let evidence_debug = format!("{evidence:?}");
        for forbidden in ["valid_candidates", "failure", "z_share", "rejected"] {
            assert!(
                !evidence_debug.contains(forbidden),
                "strict evidence must not expose {forbidden}"
            );
        }
    }

    #[test]
    fn local_response_bound_checker_keeps_results_private_to_dev_backend() {
        let (token, request) = zero_w1_token_and_request();
        let strict_request = StrictSignRequest {
            protocol_version: request.protocol_version,
            suite: request.suite,
            signing_set: request.signing_set.clone(),
            message: request.message.clone(),
            external_mu: request.external_mu,
            context: request.context.clone(),
        };
        let metadata = vec![strict_candidate_metadata::<MlDsa65>(
            &strict_request,
            &token,
            &[0x42; 64],
        )];
        let mut response = PolyVec::zero(MlDsa65::L);
        response.polys_mut()[0].coeffs_mut()[0] = MlDsa65::GAMMA1 - MlDsa65::BETA;
        let mut checker = LocalStrictResponseBoundCheckBackend::new();
        let mut driver = StrictResponseCheckPhaseDriver::new();
        driver.accept_metadata(1).expect("metadata");
        driver.accept_shared_responses(1).expect("responses");

        let (_responses, evidence) = <LocalStrictResponseBoundCheckBackend as StrictResponseBoundCheckBackend<
            MlDsa65,
        >>::check_response_bounds(
            &mut checker, &metadata, vec![response], &mut driver
        )
        .expect("bound check");

        assert_eq!(
            evidence,
            StrictResponseBoundEvidence {
                token_count: 1,
                coefficients_per_candidate: MlDsa65::L * MlDsa65::N,
            }
        );
        assert_eq!(checker.take_local_results(), vec![false]);
        assert!(!format!("{checker:?}").contains("false"));

        let mut checker = LocalStrictResponseBoundCheckBackend::new();
        let mut driver = StrictResponseCheckPhaseDriver::new();
        driver.accept_metadata(1).expect("metadata");
        driver.accept_shared_responses(1).expect("responses");
        assert_eq!(
            <LocalStrictResponseBoundCheckBackend as StrictResponseBoundCheckBackend<
                MlDsa65,
            >>::check_response_bounds(
                &mut checker,
                &[],
                vec![PolyVec::zero(MlDsa65::L)],
                &mut driver,
            ),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        );
    }

    #[test]
    fn local_hint_checker_keeps_results_private_to_dev_backend() {
        let (token, request) = zero_w1_token_and_request();
        let strict_request = StrictSignRequest {
            protocol_version: request.protocol_version,
            suite: request.suite,
            signing_set: request.signing_set.clone(),
            message: request.message.clone(),
            external_mu: request.external_mu,
            context: request.context.clone(),
        };
        let metadata = vec![strict_candidate_metadata::<MlDsa65>(
            &strict_request,
            &token,
            &[0x42; 64],
        )];
        let response = PolynomialResponse {
            ctilde: metadata[0].ctilde.clone(),
            z: PolyVec::zero(MlDsa65::L),
        };
        let mut checker = LocalStrictHintCheckBackend::new();
        let mut driver = StrictResponseCheckPhaseDriver::new();
        driver.accept_metadata(1).expect("metadata");
        driver.accept_shared_responses(1).expect("responses");
        driver.accept_response_bounds(1).expect("bounds");

        let (_responses, evidence) =
            <LocalStrictHintCheckBackend as StrictHintCheckBackend<MlDsa65>>::check_hints(
                &mut checker,
                &metadata,
                vec![response],
                &vec![0u8; MlDsa65::PK_LEN],
                &[&token.w1],
                &mut driver,
            )
            .expect("hint check");

        assert_eq!(
            evidence,
            StrictHintCheckEvidence {
                token_count: 1,
                coefficients_per_candidate: MlDsa65::K * MlDsa65::N,
            }
        );
        assert_eq!(checker.take_local_results(), vec![true]);
        assert!(!format!("{checker:?}").contains("true"));

        let mut checker = LocalStrictHintCheckBackend::new();
        let mut driver = StrictResponseCheckPhaseDriver::new();
        driver.accept_metadata(1).expect("metadata");
        driver.accept_shared_responses(1).expect("responses");
        driver.accept_response_bounds(1).expect("bounds");
        assert_eq!(
            <LocalStrictHintCheckBackend as StrictHintCheckBackend<MlDsa65>>::check_hints(
                &mut checker,
                &metadata,
                Vec::<PolynomialResponse>::new(),
                &vec![0u8; MlDsa65::PK_LEN],
                &[&token.w1],
                &mut driver,
            ),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        );
    }

    #[test]
    fn local_private_selector_chooses_lowest_priority_valid_candidate() {
        let metadata = vec![
            crate::online::StrictCandidateMetadata {
                session_id: session(1),
                token_transcript_hash: TranscriptHash([1u8; 32]),
                priority: StrictCandidatePriority([3u8; 32]),
                mu: [0u8; 64],
                ctilde: vec![1],
                encoded_w1_hash: [1u8; 32],
            },
            crate::online::StrictCandidateMetadata {
                session_id: session(2),
                token_transcript_hash: TranscriptHash([2u8; 32]),
                priority: StrictCandidatePriority([1u8; 32]),
                mu: [0u8; 64],
                ctilde: vec![2],
                encoded_w1_hash: [2u8; 32],
            },
            crate::online::StrictCandidateMetadata {
                session_id: session(3),
                token_transcript_hash: TranscriptHash([3u8; 32]),
                priority: StrictCandidatePriority([2u8; 32]),
                mu: [0u8; 64],
                ctilde: vec![3],
                encoded_w1_hash: [3u8; 32],
            },
        ];
        let candidates = vec![
            LocalStrictSelectionCandidate {
                priority: metadata[0].priority,
                signature: FinalSignature { bytes: vec![3] },
                pass: true,
            },
            LocalStrictSelectionCandidate {
                priority: metadata[1].priority,
                signature: FinalSignature { bytes: vec![1] },
                pass: false,
            },
            LocalStrictSelectionCandidate {
                priority: metadata[2].priority,
                signature: FinalSignature { bytes: vec![2] },
                pass: true,
            },
        ];
        let mut selector = LocalStrictPrivateSelectionBackend::new();
        let mut driver = StrictResponseCheckPhaseDriver::new();
        driver.accept_metadata(3).expect("metadata");
        driver.accept_shared_responses(3).expect("responses");
        driver.accept_response_bounds(3).expect("bounds");
        driver.accept_hint_checks(3).expect("hints");

        let (selected, evidence) = selector
            .select_candidate(&metadata, candidates, &mut driver)
            .expect("select");

        assert_eq!(selected.signature.bytes, vec![2]);
        assert_eq!(evidence.token_count, 3);
        assert_eq!(
            evidence.selected_priority,
            StrictCandidatePriority([2u8; 32])
        );
        assert!(!format!("{selector:?}").contains("pass"));
        assert!(!format!("{selected:?}").contains("pass"));

        let mut selector = LocalStrictPrivateSelectionBackend::new();
        let mut driver = StrictResponseCheckPhaseDriver::new();
        driver.accept_metadata(1).expect("metadata");
        driver.accept_shared_responses(1).expect("responses");
        driver.accept_response_bounds(1).expect("bounds");
        driver.accept_hint_checks(1).expect("hints");
        assert_eq!(
            selector.select_candidate(
                &metadata[..1],
                vec![LocalStrictSelectionCandidate {
                    priority: metadata[0].priority,
                    signature: FinalSignature { bytes: vec![0] },
                    pass: false,
                }],
                &mut driver,
            ),
            Err(OnlineError::GenericBatchFailure)
        );
    }

    #[test]
    fn local_selected_opener_opens_only_selected_candidate() {
        let selection = StrictPrivateSelectionEvidence {
            token_count: 3,
            selected_priority: StrictCandidatePriority([7u8; 32]),
        };
        let selected = LocalStrictSelectionCandidate {
            priority: selection.selected_priority,
            signature: FinalSignature {
                bytes: b"selected-signature".to_vec(),
            },
            pass: true,
        };
        let unselected = LocalStrictSelectionCandidate {
            priority: StrictCandidatePriority([1u8; 32]),
            signature: FinalSignature {
                bytes: b"unselected-signature".to_vec(),
            },
            pass: true,
        };

        let mut driver = StrictResponseCheckPhaseDriver::new();
        driver.accept_metadata(3).expect("metadata");
        driver.accept_shared_responses(3).expect("responses");
        driver.accept_response_bounds(3).expect("bounds");
        driver.accept_hint_checks(3).expect("hints");
        driver.accept_private_pass_bits(3).expect("pass bits");
        driver.accept_priority_selection(true).expect("selection");

        let mut opener = LocalStrictSelectedOpeningBackend::new();
        let (signature, opening) = opener
            .open_selected(&selection, selected, &mut driver)
            .expect("selected opening");
        opening
            .validate_for_selection(&selection)
            .expect("opening evidence");

        assert_eq!(signature.bytes, b"selected-signature");
        assert_eq!(opening.signature_hash, strict_signature_hash(&signature));
        assert!(!format!("{opener:?}").contains("selected-signature"));
        assert!(!format!("{unselected:?}").contains("unselected-signature"));

        let mut driver = StrictResponseCheckPhaseDriver::new();
        driver.accept_metadata(1).expect("metadata");
        driver.accept_shared_responses(1).expect("responses");
        driver.accept_response_bounds(1).expect("bounds");
        driver.accept_hint_checks(1).expect("hints");
        driver.accept_private_pass_bits(1).expect("pass bits");
        driver.accept_priority_selection(true).expect("selection");
        let mut opener = LocalStrictSelectedOpeningBackend::new();
        assert_eq!(
            opener.open_selected(
                &selection,
                LocalStrictSelectionCandidate {
                    priority: StrictCandidatePriority([8u8; 32]),
                    signature: FinalSignature { bytes: vec![0] },
                    pass: true,
                },
                &mut driver,
            ),
            Err(OnlineError::StrictResponseCheckShapeMismatch)
        );
    }

    #[test]
    fn polynomial_signing_uses_dkg_backed_s1_shares() {
        let (token, request) = zero_w1_token_and_request();
        let config = dkg_config();
        let provider = DkgBackedPolynomialShareProvider::<MlDsa65>::new(
            token.session_id,
            config.clone(),
            token
                .signer_set
                .iter()
                .map(|&party| (party, PolyVec::zero(MlDsa65::L)))
                .collect(),
            token
                .signer_set
                .iter()
                .map(|&party| zero_dkg_secret_share(&config, party))
                .collect(),
        );
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];

        let signature = sign_polynomial_with_token::<MlDsa65, _, _, _, _>(
            &mut pool,
            &mut consumed,
            &mut counters,
            &request,
            PolynomialOnlineServices {
                tr: &tr,
                public_key: &public_key,
                aggregation: PolynomialAggregation::Additive,
                partial_verifier: &NoopPolynomialPartialVerifier,
                share_provider: &provider,
                verifier: &AcceptVerifier,
            },
        )
        .expect("typed signing succeeds with DKG-backed s1 shares");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert!(consumed.is_consumed(request.session_id));
        assert_eq!(counters.tokens_consumed, 1);
        assert_eq!(counters.signatures_returned, 1);
    }

    #[test]
    fn polynomial_signing_accepts_native_dkg_key_packages() {
        let (token, request) = zero_w1_token_and_request();
        let config = dkg_config();
        let key_packages = token
            .signer_set
            .iter()
            .map(|&party| {
                dkg_key_package_from_secret(&config, zero_dkg_secret_share(&config, party))
            })
            .collect();
        let provider = DkgBackedPolynomialShareProvider::<MlDsa65>::from_key_packages(
            token.session_id,
            config,
            token
                .signer_set
                .iter()
                .map(|&party| (party, PolyVec::zero(MlDsa65::L)))
                .collect(),
            key_packages,
        );
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];

        let signature = sign_polynomial_with_token::<MlDsa65, _, _, _, _>(
            &mut pool,
            &mut consumed,
            &mut counters,
            &request,
            PolynomialOnlineServices {
                tr: &tr,
                public_key: &public_key,
                aggregation: PolynomialAggregation::Additive,
                partial_verifier: &NoopPolynomialPartialVerifier,
                share_provider: &provider,
                verifier: &AcceptVerifier,
            },
        )
        .expect("typed signing succeeds with native DKG key packages");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert!(consumed.is_consumed(request.session_id));
        assert_eq!(counters.tokens_consumed, 1);
        assert_eq!(counters.signatures_returned, 1);
    }

    #[test]
    fn debug_redacts_polynomial_signing_shares() {
        let share = PolynomialSigningShare {
            party: PartyId(9),
            y_share: polyvec_with_const(1234),
            s1_share: polyvec_with_const(5678),
        };

        assert_eq!(
            format!("{share:?}"),
            "PolynomialSigningShare { party: PartyId(9), y_share: \"<redacted>\", s1_share: \"<redacted>\" }"
        );
    }

    #[test]
    fn consumed_token_cannot_sign_again() {
        let (token, request) = token_and_request();
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];

        let first = sign_with_token::<MlDsa65, _, _, _, _>(
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
        );
        assert!(first.is_ok());
        assert_eq!(
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
            ),
            Err(OnlineError::TokenAlreadyConsumed(request.session_id))
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_consumed_token_store_survives_reopen() {
        let path = test_store_path("survives_reopen");
        let _ = std::fs::remove_file(&path);
        let session_id = session(77);

        {
            let mut store = FileConsumedTokenStore::open(&path).expect("open store");
            store
                .persist_consumed(session_id)
                .expect("persist consumed");
            assert!(store.is_consumed(session_id));
        }

        let mut reopened = FileConsumedTokenStore::open(&path).expect("reopen store");
        assert!(reopened.is_consumed(session_id));
        assert_eq!(
            reopened.persist_consumed(session_id),
            Err(OnlineError::TokenAlreadyConsumed(session_id))
        );
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_consumed_token_store_blocks_restored_token() {
        let path = test_store_path("blocks_restored_token");
        let _ = std::fs::remove_file(&path);
        let (token, request) = token_and_request();
        let mut store = FileConsumedTokenStore::open(&path).expect("open store");
        store
            .persist_consumed(request.session_id)
            .expect("persist prior consumption");

        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert restored certified token");
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];

        assert_eq!(
            sign_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut store,
                &mut counters,
                &request,
                OnlineServices {
                    tr: &tr,
                    partial_signer: &SessionAwarePartialSigner,
                    assembler: &TestAssembler,
                    verifier: &AcceptVerifier,
                },
            ),
            Err(OnlineError::TokenAlreadyConsumed(request.session_id))
        );
        assert!(pool.contains(request.session_id));
        assert_eq!(counters.tokens_consumed, 0);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_consumed_token_store_rejects_corrupt_log() {
        let path = test_store_path("rejects_corrupt_log");
        std::fs::write(&path, "not-hex\n").expect("write corrupt store");

        assert_eq!(
            FileConsumedTokenStore::open(&path),
            Err(OnlineError::ConsumedTokenStoreCorrupt { line: 1 })
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn final_verify_failure_consumes_token_without_output() {
        let (token, request) = token_and_request();
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];

        assert_eq!(
            sign_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut consumed,
                &mut counters,
                &request,
                OnlineServices {
                    tr: &tr,
                    partial_signer: &SessionAwarePartialSigner,
                    assembler: &TestAssembler,
                    verifier: &RejectVerifier,
                },
            ),
            Err(OnlineError::FinalVerifyFailed)
        );
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
        assert_eq!(counters.final_verify_failures, 1);
    }

    #[test]
    fn paper_compatible_path_exposes_rejected_z_attack_demo() {
        let (token, request) = token_and_request();
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let partial_signer = RecordingPartialSigner::default();
        let assembler = RecordingAssembler::default();

        assert_eq!(
            sign_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut consumed,
                &mut counters,
                &request,
                OnlineServices {
                    tr: &tr,
                    partial_signer: &partial_signer,
                    assembler: &assembler,
                    verifier: &RejectVerifier,
                },
            ),
            Err(OnlineError::FinalVerifyFailed)
        );

        assert!(consumed.is_consumed(request.session_id));
        assert_eq!(counters.final_verify_failures, 1);
        assert_eq!(
            partial_signer.observed_z_shares.borrow().len(),
            request.signing_set.len(),
            "paper-compatible partial signers generated clear z_i before rejection"
        );
        assert_eq!(
            assembler.observed_partial_z_shares.borrow().len(),
            request.signing_set.len(),
            "paper-compatible assembler/coordinator observed rejected z_i values"
        );
        assert!(
            assembler.observed_candidate.borrow().is_some(),
            "paper-compatible assembler formed a rejected aggregate candidate"
        );
    }

    #[test]
    fn paper_compatible_z_norm_failure_has_clear_z_attack_demo() {
        let session_id = session(0x91);
        let challenge = ChallengeMaterial {
            mu: [0x23; 64],
            encoded_w1: vec![0],
            ctilde: vec![0x42; MlDsa65::CTILDE_LEN],
        };
        let partial = PolynomialPartialSignature {
            session_id,
            party: PartyId(1),
            z_share: polyvec_with_const(MlDsa65::GAMMA1 - MlDsa65::BETA),
            challenge: challenge.ctilde.clone(),
        };
        let leaked_z = partial.z_share.clone();

        assert_eq!(
            assemble_polynomial_response::<MlDsa65>(
                session_id,
                &[PartyId(1)],
                &challenge,
                &[partial],
            ),
            Err(OnlineError::ZNormExceeded {
                norm: MlDsa65::GAMMA1 - MlDsa65::BETA,
                bound: MlDsa65::GAMMA1 - MlDsa65::BETA,
            })
        );
        assert_eq!(
            leaked_z,
            polyvec_with_const(MlDsa65::GAMMA1 - MlDsa65::BETA),
            "the paper-compatible path has already materialized rejected z"
        );
    }

    #[test]
    fn polynomial_final_verify_failure_consumes_token_without_output() {
        let (token, request) = zero_w1_token_and_request();
        let share_provider = zero_polynomial_share_provider(&token.signer_set);
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];

        assert_eq!(
            sign_polynomial_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut consumed,
                &mut counters,
                &request,
                PolynomialOnlineServices {
                    tr: &tr,
                    public_key: &public_key,
                    aggregation: PolynomialAggregation::Additive,
                    partial_verifier: &NoopPolynomialPartialVerifier,
                    share_provider: &share_provider,
                    verifier: &RejectVerifier,
                },
            ),
            Err(OnlineError::FinalVerifyFailed)
        );
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
        assert_eq!(counters.final_verify_failures, 1);
    }

    #[test]
    fn partial_mismatch_consumes_token_without_output() {
        let (token, request) = token_and_request();
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];

        assert!(matches!(
            sign_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut consumed,
                &mut counters,
                &request,
                OnlineServices {
                    tr: &tr,
                    partial_signer: &TestPartialSigner,
                    assembler: &TestAssembler,
                    verifier: &AcceptVerifier,
                },
            ),
            Err(OnlineError::Blame(_))
        ));
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
    }

    #[test]
    fn polynomial_missing_share_consumes_token_without_output() {
        let (token, request) = zero_w1_token_and_request();
        let share_provider = TestPolynomialShareProvider {
            shares: vec![],
            misbind_party: false,
        };
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];

        assert_eq!(
            sign_polynomial_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut consumed,
                &mut counters,
                &request,
                PolynomialOnlineServices {
                    tr: &tr,
                    public_key: &public_key,
                    aggregation: PolynomialAggregation::Additive,
                    partial_verifier: &NoopPolynomialPartialVerifier,
                    share_provider: &share_provider,
                    verifier: &AcceptVerifier,
                },
            ),
            Err(OnlineError::PartialSignerFailed(PartyId(1)))
        );
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
    }

    #[test]
    fn polynomial_misbound_share_blames_party() {
        let (token, request) = zero_w1_token_and_request();
        let mut share_provider = zero_polynomial_share_provider(&token.signer_set);
        share_provider.misbind_party = true;
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];

        assert_eq!(
            sign_polynomial_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut consumed,
                &mut counters,
                &request,
                PolynomialOnlineServices {
                    tr: &tr,
                    public_key: &public_key,
                    aggregation: PolynomialAggregation::Additive,
                    partial_verifier: &NoopPolynomialPartialVerifier,
                    share_provider: &share_provider,
                    verifier: &AcceptVerifier,
                },
            ),
            Err(OnlineError::Blame(PartyId(1)))
        );
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
    }

    #[test]
    fn retry_consumes_failed_token_and_succeeds_with_next() {
        let (first_token, first_request) = token_and_request_for(10);
        let (second_token, second_request) = token_and_request_for(11);
        let mut pool = TokenPool::new();
        pool.insert_certified(first_token)
            .expect("insert first token");
        pool.insert_certified(second_token)
            .expect("insert second token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let verifier = FailThenAcceptVerifier {
            calls: Cell::new(0),
        };

        let signature = sign_with_retry::<MlDsa65, _, _, _, _>(
            &mut pool,
            &mut consumed,
            &mut counters,
            &[first_request.clone(), second_request.clone()],
            OnlineServices {
                tr: &tr,
                partial_signer: &SessionAwarePartialSigner,
                assembler: &TestAssembler,
                verifier: &verifier,
            },
            RetryPolicy { max_attempts: 2 },
        );

        assert!(signature.expect("second retry succeeds").bytes.len() > 32);
        assert!(consumed.is_consumed(first_request.session_id));
        assert!(consumed.is_consumed(second_request.session_id));
        assert_eq!(counters.attempts, 2);
        assert_eq!(counters.tokens_consumed, 2);
        assert_eq!(counters.final_verify_failures, 1);
        assert_eq!(counters.signatures_returned, 1);
    }
}
