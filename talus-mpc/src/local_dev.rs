#![doc = "Test/dev-only preprocessing helpers."]

//! Clear masked-broadcast audit and paper-compatible preprocessing helpers.
//! This module is compiled only for tests or the explicit `paper-fast-dev`
//! feature and must never be part of production builds.

use talus_core::MlDsaParams;

use crate::local::{
    Commitment, MaskedBroadcastConsistencyProof, MaskedBroadcastConsistencyStatement,
    MaskedBroadcastConsistencyVerifier, PreprocessError,
};

/// Clear witness used by deterministic local audit tests.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskedBroadcastClearAudit {
    /// Unmasked unsigned high bits.
    pub highs: Vec<u32>,
    /// Unmasked unsigned low bits.
    pub lows: Vec<u32>,
    /// Public high masks used in this session.
    pub high_masks: Vec<u32>,
    /// Public rho masks used in this session.
    pub rhos: Vec<u32>,
    /// Expected rho-bit input commitment.
    pub rho_bits_commitment: Commitment,
}
/// Deterministic clear verifier for local tests and cut-and-choose audit openings.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClearMaskedBroadcastConsistencyVerifier;

#[cfg(any(test, feature = "paper-fast-dev"))]
impl MaskedBroadcastConsistencyVerifier for ClearMaskedBroadcastConsistencyVerifier {
    fn requires_clear_audit(&self) -> bool {
        true
    }

    fn verify_masked_broadcast<P: MlDsaParams>(
        &mut self,
        statement: &MaskedBroadcastConsistencyStatement,
        _proof: &MaskedBroadcastConsistencyProof,
        clear_audit: Option<&MaskedBroadcastClearAudit>,
    ) -> Result<(), PreprocessError> {
        let audit = clear_audit.ok_or(PreprocessError::MaskedBroadcastAuditRequired(
            statement.broadcast.party,
        ))?;
        verify_clear_masked_broadcast::<P>(statement, audit)
    }
}
/// Cut-and-choose audit plan. Audited openings are verified and discarded.
#[cfg(any(test, feature = "paper-fast-dev"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutAndChooseAuditPlan {
    audit_indices: Vec<usize>,
}

#[cfg(any(test, feature = "paper-fast-dev"))]
impl CutAndChooseAuditPlan {
    /// Creates a deterministic audit plan from already selected token indices.
    pub fn new(
        total_candidates: usize,
        mut audit_indices: Vec<usize>,
    ) -> Result<Self, PreprocessError> {
        if total_candidates == 0 {
            return Err(PreprocessError::InvalidAuditPlan);
        }
        audit_indices.sort_unstable();
        for (idx, &candidate_idx) in audit_indices.iter().enumerate() {
            if candidate_idx >= total_candidates {
                return Err(PreprocessError::InvalidAuditPlan);
            }
            if idx > 0 && audit_indices[idx - 1] == candidate_idx {
                return Err(PreprocessError::InvalidAuditPlan);
            }
        }
        if audit_indices.len() == total_candidates {
            return Err(PreprocessError::InvalidAuditPlan);
        }
        Ok(Self { audit_indices })
    }

    /// Returns whether a candidate index must be opened for audit.
    pub fn audits(&self, candidate_idx: usize) -> bool {
        self.audit_indices.contains(&candidate_idx)
    }

    /// Returns the number of audited candidates.
    pub fn audit_count(&self) -> usize {
        self.audit_indices.len()
    }
}
#[cfg(any(test, feature = "paper-fast-dev"))]
fn verify_clear_masked_broadcast<P: MlDsaParams>(
    statement: &MaskedBroadcastConsistencyStatement,
    audit: &MaskedBroadcastClearAudit,
) -> Result<(), PreprocessError> {
    let party = statement.broadcast.party;
    if statement.signer_set.is_empty()
        || !statement.signer_set.contains(&party)
        || statement.broadcast.masked_highs.len() != statement.coeff_count
        || statement.broadcast.masked_lows.len() != statement.coeff_count
        || audit.highs.len() != statement.coeff_count
        || audit.lows.len() != statement.coeff_count
        || audit.high_masks.len() != statement.coeff_count
        || audit.rhos.len() != statement.coeff_count
        || statement.broadcast.rho_bits_commitment != audit.rho_bits_commitment
    {
        return Err(PreprocessError::MaskedBroadcastConsistencyMismatch(party));
    }

    let high_mod = P::HIGH_MOD as u32;
    let alpha = P::alpha() as u32;
    let rho_bound = (alpha / statement.signer_set.len() as u32).max(1);
    for coeff in 0..statement.coeff_count {
        let high = audit.highs[coeff];
        let low = audit.lows[coeff];
        let high_mask = audit.high_masks[coeff];
        let rho = audit.rhos[coeff];
        if high >= high_mod || high_mask >= high_mod || low >= alpha || rho >= rho_bound {
            return Err(PreprocessError::MaskedBroadcastConsistencyMismatch(party));
        }

        let expected_high = (high + high_mask) % high_mod;
        let expected_low = low + rho;
        if statement.broadcast.masked_highs[coeff] != expected_high
            || statement.broadcast.masked_lows[coeff] != expected_low
        {
            return Err(PreprocessError::MaskedBroadcastConsistencyMismatch(party));
        }
    }

    Ok(())
}
