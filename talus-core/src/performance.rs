#![doc = "Shared production performance counters and batch sizing policy."]

use crate::MlDsaParams;

/// Cross-system performance counters for release evidence.
///
/// These counters intentionally describe public execution shape only. They do
/// not contain secrets, pass/fail bits, rejected candidates, masks, or private
/// witnesses.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TalusPerformanceCounters {
    /// Protocol rounds or phase labels represented by the evidence.
    pub rounds: u64,
    /// Directed private messages.
    pub private_messages: u64,
    /// Reliable-broadcast messages.
    pub broadcasts: u64,
    /// Canonical wire bytes.
    pub wire_bytes: u64,
    /// Durable log bytes.
    pub durable_log_bytes: u64,
    /// Vector lanes processed by this path.
    pub vector_lanes: u64,
    /// Vector chunks processed by this path.
    pub chunks: u64,
    /// Multiplication/checking circuit layers.
    pub multiplication_layers: u64,
    /// Opened lanes.
    pub opened_lanes: u64,
    /// Checked lanes.
    pub checked_lanes: u64,
    /// Tokens consumed or certified in one batch.
    pub token_batch_size: u64,
    /// Wall-clock runtime in microseconds, when measured by a driver.
    pub wall_clock_micros: u64,
    /// Scalar operations on release-capable paths.
    pub scalar_operations: u64,
}

impl TalusPerformanceCounters {
    /// Adds another counter set into this one using saturating arithmetic.
    pub fn merge(&mut self, other: Self) {
        self.rounds = self.rounds.saturating_add(other.rounds);
        self.private_messages = self.private_messages.saturating_add(other.private_messages);
        self.broadcasts = self.broadcasts.saturating_add(other.broadcasts);
        self.wire_bytes = self.wire_bytes.saturating_add(other.wire_bytes);
        self.durable_log_bytes = self
            .durable_log_bytes
            .saturating_add(other.durable_log_bytes);
        self.vector_lanes = self.vector_lanes.saturating_add(other.vector_lanes);
        self.chunks = self.chunks.saturating_add(other.chunks);
        self.multiplication_layers = self
            .multiplication_layers
            .saturating_add(other.multiplication_layers);
        self.opened_lanes = self.opened_lanes.saturating_add(other.opened_lanes);
        self.checked_lanes = self.checked_lanes.saturating_add(other.checked_lanes);
        self.token_batch_size = self.token_batch_size.saturating_add(other.token_batch_size);
        self.wall_clock_micros = self
            .wall_clock_micros
            .saturating_add(other.wall_clock_micros);
        self.scalar_operations = self
            .scalar_operations
            .saturating_add(other.scalar_operations);
    }

    /// Returns true when the evidence proves vector or chunk execution.
    pub const fn is_vectorized(self) -> bool {
        self.vector_lanes != 0 && self.scalar_operations == 0
    }
}

/// Production batch/chunk sizing policy for one ML-DSA suite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionBatchSizingPolicy {
    /// ML-DSA suite name.
    pub suite_name: &'static str,
    /// `s1` coefficient lanes.
    pub s1_lanes: usize,
    /// `s2` coefficient lanes.
    pub s2_lanes: usize,
    /// `t`/Power2Round coefficient lanes.
    pub power2round_lanes: usize,
    /// Strict response `z` coefficient lanes per candidate.
    pub strict_response_lanes_per_candidate: usize,
    /// Strict hint/highbits lanes per candidate.
    pub strict_hint_lanes_per_candidate: usize,
    /// Preprocessing BCC/CEF coefficient lanes per token.
    pub preprocessing_lanes_per_token: usize,
    /// Maximum vector lanes per production chunk.
    pub max_vector_lanes_per_chunk: usize,
    /// Maximum directed private delivery bytes per chunk.
    pub max_private_delivery_bytes: usize,
    /// Minimum strict-signing token batch size for production.
    pub min_strict_token_batch_size: usize,
    /// Recommended strict-signing token batch size for production.
    pub recommended_strict_token_batch_size: usize,
}

impl ProductionBatchSizingPolicy {
    /// Builds the default production policy for an ML-DSA suite.
    pub const fn for_suite<P: MlDsaParams>() -> Self {
        Self {
            suite_name: P::NAME,
            s1_lanes: P::L * P::N,
            s2_lanes: P::K * P::N,
            power2round_lanes: P::K * P::N,
            strict_response_lanes_per_candidate: P::L * P::N,
            strict_hint_lanes_per_candidate: P::K * P::N,
            preprocessing_lanes_per_token: P::K * P::N,
            max_vector_lanes_per_chunk: 65_536,
            max_private_delivery_bytes: 16 * 1024 * 1024,
            min_strict_token_batch_size: 2,
            recommended_strict_token_batch_size: 16,
        }
    }

    /// Returns the number of chunks needed to process `lanes`.
    pub fn chunks_for_lanes(self, lanes: usize) -> usize {
        if lanes == 0 {
            return 0;
        }
        lanes.div_ceil(self.max_vector_lanes_per_chunk)
    }
}

/// Coarse performance envelope for release-path smoke checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TalusPerformanceEnvelope {
    /// Minimum vector lanes expected.
    pub min_vector_lanes: u64,
    /// Maximum allowed protocol rounds.
    pub max_rounds: u64,
    /// Maximum allowed private messages.
    pub max_private_messages: u64,
    /// Maximum allowed broadcasts.
    pub max_broadcasts: u64,
    /// Maximum allowed canonical wire bytes.
    pub max_wire_bytes: u64,
    /// Maximum allowed durable log bytes.
    pub max_durable_log_bytes: u64,
    /// Maximum allowed wall-clock runtime in microseconds.
    pub max_wall_clock_micros: u64,
}

impl TalusPerformanceEnvelope {
    /// Baseline release smoke envelope for one ML-DSA suite.
    ///
    /// This is intentionally generous. It catches accidental scalarized release
    /// paths without trying to predict deployment RTT or storage latency.
    pub const fn smoke_for_suite<P: MlDsaParams>() -> Self {
        Self {
            min_vector_lanes: (P::K * P::N) as u64,
            max_rounds: 10_000,
            max_private_messages: 1_000_000,
            max_broadcasts: 1_000_000,
            max_wire_bytes: 1_000_000_000,
            max_durable_log_bytes: 2_500_000_000,
            max_wall_clock_micros: 30 * 60 * 1_000_000,
        }
    }
}

/// Performance gate failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PerformanceGateError {
    /// Vector lanes were below the release envelope minimum.
    VectorLanesTooLow,
    /// Scalar operations appeared in release evidence.
    ScalarOperationsPresent,
    /// Round count exceeded the release envelope.
    RoundsExceeded,
    /// Private message count exceeded the release envelope.
    PrivateMessagesExceeded,
    /// Broadcast count exceeded the release envelope.
    BroadcastsExceeded,
    /// Wire byte count exceeded the release envelope.
    WireBytesExceeded,
    /// Durable log byte count exceeded the release envelope.
    DurableLogBytesExceeded,
    /// Wall-clock runtime exceeded the release envelope.
    WallClockExceeded,
}

/// Ensures public release counters meet a coarse vectorized execution envelope.
pub fn ensure_performance_counters_within_envelope(
    counters: TalusPerformanceCounters,
    envelope: TalusPerformanceEnvelope,
) -> Result<(), PerformanceGateError> {
    if counters.scalar_operations != 0 {
        return Err(PerformanceGateError::ScalarOperationsPresent);
    }
    if counters.vector_lanes < envelope.min_vector_lanes {
        return Err(PerformanceGateError::VectorLanesTooLow);
    }
    if counters.rounds > envelope.max_rounds {
        return Err(PerformanceGateError::RoundsExceeded);
    }
    if counters.private_messages > envelope.max_private_messages {
        return Err(PerformanceGateError::PrivateMessagesExceeded);
    }
    if counters.broadcasts > envelope.max_broadcasts {
        return Err(PerformanceGateError::BroadcastsExceeded);
    }
    if counters.wire_bytes > envelope.max_wire_bytes {
        return Err(PerformanceGateError::WireBytesExceeded);
    }
    if counters.durable_log_bytes > envelope.max_durable_log_bytes {
        return Err(PerformanceGateError::DurableLogBytesExceeded);
    }
    if counters.wall_clock_micros > envelope.max_wall_clock_micros {
        return Err(PerformanceGateError::WallClockExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlDsa44, MlDsa65, MlDsa87};

    fn check_policy<P: MlDsaParams>() {
        let policy = ProductionBatchSizingPolicy::for_suite::<P>();
        assert_eq!(policy.suite_name, P::NAME);
        assert_eq!(policy.s1_lanes, P::L * P::N);
        assert_eq!(policy.s2_lanes, P::K * P::N);
        assert_eq!(policy.power2round_lanes, P::K * P::N);
        assert_eq!(policy.preprocessing_lanes_per_token, P::K * P::N);
        assert_eq!(policy.chunks_for_lanes(0), 0);
        assert_eq!(policy.chunks_for_lanes(1), 1);
        assert_eq!(
            policy.chunks_for_lanes(policy.max_vector_lanes_per_chunk + 1),
            2
        );
    }

    #[test]
    fn production_batch_sizing_policy_matches_all_suites() {
        check_policy::<MlDsa44>();
        check_policy::<MlDsa65>();
        check_policy::<MlDsa87>();
    }

    #[test]
    fn performance_envelope_rejects_scalarized_or_tiny_counters() {
        let envelope = TalusPerformanceEnvelope::smoke_for_suite::<MlDsa44>();
        assert_eq!(
            ensure_performance_counters_within_envelope(
                TalusPerformanceCounters::default(),
                envelope,
            ),
            Err(PerformanceGateError::VectorLanesTooLow)
        );
        assert_eq!(
            ensure_performance_counters_within_envelope(
                TalusPerformanceCounters {
                    vector_lanes: envelope.min_vector_lanes,
                    scalar_operations: 1,
                    ..TalusPerformanceCounters::default()
                },
                envelope,
            ),
            Err(PerformanceGateError::ScalarOperationsPresent)
        );
    }
}
