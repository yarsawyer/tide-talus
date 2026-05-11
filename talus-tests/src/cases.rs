use talus_mpc::{OnlineError, PreprocessError, TokenPoolError};
use talus_mpc_core::{BeaverError, CarryError, OpenError, TripleProviderError};
use talus_wire::WireError;

/// One deterministic property-style case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicPropertyCase {
    /// Human-readable case name.
    pub name: &'static str,
    /// Whether the property held.
    pub passed: bool,
    /// Short failure detail.
    pub detail: &'static str,
}

/// Observed outcome for one MPC-core adversarial case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MpcAdversarialOutcome {
    /// Checked opening rejected before returning a value.
    Open(OpenError),
    /// Beaver multiplication rejected before returning product shares.
    Beaver(BeaverError),
    /// Product shares were produced, but checked opening rejected them before a value was returned.
    ProductOpen(OpenError),
    /// Carry comparison rejected before returning carry/correction bits.
    Carry(CarryError),
    /// Triple provider rejected before handing out triple bundles.
    TripleProvider(TripleProviderError),
}

/// One deterministic adversarial MPC-core case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MpcAdversarialCase {
    /// Human-readable case name.
    pub name: &'static str,
    /// Observed failure.
    pub got: MpcAdversarialOutcome,
    /// Expected failure.
    pub expected: MpcAdversarialOutcome,
}

impl MpcAdversarialCase {
    /// Returns whether this case failed as expected.
    pub fn passed(&self) -> bool {
        self.got == self.expected
    }
}

/// Observed outcome for one online-signing adversarial case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnlineAdversarialOutcome {
    /// Online error returned to the caller.
    pub error: OnlineError,
    /// Whether the token was durably marked consumed.
    pub token_consumed: bool,
    /// Number of verified signatures returned.
    pub signatures_returned: u64,
    /// Number of final verifier failures counted.
    pub final_verify_failures: u64,
    /// Number of retry-exhaustion events counted.
    pub retry_exhausted: u64,
}

/// One deterministic adversarial online-signing case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnlineAdversarialCase {
    /// Human-readable case name.
    pub name: &'static str,
    /// Observed failure.
    pub got: OnlineAdversarialOutcome,
    /// Expected failure.
    pub expected: OnlineAdversarialOutcome,
}

impl OnlineAdversarialCase {
    /// Returns whether this case failed as expected.
    pub fn passed(&self) -> bool {
        self.got == self.expected
    }
}

/// Observed outcome for one preprocessing adversarial case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreprocessingAdversarialOutcome {
    /// Preprocessing rejected the mutated input or opened broadcast.
    Preprocess(PreprocessError),
    /// Token pool rejected an uncertified or duplicate object.
    TokenPool(TokenPoolError),
}

/// One deterministic adversarial preprocessing case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreprocessingAdversarialCase {
    /// Human-readable case name.
    pub name: &'static str,
    /// Observed failure.
    pub got: PreprocessingAdversarialOutcome,
    /// Expected failure.
    pub expected: PreprocessingAdversarialOutcome,
}

impl PreprocessingAdversarialCase {
    /// Returns whether this case failed as expected.
    pub fn passed(&self) -> bool {
        self.got == self.expected
    }
}

/// One deterministic adversarial wire case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireAdversarialCase {
    /// Human-readable case name.
    pub name: &'static str,
    /// Observed failure.
    pub got: WireError,
    /// Expected failure.
    pub expected: WireError,
}

impl WireAdversarialCase {
    /// Returns whether this case failed as expected.
    pub fn passed(&self) -> bool {
        self.got == self.expected
    }
}
