#![forbid(unsafe_code)]
#![doc = "Integration-test support for TALUS."]

mod cases;
mod mpc_adversarial_cases;
#[cfg(feature = "paper-fast-dev")]
mod online_adversarial_cases;
mod preprocessing_adversarial_cases;
#[cfg(feature = "paper-fast-dev")]
mod properties;
#[cfg(feature = "paper-fast-dev")]
mod wire_adversarial_cases;

pub use cases::*;
pub use mpc_adversarial_cases::run_mpc_adversarial_cases;
#[cfg(feature = "paper-fast-dev")]
pub use online_adversarial_cases::run_online_adversarial_cases;
pub use preprocessing_adversarial_cases::run_preprocessing_adversarial_cases;
#[cfg(feature = "paper-fast-dev")]
pub use properties::run_deterministic_property_cases;
#[cfg(feature = "paper-fast-dev")]
pub(crate) use wire_adversarial_cases::{commit_message, header, partial_message};
#[cfg(feature = "paper-fast-dev")]
pub use wire_adversarial_cases::{require_all_parties, run_wire_adversarial_cases};

#[cfg(feature = "paper-fast-dev")]
#[cfg(test)]
mod adversarial_tests;
#[cfg(feature = "paper-fast-dev")]
#[cfg(test)]
mod dkg_power2round_driver;
#[cfg(feature = "paper-fast-dev")]
#[cfg(test)]
mod dkg_signing_helpers;
#[cfg(feature = "paper-fast-dev")]
#[cfg(test)]
mod dkg_signing_tests;
#[cfg(test)]
mod production_api_scan;
#[cfg(feature = "paper-fast-dev")]
#[cfg(test)]
mod wire_tests;
