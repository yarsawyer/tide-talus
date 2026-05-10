#![doc = "Authenticated additive shares and checked openings."]

use core::fmt;

use crate::Gf128;

/// Identifies one local MPC party.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PartyId(pub u16);

/// One party's additive share of the global MAC key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MacKeyShare {
    /// Party that owns this MAC-key share.
    pub party: PartyId,
    /// Additive share of the global MAC key.
    pub alpha: Gf128,
}

impl fmt::Debug for MacKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacKeyShare")
            .field("party", &self.party)
            .field("alpha", &"<redacted>")
            .finish()
    }
}

/// One party's authenticated additive share.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthShare {
    /// Party that owns this value/MAC share pair.
    pub party: PartyId,
    /// Additive value share.
    pub value: Gf128,
    /// Additive MAC share.
    pub mac: Gf128,
}

impl fmt::Debug for AuthShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthShare")
            .field("party", &self.party)
            .field("value", &"<redacted>")
            .field("mac", &"<redacted>")
            .finish()
    }
}

/// Checked-opening failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenError {
    /// No authenticated shares were supplied.
    Empty,
    /// Party identifiers are duplicated in one input set.
    DuplicateParty(PartyId),
    /// An authenticated share does not have a matching MAC-key share.
    MissingMacKey(PartyId),
    /// The reconstructed MAC does not match the reconstructed value.
    MacCheckFailed,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Empty => write!(f, "no authenticated shares supplied"),
            Self::DuplicateParty(party) => write!(f, "duplicate party id {}", party.0),
            Self::MissingMacKey(party) => write!(f, "missing MAC key share for party {}", party.0),
            Self::MacCheckFailed => write!(f, "authenticated opening MAC check failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OpenError {}

impl AuthShare {
    /// Adds another share owned by the same party.
    pub fn add_same_party(self, rhs: Self) -> Option<Self> {
        if self.party != rhs.party {
            return None;
        }

        Some(Self {
            party: self.party,
            value: self.value + rhs.value,
            mac: self.mac + rhs.mac,
        })
    }

    /// Subtracts another share owned by the same party.
    pub fn sub_same_party(self, rhs: Self) -> Option<Self> {
        self.add_same_party(rhs)
    }

    /// Multiplies this authenticated share by a public field element.
    pub fn mul_public(self, rhs: Gf128) -> Self {
        Self {
            party: self.party,
            value: self.value * rhs,
            mac: self.mac * rhs,
        }
    }

    /// Adds a public value to an authenticated share.
    ///
    /// The public value is added to `value_party`'s value share. Every party
    /// adjusts its MAC share by its local MAC-key share times the public value.
    pub fn add_public(
        self,
        public_value: Gf128,
        mac_key: MacKeyShare,
        value_party: PartyId,
    ) -> Option<Self> {
        if self.party != mac_key.party {
            return None;
        }

        let mut out = self;
        out.mac += mac_key.alpha * public_value;
        if out.party == value_party {
            out.value += public_value;
        }
        Some(out)
    }
}

/// Opens one authenticated value after checking its SPDZ-style MAC equation.
pub fn open_checked(shares: &[AuthShare], mac_keys: &[MacKeyShare]) -> Result<Gf128, OpenError> {
    if shares.is_empty() {
        return Err(OpenError::Empty);
    }

    for (idx, share) in shares.iter().enumerate() {
        if shares[..idx].iter().any(|prev| prev.party == share.party) {
            return Err(OpenError::DuplicateParty(share.party));
        }
    }

    for (idx, mac_key) in mac_keys.iter().enumerate() {
        if mac_keys[..idx]
            .iter()
            .any(|prev| prev.party == mac_key.party)
        {
            return Err(OpenError::DuplicateParty(mac_key.party));
        }
    }

    let mut value = Gf128::ZERO;
    let mut mac = Gf128::ZERO;
    let mut alpha = Gf128::ZERO;

    for share in shares {
        value += share.value;
        mac += share.mac;

        let mac_key = mac_keys
            .iter()
            .find(|candidate| candidate.party == share.party)
            .ok_or(OpenError::MissingMacKey(share.party))?;
        alpha += mac_key.alpha;
    }

    if mac != alpha * value {
        return Err(OpenError::MacCheckFailed);
    }

    Ok(value)
}

/// Opens many authenticated values, checking each before returning any output.
pub fn open_many_checked(
    openings: &[&[AuthShare]],
    mac_keys: &[MacKeyShare],
) -> Result<Vec<Gf128>, OpenError> {
    let mut values = Vec::with_capacity(openings.len());

    for shares in openings {
        values.push(open_checked(shares, mac_keys)?);
    }

    Ok(values)
}

#[cfg(any(test, feature = "test-dealer"))]
pub mod test_dealer {
    //! Deterministic trusted dealer for tests only.

    use super::*;

    /// Deterministically splits a secret and authenticates the shares.
    pub fn deal_authenticated(secret: Gf128, alpha: Gf128, party_count: u16) -> Deal {
        let mut values = Vec::new();
        let mut macs = Vec::new();
        let mut mac_keys = Vec::new();
        let mut seed = secret.to_u128() ^ alpha.to_u128() ^ u128::from(party_count);
        let mut value_sum = Gf128::ZERO;
        let mut alpha_sum = Gf128::ZERO;
        let mut mac_sum = Gf128::ZERO;

        for party in 0..party_count {
            let party_id = PartyId(party);
            let is_last = party + 1 == party_count;
            let alpha_share = if is_last {
                alpha + alpha_sum
            } else {
                next_field(&mut seed)
            };
            let value_share = if is_last {
                secret + value_sum
            } else {
                next_field(&mut seed)
            };
            let mac_share = if is_last {
                (alpha * secret) + mac_sum
            } else {
                next_field(&mut seed)
            };

            alpha_sum += alpha_share;
            value_sum += value_share;
            mac_sum += mac_share;
            mac_keys.push(MacKeyShare {
                party: party_id,
                alpha: alpha_share,
            });
            values.push(AuthShare {
                party: party_id,
                value: value_share,
                mac: mac_share,
            });
            macs.push(mac_share);
        }

        Deal {
            shares: values,
            mac_keys,
            macs,
        }
    }

    fn next_field(seed: &mut u128) -> Gf128 {
        *seed = seed
            .wrapping_mul(0xd134_2543_de82_ef95_d134_2543_de82_ef95)
            .wrapping_add(0x6a09_e667_f3bc_c909_9e37_79b9_7f4a_7c15);
        Gf128::from_u128(*seed)
    }

    /// Test-dealer output.
    #[derive(Clone, Eq, PartialEq)]
    pub struct Deal {
        /// Authenticated shares of the secret.
        pub shares: Vec<AuthShare>,
        /// Additive shares of the MAC key.
        pub mac_keys: Vec<MacKeyShare>,
        /// Raw MAC shares, exposed for negative tests and diagnostics.
        pub macs: Vec<Gf128>,
    }

    impl fmt::Debug for Deal {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Deal")
                .field("shares_len", &self.shares.len())
                .field("mac_keys_len", &self.mac_keys.len())
                .field("macs", &"<redacted>")
                .finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_dealer::deal_authenticated;
    use super::*;

    #[test]
    fn open_checked_valid() {
        let secret = Gf128::from_u128(0x1234);
        let alpha = Gf128::from_u128(0xdead_beef);
        let deal = deal_authenticated(secret, alpha, 4);

        assert_eq!(open_checked(&deal.shares, &deal.mac_keys), Ok(secret));
    }

    #[test]
    fn bad_value_share_fails_before_output_is_used() {
        let secret = Gf128::from_u128(0x1234);
        let alpha = Gf128::from_u128(0xdead_beef);
        let mut deal = deal_authenticated(secret, alpha, 4);
        deal.shares[1].value += Gf128::ONE;

        assert_eq!(
            open_checked(&deal.shares, &deal.mac_keys),
            Err(OpenError::MacCheckFailed)
        );
    }

    #[test]
    fn bad_mac_share_fails_before_output_is_used() {
        let secret = Gf128::from_u128(0x1234);
        let alpha = Gf128::from_u128(0xdead_beef);
        let mut deal = deal_authenticated(secret, alpha, 4);
        deal.shares[2].mac += Gf128::X;

        assert_eq!(
            open_checked(&deal.shares, &deal.mac_keys),
            Err(OpenError::MacCheckFailed)
        );
    }

    #[test]
    fn local_share_arithmetic_preserves_authentication() {
        let alpha = Gf128::from_u128(0xbeef);
        let lhs = deal_authenticated(Gf128::from_u128(0x1111), alpha, 3);
        let rhs = deal_authenticated(Gf128::from_u128(0x2222), alpha, 3);
        let mut sum_shares = Vec::new();

        for (lhs_share, rhs_share) in lhs.shares.iter().zip(&rhs.shares) {
            sum_shares.push(
                lhs_share
                    .add_same_party(*rhs_share)
                    .expect("test dealer emits aligned party ids"),
            );
        }

        assert_eq!(
            open_checked(&sum_shares, &lhs.mac_keys),
            Ok(Gf128::from_u128(0x1111) + Gf128::from_u128(0x2222))
        );
    }

    #[test]
    fn duplicate_party_is_rejected() {
        let alpha = Gf128::from_u128(0xbeef);
        let mut deal = deal_authenticated(Gf128::from_u128(0x1111), alpha, 3);
        deal.shares[1].party = deal.shares[0].party;

        assert_eq!(
            open_checked(&deal.shares, &deal.mac_keys),
            Err(OpenError::DuplicateParty(PartyId(0)))
        );
    }

    #[test]
    fn open_many_checked_returns_values_after_all_checks_pass() {
        let alpha = Gf128::from_u128(0xabc);
        let first = deal_authenticated(Gf128::from_u128(0x1111), alpha, 3);
        let second = deal_authenticated(Gf128::from_u128(0x2222), alpha, 3);
        let openings = [first.shares.as_slice(), second.shares.as_slice()];

        assert_eq!(
            open_many_checked(&openings, &first.mac_keys),
            Ok(vec![Gf128::from_u128(0x1111), Gf128::from_u128(0x2222)])
        );
    }

    #[test]
    fn open_many_checked_rejects_before_returning_any_values() {
        let alpha = Gf128::from_u128(0xabc);
        let first = deal_authenticated(Gf128::from_u128(0x1111), alpha, 3);
        let mut second = deal_authenticated(Gf128::from_u128(0x2222), alpha, 3);
        second.shares[0].mac += Gf128::ONE;
        let openings = [first.shares.as_slice(), second.shares.as_slice()];

        assert_eq!(
            open_many_checked(&openings, &first.mac_keys),
            Err(OpenError::MacCheckFailed)
        );
    }

    #[test]
    fn debug_redacts_authenticated_secret_material() {
        let share = AuthShare {
            party: PartyId(7),
            value: Gf128::from_u128(0x1234),
            mac: Gf128::from_u128(0xabcd),
        };
        let mac_key = MacKeyShare {
            party: PartyId(7),
            alpha: Gf128::from_u128(0xdead_beef),
        };

        assert_eq!(
            format!("{share:?}"),
            "AuthShare { party: PartyId(7), value: \"<redacted>\", mac: \"<redacted>\" }"
        );
        assert_eq!(
            format!("{mac_key:?}"),
            "MacKeyShare { party: PartyId(7), alpha: \"<redacted>\" }"
        );

        let deal = deal_authenticated(Gf128::from_u128(0x1234), Gf128::from_u128(0xbeef), 2);
        assert_eq!(
            format!("{deal:?}"),
            "Deal { shares_len: 2, mac_keys_len: 2, macs: \"<redacted>\" }"
        );
    }
}
