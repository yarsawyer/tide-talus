#![doc = "Authenticated unsigned integers, public comparisons, and CEF carry bits."]

use core::fmt;

use crate::auth::{MacKeyShare, OpenError, PartyId};
use crate::beaver::{CertifiedBeaverTripleShare, TripleUseTracker};
use crate::bit::{
    and_bits_checked, full_adder_checked, not_bits, open_bit_checked, public_bit, xor_bits,
    AuthBit, AuthBitError,
};
use crate::Gf128;
use talus_core::MlDsaParams;

/// Maximum bit width needed for TALUS low-mask sums.
pub const AUTH_U19_WIDTH: usize = 19;

/// Authenticated unsigned integer with little-endian bits.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthU19 {
    bits: Vec<Vec<AuthBit>>,
}

impl fmt::Debug for AuthU19 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthU19")
            .field("width", &self.bits.len())
            .field(
                "party_count",
                &self.bits.first().map_or(0, |bits| bits.len()),
            )
            .field("bits", &"<redacted>")
            .finish()
    }
}

impl AuthU19 {
    /// Builds an authenticated U19 from little-endian authenticated bits.
    pub fn from_bits_le(bits: Vec<Vec<AuthBit>>) -> Result<Self, CarryError> {
        if bits.is_empty() || bits.len() > AUTH_U19_WIDTH {
            return Err(CarryError::InvalidWidth(bits.len()));
        }

        let party_count = bits[0].len();
        if party_count == 0 {
            return Err(CarryError::EmptyParties);
        }

        for bit in &bits {
            if bit.len() != party_count {
                return Err(CarryError::PartyCountMismatch {
                    expected: party_count,
                    got: bit.len(),
                });
            }
        }

        Ok(Self { bits })
    }

    /// Returns the bit width.
    pub fn width(&self) -> usize {
        self.bits.len()
    }

    /// Returns little-endian bits.
    pub fn bits_le(&self) -> &[Vec<AuthBit>] {
        &self.bits
    }

    /// Opens the integer after checking every bit and MAC.
    pub fn open_checked(&self, mac_keys: &[MacKeyShare]) -> Result<u32, CarryError> {
        let mut value = 0u32;

        for (idx, bit) in self.bits.iter().enumerate() {
            if open_bit_checked(bit, mac_keys)? {
                value |= 1u32 << idx;
            }
        }

        Ok(value)
    }

    /// Opens and checks that the integer is strictly below `upper_bound`.
    pub fn open_range_checked(
        &self,
        upper_bound: u32,
        mac_keys: &[MacKeyShare],
    ) -> Result<u32, CarryError> {
        let value = self.open_checked(mac_keys)?;
        if value >= upper_bound {
            return Err(CarryError::RangeCheckFailed { value, upper_bound });
        }

        Ok(value)
    }
}

/// Supplies one Beaver triple per AND gate in circuit order.
pub struct TripleCursor<'a> {
    triples: &'a [Vec<CertifiedBeaverTripleShare>],
    next: usize,
}

impl<'a> TripleCursor<'a> {
    /// Creates a cursor over triple bundles.
    pub const fn new(triples: &'a [Vec<CertifiedBeaverTripleShare>]) -> Self {
        Self { triples, next: 0 }
    }

    fn take(&mut self) -> Result<&'a [CertifiedBeaverTripleShare], CarryError> {
        let triples = self
            .triples
            .get(self.next)
            .ok_or(CarryError::InsufficientTriples)?;
        self.next += 1;
        Ok(triples)
    }

    /// Returns the number of consumed triple bundles.
    pub const fn consumed(&self) -> usize {
        self.next
    }
}

/// Carry-comparison failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CarryError {
    /// Bit operation failed.
    Bit(AuthBitError),
    /// Invalid integer width.
    InvalidWidth(usize),
    /// No party shares were supplied.
    EmptyParties,
    /// Bit vectors had inconsistent party counts.
    PartyCountMismatch {
        /// Expected party count.
        expected: usize,
        /// Actual party count.
        got: usize,
    },
    /// Public comparison constant does not fit the requested width.
    ConstantTooLarge {
        /// Public constant.
        constant: u32,
        /// Bit width.
        width: usize,
    },
    /// The triple cursor did not contain enough AND triples.
    InsufficientTriples,
    /// Opened range check failed.
    RangeCheckFailed {
        /// Opened value.
        value: u32,
        /// Exclusive upper bound.
        upper_bound: u32,
    },
    /// Authenticated range check failed without opening the private value.
    AuthenticatedRangeCheckFailed {
        /// Exclusive upper bound.
        upper_bound: u32,
    },
    /// Fixed-width authenticated addition overflowed.
    SumOverflow,
    /// Public value is outside the decomposition modulus.
    InvalidPublicT {
        /// Public `t = B mod alpha`.
        t: u32,
        /// Decomposition base `alpha`.
        alpha: u32,
    },
}

impl fmt::Display for CarryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bit(err) => write!(f, "bit circuit failed: {err}"),
            Self::InvalidWidth(width) => write!(f, "invalid authenticated integer width {width}"),
            Self::EmptyParties => write!(f, "no authenticated parties supplied"),
            Self::PartyCountMismatch { expected, got } => {
                write!(f, "party count mismatch: expected {expected}, got {got}")
            }
            Self::ConstantTooLarge { constant, width } => {
                write!(f, "constant {constant} does not fit width {width}")
            }
            Self::InsufficientTriples => write!(f, "insufficient Beaver triples for circuit"),
            Self::RangeCheckFailed { value, upper_bound } => {
                write!(f, "range check failed: {value} >= {upper_bound}")
            }
            Self::AuthenticatedRangeCheckFailed { upper_bound } => {
                write!(
                    f,
                    "authenticated range check failed: value >= {upper_bound}"
                )
            }
            Self::SumOverflow => write!(f, "authenticated U19 sum overflowed"),
            Self::InvalidPublicT { t, alpha } => {
                write!(f, "public t {t} is outside alpha {alpha}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CarryError {}

impl From<AuthBitError> for CarryError {
    fn from(value: AuthBitError) -> Self {
        Self::Bit(value)
    }
}

impl From<OpenError> for CarryError {
    fn from(value: OpenError) -> Self {
        Self::Bit(AuthBitError::Open(value))
    }
}

/// Checks bitness with zero-knowledge-style equations `b * (b + 1) = 0`.
pub fn check_bits_are_bits(
    value: &AuthU19,
    mac_keys: &[MacKeyShare],
    public_party: PartyId,
    triples: &mut TripleCursor<'_>,
    tracker: &mut TripleUseTracker,
) -> Result<(), CarryError> {
    for bit in value.bits_le() {
        let not_bit = not_bits(bit, mac_keys, public_party)?;
        let product = and_with_next_triple(bit, &not_bit, mac_keys, triples, tracker)?;
        let opened = open_bit_product_zero_checked(&product, mac_keys)?;
        if !opened {
            return Err(CarryError::Bit(AuthBitError::NotBit(Gf128::from_u128(2))));
        }
    }

    Ok(())
}

/// Returns authenticated shares of `[value > constant]`.
pub fn gt_public_checked(
    value: &AuthU19,
    constant: u32,
    mac_keys: &[MacKeyShare],
    public_party: PartyId,
    triples: &mut TripleCursor<'_>,
    tracker: &mut TripleUseTracker,
) -> Result<Vec<AuthBit>, CarryError> {
    compare_public_checked(
        value,
        constant,
        CompareKind::Greater,
        mac_keys,
        public_party,
        triples,
        tracker,
    )
}

/// Returns authenticated shares of `[value < constant]`.
pub fn lt_public_checked(
    value: &AuthU19,
    constant: u32,
    mac_keys: &[MacKeyShare],
    public_party: PartyId,
    triples: &mut TripleCursor<'_>,
    tracker: &mut TripleUseTracker,
) -> Result<Vec<AuthBit>, CarryError> {
    compare_public_checked(
        value,
        constant,
        CompareKind::Less,
        mac_keys,
        public_party,
        triples,
        tracker,
    )
}

/// Sums authenticated U19 values with a fixed-width ripple-carry circuit.
///
/// The output stays 19 bits. The final carry is opened as an overflow check,
/// which reveals only whether the caller violated the expected range envelope.
pub fn sum_u19_checked(
    values: &[AuthU19],
    mac_keys: &[MacKeyShare],
    public_party: PartyId,
    triples: &mut TripleCursor<'_>,
    tracker: &mut TripleUseTracker,
) -> Result<AuthU19, CarryError> {
    let mut acc = AuthU19::from_bits_le(
        (0..AUTH_U19_WIDTH)
            .map(|_| public_bit(false, mac_keys, public_party))
            .collect(),
    )?;

    for value in values {
        acc = add_u19_checked(&acc, value, mac_keys, public_party, triples, tracker)?;
    }

    Ok(acc)
}

/// Authenticated CEF carry/correction bits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarryCompare {
    /// `kappa = [R > t]`.
    pub kappa: Vec<AuthBit>,
    /// `delta = [R < t - gamma2 + kappa * alpha]`.
    pub delta: Vec<AuthBit>,
}

/// Computes TALUS CEF `kappa` and `delta` from an authenticated `R = sum rho_i`
/// and public `t = B mod alpha`.
pub fn carry_compare<P: MlDsaParams>(
    r_sum: &AuthU19,
    t: u32,
    mac_keys: &[MacKeyShare],
    public_party: PartyId,
    triples: &mut TripleCursor<'_>,
    tracker: &mut TripleUseTracker,
) -> Result<CarryCompare, CarryError> {
    let alpha = P::alpha() as u32;
    let gamma2 = P::GAMMA2 as u32;
    if t >= alpha {
        return Err(CarryError::InvalidPublicT { t, alpha });
    }

    check_bits_are_bits(r_sum, mac_keys, public_party, triples, tracker)?;

    let range_ok = lt_public_checked(r_sum, alpha, mac_keys, public_party, triples, tracker)?;
    if !open_bit_checked(&range_ok, mac_keys)? {
        return Err(CarryError::AuthenticatedRangeCheckFailed { upper_bound: alpha });
    }

    let kappa = gt_public_checked(r_sum, t, mac_keys, public_party, triples, tracker)?;

    let delta0 = if t > gamma2 {
        Some(lt_public_checked(
            r_sum,
            t - gamma2,
            mac_keys,
            public_party,
            triples,
            tracker,
        )?)
    } else {
        None
    };

    let threshold1 = t + gamma2;
    let delta1 = if threshold1 >= alpha {
        None
    } else {
        Some(lt_public_checked(
            r_sum,
            threshold1,
            mac_keys,
            public_party,
            triples,
            tracker,
        )?)
    };

    let not_kappa = not_bits(&kappa, mac_keys, public_party)?;
    let term0 = if let Some(delta0) = delta0 {
        and_with_next_triple(&not_kappa, &delta0, mac_keys, triples, tracker)?
    } else {
        public_bit(false, mac_keys, public_party)
    };
    let term1 = if let Some(delta1) = delta1 {
        and_with_next_triple(&kappa, &delta1, mac_keys, triples, tracker)?
    } else {
        kappa.clone()
    };
    let delta = xor_bits(&term0, &term1)?;

    Ok(CarryCompare { kappa, delta })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompareKind {
    Greater,
    Less,
}

fn compare_public_checked(
    value: &AuthU19,
    constant: u32,
    kind: CompareKind,
    mac_keys: &[MacKeyShare],
    public_party: PartyId,
    triples: &mut TripleCursor<'_>,
    tracker: &mut TripleUseTracker,
) -> Result<Vec<AuthBit>, CarryError> {
    let width = value.width();
    if constant >= (1u32 << width) {
        return Err(CarryError::ConstantTooLarge { constant, width });
    }

    let party_count = value.bits_le()[0].len();
    let mut eq = public_bit(true, mac_keys, public_party);
    let mut out = public_bit(false, mac_keys, public_party);
    debug_assert_eq!(eq.len(), party_count);

    for bit_idx in (0..width).rev() {
        let x_i = &value.bits_le()[bit_idx];
        let c_i = ((constant >> bit_idx) & 1) == 1;
        let not_x_i;

        match (kind, c_i) {
            (CompareKind::Greater, false) | (CompareKind::Less, true) => {
                let candidate_bit = if kind == CompareKind::Greater {
                    x_i.as_slice()
                } else {
                    not_x_i = not_bits(x_i, mac_keys, public_party)?;
                    not_x_i.as_slice()
                };
                let candidate =
                    and_with_next_triple(&eq, candidate_bit, mac_keys, triples, tracker)?;
                out = xor_bits(&out, &candidate)?;
            }
            _ => {}
        }

        let eq_bit = if c_i {
            x_i.clone()
        } else {
            not_bits(x_i, mac_keys, public_party)?
        };
        eq = and_with_next_triple(&eq, &eq_bit, mac_keys, triples, tracker)?;
    }

    Ok(out)
}

fn add_u19_checked(
    lhs: &AuthU19,
    rhs: &AuthU19,
    mac_keys: &[MacKeyShare],
    public_party: PartyId,
    triples: &mut TripleCursor<'_>,
    tracker: &mut TripleUseTracker,
) -> Result<AuthU19, CarryError> {
    if lhs.width() != AUTH_U19_WIDTH || rhs.width() != AUTH_U19_WIDTH {
        return Err(CarryError::InvalidWidth(lhs.width().max(rhs.width())));
    }

    let mut carry = public_bit(false, mac_keys, public_party);
    let mut sum = Vec::with_capacity(AUTH_U19_WIDTH);

    for bit_idx in 0..AUTH_U19_WIDTH {
        let lhs_rhs_triples = triples.take()?;
        let carry_triples = triples.take()?;
        let out = full_adder_checked(
            &lhs.bits_le()[bit_idx],
            &rhs.bits_le()[bit_idx],
            &carry,
            lhs_rhs_triples,
            carry_triples,
            mac_keys,
            tracker,
        )?;
        sum.push(out.sum);
        carry = out.carry;
    }

    if open_bit_checked(&carry, mac_keys)? {
        return Err(CarryError::SumOverflow);
    }

    AuthU19::from_bits_le(sum)
}

fn and_with_next_triple(
    lhs: &[AuthBit],
    rhs: &[AuthBit],
    mac_keys: &[MacKeyShare],
    triples: &mut TripleCursor<'_>,
    tracker: &mut TripleUseTracker,
) -> Result<Vec<AuthBit>, CarryError> {
    Ok(and_bits_checked(
        lhs,
        rhs,
        triples.take()?,
        mac_keys,
        tracker,
    )?)
}

fn open_bit_product_zero_checked(
    bits: &[AuthBit],
    mac_keys: &[MacKeyShare],
) -> Result<bool, CarryError> {
    let shares: Vec<_> = bits.iter().map(|bit| bit.share).collect();
    let value = crate::open_checked(&shares, mac_keys)?;
    Ok(value == Gf128::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::test_dealer::deal_authenticated;
    use crate::beaver::{
        certify_triple_bundle_for_test, CertifiedBeaverTripleShare, TripleId,
        UncheckedBeaverTripleShare,
    };
    use talus_core::{MlDsa44, MlDsa65, MlDsa87};

    fn deal_bit(bit: bool, alpha: Gf128, party_count: u16) -> (Vec<AuthBit>, Vec<MacKeyShare>) {
        let value = if bit { Gf128::ONE } else { Gf128::ZERO };
        let deal = deal_authenticated(value, alpha, party_count);
        (
            deal.shares
                .into_iter()
                .map(AuthBit::from_share_unchecked)
                .collect(),
            deal.mac_keys,
        )
    }

    fn deal_u19(
        value: u32,
        width: usize,
        alpha: Gf128,
        party_count: u16,
    ) -> (AuthU19, Vec<MacKeyShare>) {
        let mut bits = Vec::new();
        let mut mac_keys = Vec::new();

        for bit_idx in 0..width {
            let (bit, keys) = deal_bit(((value >> bit_idx) & 1) == 1, alpha, party_count);
            if bit_idx == 0 {
                mac_keys = keys;
            }
            bits.push(bit);
        }

        (
            AuthU19::from_bits_le(bits).expect("test width is valid"),
            mac_keys,
        )
    }

    fn deal_triple(
        id: TripleId,
        alpha: Gf128,
        party_count: u16,
    ) -> Vec<CertifiedBeaverTripleShare> {
        let a_deal = deal_authenticated(Gf128::ONE, alpha, party_count);
        let b_deal = deal_authenticated(Gf128::ONE, alpha, party_count);
        let c_deal = deal_authenticated(Gf128::ONE, alpha, party_count);

        let unchecked = a_deal
            .shares
            .iter()
            .zip(&b_deal.shares)
            .zip(&c_deal.shares)
            .map(|((a_share, b_share), c_share)| UncheckedBeaverTripleShare {
                id,
                party: a_share.party,
                a: *a_share,
                b: *b_share,
                c: *c_share,
            })
            .collect::<Vec<_>>();
        let mac_keys = deal_authenticated(Gf128::ZERO, alpha, party_count).mac_keys;
        certify_triple_bundle_for_test(&unchecked, &mac_keys).expect("test triple certifies")
    }

    fn triple_bundles(
        count: usize,
        alpha: Gf128,
        party_count: u16,
    ) -> Vec<Vec<CertifiedBeaverTripleShare>> {
        (0..count)
            .map(|idx| deal_triple(TripleId(idx as u64 + 10_000), alpha, party_count))
            .collect()
    }

    #[test]
    fn auth_u19_open_and_range_checks() {
        let alpha = Gf128::from_u128(0x1111);
        let (value, mac_keys) = deal_u19(17, 5, alpha, 3);

        assert_eq!(value.open_checked(&mac_keys), Ok(17));
        assert_eq!(value.open_range_checked(18, &mac_keys), Ok(17));
        assert_eq!(
            value.open_range_checked(17, &mac_keys),
            Err(CarryError::RangeCheckFailed {
                value: 17,
                upper_bound: 17,
            })
        );
    }

    #[test]
    fn exhaustive_comparator_tests_for_reduced_width() {
        let alpha = Gf128::from_u128(0x2222);

        for value_clear in 0..16 {
            for constant in 0..16 {
                let (value, mac_keys) = deal_u19(value_clear, 4, alpha, 3);
                let bundles = triple_bundles(16, alpha, 3);
                let mut cursor = TripleCursor::new(&bundles);
                let mut tracker = TripleUseTracker::new();
                let gt = gt_public_checked(
                    &value,
                    constant,
                    &mac_keys,
                    PartyId(0),
                    &mut cursor,
                    &mut tracker,
                )
                .expect("gt circuit has enough triples");

                let bundles = triple_bundles(16, alpha, 3);
                let mut cursor = TripleCursor::new(&bundles);
                let mut tracker = TripleUseTracker::new();
                let lt = lt_public_checked(
                    &value,
                    constant,
                    &mac_keys,
                    PartyId(0),
                    &mut cursor,
                    &mut tracker,
                )
                .expect("lt circuit has enough triples");

                assert_eq!(open_bit_checked(&gt, &mac_keys), Ok(value_clear > constant));
                assert_eq!(open_bit_checked(&lt, &mac_keys), Ok(value_clear < constant));
            }
        }
    }

    #[test]
    fn random_u19_comparison_tests() {
        let alpha = Gf128::from_u128(0x3333);
        let cases = [
            (0, 1),
            (1, 0),
            (95_231, 95_232),
            (190_463, 190_000),
            (261_887, 261_888),
            (523_775, 400_000),
        ];

        for (value_clear, constant) in cases {
            let (value, mac_keys) = deal_u19(value_clear, AUTH_U19_WIDTH, alpha, 3);
            let bundles = triple_bundles(2 * AUTH_U19_WIDTH, alpha, 3);
            let mut cursor = TripleCursor::new(&bundles);
            let mut tracker = TripleUseTracker::new();
            let gt = gt_public_checked(
                &value,
                constant,
                &mac_keys,
                PartyId(0),
                &mut cursor,
                &mut tracker,
            )
            .expect("gt circuit has enough triples");

            assert_eq!(open_bit_checked(&gt, &mac_keys), Ok(value_clear > constant));
        }
    }

    #[test]
    fn sum_u19_matches_clear_sum() {
        let alpha = Gf128::from_u128(0x7777);
        let clear_values = [17u32, 91, 1024, 65_535];
        let mut values = Vec::new();
        let mut mac_keys = Vec::new();

        for (idx, clear) in clear_values.iter().copied().enumerate() {
            let (value, keys) = deal_u19(clear, AUTH_U19_WIDTH, alpha, 3);
            if idx == 0 {
                mac_keys = keys;
            }
            values.push(value);
        }

        let bundles = triple_bundles(clear_values.len() * AUTH_U19_WIDTH * 2, alpha, 3);
        let mut cursor = TripleCursor::new(&bundles);
        let mut tracker = TripleUseTracker::new();
        let sum = sum_u19_checked(&values, &mac_keys, PartyId(0), &mut cursor, &mut tracker)
            .expect("sum stays within 19 bits");

        assert_eq!(
            sum.open_checked(&mac_keys),
            Ok(clear_values.iter().copied().sum())
        );
    }

    #[test]
    fn sum_u19_rejects_overflow() {
        let alpha = Gf128::from_u128(0x8888);
        let (lhs, mac_keys) = deal_u19((1 << AUTH_U19_WIDTH) - 1, AUTH_U19_WIDTH, alpha, 3);
        let (rhs, _) = deal_u19(1, AUTH_U19_WIDTH, alpha, 3);
        let values = [lhs, rhs];
        let bundles = triple_bundles(values.len() * AUTH_U19_WIDTH * 2, alpha, 3);
        let mut cursor = TripleCursor::new(&bundles);
        let mut tracker = TripleUseTracker::new();

        assert_eq!(
            sum_u19_checked(&values, &mac_keys, PartyId(0), &mut cursor, &mut tracker),
            Err(CarryError::SumOverflow)
        );
    }

    fn assert_carry_compare_case<P: MlDsaParams>(r_clear: u32, t: u32) {
        let alpha_field = Gf128::from_u128(0x4444 + u128::from(r_clear) + u128::from(t));
        let (r_sum, mac_keys) = deal_u19(r_clear, AUTH_U19_WIDTH, alpha_field, 3);
        let bundles = triple_bundles(256, alpha_field, 3);
        let mut cursor = TripleCursor::new(&bundles);
        let mut tracker = TripleUseTracker::new();
        let got = carry_compare::<P>(&r_sum, t, &mac_keys, PartyId(0), &mut cursor, &mut tracker)
            .expect("carry compare has enough triples");

        let alpha = P::alpha();
        let gamma2 = P::GAMMA2;
        let kappa = (r_clear as i32) > (t as i32);
        let threshold = t as i32 - gamma2 + i32::from(kappa) * alpha;
        let delta = (r_clear as i32) < threshold;

        assert_eq!(open_bit_checked(&got.kappa, &mac_keys), Ok(kappa));
        assert_eq!(open_bit_checked(&got.delta, &mac_keys), Ok(delta));
    }

    #[test]
    fn carry_compare_matches_clear_computation_representative() {
        assert_carry_compare_case::<MlDsa44>(0, MlDsa44::GAMMA2 as u32 + 1);
        assert_carry_compare_case::<MlDsa44>(1_000, 500);
        assert_carry_compare_case::<MlDsa65>(0, MlDsa65::GAMMA2 as u32 + 1);
        assert_carry_compare_case::<MlDsa65>(1_000, 500);
        assert_carry_compare_case::<MlDsa87>(0, MlDsa87::GAMMA2 as u32);
        assert_carry_compare_case::<MlDsa87>(MlDsa87::alpha() as u32 - 1, 500);
    }

    #[test]
    fn carry_compare_rejects_out_of_range_rho_sum_before_returning_bits() {
        let alpha = Gf128::from_u128(0x5555);
        let (r_sum, mac_keys) = deal_u19(MlDsa65::alpha() as u32, AUTH_U19_WIDTH, alpha, 3);
        let bundles = triple_bundles(256, alpha, 3);
        let mut cursor = TripleCursor::new(&bundles);
        let mut tracker = TripleUseTracker::new();

        assert_eq!(
            carry_compare::<MlDsa65>(&r_sum, 0, &mac_keys, PartyId(0), &mut cursor, &mut tracker,),
            Err(CarryError::AuthenticatedRangeCheckFailed {
                upper_bound: MlDsa65::alpha() as u32,
            })
        );
    }

    #[test]
    fn carry_compare_rejects_non_bit_input_before_returning_bits() {
        let alpha = Gf128::from_u128(0x6666);
        let mut bits = Vec::new();
        let bad_bit = deal_authenticated(Gf128::from_u128(2), alpha, 3);
        bits.push(
            bad_bit
                .shares
                .into_iter()
                .map(AuthBit::from_share_unchecked)
                .collect(),
        );
        for _ in 1..AUTH_U19_WIDTH {
            bits.push(public_bit(false, &bad_bit.mac_keys, PartyId(0)));
        }
        let r_sum = AuthU19::from_bits_le(bits).expect("test bit width is valid");
        let bundles = triple_bundles(256, alpha, 3);
        let mut cursor = TripleCursor::new(&bundles);
        let mut tracker = TripleUseTracker::new();

        assert_eq!(
            carry_compare::<MlDsa65>(
                &r_sum,
                0,
                &bad_bit.mac_keys,
                PartyId(0),
                &mut cursor,
                &mut tracker,
            ),
            Err(CarryError::Bit(AuthBitError::NotBit(Gf128::from_u128(2))))
        );
    }

    #[test]
    fn carry_compare_rejects_bad_mac_before_returning_bits() {
        let alpha = Gf128::from_u128(0x7777);
        let (mut r_sum, mac_keys) = deal_u19(17, AUTH_U19_WIDTH, alpha, 3);
        r_sum.bits[0][0].share.mac += Gf128::ONE;
        let bundles = triple_bundles(256, alpha, 3);
        let mut cursor = TripleCursor::new(&bundles);
        let mut tracker = TripleUseTracker::new();

        assert!(matches!(
            carry_compare::<MlDsa65>(&r_sum, 0, &mac_keys, PartyId(0), &mut cursor, &mut tracker,),
            Err(CarryError::Bit(AuthBitError::Beaver(_)))
                | Err(CarryError::Bit(AuthBitError::Open(_)))
        ));
    }

    #[test]
    fn debug_redacts_authenticated_integer_bits() {
        let alpha = Gf128::from_u128(0x8888);
        let (value, _) = deal_u19(17, 5, alpha, 3);

        assert_eq!(
            format!("{value:?}"),
            "AuthU19 { width: 5, party_count: 3, bits: \"<redacted>\" }"
        );
    }
}
