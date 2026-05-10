#![doc = "GF(2^128) arithmetic for authenticated TALUS-MPC MACs."]

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use zeroize::Zeroize;

/// Reduction constant for `x^128 = x^7 + x^2 + x + 1`.
const REDUCTION: u128 = 0x87;

/// Field element in `GF(2^128)` using the polynomial
/// `x^128 + x^7 + x^2 + x + 1`.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq, Zeroize)]
#[repr(transparent)]
pub struct Gf128(u128);

impl Gf128 {
    /// Additive identity.
    pub const ZERO: Self = Self(0);

    /// Multiplicative identity.
    pub const ONE: Self = Self(1);

    /// The polynomial indeterminate `x`.
    pub const X: Self = Self(2);

    /// Creates an element from its canonical bit representation.
    pub const fn from_u128(value: u128) -> Self {
        Self(value)
    }

    /// Returns the canonical bit representation.
    pub const fn to_u128(self) -> u128 {
        self.0
    }

    /// Returns whether this is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Squares this element.
    pub fn square(self) -> Self {
        self * self
    }

    /// Raises this element to `exponent`.
    pub fn pow(self, mut exponent: u128) -> Self {
        let mut base = self;
        let mut acc = Self::ONE;

        while exponent != 0 {
            if exponent & 1 == 1 {
                acc *= base;
            }
            base = base.square();
            exponent >>= 1;
        }

        acc
    }

    /// Returns the multiplicative inverse, or `None` for zero.
    pub fn invert(self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        Some(self.pow(u128::MAX - 1))
    }

    fn mul_x(self) -> Self {
        let carry = self.0 >> 127;
        let mut shifted = self.0 << 1;
        if carry != 0 {
            shifted ^= REDUCTION;
        }
        Self(shifted)
    }
}

impl fmt::Debug for Gf128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Gf128(0x{:032x})", self.0)
    }
}

impl From<u128> for Gf128 {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

impl From<Gf128> for u128 {
    fn from(value: Gf128) -> Self {
        value.to_u128()
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for Gf128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl AddAssign for Gf128 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Sub for Gf128 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl SubAssign for Gf128 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for Gf128 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut acc = Self::ZERO;
        let mut a = self;
        let mut b = rhs.0;

        while b != 0 {
            if b & 1 == 1 {
                acc += a;
            }
            a = a.mul_x();
            b >>= 1;
        }

        acc
    }
}

impl MulAssign for Gf128 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seed: &mut u128) -> Gf128 {
        *seed = seed
            .wrapping_mul(0xd134_2543_de82_ef95_d134_2543_de82_ef95)
            .wrapping_add(0x9e37_79b9_7f4a_7c15_6a09_e667_f3bc_c909);
        Gf128::from_u128(*seed)
    }

    fn schoolbook_mul(lhs: Gf128, rhs: Gf128) -> Gf128 {
        let mut terms = [false; 256];

        for lhs_bit in 0..128 {
            if (lhs.to_u128() >> lhs_bit) & 1 == 0 {
                continue;
            }

            for rhs_bit in 0..128 {
                if (rhs.to_u128() >> rhs_bit) & 1 == 1 {
                    terms[lhs_bit + rhs_bit] ^= true;
                }
            }
        }

        for bit in (128..256).rev() {
            if !terms[bit] {
                continue;
            }

            terms[bit] = false;
            let offset = bit - 128;
            terms[offset + 7] ^= true;
            terms[offset + 2] ^= true;
            terms[offset + 1] ^= true;
            terms[offset] ^= true;
        }

        let mut out = 0u128;
        for (bit, term) in terms.iter().enumerate().take(128) {
            if *term {
                out |= 1u128 << bit;
            }
        }
        Gf128::from_u128(out)
    }

    #[test]
    fn gf128_known_vectors() {
        assert_eq!(Gf128::ZERO * Gf128::ONE, Gf128::ZERO);
        assert_eq!(
            Gf128::ONE * Gf128::from_u128(0xabc),
            Gf128::from_u128(0xabc)
        );
        assert_eq!(Gf128::X * Gf128::X, Gf128::from_u128(4));
        assert_eq!(
            Gf128::from_u128(1u128 << 127) * Gf128::X,
            Gf128::from_u128(0x87)
        );
        assert_eq!(
            Gf128::from_u128(1u128 << 127) * Gf128::from_u128(4),
            Gf128::from_u128(0x10e)
        );
    }

    #[test]
    fn gf128_mul_matches_schoolbook_reduction() {
        let mut seed = 1u128;

        for _ in 0..128 {
            let lhs = sample(&mut seed);
            let rhs = sample(&mut seed);
            assert_eq!(lhs * rhs, schoolbook_mul(lhs, rhs));
        }
    }

    #[test]
    fn gf128_field_laws_representative() {
        let mut seed = 7u128;

        for _ in 0..128 {
            let a = sample(&mut seed);
            let b = sample(&mut seed);
            let c = sample(&mut seed);

            assert_eq!(a + b, b + a);
            assert_eq!((a + b) + c, a + (b + c));
            assert_eq!(a * b, b * a);
            assert_eq!((a * b) * c, a * (b * c));
            assert_eq!(a * (b + c), (a * b) + (a * c));
            assert_eq!(a + Gf128::ZERO, a);
            assert_eq!(a * Gf128::ONE, a);
            assert_eq!(a - a, Gf128::ZERO);
        }
    }

    #[test]
    fn gf128_inverse_roundtrip() {
        let mut seed = 11u128;

        for _ in 0..32 {
            let element = sample(&mut seed);
            let inverse = element
                .invert()
                .expect("sampled nonzero element has inverse");
            assert_eq!(element * inverse, Gf128::ONE);
        }

        assert_eq!(Gf128::ZERO.invert(), None);
    }
}
