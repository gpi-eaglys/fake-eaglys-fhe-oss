use std::{
    ops::{Shl, ShlAssign, Shr, ShrAssign},
    str::FromStr,
};

use ruint::aliases::U128;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct BigUint(pub U128);

impl BigUint {
    pub fn to_le_bytes(&self) -> Vec<u8> {
        self.0.to_le_bytes_trimmed_vec()
    }

    pub fn from_le_bytes(bytes: &[u8]) -> Self {
        BigUint(
            U128::try_from_le_slice(bytes).expect("value too large for 128-bit BigUint backend"),
        )
    }
}

impl Serialize for BigUint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_le_bytes())
    }
}

impl<'de> Deserialize<'de> for BigUint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        U128::try_from_le_slice(&bytes)
            .map(BigUint)
            .ok_or_else(|| serde::de::Error::custom("value too large for 128-bit BigUint backend"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PortableBigUint(pub String);

impl From<&BigUint> for PortableBigUint {
    fn from(value: &BigUint) -> Self {
        PortableBigUint(value.to_string())
    }
}

impl TryFrom<PortableBigUint> for BigUint {
    type Error = <U128 as FromStr>::Err;

    fn try_from(value: PortableBigUint) -> Result<Self, Self::Error> {
        U128::from_str(&value.0).map(BigUint)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PortableBigUintBytes(pub Vec<u8>);

impl From<&BigUint> for PortableBigUintBytes {
    fn from(value: &BigUint) -> Self {
        PortableBigUintBytes(value.to_le_bytes())
    }
}

impl PortableBigUintBytes {
    pub fn into_biguint(self) -> BigUint {
        BigUint::from_le_bytes(&self.0)
    }
}

macro_rules! forward_binop {
    ($trait:ident, $method:ident, $op:tt) => {
        impl std::ops::$trait for BigUint {
            type Output = Self;
            fn $method(self, rhs: Self) -> Self::Output {
                BigUint(self.0 $op rhs.0)
            }
        }
    };
}

macro_rules! forward_binop_assign {
    ($trait:ident, $method:ident, $op:tt) => {
        impl std::ops::$trait for BigUint {
            fn $method(&mut self, rhs: Self) {
                self.0 $op rhs.0;
            }
        }
    };
}

macro_rules! forward_binop_rhs_ref {
    ($trait:ident, $method:ident, $op:tt) => {
        impl std::ops::$trait<&BigUint> for BigUint {
            type Output = Self;
            fn $method(self, rhs: &BigUint) -> Self::Output {
                BigUint(self.0 $op rhs.0)
            }
        }
    };
}

forward_binop!(Add, add, +);
forward_binop_assign!(AddAssign, add_assign, +=);
forward_binop!(Sub, sub, -);
forward_binop_assign!(SubAssign, sub_assign, -=);
forward_binop!(Mul, mul, *);
forward_binop_assign!(MulAssign, mul_assign, *=);
forward_binop!(Div, div, /);
forward_binop_assign!(DivAssign, div_assign, /=);
forward_binop!(Rem, rem, %);
forward_binop_assign!(RemAssign, rem_assign, %=);
forward_binop!(BitAnd, bitand, &);
forward_binop_assign!(BitAndAssign, bitand_assign, &=);
forward_binop!(BitOr, bitor, |);
forward_binop_assign!(BitOrAssign, bitor_assign, |=);
forward_binop!(BitXor, bitxor, ^);
forward_binop_assign!(BitXorAssign, bitxor_assign, ^=);

forward_binop_rhs_ref!(Add, add, +);
forward_binop_rhs_ref!(Sub, sub, -);
forward_binop_rhs_ref!(Mul, mul, *);
forward_binop_rhs_ref!(Div, div, /);
forward_binop_rhs_ref!(Rem, rem, %);

impl Shl<u32> for BigUint {
    type Output = Self;
    fn shl(self, rhs: u32) -> Self::Output {
        BigUint(self.0 << rhs)
    }
}

impl ShlAssign<u32> for BigUint {
    fn shl_assign(&mut self, rhs: u32) {
        self.0 <<= rhs;
    }
}

impl Shl<u64> for BigUint {
    type Output = Self;
    fn shl(self, rhs: u64) -> Self::Output {
        let bits = usize::try_from(rhs).expect("shift too large for 128-bit BigUint backend");
        BigUint(self.0 << bits)
    }
}

impl ShlAssign<u64> for BigUint {
    fn shl_assign(&mut self, rhs: u64) {
        let bits = usize::try_from(rhs).expect("shift too large for 128-bit BigUint backend");
        self.0 <<= bits;
    }
}

impl Shl<usize> for BigUint {
    type Output = Self;
    fn shl(self, rhs: usize) -> Self::Output {
        BigUint(self.0 << rhs)
    }
}

impl ShlAssign<usize> for BigUint {
    fn shl_assign(&mut self, rhs: usize) {
        self.0 <<= rhs;
    }
}

impl Shl<i32> for BigUint {
    type Output = Self;
    fn shl(self, rhs: i32) -> Self::Output {
        let bits = usize::try_from(rhs).expect("shift must be non-negative");
        BigUint(self.0 << bits)
    }
}

impl ShlAssign<i32> for BigUint {
    fn shl_assign(&mut self, rhs: i32) {
        let bits = usize::try_from(rhs).expect("shift must be non-negative");
        self.0 <<= bits;
    }
}

impl Shr<u32> for BigUint {
    type Output = Self;
    fn shr(self, rhs: u32) -> Self::Output {
        BigUint(self.0 >> rhs)
    }
}

impl ShrAssign<u32> for BigUint {
    fn shr_assign(&mut self, rhs: u32) {
        self.0 >>= rhs;
    }
}

impl From<u64> for BigUint {
    fn from(value: u64) -> Self {
        BigUint(U128::from(value))
    }
}

impl From<i32> for BigUint {
    fn from(value: i32) -> Self {
        let as_u64 = u64::try_from(value).expect("negative value is not supported for BigUint");
        BigUint(U128::from(as_u64))
    }
}

impl From<u128> for BigUint {
    fn from(value: u128) -> Self {
        BigUint(U128::from(value))
    }
}

impl TryFrom<BigUint> for u64 {
    type Error = <u64 as TryFrom<U128>>::Error;

    fn try_from(value: BigUint) -> Result<Self, Self::Error> {
        u64::try_from(value.0)
    }
}

impl TryFrom<&BigUint> for u64 {
    type Error = <u64 as TryFrom<U128>>::Error;

    fn try_from(value: &BigUint) -> Result<Self, Self::Error> {
        u64::try_from(value.0)
    }
}

impl std::str::FromStr for BigUint {
    type Err = <U128 as std::str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        U128::from_str(s).map(BigUint)
    }
}

impl ToString for BigUint {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

pub fn addmod(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    BigUint(a.0.add_mod(b.0, modulus.0))
}

pub fn submod(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus.0.is_zero() {
        return BigUint::default();
    }

    let lhs = a.0.reduce_mod(modulus.0);
    let rhs = b.0.reduce_mod(modulus.0);

    if lhs >= rhs {
        BigUint(lhs - rhs)
    } else {
        BigUint(modulus.0 - (rhs - lhs))
    }
}

pub fn mulmod(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    BigUint(a.0.mul_mod(b.0, modulus.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addmod() {
        let m = BigUint::from(7u64);
        let a = BigUint::from(5u64);
        let b = BigUint::from(6u64);
        assert_eq!(addmod(&a, &b, &m), BigUint::from(4u64));
    }

    #[test]
    fn test_submod() {
        let m = BigUint::from(7u64);
        let a = BigUint::from(2u64);
        let b = BigUint::from(5u64);
        assert_eq!(submod(&a, &b, &m), BigUint::from(4u64));
    }

    #[test]
    fn test_mulmod() {
        let m = BigUint::from(11u64);
        let a = BigUint::from(7u64);
        let b = BigUint::from(9u64);
        assert_eq!(mulmod(&a, &b, &m), BigUint::from(8u64));
    }

    #[test]
    fn test_addmod_overflow_near_u128_limit() {
        let m = BigUint::from(u128::MAX - (1_u128 << 54) + 2);
        let a = BigUint::from(u128::MAX - (1_u128 << 54) + 1);
        let b = BigUint::from(u128::MAX - (1_u128 << 54) + 1);

        assert_eq!(
            addmod(&a, &b, &m),
            BigUint::from(u128::MAX - (1_u128 << 54))
        );
    }

    #[test]
    fn test_mulmod_near_u128_limit() {
        let m = BigUint::from(u128::MAX - (1_u128 << 54) + 2);
        let a = BigUint::from(u128::MAX - (1_u128 << 54) + 1);
        let b = BigUint::from(u128::MAX - (1_u128 << 54) + 1);

        assert_eq!(mulmod(&a, &b, &m), BigUint::from(1u64));
    }

    #[test]
    fn test_portable_roundtrip() {
        let value = BigUint::from(u128::MAX - 17);
        let portable = PortableBigUint::from(&value);
        let decoded: BigUint = portable.try_into().expect("convert portable biguint");
        assert_eq!(decoded, value);

        let portable_bytes = PortableBigUintBytes::from(&value);
        let decoded_bytes = portable_bytes.into_biguint();
        assert_eq!(decoded_bytes, value);
    }
}
