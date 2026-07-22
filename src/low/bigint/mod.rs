use std::ops::{Shl, ShlAssign, Shr, ShrAssign};

use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BigInt(pub i64);

macro_rules! forward_binop {
    ($trait:ident, $method:ident, $op:tt) => {
        impl std::ops::$trait for BigInt {
            type Output = Self;
            fn $method(self, rhs: Self) -> Self::Output {
                BigInt(self.0 $op rhs.0)
            }
        }
    };
}

macro_rules! forward_binop_assign {
    ($trait:ident, $method:ident, $op:tt) => {
        impl std::ops::$trait for BigInt {
            fn $method(&mut self, rhs: Self) {
                self.0 $op rhs.0;
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

impl Shl<u32> for BigInt {
    type Output = Self;
    fn shl(self, rhs: u32) -> Self::Output {
        BigInt(self.0 << rhs)
    }
}

impl ShlAssign<u32> for BigInt {
    fn shl_assign(&mut self, rhs: u32) {
        self.0 <<= rhs;
    }
}

impl Shr<u32> for BigInt {
    type Output = Self;
    fn shr(self, rhs: u32) -> Self::Output {
        BigInt(self.0 >> rhs)
    }
}

impl ShrAssign<u32> for BigInt {
    fn shr_assign(&mut self, rhs: u32) {
        self.0 >>= rhs;
    }
}

impl From<i64> for BigInt {
    fn from(value: i64) -> Self {
        BigInt(value)
    }
}

impl TryFrom<BigInt> for i64 {
    type Error = std::convert::Infallible;

    fn try_from(value: BigInt) -> Result<Self, Self::Error> {
        Ok(value.0)
    }
}

impl std::str::FromStr for BigInt {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        i64::from_str_radix(s, 10).map(BigInt)
    }
}

impl ToString for BigInt {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::BigInt;

    #[test]
    fn test_bigintlike() {
        let zero = BigInt::from(0i64);
        let one = BigInt::from(1i64);
        assert_eq!(zero + one, BigInt::from(1i64));
        assert_eq!(one + one, BigInt::from(2i64));
        assert_eq!(one * one, BigInt::from(1i64));
        assert_eq!(
            BigInt::from(-5i64) + BigInt::from(1i64),
            BigInt::from(-4i64)
        );
    }
}
