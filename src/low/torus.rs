use serde::{Deserialize, Serialize};

use crate::low::{biguint::BigUint, module::Module};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Torus {
    pub value: u64,
}

#[derive(Copy, Clone, Default, Debug, Serialize, Deserialize)]
pub struct TorusParam {
    // TODO: rename TorusParameter
    pub bitsize: usize,
}

impl Torus {
    pub fn new(value: u64) -> Torus {
        Torus { value }
    }

    pub fn from_biguint_checked(value: &BigUint) -> Torus {
        let raw: u64 = value
            .clone()
            .try_into()
            .expect("torus values must fit into u64 for non-NTT storage");
        Torus::new(raw)
    }
}

impl TorusParam {
    #[inline]
    pub fn apply_modulus(&self, value: u64) -> u64 {
        assert!(
            self.bitsize <= 64,
            "torus bitsize > 64 is unsupported for non-NTT storage"
        );

        if self.bitsize == 64 {
            value
        } else if self.bitsize == 0 {
            0
        } else {
            value & ((1u64 << self.bitsize) - 1)
        }
    }
}

impl Module<TorusParam> for Torus {
    fn add(&self, other: &Self, param: &TorusParam) -> Self {
        Torus::new(param.apply_modulus(self.value.wrapping_add(other.value)))
    }
    fn sub(&self, other: &Self, param: &TorusParam) -> Self {
        Torus::new(param.apply_modulus(self.value.wrapping_sub(other.value)))
    }
    fn scalar_mul(&self, other: &u64, param: &TorusParam) -> Self {
        Torus::new(param.apply_modulus(self.value.wrapping_mul(*other)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let param = TorusParam { bitsize: 8 };
        let a = Torus::new(10);
        let b = Torus::new(20);
        let c = a.add(&b, &param);
        assert_eq!(c.value, 30);

        // Overflow addition: 255 + 1 mod 256 = 0
        let max = Torus::new(255);
        let one = Torus::new(1);
        let res = max.add(&one, &param);
        assert_eq!(res.value, 0);
    }

    #[test]
    fn test_sub() {
        let param = TorusParam { bitsize: 8 };
        let a = Torus::new(10);
        let b = Torus::new(5);
        let c = a.sub(&b, &param);
        assert_eq!(c.value, 5);

        // Underflow subtraction: 0 - 1 mod 256 = 255
        let zero = Torus::new(0);
        let one = Torus::new(1);
        let res = zero.sub(&one, &param);
        assert_eq!(res.value, 255);
    }

    #[test]
    fn test_scalar_mul() {
        let param = TorusParam { bitsize: 8 };
        let a = Torus::new(3);
        let b = 4;
        let c = a.scalar_mul(&b, &param);
        assert_eq!(c.value, 12);

        // Overflow multiplication: 200 * 2 mod 256 = 144
        let max = Torus::new(200);
        let two = 2;
        let res = max.scalar_mul(&two, &param);
        assert_eq!(res.value, 144);
    }

    #[test]
    #[should_panic(expected = "torus bitsize > 64 is unsupported for non-NTT storage")]
    fn test_apply_modulus_for_large_bitsize_panics() {
        let param = TorusParam { bitsize: 256 };
        let _ = param.apply_modulus(u64::MAX);
    }
}
