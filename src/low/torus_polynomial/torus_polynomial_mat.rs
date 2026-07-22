use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::low::biguint::BigUint;
use crate::low::{
    module::Module,
    modulus::ModulusPattern,
    torus_polynomial::{TorusPolynomialParameter, torus_polynomial_vec::TorusPolynomialVec},
};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(bound = "M: ModulusPattern")]
pub struct TorusPolynomialMat<M: ModulusPattern> {
    pub poly_vec: Vec<TorusPolynomialVec<M>>,
}

impl<M: ModulusPattern> TorusPolynomialMat<M> {
    pub fn new(poly_vec: Vec<TorusPolynomialVec<M>>) -> Self {
        Self { poly_vec }
    }
}

impl<M: ModulusPattern> Module<TorusPolynomialParameter> for TorusPolynomialMat<M> {
    fn add(&self, other: &Self, param: &TorusPolynomialParameter) -> Self {
        debug_assert!(
            self.poly_vec.len() == other.poly_vec.len(),
            "length mismatch"
        );
        Self::new(
            self.poly_vec
                .iter()
                .zip(other.poly_vec.iter())
                .map(|(a, b)| a.add(b, param))
                .collect(),
        )
    }

    fn sub(&self, other: &Self, param: &TorusPolynomialParameter) -> Self {
        debug_assert!(
            self.poly_vec.len() == other.poly_vec.len(),
            "length mismatch"
        );
        Self::new(
            self.poly_vec
                .iter()
                .zip(other.poly_vec.iter())
                .map(|(a, b)| a.sub(b, param))
                .collect(),
        )
    }

    fn scalar_mul(&self, other: &u64, param: &TorusPolynomialParameter) -> Self {
        Self::new(
            self.poly_vec
                .iter()
                .map(|a| a.scalar_mul(other, param))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::low::{
        modulus::TwoPowerModulusPattern,
        torus::{Torus, TorusParam},
        torus_polynomial::TorusPolynomial,
    };

    #[test]
    fn test_new_returns_empty_poly() {
        let ring: TorusPolynomialMat<TwoPowerModulusPattern> = TorusPolynomialMat::new(vec![]);
        assert!(ring.poly_vec.is_empty());
    }

    #[test]
    fn test_add_correctness() {
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(1),
            ntt_prime_psi: BigUint::from(1),
            inverse_ntt_prime_psi: BigUint::from(1),
            ntt_prime_omega: BigUint::from(1),
            inverse_ntt_prime_omega: BigUint::from(1),
            inverse_poly_size: BigUint::from(1),
            torus_parameter: TorusParam { bitsize: 6 }, // 2^8 = 64bit
        };
        let a_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(1), Torus::new(2), Torus::new(3)]);
        let a_poly_vec: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![a_poly.clone(); 3]);
        let a: TorusPolynomialMat<TwoPowerModulusPattern> =
            TorusPolynomialMat::new(vec![a_poly_vec.clone(); 2]);
        let b_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(4), Torus::new(5), Torus::new(6)]);
        let b_poly_vec: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![b_poly.clone(); 3]);
        let b: TorusPolynomialMat<TwoPowerModulusPattern> =
            TorusPolynomialMat::new(vec![b_poly_vec.clone(); 2]);
        let result = a.add(&b, &param);
        let expected: Vec<u64> = vec![5, 7, 9];
        for i in 0..result.poly_vec.len() {
            for (res, &exp) in result.poly_vec[i].poly[0]
                .coeffs
                .iter()
                .zip(expected.iter())
            {
                assert_eq!(res.value, exp);
            }
        }
    }

    #[test]
    fn test_sub_correctness() {
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(1),
            ntt_prime_psi: BigUint::from(1),
            inverse_ntt_prime_psi: BigUint::from(1),
            ntt_prime_omega: BigUint::from(1),
            inverse_ntt_prime_omega: BigUint::from(1),
            inverse_poly_size: BigUint::from(1),
            torus_parameter: TorusParam { bitsize: 6 }, // 2^8 = 64bit
        };
        let a_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(1), Torus::new(2), Torus::new(3)]);
        let a_poly_vec: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![a_poly.clone(); 3]);
        let a: TorusPolynomialMat<TwoPowerModulusPattern> =
            TorusPolynomialMat::new(vec![a_poly_vec.clone(); 2]);
        let b_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(4), Torus::new(5), Torus::new(6)]);
        let b_poly_vec: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![b_poly.clone(); 3]);
        let b: TorusPolynomialMat<TwoPowerModulusPattern> =
            TorusPolynomialMat::new(vec![b_poly_vec.clone(); 2]);
        let result = b.sub(&a, &param);
        let expected: Vec<u64> = vec![3, 3, 3];
        for i in 0..result.poly_vec.len() {
            for (res, &exp) in result.poly_vec[i].poly[0]
                .coeffs
                .iter()
                .zip(expected.iter())
            {
                assert_eq!(res.value, exp);
            }
        }
    }

    #[test]
    fn test_scalar_mul_correctness() {
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(1),
            ntt_prime_psi: BigUint::from(1),
            inverse_ntt_prime_psi: BigUint::from(1),
            ntt_prime_omega: BigUint::from(1),
            inverse_ntt_prime_omega: BigUint::from(1),
            inverse_poly_size: BigUint::from(1),
            torus_parameter: TorusParam { bitsize: 6 }, // 2^8 = 64bit
        };
        let a_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(1), Torus::new(2), Torus::new(3)]);
        let a_poly_vec: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![a_poly.clone(); 3]);
        let a: TorusPolynomialMat<TwoPowerModulusPattern> =
            TorusPolynomialMat::new(vec![a_poly_vec.clone(); 2]);
        let scalar = 2;
        let result = a.scalar_mul(&scalar, &param);
        let expected: Vec<u64> = vec![2, 4, 6];
        for i in 0..result.poly_vec.len() {
            for (res, &exp) in result.poly_vec[i].poly[0]
                .coeffs
                .iter()
                .zip(expected.iter())
            {
                assert_eq!(res.value, exp);
            }
        }
    }
}
