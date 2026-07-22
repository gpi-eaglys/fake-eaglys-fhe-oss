use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::low::biguint::BigUint;
use crate::low::{
    module::Module,
    modulus::{ModulusPattern, TwoPowerModulusPattern},
    torus::Torus,
    torus_polynomial::{TorusPolynomial, TorusPolynomialParameter},
};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(bound = "M: ModulusPattern")]
pub struct TorusPolynomialVec<M: ModulusPattern> {
    pub poly: Vec<TorusPolynomial<M>>,
}

impl<M: ModulusPattern> TorusPolynomialVec<M> {
    pub fn new(poly: Vec<TorusPolynomial<M>>) -> Self {
        Self { poly }
    }
}

impl<M: ModulusPattern> Module<TorusPolynomialParameter> for TorusPolynomialVec<M> {
    fn add(&self, other: &Self, param: &TorusPolynomialParameter) -> Self {
        debug_assert!(self.poly.len() == other.poly.len(), "length mismatch");
        Self::new(
            self.poly
                .iter()
                .zip(other.poly.iter())
                .map(|(a, b)| a.add(b, param))
                .collect(),
        )
    }

    fn sub(&self, other: &Self, param: &TorusPolynomialParameter) -> Self {
        debug_assert!(self.poly.len() == other.poly.len(), "length mismatch");
        Self::new(
            self.poly
                .iter()
                .zip(other.poly.iter())
                .map(|(a, b)| a.sub(b, param))
                .collect(),
        )
    }

    fn scalar_mul(&self, other: &u64, param: &TorusPolynomialParameter) -> Self {
        Self::new(
            self.poly
                .iter()
                .map(|a| a.scalar_mul(other, param))
                .collect(),
        )
    }
}

impl TorusPolynomialVec<TwoPowerModulusPattern> {
    // scalar vector multiplication
    pub fn rotate_left(
        &self,
        n: usize,
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomialVec<TwoPowerModulusPattern> {
        let torus_polynomial_vec: Vec<TorusPolynomial<TwoPowerModulusPattern>> =
            self.poly.iter().map(|a| a.rotate_left(n, param)).collect();

        TorusPolynomialVec::new(torus_polynomial_vec)
    }

    pub fn rotate_right(
        &self,
        n: usize,
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomialVec<TwoPowerModulusPattern> {
        let torus_polynomial_vec: Vec<TorusPolynomial<TwoPowerModulusPattern>> =
            self.poly.iter().map(|a| a.rotate_right(n, param)).collect();

        TorusPolynomialVec::new(torus_polynomial_vec)
    }

    pub fn inner_product(
        &self,
        other: &Self,
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomial<TwoPowerModulusPattern> {
        let torus_polynomial_vec: Vec<TorusPolynomial<TwoPowerModulusPattern>> = self
            .poly
            .iter()
            .zip(other.poly.iter())
            .map(|(a, b)| a.torus_vec_mul(b, param))
            .collect();

        let mut torus_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(0); torus_polynomial_vec[0].coeffs.len()]);

        for ith_torus_poly in torus_polynomial_vec {
            torus_poly = torus_poly.add(&ith_torus_poly, param);
        }

        torus_poly
    }

    pub fn inner_product_ntt(
        &self,
        other: &Self,
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomial<TwoPowerModulusPattern> {
        let torus_polynomial_vec: Vec<TorusPolynomial<TwoPowerModulusPattern>> = self
            .poly
            .iter()
            .zip(other.poly.iter())
            .map(|(a, b)| a.scalar_vec_mul_ntt(b, param))
            .collect();

        let mut torus_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(0); torus_polynomial_vec[0].coeffs.len()]);

        for ith_torus_poly in torus_polynomial_vec {
            torus_poly = torus_poly.add(&ith_torus_poly, param);
        }

        torus_poly
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::low::torus::TorusParam;

    #[test]
    fn test_new_returns_empty_poly() {
        let ring: TorusPolynomialVec<TwoPowerModulusPattern> = TorusPolynomialVec::new(vec![]);
        assert!(ring.poly.is_empty());
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
        let a: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![a_poly.clone(); 3]);
        let b_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(4), Torus::new(5), Torus::new(6)]);
        let b: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![b_poly.clone(); 3]);
        let result = a.add(&b, &param);
        let expected: Vec<u64> = vec![5, 7, 9];
        for i in 0..result.poly.len() {
            for (res, &exp) in result.poly[i].coeffs.iter().zip(expected.iter()) {
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
        let a: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![a_poly.clone(); 3]);
        let b_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(4), Torus::new(5), Torus::new(6)]);
        let b: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![b_poly.clone(); 3]);
        let result = b.sub(&a, &param);
        let expected: Vec<u64> = vec![3, 3, 3];
        for i in 0..result.poly.len() {
            for (res, &exp) in result.poly[i].coeffs.iter().zip(expected.iter()) {
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
        let a: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![a_poly.clone(); 3]);
        let scalar = 2;
        let result = a.scalar_mul(&scalar, &param);
        let expected: Vec<u64> = vec![2, 4, 6];
        for i in 0..result.poly.len() {
            for (res, &exp) in result.poly[i].coeffs.iter().zip(expected.iter()) {
                assert_eq!(res.value, exp);
            }
        }
    }

    #[test]
    fn test_rotate_left() {
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(1),
            ntt_prime_psi: BigUint::from(1),
            inverse_ntt_prime_psi: BigUint::from(1),
            ntt_prime_omega: BigUint::from(1),
            inverse_ntt_prime_omega: BigUint::from(1),
            inverse_poly_size: BigUint::from(1),
            torus_parameter: TorusParam { bitsize: 8 },
        };
        let a_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(2_u64.pow(8) - 2), Torus::new(2)]);
        let a: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![a_poly.clone(); 3]);
        let n: usize = 1;
        let result = a.rotate_left(n, &param);
        let expected: Vec<u64> = vec![2, 2];
        for i in 0..result.poly.len() {
            for (res, &exp) in result.poly[i].coeffs.iter().zip(expected.iter()) {
                assert_eq!(res.value, exp);
            }
        }
    }

    #[test]
    fn test_rotate_right() {
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(1),
            ntt_prime_psi: BigUint::from(1),
            inverse_ntt_prime_psi: BigUint::from(1),
            ntt_prime_omega: BigUint::from(1),
            inverse_ntt_prime_omega: BigUint::from(1),
            inverse_poly_size: BigUint::from(1),
            torus_parameter: TorusParam { bitsize: 8 },
        };
        let a_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(2), Torus::new(2_u64.pow(8) - 2)]);
        let a: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![a_poly.clone(); 3]);
        let n: usize = 1;
        let result = a.rotate_right(n, &param);
        let expected: Vec<u64> = vec![2, 2];
        for i in 0..result.poly.len() {
            for (res, &exp) in result.poly[i].coeffs.iter().zip(expected.iter()) {
                assert_eq!(res.value, exp);
            }
        }
    }

    #[test]
    fn test_inner_product() {
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
            TorusPolynomial::new(vec![Torus::new(1), Torus::new(1)]);
        let a: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![a_poly.clone(); 3]);
        let _b_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(1), Torus::new(1)]);
        let b: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![a_poly.clone(); 3]);
        let result = a.inner_product(&b, &param);
        let expected: Vec<u64> = vec![0, 6];
        for (res, &exp) in result.coeffs.iter().zip(expected.iter()) {
            assert_eq!(res.value, exp);
        }
    }

    // TODO: must accelerate inner_product_ntt because the execution time for
    // test_inner_product_ntt is about 5s
    #[test]
    fn test_inner_product_ntt() {
        let mut input_a: Vec<Torus> = Vec::new();
        let mut input_b: Vec<Torus> = Vec::new();
        // expected = [-65534, -65532, ..., 0, 2, 4, ..., 65536]
        let mut expected: Vec<u64> = Vec::new();

        for i in 0..65536 {
            input_a.push(Torus::new(1));
            input_b.push(Torus::new(1));
            // 32768 = 65536 / 2
            if i < 32767 {
                expected.push(u64::MAX - 2 * 65533 - 1 + 4 * i);
            } else {
                expected.push(4 * (i - 32767));
            }
        }

        let a_poly: TorusPolynomial<TwoPowerModulusPattern> = TorusPolynomial::new(input_a);
        let b_poly: TorusPolynomial<TwoPowerModulusPattern> = TorusPolynomial::new(input_b);

        let a: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![a_poly.clone(); 2]);
        let b: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![b_poly.clone(); 2]);
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 65536,
            log_polynomial_length: 16,
            prime_modulus: BigUint::from(u128::MAX - 2_u128.pow(54) + 2),
            ntt_prime_psi: BigUint::from(15479278773488526269853478226682162690_u128),
            inverse_ntt_prime_psi: BigUint::from(149844963811214215698651536441648540446_u128),
            ntt_prime_omega: BigUint::from(274761496178149862042109796498575449673_u128),
            inverse_ntt_prime_omega: BigUint::from(276625252932050520471031159916991523792_u128),
            inverse_poly_size: BigUint::from(340277174624079928635728062811807416321_u128),
            torus_parameter: TorusParam { bitsize: 1 << 6 }, // 2^6 = 64bit
        };
        let result: TorusPolynomial<TwoPowerModulusPattern> = a.inner_product_ntt(&b, &param);
        for (res, &exp) in result.coeffs.iter().zip(expected.iter()) {
            assert_eq!(res.value, exp);
        }
    }
}
