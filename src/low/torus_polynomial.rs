use serde::{Deserialize, Serialize};

use crate::low::{
    biguint::{BigUint, mulmod},
    math::ntt::{
        biguint_vec_element_wise_multiplication,
        convert_biguint_vec_to_torus_polynomial_for_poly_mul,
        convert_torus_polynomial_to_biguint_vec, generate_bit_reversed_inverse_twiddle_list,
        generate_bit_reversed_twiddle_list, intt_butterfly_operation_gentleman_sande_type,
        multiply_inverse_psi_power_list, multiply_psi_power_list,
        ntt_butterfly_operation_cooley_tukey_type,
    },
    module::Module,
    modulus::{GeneralModulusPattern, ModulusPattern, TwoPowerModulusPattern},
    torus::{Torus, TorusParam},
};

pub mod torus_polynomial_mat;
pub mod torus_polynomial_vec;
// Operations to implement: add, sub, mul, mul w/ scalar
// Think about adding generics parameter for NTT: NTTCS, NTTGS

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct TorusPolynomialParameter {
    pub polynomial_length: usize,

    // only ntt
    pub log_polynomial_length: usize,
    pub prime_modulus: BigUint,

    pub ntt_prime_psi: BigUint,
    pub inverse_ntt_prime_psi: BigUint,
    pub ntt_prime_omega: BigUint,
    pub inverse_ntt_prime_omega: BigUint,
    pub inverse_poly_size: BigUint,
    pub torus_parameter: TorusParam,
}

impl TorusPolynomialParameter {
    #[inline(always)]
    pub fn prime_modulus_bit_width(&self) -> usize {
        (1usize.wrapping_shl(self.torus_parameter.bitsize as u32)) << 1
    }
}
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct TorusPolynomial<M: ModulusPattern> {
    pub coeffs: Vec<Torus>, // TODO: need to decide this name ( poly vs coeffs )
    _modulus_pattern: std::marker::PhantomData<M>,
}

impl<M: ModulusPattern> TorusPolynomial<M> {
    pub fn new(coeffs: Vec<Torus>) -> TorusPolynomial<M> {
        TorusPolynomial {
            coeffs,
            _modulus_pattern: std::marker::PhantomData,
        }
    }
}

impl<M: ModulusPattern> Module<TorusPolynomialParameter> for TorusPolynomial<M> {
    fn add(
        &self,
        other: &TorusPolynomial<M>,
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomial<M> {
        debug_assert!(self.coeffs.len() == other.coeffs.len(), "length mismatch");
        TorusPolynomial::new(
            self.coeffs
                .iter()
                .zip(other.coeffs.iter())
                .map(|(a, b)| a.add(b, &param.torus_parameter))
                .collect(),
        )
    }

    fn sub(
        &self,
        other: &TorusPolynomial<M>,
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomial<M> {
        debug_assert!(self.coeffs.len() == other.coeffs.len(), "length mismatch");
        TorusPolynomial::new(
            self.coeffs
                .iter()
                .zip(other.coeffs.iter())
                .map(|(a, b)| a.sub(b, &param.torus_parameter))
                .collect(),
        )
    }

    fn scalar_mul(&self, other: &u64, param: &TorusPolynomialParameter) -> TorusPolynomial<M> {
        TorusPolynomial::new(
            self.coeffs
                .iter()
                .map(|a| a.scalar_mul(other, &param.torus_parameter))
                .collect(),
        )
    }
}

impl TorusPolynomial<TwoPowerModulusPattern> {
    // scalar vector multiplication
    fn scalar_vec_mul(
        &self,
        other: &[u64],
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomial<TwoPowerModulusPattern> {
        let mut extended_coeffs_vec: Vec<Torus> = Vec::new();

        // init extended_coeffs_vec
        for _ in 0..(2 * param.polynomial_length) {
            extended_coeffs_vec.push(Torus::new(0));
        }

        for i in 0..self.coeffs.len() {
            for (j, scalar) in other.iter().enumerate() {
                let coeff = self.coeffs[i].scalar_mul(scalar, &param.torus_parameter);
                extended_coeffs_vec[i + j] =
                    extended_coeffs_vec[i + j].add(&coeff, &param.torus_parameter);
            }
        }

        let extended_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(extended_coeffs_vec);

        extended_poly.rem(param)
    }

    // scalar vector multiplication
    fn torus_vec_mul(
        &self,
        other: &TorusPolynomial<TwoPowerModulusPattern>, /* TODO: need to consider to make
                                                          * struct for Vec<S> */
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomial<TwoPowerModulusPattern> {
        let mut extended_coeffs_vec: Vec<Torus> = Vec::new();

        // init extended_coeffs_vec
        for _ in 0..(2 * param.polynomial_length) {
            extended_coeffs_vec.push(Torus::new(0));
        }

        for i in 0..self.coeffs.len() {
            for j in 0..other.coeffs.len() {
                let coeff = Torus::new(
                    param
                        .torus_parameter
                        .apply_modulus(self.coeffs[i].value.wrapping_mul(other.coeffs[j].value)),
                );
                extended_coeffs_vec[i + j] =
                    extended_coeffs_vec[i + j].add(&coeff, &param.torus_parameter);
            }
        }

        let extended_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(extended_coeffs_vec);

        extended_poly.rem(param)
    }

    // ntt algorithm for ciphertext
    // TODO: restructure ntt/intt interface functions
    pub fn ntt_for_torus_polynomial(&self, param: &TorusPolynomialParameter) -> Vec<BigUint> {
        // transform TorusPolynomial into a vector of BigUint
        let ctxt_vec: Vec<BigUint> = convert_torus_polynomial_to_biguint_vec(self, param);

        let ntt_data_vec: Vec<BigUint> = multiply_psi_power_list(&ctxt_vec, param);

        let twiddle_list: Vec<Vec<BigUint>> = generate_bit_reversed_twiddle_list(param);

        ntt_butterfly_operation_cooley_tukey_type(&ntt_data_vec, &twiddle_list, param)
    }

    // ntt algorithm for bootstrap key
    pub fn ntt_from_bootstrap_key(&self, param: &TorusPolynomialParameter) -> Vec<BigUint> {
        // transform TorusPolynomial into a vector of BigUint
        let ctxt_vec: Vec<BigUint> = convert_torus_polynomial_to_biguint_vec(self, param);

        let mut ntt_data_vec: Vec<BigUint> = multiply_psi_power_list(&ctxt_vec, param);

        let twiddle_list: Vec<Vec<BigUint>> = generate_bit_reversed_twiddle_list(param);

        ntt_data_vec =
            ntt_butterfly_operation_cooley_tukey_type(&ntt_data_vec, &twiddle_list, param);

        for i in 0..ntt_data_vec.len() {
            ntt_data_vec[i] = mulmod(
                &ntt_data_vec[i],
                &param.inverse_poly_size,
                &param.prime_modulus,
            );
        }

        ntt_data_vec
    }

    pub fn intt_to_torus_polynomial(
        ntt_data_vec: &[BigUint],
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomial<TwoPowerModulusPattern> {
        let inverse_twiddle_list: Vec<Vec<BigUint>> =
            generate_bit_reversed_inverse_twiddle_list(param);

        let intt_data_vec = intt_butterfly_operation_gentleman_sande_type(
            ntt_data_vec,
            &inverse_twiddle_list,
            param,
        );

        let inverse_psi_intt_data_vec = multiply_inverse_psi_power_list(&intt_data_vec, param);

        convert_biguint_vec_to_torus_polynomial_for_poly_mul(&inverse_psi_intt_data_vec, param)
    }

    // scalar vector multiplication with ntt
    fn scalar_vec_mul_ntt(
        &self,
        other: &TorusPolynomial<TwoPowerModulusPattern>, /* TODO: need to consider to make
                                                          * struct
                                                          * for Vec<S> */
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomial<TwoPowerModulusPattern> {
        let ntt_ctxt: Vec<BigUint> = self.ntt_for_torus_polynomial(param);
        let ntt_bootstrap_key: Vec<BigUint> = other.ntt_from_bootstrap_key(param);

        let poly_mul: Vec<BigUint> =
            biguint_vec_element_wise_multiplication(&ntt_ctxt, &ntt_bootstrap_key, param);

        TorusPolynomial::<TwoPowerModulusPattern>::intt_to_torus_polynomial(&poly_mul, param)
    }

    fn rotate_left(
        &self,
        n: usize,
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomial<TwoPowerModulusPattern> {
        let mut extended_coeffs_vec: Vec<Torus> = Vec::new();

        // init extended_coeffs_vec
        for _ in 0..(2 * param.polynomial_length) {
            extended_coeffs_vec.push(Torus::new(0));
        }

        // TODO: consider to use clone
        for i in 0..self.coeffs.len() {
            if i < n {
                extended_coeffs_vec[2 * param.polynomial_length - n + i] = self.coeffs[i].clone();
            } else {
                extended_coeffs_vec[i - n] = self.coeffs[i].clone();
            }
        }

        let extended_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(extended_coeffs_vec);

        extended_poly.rem(param)
    }

    pub fn rotate_right(
        &self,
        n: usize,
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomial<TwoPowerModulusPattern> {
        let mut extended_coeffs_vec: Vec<Torus> = Vec::new();

        // init extended_coeffs_vec
        for _ in 0..(2 * param.polynomial_length) {
            extended_coeffs_vec.push(Torus::new(0));
        }

        for i in 0..self.coeffs.len() {
            if i + n < (2 * param.polynomial_length) {
                extended_coeffs_vec[i + n] = self.coeffs[i].clone();
            } else {
                extended_coeffs_vec[i + n - (2 * param.polynomial_length)] = self.coeffs[i].clone();
            }
        }

        let extended_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(extended_coeffs_vec);

        extended_poly.rem(param)
    }

    fn rem(&self, param: &TorusPolynomialParameter) -> TorusPolynomial<TwoPowerModulusPattern> {
        let mut coeffs_vec: Vec<Torus> = Vec::new();

        // init coeffs_vec
        for _ in 0..param.polynomial_length {
            coeffs_vec.push(Torus::new(0));
        }

        for i in 0..self.coeffs.len() {
            if i < param.polynomial_length {
                coeffs_vec[i] = coeffs_vec[i].add(&self.coeffs[i], &param.torus_parameter);
            } else {
                coeffs_vec[i - param.polynomial_length] = coeffs_vec[i - param.polynomial_length]
                    .sub(&self.coeffs[i], &param.torus_parameter);
            }
        }

        TorusPolynomial::new(coeffs_vec)
    }
}

impl TorusPolynomial<GeneralModulusPattern> {
    // scalar vector multiplication
    fn scalar_vec_mul(
        &self,
        other: &[u64], // TODO: need to consider to make struct for Vec<S>
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomial<GeneralModulusPattern> {
        todo!();
    }

    fn rotate_left(
        &self,
        n: BigUint,
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomial<GeneralModulusPattern> {
        todo!();
    }

    fn rotate_right(
        &self,
        n: BigUint,
        param: &TorusPolynomialParameter,
    ) -> TorusPolynomial<GeneralModulusPattern> {
        todo!();
    }

    fn rem(&self, param: &()) -> TorusPolynomial<GeneralModulusPattern> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_returns_empty_poly() {
        let ring: TorusPolynomial<TwoPowerModulusPattern> = TorusPolynomial::new(vec![]);
        assert!(ring.coeffs.is_empty());
    }

    #[test]
    fn test_add_correctness() {
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 0,
            log_polynomial_length: 0,
            prime_modulus: BigUint::from(0),
            ntt_prime_psi: BigUint::from(0),
            inverse_ntt_prime_psi: BigUint::from(0),
            ntt_prime_omega: BigUint::from(0),
            inverse_ntt_prime_omega: BigUint::from(0),
            inverse_poly_size: BigUint::from(0),
            torus_parameter: TorusParam { bitsize: 8 },
        };
        let a: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(1), Torus::new(2), Torus::new(3)]);

        let b: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(4), Torus::new(5), Torus::new(6)]);
        let result = a.add(&b, &param);
        let expected: Vec<u64> = vec![5, 7, 9];
        for (res, &exp) in result.coeffs.iter().zip(expected.iter()) {
            assert_eq!(res.value, exp);
        }
    }

    #[test]
    fn test_sub_correctness() {
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 0,
            log_polynomial_length: 0,
            prime_modulus: BigUint::from(0),
            ntt_prime_psi: BigUint::from(0),
            inverse_ntt_prime_psi: BigUint::from(0),
            ntt_prime_omega: BigUint::from(0),
            inverse_ntt_prime_omega: BigUint::from(0),
            inverse_poly_size: BigUint::from(0),
            torus_parameter: TorusParam { bitsize: 8 },
        };
        let a: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(1), Torus::new(2), Torus::new(3)]);

        let b: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(4), Torus::new(5), Torus::new(6)]);
        let result = b.sub(&a, &param);
        let expected: Vec<u64> = vec![3, 3, 3];
        for (res, &exp) in result.coeffs.iter().zip(expected.iter()) {
            assert_eq!(res.value, exp);
        }
    }

    #[test]
    fn test_scalar_mul_correctness() {
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 0,
            log_polynomial_length: 0,
            prime_modulus: BigUint::from(0),
            ntt_prime_psi: BigUint::from(0),
            inverse_ntt_prime_psi: BigUint::from(0),
            ntt_prime_omega: BigUint::from(0),
            inverse_ntt_prime_omega: BigUint::from(0),
            inverse_poly_size: BigUint::from(0),
            torus_parameter: TorusParam { bitsize: 8 },
        };
        let a: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(1), Torus::new(2), Torus::new(3)]);
        let scalar = 2;
        let result = a.scalar_mul(&scalar, &param);
        let expected: Vec<u64> = vec![2, 4, 6];
        for (res, &exp) in result.coeffs.iter().zip(expected.iter()) {
            assert_eq!(res.value, exp);
        }
    }

    #[test]
    fn test_rem() {
        let a: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(3), Torus::new(2), Torus::new(1)]);
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
        let result = a.rem(&param);
        let expected: Vec<u64> = vec![2, 2];
        for (res, &exp) in result.coeffs.iter().zip(expected.iter()) {
            assert_eq!(res.value, exp);
        }
    }

    #[test]
    fn test_scalar_vec_mul() {
        let a: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(1), Torus::new(1)]);
        let b: Vec<u64> = vec![1, 1];
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(1),
            ntt_prime_psi: BigUint::from(1),
            inverse_ntt_prime_psi: BigUint::from(1),
            ntt_prime_omega: BigUint::from(1),
            inverse_ntt_prime_omega: BigUint::from(1),
            inverse_poly_size: BigUint::from(1),
            torus_parameter: TorusParam { bitsize: 6 }, // 2^6 = 64bit
        };
        let result = a.scalar_vec_mul(&b, &param);
        let expected: Vec<u64> = vec![0, 2];
        for (res, &exp) in result.coeffs.iter().zip(expected.iter()) {
            assert_eq!(res.value, exp);
        }
    }

    #[test]
    fn test_torus_vec_mul() {
        let a: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(1), Torus::new(1)]);
        let b: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(1), Torus::new(1)]);
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(1),
            ntt_prime_psi: BigUint::from(1),
            inverse_ntt_prime_psi: BigUint::from(1),
            ntt_prime_omega: BigUint::from(1),
            inverse_ntt_prime_omega: BigUint::from(1),
            inverse_poly_size: BigUint::from(1),
            torus_parameter: TorusParam { bitsize: 6 }, // 2^6 = 64bit
        };
        let result = a.torus_vec_mul(&b, &param);
        let expected: Vec<u64> = vec![0, 2];
        for (res, &exp) in result.coeffs.iter().zip(expected.iter()) {
            assert_eq!(res.value, exp);
        }
    }

    #[test]
    fn test_scalar_vec_mul_ntt() {
        let mut input_a: Vec<Torus> = Vec::new();
        let mut input_b: Vec<Torus> = Vec::new();
        // expected = [-65534, -65532, ..., 0, 2, 4, ..., 65536]
        let mut expected: Vec<u64> = Vec::new();

        for i in 0..65536 {
            input_a.push(Torus::new(1));
            input_b.push(Torus::new(1));
            // 32768 = 65536 / 2
            if i < 32767 {
                expected.push(u64::MAX - 65533 + 2 * i);
            } else {
                expected.push(2 * (i - 32767));
            }
        }

        let a: TorusPolynomial<TwoPowerModulusPattern> = TorusPolynomial::new(input_a);
        let b: TorusPolynomial<TwoPowerModulusPattern> = TorusPolynomial::new(input_b);
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
        let result: TorusPolynomial<TwoPowerModulusPattern> = a.scalar_vec_mul_ntt(&b, &param);
        for (res, &exp) in result.coeffs.iter().zip(expected.iter()) {
            assert_eq!(res.value, exp);
        }
    }

    #[test]
    fn test_rotate_left() {
        let a: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(u64::MAX - 1), Torus::new(2)]);
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(1),
            ntt_prime_psi: BigUint::from(1),
            inverse_ntt_prime_psi: BigUint::from(1),
            ntt_prime_omega: BigUint::from(1),
            inverse_ntt_prime_omega: BigUint::from(1),
            inverse_poly_size: BigUint::from(1),
            torus_parameter: TorusParam { bitsize: 1 << 6 },
        };
        let n: usize = 1;
        let result = a.rotate_left(n, &param);
        let expected: Vec<u64> = vec![2, 2];
        for (res, &exp) in result.coeffs.iter().zip(expected.iter()) {
            assert_eq!(res.value, exp);
        }
    }

    #[test]
    fn test_rotate_right() {
        let a: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(2), Torus::new(2_u64.pow(8) - 2)]);
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
        let n: usize = 1;
        let result = a.rotate_right(n, &param);
        let expected: Vec<u64> = vec![2, 2];
        for (res, &exp) in result.coeffs.iter().zip(expected.iter()) {
            assert_eq!(res.value, exp);
        }
    }
}
