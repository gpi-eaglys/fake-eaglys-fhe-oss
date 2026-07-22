#[cfg(test)]
use crate::low::biguint::BigUint;
use crate::low::{
    modulus::ModulusPattern,
    torus::{Torus, TorusParam},
    torus_polynomial::{
        TorusPolynomial, TorusPolynomialParameter, torus_polynomial_mat::TorusPolynomialMat,
        torus_polynomial_vec::TorusPolynomialVec,
    },
};

pub fn generate_gadget_vector(
    torus_param: &TorusParam,
    bg: usize, // TODO: reconsider parameter name
    l: usize,  // TODO: reconsider parameter name
) -> Vec<Torus> {
    let mut g_d: Vec<Torus> = vec![Torus::new(0); l];

    for v in 1..(l + 1) {
        let shift = torus_param.bitsize - (bg * v);
        debug_assert!(
            shift < 64,
            "gadget vector shift must fit into u64, got {shift}"
        );
        let d_v = 1_u64 << shift;
        g_d[v - 1] = Torus::new(d_v);
    }

    g_d
}

pub fn generate_gadget_matrix<M: ModulusPattern>(
    poly_param: &TorusPolynomialParameter,
    k: usize,
    bg: usize, // TODO: reconsider parameter name
    l: usize,  // TODO: reconsider parameter name
) -> TorusPolynomialMat<M>
where
    TorusPolynomial<M>: Clone,
    TorusPolynomialVec<M>: Clone,
{
    let mut torus_poly_mat: Vec<TorusPolynomialVec<M>> = Vec::new();

    let gadget_vector: Vec<Torus> = generate_gadget_vector(&poly_param.torus_parameter, bg, l);

    let base_poly: Vec<Torus> = vec![Torus::new(0); poly_param.polynomial_length];
    let base_torus_poly: TorusPolynomial<M> = TorusPolynomial::new(base_poly.clone());
    let base_poly_vec: Vec<TorusPolynomial<M>> = vec![base_torus_poly.clone(); k + 1];

    for i in 0..(k + 1) {
        for j in 0..l {
            let mut poly: Vec<Torus> = base_poly.clone();
            poly[0] = gadget_vector[j].clone();

            let mut poly_vec: Vec<TorusPolynomial<M>> = base_poly_vec.clone();
            let torus_poly: TorusPolynomial<M> = TorusPolynomial::new(poly);
            poly_vec[i] = torus_poly.clone();

            torus_poly_mat.push(TorusPolynomialVec::new(poly_vec.clone()));
        }
    }

    let gadget_matrix: TorusPolynomialMat<M> = TorusPolynomialMat::new(torus_poly_mat.clone());

    gadget_matrix
}

pub fn gadget_decomposition_to_torus(
    torus_num: &Torus,
    torus_param: &TorusParam,
    bg: usize, // TODO: reconsider parameter name
    l: usize,  // TODO: reconsider parameter name
) -> Vec<Torus> {
    let mut g_d: Vec<Torus> = vec![Torus::new(0); l];
    let round_shift = torus_param.bitsize - bg * l - 1;
    debug_assert!(
        round_shift < 128,
        "gadget decomposition round shift must fit into u128, got {round_shift}"
    );
    let round_num: u128 = 1_u128 << round_shift;
    let mut gadget_d = u128::from(torus_num.value) + round_num;

    for v in 1..(l + 1) {
        let shift = torus_param.bitsize - (bg * v);
        debug_assert!(
            shift < 128,
            "gadget decomposition shift must fit into u128, got {shift}"
        );
        let d_v = gadget_d >> shift;
        let consumed = d_v << shift;
        gadget_d -= consumed;
        g_d[v - 1] =
            Torus::new(u64::try_from(d_v).expect("gadget decomposition digits must fit into u64"));
    }

    g_d
}

pub fn gadget_decomposition_to_torus_polynomial<M: ModulusPattern>(
    torus_poly: &TorusPolynomial<M>,
    poly_param: &TorusPolynomialParameter,
    bg: usize, // TODO: reconsider parameter name
    l: usize,  // TODO: reconsider parameter name
) -> Vec<TorusPolynomial<M>> {
    let mut g_d_poly: Vec<TorusPolynomial<M>> = Vec::new();
    let mut g_d: Vec<Vec<Torus>> = vec![vec![Torus::new(0); poly_param.polynomial_length]; l];
    let mut rev_g_d: Vec<Vec<Torus>> = vec![vec![Torus::new(0); l]; poly_param.polynomial_length];

    for i in 0..poly_param.polynomial_length {
        rev_g_d[i] = gadget_decomposition_to_torus(
            &torus_poly.coeffs[i],
            &poly_param.torus_parameter,
            bg,
            l,
        );
    }

    for i in 0..l {
        for j in 0..poly_param.polynomial_length {
            g_d[i][j] = rev_g_d[j][i].clone();
        }
        g_d_poly.push(TorusPolynomial::new(g_d[i].clone()));
    }

    g_d_poly
}

pub fn gadget_decomposition_to_torus_polynomial_vec<M: ModulusPattern>(
    torus_poly_vec: &TorusPolynomialVec<M>,
    poly_param: &TorusPolynomialParameter,
    bg: usize, // TODO: reconsider parameter name
    l: usize,  // TODO: reconsider parameter name
) -> Vec<TorusPolynomialVec<M>> {
    let mut g_d_poly_vec: Vec<TorusPolynomialVec<M>> = Vec::new();

    for i in 0..torus_poly_vec.poly.len() {
        g_d_poly_vec.push(TorusPolynomialVec::new(
            gadget_decomposition_to_torus_polynomial(&torus_poly_vec.poly[i], poly_param, bg, l),
        ));
    }

    g_d_poly_vec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::low::modulus::TwoPowerModulusPattern;

    #[test]
    fn test_generate_gadget_vector() {
        let param = TorusParam { bitsize: 1 << 6 }; // 32-bit Torus
        let bg: usize = 16;
        let l: usize = 1;
        let result = generate_gadget_vector(&param, bg, l);
        let expected: u64 = 1_u64 << 48;
        assert_eq!(result[0].value, expected);
    }

    #[test]
    fn test_generate_gadget_matrix() {
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(0),
            ntt_prime_psi: BigUint::from(0),
            inverse_ntt_prime_psi: BigUint::from(0),
            ntt_prime_omega: BigUint::from(0),
            inverse_ntt_prime_omega: BigUint::from(0),
            inverse_poly_size: BigUint::from(0),
            torus_parameter: TorusParam { bitsize: 1 << 6 }, // 2^5 = 32bit
        };
        let k: usize = 1;
        let bg: usize = 16;
        let l: usize = 1;
        let result: TorusPolynomialMat<TwoPowerModulusPattern> =
            generate_gadget_matrix(&param, k, bg, l);
        let val: u64 = 1_u64 << 48;
        /*
        expected =
        [
        [[(1 << 48) + 0 X], [0 + 0 X]]
        [[0 + 0 X], [(1 << 48) + 0 X]]
        ]
         */
        assert_eq!(result.poly_vec[0].poly[0].coeffs[0].value, val);
        assert_eq!(result.poly_vec[0].poly[0].coeffs[1].value, 0);
        assert_eq!(result.poly_vec[0].poly[1].coeffs[0].value, 0);
        assert_eq!(result.poly_vec[0].poly[1].coeffs[1].value, 0);
        assert_eq!(result.poly_vec[1].poly[0].coeffs[0].value, 0);
        assert_eq!(result.poly_vec[1].poly[0].coeffs[1].value, 0);
        assert_eq!(result.poly_vec[1].poly[1].coeffs[0].value, val);
        assert_eq!(result.poly_vec[1].poly[1].coeffs[1].value, 0);
    }

    #[test]
    fn test_gadget_decomposition_to_torus() {
        let val: u64 = 1_u64 << 48;
        let torus_num: Torus = Torus::new(2 * val);
        let param = TorusParam { bitsize: 1 << 6 }; // 32-bit Torus
        let bg: usize = 16;
        let l: usize = 1;
        let result = gadget_decomposition_to_torus(&torus_num, &param, bg, l);
        assert_eq!(result[0].value, 2);
    }

    #[test]
    fn test_gadget_decomposition_to_torus_polynomial() {
        let val: u64 = 1_u64 << 48;
        let torus_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(2 * val), Torus::new(val)]);
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(0),
            ntt_prime_psi: BigUint::from(0),
            inverse_ntt_prime_psi: BigUint::from(0),
            ntt_prime_omega: BigUint::from(0),
            inverse_ntt_prime_omega: BigUint::from(0),
            inverse_poly_size: BigUint::from(0),
            torus_parameter: TorusParam { bitsize: 1 << 6 }, // 2^5 = 32bit
        };
        let bg: usize = 16;
        let l: usize = 1;
        let result = gadget_decomposition_to_torus_polynomial(&torus_poly, &param, bg, l);
        assert_eq!(result[0].coeffs[0].value, 2);
        assert_eq!(result[0].coeffs[1].value, 1);
    }

    #[test]
    fn test_gadget_decomposition_to_torus_polynomial_vec() {
        let val: u64 = 1_u64 << 48;
        let torus_poly: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(2 * val), Torus::new(val)]);
        let torus_poly_vec: TorusPolynomialVec<TwoPowerModulusPattern> =
            TorusPolynomialVec::new(vec![torus_poly.clone(); 2]);
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(0),
            ntt_prime_psi: BigUint::from(0),
            inverse_ntt_prime_psi: BigUint::from(0),
            ntt_prime_omega: BigUint::from(0),
            inverse_ntt_prime_omega: BigUint::from(0),
            inverse_poly_size: BigUint::from(0),
            torus_parameter: TorusParam { bitsize: 1 << 6 }, // 2^5 = 32bit
        };
        let bg: usize = 16;
        let l: usize = 1;
        let result = gadget_decomposition_to_torus_polynomial_vec(&torus_poly_vec, &param, bg, l);
        assert_eq!(result[0].poly[0].coeffs[0].value, 2);
        assert_eq!(result[0].poly[0].coeffs[1].value, 1);
        assert_eq!(result[1].poly[0].coeffs[0].value, 2);
        assert_eq!(result[1].poly[0].coeffs[1].value, 1);
    }
}
