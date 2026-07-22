use crate::low::{
    module::Module,
    modulus::ModulusPattern,
    torus::Torus,
    torus_polynomial::{TorusPolynomialParameter, torus_polynomial_vec::TorusPolynomialVec},
};

pub fn sample_extraction_to_ctxt<M: ModulusPattern>(
    trlwe_ciphertext: &TorusPolynomialVec<M>,
    poly_param: &TorusPolynomialParameter,
) -> Vec<Torus> {
    let trlwe_encryption_sample_num: usize = trlwe_ciphertext.poly.len() - 1;

    let mut result: Vec<Torus> = Vec::new();

    for j in 0..trlwe_encryption_sample_num {
        result.push(trlwe_ciphertext.poly[j].coeffs[0].clone());
        for m in 1..poly_param.polynomial_length {
            let zero: Torus = Torus::new(0);
            let torus_polynomial_coeff: Torus =
                trlwe_ciphertext.poly[j].coeffs[poly_param.polynomial_length - m].clone();
            let res = zero.sub(&torus_polynomial_coeff, &poly_param.torus_parameter);

            result.push(res);
        }
    }

    result.push(trlwe_ciphertext.poly[trlwe_encryption_sample_num].coeffs[0].clone());

    result
}

pub fn sample_extraction_to_key(trlwe_seckey: &[Vec<u8>]) -> Vec<u8> {
    let poly_size: usize = trlwe_seckey[0].len();
    let mut result: Vec<u8> = vec![0_u8; trlwe_seckey.len() * poly_size];

    for j in 0..trlwe_seckey.len() {
        for m in 0..poly_size {
            result[j * poly_size + m] = trlwe_seckey[j][m];
        }
    }

    result
}
