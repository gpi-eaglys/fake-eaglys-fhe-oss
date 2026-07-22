use crate::low::{
    module::Module,
    modulus::ModulusPattern,
    torus_polynomial::{
        TorusPolynomial, TorusPolynomialParameter, torus_polynomial_vec::TorusPolynomialVec,
    },
};

pub fn trlwe_ciphertext_add<M: ModulusPattern>(
    ciphertext1: &TorusPolynomialVec<M>,
    ciphertext2: &TorusPolynomialVec<M>,
    poly_param: &TorusPolynomialParameter,
) -> TorusPolynomialVec<M> {
    let mut ciphertext: Vec<TorusPolynomial<M>> = Vec::with_capacity(ciphertext1.poly.len());

    for (ciphertext1_poly, ciphertext2_poly) in ciphertext1.poly.iter().zip(ciphertext2.poly.iter())
    {
        ciphertext.push(ciphertext1_poly.add(ciphertext2_poly, poly_param));
    }

    TorusPolynomialVec::new(ciphertext)
}

pub fn trlwe_ciphertext_sub<M: ModulusPattern>(
    ciphertext1: &TorusPolynomialVec<M>,
    ciphertext2: &TorusPolynomialVec<M>,
    poly_param: &TorusPolynomialParameter,
) -> TorusPolynomialVec<M> {
    let mut ciphertext: Vec<TorusPolynomial<M>> = Vec::with_capacity(ciphertext1.poly.len());

    for (ciphertext1_poly, ciphertext2_poly) in ciphertext1.poly.iter().zip(ciphertext2.poly.iter())
    {
        ciphertext.push(ciphertext1_poly.sub(ciphertext2_poly, poly_param));
    }

    TorusPolynomialVec::new(ciphertext)
}

pub fn trlwe_ciphertext_scalar_mul<M: ModulusPattern>(
    ciphertext1: &TorusPolynomialVec<M>,
    scalar: u64,
    poly_param: &TorusPolynomialParameter,
) -> TorusPolynomialVec<M> {
    let mut ciphertext: Vec<TorusPolynomial<M>> = Vec::with_capacity(ciphertext1.poly.len());

    for ciphertext1_poly in ciphertext1.poly.iter() {
        ciphertext.push(ciphertext1_poly.scalar_mul(&scalar, poly_param));
    }

    TorusPolynomialVec::new(ciphertext)
}
