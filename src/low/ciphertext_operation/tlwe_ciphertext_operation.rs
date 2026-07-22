use crate::low::{
    module::Module,
    torus::{Torus, TorusParam},
};

pub fn tlwe_ciphertext_add(
    ciphertext1: &[Torus],
    ciphertext2: &[Torus],
    torus_param: &TorusParam,
) -> Vec<Torus> {
    let ciphertext_length: usize = ciphertext1.len();
    let mut ciphertext: Vec<Torus> = vec![Torus::new(0); ciphertext_length];

    for i in 0..ciphertext_length {
        ciphertext[i] = ciphertext1[i].add(&ciphertext2[i], torus_param);
    }

    ciphertext
}

pub fn tlwe_ciphertext_sub(
    ciphertext1: &[Torus],
    ciphertext2: &[Torus],
    torus_param: &TorusParam,
) -> Vec<Torus> {
    let ciphertext_length: usize = ciphertext1.len();
    let mut ciphertext: Vec<Torus> = vec![Torus::new(0); ciphertext_length];

    for i in 0..ciphertext_length {
        ciphertext[i] = ciphertext1[i].sub(&ciphertext2[i], torus_param);
    }

    ciphertext
}

pub fn tlwe_ciphertext_scalar_mul(
    ciphertext1: &[Torus],
    scalar: u64,
    torus_param: &TorusParam,
) -> Vec<Torus> {
    let ciphertext_length: usize = ciphertext1.len();
    let mut ciphertext: Vec<Torus> = vec![Torus::new(0); ciphertext_length];

    for i in 0..ciphertext_length {
        ciphertext[i] = ciphertext1[i].scalar_mul(&scalar, torus_param);
    }

    ciphertext
}
