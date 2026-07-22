use crate::low::{
    encryption::tlwe_encryption::tlwe_symmetric_encrypt,
    torus::{Torus, TorusParam},
};

pub fn generate_tlwe_public_key(
    seckey: &[u8],
    torus_param: &TorusParam,
    encryption_sample_num: usize,
    tlwe_stddev: f32,
    tlwe_public_key_size: usize,
) -> Vec<Vec<Torus>> {
    // tlwe_public_key (2-dim) size is ((lwe_encryption_sample_num + 1), public_key_size)
    let mut tlwe_public_key: Vec<Vec<Torus>> = Vec::with_capacity(tlwe_public_key_size);

    for _ in 0..tlwe_public_key_size {
        tlwe_public_key.push(tlwe_symmetric_encrypt(
            &Torus::new(0),
            seckey,
            torus_param,
            encryption_sample_num,
            tlwe_stddev,
        ));
    }

    tlwe_public_key
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "fixed_tlwe_torus_rnd")]
    use std::ops::Range;

    #[cfg(feature = "fixed_tlwe_torus_rnd")]
    use super::*;
    #[cfg(feature = "fixed_tlwe_torus_rnd")]
    use crate::low::secret_key::tlwe_secret_key::generate_tlwe_seckey;

    #[cfg(feature = "fixed_tlwe_torus_rnd")]
    #[test]
    fn test_generate_tlwe_public_key() {
        let torus_param: TorusParam = TorusParam { bitsize: 1 << 6 };
        let tlwe_seckey_value: Range<u8> = 0u8..2u8;
        let encryption_sample_num: usize = 3;
        let tlwe_stddev: f32 = 0.0;
        let tlwe_public_key_size: usize = 100;

        let seckey: Vec<u8> = generate_tlwe_seckey(tlwe_seckey_value, encryption_sample_num);

        let result: Vec<Vec<Torus>> = generate_tlwe_public_key(
            &seckey,
            &torus_param,
            encryption_sample_num,
            tlwe_stddev,
            tlwe_public_key_size,
        );

        let mut expected: Vec<Vec<u64>> = vec![vec![0_u64; 4]; 100];

        for (result_row, expected_row) in result.iter().zip(expected.iter()) {
            for (res, &exp) in result_row.iter().zip(expected_row.iter()) {
                assert_eq!(res.value, exp);
            }
        }
    }
}
