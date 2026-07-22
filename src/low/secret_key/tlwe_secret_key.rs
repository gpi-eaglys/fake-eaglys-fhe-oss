use std::ops::Range;

use crate::low::rand::secret_key_rnd_generation::generate_secret_key_rnd;

// generate the secret key used in LWE cryptosystem
pub fn generate_tlwe_seckey(tlwe_seckey_value: Range<u8>, encryption_sample_num: usize) -> Vec<u8> {
    #[cfg(feature = "fixed_tlwe_seckey_rnd")]
    {
        return vec![0_u8; encryption_sample_num];
    }

    // Default: random secret key.
    let mut tlwe_secret_key: Vec<u8> = Vec::with_capacity(encryption_sample_num);
    for _ in 0..encryption_sample_num {
        tlwe_secret_key.push(generate_secret_key_rnd(tlwe_seckey_value.clone()));
    }
    tlwe_secret_key
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "fixed_tlwe_seckey_rnd")]
    use std::ops::Range;

    #[cfg(feature = "fixed_tlwe_seckey_rnd")]
    use crate::low::secret_key::tlwe_secret_key::generate_tlwe_seckey;

    #[cfg(feature = "fixed_tlwe_seckey_rnd")]
    #[test]
    fn test_generate_tlwe_seckey() {
        let tlwe_seckey_value: Range<u8> = 0u8..2u8;
        let encryption_sample_num: usize = 3;

        let seckey: Vec<u8> = vec![0_u8; 3];

        let result: Vec<u8> = generate_tlwe_seckey(tlwe_seckey_value, encryption_sample_num);
        let mut expected: Vec<u8> = vec![0_u8; 3];

        for (res, exp) in result.iter().zip(expected.iter()) {
            assert_eq!(res, exp);
        }
    }
}
