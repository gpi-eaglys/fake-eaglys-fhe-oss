use rand::{Rng, thread_rng};

use crate::low::{
    ciphertext_operation::tlwe_ciphertext_operation::tlwe_ciphertext_add,
    module::Module,
    rand::{noise_generation::generate_noise, torus_rnd_generation::generate_torus_rnd},
    torus::{Torus, TorusParam},
};

pub fn tlwe_symmetric_encrypt(
    plaintext: &Torus,
    seckey: &[u8],
    torus_param: &TorusParam,
    encryption_sample_num: usize,
    tlwe_stddev: f32,
) -> Vec<Torus> {
    // ciphertext (1-dim) size is (lwe_encryption_sample_num + 1)
    let mut nth_ciphertext_num: Torus = Torus::new(0);

    // generate lwe_sample randomly
    // lwe_sample (1-dim) size is (lwe_encryption_sample_num)
    let mut lwe_sample: Vec<Torus> = Vec::with_capacity(encryption_sample_num);
    for _ in 0..encryption_sample_num {
        lwe_sample.push(generate_torus_rnd(torus_param));
    }

    let noise: Torus = generate_noise(torus_param, tlwe_stddev);

    // compute the inner product <seckey, lwe_sample>
    for (&seckey_bit, lwe_sample_i) in seckey.iter().zip(lwe_sample.iter()) {
        if seckey_bit == 1 {
            nth_ciphertext_num = nth_ciphertext_num.add(lwe_sample_i, torus_param);
        }
    }

    // compute <seckey, lwe_sample> + plaintext + e
    nth_ciphertext_num = nth_ciphertext_num.add(plaintext, torus_param);
    nth_ciphertext_num = nth_ciphertext_num.add(&noise, torus_param);

    let mut ciphertext: Vec<Torus> = lwe_sample;
    ciphertext.push(nth_ciphertext_num);

    ciphertext
}

pub fn tlwe_public_encrypt(
    plaintext: &Torus,
    pubkey: &[Vec<Torus>],
    torus_param: &TorusParam,
    tlwe_chosen_ctxt_from_public_key: usize,
) -> Vec<Torus> {
    let mut rng = thread_rng();
    let ciphertext_length: usize = pubkey[0].len();

    // ciphertext (1-dim) size is (lwe_encryption_sample_num + 1)
    let mut ciphertext: Vec<Torus> = vec![Torus::new(0); ciphertext_length];
    ciphertext[ciphertext_length - 1] = plaintext.clone();

    for _ in 0..tlwe_chosen_ctxt_from_public_key {
        let rng_index: usize = rng.gen_range(0..pubkey.len() - 1);
        ciphertext = tlwe_ciphertext_add(&ciphertext, &pubkey[rng_index], torus_param);
    }

    ciphertext
}

pub fn tlwe_decrypt(ciphertext: &[Torus], seckey: &[u8], torus_param: &TorusParam) -> Torus {
    let encryption_sample_num: usize = seckey.len();
    let mut decrypted_ciphertext: Torus = ciphertext[encryption_sample_num].clone();

    // compute the phase
    // phase = ciphertext - <seckey, lwe_sample>
    for (&seckey_bit, ciphertext_i) in seckey
        .iter()
        .zip(ciphertext.iter().take(encryption_sample_num))
    {
        if seckey_bit == 1 {
            decrypted_ciphertext = decrypted_ciphertext.sub(ciphertext_i, torus_param);
        }
    }

    decrypted_ciphertext
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;
    use crate::low::{
        public_key::tlwe_public_key::generate_tlwe_public_key,
        secret_key::tlwe_secret_key::generate_tlwe_seckey,
    };

    #[cfg(feature = "fixed_tlwe_torus_rnd")]
    #[test]
    fn test_encrypt() {
        let plaintext: Torus = Torus::new(10);
        let seckey: Vec<u8> = vec![0_u8; 3];
        let torus_param: TorusParam = TorusParam { bitsize: 1 << 6 };
        let encryption_sample_num: usize = 3;
        let tlwe_stddev: f32 = 0.0;

        let result: Vec<Torus> = tlwe_symmetric_encrypt(
            &plaintext,
            &seckey,
            &torus_param,
            encryption_sample_num,
            tlwe_stddev,
        );
        let mut expected: Vec<u64> = vec![0u64; 3];
        expected.push(10);

        for (res, &exp) in result.iter().zip(expected.iter()) {
            assert_eq!(res.value, exp);
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext: Torus = Torus::new(10);
        let torus_param: TorusParam = TorusParam { bitsize: 1 << 6 };
        let tlwe_seckey_value: Range<u8> = 0u8..2u8;
        let encryption_sample_num: usize = 3;
        let tlwe_stddev: f32 = 0.0;
        let tlwe_public_key_size: usize = 100;
        let tlwe_chosen_ctxt_from_public_key: usize = 5;

        let seckey: Vec<u8> = generate_tlwe_seckey(tlwe_seckey_value, encryption_sample_num);
        let pubkey: Vec<Vec<Torus>> = generate_tlwe_public_key(
            &seckey,
            &torus_param,
            encryption_sample_num,
            tlwe_stddev,
            tlwe_public_key_size,
        );

        let ciphertext: Vec<Torus> = tlwe_public_encrypt(
            &plaintext,
            &pubkey,
            &torus_param,
            tlwe_chosen_ctxt_from_public_key,
        );
        let decrypted_ciphertext: Torus = tlwe_decrypt(&ciphertext, &seckey, &torus_param);

        assert_eq!(decrypted_ciphertext.value, 10);
    }
}
