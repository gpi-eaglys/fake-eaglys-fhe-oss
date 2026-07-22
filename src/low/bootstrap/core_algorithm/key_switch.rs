use crate::low::{
    ciphertext_operation::tlwe_ciphertext_operation::{
        tlwe_ciphertext_scalar_mul, tlwe_ciphertext_sub,
    },
    math::gadget_decomposition::gadget_decomposition_to_torus,
    torus::{Torus, TorusParam},
};

pub fn public_key_switch(
    source_tlwe_ciphertext: &[Torus],
    source_param: &TorusParam,
    target_param: &TorusParam,
    ksk_precision: usize,
    key_switch_key: &[Vec<Vec<Torus>>],
) -> Vec<Torus> {
    let source_tlwe_ciphertext_length: usize = source_tlwe_ciphertext.len();
    let target_tlwe_ciphertext_length: usize = key_switch_key[0][0].len();

    let mut converted_source_tlwe_ciphertext: Vec<Torus> =
        Vec::with_capacity(source_tlwe_ciphertext_length);

    let shift = source_param.bitsize.saturating_sub(target_param.bitsize);

    for source_tlwe_ciphertext_num in source_tlwe_ciphertext
        .iter()
        .take(source_tlwe_ciphertext_length)
    {
        converted_source_tlwe_ciphertext
            .push(Torus::new(source_tlwe_ciphertext_num.value >> shift));
    }

    let mut switched_tlwe_ciphertext: Vec<Torus> =
        vec![Torus::new(0); target_tlwe_ciphertext_length];
    switched_tlwe_ciphertext[target_tlwe_ciphertext_length - 1] =
        converted_source_tlwe_ciphertext[source_tlwe_ciphertext_length - 1].clone();

    for u in 0..(source_tlwe_ciphertext_length - 1) {
        let binary_decomposed_ciphertext_sample: Vec<Torus> = gadget_decomposition_to_torus(
            &converted_source_tlwe_ciphertext[u],
            target_param,
            1,
            ksk_precision,
        );

        for v in 0..ksk_precision {
            let vth_scalared_key_switch_key: Vec<Torus> = tlwe_ciphertext_scalar_mul(
                &key_switch_key[u][v],
                binary_decomposed_ciphertext_sample[v].value,
                target_param,
            );
            switched_tlwe_ciphertext = tlwe_ciphertext_sub(
                &switched_tlwe_ciphertext,
                &vth_scalared_key_switch_key,
                target_param,
            );
        }
    }

    switched_tlwe_ciphertext
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;
    use crate::low::{
        bootstrap::core_algorithm::key_switch_key_generation::generate_key_switch_key,
        encoder::tlwe_encoder::{tlwe_decode, tlwe_encode},
        encryption::tlwe_encryption::{tlwe_decrypt, tlwe_public_encrypt},
        public_key::tlwe_public_key::generate_tlwe_public_key,
        secret_key::tlwe_secret_key::generate_tlwe_seckey,
    };

    #[test]
    fn test_public_key_switch() {
        let val: u64 = 3 * (1_u64 << 60);
        let plaintext: Torus = Torus::new(val);
        let source_torus_param: TorusParam = TorusParam { bitsize: 1 << 6 };
        let target_torus_param: TorusParam = TorusParam { bitsize: 1 << 6 };
        let tlwe_seckey_value: Range<u8> = 0u8..2u8;
        let source_encryption_sample_num: usize = 100;
        let target_encryption_sample_num: usize = 10;
        let tlwe_stddev: f32 = 0.0;
        let tlwe_public_key_size: usize = 100;
        let tlwe_chosen_ctxt_from_public_key: usize = 5;
        let ksk_precision: usize = target_torus_param.bitsize - 1;

        let source_seckey: Vec<u8> =
            generate_tlwe_seckey(tlwe_seckey_value.clone(), source_encryption_sample_num);
        let target_seckey: Vec<u8> =
            generate_tlwe_seckey(tlwe_seckey_value.clone(), target_encryption_sample_num);

        let source_pubkey: Vec<Vec<Torus>> = generate_tlwe_public_key(
            &source_seckey,
            &source_torus_param,
            source_encryption_sample_num,
            tlwe_stddev,
            tlwe_public_key_size,
        );
        let target_pubkey: Vec<Vec<Torus>> = generate_tlwe_public_key(
            &target_seckey,
            &target_torus_param,
            target_encryption_sample_num,
            tlwe_stddev,
            tlwe_public_key_size,
        );

        let key_switch_key: Vec<Vec<Vec<Torus>>> = generate_key_switch_key(
            &source_seckey,
            &target_pubkey,
            &target_torus_param,
            tlwe_chosen_ctxt_from_public_key,
            ksk_precision,
        );

        let source_ciphertext: Vec<Torus> = tlwe_public_encrypt(
            &plaintext,
            &source_pubkey,
            &source_torus_param,
            tlwe_chosen_ctxt_from_public_key,
        );

        let switched_ciphertext: Vec<Torus> = public_key_switch(
            &source_ciphertext,
            &source_torus_param,
            &target_torus_param,
            ksk_precision,
            &key_switch_key,
        );

        let decrypted_ciphertext: Torus =
            tlwe_decrypt(&switched_ciphertext, &target_seckey, &target_torus_param);

        assert_eq!(decrypted_ciphertext.value, val);
    }

    #[test]
    fn test_public_key_switch_source_and_target_diff() {
        let computational_accuracy_bit: usize = 16;
        let message_value_range = (-10.0, 10.0);
        let source_torus_param: TorusParam = TorusParam { bitsize: 1 << 6 };
        let target_torus_param: TorusParam = TorusParam { bitsize: 1 << 5 };
        let tlwe_seckey_value: Range<u8> = 0u8..2u8;
        let source_encryption_sample_num: usize = 100;
        let target_encryption_sample_num: usize = 10;
        let tlwe_stddev: f32 = 0.0;
        let tlwe_public_key_size: usize = 100;
        let tlwe_chosen_ctxt_from_public_key: usize = 5;
        let ksk_precision: usize = target_torus_param.bitsize - 1;

        let cleartext: f32 = 0.0;

        let plaintext: Torus = tlwe_encode(
            cleartext,
            &source_torus_param,
            computational_accuracy_bit,
            message_value_range,
        );

        let source_seckey: Vec<u8> =
            generate_tlwe_seckey(tlwe_seckey_value.clone(), source_encryption_sample_num);
        let target_seckey: Vec<u8> =
            generate_tlwe_seckey(tlwe_seckey_value.clone(), target_encryption_sample_num);

        let source_pubkey: Vec<Vec<Torus>> = generate_tlwe_public_key(
            &source_seckey,
            &source_torus_param,
            source_encryption_sample_num,
            tlwe_stddev,
            tlwe_public_key_size,
        );
        let target_pubkey: Vec<Vec<Torus>> = generate_tlwe_public_key(
            &target_seckey,
            &target_torus_param,
            target_encryption_sample_num,
            tlwe_stddev,
            tlwe_public_key_size,
        );

        let key_switch_key: Vec<Vec<Vec<Torus>>> = generate_key_switch_key(
            &source_seckey,
            &target_pubkey,
            &target_torus_param,
            tlwe_chosen_ctxt_from_public_key,
            ksk_precision,
        );

        let source_ciphertext: Vec<Torus> = tlwe_public_encrypt(
            &plaintext,
            &source_pubkey,
            &source_torus_param,
            tlwe_chosen_ctxt_from_public_key,
        );

        let switched_ciphertext: Vec<Torus> = public_key_switch(
            &source_ciphertext,
            &source_torus_param,
            &target_torus_param,
            ksk_precision,
            &key_switch_key,
        );

        let decrypted_ciphertext: Torus =
            tlwe_decrypt(&switched_ciphertext, &target_seckey, &target_torus_param);

        let decoded_decrypted_ciphertext: f32 = tlwe_decode(
            &decrypted_ciphertext,
            &target_torus_param,
            computational_accuracy_bit,
            message_value_range,
        );

        assert_eq!(decoded_decrypted_ciphertext, cleartext);
    }
}
