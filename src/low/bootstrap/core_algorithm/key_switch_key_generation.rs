use crate::low::{
    encryption::tlwe_encryption::tlwe_public_encrypt,
    torus::{Torus, TorusParam},
};

pub fn generate_key_switch_key(
    source_seckey: &[u8],
    target_pubkey: &[Vec<Torus>],
    target_param: &TorusParam,
    tlwe_chosen_ctxt_from_public_key: usize,
    ksk_precision: usize,
) -> Vec<Vec<Vec<Torus>>> {
    let source_seckey_length: usize = source_seckey.len();

    let mut key_switch_key: Vec<Vec<Vec<Torus>>> = Vec::with_capacity(source_seckey_length);

    for &source_seckey_num in source_seckey.iter() {
        let mut uth_key_switch_key: Vec<Vec<Torus>> = Vec::with_capacity(ksk_precision);
        for v in 1..(ksk_precision + 1) {
            let mut source_seckey_torus_num: u64 = 0;
            if source_seckey_num == 1 {
                source_seckey_torus_num = 1_u64 << (target_param.bitsize - v);
            }
            let source_seckey_torus_num: Torus = Torus::new(source_seckey_torus_num);
            uth_key_switch_key.push(tlwe_public_encrypt(
                &source_seckey_torus_num,
                target_pubkey,
                target_param,
                tlwe_chosen_ctxt_from_public_key,
            ));
        }
        key_switch_key.push(uth_key_switch_key);
    }

    key_switch_key
}
