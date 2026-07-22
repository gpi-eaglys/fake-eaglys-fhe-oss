use std::ops::Range;

use rand::{Rng, thread_rng};

pub fn generate_secret_key_rnd(tlwe_seckey_value: Range<u8>) -> u8 {
    let mut rng = thread_rng();
    let num: u8 = rng.gen_range(tlwe_seckey_value);

    num
}
