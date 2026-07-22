#![allow(clippy::manual_is_multiple_of)]

use std::any::TypeId;

use crate::{
    high::{ciphertext::Ciphertext, eval_key::EvalKey, key_switch_key::KeySwitchKey},
    low::{
        modulus::TwoPowerModulusPattern, torus::Torus,
        torus_polynomial::torus_polynomial_mat::TorusPolynomialMat,
    },
};

/// Namespace for serializing in FPGA-compatible format (firmware v3.0).
/// Handles both `Low` and `Sec128` parameter sets, but only `Sec128` is compatible with the FPGA.
pub struct FpgaV3CompatSerializer;

impl FpgaV3CompatSerializer {
    pub fn serialize<T: 'static>(obj: &T) -> Result<Vec<u8>, String> {
        let type_id = TypeId::of::<T>();
        if type_id == TypeId::of::<Ciphertext>() {
            let type_size = 8; // u64 fixed
            let cipher = unsafe { &*(obj as *const T as *const Ciphertext) };
            serialize_1d_torus(&cipher.vector_torus, type_size)
        } else if type_id == TypeId::of::<Vec<Vec<Vec<Torus>>>>() {
            // keyswitch key
            let type_size = 8;
            let torus_3d = unsafe { &*(obj as *const T as *const Vec<Vec<Vec<Torus>>>) };
            serialize_3d_torus(torus_3d, type_size)
        } else if type_id == TypeId::of::<KeySwitchKey>() {
            let ksk = unsafe { &*(obj as *const T as *const KeySwitchKey) };
            // recursive call to serialize the inner 3D Torus
            FpgaV3CompatSerializer::serialize(&ksk.key_switch_key)
        } else if type_id == TypeId::of::<Vec<TorusPolynomialMat<TwoPowerModulusPattern>>>() {
            // bootstrap key
            let bkntt = unsafe {
                &*(obj as *const T as *const Vec<TorusPolynomialMat<TwoPowerModulusPattern>>)
            };
            let type_size = 16; //serialized as u128
            let dim0 = bkntt.len();
            let dim1 = bkntt[0].poly_vec.len();
            let dim2 = bkntt[0].poly_vec[0].poly.len();
            let dim3 = bkntt[0].poly_vec[0].poly[0].coeffs.len();
            let serialized_data_size = type_size * dim0 * dim1 * dim2 * dim3;
            let mut serialized: Vec<u8> = Vec::with_capacity(serialized_data_size);
            for vec3d in bkntt {
                for vec2d in &vec3d.poly_vec {
                    for vec1d in &vec2d.poly {
                        for elem in &vec1d.coeffs {
                            let bytes = elem.value.to_le_bytes();
                            if bytes.len() <= type_size {
                                serialized.extend_from_slice(&bytes);
                                // Pad remaining bytes with 0
                                serialized.resize(serialized.len() + (type_size - bytes.len()), 0);
                            } else {
                                // Truncate to 8 bytes if larger (unlikely but safe)
                                let msg = format!(
                                    "Failed to serialize: the specified {} byte container size is too small for {:?}",
                                    type_size, elem.value
                                );
                                return Err(msg);
                            }
                        }
                    }
                }
            }
            Ok(serialized)
        } else if type_id == TypeId::of::<EvalKey>() {
            let eval_key = unsafe { &*(obj as *const T as *const EvalKey) };
            // aliases
            let bkntt = &eval_key.bootstrap_key;
            let ksk_inner = &eval_key.key_switch_key;
            // recursively serialize bk and ksk
            let serialized_bkntt = FpgaV3CompatSerializer::serialize(bkntt)?;
            let mut serialized_ksk = FpgaV3CompatSerializer::serialize(ksk_inner)?;
            serialized_ksk.reserve(serialized_bkntt.len());
            serialized_ksk.extend_from_slice(&serialized_bkntt);
            Ok(serialized_ksk)
        } else {
            Err(format!(
                "Serialization for type {} is not implemented",
                std::any::type_name::<T>()
            ))
        }
    }
}

fn serialize_1d_torus(vec1d: &Vec<Torus>, type_size: usize) -> Result<Vec<u8>, String> {
    let serialized_data_size = type_size * vec1d.len();
    let mut serialized: Vec<u8> = Vec::with_capacity(serialized_data_size);

    for elem in vec1d {
        let bytes = elem.value.to_le_bytes();

        if bytes.len() <= type_size {
            serialized.extend_from_slice(&bytes);
            // Pad remaining bytes with 0
            serialized.resize(serialized.len() + (type_size - bytes.len()), 0);
        } else {
            // Truncate to 8 bytes if larger (unlikely but safe)
            let msg = format!(
                "Failed to serialize: the specified {} byte container size is too small for {:?}",
                type_size, elem.value
            );
            return Err(msg);
        }
    }
    Ok(serialized)
}

fn serialize_3d_torus(vec3d: &Vec<Vec<Vec<Torus>>>, type_size: usize) -> Result<Vec<u8>, String> {
    let (dim0, dim1, dim2) = (vec3d.len(), vec3d[0].len(), vec3d[0][0].len());
    let serialized_data_size = type_size * dim0 * dim1 * dim2;
    let mut serialized: Vec<u8> = Vec::with_capacity(serialized_data_size);
    println!(
        "3D Torus: {} elements, {} bytes",
        dim0 * dim1 * dim2,
        serialized_data_size
    );

    for vec2d in vec3d {
        for vec1d in vec2d {
            for elem in vec1d {
                let bytes = elem.value.to_le_bytes();
                if bytes.len() <= type_size {
                    serialized.extend_from_slice(&bytes);
                    // Pad remaining bytes with 0
                    serialized.resize(serialized.len() + (type_size - bytes.len()), 0);
                } else {
                    // Truncate to 8 bytes if larger (unlikely but safe)
                    let msg = format!(
                        "Failed to serialize: the specified {} byte container size is too small for {:?}",
                        type_size, elem.value
                    );
                    return Err(msg);
                }
            }
        }
    }
    Ok(serialized)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::high::{
        eval_key::EvalKey, key_switch_key::KeySwitchKey, parameter::Parameter,
        public_key::PublicKey, secret_key::SecretKey, serializer::FpgaV3CompatSerializer,
    };

    fn _test_serialize_ciphertext(par: &Parameter) {
        let sk = SecretKey::new(par);
        let pk = PublicKey::new(par, &sk);
        let val = 1.25_f32;

        let cipher = pk.encode_encrypt(val, BTreeMap::new(), None);

        let serialized =
            FpgaV3CompatSerializer::serialize(&cipher).expect("Failed to serialize Ciphertext");
        assert!(!serialized.is_empty());
        assert!(serialized.len() % 8 == 0); // Each Torus should be serialized into 8 bytes

        let elem_size = match par.torus_param.bitsize / 8 {
            n if n <= 4 => 4,
            n if n <= 8 => 8, // u64
            _ => 16,          // u128
        };

        let expected_byte_size = (par.default_encryption_sample_num + 1) * elem_size;
        assert_eq!(
            serialized.len(),
            expected_byte_size,
            "Unexpected serialized length: {} != {}, elem-size={}",
            serialized.len(),
            expected_byte_size,
            elem_size
        ); // Each Torus should be serialized into elem_size bytes
    }

    #[test]
    fn test_serialize_ciphertext_low() {
        let par = Parameter::from_preset(crate::high::parameter::ParameterPreset::Low);
        _test_serialize_ciphertext(&par);
    }

    #[test]
    fn test_serialize_ciphertext_sec128() {
        let par = Parameter::from_preset(crate::high::parameter::ParameterPreset::Sec128);
        _test_serialize_ciphertext(&par);
    }

    fn _test_serialize_ksk(par: &Parameter) {
        // 1. User Key Creation
        let usk = SecretKey::new(par);
        let upk = PublicKey::new(par, &usk);
        // 2. Project Key Creation
        let psk = SecretKey::new(par);
        let ksk_lvl0 = KeySwitchKey::new(par, &psk, &upk);

        let serialized = FpgaV3CompatSerializer::serialize(&ksk_lvl0)
            .expect("Failed to serialize keyswitch key");
        assert!(!serialized.is_empty());
        assert!(serialized.len() % 8 == 0); //  Torus should be serialized into 8 bytes
    }

    #[test]
    fn test_serialize_ksk_low() {
        let par = Parameter::from_preset(crate::high::parameter::ParameterPreset::Low);
        _test_serialize_ksk(&par);
    }
    #[test]
    fn test_serialize_ksk_sec128() {
        let par = Parameter::from_preset(crate::high::parameter::ParameterPreset::Sec128);
        _test_serialize_ksk(&par);
    }

    fn _test_serialize_evalkey(par: &Parameter) {
        // 1. User Key Creation
        let seckey = SecretKey::new(par);
        let eval_key = EvalKey::new(par, &seckey);

        let serialized =
            FpgaV3CompatSerializer::serialize(&eval_key).expect("Failed to serialize eval key");
        assert!(!serialized.is_empty());
        assert!(serialized.len() % 8 == 0); // Each Torus should be serialized into 8 bytes

        let ksk_type_size = 8;
        let bkntt_type_size = 16; // fixed for u128 
        let expected_bkntt_size = {
            let dim0: usize = par.default_encryption_sample_num;
            let dim1: usize = par.default_l * (par.default_trlwe_encryption_sample_num + 1);
            let dim2: usize = par.default_trlwe_encryption_sample_num + 1;
            let dim3: usize = par.torus_polynomial_parameter.polynomial_length;
            bkntt_type_size * dim0 * dim1 * dim2 * dim3
        };
        let expected_ksk_size = {
            let dim0: usize = par.torus_polynomial_parameter.polynomial_length;
            let dim1: usize = par.default_ksk_precision;
            let dim2: usize = par.encryption_sample_num + 1;
            ksk_type_size * dim0 * dim1 * dim2
        };
        println!(
            "Expected ksk size: {} bytes (u{})",
            expected_ksk_size,
            8 * ksk_type_size
        );
        println!(
            "Expected bkntt size: {} bytes (u{})",
            expected_bkntt_size,
            8 * bkntt_type_size
        );
        let expected_total_size = expected_bkntt_size + expected_ksk_size;

        assert_eq!(
            expected_total_size,
            serialized.len(),
            "Unexpected serialized length: {} != {}",
            serialized.len(),
            expected_total_size
        );
    }

    #[test]
    fn test_serialize_evalkey_low() {
        let par = Parameter::from_preset(crate::high::parameter::ParameterPreset::Low);
        _test_serialize_evalkey(&par);
    }
    #[test]
    #[ignore = "takes hours to run"] // use enforce run with `cargo test -- --include-ignored``
    fn test_serialize_evalkey_sec128() {
        let par = Parameter::from_preset(crate::high::parameter::ParameterPreset::Sec128);
        _test_serialize_evalkey(&par);
    }
}
