use std::{ops::Range, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::low::{biguint::BigUint, torus::TorusParam, torus_polynomial::TorusPolynomialParameter};
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Parameter {
    pub origin: ParameterOrigin,
    pub torus_param: TorusParam,
    pub torus_polynomial_parameter: TorusPolynomialParameter,

    // Note: computational_accuracy_bit, encryption_sample_num will be one struct
    pub computational_accuracy_bit: usize,
    pub encryption_sample_num: usize,

    // related to encoder
    pub default_message_value_range: (f32, f32),

    // related to secret key
    pub default_encryption_sample_num: usize, // TODO: duplicated from encryption_sample_num
    pub default_tlwe_seckey_value: Range<u8>, /* TODO: rename seckey_value to the
                                               * seckey_value_range */
    pub default_trlwe_seckey_value: Range<u8>,
    pub default_trlwe_encryption_sample_num: usize,

    // related to public key
    pub default_tlwe_stddev: f32,
    pub default_tlwe_chosen_ctxt_from_public_key: usize,
    pub default_tlwe_public_key_size: usize,

    // related to eval key
    pub default_ksk_precision: usize,
    pub default_trlwe_stddev: f32,
    pub default_bg: usize,
    pub default_l: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParameterPreset {
    Low,
    Sec128,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ParameterOrigin {
    Preset(ParameterPreset),
    #[default]
    Custom,
}

impl Parameter {
    pub fn from_preset(preset: ParameterPreset) -> Self {
        match preset {
            ParameterPreset::Low => Parameter {
                origin: ParameterOrigin::Preset(ParameterPreset::Low),
                torus_param: TorusParam { bitsize: 64 },
                torus_polynomial_parameter: TorusPolynomialParameter {
                    polynomial_length: 1024,
                    log_polynomial_length: 10,
                    prime_modulus: BigUint::from(1),
                    ntt_prime_psi: BigUint::from(1),
                    inverse_ntt_prime_psi: BigUint::from(1),
                    ntt_prime_omega: BigUint::from(1),
                    inverse_ntt_prime_omega: BigUint::from(1),
                    inverse_poly_size: BigUint::from(1),
                    torus_parameter: TorusParam { bitsize: 64 },
                },
                computational_accuracy_bit: 10,
                encryption_sample_num: 3,
                default_message_value_range: (-10.0, 10.0),
                default_encryption_sample_num: 3,
                default_tlwe_seckey_value: 0u8..2u8,
                default_trlwe_encryption_sample_num: 1,
                default_trlwe_seckey_value: 0u8..2u8,
                default_tlwe_public_key_size: 100,
                default_tlwe_stddev: 0.0,
                default_tlwe_chosen_ctxt_from_public_key: 5,
                default_ksk_precision: 63,
                default_trlwe_stddev: 0.0,
                default_bg: 31,
                default_l: 2,
            },
            ParameterPreset::Sec128 => Parameter {
                origin: ParameterOrigin::Preset(ParameterPreset::Sec128),
                torus_param: TorusParam { bitsize: 48 },
                torus_polynomial_parameter: TorusPolynomialParameter {
                    polynomial_length: 65536,
                    log_polynomial_length: 16,
                    prime_modulus: BigUint::from(u128::MAX - 2_u128.pow(54) + 2),
                    ntt_prime_psi: BigUint::from(15479278773488526269853478226682162690_u128),
                    inverse_ntt_prime_psi: BigUint::from(
                        149844963811214215698651536441648540446_u128,
                    ),
                    ntt_prime_omega: BigUint::from(274761496178149862042109796498575449673_u128),
                    inverse_ntt_prime_omega: BigUint::from(
                        276625252932050520471031159916991523792_u128,
                    ),
                    inverse_poly_size: BigUint::from(340277174624079928635728062811807416321_u128),
                    torus_parameter: TorusParam { bitsize: 64 },
                },
                computational_accuracy_bit: 16,
                encryption_sample_num: 1600,
                default_message_value_range: (-10.0, 10.0),
                default_encryption_sample_num: 1600,
                default_tlwe_seckey_value: 0u8..2u8,
                default_trlwe_encryption_sample_num: 1,
                default_trlwe_seckey_value: 0u8..2u8,
                default_tlwe_public_key_size: 100,
                default_tlwe_stddev: 2.0_f32.powf(-38.0),
                default_tlwe_chosen_ctxt_from_public_key: 5,
                default_ksk_precision: 20,
                default_trlwe_stddev: 2.0_f32.powf(-60.0),
                default_bg: 31,
                default_l: 2,
            },
        }
    }
}

impl ParameterPreset {
    pub fn as_str(&self) -> &'static str {
        match self {
            ParameterPreset::Low => "low",
            ParameterPreset::Sec128 => "sec128",
        }
    }

    /// Presets that have parameters defined and are supported for use.
    pub fn supported() -> &'static [ParameterPreset] {
        // Extend this list when new presets become usable.
        &[ParameterPreset::Low]
    }
}

impl FromStr for ParameterPreset {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let needle = s.to_ascii_lowercase();
        ParameterPreset::supported()
            .iter()
            .copied()
            .find(|p| p.as_str() == needle)
            .ok_or(())
    }
}

#[cfg(test)]
fn default_preset_for_test() -> ParameterPreset {
    if cfg!(feature = "128_bit_security_test") {
        ParameterPreset::Sec128
    } else {
        ParameterPreset::Low
    }
}

#[cfg(test)]
pub(crate) fn preset_for_test() -> ParameterPreset {
    default_preset_for_test()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_preset_sets_origin() {
        let param = Parameter::from_preset(ParameterPreset::Low);
        assert_eq!(param.origin, ParameterOrigin::Preset(ParameterPreset::Low));
    }

    #[cfg(not(feature = "128_bit_security_test"))]
    #[test]
    fn test_default_preset_for_test_without_128_bit_feature() {
        assert_eq!(default_preset_for_test(), ParameterPreset::Low);
    }

    #[cfg(feature = "128_bit_security_test")]
    #[test]
    fn test_default_preset_for_test_with_128_bit_feature() {
        assert_eq!(default_preset_for_test(), ParameterPreset::Sec128);
    }
}
