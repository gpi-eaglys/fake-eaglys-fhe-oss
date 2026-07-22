use crate::low::torus::{Torus, TorusParam};

pub fn generate_torus_rnd(torus_param: &TorusParam) -> Torus {
    assert!(
        torus_param.bitsize <= 64,
        "torus bitsize > 64 is unsupported for non-NTT storage"
    );

    #[cfg(feature = "fixed_torus_rnd")]
    {
        return Torus::new(0_u64);
    }

    Torus::new(torus_param.apply_modulus(rand::random::<u64>()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_torus_rnd() {
        let param = TorusParam { bitsize: 1 << 6 };
        let torus = generate_torus_rnd(&param);
        assert_eq!(torus.value, param.apply_modulus(torus.value));
    }
}
