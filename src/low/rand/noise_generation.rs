use rand_distr::{Distribution, Normal};

use crate::low::torus::{Torus, TorusParam};

// TODO: 本来 noise が取りうる値の type は BigInt をベースにする IntTorus であるべきだが、
// i64 から無理に Torus へ変換する実装としている
pub fn generate_noise(torus_param: &TorusParam, stddev: f32) -> Torus {
    if stddev == 0.0 {
        Torus::new(0_u64)
    } else {
        let mean: f32 = 0.0;
        let torus_stddev: f32 = stddev * (torus_param.bitsize) as f32;

        let mut noise_flag = false;
        let mut rng = rand::thread_rng();
        let mut float_noise: f64 = 0.0;

        // if noise is 0, repeat samples
        while !noise_flag {
            let normal = Normal::<f64>::new(mean.into(), torus_stddev.into()).unwrap();
            float_noise = normal.sample(&mut rng);

            if float_noise != 0.0 {
                float_noise = normal.sample(&mut rng);
                noise_flag = true;
            }
        }

        let int_noise: i64 = float_noise.round() as i64;
        Torus::new(int_noise as u64)
    }
}
