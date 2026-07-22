// TODO: for EvalKey's Vec<TorusPolynomialMat<TwoPowerModulusPattern>> serialization, it needs to
// set lifetime, better to understand what it happens.
use serde::{Deserialize, Serialize};

pub trait ModulusPattern: Clone + Copy + Serialize + for<'de> Deserialize<'de> {}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct TwoPowerModulusPattern {}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct GeneralModulusPattern {}

impl ModulusPattern for TwoPowerModulusPattern {}
impl ModulusPattern for GeneralModulusPattern {}
