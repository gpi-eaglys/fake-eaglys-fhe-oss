/// Represents a mathematical additive group
pub trait Module<P> {
    fn add(&self, other: &Self, param: &P) -> Self;
    fn sub(&self, other: &Self, param: &P) -> Self;
    fn scalar_mul(&self, other: &u64, param: &P) -> Self;
}
