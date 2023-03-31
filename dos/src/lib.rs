//! Degrees of Separation (DOS)
//!
//! This is a simple implementation of the Degrees of Separation algorithm
use plonky2::{
    self, field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
};

mod voucher;

pub(crate) const D: usize = 2;
pub(crate) type F = GoldilocksField;
pub(crate) type C = PoseidonGoldilocksConfig;
pub(crate) type GoldilocksAddress = [F; 5];
