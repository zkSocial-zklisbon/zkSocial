//! Degrees of Separation (DOS)
//!
//! This is a simple implementation of the Degrees of Separation algorithm
use hex_literal::hex;
use plonky2::{
    self,
    field::goldilocks_field::GoldilocksField,
    plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
};

mod voucher;

pub(crate) const D: usize = 2;
// first 4 bytes of keccak256("dos.voucher.locus");
pub(crate) const LOCUS_DOMAIN_SEPARATOR: [u8; 4] = hex!("73afcf84");
pub(crate) type C = PoseidonGoldilocksConfig;
pub(crate) type F = <C as GenericConfig<D>>::F;
// pub(crate) type GoldilocksAddress = [F; 5];
