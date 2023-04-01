//! Degrees of Separation (DOS)
//!
//! This is a simple implementation of the Degrees of Separation algorithm
use ed25519_proofs::{add_eddsa_targets, EDDSATargets, MessageDigest, PublicKey, Signature};
use hex_literal::hex;
use plonky2::{
    self,
    field::goldilocks_field::GoldilocksField,
    field::types::Field,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitData,
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use plonky2_sha512::circuit::array_to_bits;

mod original_voucher;
mod path_voucher;
mod utils;
mod voucher;

pub(crate) const D: usize = 2;
// first 4 bytes of keccak256("dos.voucher.locus");
pub(crate) const LOCUS_DOMAIN_SEPARATOR: [u8; 4] = hex!("73afcf84");
pub(crate) type C = PoseidonGoldilocksConfig;
pub(crate) type F = <C as GenericConfig<D>>::F;
// pub(crate) type GoldilocksAddress = [F; 5];
