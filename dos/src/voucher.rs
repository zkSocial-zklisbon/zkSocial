use plonky2::{field::types::Field, plonk::circuit_data::CircuitConfig};

use crate::{GoldilocksAddress, D, F};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use ed25519_proofs::{MessageDigest, PublicKey, Signature};

pub struct Voucher {
    pub(crate) origin: PublicKey,
    pub(crate) locus: PublicKey,
}

pub struct VoucherVerifier {}

impl Voucher {
    pub fn bootstrap(origin: PublicKey, locus: PublicKey, signature: &[u8], expiry: F) -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut circuit_builder = CircuitBuilder::<F, D>::new(config);

        Self { origin, locus }
    }
}
