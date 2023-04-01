use plonky2::{
    field::types::Field,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_data::CircuitConfig, proof::ProofWithPublicInputs},
};

use crate::{C, D, F, LOCUS_DOMAIN_SEPARATOR};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use ed25519_proofs::{add_eddsa_targets, MessageDigest, PublicKey, Signature};

pub struct Voucher {
    pub(crate) origin: PublicKey,
    pub(crate) locus: PublicKey,
    pub(crate) degree: F,
    pub(crate) proof_data: ProofWithPublicInputs<F, C, D>,
}

pub struct VoucherVerifier {}

impl Voucher {
    ///
    pub fn vouch(
        origin: PublicKey,
        locus: PublicKey,
        signature: Signature,
        input_degree: F,
        expiry: F,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut circuit_builder = CircuitBuilder::<F, D>::new(config);

        let mut partial_witness = PartialWitness::<F>::new();
        let mut output_degree = input_degree + F::ONE;

        increment_degree_targets(
            &mut circuit_builder,
            &mut partial_witness,
            input_degree,
            output_degree,
        );

        // message
        // TODO: hash the locus with a domain separator to a message
        // let mut domain_separated_locus = LOCUS_DOMAIN_SEPARATOR.to_vec();
        // domain_separated_locus.extend(locus);
        let message = locus;

        // build circuit for signature verification
        add_eddsa_targets(
            &mut circuit_builder,
            &mut partial_witness,
            message,
            signature,
            origin,
        );

        Self {
            origin,
            locus,
            degree: F::ONE,
        }
    }

    pub fn verify() -> Result<(), anyhow::Error> {
        Ok(())
    }
}

pub fn increment_degree_targets(
    builder: &mut CircuitBuilder<F, D>,
    partial_witness: &mut PartialWitness<F>,
    input_degree: F,
    output_degree: F,
) {
    let input_degree_target = builder.add_virtual_target();
    let output_degree_target = builder.add_virtual_target();

    builder.register_public_input(output_degree_target);

    builder.connect(
        output_degree_target,
        builder.add(input_degree_target, builder.one()),
    );

    partial_witness.set_target(input_degree_target, input_degree);
    partial_witness.set_target(output_degree_target, output_degree);
}
