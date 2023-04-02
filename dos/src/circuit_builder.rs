use plonky2::{
    field::types::Field,
    hash::poseidon::PoseidonHash,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, VerifierCircuitTarget},
    },
};
use simple_crypto::{C, D, DIGEST_LENGTH, F, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH};

pub struct VoucherTargets {
    pub(crate) origin_targets: Vec<Target>,
    pub(crate) locus_targets: Vec<Target>,
    pub(crate) signature_targets: Vec<Target>,
    pub(crate) degree_target: Target,
    pub(crate) private_key_targets: Vec<Target>,
}

pub struct ExtendedVoucherTargets {
    pub(crate) inner_origin_targets: Vec<Target>,
    pub(crate) inner_locus_targets: Vec<Target>,
    pub(crate) inner_degree_target: Target,
    pub(crate) outer_origin_targets: Vec<Target>,
    pub(crate) outer_locus_targets: Vec<Target>,
    pub(crate) outer_signature_targets: Vec<Target>,
    pub(crate) outer_degree_target: Target,
    pub(crate) private_key_targets: Vec<Target>,
    // pub(crate) inner_verify_data_targets: VerifierCircuitTarget,
}

pub fn make_origin_voucher_circuit(builder: &mut CircuitBuilder<F, D>) -> VoucherTargets {
    // allocate targets for the public inputs
    let origin_targets = builder.add_virtual_targets(PUBLIC_KEY_LENGTH);
    let locus_targets = builder.add_virtual_targets(PUBLIC_KEY_LENGTH);
    // todo: the locus is the message that gets signed,
    // so the signature doesnt need to be a target or public input,
    // but to be sure we add it (but can be removed later)
    let signature_targets = builder.add_virtual_targets(DIGEST_LENGTH);
    let degree_target = builder.add_virtual_target();

    builder.register_public_inputs(&origin_targets);
    builder.register_public_inputs(&locus_targets);
    builder.register_public_inputs(&signature_targets);
    builder.register_public_input(degree_target);

    // allocate remaining internal targets
    let private_key_targets = builder.add_virtual_targets(PRIVATE_KEY_LENGTH);
    let topic_public_key_targets = builder.add_virtual_targets(DIGEST_LENGTH);

    let zero_target = builder.zero();

    // topic for public key is [F::ZERO; 4]
    for i in 0..DIGEST_LENGTH {
        builder.connect(topic_public_key_targets[i], zero_target);
    }

    // for origin voucher the origin and locus must be the same
    for i in 0..PUBLIC_KEY_LENGTH {
        builder.connect(origin_targets[i], locus_targets[i]);
    }

    // the degree must be zero
    builder.connect(degree_target, zero_target);

    // the prover must know the private key, so it must hash to public key
    let should_be_public_key_origin_targets = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        [private_key_targets.clone(), topic_public_key_targets].concat(),
    );
    for i in 0..PUBLIC_KEY_LENGTH {
        builder.connect(
            origin_targets[i],
            should_be_public_key_origin_targets.elements[i],
        );
    }

    // the prover must sign the locus correctly, so they should hash the public key
    // (origin) with the message (locuss)
    let should_be_signature_targets = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        [origin_targets.clone(), locus_targets.clone()].concat(),
    );
    for i in 0..DIGEST_LENGTH {
        builder.connect(
            signature_targets[i],
            should_be_signature_targets.elements[i],
        );
    }

    VoucherTargets {
        origin_targets,
        locus_targets,
        signature_targets,
        degree_target,
        private_key_targets,
    }
}

pub fn make_extended_voucher_circuit(
    builder: &mut CircuitBuilder<F, D>,
    inner_circuit_data: &CircuitData<F, C, D>,
) -> ExtendedVoucherTargets {
    // allocate targets for the public inputs
    let outer_origin_targets = builder.add_virtual_targets(PUBLIC_KEY_LENGTH);
    let outer_locus_targets = builder.add_virtual_targets(PUBLIC_KEY_LENGTH);
    let outer_signature_targets = builder.add_virtual_targets(DIGEST_LENGTH);
    let outer_degree_target = builder.add_virtual_target();

    builder.register_public_inputs(&outer_origin_targets);
    builder.register_public_inputs(&outer_locus_targets);
    builder.register_public_inputs(&outer_signature_targets);
    builder.register_public_input(outer_degree_target);

    // allocate remaining internal targets
    let private_key_targets = builder.add_virtual_targets(PRIVATE_KEY_LENGTH);
    let topic_public_key_targets = builder.add_virtual_targets(DIGEST_LENGTH);

    let inner_origin_targets = builder.add_virtual_targets(PUBLIC_KEY_LENGTH);
    let inner_locus_targets = builder.add_virtual_targets(PUBLIC_KEY_LENGTH);
    let inner_degree_target = builder.add_virtual_target();

    builder.register_public_inputs(&inner_origin_targets);
    builder.register_public_inputs(&inner_locus_targets);
    builder.register_public_input(inner_degree_target);

    // inner and outer origin must be the same
    for i in 0..PUBLIC_KEY_LENGTH {
        builder.connect(outer_origin_targets[i], inner_origin_targets[i]);
    }

    // outer locus and origin should be distinct
    let mut bool_cumulative_target =
        builder.is_equal(outer_locus_targets[0], outer_origin_targets[0]);
    for i in 1..PUBLIC_KEY_LENGTH {
        let equality_element_target =
            builder.is_equal(outer_locus_targets[i], outer_origin_targets[i]);
        bool_cumulative_target = builder.and(bool_cumulative_target, equality_element_target);
    }
    let origin_and_locus_must_not_be_equal_target = builder.not(bool_cumulative_target);

    // the outer degree must be one more than the inner degree
    let one_target = builder.constant(F::ONE);
    let should_be_inner_degree_plus_one_target = builder.add(inner_degree_target, one_target);
    builder.connect(should_be_inner_degree_plus_one_target, outer_degree_target);

    // prove that we know the private key
    // topic for public key is [F::ZERO; 4]
    let zero_target = builder.zero();
    for i in 0..DIGEST_LENGTH {
        builder.connect(topic_public_key_targets[i], zero_target);
    }

    let should_be_public_key_inner_locus_targets = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        [private_key_targets.clone(), topic_public_key_targets].concat(),
    );
    for i in 0..PUBLIC_KEY_LENGTH {
        builder.connect(
            inner_locus_targets[i],
            should_be_public_key_inner_locus_targets.elements[i],
        );
    }

    // the prover must sign the outer locus correctly, so they should hash the public key
    // (origin) with the message (outer locus)
    let should_be_signature_targets = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        [inner_locus_targets.clone(), outer_locus_targets.clone()].concat(),
    );
    for i in 0..DIGEST_LENGTH {
        builder.connect(
            outer_signature_targets[i],
            should_be_signature_targets.elements[i],
        );
    }

    // let inner_proof_targets = builder.add_virtual_proof_with_pis(&inner_circuit_data.common);
    // let inner_verify_data_targets = builder.add_virtual_verifier_data(inner_circuit_data.common.config.fri_config.cap_height);

    // builder.verify_proof::<C>(&inner_proof_targets, &inner_verify_data_targets, &inner_circuit_data.common);

    ExtendedVoucherTargets {
        inner_origin_targets,
        inner_locus_targets,
        inner_degree_target,
        outer_origin_targets,
        outer_locus_targets,
        outer_signature_targets,
        outer_degree_target,
        private_key_targets,
        // inner_verify_data_targets,
    }
}

pub fn fill_origin_voucher_circuit(
    partial_witness: &mut PartialWitness<F>,
    voucher_targets: VoucherTargets,
    origin: [F; PUBLIC_KEY_LENGTH],
    locus: [F; PUBLIC_KEY_LENGTH],
    private_key: [F; PRIVATE_KEY_LENGTH],
    signature: [F; DIGEST_LENGTH],
) {
    let VoucherTargets {
        origin_targets,
        locus_targets,
        signature_targets,
        degree_target,
        private_key_targets,
    } = voucher_targets;

    // fill origin targets with origin entries
    for i in 0..PUBLIC_KEY_LENGTH {
        partial_witness.set_target(origin_targets[i], origin[i]);
    }

    // fill locus targets with locus entries
    for i in 0..PUBLIC_KEY_LENGTH {
        partial_witness.set_target(locus_targets[i], locus[i]);
    }

    // fill signature targets with signature entries
    for i in 0..DIGEST_LENGTH {
        partial_witness.set_target(signature_targets[i], signature[i]);
    }

    // todo: we already set degree to zero in the circuit, so this is redundant
    // partial_witness.set_target(degree_target, F::ZERO);

    // fill private key targets with private key entries
    for i in 0..PRIVATE_KEY_LENGTH {
        partial_witness.set_target(private_key_targets[i], private_key[i]);
    }
}

pub fn fill_extend_voucher_circuit(
    partial_witness: &mut PartialWitness<F>,
    voucher_targets: ExtendedVoucherTargets,
    origin: [F; PUBLIC_KEY_LENGTH],

    inner_locus: [F; PUBLIC_KEY_LENGTH],
    inner_degree: F,
    outer_locus: [F; PUBLIC_KEY_LENGTH],
    private_key: [F; PRIVATE_KEY_LENGTH],
    signature: [F; DIGEST_LENGTH],
    inner_circuit_data: &CircuitData<F, C, D>,
) {
    let ExtendedVoucherTargets {
        inner_origin_targets,
        inner_locus_targets,
        inner_degree_target,
        outer_origin_targets,
        outer_locus_targets,
        outer_signature_targets,
        outer_degree_target,
        private_key_targets,
        // inner_verify_data_targets,
    } = voucher_targets;

    // fill both origin targets with origin entries
    for i in 0..PUBLIC_KEY_LENGTH {
        partial_witness.set_target(outer_origin_targets[i], origin[i]);
        partial_witness.set_target(inner_origin_targets[i], origin[i]);
    }

    // fill both locus targets with locus entries
    for i in 0..PUBLIC_KEY_LENGTH {
        partial_witness.set_target(outer_locus_targets[i], outer_locus[i]);
        partial_witness.set_target(inner_locus_targets[i], inner_locus[i]);
    }

    // fill outer signature targets with signature entries
    for i in 0..DIGEST_LENGTH {
        partial_witness.set_target(outer_signature_targets[i], signature[i]);
    }

    // fill private key targets with private key entries
    for i in 0..PRIVATE_KEY_LENGTH {
        partial_witness.set_target(private_key_targets[i], private_key[i]);
    }

    // // fill targets for verified circuit data
    // partial_witness.set_cap_target(
    //     &inner_verify_data_targets.constants_sigmas_cap,
    //     &inner_circuit_data.verifier_only.constants_sigmas_cap,
    // );
    // partial_witness.set_hash_target(
    //     inner_verify_data_targets.circuit_digest,
    //     inner_circuit_data.verifier_only.circuit_digest,
    // );
}
