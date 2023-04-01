use plonky2::{iop::target::Target, plonk::circuit_builder::CircuitBuilder};
use simple_crypto::{C, D, DIGEST_LENGTH, F, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH};

pub struct VoucherTargets {
    pub(crate) origin_targets: Vec<Target>,
    pub(crate) locus_targets: Vec<Target>,
    pub(crate) signature_targets: Vec<Target>,
    pub(crate) degree_target: Target,
    pub(crate) private_key_targts: Vec<Target>,
}

pub(crate) fn make_origin_voucher_circuit(builder: &mut CircuitBuilder<F, D>) -> VoucherTargets {
    // allocate targets for the public inputs
    let origin_targets = builder.add_virtual_targets(PUBLIC_KEY_LENGTH);
    let locus_targets = builder.add_virtual_targets(PUBLIC_KEY_LENGTH);
    // todo: the locus is the message that gets signed,
    // so the signature doesnt need to be a target or public input,
    // but to be sure we add it (but can be removed later)
    let signature_targets = builder.add_virtual_targets(DIGEST_LENGTH);
    let degree_target = builder.add_virtual_target();

    // allocate remaining internal targets
    let private_key_targets = builder.add_virtual_targets(PRIVATE_KEY_LENGTH);
    let topic_public_key_targets = builder.add_virtual_targets(DIGEST_LENGTH);

    // topic for public key is [F::ZERO; 4]
    for i in 0..DIGEST_LENGTH {
        builder.connect(topic_public_key_targets[i], builder.zero());
    }

    // for origin voucher the origin and locus must be the same
    for i in 0..PUBLIC_KEY_LENGTH {
        builder.connect(origin_targets[i], locus_targets[i]);
    }

    // the degree must be zero
    builder.connect(degree_target, builder.zero());

    // the prover must know the private key, so it must hash to public key
    let should_be_public_key_origin_targets = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        [private_key_targets, topic_public_key_targets].concat(),
    );
    for i in 0..PUBLIC_KEY_LENGTH {
        builder.connect(origin_targets[i], should_be_public_key_origin_targets[i]);
    }

    // the prover must sign the locus correctly, so they should hash the public key
    // (origin) with the message (locuss)
    let should_be_signature_targets =
        builder.hash_n_to_hash_no_pad::<PoseidonHash>([origin_targets, locus_targets].concat());
    for i in 0..DIGEST_LENGTH {
        builder.connect(signature_targets[i], should_be_signature_targets[i]);
    }

    VoucherTargets {
        origin_targets,
        locus_targets,
        signature_targets,
        degree_target,
        private_key_targets,
    }
}
