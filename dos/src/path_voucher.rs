use crate::{
    utils::get_circuit_builder_and_partial_witness, voucher::Voucher, PublicKey, Signature, C, D,
    F, *,
};

use ed25519_proofs::Ed25519Targets;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;

pub(crate) struct PathVoucherTargets {
    pub(crate) inner_voucher_origin_targets: Vec<BoolTarget>,
    pub(crate) origin_targets: Vec<BoolTarget>,
    pub(crate) one_target: Option<Target>,
    pub(crate) zero_target: Option<Target>,
    pub(crate) inner_voucher_degree_target: Option<Target>,
    pub(crate) degree_target: Option<Target>,
    pub(crate) eddsa_targets: Ed25519Targets,
}

impl PathVoucherTargets {
    pub fn new() -> Self {
        Self {
            inner_voucher_origin_targets: vec![],
            origin_targets: vec![],
            one_target: None,
            zero_target: None,
            inner_voucher_degree_target: None,
            degree_target: None,
            eddsa_targets: Ed25519Targets {
                msg: vec![],
                pk: vec![],
                sig: vec![],
            },
        }
    }
}

/// Adds targets to circuit to verify increment degree logic.
/// Additionally, it sets partial witness values to targets
pub(crate) fn increment_degree_targets(
    builder: &mut CircuitBuilder<F, D>,
    partial_witness: &mut PartialWitness<F>,
    targets: &mut PathVoucherTargets,
    input_degree: F,
    output_degree: F,
) {
    let input_degree_target = builder.add_virtual_target();
    let output_degree_target = builder.add_virtual_target();

    builder.register_public_input(output_degree_target);

    let one_target = builder.one();
    let increment_target = builder.add(input_degree_target, one_target);

    builder.connect(output_degree_target, increment_target);

    partial_witness.set_target(input_degree_target, input_degree);
    partial_witness.set_target(output_degree_target, output_degree);

    targets.inner_voucher_degree_target = Some(input_degree_target);
    targets.degree_target = Some(output_degree_target);
    targets.one_target = Some(one_target);
}

/// Adds targets to circuit to verify origin invariance across vouchers logic.
/// Additionally, it sets partial witness values to targets
pub(crate) fn origin_check_targets(
    builder: &mut CircuitBuilder<F, D>,
    partial_witness: &mut PartialWitness<F>,
    targets: &mut PathVoucherTargets,
    previous_origin: PublicKey,
    current_origin: PublicKey,
) {
    // todo: check that the len of both previous and current origin pubkeys is == 32
    // this should already be done in the ed25519 plonky2 lib (to be confirmed)
    let origin_len_in_bits = previous_origin.len() * 8;
    let previous_origin_bits: Vec<bool> = array_to_bits(&previous_origin);
    let current_origin_bits: Vec<bool> = array_to_bits(&current_origin);

    let mut previous_origin_targets = vec![];
    let mut current_origin_targets = vec![];

    for i in 0..origin_len_in_bits {
        let previous_origin_target = builder.add_virtual_bool_target_safe();
        let current_origin_target = builder.add_virtual_bool_target_safe();

        previous_origin_targets.push(previous_origin_target);
        current_origin_targets.push(current_origin_target);

        builder.connect(previous_origin_target.target, current_origin_target.target);

        partial_witness.set_bool_target(previous_origin_target, previous_origin_bits[i]);
        partial_witness.set_bool_target(current_origin_target, current_origin_bits[i]);
    }

    targets.inner_voucher_origin_targets = previous_origin_targets;
    targets.origin_targets = current_origin_targets;
}

/// Adds targets to circuit proving that previous voucher is valid.
/// Additionally, it sets partial witness values to targets
pub(crate) fn check_if_previous_voucher_is_origin(
    builder: &mut CircuitBuilder<F, D>,
    partial_witness: &mut PartialWitness<F>,
    targets: &PathVoucherTargets,
    inner_voucher: impl Voucher,
) {
    let inner_voucher_degree = inner_voucher.degree();
    let inner_voucher_degree_target = targets
        .inner_voucher_degree_target
        .expect("Degree targets are not available");

    let zero_target = builder.zero();
    let is_origin_bool_target = builder.is_equal(inner_voucher_degree_target, zero_target);

    let is_origin_target = builder._true();
    let not_origin_target = builder._true();

    builder._if(
        is_origin_bool_target,
        is_origin_target.target,
        not_origin_target.target,
    );

    if inner_voucher_degree == F::ZERO {
        partial_witness.set_target(is_origin_bool_target.target, F::ONE);
    } else {
        partial_witness.set_target(is_origin_bool_target.target, F::ZERO);
    }
}

// todo: add expiry timestamp to carry forward
/// [`PathVoucher`] represents a degree > 0 [`Voucher`] instance
pub struct PathVoucher {
    pub(crate) origin: PublicKey,
    pub(crate) locus: PublicKey,
    pub(crate) degree: F,
    pub(crate) circuit_data: CircuitData<F, C, D>,
    pub(crate) proof_data: ProofWithPublicInputs<F, C, D>,
}

impl Voucher for PathVoucher {
    fn incremental_vouch(
        inner_voucher: impl Voucher,
        origin: PublicKey,
        locus: PublicKey,
        signature: Signature,
    ) -> Self {
        // verify inner voucher
        if !inner_voucher.verify() {
            panic!("Inner voucher proof is invalid!!")
        }
        // TODO: distinguish between cases path and origin voucher cases
        let (mut circuit_builder, mut partial_witness) = get_circuit_builder_and_partial_witness();

        // start empty target struct
        let mut circuit_targets = PathVoucherTargets::new();
        // TODO: verify previous proof
        // circuit_builder.verify_proof(inner_voucher.proof_data(), inner_voucher.circuit_data());

        let inner_voucher_degree = inner_voucher.degree();
        let degree = inner_voucher_degree + F::ONE;
        let inner_voucher_origin = inner_voucher.origin();

        increment_degree_targets(
            &mut circuit_builder,
            &mut partial_witness,
            &mut circuit_targets,
            inner_voucher_degree,
            degree,
        );

        origin_check_targets(
            &mut circuit_builder,
            &mut partial_witness,
            &mut circuit_targets,
            inner_voucher_origin,
            origin,
        );

        circuit_targets.eddsa_targets = add_eddsa_targets(
            &mut circuit_builder,
            &mut partial_witness,
            origin.clone(),
            signature,
            inner_voucher.locus(),
        );

        let circuit_data = circuit_builder.build::<C>();
        let proof_with_pis = circuit_data
            .prove(partial_witness)
            .unwrap_or_else(|e| panic!("Invalid proof for current voucher, with error {e} !"));

        Self {
            origin,
            degree,
            locus,
            circuit_data,
            proof_data: proof_with_pis,
        }
    }

    fn degree(&self) -> F {
        self.degree
    }

    fn verify(&self) -> bool {
        // TODO: can we make it without cloning the proof ?
        self.circuit_data.verify(self.proof_data.clone()).is_ok()
    }

    fn is_origin(&self) -> bool {
        false
    }

    fn proof_data(&self) -> &ProofWithPublicInputs<F, C, D> {
        &self.proof_data
    }

    fn origin(&self) -> PublicKey {
        self.origin
    }

    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.circuit_data
    }

    fn locus(&self) -> PublicKey {
        self.locus
    }
}

// impl PathVoucher {
//     // pub fn origin_vouch(
//     //     origin: PublicKey,
//     //     signature: Signature,
//     // )

//     /// make a new voucher by signing a new locus from a previous voucher
//     pub fn incremental_vouch(
//         inner_voucher: impl GenericVoucher,
//         origin: PublicKey,
//         locus: PublicKey,
//         signature: Signature,
//         input_degree: F,
//         // expiry: F,
//     ) -> Result<Self, anyhow::Error> {
//         let config = CircuitConfig::standard_recursion_zk_config();
//         let mut circuit_builder = CircuitBuilder::<F, D>::new(config);

//         let mut partial_witness = PartialWitness::<F>::new();
//         let output_degree = input_degree + F::ONE;

//         increment_degree_targets(
//             &mut circuit_builder,
//             &mut partial_witness,
//             input_degree,
//             output_degree,
//         );

//         // message
//         // TODO: hash the locus with a domain separator to a message
//         // let mut domain_separated_locus = LOCUS_DOMAIN_SEPARATOR.to_vec();
//         // domain_separated_locus.extend(locus);
//         let message = locus;

//         // build circuit for signature verification
//         add_eddsa_targets(
//             &mut circuit_builder,
//             &mut partial_witness,
//             message,
//             signature,
//             origin,
//         );

//         // verify the previous voucher's proof data

//         let circuit_data = circuit_builder.build::<C>();
//         let proof_with_pis = circuit_data.prove(partial_witness)?;

//         Ok(Self {
//             origin,
//             locus,
//             degree: F::ONE,
//             proof_data: proof_with_pis,
//         })
//     }

//     pub fn verify(self) -> Result<(), anyhow::Error> {
//         Ok(())
//     }
// }
