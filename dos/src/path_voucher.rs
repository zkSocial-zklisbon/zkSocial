// todo: add expiry timestamp to carry forward
pub struct PathVoucher {
    pub(crate) origin: PublicKey,
    pub(crate) locus: PublicKey,
    pub(crate) degree: F,
    pub(crate) proof_data: ProofWithPublicInputs<F, C, D>,
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

// pub fn increment_degree_targets(
//     builder: &mut CircuitBuilder<F, D>,
//     partial_witness: &mut PartialWitness<F>,
//     input_degree: F,
//     output_degree: F,
// ) {
//     let input_degree_target = builder.add_virtual_target();
//     let output_degree_target = builder.add_virtual_target();

//     builder.register_public_input(output_degree_target);

//     let one_target = builder.one();
//     let increment_target = builder.add(input_degree_target, one_target);

//     builder.connect(output_degree_target, increment_target);

//     partial_witness.set_target(input_degree_target, input_degree);
//     partial_witness.set_target(output_degree_target, output_degree);
// }
