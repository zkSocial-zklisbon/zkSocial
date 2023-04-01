use plonky2::{iop::target::{Target, BoolTarget}, hash::hash_types::RichField, field::extension::Extendable};

use crate::{
    add_eddsa_targets,
    utils::get_circuit_builder_and_partial_witness,
    voucher::Voucher,
    *,
};

use ed25519_proofs::Ed25519Targets;

pub struct OriginVoucher {
    pub(crate) origin: PublicKey,
    pub(crate) circuit_data: CircuitData<F, C, D>,
    pub(crate) proof_data: ProofWithPublicInputs<F, C, D>,
}

pub struct OriginVoucherTargets {
    pub(crate) origin: Vec<BoolTarget>,
    pub(crate) signature: Vec<BoolTarget>,
    pub(crate) message: Vec<BoolTarget>,
    pub(crate) degree: Target,
    pub(crate) eddsa: Ed25519Targets,
}


fn origin_vouch(origin: PublicKey, signature: Signature) -> OriginVoucher {
    let (mut circuit_builder, mut partial_witness) = get_circuit_builder_and_partial_witness();

    // Steps:
    //  1. have PI target for the degree to be zero (constant target == 0)
    //  2. Verify signature of origin signing (message hash of) origin

    // let voucher_targets =
    //     make_all_origin_voucher_targets(&mut circuit_builder);
    let zero_degree_target = circuit_builder.add_virtual_target();
    let message: [u8; MESSAGE_LENGTH] = origin.clone();
    add_eddsa_targets(
        &mut circuit_builder,
        &mut partial_witness,
        message,
        signature,
        origin,
    );

    circuit_builder.register_public_input(zero_degree_target);
    partial_witness.set_target(zero_degree_target, F::ZERO);

    let circuit_data = circuit_builder.build::<C>();
    let proof_with_pis = circuit_data.prove(partial_witness).unwrap();

    OriginVoucher {
        origin,
        circuit_data,
        proof_data: proof_with_pis,
    }
}

impl Voucher for OriginVoucher {
    fn degree(&self) -> F {
        F::ZERO
    }

    fn is_origin(&self) -> bool {
        true
    }

    fn verify(&self) -> bool {
        // TODO: can we make it without cloning the proof ?
        self.circuit_data.verify(self.proof_data.clone()).is_ok()
    }

    fn incremental_vouch(
        existing_voucher: impl Voucher,
        origin: PublicKey,
        locus: PublicKey,
        signature: Signature,
        input_degree: F,
    ) -> Self {
        unimplemented!("Implement me");
    }

    fn proof_data(&self) -> &ProofWithPublicInputs<F, C, D>{
        &self.proof_data
    }

    fn origin(&self) -> PublicKey {
        self.origin
    }
}

// pub fn make_all_origin_voucher_targets<F: RichField + Extendable<D>, const D: usize>(
//     circuit_builder: &mut CircuitBuilder<F, D>,
// ) -> OriginVoucherTargets {
//     // allocate a vector of binary (bool) targets 
//     // for each of the origin, signature and message
//     let origin_targets: Vec<BoolTarget> = Vec::with_capacity(PUBLIC_KEY_LENGTH_BITS);
//     let signature_targets: Vec<BoolTarget> = Vec::with_capacity(SIGNATURE_LENGTH_BITS);
//     let message_targets: Vec<BoolTarget> = Vec::with_capacity(MESSAGE_LENGTH_BITS);
    
//     // add a single target for the degree
//     let degree_target: Target = circuit_builder.add_virtual_target();


//     // let eddsa = make_verify_circuits(circuit_builder, 32);

//     OriginVoucherTargets {
//         origin,
//         signature,
//         message,
//         degree,
//         eddsa,
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Keypair, PublicKey, Signer, Verifier};
    use hex_literal::hex;
    use rand::rngs::OsRng;

    #[test]
    fn it_works_original_voucher_proof_and_verify() {
        let mut csprng = OsRng {};
        let key_pair = Keypair::generate(&mut csprng);
        let origin = key_pair.public.to_bytes();
        let message = origin.clone();
        let signature = key_pair.sign(&message).to_bytes();

        let origin_voucher: OriginVoucher = origin_vouch(origin, signature);
        assert!(origin_voucher.verify());
    }

    #[test]
    fn it_works_ed25519_signature() {
        let message: [u8; 8] = hex!("0123456789ABCDEF");
        let public_key: PublicKey = PublicKey::from_bytes(&hex!(
            "9DBB279277D4EFE2E5F114A9AAB25C83FC9509D3B3D3B90929854F5A243AEBCD"
        ))
        .unwrap();

        let expected_signature = ed25519_dalek::Signature::try_from(&hex!("2EF7A1AA2FC58D40691236664418ADC903C153ABC0C95D02AC45B436C02081C2B93891B37B17F57C7CDE97B52BBB8F1865C14A92ADA4DC34ED0DE7935346E40E")[..]).unwrap();

        assert!(public_key.verify(&message, &expected_signature).is_ok());
    }
}
