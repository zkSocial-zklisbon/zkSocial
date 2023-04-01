use simple_crypto::{
    F, C, D,
    PublicKey,
    PrivateKey,
    Digest,
};

use plonky2::{
    plonk::{
        config::Hasher,
        circuit_data::{
            CircuitData, CircuitConfig},
        circuit_builder::CircuitBuilder, 
        proof::ProofWithPublicInputs},
    field::types::Field,
    iop::witness::PartialWitness, hash::poseidon::PoseidonHash};
use crate::circuit_builder::{make_origin_voucher_circuit, fill_circuit};

pub struct Voucher {
    pub(crate) origin: PublicKey,
    pub(crate) locus: PublicKey,
    pub(crate) degree: F,
    pub(crate) voucher_proof_data: VoucherProofData,
}

pub enum VoucherProofData {
    PathProofData {
        circuit_data: CircuitData<F, C, D>,
        proof_data: ProofWithPublicInputs<F, C, D>,
    },
    OriginProofData { 
        circuit_data: CircuitData<F, C, D>,
        proof_data: ProofWithPublicInputs<F, C, D>,
    },
}

impl Voucher {
    fn new_origin(origin: PublicKey, private_key: PrivateKey) -> Self {
        // compute "signature" to pass as public inputs
        let locus: PublicKey = origin.clone();
        let signature: Digest = 
            PoseidonHash::hash_no_pad(
                &[origin, locus].concat())
                .elements;
        
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut circuit_builder = CircuitBuilder::<F, D>::new(config);
        let mut partial_witness = PartialWitness::<F>::new();

        let voucher_targets = make_origin_voucher_circuit(&mut circuit_builder);
        fill_circuit(&mut partial_witness, voucher_targets, origin, locus, private_key, signature);

        let circuit_data = circuit_builder.build::<C>();
        let proof_with_pis = 
            circuit_data.prove(partial_witness).expect(
                "Failed to prove origin voucher circuit");

        Voucher {
            origin,
            locus: origin,
            degree: F::ZERO,
            voucher_proof_data: VoucherProofData::OriginProofData {
                circuit_data: circuit_data,
                proof_data: proof_with_pis,
            },
        }
    }

    // fn verify
}