use simple_crypto::{Digest, PrivateKey, PublicKey, C, D, F};

use crate::circuit_builder::{
    fill_extend_voucher_circuit, fill_origin_voucher_circuit, make_extended_voucher_circuit,
    make_origin_voucher_circuit,
};
use plonky2::{
    field::types::Field,
    hash::poseidon::PoseidonHash,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::Hasher,
        proof::ProofWithPublicInputs,
    },
};

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
        let signature: Digest = PoseidonHash::hash_no_pad(&[origin, locus].concat()).elements;

        let config = CircuitConfig::standard_recursion_zk_config();
        let mut circuit_builder = CircuitBuilder::<F, D>::new(config);
        let mut partial_witness = PartialWitness::<F>::new();

        let voucher_targets = make_origin_voucher_circuit(&mut circuit_builder);
        fill_origin_voucher_circuit(
            &mut partial_witness,
            voucher_targets,
            origin,
            locus,
            private_key,
            signature,
        );

        let circuit_data = circuit_builder.build::<C>();
        let proof_with_pis = circuit_data
            .prove(partial_witness)
            .expect("Failed to prove origin voucher circuit");

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

    fn extend_voucher(
        &self,
        inner_private_key_locus: PrivateKey,
        outer_locus: PublicKey,
    ) -> Voucher {
        let outer_origin: PublicKey = self.origin.clone();
        let inner_locus: PublicKey = self.locus.clone();
        let inner_degree: F = self.degree;

        let outer_signature: Digest =
            PoseidonHash::hash_no_pad(&[outer_origin, outer_locus].concat()).elements;

        let config = CircuitConfig::standard_recursion_zk_config();
        let mut circuit_builder = CircuitBuilder::<F, D>::new(config);
        let mut partial_witness = PartialWitness::<F>::new();

        let inner_circuit_data = match &self.voucher_proof_data {
            VoucherProofData::PathProofData { .. } => unimplemented!(),
            VoucherProofData::OriginProofData { circuit_data, .. } => circuit_data,
        };
        let voucher_targets =
            make_extended_voucher_circuit(&mut circuit_builder, inner_circuit_data);

        fill_extend_voucher_circuit(
            &mut partial_witness,
            voucher_targets,
            outer_origin,
            inner_locus,
            inner_degree,
            outer_locus,
            inner_private_key_locus,
            outer_signature,
            inner_circuit_data,
        );

        let circuit_data = circuit_builder.build::<C>();
        let proof_with_pis = circuit_data
            .prove(partial_witness)
            .expect("Failed to prove origin voucher circuit");

        Voucher {
            origin: outer_origin,
            locus: outer_locus,
            degree: inner_degree + F::ONE,
            voucher_proof_data: VoucherProofData::PathProofData {
                circuit_data,
                proof_data: proof_with_pis,
            },
        }
    }

    // fn verify
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_crypto::KeyPair;

    #[test]
    fn it_works_origin_voucher() {
        let key_pair = KeyPair::generate_key_pair();
        let origin_voucher = Voucher::new_origin(key_pair.public_key, key_pair.private_key);

        match origin_voucher.voucher_proof_data {
            VoucherProofData::PathProofData { .. } => panic!("Expected origin voucher proof data"),
            VoucherProofData::OriginProofData {
                circuit_data,
                proof_data,
            } => {
                assert!(circuit_data.verify(proof_data).is_ok());
            }
        }
    }

    #[test]
    fn it_works_extended_voucher() {
        let origin_key_pair = KeyPair::generate_key_pair();
        let origin_private_key = origin_key_pair.private_key.clone();
        let outer_locus = KeyPair::generate_key_pair().public_key;
        let origin_voucher =
            Voucher::new_origin(origin_key_pair.public_key, origin_key_pair.private_key);

        let origin_voucher_proof_data = origin_voucher.voucher_proof_data;
        match origin_voucher_proof_data {
            VoucherProofData::PathProofData { .. } => panic!("Expected origin voucher proof data"),
            VoucherProofData::OriginProofData {
                circuit_data,
                proof_data,
            } => {
                assert!(circuit_data.verify(proof_data).is_ok());
            }
        }

        let origin_voucher_copy =
            Voucher::new_origin(origin_key_pair.public_key, origin_key_pair.private_key);
        let extended_voucher = origin_voucher_copy.extend_voucher(origin_private_key, outer_locus);

        // match extended_voucher.voucher_proof_data {
        //     VoucherProofData::OriginProofData { .. } => panic!("No cuteness today"),
        //     VoucherProofData::PathProofData { circuit_data, proof_data } => {
        //         assert!(circuit_data.verify(proof_data).is_ok())
        //     }
        // }
    }
}
