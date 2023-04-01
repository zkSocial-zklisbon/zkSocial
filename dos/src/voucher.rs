use simple_crypto::{
    F, C, D,
    PublicKey,
    PrivateKey,
};

use plonky2::{plonk::circuit_data::CircuitData, proof::ProofWithPublicInputs};

pub struct Voucher {
    pub(crate) origin: PublicKey,
    pub(crate) locus: PublicKey,
    pub(crate) degree: F,
    pub(crate) voucher_proof_data: VoucherProofData,
}

pub enum VoucherProofData {
    PathProofData {
        pub(crate) circuit_data: CircuitData<F, C, D>,
        pub(crate) proof_data: ProofWithPublicInputs<F, C, D>,
    },
    OriginProofData { 
        pub(crate) circuit_data: CircuitData<F, C, D>,
        pub(crate) proof_data: ProofWithPublicInputs<F, C, D>,
    },
}

impl Voucher {
    fn new_origin(origin: PublicKey) -> Self {
        
    }
}