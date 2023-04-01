use plonky2::{
    field::types::{Field, Sample},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitData,
        config::{Hasher, GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
    hash::{poseidon::PoseidonHash},
};

pub(crate) const D: usize = 2;
pub(crate) type C = PoseidonGoldilocksConfig;
pub(crate) type F = <C as GenericConfig<D>>::F;
pub(crate) type PlonkyProof = ProofWithPublicInputs<F, C, 2>;

pub const PUBLIC_KEY_LENGTH: usize = 4;
pub const PRIVATE_KEY_LENGTH: usize = 4;
pub const DIGEST_LENGTH: usize = 4;
pub static PUBLIC_KEY_POSTFIX: [F; 4] = [F::ZERO; 4];

pub type Digest = [F; DIGEST_LENGTH];
pub type PublicKey = [F; PUBLIC_KEY_LENGTH];
pub type PrivateKey = [F; PRIVATE_KEY_LENGTH];

pub struct KeyPair {
    pub(crate) public_key: PublicKey,
    pub(crate) private_key: PrivateKey,
}

impl KeyPair {
    pub fn generate_key_pair() -> Self {
        let private_key: PrivateKey = [F::rand(); 4];
        let public_key: PublicKey = 
            PoseidonHash::hash_no_pad(
                &[private_key, PUBLIC_KEY_POSTFIX].concat())
                .elements;
        KeyPair {
            public_key,
            private_key,
        }
    }
}
