use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use plonky2_ed25519::gadgets::eddsa::{EDDSATargets, fill_circuits, make_verify_circuits};
// we can hash messages to a 256bit hash.
pub type MessageDigest = [u8; 32];
// ed25519 signatures are 512bits long.
pub type Signature = [u8; 64];
// ed25519 public key is 256 bits long.
pub type PublicKey = [u8; 32];

pub type Ed25519Targets = EDDSATargets;

pub fn add_eddsa_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    partial_witness: &mut PartialWitness<F>,
    message: MessageDigest,
    signature: Signature,
    public_key: PublicKey,
) {
    // first verify the signature before attempting to prove it
    // todo:

    // build verification circuit
    let msg_len = message.len();
    let eddsa_targets = make_verify_circuits(builder, msg_len);

    fill_circuits(
        partial_witness,
        message.as_ref(),
        signature.as_ref(),
        public_key.as_ref(),
        &eddsa_targets,
    );
}
