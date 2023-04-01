use plonky2::iop::target::BoolTarget;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::witness::PartialWitness,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ed25519::gadgets::eddsa::{EDDSATargets, fill_circuits, make_verify_circuits};
use plonky2_ed25519::curve::curve_types::Curve;
use plonky2_ed25519::curve::ed25519::Ed25519;
use plonky2_ed25519::gadgets::curve::CircuitBuilderCurve;
use plonky2_ed25519::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use plonky2_ed25519::gadgets::curve_windowed_mul::CircuitBuilderWindowedMul;
use plonky2_ed25519::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_sha512::circuit::{bits_to_biguint_target, make_circuits};

// we can hash messages to a 256bit hash.
pub type MessageDigest = [u8; 32];
// ed25519 signatures are 512bits long.
pub type Signature = [u8; 64];
// ed25519 public key is 256 bits long.
pub type PublicKey = [u8; 32];

pub type Ed25519Targets = EDDSATargets;

// todo: I dont know if Jorge depends on the above,
// so I'm building a new one for now.
pub struct Ed25519TargetsHomeGrown {
    pub(crate) message: Vec<BoolTarget>,
    pub(crate) signature: Vec<BoolTarget>,
    pub(crate) public_key: Vec<BoolTarget>,
}

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

pub fn make_ed25519_verification_ciruit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message_targets: &Vec<BoolTarget>,
    signature_targets: &Vec<BoolTarget>,
    public_key_targets: &Vec<BoolTarget>,
    message_length: usize,
) -> Ed25519Targets {
    // based on work from gh.com/polymerdao/plonky2-ed25519

    let message_length_in_bits: usize = message_length * 8;
    let sha512_msg_len = msg_len_in_bits + 512;
    let sha512 = make_circuits(builder, sha512_msg_len as u128);

    // let mut msg = Vec::new();
    // let mut sig = Vec::new();
    // let mut pk = Vec::new();
    for i in 0..msg_len_in_bits {
        builder.register_public_input(sha512.message[512 + i].target);
        message_targets.push(sha512.message[512 + i]);
    }
    for _ in 0..512 {
        signature_targets.push(builder.add_virtual_bool_target_unsafe());
    }
    for _ in 0..256 {
        let t = builder.add_virtual_bool_target_unsafe();
        builder.register_public_input(t.target);
        pk.push(t);
    }
    for i in 0..256 {
        builder.connect(sha512.message[i].target, sig[i].target);
    }
    for i in 0..256 {
        builder.connect(sha512.message[256 + i].target, pk[i].target);
    }

    let digest_bits = bits_in_le(sha512.digest.clone());
    let hash = bits_to_biguint_target(builder, digest_bits);
    let h = builder.reduce(&hash);

    let s_bits = bits_in_le(sig[256..512].to_vec());
    let s_biguint = bits_to_biguint_target(builder, s_bits);
    let s = builder.biguint_to_nonnative(&s_biguint);

    let pk_bits = bits_in_le(pk.clone());
    let a = builder.point_decompress(&pk_bits);

    let ha = builder.curve_scalar_mul_windowed(&a, &h);

    let r_bits = bits_in_le(sig[..256].to_vec());
    let r = builder.point_decompress(&r_bits);

    let sb = fixed_base_curve_mul_circuit(builder, Ed25519::GENERATOR_AFFINE, &s);
    let rhs = builder.curve_add(&r, &ha);
    builder.connect_affine_point(&sb, &rhs);

    return Ed25519Targets { msg, sig, pk };

    // make_verify_circuits(builder, message_length)
}

// thanks, taken from gh.com/polymerdao/plonky2-ed25519
fn bits_in_le(input_vec: Vec<BoolTarget>) -> Vec<BoolTarget> {
    let mut bits = Vec::new();
    for i in 0..input_vec.len() / 8 {
        for j in 0..8 {
            bits.push(input_vec[i * 8 + 7 - j]);
        }
    }
    bits.reverse();
    bits
}