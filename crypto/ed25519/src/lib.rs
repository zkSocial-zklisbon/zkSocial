use plonky2_ed25519::gadgets::eddsa::{fill_circuits, make_verify_circuits};

// we can hash messages to a 256bit hash.
pub type MessageDigest = [u8; 32];
// ed25519 signatures are 512bits long.
pub type Signature = [u8; 64];
// ed25519 public key is 256 bits long.
pub type PublicKey = [u8; 32];

pub fn prove_eddsa(
    message: MessageDigest,
    signature: Signature,
    public_key: PublicKey,
) -> Result<(), ()> {
    // first verify the signature before attempting to prove it

    Ok(())
}