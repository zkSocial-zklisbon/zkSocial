use ed25519_proofs::{PublicKey, Signature, MessageDigest};

pub struct Voucher {
    pub(crate) origin: PublicKey,
    pub(crate) locus: PublicKey,

}