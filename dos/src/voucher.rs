use crate::{PublicKey, Signature, F};

pub(crate) trait Voucher {
    fn origin_vouch(origin: PublicKey, signature: Signature) -> Self;
    fn incremental_vouch(
        existing_voucher: impl Voucher,
        origin: PublicKey,
        locus: PublicKey,
        signature: Signature,
        input_degree: F,
    ) -> Self;
    fn degree(&self) -> F;
    fn is_origin(&self) -> bool;
    fn verify(&self) -> bool;
}
