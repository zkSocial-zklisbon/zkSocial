use plonky2::plonk::circuit_data::CircuitData;

use crate::{ProofWithPublicInputs, PublicKey, Signature, C, D, F};

pub(crate) trait Voucher {
    fn incremental_vouch(
        existing_voucher: impl Voucher,
        origin: PublicKey,
        locus: PublicKey,
        signature: Signature,
    ) -> Self;
    fn degree(&self) -> F;
    fn is_origin(&self) -> bool;
    fn proof_data(&self) -> &ProofWithPublicInputs<F, C, D>;
    fn verify(&self) -> bool;
    fn origin(&self) -> PublicKey;
    fn circuit_data(&self) -> &CircuitData<F, C, D>;
    fn locus(&self) -> PublicKey;
}
