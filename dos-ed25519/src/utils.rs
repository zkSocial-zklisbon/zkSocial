use plonky2::{
    iop::witness::PartialWitness,
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};

use crate::{D, F};

pub(crate) fn get_circuit_builder_and_partial_witness() -> (CircuitBuilder<F, D>, PartialWitness<F>)
{
    let config = CircuitConfig::wide_ecc_config();
    let circuit_builder = CircuitBuilder::<F, D>::new(config);
    let partial_witness = PartialWitness::<F>::new();

    (circuit_builder, partial_witness)
}
