use plonky2::{
    iop::witness::PartialWitness,
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};

use crate::{D, F};

pub(crate) fn get_circuit_builder_and_partial_witness() -> (CircuitBuilder<F, D>, PartialWitness<F>)
{
    let config = CircuitConfig::standard_recursion_zk_config();
    let mut circuit_builder = CircuitBuilder::<F, D>::new(config);

    let mut partial_witness = PartialWitness::<F>::new();

    (circuit_builder, partial_witness)
}
