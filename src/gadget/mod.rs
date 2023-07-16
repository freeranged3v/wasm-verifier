pub mod arithmetic;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Value},
    plonk,
    plonk::{Advice, Assigned, Column},
};

/// For assigning private value
pub fn assign_free_advice<F: Field, V: Copy>(
    mut layouter: impl Layouter<F>,
    column: Column<Advice>,
    value: Value<V>,
) -> Result<AssignedCell<V, F>, plonk::Error>
where
    for<'v> Assigned<F>: From<&'v V>,
{
    // Assign the value to a region of 1 cell and return AssignedCell
    // You could think of it like copying the private value to the table
    layouter.assign_region(
        || "load private",
        |mut region| region.assign_advice(|| "load private", column, 0, || value),
    )
}
