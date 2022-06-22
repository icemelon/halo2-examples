use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter},
    plonk::{Assigned, ConstraintSystem, Error},
};

/// This gadget range-constrains an element witnessed in the circuit to be N bits.
///
/// Internally, this gadget uses the `range_check` helper, which provides a K-bit
/// lookup table.
///
/// Given an element `value`, we use a running sum to break it into K-bit chunks.
/// Assume for now that N | K, and define C = N / K.
///
///     value = [b_0, b_1, ..., b_{N-1}]   (little-endian)
///           = c_0 + 2^K * c_1  + 2^{2K} * c_2 + ... + 2^{(C-1)K} * c_{C-1}
///
/// Initialise the running sum at
///                                 value = z_0.
///
/// Consequent terms of the running sum are z_{i+1} = (z_i - c_i) * 2^{-K}:
///
///                           z_1 = (z_0 - c_0) * 2^{-K}
///                           z_2 = (z_1 - c_1) * 2^{-K}
///                              ...
///                       z_{C-1} = c_{C-1}
///                           z_C = (z_{C-1} - c_{C-1}) * 2^{-K}
///                               = 0
///
/// One configuration for this gadget could look like:
///
///     | running_sum |  q_decompose  |  table_value  |
///     -----------------------------------------------
///     |     z_0     |       1       |       0       |
///     |     z_1     |       1       |       1       |
///     |     ...     |      ...      |      ...      |
///     |   z_{C-1}   |       1       |      ...      |
///     |     z_C     |       0       |      ...      |
///
/// Stretch task: use the tagged lookup table to constrain arbitrary bitlengths
/// (even non-multiples of K)

#[derive(Debug, Clone)]
struct DecomposeConfig<F: FieldExt, const LOOKUP_NUM_BITS: usize, const LOOKUP_RANGE: usize> {
    // You'll need an advice column to witness your running sum;
    // A selector to constrain the running sum;
    // A selector to lookup the K-bit chunks;
    // And of course, the K-bit lookup table
    table: RangeTableConfig<F, LOOKUP_NUM_BITS, LOOKUP_RANGE>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const LOOKUP_NUM_BITS: usize> DecomposeConfig<F, LOOKUP_NUM_BITS> {
    fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        // Create the needed columns and internal configs.

        // Check that each interstitial value of the running sum is composed correctly from the previous one.
        meta.create_gate(|| "z_{i+1} = (z_i - c_i) * 2^{-K}", |meta| todo!());

        // Range-constrain each K-bit chunk `c_i = z_i - z_{i+1} * 2^K` derived from the running sum.
        meta.lookup(|meta| todo!());
    }

    fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        value: AssignedCell<Assigned<F>, F>,
        num_bits: usize,
    ) -> Result<(), Error> {
        // 1. Compute the interstitial running sum values {z_0, ..., z_C}}
        // 2. Assign the running sum values
        // 3. Make sure to enable the relevant selector on each row of the running sum
        todo!()
    }
}
