use ff::PrimeFieldBits;
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

mod table;
use table::RangeTableConfig;

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
/// In the case where `N` is not a multiple of `K`, we will have to handle the
/// final `l`-bit partial chunk separately (where `l` < `K`). In other words, we
/// will have to constrain c_{C-1} to `l` bits.
///
///     |      num_bits    | running_sum |  q_decompose  | q_partial_check | table_num_bits|  table_value  |
///     --------------------------------------------------------------------------------------------
///     |         0        |     z_0     |       1       |        0        |       1       |       0       |
///     |         0        |     z_1     |       1       |        0        |       1       |       1       |
///     |        ...       |     ...     |      ...      |       ...       |      ...      |      ...      |
///     |log2_ceil(c_{C-1})|   z_{C-1}   |       1       |        1        |      ...      |      ...      |
///     |         0        |     z_C     |       0       |        0        |      ...      |      ...      |
///
/// To do this, we can lookup the number of bits of c_{C-1} and check that it
/// equals `l`.
///
/// N = 64, K = 10
/// l = 4
///
/// value: u64 = 0
/// value: u64 = 0xFFFFFFFF
///
/// witness:
///     - final_chunk
///     - witness log_final_chunk = log_2_ceil(final_chunk)
///     - range_check that log_final_chunk \in [0, l]
///
/// lookup: (log_final_chunk, final_chunk) against (table.num_bits, table.value)
///
///

#[derive(Debug, Clone)]
struct DecomposeConfig<
    F: FieldExt + PrimeFieldBits,
    const WORD_NUM_BITS: usize,
    const LOOKUP_NUM_BITS: usize,
    const LOOKUP_RANGE: usize,
> {
    // You'll need an advice column to witness your running sum;
    running_sum: Column<Advice>,
    num_bits: Column<Advice>,
    // A selector to constrain the running sum;
    q_decompose: Selector,
    // A selector to constrain the partial chunk;
    q_partial_check: Selector,
    // And of course, the K-bit lookup table
    table: RangeTableConfig<F, LOOKUP_NUM_BITS, LOOKUP_RANGE>,
    _marker: PhantomData<F>,
}

impl<
        F: FieldExt + PrimeFieldBits,
        const WORD_NUM_BITS: usize,
        const LOOKUP_NUM_BITS: usize,
        const LOOKUP_RANGE: usize,
    > DecomposeConfig<F, WORD_NUM_BITS, LOOKUP_NUM_BITS, LOOKUP_RANGE>
{
    fn configure(
        meta: &mut ConstraintSystem<F>,
        num_bits: Column<Advice>,
        running_sum: Column<Advice>,
    ) -> Self {
        // Create the needed columns and internal configs.
        let q_decompose = meta.complex_selector();
        let q_partial_check = meta.complex_selector();
        let table = RangeTableConfig::configure(meta);

        meta.enable_equality(running_sum);

        // Range-constrain each K-bit chunk `c_i = z_i - z_{i+1} * 2^K` derived from the running sum.
        meta.lookup(|meta| {
            let q_decompose = meta.query_selector(q_decompose);

            // z_i
            let z_cur = meta.query_advice(running_sum, Rotation::cur());
            // z_{i+1}
            let z_next = meta.query_advice(running_sum, Rotation::next());
            // c_i = z_i - z_{i+1} * 2^K
            let chunk = z_cur - z_next * F::from(1u64 << LOOKUP_NUM_BITS);

            // Lookup default value 0 when q_decompose = 0
            let not_q_decompose = Expression::Constant(F::one()) - q_decompose.clone();
            let default_chunk = Expression::Constant(F::zero());

            let value = q_decompose * chunk + not_q_decompose * default_chunk;

            vec![(value, table.value)]
        });

        // Range-constrain the final partial chunk.
        meta.lookup(|meta| {
            let q_partial_check = meta.query_selector(q_partial_check);

            // z_i
            let z_cur = meta.query_advice(running_sum, Rotation::cur());
            // z_{i+1}
            let z_next = meta.query_advice(running_sum, Rotation::next());
            // c_i = z_i - z_{i+1} * 2^K
            let chunk = z_cur - z_next * F::from(1u64 << LOOKUP_NUM_BITS);
            // num_bits
            let num_bits = meta.query_advice(num_bits, Rotation::cur());

            // Lookup default value 0 when q_partial_check = 0
            let not_q_partial_check = Expression::Constant(F::one()) - q_partial_check.clone();
            let default_value = Expression::Constant(F::zero());
            let value =
                q_partial_check.clone() * chunk + not_q_partial_check.clone() * default_value;

            // Lookup default num_bits 1 when q_partial_check = 0
            let default_num_bits = Expression::Constant(F::one());
            let num_bits = q_partial_check * num_bits + not_q_partial_check * default_num_bits;

            vec![(value, table.value), (num_bits, table.num_bits)]
        });

        let partial_len = WORD_NUM_BITS % LOOKUP_NUM_BITS;
        if partial_len > 0 {
            // Range-constrain `num_bits` of the final chunk.
            meta.create_gate("Range-constrain final chunk num_bits", |meta| {
                let q_partial_check = meta.query_selector(q_partial_check);

                // Given a range R and a value v, returns the expression
                // (v) * (1 - v) * (2 - v) * ... * (R - 1 - v)
                let range_check = |range: usize, value: Expression<F>| {
                    assert!(range > 0);
                    (1..range).fold(value.clone(), |expr, i| {
                        expr * (Expression::Constant(F::from(i as u64)) - value.clone())
                    })
                };

                // num_bits
                let num_bits = meta.query_advice(num_bits, Rotation::cur());

                Constraints::with_selector(
                    q_partial_check,
                    [range_check(partial_len + 1, num_bits)],
                )
            });
        }

        Self {
            num_bits,
            running_sum,
            q_decompose,
            q_partial_check,
            table,
            _marker: PhantomData,
        }
    }

    fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        value: AssignedCell<Assigned<F>, F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Decompose value",
            |mut region| {
                let mut offset = 0;
                let partial_chunk_len = WORD_NUM_BITS % LOOKUP_NUM_BITS;

                // 0. Copy in the witnessed `value` at offset = 0
                let mut z = value.copy_advice(
                    || "Copy in value for decomposition",
                    &mut region,
                    self.running_sum,
                    offset,
                )?;

                // Increase offset after copying `value`
                offset += 1;

                // 1. Compute the interstitial running sum values {z_1, ..., z_C}}
                let expected_vec_len = if partial_chunk_len > 0 {
                    1 + WORD_NUM_BITS / LOOKUP_NUM_BITS
                } else {
                    WORD_NUM_BITS / LOOKUP_NUM_BITS
                };
                let running_sum: Vec<_> = value
                    .value()
                    .map(|&v| compute_running_sum::<_, LOOKUP_NUM_BITS>(v, WORD_NUM_BITS))
                    .transpose_vec(expected_vec_len);

                // 2. Assign the running sum values
                for z_i in running_sum.into_iter() {
                    z = region.assign_advice(
                        || format!("assign z_{:?}", offset),
                        self.running_sum,
                        offset,
                        || z_i,
                    )?;
                    offset += 1;
                }

                // 3. Make sure to enable the relevant selector on each row of the running sum
                //    (but not on the row where z_C is witnessed)
                for offset in 0..(WORD_NUM_BITS / LOOKUP_NUM_BITS) {
                    self.q_decompose.enable(&mut region, offset)?;
                }

                // 4. Constrain the final running sum `z_C` to be 0.
                region.constrain_constant(z.cell(), F::zero())?;

                if partial_chunk_len > 0 {
                    // Enable q_partial_check
                    self.q_partial_check.enable(&mut region, offset - 2)?;

                    // The final chunk
                    let final_chunk = value.value().map(|v| {
                        let v: Vec<_> = v
                            .evaluate()
                            .to_le_bits()
                            .iter()
                            .by_vals()
                            .take(WORD_NUM_BITS)
                            .collect();
                        let final_chunk = &v[(WORD_NUM_BITS - partial_chunk_len)..WORD_NUM_BITS];
                        lebs2ip(final_chunk)
                    });

                    let num_bits = final_chunk.map(|c| {
                        if c == 0 {
                            Assigned::from(F::zero())
                        } else {
                            Assigned::from(F::from(log2_ceil(c)))
                        }
                    });

                    // Witness `num_bits`
                    region.assign_advice(
                        || "num_bits for partial chunk",
                        self.num_bits,
                        offset - 2,
                        || num_bits,
                    )?;
                }

                Ok(())
            },
        )
    }
}

fn lebs2ip(bits: &[bool]) -> u64 {
    assert!(bits.len() <= 64);
    bits.iter()
        .enumerate()
        .fold(0u64, |acc, (i, b)| acc + if *b { 1 << i } else { 0 })
}

// Function to compute the interstitial running sum values {z_1, ..., z_C}}
fn compute_running_sum<F: FieldExt + PrimeFieldBits, const LOOKUP_NUM_BITS: usize>(
    value: Assigned<F>,
    num_bits: usize,
) -> Vec<Assigned<F>> {
    let mut running_sum = vec![];
    let mut z = value;

    // Get the little-endian bit representation of `value`.
    let value: Vec<_> = value
        .evaluate()
        .to_le_bits()
        .iter()
        .by_vals()
        .take(num_bits)
        .collect();
    for chunk in value.chunks(LOOKUP_NUM_BITS) {
        let chunk = Assigned::from(F::from(lebs2ip(chunk)));
        // z_{i+1} = (z_i - c_i) * 2^{-K}:
        z = (z - chunk) * Assigned::from(F::from(1u64 << LOOKUP_NUM_BITS)).invert();
        running_sum.push(z);
    }

    running_sum
}

fn log2_ceil(num: u64) -> u64 {
    println!("num in log2: {}", num);
    assert!(num > 0);

    let mut pow = 0;

    while (1 << (pow + 1)) <= num {
        pow += 1;
    }

    if (1 << pow) <= num {
        pow += 1;
    }

    pow
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{circuit::floor_planner::V1, dev::MockProver, pasta::Fp};
    use rand;

    use super::*;

    struct MyCircuit<
        F: FieldExt,
        const WORD_NUM_BITS: usize,
        const NUM_BITS: usize,
        const RANGE: usize,
    > {
        value: Value<Assigned<F>>,
    }

    impl<
            F: FieldExt + PrimeFieldBits,
            const WORD_NUM_BITS: usize,
            const NUM_BITS: usize,
            const RANGE: usize,
        > Circuit<F> for MyCircuit<F, WORD_NUM_BITS, NUM_BITS, RANGE>
    {
        type Config = DecomposeConfig<F, WORD_NUM_BITS, NUM_BITS, RANGE>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self {
                value: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            // Fixed column for constants
            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            let num_bits = meta.advice_column();
            let value = meta.advice_column();
            DecomposeConfig::configure(meta, num_bits, value)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.table.load(&mut layouter)?;

            // Witness the value somewhere
            let value = layouter.assign_region(
                || "Witness value",
                |mut region| {
                    region.assign_advice(|| "Witness value", config.running_sum, 0, || self.value)
                },
            )?;

            config.assign(layouter.namespace(|| "Decompose value"), value)?;

            Ok(())
        }
    }

    #[test]
    fn test_decompose_2() {
        let k = 11;
        const WORD_NUM_BITS: usize = 64;
        const LOOKUP_NUM_BITS: usize = 10;
        const RANGE: usize = 1024; // 10-bit value

        // Random u64 value
        let value: u64 = rand::random();
        // let value: u64 = 0xFFFFFFFF;
        let value = Value::known(Assigned::from(Fp::from(value)));

        let circuit = MyCircuit::<Fp, WORD_NUM_BITS, LOOKUP_NUM_BITS, RANGE> { value };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_decompose_2() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("decompose-ext-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled(
                "Decompose Range Check (Extension) Layout",
                ("sans-serif", 60),
            )
            .unwrap();

        let circuit = MyCircuit::<Fp, 64, 10, 1024> {
            value: Value::unknown(),
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(11, &circuit, &root)
            .unwrap();
    }
}
