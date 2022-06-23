use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{
        Advice, Assigned, Column, ConstraintSystem, Constraints, Error, Expression, Selector,
        TableColumn,
    },
    poly::Rotation,
};

mod table;
use table::*;

/// This helper uses a lookup table to check that the value witnessed in a given cell is
/// within a given range.
///
/// The lookup table is tagged by `num_bits` to give a strict range check.
///
///        value     |   q_lookup  |  table_num_bits  |  table_value  |
///       -------------------------------------------------------------
///          v_0     |      0      |        1         |       0       |
///          v_1     |      1      |        1         |       1       |
///          ...     |     ...     |        2         |       2       |
///          ...     |     ...     |        2         |       3       |
///          ...     |     ...     |        3         |       4       |
///
/// We use a K-bit lookup table, that is tagged 1..=K, where the tag `i` marks an `i`-bit value.
///

#[derive(Debug, Clone)]
/// A range-constrained value in the circuit produced by the RangeCheckConfig.
struct RangeConstrained<F: FieldExt> {
    num_bits: AssignedCell<Assigned<F>, F>,
    assigned_cell: AssignedCell<Assigned<F>, F>,
}

#[derive(Debug, Clone)]
struct RangeCheckConfig<F: FieldExt, const NUM_BITS: usize, const RANGE: usize> {
    q_lookup: Selector,
    num_bits: Column<Advice>,
    value: Column<Advice>,
    table: RangeTableConfig<F, NUM_BITS, RANGE>,
}

impl<F: FieldExt, const NUM_BITS: usize, const RANGE: usize> RangeCheckConfig<F, NUM_BITS, RANGE> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        num_bits: Column<Advice>,
        value: Column<Advice>,
    ) -> Self {
        let q_lookup = meta.complex_selector();
        let table = RangeTableConfig::configure(meta);

        meta.lookup(|meta| {
            let q_lookup = meta.query_selector(q_lookup);
            let num_bits = meta.query_advice(num_bits, Rotation::cur());
            let value = meta.query_advice(value, Rotation::cur());

            // THIS IS BROKEN!!!!!!
            // Hint: consider the case where q_lookup = 0. What are our input expressions to the lookup argument then?
            vec![
                (q_lookup.clone() * num_bits, table.num_bits),
                (q_lookup * value, table.value),
            ]
        });

        Self {
            q_lookup,
            num_bits,
            value,
            table,
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        num_bits: Value<u8>,
        value: Value<Assigned<F>>,
    ) -> Result<RangeConstrained<F>, Error> {
        layouter.assign_region(
            || "Assign value",
            |mut region| {
                let offset = 0;

                // Enable q_lookup
                self.q_lookup.enable(&mut region, offset)?;

                // Assign num_bits
                let num_bits = num_bits.map(|v| F::from(v as u64));
                let num_bits = region.assign_advice(
                    || "num_bits",
                    self.num_bits,
                    offset,
                    || num_bits.into(),
                )?;

                // Assign value
                let assigned_cell =
                    region.assign_advice(|| "value", self.value, offset, || value)?;

                Ok(RangeConstrained {
                    num_bits,
                    assigned_cell,
                })
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{FailureLocation, MockProver, VerifyFailure},
        pasta::Fp,
        plonk::{Any, Circuit},
    };

    use super::*;

    #[derive(Default)]
    struct MyCircuit<F: FieldExt, const NUM_BITS: usize, const RANGE: usize> {
        num_bits: Value<u8>,
        value: Value<Assigned<F>>,
    }

    impl<F: FieldExt, const NUM_BITS: usize, const RANGE: usize> Circuit<F>
        for MyCircuit<F, NUM_BITS, RANGE>
    {
        type Config = RangeCheckConfig<F, NUM_BITS, RANGE>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let num_bits = meta.advice_column();
            let value = meta.advice_column();
            RangeCheckConfig::configure(meta, num_bits, value)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.table.load(&mut layouter)?;

            config.assign(
                layouter.namespace(|| "Assign value"),
                self.num_bits,
                self.value,
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_range_check_3() {
        let k = 9;
        const NUM_BITS: usize = 8;
        const RANGE: usize = 256; // 8-bit value

        // Successful cases
        for num_bits in 1u8..=NUM_BITS.try_into().unwrap() {
            for value in (1 << (num_bits - 1))..(1 << num_bits) {
                let circuit = MyCircuit::<Fp, NUM_BITS, RANGE> {
                    num_bits: Value::known(num_bits),
                    value: Value::known(Fp::from(value as u64).into()),
                };

                let prover = MockProver::run(k, &circuit, vec![]).unwrap();
                prover.assert_satisfied();
            }
        }
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_range_check_3() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("range-check-3-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Range Check 3 Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = MyCircuit::<Fp, 8, 256> {
            num_bits: Value::unknown(),
            value: Value::unknown(),
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(9, &circuit, &root)
            .unwrap();
    }
}
