use std::marker::PhantomData;

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};

#[derive(Debug, Clone)]
struct TableConfig<F: FieldExt> {
    col0: TableColumn,
    col1: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> TableConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            col0: meta.lookup_table_column(),
            col1: meta.lookup_table_column(),
            _marker: PhantomData,
        }
    }

    fn load(&self, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "table",
            |mut table| {
                let mut offset = 0;

                // Only assign one row in col0
                table.assign_cell(|| "col0", self.col0, offset, || Value::known(F::one()))?;

                // Assign two rows in col1
                table.assign_cell(
                    || "col1 row 0",
                    self.col0,
                    offset,
                    || Value::known(F::one()),
                )?;
                offset += 1;
                table.assign_cell(
                    || "col1 row 1",
                    self.col0,
                    offset,
                    || Value::known(F::one()),
                )?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{FailureLocation, MockProver, VerifyFailure},
        pasta::Fp,
    };

    struct MyCircuit<F: FieldExt>(PhantomData<F>);
    impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
        type Config = TableConfig<F>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self(PhantomData)
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            Self::Config::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.load(layouter)
        }
    }

    #[test]
    fn test_uneven_table() {
        let k = 3;
        let circuit = MyCircuit::<Fp>(PhantomData);
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
