use super::gadget::{IsZeroChip, IsZeroConfig};
use halo2_proofs::{
    arithmetic::FieldExt, circuit::*, dev::MockProver, pasta::Fp, plonk::*, poly::Rotation,
};

// f(a, b, c) = if a == b {c} else {a - b}
#[derive(Debug, Clone)]
struct FunctionConfig<F: FieldExt> {
    selector: Selector,
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    a_equals_b: IsZeroConfig<F>,
    output: Column<Advice>,
}

struct Chip<F: FieldExt> {
    config: Config,
}

impl<F: FieldExt> FiboChip<F> {
    pub fn construct(config: FiboConfig) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        let selector = meta.selector();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let output = meta.advice_column();

        let a_equals_b = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(selector),
            |meta| meta.query_advice(a, Rotation::cur()) - meta.query_advice(b, Rotation::cur()),
            meta.advice_column(),
        );

        meta.create_gate("f(a, b, c) = if a == b {c} else {a - b}", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let output = meta.query_advice(output, Rotation::cur());
            vec![
                s * (a_equals_b.expr() * (output - c)),
                s * (1.expr() - a_equals_b.expr()) * (output - (a - b)),
            ]
        });

        Config {
            selector,
            a,
            b,
            c,
            a_equals_b,
            output,
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        a: F,
        b: F,
        c: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "f(a, b, c) = if a == b {c} else {a - b}",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;
                region.assign_advice(|| "a", self.config.a, 0, || a)?;
                region.assign_advice(|| "b", self.config.b, 0, || b)?;
                region.assign_advice(|| "c", self.config.c, 0, || c)?;

                self.config.a_equals_b.assign(region, 0, a - b)?;

                let output = if a == b { c } else { a - b };
                region.assign_advice(|| "output", self.config.output, 0, || output)?
            },
        )
    }
}

#[derive(Default)]
struct FunctionCircuit<F> {
    a: F,
    b: F,
    c: F,
}

impl<F: FieldExt> Circuit<F> for FunctionCircuit<F> {
    type Config = FiboConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        FunctionChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = FiboChip::construct(config);

        let (prev_a, mut prev_b, mut prev_c) =
            chip.assign_first_row(layouter.namespace(|| "first row"), self.a, self.b)?;

        chip.expose_public(layouter.namespace(|| "private a"), &prev_a, 0)?;
        chip.expose_public(layouter.namespace(|| "private b"), &prev_b, 1)?;

        for _i in 3..10 {
            let c_cell = chip.assign_row(layouter.namespace(|| "next row"), &prev_b, &prev_c)?;
            prev_b = prev_c;
            prev_c = c_cell;
        }

        chip.expose_public(layouter.namespace(|| "output"), &prev_c, 2)?;

        Ok(())
    }
}

fn main() {
    let k = 4;

    let a = Fp::from(1); // F[0]
    let b = Fp::from(1); // F[1]
    let out = Fp::from(55); // F[9]

    let circuit = MyCircuit {
        a: Value::known(a),
        b: Value::known(b),
    };

    let mut public_input = vec![a, b, out];

    let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
    prover.assert_satisfied();

    public_input[2] += Fp::one();
    let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
    // uncomment the following line and the assert will fail
    // prover.assert_satisfied();
}
