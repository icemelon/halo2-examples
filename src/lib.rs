pub mod fibonacci;
mod is_zero;
mod range_check;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {}!", name));
}

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};
use halo2_proofs::{circuit::Value, dev::MockProver, pasta::Fp};
use fibonacci::example1::MyCircuit;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Assigned, BatchVerifier, Circuit,
    Column, ConstraintSystem, Error, Fixed, SingleVerifier, TableColumn, VerificationStrategy,
};
use halo2_proofs::poly::{commitment::Params};
use halo2_proofs::pasta::{Eq, EqAffine};
use rand_core::OsRng;
use std::io::{self, Write};

#[wasm_bindgen]
pub fn proofGen(name: &str) {
    alert(&format!("Generating proof, {}!", name));

    let a = Fp::from(1); // F[0]
    let b = Fp::from(1); // F[1]
    let out = Fp::from(55); // F[9]

    let circuit = MyCircuit {
        a: Value::known(a),
        b: Value::known(b),
    };

    let mut public_input = vec![a, b, out];
    const K: u32 = 5;
    let params: Params<EqAffine> = Params::new(K);
    let empty_circuit: MyCircuit<Fp> = MyCircuit {
        a: Value::unknown(),
        b: Value::unknown()
    };

    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    // Create a proof
    create_proof(
        &params,
        &pk,
        &[circuit.clone(), circuit.clone()],
        // public_
        &[&[&public_input], &[&public_input]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof: Vec<u8> = transcript.finalize();


}