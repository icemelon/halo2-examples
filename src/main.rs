use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};
use halo2_proofs::{circuit::Value, dev::MockProver, pasta::Fp};
use halo2_examples::fibonacci::example1::MyCircuit;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Assigned, BatchVerifier, Circuit,
    Column, ConstraintSystem, Error, Fixed, SingleVerifier, TableColumn, VerificationStrategy,
};
use halo2_proofs::poly::{commitment::Params};
use halo2_proofs::pasta::{Eq, EqAffine};
use rand_core::OsRng;
use std::io::{self, Write};

fn main() {
    println!("Hello, world!");
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

    // public_input[2] += Fp::one();
    // let _prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
    // uncomment the following line and the assert will fail
    // _prover.assert_satisfied();
    println!("Bye, world!");

    const K: u32 = 5;
    // Initialize the polynomial commitment parameters
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
        &[&[&[public_input[0]]], &[&[public_input[1]]], &[&[public_input[2]]]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof: Vec<u8> = transcript.finalize();

    std::fs::write("plonk_api_proof.bin", &proof[..])
        .expect("should succeed to write new proof");

    io::stdout().write_all(&proof);

    // Check that a hardcoded proof is satisfied
    let proof = include_bytes!("../plonk_api_proof.bin");
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(verify_proof(
        &params,
        pk.get_vk(),
        strategy,
        &[&[&[public_input[0]]], &[&[public_input[1]]], &[&[public_input[2]]]],
        &mut transcript,
    )
    .is_ok());
}