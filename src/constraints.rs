use ark_relations::r1cs::{SynthesisError, ConstraintSynthesizer, ConstraintSystemRef, ConstraintSystem};
use crate::sha256_merkle::{MerklePath, MerkleTree};
use std::time::Instant;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use rand::{rngs::StdRng, SeedableRng};
use ark_bls12_381::{Bls12_381, Fr, FrConfig};
use ark_crypto_primitives::crh::CRHScheme;


#[derive(Clone)]
pub struct Circuit {
    root: Vec<u8>,
    h_leaf: Vec<u8>,
    poof: MerklePath,
}

impl ConstraintSynthesizer<Fr> for Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        MerkleTree::zk_verify(cs.clone(), self.root, self.h_leaf, self.poof);
        Ok(())
    }
}

#[test]
fn test() {
    let depth = 10;
    let index = 5;

    let _merkle_tree = MerkleTree::new(depth);
    let cs = ConstraintSystem::<Fr>::new_ref();
    let mut rng: StdRng = StdRng::from_entropy();

    let init_circuit = Circuit {
        root: Vec::new(),
        h_leaf: Vec::new(),
        poof: MerklePath {
            poof_nodes: Vec::new(),
            index_on_tree: 0,
        },
    };

    let start = Instant::now();
    let (pk, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(init_circuit.clone(), &mut rng).unwrap();
    let setup_time = start.elapsed();


    let circuit = Circuit {
        root: _merkle_tree.get_root().clone(),
        h_leaf: _merkle_tree.get_h_leaf(index).clone(),
        poof: _merkle_tree.get_poof(index as u32).clone(),
    };


    let start = Instant::now();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).unwrap();
    let prove_time = start.elapsed();


    let public_input = vec![];
    let start = Instant::now();
    let valid_proof = Groth16::<Bls12_381>::verify(&vk, &public_input, &proof).unwrap();
    let verify_time = start.elapsed();

    println!("setup time: {:?}", setup_time);
    println!("prove time: {:?}", prove_time);
    println!("verify time: {:?}", verify_time);
    assert!(valid_proof);
}