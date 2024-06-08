// use ark_relations::r1cs::{SynthesisError, ConstraintSynthesizer, ConstraintSystemRef, ConstraintSystem};
// use crate::sha256_merkle::{MerklePath, MerkleTree};
// use ark_ed_on_bls12_381::{Fr};
// use std::time::Instant;
// use ark_crypto_primitives::snark::SNARK;
// use ark_groth16;
// use rand::{rngs::StdRng, SeedableRng};
//
// #[derive(Clone)]
// pub struct Circuit {
//     pub root: Vec<u8>,
//     pub h_leaf: Vec<u8>,
//     pub poof: MerklePath,
// }
//
// impl ConstraintSynthesizer<Fr> for Circuit {
//     fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
//         MerkleTree::zk_verify(cs.clone(), self.root, self.h_leaf, self.poof);
//         Ok(())
//     }
// }
//
// #[test]
// fn test() {
//     let depth = 10;
//
//     let _merkle_tree = MerkleTree::new(depth);
//     let cs = ConstraintSystem::<Fr>::new_ref();
//     let mut rng: StdRng = StdRng::from_entropy();
//
//     let circuit = Circuit {
//         root: _merkle_tree.get_root(),
//         h_leaf: _merkle_tree.get_h_leaf(5),
//         poof: _merkle_tree.get_poof(5),
//     };
//
//     let start = Instant::now();
//     ark_groth16::generator::
    // let (pk, vk) =
    //     Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
    // println!("setup time: {:?}", start.elapsed());


    // let public_input = vec![Fr::from(_merkle_tree.get_root())];
// }