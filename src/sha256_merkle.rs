use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::crh::sha256::constraints::{Sha256Gadget, UnitVar};
use ark_crypto_primitives::crh::sha256::digest::consts::U8;
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_bls12_381::Fr;
use ark_r1cs_std::prelude::UInt8;
use ark_r1cs_std::{R1CSVar, ToBytesGadget};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Field, Namespace};


use ark_std::rand::RngCore;

pub struct MerkleTree {
    pub nodes: Vec<Vec<u8>>,
}

#[derive(Clone)]
pub struct MerklePath {
    pub poof_nodes: Vec<Vec<u8>>,
    pub index_on_tree: u32,
}


impl MerkleTree {
    pub fn new(depth: u8) -> MerkleTree {
        println!("创建一棵深度{}的Merkle树：", depth);
        let unit = ();
        let mut rng = ark_std::test_rng();

        let mut leaf_count = 2u32.pow(depth as u32);
        let mut leafs = Vec::new();

        for i in 0..leaf_count {
            let mut leaf = vec![0u8; 32];
            rng.fill_bytes(&mut leaf);
            leafs.push(leaf);
        }
        println!("随机产生{}个叶子结点:{:?}", leaf_count, leafs);

        let mut nodes = Vec::new();
        for leaf in leafs {
            let h_leaf = <Sha256 as CRHScheme>::evaluate(&unit, leaf).unwrap();
            nodes.push(h_leaf);
        }
        nodes.extend(nodes.clone());
        for i in (3usize..2 * leaf_count as usize).step_by(2).rev() {
            let leaf_child = nodes.get(i - 1).unwrap();
            let right_child = nodes.get(i).unwrap();
            let father = <Sha256 as TwoToOneCRHScheme>::evaluate(&unit, leaf_child.clone(), right_child.clone()).unwrap();
            nodes[i / 2] = father.clone();
        }
        println!("创建Merkel树:");
        let mut endl = 1;
        for i in 1..nodes.len() {
            print!("{:?}", nodes[i]);
            if endl == i {
                print!("\n");
                endl += i + 1;
            } else {
                print!(",");
            }
        }

        MerkleTree { nodes }
    }

    pub fn get_root(&self) -> Vec<u8> {
        println!("获取根节点:{:?}", self.nodes[1].clone());
        return self.nodes[1].clone();
    }

    pub fn get_h_leaf(&self, index: usize) -> Vec<u8> {
        println!("获取第{}个叶子结点的hash值:{:?}", index, self.nodes[self.nodes.len() / 2 + index].clone());
        return self.nodes[self.nodes.len() / 2 + index].clone();
    }

    pub fn get_poof(&self, index: u32) -> MerklePath {
        let mut poof_nodes = Vec::new();
        let mut now = index + self.nodes.len() as u32 / 2u32;
        let index_on_tree = now.clone();
        while now > 1 {
            if now % 2 == 0 {
                poof_nodes.push(self.nodes[now as usize + 1].clone());
            } else {
                poof_nodes.push(self.nodes[now as usize - 1].clone());
            }
            now = now / 2;
        }
        println!("第{}个叶子结点的证明路径{:?}", index, poof_nodes);
        return MerklePath { poof_nodes, index_on_tree };
    }


    pub fn zk_verify(cs: ConstraintSystemRef<Fr>, root: Vec<u8>, h_leaf: Vec<u8>, poof: MerklePath) {
        let unit_var = UnitVar::default();
        let mut now = poof.index_on_tree;
        let mut hs = UInt8::new_witness_vec(cs.clone(), &h_leaf).unwrap();
        for node in poof.poof_nodes {
            if now % 2 == 0 {
                let h_right = UInt8::new_witness_vec(cs.clone(), &node).unwrap();
                let h_left = hs;
                let h_father = <Sha256Gadget<Fr> as TwoToOneCRHSchemeGadget<Sha256, Fr>>::evaluate(&unit_var, &h_left, &h_right).unwrap();
                hs = h_father.to_bytes().unwrap();
            } else {
                let h_left = UInt8::new_witness_vec(cs.clone(), &node).unwrap();
                let h_right = hs;
                let h_father = <Sha256Gadget<Fr> as TwoToOneCRHSchemeGadget<Sha256, Fr>>::evaluate(&unit_var, &h_left, &h_right).unwrap();
                hs = h_father.to_bytes().unwrap();
            }
            now /= 2;
        }
        println!("~~~~验证~~~~\nhash:{:?}\n与\nroot:{:?}\n~~~是否相等~~~", hs.value().unwrap().to_vec(), root.clone());
        assert_eq!(root, hs.value().unwrap().to_vec());
    }
}

#[test]
fn test_merkle_tree_success() {
    let _merkle_tree = MerkleTree::new(10);
    let cs = ConstraintSystem::<Fr>::new_ref();
    MerkleTree::zk_verify(cs.clone(), _merkle_tree.get_root().clone(), _merkle_tree.get_h_leaf(5).clone(), _merkle_tree.get_poof(5).clone());
    println!("验证成功\n约束：{}\n##################\n", cs.num_constraints());
}

#[test]
fn test_merkle_tree_failure() {
    let _merkle_tree = MerkleTree::new(10);
    let cs = ConstraintSystem::<Fr>::new_ref();
    MerkleTree::zk_verify(cs.clone(), _merkle_tree.get_root().clone(), _merkle_tree.get_h_leaf(4).clone(), _merkle_tree.get_poof(5).clone());
    println!("验证失败\n约束：{}\n##################\n", cs.num_constraints());
}
