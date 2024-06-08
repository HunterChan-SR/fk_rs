use ark_crypto_primitives::crh::poseidon::constraints::{CRHGadget, CRHParametersVar, TwoToOneCRHGadget};
use ark_crypto_primitives::crh::poseidon::{TwoToOneCRH, CRH};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::crh::{TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ed_on_bls12_381::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::{
    fields::fp::{AllocatedFp, FpVar},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Field, Namespace};
use ark_std::UniformRand;

pub struct MerkleTree {
    pub params: PoseidonConfig<Fr>,
    pub nodes: Vec<Fr>,
}

pub struct MerklePath {
    pub poof_nodes: Vec<Fr>,
    pub index_on_tree: u32,
}

impl MerkleTree {
    pub fn new(depth: u8) -> MerkleTree {
        println!("创建一棵深度{}的Merkle树：", depth);
        let mut test_rng = ark_std::test_rng();
        let mut mds = vec![vec![]; 3];
        for i in 0..3 {
            for _ in 0..3 {
                mds[i].push(Fr::rand(&mut test_rng));
            }
        }
        let mut ark = vec![vec![]; 8 + 24];
        for i in 0..8 + 24 {
            for _ in 0..3 {
                ark[i].push(Fr::rand(&mut test_rng));
            }
        }
        let params = PoseidonConfig::<Fr>::new(8, 24, 31, mds, ark, 2, 1);


        let mut leaf_count = 2u32.pow(depth as u32);
        let mut leafs = Vec::new();

        for i in 0..leaf_count {
            let mut leaf = Vec::new();
            // leaf.push(Fr::from(340282366920938463463374607431768211455u128));
            leaf.push(Fr::rand(&mut test_rng));
            leafs.push(leaf);
        }
        println!("随机产生{}个叶子结点:{:?}", leaf_count, leafs);


        let mut nodes = Vec::new();
        for leaf in leafs.clone() {
            let h_leaf = CRH::<Fr>::evaluate(&params, leaf.clone()).unwrap();
            nodes.push(h_leaf);
        }

        nodes.extend(nodes.clone());
        for i in (3usize..2 * leaf_count as usize).step_by(2).rev() {
            // println!("{}", i);
            let leaf_child = nodes.get(i - 1).unwrap();
            let right_child = nodes.get(i).unwrap();
            let father = TwoToOneCRH::<Fr>::compress(&params, leaf_child.clone(), right_child.clone()).unwrap();
            nodes[i / 2] = father;
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


        return MerkleTree { params, nodes };
    }

    pub fn get_root(&self) -> Fr {
        println!("获取根节点:{:?}", self.nodes[1]);
        return self.nodes[1];
    }
    pub fn get_h_leaf(&self, index: usize) -> Fr {
        println!("获取第{}个叶子结点的hash值:{:?}", index, self.nodes[self.nodes.len() / 2 + index]);
        return self.nodes[self.nodes.len() / 2 + index];
    }

    pub fn get_poof(&self, index: u32) -> MerklePath {
        let mut poof_nodes = Vec::new();
        let mut now = index + self.nodes.len() as u32 / 2u32;
        let index_on_tree = now.clone();
        while now > 1 {
            if now % 2 == 0 {
                poof_nodes.push(self.nodes[now as usize + 1]);
            } else {
                poof_nodes.push(self.nodes[now as usize - 1]);
            }
            now = now / 2;
        }
        println!("第{}个叶子结点的证明路径{:?}", index, poof_nodes);
        return MerklePath { poof_nodes, index_on_tree };
    }

    pub fn zk_verify(cs: ConstraintSystemRef<Fr>, params: PoseidonConfig<Fr>, root: Fr, h_leaf: Fr, poof: MerklePath) {
        let params_g = CRHParametersVar::<Fr>::new_witness(cs.clone(), || Ok(params)).unwrap();
        let mut now = poof.index_on_tree;
        let mut hs = FpVar::<Fr>::new_witness(cs.clone(), || Ok(h_leaf)).unwrap();
        for node in poof.poof_nodes {
            if now % 2 == 0 {
                let h_right = FpVar::<Fr>::new_witness(cs.clone(), || Ok(node)).unwrap();
                let h_left = hs;
                let h_father = TwoToOneCRHGadget::<Fr>::compress(&params_g, &h_left, &h_right).unwrap();
                hs = h_father;
            } else {
                let h_left = FpVar::<Fr>::new_witness(cs.clone(), || Ok(node)).unwrap();
                let h_right = hs;
                let h_father = TwoToOneCRHGadget::<Fr>::compress(&params_g, &h_left, &h_right).unwrap();
                hs = h_father;
            }
            now /= 2;
        }
        println!("~~~~验证~~~~\nhash:{:?}\n与\nroot:{:?}\n~~~是否相等~~~", hs.value().unwrap(), root);
        assert_eq!(root, hs.value().unwrap());
    }
}

#[test]
fn test_merkle_tree_success() {
    let _merkle_tree = MerkleTree::new(10);
    let cs = ConstraintSystem::<Fr>::new_ref();
    MerkleTree::zk_verify(cs.clone(), _merkle_tree.params.clone(), _merkle_tree.get_root(), _merkle_tree.get_h_leaf(5), _merkle_tree.get_poof(5));
    println!("验证成功\n约束：{}\n##################\n", cs.num_constraints());
}

#[test]
fn test_merkle_tree_failure() {
    let _merkle_tree = MerkleTree::new(10);
    let cs = ConstraintSystem::<Fr>::new_ref();
    MerkleTree::zk_verify(cs.clone(), _merkle_tree.params.clone(), _merkle_tree.get_root(), _merkle_tree.get_h_leaf(4), _merkle_tree.get_poof(5));
    println!("验证失败\n约束：{}\n##################\n", cs.num_constraints());
}



