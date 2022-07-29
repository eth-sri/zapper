use ark_std::cell::{Ref, RefCell};
use ark_std::rc::Rc;
use ark_std::collections::BTreeMap;
use ark_crypto_primitives::{merkle_tree, CRH, crh::TwoToOneCRH};
use ark_ff::ToBytes;

#[derive(Clone)]
struct NodePtr<P: Clone + merkle_tree::Config>(Rc<RefCell<Node<P>>>);

impl<P: Clone + merkle_tree::Config> NodePtr<P> {
    pub fn borrow(&self) -> Ref<Node<P>> {
        return self.0.borrow();
    }

    pub fn new(node: Node<P>) -> NodePtr<P> {
        NodePtr(Rc::new(RefCell::new(node)))
    }
}

enum NodeData<P: Clone + merkle_tree::Config> {
    Inner(merkle_tree::TwoToOneDigest<P>),
    Leaf(merkle_tree::LeafDigest<P>)
}

struct Node<P: Clone + merkle_tree::Config> {
    data: NodeData<P>,
    left_child: Option<NodePtr<P>>,
    right_child: Option<NodePtr<P>>
}

impl<P: Clone + merkle_tree::Config> Node<P> {
    pub fn new_leaf(hash: merkle_tree::LeafDigest<P>) -> Node<P> {
        Node {
            data: NodeData::Leaf(hash),
            left_child: None,
            right_child: None
        }
    }

    pub fn new_internal(hash: merkle_tree::TwoToOneDigest<P>, left: NodePtr<P>, right: NodePtr<P>) -> Node<P> {
        Node {
            data: NodeData::Inner(hash),
            left_child: Some(left),
            right_child: Some(right)
        }
    }

    pub fn get_left(&self) -> Ref<Node<P>> {
        self.left_child.as_ref().unwrap().borrow()
    }

    pub fn get_right(&self) -> Ref<Node<P>> {
        self.right_child.as_ref().unwrap().borrow()
    }

    pub fn try_get_leaf_hash(&self) -> Option<merkle_tree::LeafDigest<P>> {
        match &self.data {
            NodeData::Leaf(hash) => Some(hash.clone()),
            _ => None
        }
    }

    pub fn try_get_inner_hash(&self) -> Option<merkle_tree::TwoToOneDigest<P>> {
        match &self.data {
            NodeData::Inner(hash) => Some(hash.clone()),
            _ => None
        }
    }
}

struct SparseMerkleTreePath<P: Clone + merkle_tree::Config> {
    pub is_left: Vec<bool>,
    pub nodes: Vec<NodePtr<P>>
}

pub struct SparseMerkleTree<P: Clone + merkle_tree::Config> {
    height: usize,
    root: NodePtr<P>,
    leaves: BTreeMap<u128, NodePtr<P>>,
    leaf_hash_param: merkle_tree::LeafParam<P>,
    inner_hash_param: merkle_tree::TwoToOneParam<P>
}

impl<P: Clone + merkle_tree::Config> SparseMerkleTree<P> {
    /// Creates a new empty merkle tree of the specified height (can store 2^(height-1) leafs)
    pub fn new(leaf_hash_param: &merkle_tree::LeafParam<P>,
               inner_hash_param: &merkle_tree::TwoToOneParam<P>,
               height: usize) -> SparseMerkleTree<P> {
        assert!(height >= 2, "height must be at least 2");

        // create empty leaf
        let empty_leaf_hash = P::LeafHash::evaluate(leaf_hash_param, &vec![0u8; P::LeafHash::INPUT_SIZE_BITS / 8]).unwrap();
        let empty_leaf = NodePtr::new(Node::new_leaf(empty_leaf_hash.clone()));
        let mut cur = empty_leaf.clone();

        // create bottom layer internal node
        let hash: merkle_tree::TwoToOneDigest<P> = P::TwoToOneHash::evaluate(
            inner_hash_param,
            &ark_ff::to_bytes!(&empty_leaf_hash).unwrap(),
            &ark_ff::to_bytes!(&empty_leaf_hash).unwrap()
        ).unwrap();
        let next = NodePtr::new(Node::new_internal(hash.clone(), cur.clone(), cur.clone()));
        cur = next;

        // create remaining internal nodes
        let mut prev_hash = hash;
        for _ in 2..height {
            prev_hash = P::TwoToOneHash::evaluate(
                inner_hash_param,
                &ark_ff::to_bytes!(&prev_hash).unwrap(),
                &ark_ff::to_bytes!(&prev_hash).unwrap()
            ).unwrap();
            let next = NodePtr::new(Node::new_internal(prev_hash.clone(), cur.clone(), cur.clone()));
            cur = next;
        }

        SparseMerkleTree {
            height: height,
            root: cur,
            leaves: BTreeMap::new(),
            leaf_hash_param: leaf_hash_param.clone(),
            inner_hash_param: inner_hash_param.clone()
        }
    }

    /// Updates leaf at position `idx` with `new_leaf_data`
    pub fn update<L: ToBytes>(&mut self, idx: u128, new_leaf_data: &L) {
        assert!(idx < (1 << self.height-1), "index too large for tree height");

        // create new leaf
        let new_leaf_hash = P::LeafHash::evaluate(&self.leaf_hash_param, &ark_ff::to_bytes!(&new_leaf_data).unwrap()).unwrap();
        let mut cur = NodePtr::new(Node::new_leaf(new_leaf_hash.clone()));
        self.leaves.insert(idx, cur.clone());

        // find position in tree
        let path = self.get_path(idx);

        // update bottom layer internal node
        let mut prev_hash;
        let original = &path.nodes[path.is_left.len() - 1];
        if path.is_left[path.is_left.len() - 1] {
            let right_hash = original.borrow().get_right().try_get_leaf_hash().expect("malformed node");
            prev_hash = P::TwoToOneHash::evaluate(
                &self.inner_hash_param,
                &ark_ff::to_bytes!(&new_leaf_hash).unwrap(),
                &ark_ff::to_bytes!(&right_hash).unwrap()
            ).unwrap();
            cur = NodePtr::new(Node::new_internal(prev_hash.clone(), cur.clone(), original.borrow().right_child.as_ref().unwrap().clone()));
        } else {
            let left_hash = original.borrow().get_left().try_get_leaf_hash().expect("malformed node");
            prev_hash = P::TwoToOneHash::evaluate(
                &self.inner_hash_param,
                &ark_ff::to_bytes!(&left_hash).unwrap(),
                &ark_ff::to_bytes!(&new_leaf_hash).unwrap()
            ).unwrap();
            cur = NodePtr::new(Node::new_internal(prev_hash.clone(), original.borrow().left_child.as_ref().unwrap().clone(), cur.clone()));
        }

        // update remaining internal nodes
        if self.height > 2 {
            let mut i = path.is_left.len() - 2;
            loop {
                let original = &path.nodes[i];
                if path.is_left[i] {
                    let right_hash = original.borrow().get_right().try_get_inner_hash().expect("malformed node");
                    prev_hash = P::TwoToOneHash::evaluate(
                        &self.inner_hash_param,
                        &ark_ff::to_bytes!(&prev_hash.clone()).unwrap(),
                        &ark_ff::to_bytes!(&right_hash).unwrap()
                    ).unwrap();
                    cur = NodePtr::new(Node::new_internal(prev_hash.clone(), cur.clone(), original.borrow().right_child.as_ref().unwrap().clone()));
                } else {
                    let left_hash = original.borrow().get_left().try_get_inner_hash().expect("malformed node");
                    prev_hash = P::TwoToOneHash::evaluate(
                        &self.inner_hash_param,
                        &ark_ff::to_bytes!(&left_hash).unwrap(),
                        &ark_ff::to_bytes!(&prev_hash.clone()).unwrap()
                    ).unwrap();
                    cur = NodePtr::new(Node::new_internal(prev_hash.clone(), original.borrow().left_child.as_ref().unwrap().clone(), cur.clone()));
                }
                if i == 0 { break; }
                i -= 1;
            }
        }
        self.root = cur;
    }

    /// Returns the root hash of the Merkle tree.
    pub fn root(&self) -> merkle_tree::TwoToOneDigest<P> {
        self.root.borrow().try_get_inner_hash().expect("malformed root")
    }

    /// Returns the height of the Merkle tree
    pub fn height(&self) -> usize {
        self.height
    }

    /// Returns the authentication path from root to leaf at position `idx`.
    /// Currently only supports usize indices due to `merkle_tree::Path`.
    pub fn generate_proof(&self, idx: usize) -> merkle_tree::Path<P> {
        let path = self.get_path(idx as u128);
        let lowest_inner_node = path.nodes[path.nodes.len() - 2].borrow();
        let leaf_sibling_node = if path.is_left[path.nodes.len() - 2] {
            lowest_inner_node.right_child.as_ref().unwrap()
        } else {
            lowest_inner_node.left_child.as_ref().unwrap()
        };
        let leaf_sibling_hash = leaf_sibling_node.borrow().try_get_leaf_hash().expect("malformed leaf node");

        // auth_path.len() = `self.height - 2`, the two missing elements being the leaf sibling hash and the root
        let mut auth_path = Vec::with_capacity(self.height - 2);
        for i in 0..path.nodes.len()-2 {
            let node = path.nodes[i].borrow();
            let sibling_node = if path.is_left[i] {
                node.right_child.as_ref().unwrap()
            } else {
                node.left_child.as_ref().unwrap()
            };
            let sibling_hash = sibling_node.borrow().try_get_inner_hash().expect("malformed inner node");
            auth_path.push(sibling_hash);
        }

        merkle_tree::Path {
            leaf_index: idx,
            auth_path: auth_path,
            leaf_sibling_hash
        }
    }

    /// For the leaf at position `idx`, returns the path starting at the root and leading to the leaf.
    fn get_path(&self, idx: u128) -> SparseMerkleTreePath<P> {
        let mut path = SparseMerkleTreePath {
            is_left: vec![],
            nodes: vec![]
        };
        let mut cur = self.root.clone();
        path.nodes.push(cur.clone());
        for level in 0..self.height - 1 {
            let nof_leaves_at_level = 1 << (self.height - 1 - level);
            let is_left = (idx % nof_leaves_at_level) < (nof_leaves_at_level >> 1);
            let node = if is_left { cur.borrow().left_child.as_ref().unwrap().clone() } else { cur.borrow().right_child.as_ref().unwrap().clone() };
            path.is_left.push(is_left);
            path.nodes.push(node.clone());
            cur = node;
        }
        path
    }
}

#[cfg(test)]
mod tests {
    use super::SparseMerkleTree;
    use ark_crypto_primitives::{
        crh::{pedersen, *},
        merkle_tree::*,
    };
    use ark_ed_on_bls12_381::EdwardsProjective;
    use ark_std::{test_rng, UniformRand};

    #[derive(Clone)]
    pub struct Window;
    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 384;
    }

    type H = pedersen::CRH<EdwardsProjective, Window>;

    #[derive(Clone)]
    struct MerkleTreeParams;
    impl Config for MerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;
    }

    fn create_blank_trees(height: usize) -> (MerkleTree<MerkleTreeParams>, SparseMerkleTree<MerkleTreeParams>) {
        let mut rng = test_rng();
        let leaf_hash_param = <H as CRH>::setup(&mut rng).unwrap();
        let inner_hash_param = <H as TwoToOneCRH>::setup(&mut rng).unwrap();

        let dense_tree = MerkleTree::<MerkleTreeParams>::blank(&leaf_hash_param, &inner_hash_param, height).unwrap();
        let sparse_tree = SparseMerkleTree::<MerkleTreeParams>::new(&leaf_hash_param, &inner_hash_param, height);

        (dense_tree, sparse_tree)
    }

    #[test]
    fn empty_tree_test() {
        let (dense_tree, sparse_tree) = create_blank_trees(2);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        let (dense_tree, sparse_tree) = create_blank_trees(3);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        let (dense_tree, sparse_tree) = create_blank_trees(8);
        assert_eq!(dense_tree.root(), sparse_tree.root());
    }

    #[test]
    fn insertion_test() {
        let mut rng = test_rng();

        // smallest possible tree (height 2)
        let (mut dense_tree, mut sparse_tree) = create_blank_trees(2);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(0, &new_leaf).unwrap();
        sparse_tree.update(0, &new_leaf);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(1, &new_leaf).unwrap();
        sparse_tree.update(1, &new_leaf);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        // minimal complete tree (height 3)
        let (mut dense_tree, mut sparse_tree) = create_blank_trees(3);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(0, &new_leaf).unwrap();
        sparse_tree.update(0, &new_leaf);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(1, &new_leaf).unwrap();
        sparse_tree.update(1, &new_leaf);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(2, &new_leaf).unwrap();
        sparse_tree.update(2, &new_leaf);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(3, &new_leaf).unwrap();
        sparse_tree.update(3, &new_leaf);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        // large tree (height 9)
        // minimal complete tree (height 3)
        let (mut dense_tree, mut sparse_tree) = create_blank_trees(9);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(164, &new_leaf).unwrap();
        sparse_tree.update(164, &new_leaf);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(19, &new_leaf).unwrap();
        sparse_tree.update(19, &new_leaf);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(201, &new_leaf).unwrap();
        sparse_tree.update(201, &new_leaf);
        assert_eq!(dense_tree.root(), sparse_tree.root());

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(40, &new_leaf).unwrap();
        sparse_tree.update(40, &new_leaf);
        assert_eq!(dense_tree.root(), sparse_tree.root());
    }

    #[test]
    fn proof_generation_test() {
        let mut rng = test_rng();

        let (mut dense_tree, mut sparse_tree) = create_blank_trees(9);

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(164, &new_leaf).unwrap();
        sparse_tree.update(164, &new_leaf);

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(19, &new_leaf).unwrap();
        sparse_tree.update(19, &new_leaf);

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(201, &new_leaf).unwrap();
        sparse_tree.update(201, &new_leaf);

        let new_leaf = EdwardsProjective::rand(&mut rng);
        dense_tree.update(40, &new_leaf).unwrap();
        sparse_tree.update(40, &new_leaf);

        let dense_proof = dense_tree.generate_proof(164).unwrap();
        let sparse_proof = sparse_tree.generate_proof(164);
        assert_eq!(dense_proof.auth_path, sparse_proof.auth_path);
        assert_eq!(dense_proof.leaf_sibling_hash, sparse_proof.leaf_sibling_hash);
        assert_eq!(dense_proof.leaf_index, sparse_proof.leaf_index);

        let dense_proof = dense_tree.generate_proof(165).unwrap();
        let sparse_proof = sparse_tree.generate_proof(165);
        assert_eq!(dense_proof.auth_path, sparse_proof.auth_path);
        assert_eq!(dense_proof.leaf_sibling_hash, sparse_proof.leaf_sibling_hash);
        assert_eq!(dense_proof.leaf_index, sparse_proof.leaf_index);

        let dense_proof = dense_tree.generate_proof(57).unwrap();
        let sparse_proof = sparse_tree.generate_proof(57);
        assert_eq!(dense_proof.auth_path, sparse_proof.auth_path);
        assert_eq!(dense_proof.leaf_sibling_hash, sparse_proof.leaf_sibling_hash);
        assert_eq!(dense_proof.leaf_index, sparse_proof.leaf_index);
    }
}