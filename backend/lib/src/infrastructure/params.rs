use crate::common::*;
use crate::constants::*;
use crate::crypto::poseidon::HybridPoseidonCipher;
use crate::crypto::poseidon::HybridPoseidonParams;

use ark_crypto_primitives::{crh::{pedersen, injective_map::{PedersenCRHCompressor, TECompressor}, CRH, TwoToOneCRH}};
use ark_crypto_primitives::merkle_tree;
use ark_std::rand::Rng;

use super::record::ENC_RECORD_BYTES;


#[derive(Clone)]
pub struct InnerWindow;
impl pedersen::Window for InnerWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = FE_BYTES * 4;    // two field elements à 8*FE_BYTES bits, divided by 4 (window size)
}

#[derive(Clone)]
pub struct LeafWindow;
impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = ENC_RECORD_BYTES * 2;    // one record à 8*ENC_RECORD_BYTES bits, divided by 4 (window size)
}

pub type InnerHash = PedersenCRHCompressor<InnerEdProjective, TECompressor, InnerWindow>;
pub type LeafHash = PedersenCRHCompressor<InnerEdProjective, TECompressor, LeafWindow>;

#[derive(Clone)]
pub struct MerkleTreeParams;
impl merkle_tree::Config for MerkleTreeParams {
    type LeafHash = LeafHash;
    type TwoToOneHash = InnerHash;
}

#[derive(Clone)]
pub struct CryptoParams {
    pub leaf_hash_param: merkle_tree::LeafParam<MerkleTreeParams>,
    pub inner_hash_param: merkle_tree::TwoToOneParam<MerkleTreeParams>,
    pub enc_params: HybridPoseidonParams
}

impl CryptoParams {
    pub fn setup<R: Rng>(rng: &mut R) -> CryptoParams {
        CryptoParams {
            leaf_hash_param: <LeafHash as CRH>::setup(rng).unwrap(),
            inner_hash_param: <InnerHash as TwoToOneCRH>::setup(rng).unwrap(),
            enc_params: HybridPoseidonCipher::setup(rng),
        }
    }
}

#[derive(Clone)]
pub struct MerkleTreePath(pub merkle_tree::Path<MerkleTreeParams>);
impl Default for MerkleTreePath {
    fn default() -> Self {
        MerkleTreePath(merkle_tree::Path::<MerkleTreeParams> {
            leaf_sibling_hash: <LeafHash as CRH>::Output::default(),
            auth_path: vec![<InnerHash as CRH>::Output::default(); TREE_HEIGHT - 2],
            leaf_index: 0
        })
    }
}

#[derive(Clone,Debug,Eq,PartialEq,Default)]
pub struct MerkleTreeRoot(pub merkle_tree::TwoToOneDigest<MerkleTreeParams>);
