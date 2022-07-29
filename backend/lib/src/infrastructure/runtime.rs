use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::rc::Rc;
use ark_crypto_primitives::encryption::elgamal::SecretKey;
use ark_ff::to_bytes;
use ark_gm17::ProvingKey;
use ark_std::UniformRand;
use ark_std::Zero;
use log::debug;
use rand::{Rng, CryptoRng};
use crate::crypto::elgamal_ext::derive_pk_from_sk;
use crate::crypto::sparse_merkle_tree::SparseMerkleTree;
use crate::infrastructure::identities::Identity;

use crate::common::*;
use crate::constants::*;
use crate::crypto::elgamal_ext::ExtSecretKey;
use crate::infrastructure::record::*;
use crate::infrastructure::params::{MerkleTreePath, MerkleTreeRoot};
use crate::infrastructure::derivations::*;
use crate::time_measure;

use super::circuit::{generate_main_proof, MainProof};
use super::params::{CryptoParams, MerkleTreeParams};
use super::processor::{ZkInstruction, ZkProcessor, ZkProcessorPartialState, ZkProcessorState};

pub struct InRecordContext {
    /// secret key used to decrypt input record
    pub sk: ExtSecretKey<InnerEdProjective>,
    /// serialized form of `sk`
    pub sk_serialized: [u8; SERIALIZED_SK_BYTES],
    /// randomness used to derive in_sn_nonce for dummy inputs
    pub rand_dummy_sn_nonce: [u8; RAND_BYTES],
    /// serial number of input record
    pub sn: Serial,
    /// plaintext input record
    pub plaintext: Record,
    /// encrypted input record
    pub encrypted: EncryptedRecord,
    /// the merkle tree path for the input record
    pub path: MerkleTreePath,
}

impl InRecordContext {
    pub fn derive_and_set_serial(&mut self)  {
        let serial_nonce = self.plaintext.serial_nonce;
        self.sn = derive_sn_from_nonce(&serial_nonce, &self.sk_serialized);
    }
}

impl Default for InRecordContext {
    fn default() -> Self {
        Self {
            sk: Default::default(),
            sk_serialized: [0u8; SERIALIZED_SK_BYTES],
            rand_dummy_sn_nonce: [0u8; RAND_BYTES],
            sn: Default::default(),
            plaintext: Default::default(),  // this is a dummy record by default
            encrypted: Default::default(),
            path: Default::default()
        }
    }
}

pub struct OutRecordContext {
    /// plaintext output record
    pub plaintext: Record,
    /// encrypted output record
    pub encrypted: EncryptedRecord,
    /// public key used to encrypt output record
    pub pk_owner: InnerEdAffine,
    /// randomness used to encrypt output record
    pub rand_encryption: EncRandomness,
    /// randomness used to derive out_sn_nonce
    pub rand_sn_nonce: [u8; RAND_BYTES],
}

impl Default for OutRecordContext {
    fn default() -> Self {
        Self {
            plaintext: Default::default(),  // this is a dummy record by default
            encrypted: Default::default(),
            pk_owner: InnerEdAffine::default(),
            rand_encryption: Default::default(),
            rand_sn_nonce: Default::default()
        }
    }
}

pub struct ProofContext {
    /// the merkle tree path root indicating the state on which this transaction is based
    pub merkle_root: MerkleTreeRoot,

    /// the address of the transaction sender
    pub sender_address: OuterScalarField,
    /// the serialized secret key of the transaction sender
    pub sender_sk_bytes: [u8; FE_BYTES],

    /// the unique seed used to derive random values
    pub unique_seed: [u8; RAND_BYTES],

    /// data of input records
    pub in_records: [InRecordContext; NOF_TX_RECORDS],
    /// data of output record
    pub out_records: [OutRecordContext; NOF_TX_RECORDS],

    /// class id of called class
    pub called_class_id: OuterScalarField,
    /// function id of called function,
    pub called_function_id: OuterScalarField,
    /// the instructions executed by the processor
    pub processor_instructions: [ZkInstruction; NOF_PROCESSOR_CYCLES],
    /// the current time for the processor
    pub processor_current_time: OuterScalarField,
    /// the intermediate states of the processor
    pub processor_states: [ZkProcessorState; NOF_PROCESSOR_CYCLES + 1],

    /// randomness used to derive fresh object ids
    pub rand_oid: [[u8; RAND_BYTES]; NOF_TX_FRESH],
    /// randomness used to derive fresh object secret keys
    pub rand_sk: [[u8; RAND_BYTES]; NOF_TX_FRESH],
    /// randomness used to derive unique values
    pub rand_fresh_vals: [[u8; RAND_BYTES]; NOF_TX_FRESH],

    /// parameters used for the cryptographic primitives
    pub crypto_params: CryptoParams,
}

impl ProofContext {
    pub fn default_with_params(params: CryptoParams) -> ProofContext {
        // NOTE: this function must initialize the proof context with the correct sizes, as it is used for the circuit setup phase
        ProofContext {
            merkle_root: Default::default(),
            sender_address: Default::default(),
            sender_sk_bytes: [0u8; FE_BYTES],
            unique_seed: Default::default(),
            in_records: Default::default(),
            out_records: Default::default(),
            called_class_id: Default::default(),
            called_function_id: Default::default(),
            processor_instructions: [(); NOF_PROCESSOR_CYCLES].map(|_| ZkInstruction::default()),
            processor_current_time: Default::default(),
            processor_states: [(); NOF_PROCESSOR_CYCLES + 1].map(|_| ZkProcessorState::default()),
            rand_oid: Default::default(),
            rand_sk: Default::default(),
            rand_fresh_vals: Default::default(),
            crypto_params: params
        }
    }

    pub fn new<R: Rng>(rng: &mut R,
               merkle_root: MerkleTreeRoot,
               crypto_params: CryptoParams,
               sender_address: OuterScalarField
    ) -> ProofContext {    
        // prepare proof context
        let mut ctx = ProofContext::default_with_params(crypto_params);
        ctx.merkle_root = merkle_root;
        ctx.sender_address = sender_address;

        // set random unique seed
        rng.fill_bytes(&mut ctx.unique_seed);

        // set serial nonce and serial number for dummy inputs
        for (idx, rec) in ctx.in_records.iter_mut().enumerate() {
            let dummy_nonce;
            loop {
                rng.fill_bytes(&mut rec.rand_dummy_sn_nonce);
                let sn_nonce = try_derive_fresh_sn_nonce(&rec.rand_dummy_sn_nonce, (idx + NOF_TX_RECORDS) as u8, &ctx.unique_seed);
                if let Some(sn_nonce) = sn_nonce {
                    dummy_nonce = sn_nonce;
                    break;
                }
            }
            rec.plaintext.serial_nonce = dummy_nonce;
            rec.derive_and_set_serial();
        }
        ctx
    }

    pub fn set_input_and_decrypt(&mut self, idx: usize, sk: ExtSecretKey<InnerEdProjective>, encrypted: EncryptedRecord, path: MerkleTreePath) {
        let rec = &mut self.in_records[idx];
        rec.sk_serialized.copy_from_slice(to_bytes!(sk).unwrap().as_slice());
        rec.sk = sk;
        rec.encrypted = encrypted.clone();
        rec.plaintext = Record::decrypt(&encrypted, &rec.sk, &self.crypto_params.enc_params).unwrap();
        rec.path = path;
        rec.derive_and_set_serial();
    }

    fn set_output_and_encrypt<R: Rng>(&mut self, rng: &mut R, idx: usize, mut out_record: Record) -> EncryptedRecord {
        let rec = &mut self.out_records[idx];

        loop {
            rng.fill_bytes(&mut rec.rand_sn_nonce);
            let sn_nonce = try_derive_fresh_sn_nonce(&rec.rand_sn_nonce, idx as u8, &self.unique_seed);
            if let Some(sn_nonce) = sn_nonce {
                out_record.serial_nonce = sn_nonce;
                break;
            }
        }

        rec.pk_owner = get_pk_for_addr(&out_record.addr_owner);
        let res = out_record.encrypt(&rec.pk_owner, &self.crypto_params.enc_params, rng);
        rec.plaintext = out_record;
        rec.encrypted = res.0;
        rec.rand_encryption = res.1;
        rec.encrypted.clone()
    }

    /// derives fresh object ids, secret keys, addresses, and values. Returns a triple (fresh_oids, fresh_obj_sks, fresh_obj_addrs, fresh_vals).
    pub fn derive_fresh_values<R: Rng>(&mut self, rng: &mut R) -> (Vec<OuterScalarField>, Vec<OuterScalarField>, Vec<OuterScalarField>, Vec<OuterScalarField>) {
        let mut fresh_oids = vec![];
        for i in 0..NOF_TX_FRESH {
            loop {
                rng.fill_bytes(&mut self.rand_oid[i]);
                let oid = try_derive_fresh_object_id(&self.rand_oid[i], i as u8, &self.unique_seed);
                if let Some(oid) = oid {
                    fresh_oids.push(oid);
                    break;
                }
            }
        }

        let mut fresh_obj_sks = vec![];
        let mut fresh_obj_addrs = vec![];
        for i in 0..NOF_TX_FRESH {
            let (rand, sk) = derive_fresh_object_sk(rng, &self.crypto_params, i as u8, &self.unique_seed);
            self.rand_sk[i] = rand;
            let pk = derive_pk_from_sk(&self.crypto_params.enc_params.elgamal_params, &SecretKey(sk));
            let addr = get_addr_for_pk(&pk);
            fresh_obj_sks.push(FeConverter::to_larger(&sk));
            fresh_obj_addrs.push(addr);
        }

        let mut fresh_vals = vec![];
        for i in 0..NOF_TX_FRESH {
            loop {
                rng.fill_bytes(&mut self.rand_fresh_vals[i]);
                let fresh = try_derive_fresh_value(&self.rand_fresh_vals[i], i as u8, &self.unique_seed);
                if let Some(fresh) = fresh {
                    fresh_vals.push(fresh);
                    break;
                }
            }
        }

        (fresh_oids, fresh_obj_sks, fresh_obj_addrs, fresh_vals)
    }
}

pub struct ObjectInfo {
    /// The leaf index of this object in the state Merkle tree
    pub leaf_idx: usize,

    /// The identity of this object's owner
    pub owner_identity: Rc<Identity>,

    /// The serial number of this object
    pub serial_number: Serial
}

pub struct RuntimeStateView {
    /// The crypto parameters to be used in this runtime.
    crypto_params: CryptoParams,

    /// The number of transactions synced so far
    pub nof_synced_tx: usize,

    /// A local copy of the remote ledger Merkle tree
    pub merkle_tree: SparseMerkleTree<MerkleTreeParams>,

    /// Mapping of Merkle tree leaf indices to leaf data
    pub tree_leaves: BTreeMap<usize, EncryptedRecord>,
    
    /// Mapping object ids to object information for all known objects
    pub known_objects: BTreeMap<ObjectId, ObjectInfo>,
}

impl RuntimeStateView {
    pub fn new(crypto_params: CryptoParams) -> RuntimeStateView {
        let tree = SparseMerkleTree::new(&crypto_params.leaf_hash_param, &crypto_params.inner_hash_param, TREE_HEIGHT);

        RuntimeStateView {
            crypto_params,
            nof_synced_tx: 0,
            merkle_tree: tree,
            tree_leaves: BTreeMap::new(),
            known_objects: BTreeMap::new()
        }
    }

    pub fn get_enc_record_with_path_and_sk(&self, oid: &ObjectId) -> Result<(EncryptedRecord, MerkleTreePath, ExtSecretKey<InnerEdProjective>), ()> {
        assert!(!oid.is_zero());
        let info = self.known_objects.get(oid).ok_or(())?;
        let owner_sk = info.owner_identity.secret_key.clone();
        let enc_record = self.tree_leaves.get(&info.leaf_idx).unwrap();
        let path = self.merkle_tree.generate_proof(info.leaf_idx);
        Ok((enc_record.clone(), MerkleTreePath(path), owner_sk))
    }

    pub fn get_record_for_oid(&self, oid: &ObjectId) -> Result<Record, ()> {
        assert!(!oid.is_zero());
        let info = self.known_objects.get(oid).ok_or(())?;
        let owner = &info.owner_identity;
        let enc_record = self.tree_leaves.get(&info.leaf_idx).unwrap();
        let record = Record::decrypt(&enc_record, &owner.secret_key, &self.crypto_params.enc_params).unwrap();
        assert_eq!(&record.object_id, oid);
        Ok(record)
    }

    pub fn get_root(&self) -> MerkleTreeRoot {
        MerkleTreeRoot(self.merkle_tree.root())
    }
}

pub struct ExecutionResult {
    /// the merkle tree root of the state containing the consumed records
    pub merkle_tree_root: MerkleTreeRoot,

    /// the current timestamp used for the transaction,
    pub current_time: OuterScalarField,

    /// the consumed serial numbers
    pub consumed_serials: Vec<Serial>,

    /// the created new records
    pub new_records: Vec<EncryptedRecord>,

    /// the correctness proof (can set to None for debugging purposes, in which case proofs are not verified)
    pub proof: Option<MainProof>,

    /// a unique seed used to derive fresh values
    pub unique_seed: [u8; RAND_BYTES],

    /// the return value of the top-level function call
    pub return_value: OuterScalarField
}

pub struct Runtime<R: Rng + CryptoRng> {
    /// the crypto parameters to be used in this runtime
    pub crypto_params: CryptoParams,

    /// a random number generator to be used for all random choices
    pub rand: RefCell<R>,

    /// a mirror of the on-chain ledger state, to be synced by using `sync_tx`
    pub ledger_state_view: Rc<RefCell<RuntimeStateView>>,

    /// maps addresses to known identities
    pub identities: BTreeMap<OuterScalarField, Rc<Identity>>,

    /// The outer prover key to be used in this runtime.
    /// Can be set to `None` for debugging purposes, in which case proofs are not generated.
    pub proving_key: Option<ProvingKey<OuterPairing>>
}

impl<R: Rng + CryptoRng> Runtime<R> {
    /// creates a new runtime for the given parameters, proving key (`None` for debugging purposes) and random number generator
    pub fn new(crypto_params: CryptoParams, proving_key: Option<ProvingKey<OuterPairing>>, rand: RefCell<R>) -> Runtime<R> {
        Runtime {
            crypto_params: crypto_params.clone(),
            rand,
            ledger_state_view: Rc::new(RefCell::new(RuntimeStateView::new(crypto_params))),
            identities: BTreeMap::new(),
            proving_key
        }
    }

    /// returns the number of transactions that have been synced so far
    pub fn get_nof_synced_tx(&self) -> usize {
        self.ledger_state_view.borrow().nof_synced_tx
    }

    /// Synchronizes the local mirror of the ledger state using the given transaction.
    /// The transaction index `tx_idx` must not be larger than the return value of `get_nof_synced_tx()`.
    pub fn sync_tx(&mut self, tx_idx: usize, published_serials: &[Serial], published_records: &[EncryptedRecord]) {
        let nof_synced = self.get_nof_synced_tx();
        if tx_idx == nof_synced {
            debug!("synchronizing transaction index {}", tx_idx);
            for serial in published_serials.iter() {
                self.try_recognize_published_serial(serial);
            }
            let mut idx_and_records = vec![];
            for enc_record in published_records {
                let leaf_idx = self.ledger_state_view.borrow().tree_leaves.len();
                self.ledger_state_view.borrow_mut().merkle_tree.update(leaf_idx as u128, enc_record);
                self.ledger_state_view.borrow_mut().tree_leaves.insert(leaf_idx, enc_record.clone());
                idx_and_records.push((leaf_idx, enc_record.clone()));
            }
            self.try_recognize_enc_records(idx_and_records);
            self.ledger_state_view.borrow_mut().nof_synced_tx += 1;
        } else if tx_idx > nof_synced {
            panic!("transaction index too high: synchronize transaction {} first", nof_synced);
        }
    }

    /// Registers an identity.
    pub fn register_identity(&mut self, iden: Identity) {
        // check whether identity is correct (e.g., matches the configured crypto parameters)
        assert!(iden.is_valid(&self.crypto_params), "tried to register invalid identity (was the identity derived from mismatching crypto parameters?)");

        debug!("registered identity with address {}, public key ({}, {}), secret key {}",
            fe_to_be_hex_str(&iden.address),
            fe_to_be_hex_str(&iden.public_key.x),
            fe_to_be_hex_str(&iden.public_key.y),
            fe_to_be_hex_str(&iden.secret_key.0.0));
        self.identities.insert(iden.address, Rc::new(iden));
    }

    /// Returns the current state of object with object id `oid`.
    /// The object and it's owner's identity must be known to the runtime.
    pub fn get_state(&self, oid: ObjectId) -> Result<Record, ()> {
        let record = self.ledger_state_view.borrow().get_record_for_oid(&oid)?;
        Ok(record)
    }

    /// Executes the given program with given arguments for the current mirror of the ledger state.
    /// - The first argument is the address of the transaction sender.
    /// - The mirror should be updated using `sync_tx` before this function is called.
    /// - The mirror is not updated by this function; only once the transaction is accepted by the ledger,
    ///   the resulting state updates will be applied to the mirror as part of `sync_tx`.
    /// - If `dbg_sync_immediately` is `true`, the mirror is directly updated (useful for debugging purposes)
    pub fn execute(&mut self,
        called_class_id: OuterScalarField,
        called_function_id: OuterScalarField,
        program: Vec<ZkInstruction>,
        arguments: Vec<OuterScalarField>,
        return_register: usize,
        current_time: OuterScalarField,
        dbg_sync_immediately: bool
    ) -> ExecutionResult {
        let root = self.ledger_state_view.borrow().get_root();
        let consumed_serials: Vec<_>;
        let mut new_records;
        let proof;
        let unique_seed;
        let result_state;
        {
            // enforce sender address is a user address
            assert!(!arguments.is_empty(), "requires at least 1 argument (for sender address)");
            let sender_address = arguments[0];
            assert!(is_external_account(&sender_address), "sender address (argument 0) must be an external user account address");

            let rand: &mut R = &mut self.rand.borrow_mut();
            let mut ctx = ProofContext::new(rand, root.clone(), self.crypto_params.clone(), sender_address);

            // get sender identity and sender secret key
            let sender_ident = self.try_get_identity_for_addr(&sender_address)
                .unwrap_or_else(|| panic!("no secret key registered for sender address {}", &fe_to_be_hex_str(&sender_address)));
            ctx.sender_sk_bytes.copy_from_slice(&to_bytes!(sender_ident.secret_key.0.0).unwrap());

            debug!("using sender identity with address {}, public key ({}, {}), secret key {}",
                    fe_to_be_hex_str(&sender_ident.address),
                    fe_to_be_hex_str(&sender_ident.public_key.x),
                    fe_to_be_hex_str(&sender_ident.public_key.y),
                    fe_to_be_hex_str(&sender_ident.secret_key.0.0));

            let check_pk = derive_pk_from_sk(&self.crypto_params.enc_params.elgamal_params, &sender_ident.secret_key.0);
            assert_eq!(check_pk, sender_ident.public_key, "invalid sender identity: public key does not match secret key");

            // populate initial processor state with fresh values and arguments
            let mut initial_proc_state = ZkProcessorPartialState::default();
            let (new_oids, new_obj_sks, new_obj_addrs, fresh_vals) = ctx.derive_fresh_values(rand);
            initial_proc_state.new_oids = new_oids;
            initial_proc_state.new_obj_sks = new_obj_sks;
            initial_proc_state.new_obj_addrs = new_obj_addrs;
            initial_proc_state.fresh_vals = fresh_vals;
            initial_proc_state.registers[..arguments.len()].clone_from_slice(&arguments[..]);

            ctx.processor_current_time = current_time;
            ctx.called_class_id = called_class_id;
            ctx.called_function_id = called_function_id;

            // pad program with NOOPs
            assert!(program.len() <= NOF_PROCESSOR_CYCLES, "too many instructions (got: {}, max: {})", program.len(), NOF_PROCESSOR_CYCLES);
            ctx.processor_instructions[0..program.len()].clone_from_slice(&program);

            // run processor
            let mut processor = ZkProcessor::default();
            time_measure!("run_processor", processor.run(self.ledger_state_view.clone(), &ctx.processor_instructions, initial_proc_state, ctx.processor_current_time) );

            // store intermediate states to context
            ctx.processor_states.clone_from_slice(&processor.states);

            // prepare all inputs for context
            let initial_state = processor.get_initial_state();
            for i in 0..NOF_TX_RECORDS {
                let data = &initial_state.obj_data[i];
                if data.is_empty.is_zero() {
                    assert_ne!(data.object_id, OuterScalarField::zero());
                    debug!("input record object id: {}", fe_to_string(&data.object_id));
                    let (enc_record, path, sk) = self.ledger_state_view.borrow().get_enc_record_with_path_and_sk(&data.object_id).unwrap();
                    ctx.set_input_and_decrypt(i, sk, enc_record, path)
                }
            }

            // prepare all outputs for context
            new_records = vec![];
            result_state = processor.get_result_state();
            for i in 0..NOF_TX_RECORDS {
                let data = &result_state.obj_data[i];
                let mut record = Record::from_object_data(data);
                if !record.is_dummy() {
                    debug!("output record object id: {}", fe_to_string(&record.object_id));
                    debug!("{:?}", record);
                    let pk_owner = try_get_pk_for_addr(&record.addr_owner);
                    assert!(pk_owner.is_some() && pk_owner.unwrap().is_on_curve() && pk_owner.unwrap().is_in_correct_subgroup_assuming_on_curve(),
                        "invalid owner address for object {}; did the program correctly store the owner?",  fe_to_be_hex_str(&record.object_id));
                } else {
                    // set the owner of dummy output records to the sender address
                    // this ensures that dummy outputs are encrypted indistinguishably from non-dummy outputs
                    // and that no internal processor information (e.g., state of deleted objects) is leaked to
                    // parties other than the sender
                    record.addr_owner = sender_address;
                }
                let enc_record = ctx.set_output_and_encrypt(rand, i, record);
                new_records.push(enc_record);
            }

            // collect consumed serial numbers and unique seed
            consumed_serials = ctx.in_records.iter().map(|rec| rec.sn).collect();
            unique_seed = ctx.unique_seed;

            // generate proof
            time_measure!("generate_proof", proof = generate_main_proof(rand, &self.proving_key, ctx));
        }   // end borrowing of self.rand

        // NOTE: do not update the ledger_state_view here (must be done via sync, after acceptance of the transaction),
        // except if flag dbg_sync_immediately is set
        if dbg_sync_immediately {
            debug!("updating local ledger state due to flag dbg_sync_immediately");
            let next_idx = self.get_nof_synced_tx();
            self.sync_tx(next_idx, &consumed_serials, &new_records);
        }

        ExecutionResult {
            merkle_tree_root: root,
            current_time,
            consumed_serials,
            new_records,
            proof,
            unique_seed,
            return_value: result_state.partial.registers[return_register],
        }
    }

    fn try_get_identity_for_addr(&self, addr: &OuterScalarField) -> Option<Rc<Identity>> {
        let iden = self.identities.get(addr);
        iden.cloned()
    }

    fn try_recognize_enc_records(&mut self, idx_and_records: Vec<(usize, EncryptedRecord)>) {
        // as new records may be mutual owners of each other, need to iterate multiple times
        let mut found_new_identity = true;
        let mut recognized = BTreeSet::new();
        while found_new_identity {
            found_new_identity = false;
            let mut new_identities = vec![];
            for (idx, enc_record) in idx_and_records.iter() {
                if recognized.contains(idx) {
                    continue;
                }
                for (_, ident) in self.identities.iter() {
                    let res = Record::decrypt(enc_record, &ident.secret_key, &self.crypto_params.enc_params);
                    if let Ok(record) = res {
                        recognized.insert(idx);
                        if record.is_dummy() {
                            // dummy records do not have to be remembered
                            break;
                        }
        
                        // derive serial number (such that we can later observe once this record is consumed)
                        let mut sk_serialized = [0u8; SERIALIZED_SK_BYTES];
                        sk_serialized.copy_from_slice(to_bytes!(&ident.secret_key).unwrap().as_slice());
                        let serial_number = derive_sn_from_nonce(&record.serial_nonce, &sk_serialized);
        
                        // update known objects
                        let info = ObjectInfo {
                            leaf_idx: *idx,
                            owner_identity: ident.clone(),
                            serial_number
                        };
                        self.ledger_state_view.borrow_mut().known_objects.insert(record.object_id, info);
        
                        // remember new object identity for registration, if not known yet
                        if !self.identities.contains_key(&record.addr_object) {
                            assert!(!is_external_account(&record.addr_object));
                            let obj_iden = Identity {
                                is_external_account: false,
                                secret_key: ExtSecretKey(SecretKey(FeConverter::to_smaller(&record.sk_object).unwrap())),
                                public_key: get_pk_for_addr(&record.addr_object),
                                address: record.addr_object,
                            };
                            new_identities.push(obj_iden);
                        }
                        break;
                    }
                }
            }
            // register newly observed identities
            for obj_iden in new_identities {
                found_new_identity = true;
                self.register_identity(obj_iden);
            }
        }      
    }

    fn try_recognize_published_serial(&mut self, serial: &Serial) {
        let mut found_obj: Option<ObjectId> = None;
        for info in self.ledger_state_view.borrow().known_objects.iter() {
            if serial == &info.1.serial_number {
                found_obj = Some(*info.0);
                break;
            }
        }
        if let Some(oid) = found_obj {
            self.ledger_state_view.borrow_mut().known_objects.remove(&oid);
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_crypto_primitives::encryption::elgamal::SecretKey;
    use ark_gm17::VerifyingKey;
    use ark_std::rand::Rng;
    use ark_std::{Zero, test_rng};
    use rand::prelude::StdRng;
    use crate::crypto::elgamal_ext::derive_pk_from_sk;
    use crate::infrastructure::circuit::{setup_main_proof_circuit, MainProofVerifier};
    use crate::infrastructure::identities::Identity;
    use crate::infrastructure::processor::{OPCODE_STORE, OPCODE_LOAD, OPCODE_KILL, OPCODE_NEW, OPCODE_ADD, OPCODE_MOV, RegOrConst, OPCODE_NOOP};
    use super::*;

    fn get_record<R: Rng>(rng: &mut R, addr_owner: &OuterScalarField, params: &CryptoParams) -> (Record, EncryptedRecord) {
        let mut payload = [OuterScalarField::zero(); NOF_RECORD_PAYLOAD_ELEMENTS];
        for i in 0..NOF_RECORD_PAYLOAD_ELEMENTS {
            payload[i] = OuterScalarField::rand(rng);
        }

        let serial_nonce = OuterScalarField::rand(rng);
        let contract_id = OuterScalarField::rand(rng);
        let object_id = OuterScalarField::rand(rng);

        // get a non-external identity
        let mut sk_object;
        let mut pk_object;
        let mut addr_object;
        loop {
            sk_object = InnerEdScalarField::rand(rng);
            pk_object = derive_pk_from_sk(&params.enc_params.elgamal_params, &SecretKey(sk_object));
            if is_reconstructable(&pk_object) {
                addr_object = get_addr_for_pk(&pk_object);
                if !is_external_account(&addr_object) {
                    break;
                }
            }
        }

        let record = Record {
            serial_nonce,
            contract_id,
            object_id,
            sk_object: FeConverter::to_larger(&sk_object),
            addr_object,
            addr_owner: *addr_owner,
            payload
        };
        let enc_record = record.encrypt(&get_pk_for_addr(addr_owner), &params.enc_params, rng).0;

        (record, enc_record)
    }

    fn init_runtime(
        rng: RefCell<StdRng>,
        with_real_proofs: bool
    ) -> (Record, Record, Runtime<StdRng>, ExtSecretKey<InnerEdProjective>, OuterScalarField,  CryptoParams, Option<VerifyingKey<OuterPairing>>) {
        let iden: Identity;
        let record_1;
        let record_2;
        let params: CryptoParams;
        let enc_record_1;
        let enc_record_2;
        {
            let rng_borrowed: &mut StdRng = &mut rng.borrow_mut();
            params = CryptoParams::setup(rng_borrowed);

            // get example records
            iden = Identity::new_external(rng_borrowed, &params);
            let r1 = get_record(rng_borrowed, &iden.address, &params);
            record_1 = r1.0;
            enc_record_1 = r1.1;
            let r2 = get_record(rng_borrowed, &iden.address, &params);
            record_2 = r2.0;
            enc_record_2 = r2.1;
        }

        // circuit setup
        let prover_key;
        let verifier_key;
        if with_real_proofs {
            let rng_borrowed: &mut StdRng = &mut rng.borrow_mut();
            let keys = setup_main_proof_circuit(params.clone(), rng_borrowed);
            prover_key = Some(keys.0);
            verifier_key = Some(keys.1);
        } else {
            prover_key = None;
            verifier_key = None;
        }

        // start runtime and add example records
        let mut runtime = Runtime::new(params.clone(), prover_key, rng);
        runtime.register_identity(iden.clone());
        runtime.sync_tx(0, &[], &[enc_record_1, enc_record_2]);

        (record_1, record_2, runtime, iden.secret_key, iden.address, params, verifier_key)
    }

    fn check_eq_record_non_payload(r1: &Record, r2: &Record) {
        assert_eq!(r1.contract_id, r2.contract_id);
        assert_eq!(r1.object_id, r2.object_id);
        assert_eq!(r1.sk_object, r2.sk_object);
        assert_eq!(r1.addr_object, r2.addr_object);
    }

    #[test]
    fn test_runtime_get_state() {
        let rng = RefCell::new(test_rng());
        let (record_1, record_2, runtime, _, _, _, _) = init_runtime(rng, false);
        
        // check get_state
        let state = runtime.get_state(record_1.object_id).unwrap();
        assert_eq!(state, record_1);
        let state = runtime.get_state(record_2.object_id).unwrap();
        assert_eq!(state, record_2);
    }

    #[test]
    fn test_runtime_execute_store_load() {
        let rng = RefCell::new(test_rng());
        let (record_1, record_2, mut runtime, sk, addr, params, _) = init_runtime(rng, false);
        let current_time = OuterScalarField::from(777);
        let called_class_id = OuterScalarField::from(123);
        let called_function_id = OuterScalarField::from(7);

        let program = vec![
            ZkInstruction { opcode: OPCODE_MOV, dst: 1, src_1: RegOrConst::Reg(2), src_2: RegOrConst::Reg(0)},
            ZkInstruction { opcode: OPCODE_STORE, dst: 1, src_1: RegOrConst::Const(record_1.object_id), src_2: RegOrConst::Const(OuterScalarField::from(2))},
            ZkInstruction { opcode: OPCODE_LOAD, dst: 2, src_1: RegOrConst::Const(record_2.object_id), src_2: RegOrConst::Const(OuterScalarField::from(2))}
        ];
        let res = runtime.execute(called_class_id, called_function_id, program, vec![addr, OuterScalarField::from(0), OuterScalarField::from(999)], 0, current_time, false);

        let check_record = Record::decrypt(&res.new_records[0], &sk, &params.enc_params).unwrap();
        check_eq_record_non_payload(&check_record, &record_1);
        assert_eq!(check_record.payload[1], OuterScalarField::from(999));

        let check_record = Record::decrypt(&res.new_records[1], &sk, &params.enc_params).unwrap();
        check_eq_record_non_payload(&check_record, &record_2);
        assert_eq!(check_record.payload, record_2.payload);
    }

    #[test]
    fn test_runtime_execute_kill() {
        let rng = RefCell::new(test_rng());
        let (_, record_2, mut runtime, sk, addr, params, _) = init_runtime(rng, false);
        let current_time = OuterScalarField::from(777);
        let called_class_id = OuterScalarField::from(123);
        let called_function_id = OuterScalarField::from(7);

        let program = vec![
            ZkInstruction { opcode: OPCODE_KILL, dst: 0, src_1: RegOrConst::Const(record_2.object_id), src_2: RegOrConst::Reg(0) }
        ];
        let res = runtime.execute(called_class_id, called_function_id, program, vec![addr, OuterScalarField::from(0),], 0, current_time, false);

        for i in 0..NOF_TX_RECORDS {
            let check_record = Record::decrypt(&res.new_records[i], &sk, &params.enc_params).unwrap();
            assert!(check_record.is_dummy());
        }

        runtime.sync_tx(1, &res.consumed_serials, &res.new_records);
        assert!(!runtime.ledger_state_view.borrow().known_objects.contains_key(&record_2.object_id));
    }

    #[test]
    fn test_runtime_execute_new() {
        let rng = RefCell::new(test_rng());
        let (_, _, mut runtime, _, _, params, _) = init_runtime(rng, false);
        let current_time = OuterScalarField::from(777);
        let called_class_id = OuterScalarField::from(123);
        let called_function_id = OuterScalarField::from(7);

        let contract_id_new = OuterScalarField::from(56789);
        let iden_new = Identity::new_external(&mut test_rng(), &params);
        runtime.register_identity(iden_new.clone());

        let program = vec![
            ZkInstruction { opcode: OPCODE_NEW, dst: 4, src_1: RegOrConst::Const(contract_id_new), src_2: RegOrConst::Reg(0) },
            ZkInstruction { opcode: OPCODE_STORE, dst: 0, src_1: RegOrConst::Reg(4), src_2: RegOrConst::Const(OuterScalarField::from(0)) },
            ZkInstruction { opcode: OPCODE_STORE, dst: 1, src_1: RegOrConst::Reg(4), src_2: RegOrConst::Const(OuterScalarField::from(1)) }
        ];
        let res = runtime.execute(called_class_id, called_function_id, program, vec![iden_new.public_key.x, iden_new.public_key.y], 0, current_time, false);

        let check_record = Record::decrypt(&res.new_records[0], &iden_new.secret_key, &params.enc_params).unwrap();
        assert_eq!(check_record.contract_id, contract_id_new);
        assert_eq!(check_record.addr_owner, iden_new.address);
        let sk = FeConverter::to_smaller(&check_record.sk_object).unwrap();
        let pk = derive_pk_from_sk(&params.enc_params.elgamal_params, &SecretKey(sk));
        assert_eq!(check_record.addr_object, get_addr_for_pk(&pk));

        // sync with new record
        runtime.register_identity(iden_new);
        runtime.sync_tx(1, &res.consumed_serials, &res.new_records);
        
        // try to get state of new object
        let state = runtime.get_state(check_record.object_id).unwrap();
        assert_eq!(state.addr_owner, check_record.addr_owner);
    }

    #[test]
    fn test_runtime_execute_mixed() {
        let rng = RefCell::new(test_rng());
        let (record_1, record_2, mut runtime, sk, _, params, _) = init_runtime(rng, false);
        let current_time = OuterScalarField::from(777);
        let called_class_id = OuterScalarField::from(123);
        let called_function_id = OuterScalarField::from(7);

        let contract_id_new = OuterScalarField::from(56789);
        let iden_new = Identity::new_external(&mut test_rng(), &params);
        runtime.register_identity(iden_new.clone());

        let program = vec![
            ZkInstruction { opcode: OPCODE_MOV, dst: 3, src_1: RegOrConst::Const(OuterScalarField::from(789)), src_2: RegOrConst::Reg(0)},
            ZkInstruction { opcode: OPCODE_STORE, dst: 3, src_1: RegOrConst::Const(record_1.object_id), src_2: RegOrConst::Const(OuterScalarField::from(4)) },
            ZkInstruction { opcode: OPCODE_LOAD, dst: 2, src_1: RegOrConst::Const(record_2.object_id), src_2: RegOrConst::Const(OuterScalarField::from(2)) },
            ZkInstruction { opcode: OPCODE_ADD, dst: 2, src_1: RegOrConst::Const(OuterScalarField::from(1)), src_2: RegOrConst::Const(OuterScalarField::from(5))},
            ZkInstruction { opcode: OPCODE_NEW, dst: 4, src_1: RegOrConst::Const(contract_id_new), src_2: RegOrConst::Reg(0) },
            ZkInstruction { opcode: OPCODE_STORE, dst: 0, src_1: RegOrConst::Reg(4), src_2: RegOrConst::Const(OuterScalarField::from(0)) },
            ZkInstruction { opcode: OPCODE_STORE, dst: 1, src_1: RegOrConst::Reg(4), src_2: RegOrConst::Const(OuterScalarField::from(1)) },
            ZkInstruction { opcode: OPCODE_STORE, dst: 2, src_1: RegOrConst::Reg(4), src_2: RegOrConst::Const(OuterScalarField::from(2)) },
            ZkInstruction { opcode: OPCODE_KILL, dst: 0, src_1: RegOrConst::Const(record_2.object_id), src_2: RegOrConst::Reg(0) },
            ZkInstruction { opcode: OPCODE_NOOP, dst: 0, src_1: RegOrConst::Reg(0), src_2: RegOrConst::Reg(0)},
        ];
        let res = runtime.execute(called_class_id, called_function_id, program, vec![iden_new.address], 0, current_time, false);

        let check_record = Record::decrypt(&res.new_records[0], &sk, &params.enc_params).unwrap();
        check_eq_record_non_payload(&check_record, &record_1);
        assert_eq!(check_record.payload[3], OuterScalarField::from(789));

        let check_record = Record::decrypt(&res.new_records[2], &iden_new.secret_key, &params.enc_params).unwrap();
        assert_eq!(check_record.contract_id, contract_id_new);
        assert_eq!(check_record.addr_owner, iden_new.address);
        assert_eq!(check_record.payload[1], OuterScalarField::from(6));
    }

    #[test]
    #[ignore]
    fn test_runtime_real_proof_noop() {
        let rng = RefCell::new(test_rng());
        let (_, _, mut runtime, _, addr, _, verifier_key) = init_runtime(rng, true);
        let current_time = OuterScalarField::from(777);
        let called_class_id = OuterScalarField::from(123);
        let called_function_id = OuterScalarField::from(7);

        let program: Vec<_> = (0..NOF_PROCESSOR_CYCLES)
            .map(|_| ZkInstruction { opcode: OPCODE_NOOP, dst: 0, src_1: RegOrConst::Reg(0), src_2: RegOrConst::Reg(0)})
            .collect();
        let res = runtime.execute(called_class_id, called_function_id, program.clone(), vec![addr], 0, current_time, false);
        assert!(res.proof.is_some());

        let verifier = MainProofVerifier::new(verifier_key.unwrap());
        let ok = verifier.verify(&res.unique_seed, &res.merkle_tree_root, &res.consumed_serials, &res.new_records, called_class_id, called_function_id, &program, current_time, res.proof.as_ref().unwrap());
        assert!(ok);

        let ok = verifier.verify(&[99u8; RAND_BYTES], &res.merkle_tree_root, &res.consumed_serials, &res.new_records, called_class_id, called_function_id, &program, current_time, res.proof.as_ref().unwrap());
        assert!(!ok);
    }
}