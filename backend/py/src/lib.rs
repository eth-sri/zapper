
use ark_gm17::{ProvingKey, VerifyingKey};
use pyo3::prelude::*;
use rand::prelude::ThreadRng;
use std::cell::RefCell;
use ark_ff::{to_bytes, FromBytes};
use zapper_backend_lib::{common::*, infrastructure::{params::{CryptoParams, MerkleTreeParams, MerkleTreeRoot}, runtime::{Runtime, ExecutionResult}, processor::{self, RegOrConst}, record::{Record, EncryptedRecord}, identities::Identity, circuit::{setup_main_proof_circuit, MainProofVerifier, MainProof}}, common::OuterScalarField, crypto::{sparse_merkle_tree::SparseMerkleTree}, constants::{TREE_HEIGHT, SN_BYTES}};
use pyo3::create_exception;

create_exception!(zapper_backend, ZapperBackendError, pyo3::exceptions::PyException);

#[pymodule]
fn zapper_backend(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(enable_logging, m)?)?;
    m.add_function(wrap_pyfunction!(trusted_setup, m)?)?;
    m.add_function(wrap_pyfunction!(new_user_account, m)?)?;
    m.add_class::<RuntimeInterface>()?;
    m.add_class::<ObjectState>()?;
    m.add_class::<KeyPair>()?;
    m.add_class::<ExportedExecutionResult>()?;
    m.add_class::<ExportedCryptoParams>()?;
    m.add_class::<VerifierInterface>()?;
    m.add_class::<MerkleTreeInterface>()?;
    Ok(())
}

#[pyfunction]
fn enable_logging() {
    init_logging();
}

#[derive(FromPyObject)]
struct Instruction {
    pub opcode: u8,
    pub dst: usize,
    pub src_1: String,
    pub src_1_is_const: bool,
    pub src_2: String,
    pub src_2_is_const: bool,
}

impl Instruction {
    pub fn to_zk_instruction(&self) -> processor::ZkInstruction {
        processor::ZkInstruction {
            opcode: self.opcode,
            dst: self.dst,
            src_1: if self.src_1_is_const { RegOrConst::Const(fe_from_be_hex_str(&self.src_1)) } else { RegOrConst::Reg(usize_from_be_hex_str(&self.src_1)) },
            src_2: if self.src_2_is_const { RegOrConst::Const(fe_from_be_hex_str(&self.src_2)) } else { RegOrConst::Reg(usize_from_be_hex_str(&self.src_2)) },
        }
    }
}

fn convert_instructions(orig: Vec<Instruction>) -> Vec<processor::ZkInstruction> {
    orig.iter().map(|inst| inst.to_zk_instruction()).collect()
}

fn convert_arguments(orig: Vec<String>) -> Vec<OuterScalarField> {
    orig.iter().map(|arg| fe_from_be_hex_str(arg)).collect()
}

#[pyclass(name="ObjectState")]
struct ObjectState {
    #[pyo3(get, set)]
    contract_id: String,
    #[pyo3(get, set)]
    object_id: String,
    #[pyo3(get, set)]
    sk_object: String,
    #[pyo3(get, set)]
    addr_object: String,
    #[pyo3(get, set)]
    addr_owner: String,
    #[pyo3(get, set)]
    payload: Vec<String>
}

impl ObjectState {
    pub fn from_record(record: Record) -> ObjectState {
        ObjectState {
            contract_id: fe_to_be_hex_str(&record.contract_id),
            object_id: fe_to_be_hex_str(&record.object_id),
            sk_object: fe_to_be_hex_str(&record.sk_object),
            addr_object: fe_to_be_hex_str(&record.addr_object),
            addr_owner: fe_to_be_hex_str(&record.addr_owner),
            payload: record.payload.iter().map(|elem| fe_to_be_hex_str(&elem)).collect(),
        }
    }
}

#[pymethods]
impl ObjectState {
    fn __str__(self_: PyRef<Self>) -> String {
        format!(
            "{{\n contract_id: {}\n object_id: {}\n sk_object: {}\n addr_object: {}\n addr_owner: {}\n payload: {:?}\n}}",
            self_.contract_id,
            self_.object_id,
            self_.sk_object,
            self_.addr_object,
            self_.addr_owner,
            self_.payload
        )
    }
}

#[pyclass(name="KeyPair")]
struct KeyPair {
    #[pyo3(get, set)]
    secret_key: String,
    #[pyo3(get, set)]
    public_key: (String, String),
    #[pyo3(get, set)]
    address: String
}

impl KeyPair {
    pub fn from_identity(identity: &Identity) -> KeyPair {
        KeyPair {
            secret_key: fe_to_be_hex_str(&FeConverter::to_larger(&identity.secret_key.0.0)),
            public_key: (fe_to_be_hex_str(&identity.public_key.x), fe_to_be_hex_str(&identity.public_key.y)),
            address: fe_to_be_hex_str(&identity.address)
        }
    }

    pub fn to_identity(&self) -> Identity {
        Identity::from_coords(fe_from_be_hex_str(&self.public_key.0), fe_from_be_hex_str(&self.public_key.1), fe_from_be_hex_str(&self.secret_key))
    }
}

#[pyclass(name="CryptoParameters")]
struct ExportedCryptoParams {
    general_params: CryptoParams,
    prover_key: Option<ProvingKey<OuterPairing>>,
    verifier_key: Option<VerifyingKey<OuterPairing>>
}

#[pyfunction(dbg_no_circuit_setup = "false")]
fn trusted_setup(dbg_no_circuit_setup: bool) -> ExportedCryptoParams {
    let mut rng = rand::thread_rng();
    let general_params = CryptoParams::setup(&mut rng);
    let prover_key;
    let verifier_key;
    if dbg_no_circuit_setup {
        prover_key = None;
        verifier_key = None;
    } else {
        let keys = setup_main_proof_circuit(general_params.clone(), &mut rng);
        prover_key = Some(keys.0);
        verifier_key = Some(keys.1);
    }
    ExportedCryptoParams {
        general_params,
        prover_key,
        verifier_key
    }
}

#[pyfunction]
fn new_user_account(crypto_params: PyRef<ExportedCryptoParams>) -> PyResult<KeyPair> {
    let rng_borrowed = &mut rand::thread_rng();
    let identity = Identity::new_external(rng_borrowed, &crypto_params.general_params);
    let key_pair = KeyPair::from_identity(&identity);
    Ok(key_pair)
}

#[pyclass(name="ExecutionResult")]
struct ExportedExecutionResult {
    #[pyo3(get, set)]
    pub merkle_tree_root: String,
    #[pyo3(get, set)]
    pub current_time: String,
    #[pyo3(get, set)]
    pub consumed_serials: Vec<String>,
    #[pyo3(get, set)]
    pub new_records: Vec<String>,
    #[pyo3(get, set)]
    pub proof: Option<String>,
    #[pyo3(get, set)]
    pub unique_seed: String,
    #[pyo3(get, set)]
    pub return_value: String
}

impl ExportedExecutionResult {
    pub fn from(result: ExecutionResult) -> ExportedExecutionResult {
        ExportedExecutionResult {
            merkle_tree_root: fe_to_be_hex_str(&result.merkle_tree_root.0),
            current_time: fe_to_be_hex_str(&result.current_time),
            consumed_serials: result.consumed_serials.iter().map(|bytes| hex::encode(bytes)).collect(),
            new_records: result.new_records.iter().map(|enc_record| hex::encode(to_bytes!(enc_record).unwrap())).collect(),
            proof: result.proof.map(|proof| hex::encode(to_bytes!(proof).unwrap())),
            unique_seed: hex::encode(result.unique_seed),
            return_value: fe_to_be_hex_str(&result.return_value),
        }
    }
}

#[pyclass(name="Runtime",unsendable)]   // NOTE: the class will panic if accessed from different thread
#[pyo3(text_signature = "(crypto_params)")] // text_signature for new
struct RuntimeInterface {
    runtime: Runtime<ThreadRng>,
    params: CryptoParams
}

#[pymethods]
impl RuntimeInterface {
    #[new]
    fn new(crypto_params: PyRef<ExportedCryptoParams>) -> PyResult<RuntimeInterface> {
        let rng = RefCell::new(rand::thread_rng());
        let params = crypto_params.general_params.clone();
        let runtime = Runtime::new(params.clone(), crypto_params.prover_key.clone(), rng);
        Ok(RuntimeInterface {
            runtime,
            params
        })
    }

    #[args(dbg_sync_immediately = "false")]
    #[pyo3(text_signature = "(self, program, arguments, current_time, dbg_sync_immediately)")]
    fn execute(mut self_: PyRefMut<Self>,
        called_class_id: String,
        called_function_id: String,
        program: Vec<Instruction>,
        arguments: Vec<String>,
        return_register: usize,
        current_time: String,
        dbg_sync_immediately: bool
    ) -> PyResult<ExportedExecutionResult> {
        let res = self_.runtime.execute(fe_from_be_hex_str(&called_class_id), fe_from_be_hex_str(&called_function_id), convert_instructions(program), convert_arguments(arguments), return_register, fe_from_be_hex_str(&current_time), dbg_sync_immediately);
        Ok(ExportedExecutionResult::from(res))
    }

    #[pyo3(text_signature = "(self, oid)")]
    fn get_state(self_: PyRef<Self>, oid: String) -> PyResult<ObjectState> {
        let state = self_.runtime.get_state(fe_from_be_hex_str(&oid));
        if state.is_err() {
            return Err(ZapperBackendError::new_err(format!("could not get state, unknown object id {}", oid)));
        }
        Ok(ObjectState::from_record(state.unwrap()))
    }

    #[pyo3(text_signature = "(self)")]
    fn new_user_account(mut self_: PyRefMut<Self>) -> PyResult<KeyPair> {
        let identity;
        {
            let rng_borrowed: &mut ThreadRng = &mut self_.runtime.rand.borrow_mut();
            identity = Identity::new_external(rng_borrowed, &self_.params);
        }
        let key_pair = KeyPair::from_identity(&identity);
        self_.runtime.register_identity(identity);
        Ok(key_pair)
    }

    #[pyo3(text_signature = "(self, keys)")]
    fn register_account(mut self_: PyRefMut<Self>, keys: PyRef<KeyPair>) -> PyResult<()> {
        self_.runtime.register_identity(keys.to_identity());
        Ok(())
    }

    #[pyo3(text_signature = "(self, address)")]
    fn get_account_for_address(self_: PyRef<Self>, address: String) -> PyResult<KeyPair> {
        let iden = self_.runtime.identities.get(&fe_from_be_hex_str(&address));
        if let Some(iden) = iden {
            return Ok(KeyPair::from_identity(iden))
        }
        Err(ZapperBackendError::new_err("unknown address"))
    }

    #[pyo3(text_signature = "(self)")]
    fn get_nof_synced_tx(self_: PyRef<Self>) -> PyResult<usize> {
        Ok(self_.runtime.get_nof_synced_tx())
    }

    #[pyo3(text_signature = "(self, tx_idx, published_serials, published_records)")]
    fn sync_tx(mut self_: PyRefMut<Self>, tx_idx: usize, published_serials: Vec<String>, published_records: Vec<String>) -> PyResult<()> {
        let serials: Vec<_> = published_serials.iter().map(|s| {
            let v = hex::decode(s).unwrap();
            let mut sn = [0u8; SN_BYTES];
            sn.copy_from_slice(&v);
            sn
        }).collect();
        let records: Vec<_> = published_records.iter().map(|s| EncryptedRecord::read(hex::decode(s).unwrap().as_slice()).unwrap()).collect();
        self_.runtime.sync_tx(tx_idx, &serials, &records);
        Ok(())
    }
}

#[pyclass(name="MerkleTree",unsendable)]   // NOTE: the class will panic if accessed from different thread
#[pyo3(text_signature = "(crypto_params)")] // text_signature for new
struct MerkleTreeInterface {
    merkle_tree: SparseMerkleTree<MerkleTreeParams>
}

#[pymethods]
impl MerkleTreeInterface {
    #[new]
    fn new(crypto_params: PyRef<ExportedCryptoParams>) -> PyResult<MerkleTreeInterface> {
        let leaf_hash_param = &crypto_params.general_params.leaf_hash_param;
        let inner_hash_param = &crypto_params.general_params.inner_hash_param;
        let merkle_tree = SparseMerkleTree::new(leaf_hash_param, inner_hash_param, TREE_HEIGHT);
        Ok(MerkleTreeInterface {
            merkle_tree
        })
    }

    #[pyo3(text_signature = "(self)")]
    fn get_root(self_: PyRef<Self>) -> PyResult<String> {
        Ok(fe_to_be_hex_str(&self_.merkle_tree.root()))
    }

    #[pyo3(text_signature = "(self, idx, data)")]
    fn insert(mut self_: PyRefMut<Self>, idx: u128, data: String) -> PyResult<()> {
        let data = hex::decode(data).unwrap();
        self_.merkle_tree.update(idx, &data);
        Ok(())
    }
}

fn decode_hex_byte_array(byte_string: &String) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(byte_string, &mut bytes).unwrap();
    bytes
}

#[pyclass(name="Verifier",unsendable)]   // NOTE: the class will panic if accessed from different thread
#[pyo3(text_signature = "(crypto_params)")] // text_signature for new
struct VerifierInterface {
    verifier: MainProofVerifier
}

#[pymethods]
impl VerifierInterface {
    #[new]
    fn new(crypto_params: PyRef<ExportedCryptoParams>) -> PyResult<VerifierInterface> {
        if let Some(verifier_key) = &crypto_params.verifier_key {
            return Ok(VerifierInterface {
                verifier: MainProofVerifier::new(verifier_key.clone())
            })
        }
        Err(ZapperBackendError::new_err("cannot create verifier for 'None' verifier key"))
    }

    pub fn verify(self_: PyRef<Self>,
        unique_seed: String,
        merkle_tree_root: String,
        consumed_serials: Vec<String>,
        new_records: Vec<String>,
        called_class_id: String,
        called_function_id: String,
        instructions: Vec<Instruction>,
        current_time: String,
        proof: String
    ) -> PyResult<bool> {
        let unique_seed = decode_hex_byte_array(&unique_seed);
        let merkle_tree_root = MerkleTreeRoot(fe_from_be_hex_str(&merkle_tree_root));
        let consumed_serials: Vec<_> = consumed_serials.iter().map(decode_hex_byte_array).collect();
        let new_records: Vec<_> = new_records.iter().map(|s| EncryptedRecord::read(hex::decode(s).unwrap().as_slice()).unwrap()).collect();
        let instructions = convert_instructions(instructions);
        let called_class_id = fe_from_be_hex_str(&called_class_id);
        let called_function_id = fe_from_be_hex_str(&called_function_id);
        let current_time = fe_from_be_hex_str(&current_time);
        let proof = MainProof::read(hex::decode(proof).unwrap().as_slice()).unwrap();
        let res = self_.verifier.verify(&unique_seed, &merkle_tree_root, &consumed_serials, &new_records, called_class_id, called_function_id, &instructions, current_time, &proof);
        Ok(res)
    }
}