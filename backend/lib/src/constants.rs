// ********** CONFIGURABLE CONSTANTS **********

/// Height of the merkle tree.
/// The merkle tree can store `2^(TREE_HEIGHT-1)` leafs.
#[cfg(not(feature="tiny"))]
pub const TREE_HEIGHT: usize = 32;
#[cfg(feature="tiny")]
pub const TREE_HEIGHT: usize = 5;

/// Maximum number of input and output records in a transaction.
#[cfg(not(feature="tiny"))]
pub const NOF_TX_RECORDS: usize = 4;
#[cfg(feature="tiny")]
pub const NOF_TX_RECORDS: usize = 3;

/// Maximum number of fresh values and new objects in a transaction
#[cfg(not(feature="tiny"))]
pub const NOF_TX_FRESH: usize = 4;
#[cfg(feature="tiny")]
pub const NOF_TX_FRESH: usize = 3;

/// Number of field elements in a record's payload (excluding one element for the owner address).
#[cfg(not(feature="tiny"))]
pub const NOF_RECORD_PAYLOAD_ELEMENTS: usize = 9;
#[cfg(feature="tiny")]
pub const NOF_RECORD_PAYLOAD_ELEMENTS: usize = 4;

/// Number of registers (for arguments and temporary values) for the ZK processor
#[cfg(not(feature="tiny"))]
pub const NOF_PROCESSOR_REGISTERS: usize = 10;
#[cfg(feature="tiny")]
pub const NOF_PROCESSOR_REGISTERS: usize = 8;

/// Number of cycles for the ZK processor
#[cfg(not(feature="tiny"))]
pub const NOF_PROCESSOR_CYCLES: usize = 100;
#[cfg(feature="tiny")]
pub const NOF_PROCESSOR_CYCLES: usize = 30;

/// Seed for PRF when deriving serial numbers.
pub const PRF_SN_SEED: u8 = 1;

/// Seed for PRF when deriving serial number nonces.
pub const PRF_SN_NONCE_SEED: u8 = 2;

/// Seed for PRF when deriving secret keys.
pub const PRF_SK_SEED: u8 = 3;

/// Seed for PRF when deriving object ids.
pub const PRF_OID_SEED: u8 = 4;

/// Seed for PRF when deriving fresh values.
pub const PRF_FRESH_VAL_SEED: u8 = 5;


// ********** NON-CONFIGURABLE CONSTANTS **********
// !! Do not edit unless you know what you are doing !!

// OuterScalarField:        254.9 bits (31.9 bytes)
// InnerEdScalarField:      251.8 bits (31.4 bytes)

/// Upper bound on the number of bytes required to store a field element.
/// This is used for serialization and de-serialization of field elements.
pub const FE_BYTES: usize = 32;

/// Output size of PRF.
pub const PRF_BLOCK_BYTES: usize = 32;

/// Size of serial numbers.
pub const SN_BYTES: usize = PRF_BLOCK_BYTES;

/// Size of serialized secret key.
pub const SERIALIZED_SK_BYTES: usize = FE_BYTES;

/// Size of randomness elements.
pub const RAND_BYTES: usize = PRF_BLOCK_BYTES;

/// The maximum number of bytes allowed for a uint in the processor.
pub const MAX_BYTES_UINT: usize = 15;   // = 120 bits


pub fn data_log_constants() {
    crate::data_log!(format!("{{\"config\": {{\"TREE_HEIGHT\": {}, \"NOF_TX_RECORDS\": {}, \"NOF_TX_FRESH\": {}, \"NOF_RECORD_PAYLOAD_ELEMENTS\": {}, \"NOF_PROCESSOR_REGISTERS\": {}, \"NOF_PROCESSOR_CYCLES\": {}}}}}",
    TREE_HEIGHT,
    NOF_TX_RECORDS,
    NOF_TX_FRESH,
    NOF_RECORD_PAYLOAD_ELEMENTS,
    NOF_PROCESSOR_REGISTERS,
    NOF_PROCESSOR_CYCLES));
}