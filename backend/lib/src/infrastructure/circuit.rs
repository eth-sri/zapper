use ark_crypto_primitives::crh::injective_map::constraints::{PedersenCRHCompressorGadget, TECompressorGadget};
use ark_crypto_primitives::crh::injective_map::TECompressor;
use ark_crypto_primitives::crh::TwoToOneCRHGadget;
use ark_crypto_primitives::encryption::elgamal;
use ark_crypto_primitives::{CRHGadget, PathVar, SNARK};
use ark_ec::PairingEngine;
use ark_ff::{to_bytes, ToBytes, FromBytes, ToConstraintField};
use ark_gm17::{GM17, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_sponge::poseidon::PoseidonParameters;
use log::{info, debug};
use rand::{Rng, CryptoRng};

use crate::{common::*, data_log, time_measure};
use crate::constants::*;
use crate::crypto::elgamal_ext::{ElGamalDecGadget, SecretKeyVar, MyParametersVar, ElGamalEncGadget, ElGamalKeyGadget};
use crate::crypto::poseidon::constraints::PoseidonCipherGadget;
use crate::infrastructure::params::{InnerHash, InnerWindow, LeafHash, LeafWindow, MerkleTreeParams};
use crate::infrastructure::runtime::ProofContext;
use crate::infrastructure::derivations::constraints::*;

use super::params::{CryptoParams, MerkleTreeRoot};
use super::processor::ZkInstruction;
use super::processor::constraints::{ZkProcessorStateVar, ZkInstructionVar, ZkProcessorGadget};
use super::record::{EncryptedRecord, RECORD_CHUNKS, Record, EncRandomness, RECORD_CHUNKS_PADDED, Serial};

pub type TwoToOneHashGadget = PedersenCRHCompressorGadget<
    InnerEdProjective,
    TECompressor,
    InnerWindow,
    InnerEdVar,
    TECompressorGadget,
>;
pub type LeafHashGadget = PedersenCRHCompressorGadget<
    InnerEdProjective,
    TECompressor,
    LeafWindow,
    InnerEdVar,
    TECompressorGadget,
>;
pub type RootVar = <TwoToOneHashGadget as TwoToOneCRHGadget<InnerHash, OuterScalarField>>::OutputVar;
pub type LeafHashParamsVar = <LeafHashGadget as CRHGadget<LeafHash, OuterScalarField>>::ParametersVar;
pub type InnerHashParamsVar = <TwoToOneHashGadget as TwoToOneCRHGadget<InnerHash, OuterScalarField>>::ParametersVar;
pub type MerklePathVar = PathVar<MerkleTreeParams, LeafHashGadget, TwoToOneHashGadget, OuterScalarField>;


macro_rules! constraints_measure {
    ($cs: expr, $name: expr, $body: stmt) => {
        let xx_nof_constraints_start = $cs.num_constraints();
        $body
        let xx_nof_constraints = $cs.num_constraints()- xx_nof_constraints_start;
        if $cs.is_in_setup_mode() {
            log::debug!("constraints for {}: {}", $name, xx_nof_constraints_start);
            crate::data_log!(format!("{{\"constraints\": {{\"part\": \"{}\", \"num_constraints\": {}}}}}", $name, xx_nof_constraints));
        }
    }
}

pub fn count_constraints(crypto_params: CryptoParams) -> usize {
    let circuit = MainProofCircuit {
        ctx: ProofContext::default_with_params(crypto_params)
    };
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);
    cs.set_mode(ark_relations::r1cs::SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.num_constraints()
}

pub fn setup_main_proof_circuit<R: Rng + CryptoRng>(crypto_params: CryptoParams, rng: &mut R) -> (ProvingKey<OuterPairing>, VerifyingKey<OuterPairing>) {
    data_log_constants();
    debug!("trusted setup of main proof circuit...");
    let circuit = MainProofCircuit {
        ctx: ProofContext::default_with_params(crypto_params)
    };
    time_measure!("gm17_setup", let keys = GM17::circuit_specific_setup(circuit, rng).unwrap());
    debug!("circuit setup successful");
    keys
}

pub fn generate_main_proof<R: Rng + CryptoRng>(rng: &mut R, pk: &Option<ProvingKey<OuterPairing>>, ctx: ProofContext) -> Option<MainProof> {
    if pk.is_some() {
        debug!("generating main proof...");
        let circuit = MainProofCircuit {
            ctx
        };
        let proof = MainProof(GM17::prove(pk.as_ref().unwrap(), circuit, rng).unwrap());
        debug!("successfully generated proof");
        Some(proof)
    } else {
        info!("skipped proof generation, only checking circuit satisfaction");
        let circuit = MainProofCircuit {
            ctx
        };
        // check circuit satisfaction
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        if !cs.is_satisfied().unwrap() {
            let unsat_name = cs.which_is_unsatisfied().unwrap().unwrap();
            panic!("proof circuit not satisfied, constraint: {}", unsat_name);
        }
        None
    }
}


pub struct MainProofVerifier {
    pub verifier_key: VerifyingKey<OuterPairing>
}

impl MainProofVerifier {
    pub fn new(verifier_key: VerifyingKey<OuterPairing>) -> MainProofVerifier {
        MainProofVerifier { verifier_key }
    }

    pub fn verify(&self,
        unique_seed: &[u8; RAND_BYTES],
        merkle_tree_root: &MerkleTreeRoot,
        consumed_serials: &[Serial],
        new_records: &[EncryptedRecord],
        called_class_id: OuterScalarField,
        called_function_id: OuterScalarField,
        instructions: &[ZkInstruction],
        current_time: OuterScalarField,
        proof: &MainProof
    ) -> bool {
        assert_eq!(consumed_serials.len(), NOF_TX_RECORDS);
        assert_eq!(new_records.len(), NOF_TX_RECORDS);
        
        // pad program with NOOPs
        assert!(instructions.len() <= NOF_PROCESSOR_CYCLES, "too many instructions (got: {}, max: {})", instructions.len(), NOF_PROCESSOR_CYCLES);
        let mut padded_instructions = instructions.to_vec();
        for _ in 0..(NOF_PROCESSOR_CYCLES - instructions.len()) {
            padded_instructions.push(ZkInstruction::default());
        }

        // collect public circuit inputs
        let mut input = vec![];
        input.extend_from_slice(&unique_seed.to_field_elements().unwrap());
        input.push(merkle_tree_root.0);
        input.push(called_class_id);
        input.push(called_function_id);
        for serial in consumed_serials {
            input.extend_from_slice(&serial.to_field_elements().unwrap());
        }
        for record in new_records {
            input.extend_from_slice(&record.to_field_elements().unwrap());
        }
        for inst in padded_instructions {
            input.extend_from_slice(&inst.to_field_elements().unwrap());
        }
        input.push(current_time);
        
        debug!("verifying proof...");
        let res = GM17::verify(&self.verifier_key, &input, &proof.0).unwrap();
        debug!("verification result: {:?}", res);
        res
    }
}

#[derive(Clone)]
pub struct MainProof(pub Proof<OuterPairing>);

impl ToBytes for MainProof {
    fn write<W: ark_serialize::Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.write(writer)
    }
}

impl FromBytes for MainProof {
    fn read<R: ark_serialize::Read>(mut reader: R) -> std::io::Result<Self> {
        let a = <OuterPairing as PairingEngine>::G1Affine::read(&mut reader)?;
        let b = <OuterPairing as PairingEngine>::G2Affine::read(&mut reader)?;
        let c = <OuterPairing as PairingEngine>::G1Affine::read(&mut reader)?;
        Ok(MainProof(Proof {
            a,
            b,
            c
        }))
    }
}

pub struct EncParams {
    pub elgamal_params: MyParametersVar<InnerEdProjective, InnerEdVar>,
    pub poseidon_params: PoseidonParameters<OuterScalarField>
}

pub struct EncryptedRecordVar {
    key_part: elgamal::constraints::OutputVar<InnerEdProjective, InnerEdVar>,
    data_elems: Vec<OuterScalarVar>,
    nonce: OuterScalarVar
}

impl AllocVar<EncryptedRecord, OuterScalarField> for EncryptedRecordVar {
    fn new_variable<T: std::borrow::Borrow<EncryptedRecord>>(
        cs: impl Into<ark_relations::r1cs::Namespace<OuterScalarField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let enc_record = f()?;
        let key_part = elgamal::constraints::OutputVar::<InnerEdProjective, InnerEdVar>::new_variable(cs.clone(), || Ok(enc_record.borrow().0.key_part), mode)?;
        let data_elems = enc_record.borrow().0.data_part.elems.iter().map(|fe| OuterScalarVar::new_variable(cs.clone(), || Ok(fe), mode).unwrap()).collect();
        let nonce = OuterScalarVar::new_variable(cs, || Ok(enc_record.borrow().0.data_part.nonce), mode)?;
        Ok(EncryptedRecordVar {
            key_part,
            data_elems,
            nonce
        })
    }
}

impl ToBytesGadget<OuterScalarField> for EncryptedRecordVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<OuterScalarField>>, SynthesisError> {
        let mut v = vec![];
        v.extend_from_slice(&self.key_part.c1.to_bytes()?);
        v.extend_from_slice(&self.key_part.c2.to_bytes()?);
        v.extend_from_slice(&self.nonce.to_bytes()?);
        for elem in self.data_elems.iter() {
            v.extend_from_slice(&elem.to_bytes()?);
        }
        Ok(v)
    }
}

impl ToConstraintField<OuterScalarField> for EncryptedRecord {
    fn to_field_elements(&self) -> Option<Vec<OuterScalarField>> {
        let mut elems = vec![];
        elems.extend_from_slice(&self.0.key_part.0.to_field_elements()?);
        elems.extend_from_slice(&self.0.key_part.1.to_field_elements()?);
        elems.extend_from_slice(&self.0.data_part.elems);
        elems.push(self.0.data_part.nonce);
        Some(elems)
    }
}

pub struct RecordVar {
    pub serial_nonce: OuterScalarVar,
    pub contract_id: OuterScalarVar,
    pub object_id: OuterScalarVar,
    pub sk_object: OuterScalarVar,
    pub addr_object: OuterScalarVar,
    pub addr_owner: OuterScalarVar,
    pub payload: Vec<OuterScalarVar>,
}

impl AllocVar<Record, OuterScalarField> for RecordVar {
    fn new_variable<T: std::borrow::Borrow<Record>>(
        cs: impl Into<ark_relations::r1cs::Namespace<OuterScalarField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let record = f()?;
        let record = record.borrow();
        let serial_nonce = OuterScalarVar::new_variable(cs.clone(), || Ok(record.serial_nonce), mode)?;
        let contract_id = OuterScalarVar::new_variable(cs.clone(), || Ok(record.contract_id), mode)?;
        let object_id = OuterScalarVar::new_variable(cs.clone(), || Ok(record.object_id), mode)?;
        let sk_object = OuterScalarVar::new_variable(cs.clone(), || Ok(record.sk_object), mode)?;
        let addr_object = OuterScalarVar::new_variable(cs.clone(), || Ok(record.addr_object), mode)?;
        let addr_owner = OuterScalarVar::new_variable(cs.clone(), || Ok(record.addr_owner), mode)?;
        let payload = record.payload.iter().map(|elem: &OuterScalarField| OuterScalarVar::new_variable(cs.clone(), || Ok(elem), mode).unwrap()).collect();
        Ok(RecordVar {
            serial_nonce,
            contract_id,
            object_id,
            sk_object,
            addr_object,
            addr_owner,
            payload
        })
    }
}

impl RecordVar {
    pub fn to_encryption_data(&self) -> Vec<OuterScalarVar> {
        let mut data = vec![
           self.serial_nonce.clone(),
           self.contract_id.clone(),
           self.object_id.clone(),
           self.sk_object.clone(),
           self.addr_object.clone(),
           self.addr_owner.clone()
        ];
        data.extend_from_slice(&self.payload);
        data
    }
}

pub struct EncRandomnessVar {
    elgamal_rand: Vec<UInt8<OuterScalarField>>,
    shared_key: InnerEdVar
}

impl AllocVar<EncRandomness, OuterScalarField> for EncRandomnessVar {
    fn new_variable<T: std::borrow::Borrow<EncRandomness>>(
        cs: impl Into<ark_relations::r1cs::Namespace<OuterScalarField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let rand = f()?;
        let elgamal_rand_bytes = to_bytes!(rand.borrow().0).unwrap();
        let elgamal_rand_bytes_v = match mode {
                AllocationMode::Constant => UInt8::constant_vec(&elgamal_rand_bytes),
                AllocationMode::Input => UInt8::new_input_vec(cs.clone(), &elgamal_rand_bytes).unwrap(),
                AllocationMode::Witness => UInt8::new_witness_vec(cs.clone(), &elgamal_rand_bytes).unwrap(),
            };
        let shared_key_v = InnerEdVar::new_variable(cs, || Ok(rand.borrow().1), mode).unwrap();
        Ok(EncRandomnessVar {
            elgamal_rand: elgamal_rand_bytes_v,
            shared_key: shared_key_v
        })
    }
}

fn check_record_decryption(
    cs: &ConstraintSystemRef<OuterScalarField>,
    enc_params: &EncParams,
    sk: &SecretKeyVar<OuterScalarField>,
    enc_record: &EncryptedRecordVar,
    record: &RecordVar
) -> Boolean<OuterScalarField> {
    let shared_key = ElGamalDecGadget::<InnerEdProjective, InnerEdVar>::decrypt(sk, &enc_record.key_part).unwrap();

    let msg_len = OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(RECORD_CHUNKS as u64)).unwrap();
    let data = record.to_encryption_data();
    let check_cipher = PoseidonCipherGadget::encrypt_with_expanded_key(cs, &enc_params.poseidon_params, &shared_key, enc_record.nonce.clone(), &data, &msg_len).unwrap();
    let mut ok = Boolean::TRUE;
    for i in 0..RECORD_CHUNKS_PADDED+1 {
        ok = ok.and(&check_cipher[i].is_eq(&enc_record.data_elems[i]).unwrap()).unwrap();
    }
    ok
}

fn check_record_encryption(
    cs: &ConstraintSystemRef<OuterScalarField>,
    enc_params: &EncParams,
    pk: &InnerEdVar,
    rand: &EncRandomnessVar,
    enc_record: &EncryptedRecordVar,
    record: &RecordVar
) -> Boolean<OuterScalarField> {
    let mut ok = Boolean::TRUE;
    let check_key_part = ElGamalEncGadget::encrypt(&enc_params.elgamal_params, &rand.shared_key, &rand.elgamal_rand, pk).unwrap();
    ok = ok.and(&check_key_part.0.is_eq(&enc_record.key_part.c1).unwrap()).unwrap();
    ok = ok.and(&check_key_part.1.is_eq(&enc_record.key_part.c2).unwrap()).unwrap();

    let msg_len = OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(RECORD_CHUNKS as u64)).unwrap();
    let data = record.to_encryption_data();
    let check_cipher = PoseidonCipherGadget::encrypt_with_expanded_key(cs, &enc_params.poseidon_params, &rand.shared_key, enc_record.nonce.clone(), &data, &msg_len).unwrap();
    for i in 0..RECORD_CHUNKS_PADDED+1 {
        ok = ok.and(&check_cipher[i].is_eq(&enc_record.data_elems[i]).unwrap()).unwrap();
    }
    ok
}

fn enforce_or_dummy(is_dummy: &Boolean<OuterScalarField>, check: Boolean<OuterScalarField>) -> ark_relations::r1cs::Result<()>  {
    check.or(is_dummy)?.enforce_equal(&Boolean::TRUE)
}

pub struct MainProofCircuit {
    pub ctx: ProofContext
}

impl MainProofCircuit {
    fn access_input(&self,
                    cs: &ConstraintSystemRef<OuterScalarField>,
                    root: &RootVar,
                    idx: usize,
                    leaf_hash_param: &LeafHashParamsVar,
                    inner_hash_param: &InnerHashParamsVar,
                    enc_params: &EncParams,
                    unique_seed_bits: &[Boolean<OuterScalarField>],
                ) -> ark_relations::r1cs::Result<(Boolean<OuterScalarField>, RecordVar)> {
        // check in_record_encrypted exists in merkle tree
        let is_dummy = Boolean::new_witness(ark_relations::ns!(cs, "in_is_dummy"), || Ok(self.ctx.in_records[idx].plaintext.is_dummy()))?;
        let in_record_encrypted = EncryptedRecordVar::new_witness(ark_relations::ns!(cs, "in_record_encrypted"), || Ok(self.ctx.in_records[idx].encrypted.clone()))?;
        constraints_measure!(cs, "verify_membership_merkle_tree", {
            let in_record_encrypted_bytes: Vec<_> = in_record_encrypted.to_bytes().unwrap();
            let path = MerklePathVar::new_witness(ark_relations::ns!(cs, "path"), || Ok(self.ctx.in_records[idx].path.clone().0))?;
            enforce_or_dummy(&is_dummy, path.verify_membership(leaf_hash_param, inner_hash_param, root, &in_record_encrypted_bytes.as_slice())?)?;
        });
    
        // check in_record is correctly decrypted
        let in_record = RecordVar::new_witness(ark_relations::ns!(cs, "in_record"), || Ok(self.ctx.in_records[idx].plaintext.clone()))?;
        let sk = SecretKeyVar::new_witness(ark_relations::ns!(cs, "in_sk"), || Ok(self.ctx.in_records[idx].sk.clone()))?;
        constraints_measure!(cs, "check_record_decryption", {
            enforce_or_dummy(&is_dummy, check_record_decryption(cs, enc_params, &sk, &in_record_encrypted, &in_record))?;
        });

        // check serial nonce correctly derived (for dummy inputs)
        constraints_measure!(cs, "derive_sn_nonce_dummy", {
            let rand_sn_nonce = UInt8::new_witness_vec(ark_relations::ns!(cs, "rand_dummy_sn_nonce"), &self.ctx.in_records[idx].rand_dummy_sn_nonce)?;
            let rand_sn_nonce_bits = rand_sn_nonce.to_bits_le()?;
            let is_ok = check_derive_fresh_sn_nonce(cs, &rand_sn_nonce_bits, (idx + NOF_TX_RECORDS) as u8, unique_seed_bits, &in_record.serial_nonce.to_bytes().unwrap())?;
            enforce_or_dummy(&is_dummy.not(), is_ok)?;  // NOTE: is_dummy flag inverted
        });

        // check serial number correctly derived
        constraints_measure!(cs, "derive_sn", {
            let sk_bits: Vec<_> = sk.0.to_bytes()?.iter().flat_map(|b| b.to_bits_le().unwrap()).collect();
            let serial_nonce_bits: Vec<_> = in_record.serial_nonce.to_bytes()?.iter().flat_map(|b| b.to_bits_le().unwrap()).collect();
            let actual_sn = UInt8::new_input_vec(cs.clone(), &self.ctx.in_records[idx].sn)?;
            let is_ok = check_derive_sn_from_nonce(cs, &sk_bits, &serial_nonce_bits, &actual_sn)?;
            enforce_true_with_info(&is_ok, "access_input - derive serial number");
        });

        Ok((is_dummy, in_record))
    } 

    fn access_output(&self,
                    cs: &ConstraintSystemRef<OuterScalarField>,
                    idx: usize,
                    enc_params: &EncParams,
                    unique_seed_bits: &[Boolean<OuterScalarField>],
                ) -> ark_relations::r1cs::Result<(Boolean<OuterScalarField>, RecordVar)> {
        let out_record = RecordVar::new_witness(ark_relations::ns!(cs, "out_record"), || Ok(self.ctx.out_records[idx].plaintext.clone()))?;
        
        // check out_record.serial_nonce correctly derived
        constraints_measure!(cs, "derive_sn_nonce", {
            let rand_sn_nonce = UInt8::new_witness_vec(ark_relations::ns!(cs, "rand_sn_nonce"), &self.ctx.out_records[idx].rand_sn_nonce)?;
            let rand_sn_nonce_bits = rand_sn_nonce.to_bits_le()?;
            let is_ok = check_derive_fresh_sn_nonce(cs, &rand_sn_nonce_bits, idx as u8, unique_seed_bits, &out_record.serial_nonce.to_bytes().unwrap())?;
            enforce_true_with_info(&is_ok, "access_output - derive serial nonce");
        });

        // check owner public key correctly derived from owner address
        let pk_owner = InnerEdVar::new_witness(cs.clone(), || Ok(self.ctx.out_records[idx].pk_owner))?;
        constraints_measure!(cs, "derive_owner_public_key", {
            let check_owner_addr = get_addr_for_pk_var(&pk_owner);
            enforce_true_with_info(&check_owner_addr.is_eq(&out_record.addr_owner)?, "access_output - owner public key derivation");
        });
    
        // check out_record_encrypted correctly encrypted
        constraints_measure!(cs, "check_record_encryption", {
            let out_record_encrypted = EncryptedRecordVar::new_input(ark_relations::ns!(cs, "out_record_encrypted"), || Ok(self.ctx.out_records[idx].encrypted.clone()))?;
            let rand_enc = EncRandomnessVar::new_witness(ark_relations::ns!(cs, "rand_enc"), || Ok(self.ctx.out_records[idx].rand_encryption))?;
            enforce_true_with_info(&check_record_encryption(cs, enc_params, &pk_owner, &rand_enc, &out_record_encrypted, &out_record),
                "access_output - record encryption");
        });

        // records with object id = 0 are dummy records
        let is_dummy = out_record.object_id.is_zero()?;
        Ok((is_dummy, out_record))
    }

    fn derive_fresh_oids(&self,
        cs: &ConstraintSystemRef<OuterScalarField>,
        unique_seed_bits: &[Boolean<OuterScalarField>]
    ) -> ark_relations::r1cs::Result<Vec<OuterScalarVar>> {
        let oids = (0..NOF_TX_FRESH).map(|i| {
            let rand_oid = UInt8::new_witness_vec(cs.clone(), &self.ctx.rand_oid[i]).unwrap();
            let rand_oid_bits = rand_oid.to_bits_le().unwrap();
            derive_fresh_object_id_var(cs, &rand_oid_bits, i as u8, unique_seed_bits).unwrap()
        }).collect();
        Ok(oids)
    }

    fn derive_fresh_obj_sks(&self,
        cs: &ConstraintSystemRef<OuterScalarField>,
        unique_seed_bits: &[Boolean<OuterScalarField>],
        enc_params: &MyParametersVar::<InnerEdProjective, InnerEdVar>
    ) -> ark_relations::r1cs::Result<Vec<OuterScalarVar>> {
        let sks = (0..NOF_TX_FRESH).map(|i| {
            let rand_sk = UInt8::new_witness_vec(cs.clone(), &self.ctx.rand_sk[i]).unwrap();
            let rand_sk_bits: Vec<_> = rand_sk.iter().flat_map(|byte| byte.to_bits_le().unwrap()).collect();
            derive_and_check_fresh_object_sk_var(cs, &rand_sk_bits, i as u8, unique_seed_bits, enc_params).unwrap()
        }).collect();
        Ok(sks)
    }

    fn derive_fresh_values(&self,
        cs: &ConstraintSystemRef<OuterScalarField>,
        unique_seed_bits: &[Boolean<OuterScalarField>]
    ) -> ark_relations::r1cs::Result<Vec<OuterScalarVar>> {
        let vals = (0..NOF_TX_FRESH).map(|i| {
            let rand_fresh_vals = UInt8::new_witness_vec(cs.clone(), &self.ctx.rand_fresh_vals[i]).unwrap();
            let rand_fresh_vals_bits = rand_fresh_vals.to_bits_le().unwrap();
            derive_fresh_value_var(cs, &rand_fresh_vals_bits, i as u8, unique_seed_bits).unwrap()
        }).collect();
        Ok(vals)
    }

    fn get_and_authenticate_sender(&self,
        cs: &ConstraintSystemRef<OuterScalarField>,
        enc_params: &EncParams
    ) -> ark_relations::r1cs::Result<OuterScalarVar> {
        let sender_address = OuterScalarVar::new_witness(cs.clone(), || Ok(self.ctx.sender_address))?;

        // ensure sender address is a valid external account
        enforce_true_with_info(&is_external_account(&sender_address)?, "is_external_account");

        // authenticate the sender by checking knowledge of the sender secret key
        let sender_sk_bytes = UInt8::new_witness_vec(cs.clone(), &self.ctx.sender_sk_bytes)?;
        let check_pk = ElGamalKeyGadget::derive_pk(&SecretKeyVar(sender_sk_bytes), &enc_params.elgamal_params)?;
        let check_address = get_addr_for_pk_var(&check_pk);
        enforce_true_with_info(&check_address.is_eq(&sender_address)?, "sender knows secret key");

        Ok(sender_address)
    }

    fn run_processor(&self,
        cs: &ConstraintSystemRef<OuterScalarField>,
        enc_param: &EncParams,
        unique_seed_bits: &[Boolean<OuterScalarField>],
        in_is_dummy: &[Boolean<OuterScalarField>],
        in_records: &[RecordVar],
        out_is_dummy: &[Boolean<OuterScalarField>],
        out_records: &[RecordVar],
        sender_address: &OuterScalarVar,
    ) -> ark_relations::r1cs::Result<()> {
        // derive fresh values
        let fresh_oids;
        let fresh_obj_sks;
        let fresh_values;
        constraints_measure!(cs, "derive_fresh_values", {
            fresh_oids = self.derive_fresh_oids(cs, unique_seed_bits)?;
            fresh_obj_sks = self.derive_fresh_obj_sks(cs, unique_seed_bits, &enc_param.elgamal_params)?;
            fresh_values = self.derive_fresh_values(cs, unique_seed_bits)?;
            dbg_ensure_satisfied(cs, "processor - deriving fresh values");
        });

        // check starting state matches (in_records, fresh_*), and final state matches out_records
        let states: Vec<_> = self.ctx.processor_states.iter().map(|st| ZkProcessorStateVar::new_witness(cs.clone(), || Ok(st)).unwrap()).collect();
        let initial_state = &states[0];
        let final_state = &states[states.len()-1];

        constraints_measure!(cs, "processor_state_matching", {
            // check matching sender address (first argument of processor)
            initial_state.registers[0].enforce_equal(sender_address)?;
            dbg_ensure_satisfied(cs, "processor - checking matching sender address");

            // check inputs and outputs
            for i in 0..NOF_TX_FRESH {
                initial_state.new_oids[i].enforce_equal(&fresh_oids[i])?;
                initial_state.new_obj_sks[i].enforce_equal(&fresh_obj_sks[i])?;
                initial_state.fresh_vals[i].enforce_equal(&fresh_values[i])?;
                dbg_ensure_satisfied(cs, &format!("processor - checking matching fresh values, i = {}", i));
            }
            for i in 0..NOF_TX_RECORDS {
                initial_state.obj_data[i].is_empty.enforce_equal(&in_is_dummy[i].clone().into())?;
                initial_state.obj_data[i].contract_id.is_eq(&in_records[i].contract_id)?.or(&in_is_dummy[i])?.enforce_equal(&Boolean::TRUE)?;
                initial_state.obj_data[i].object_id.is_eq(&in_records[i].object_id)?.or(&in_is_dummy[i])?.enforce_equal(&Boolean::TRUE)?;
                initial_state.obj_data[i].sk_object.is_eq(&in_records[i].sk_object)?.or(&in_is_dummy[i])?.enforce_equal(&Boolean::TRUE)?;
                initial_state.obj_data[i].addr_object.is_eq(&in_records[i].addr_object)?.or(&in_is_dummy[i])?.enforce_equal(&Boolean::TRUE)?;
                initial_state.obj_data[i].payload[0].is_eq(&in_records[i].addr_owner)?.or(&in_is_dummy[i])?.enforce_equal(&Boolean::TRUE)?;
                for j in 0..NOF_RECORD_PAYLOAD_ELEMENTS {
                    initial_state.obj_data[i].payload[1+j].is_eq(&in_records[i].payload[j])?.or(&in_is_dummy[i])?.enforce_equal(&Boolean::TRUE)?;
                }
                dbg_ensure_satisfied(cs, &format!("processor - checking matching input i = {}", i));

                final_state.obj_data[i].is_empty.enforce_equal(&out_is_dummy[i].clone().into())?;
                final_state.obj_data[i].contract_id.is_eq(&out_records[i].contract_id)?.or(&out_is_dummy[i])?.enforce_equal(&Boolean::TRUE)?;
                final_state.obj_data[i].object_id.is_eq(&out_records[i].object_id)?.or(&out_is_dummy[i])?.enforce_equal(&Boolean::TRUE)?;
                final_state.obj_data[i].sk_object.is_eq(&out_records[i].sk_object)?.or(&out_is_dummy[i])?.enforce_equal(&Boolean::TRUE)?;
                final_state.obj_data[i].addr_object.is_eq(&out_records[i].addr_object)?.or(&out_is_dummy[i])?.enforce_equal(&Boolean::TRUE)?;
                final_state.obj_data[i].payload[0].is_eq(&out_records[i].addr_owner)?.or(&out_is_dummy[i])?.enforce_equal(&Boolean::TRUE)?;
                for j in 0..NOF_RECORD_PAYLOAD_ELEMENTS {
                    final_state.obj_data[i].payload[1+j].is_eq(&out_records[i].payload[j])?.or(&out_is_dummy[i])?.enforce_equal(&Boolean::TRUE)?;
                }
                dbg_ensure_satisfied(cs, &format!("processor - checking matching output i = {}", i));
            }
        });

        // run get instructions and run processor
        let instructions: Vec<_> = self.ctx.processor_instructions.iter().map(|inst| ZkInstructionVar::new_input(cs.clone(), || Ok(inst)).unwrap()).collect();
        let current_time = OuterScalarVar::new_input(cs.clone(), || Ok(self.ctx.processor_current_time))?;
        constraints_measure!(cs, "processor_gadget", {
            let processor = ZkProcessorGadget::new(cs.clone(),
                instructions,
                states,
                current_time
            );
            processor.run().unwrap();
        });
        dbg_ensure_satisfied(cs, "processor - run");

        Ok(())
    }
}

impl ConstraintSynthesizer<OuterScalarField> for MainProofCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<OuterScalarField>) -> ark_relations::r1cs::Result<()> {
        // prepare parameters
        let leaf_hash_param = LeafHashParamsVar::new_constant(cs.clone(), &self.ctx.crypto_params.leaf_hash_param)?;
        let inner_hash_param = InnerHashParamsVar::new_constant(cs.clone(), &self.ctx.crypto_params.inner_hash_param)?;
        let enc_params = EncParams {
            elgamal_params: MyParametersVar::<InnerEdProjective, InnerEdVar>::new_constant(cs.clone(), &self.ctx.crypto_params.enc_params.elgamal_params)?,
            poseidon_params: self.ctx.crypto_params.enc_params.poseidon_params.clone()
        };

        // get unique seed
        let unique_seed = UInt8::new_input_vec(cs.clone(), &self.ctx.unique_seed).unwrap();
        let unique_seed_bits: Vec<_> = unique_seed.iter().flat_map(|byte| byte.to_bits_le().unwrap()).collect();

        // get merkle tree root
        let root = RootVar::new_input(ark_relations::ns!(cs, "root"), || Ok(self.ctx.merkle_root.0))?;

        // get and check called function
        let called_class_id = OuterScalarVar::new_input(cs.clone(), || Ok(self.ctx.called_class_id)).unwrap();
        let called_function_id = OuterScalarVar::new_input(cs.clone(), || Ok(self.ctx.called_function_id)).unwrap();
        let called_class_id_check = OuterScalarVar::new_witness(cs.clone(), || Ok(self.ctx.called_class_id)).unwrap();
        let called_function_id_check = OuterScalarVar::new_witness(cs.clone(), || Ok(self.ctx.called_function_id)).unwrap();
        enforce_true_with_info(&called_class_id.is_eq(&called_class_id_check).unwrap(), "called class id matches");
        enforce_true_with_info(&called_function_id.is_eq(&called_function_id_check).unwrap(), "called function id matches");

        // check input records
        let mut in_is_dummy = vec![];
        let mut in_records = vec![];
        for i in 0..NOF_TX_RECORDS {
            constraints_measure!(cs, "access_input", {
                    let (is_dummy, plaintext) = self.access_input(&cs, &root, i, &leaf_hash_param, &inner_hash_param, &enc_params, &unique_seed_bits)?;
                    in_is_dummy.push(is_dummy);
                    in_records.push(plaintext);
            });
        }
        dbg_ensure_satisfied(&cs, "checking input records");
       
        // check output records
        let mut out_is_dummy = vec![];
        let mut out_records = vec![];
        for i in 0..NOF_TX_RECORDS {
            constraints_measure!(cs, "access_output", {
                let (is_dummy, plaintext) = self.access_output(&cs, i, &enc_params, &unique_seed_bits)?;
                out_is_dummy.push(is_dummy);
                out_records.push(plaintext);
            });
        }
        dbg_ensure_satisfied(&cs, "checking output records");

        // authenticate sender
        constraints_measure!(cs, "authenticate_sender",
            let sender_address = self.get_and_authenticate_sender(&cs, &enc_params)?
        );

        // run processor
        constraints_measure!(cs, "run_processor", {
            self.run_processor(&cs, &enc_params, &unique_seed_bits, &in_is_dummy, &in_records, &out_is_dummy, &out_records, &sender_address)?;
        });
        dbg_ensure_satisfied(&cs, "running processor");
        if cs.is_in_setup_mode() {
            data_log!(format!("{{\"constraints\": {{\"part\": \"{}\", \"num_constraints\": {}}}}}", "main_circuit", cs.num_constraints()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_std::test_rng;

    use super::*;

    #[test]
    fn test_proof_circuit_count_constraints() {
        data_log_constants();
        let mut rng = test_rng();
        let params = CryptoParams::setup(&mut rng);
        let num_constraints = count_constraints(params);
        println!("proof circuit constraints: {}", num_constraints);
    }
}