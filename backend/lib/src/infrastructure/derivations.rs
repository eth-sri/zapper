use ark_crypto_primitives::encryption::elgamal::SecretKey;
use blake2::{Digest, Blake2s};

use ark_ff::to_bytes;
use log::debug;
use rand::Rng;

use crate::common::*;
use crate::constants::*;
use crate::crypto::elgamal_ext::derive_pk_from_sk;

use super::params::CryptoParams;
use super::record::Serial;

/// Derives the serial number from a given serial nonce and secret key.
pub fn derive_sn_from_nonce(serial_nonce: &OuterScalarField, sk_bytes: &[u8; SERIALIZED_SK_BYTES]) -> Serial {
    let mut h = Blake2s::new();
    h.update(&[PRF_SN_SEED]);
    h.update(sk_bytes);
    h.update(&to_bytes!(serial_nonce).unwrap());

    let mut serial = [0u8; SN_BYTES];
    serial.copy_from_slice(&h.finalize());
    serial
}

/// Derives a fresh serial nonce for the `i`-th output record, given randomness `rand` and unique seed `unique_seed`
/// Returns `None` if no valid serial nonce could be derived (re-try using different randomness).
pub fn try_derive_fresh_sn_nonce(rand: &[u8; RAND_BYTES], i: u8, unique_seed: &[u8; RAND_BYTES]) -> Option<OuterScalarField> {
    assert!((i as usize) < 2*NOF_TX_RECORDS);

    let mut h = Blake2s::new();
    h.update(&[PRF_SN_NONCE_SEED]);
    h.update(rand);
    h.update(&[i]);
    h.update(unique_seed);

    let mut sn_nonce_bytes = [0u8; PRF_BLOCK_BYTES];
    sn_nonce_bytes.copy_from_slice(&h.finalize());
    FeConverter::from_le_bytes(&sn_nonce_bytes)
}

/// Derives a fresh object id for the `i`-th new object, given randomness `rand` and unique seed `unique_seed`
/// Returns `None` if no valid object id could be derived (re-try using different randomness).
pub fn try_derive_fresh_object_id(rand: &[u8; RAND_BYTES], i: u8, unique_seed: &[u8; RAND_BYTES]) -> Option<OuterScalarField> {
    assert!((i as usize) < NOF_TX_FRESH);

    let mut h = Blake2s::new();
    h.update(&[PRF_OID_SEED]);
    h.update(rand);
    h.update(&[i]);
    h.update(unique_seed);

    let mut oid_bytes = [0u8; PRF_BLOCK_BYTES];
    oid_bytes.copy_from_slice(&h.finalize());
    FeConverter::from_le_bytes(&oid_bytes)
}

/// Derives the `i`-th fresh value, given randomness `rand` and unique seed `unique_seed`.
/// Returns `None` if no valid fresh value could be derived (re-try using different randomness).
pub fn try_derive_fresh_value(rand: &[u8; RAND_BYTES], i: u8, unique_seed: &[u8; RAND_BYTES]) -> Option<OuterScalarField> {
    assert!((i as usize) < NOF_TX_FRESH);

    let mut h = Blake2s::new();
    h.update(&[PRF_FRESH_VAL_SEED]);
    h.update(rand);
    h.update(&[i]);
    h.update(unique_seed);

    let mut fresh_bytes = [0u8; RAND_BYTES];
    fresh_bytes.copy_from_slice(&h.finalize());
    FeConverter::from_le_bytes(&fresh_bytes)
}


/// Returns `true` iff `addr` is the address of an external account.
pub fn is_external_account(addr: &OuterScalarField) -> bool {
    // check if least significant bit of the address is 1
    let ls_byte = to_bytes!(addr).unwrap()[0];
    (ls_byte & 1u8) == 1u8
}

/// Returns the address derived from the given public key `pk`.
pub fn get_addr_for_pk(pk: &InnerEdAffine) -> OuterScalarField {
    // we use the x-coordinate as the address
    pk.x
}

/// Tries to reconstruct the public key for the given address `addr`.
/// Returns `None` not possible.
pub fn try_get_pk_for_addr(addr: &OuterScalarField) -> Option<InnerEdAffine> {
    InnerEdAffine::get_point_from_x(*addr, false)
}

/// Reconstructs the public key for the given address `addr`.
pub fn get_pk_for_addr(addr: &OuterScalarField) -> InnerEdAffine {
    try_get_pk_for_addr(addr).unwrap()
}

/// Checks if `pk` is reconstructable from its x coordinate.
pub fn is_reconstructable(pk: &InnerEdAffine) -> bool {
    let pk_check = get_pk_for_addr(&get_addr_for_pk(pk));
    *pk == pk_check
}

/// Derives a fresh object secret key for the `i`-th new object, given randomness and unique seed
/// without checking that the corresponding public key is actually an object secret key.
/// Returns `None` if no valid secret key could be derived (re-try using different randomness).
fn try_derive_fresh_object_sk_no_pk_check(rand: &[u8; RAND_BYTES], i: u8, unique_seed: &[u8; RAND_BYTES]) -> Option<InnerEdScalarField> {
    assert!((i as usize) < NOF_TX_FRESH);

    let mut h = Blake2s::new();
    h.update(&[PRF_SK_SEED]);
    h.update(rand);
    h.update(&[i]);
    h.update(unique_seed);

    let mut sk_bytes = [0u8; PRF_BLOCK_BYTES];
    sk_bytes.copy_from_slice(&h.finalize());
    FeConverter::from_le_bytes(&sk_bytes)
}

/// Derives a fresh object secret key (whose public key is guaranteed to be an object public key) for the `i`-th output record, given the unique seed.
/// Returns a tuple `(rand, sk)`, where `rand` is the randomness used to derive the secret key `sk`.
pub fn derive_fresh_object_sk<R: Rng>(rng: &mut R, crypto_params: &CryptoParams, i: u8, unique_seed: &[u8; RAND_BYTES]) -> ([u8; RAND_BYTES], InnerEdScalarField) {
    let mut rand = [0u8; RAND_BYTES];
    loop {
        rng.fill_bytes(&mut rand);
        if let Some(sk) = try_derive_fresh_object_sk_no_pk_check(&rand, i, unique_seed) {
            let sk = SecretKey(sk);
            let pk = derive_pk_from_sk(&crypto_params.enc_params.elgamal_params, &sk);
            if is_reconstructable(&pk) {
                if !is_external_account(&get_addr_for_pk(&pk)) {
                    debug!("successfully derived fresh object sk {:?} for object account", &sk.0);
                    return (rand, sk.0);
                }
            }
        }
    }
}

pub mod constraints {
    use crate::common::*;
    use crate::constants::*;
    use crate::crypto::elgamal_ext::ElGamalKeyGadget;
    use crate::crypto::elgamal_ext::MyParametersVar;
    use crate::crypto::elgamal_ext::SecretKeyVar;
    use ark_crypto_primitives::prf::blake2s::constraints::evaluate_blake2s;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystemRef;

    fn compute_prf(input: &[Boolean<OuterScalarField>]) -> ark_relations::r1cs::Result<Vec<UInt8<OuterScalarField>>> {
        Ok(evaluate_blake2s(input)?.iter().flat_map(|int| int.to_bytes().unwrap()).collect())
    }

    pub fn check_derive_sn_from_nonce(cs: &ConstraintSystemRef<OuterScalarField>,
            sk_bits: &[Boolean<OuterScalarField>],
            sn_nonce_bits: &[Boolean<OuterScalarField>],
            check_sn: &[UInt8<OuterScalarField>]
    ) -> ark_relations::r1cs::Result<Boolean<OuterScalarField>> {
        let mut hash_input_bits = UInt8::new_constant(cs.clone(), PRF_SN_SEED)?.to_bits_le()?;
        hash_input_bits.extend_from_slice(sk_bits);
        hash_input_bits.extend_from_slice(sn_nonce_bits);

        let computed_sn = compute_prf(&hash_input_bits)?;
        let res = computed_sn.is_eq(check_sn)?;
        Ok(res)
    }

    pub fn check_derive_fresh_sn_nonce(cs: &ConstraintSystemRef<OuterScalarField>,
            rand_bits: &[Boolean<OuterScalarField>],
            i: u8,
            unique_seed_bits: &[Boolean<OuterScalarField>],
            check_sn_nonce: &[UInt8<OuterScalarField>]
    ) -> ark_relations::r1cs::Result<Boolean<OuterScalarField>> {
        let mut hash_input_bits = UInt8::new_constant(cs.clone(), PRF_SN_NONCE_SEED)?.to_bits_le()?;
        hash_input_bits.extend_from_slice(rand_bits);
        let i_bits = UInt8::new_constant(cs.clone(), i)?.to_bits_le()?;
        hash_input_bits.extend_from_slice(&i_bits);
        hash_input_bits.extend_from_slice(unique_seed_bits);

        let computed_sn_nonce = compute_prf(&hash_input_bits)?;
        let res = computed_sn_nonce.is_eq(check_sn_nonce)?;
        Ok(res)
    }

    pub fn derive_fresh_object_id_var(cs: &ConstraintSystemRef<OuterScalarField>,
        rand_bits: &[Boolean<OuterScalarField>],
        i: u8,
        unique_seed_bits: &[Boolean<OuterScalarField>]
    ) -> ark_relations::r1cs::Result<OuterScalarVar> {
        let mut hash_input_bits = UInt8::new_constant(cs.clone(), PRF_OID_SEED)?.to_bits_le()?;
        hash_input_bits.extend_from_slice(rand_bits);
        let i_bits = UInt8::new_constant(cs.clone(), i)?.to_bits_le()?;
        hash_input_bits.extend_from_slice(&i_bits);
        hash_input_bits.extend_from_slice(unique_seed_bits);

        let computed_oid_bytes = compute_prf(&hash_input_bits)?;
        let computed_oid_fe = Boolean::le_bits_to_fp_var(&computed_oid_bytes.to_bits_le()?)?;

        Ok(computed_oid_fe)
    }

    pub fn derive_fresh_value_var(cs: &ConstraintSystemRef<OuterScalarField>,
        rand_bits: &[Boolean<OuterScalarField>],
        i: u8,
        unique_seed_bits: &[Boolean<OuterScalarField>]
    ) -> ark_relations::r1cs::Result<OuterScalarVar> {
        let mut hash_input_bits = UInt8::new_constant(cs.clone(), PRF_FRESH_VAL_SEED)?.to_bits_le()?;
        hash_input_bits.extend_from_slice(rand_bits);
        let i_bits = UInt8::new_constant(cs.clone(), i)?.to_bits_le()?;
        hash_input_bits.extend_from_slice(&i_bits);
        hash_input_bits.extend_from_slice(unique_seed_bits);

        let computed_fresh_bytes = compute_prf(&hash_input_bits)?;
        let computed_fresh_fe = Boolean::le_bits_to_fp_var(&computed_fresh_bytes.to_bits_le()?)?;

        Ok(computed_fresh_fe)
    }

    pub fn get_addr_for_pk_var(pk: &InnerEdVar) -> OuterScalarVar {
        pk.x.clone()
    }

    pub fn is_external_account(addr: &OuterScalarVar)
    -> ark_relations::r1cs::Result<Boolean<OuterScalarField>> {
        let ls_bit = addr.to_bits_le()?[0].clone();
        Ok(ls_bit)
    }

    pub fn derive_and_check_fresh_object_sk_var(cs: &ConstraintSystemRef<OuterScalarField>,
        rand_bits: &[Boolean<OuterScalarField>],
        i: u8,
        unique_seed_bits: &[Boolean<OuterScalarField>],
        enc_param: &MyParametersVar<InnerEdProjective, InnerEdVar>
    ) -> ark_relations::r1cs::Result<OuterScalarVar> {
        // first, compute the secret key based on the hash function
        let mut hash_input_bits = UInt8::new_constant(cs.clone(), PRF_SK_SEED)?.to_bits_le()?;
        hash_input_bits.extend_from_slice(rand_bits);
        let i_bits = UInt8::new_constant(cs.clone(), i)?.to_bits_le()?;
        hash_input_bits.extend_from_slice(&i_bits);
        hash_input_bits.extend_from_slice(unique_seed_bits);
        let computed_sk_bytes = compute_prf(&hash_input_bits)?;

        // NOTE: this enforces the bytes to be a valid OuterScalarField element
        let sk_bits: Vec<_> = computed_sk_bytes.iter().flat_map(|byte| byte.to_bits_le().unwrap()).collect();
        let sk_fe: OuterScalarVar = Boolean::le_bits_to_fp_var(&sk_bits)?;

        // then, enforce the corresponding public key is a an object account (no external account)
        let pk = ElGamalKeyGadget::<InnerEdProjective, InnerEdVar>::derive_pk(&SecretKeyVar(computed_sk_bytes), enc_param)?;
        is_external_account(&get_addr_for_pk_var(&pk))?.enforce_equal(&Boolean::FALSE)?;

        Ok(sk_fe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::encryption::elgamal::Parameters;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::test_rng;
    use rand::RngCore;

    use crate::{constants::RAND_BYTES, common::{OuterScalarField, InnerEdProjective, InnerEdVar, OuterScalarVar}, crypto::elgamal_ext::MyParametersVar};

    struct FreshObjectSkCircuit {
        rand: [u8; RAND_BYTES],
        unique_seed: [u8; RAND_BYTES],
        enc_params: Parameters<InnerEdProjective>,
        expected_sk: OuterScalarField
    }

    impl ConstraintSynthesizer<OuterScalarField> for FreshObjectSkCircuit {
        fn generate_constraints(self, cs: ark_relations::r1cs::ConstraintSystemRef<OuterScalarField>) -> ark_relations::r1cs::Result<()> {
            let rand_var: Vec<_> = self.rand.iter().flat_map(|byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap().to_bits_le().unwrap()).collect();
            let enc_params_var = MyParametersVar::<InnerEdProjective, InnerEdVar>::new_constant(cs.clone(), self.enc_params)?;
            let unique_seed_var: Vec<_> = self.unique_seed.iter().flat_map(|byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap().to_bits_le().unwrap()).collect();

            let expected_sk = OuterScalarVar::new_constant(cs.clone(), self.expected_sk)?;
            let derived_sk = constraints::derive_and_check_fresh_object_sk_var(&cs, &rand_var, 0u8, &unique_seed_var, &enc_params_var)?;
            expected_sk.enforce_equal(&derived_sk)?;

            Ok(())
        }
    }

    #[test]
    fn test_derive_and_check_fresh_object_sk_var() {
        let mut rng = test_rng();
        let params = CryptoParams::setup(&mut rng);
        let mut unique_seed = [0u8; RAND_BYTES];
        rng.fill_bytes(&mut unique_seed);
        let (rand, expected_sk) = derive_fresh_object_sk(&mut rng, &params, 0u8, &unique_seed);
        let expected_sk = FeConverter::to_larger(&expected_sk);

        let circ = FreshObjectSkCircuit {
            rand,
            unique_seed,
            enc_params: params.enc_params.elgamal_params,
            expected_sk
        };

        let cs = ConstraintSystem::<OuterScalarField>::new_ref();
        circ.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}