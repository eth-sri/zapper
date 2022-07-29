use std::ops::{Mul, Add};

use ark_crypto_primitives::encryption::{elgamal::{PublicKey, ElGamal, Parameters as ElGamalParameters, Randomness, SecretKey}, AsymmetricEncryptionScheme};
use ark_sponge::FieldBasedCryptographicSponge;
use ark_sponge::poseidon::{traits::find_poseidon_ark_and_mds, PoseidonParameters};
use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ff::{Zero, Field};
use ark_std::{UniformRand, rand::Rng};
use ark_r1cs_std::prelude::*;

use crate::common::*;

// Poseidon hash defined in:
// [1] POSEIDON: A New Hash Function for Zero-Knowledge Proof Systems
//     Lorenzo Grassi, Dmitry Khovratovich, Christian Rechberger, Arnab Roy, and Markus Schofnegger
//     USENIX Security '21
//     https://eprint.iacr.org/2019/458

// Parameters according to Appendix G, Table 8 in [1]
//     Prime p = 52435875175126190479447740508185965837690552500527637822603658699938581184513 (JubJub base field prime)
//     Security M = 128
//     Prime bits: 255
//     Width t = 4
//     S-box alpha = 5
//     Rf = 8
//     Rp = 56
const POSEIDON_JUBJUB_PRIME_BITS: u64 = 255;
const POSEIDON_JUBJUB_RATE: usize = 3;
const POSEIDON_JUBJUB_CAPACITY: usize = 1;  // width = rate + capacity
const POSEIDON_JUBJUB_FULL_ROUNDS: usize = 8;
const POSEIDON_JUBJUB_PARTIAL_ROUNDS: usize = 56;
const POSEIDON_JUBJUB_ALPHA: u64 = 5;

fn get_poseidon_jubjub_parameters() -> PoseidonParameters<OuterScalarField> {
    let (ark, mds) = find_poseidon_ark_and_mds(POSEIDON_JUBJUB_PRIME_BITS, POSEIDON_JUBJUB_RATE, POSEIDON_JUBJUB_FULL_ROUNDS as u64, POSEIDON_JUBJUB_PARTIAL_ROUNDS as u64, 0);
    PoseidonParameters::new(POSEIDON_JUBJUB_FULL_ROUNDS, POSEIDON_JUBJUB_PARTIAL_ROUNDS, POSEIDON_JUBJUB_ALPHA, mds, ark, POSEIDON_JUBJUB_RATE, POSEIDON_JUBJUB_CAPACITY)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoseidonCiphertext {
    pub elems: Vec<OuterScalarField>,
    pub nonce: OuterScalarField,
    pub msg_len: usize
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridPoseidonCiphertext {
    pub key_part: (InnerEdAffine, InnerEdAffine),
    pub data_part: PoseidonCiphertext
}

pub struct HybridPoseidonParams {
    pub poseidon_params: PoseidonParameters<OuterScalarField>,
    pub elgamal_params: ElGamalParameters<InnerEdProjective>
}

impl Clone for HybridPoseidonParams {
    fn clone(&self) -> Self {
        Self {
            poseidon_params: self.poseidon_params.clone(),
            elgamal_params: ElGamalParameters {
                generator: self.elgamal_params.generator
            }
        }
    }
}

pub struct HybridPoseidonCipher;

impl HybridPoseidonCipher {
    pub fn setup<R: Rng>(rng: &mut R) -> HybridPoseidonParams {
        HybridPoseidonParams {
            poseidon_params: get_poseidon_jubjub_parameters(),
            elgamal_params: ElGamal::setup(rng).unwrap()
        }
    }

    pub fn encrypt_hybrid<R: Rng>(params: &HybridPoseidonParams, pk: &PublicKey<InnerEdProjective>, msg: &[OuterScalarField], rng: &mut R) -> (HybridPoseidonCiphertext, InnerEdScalarField, InnerEdAffine) {
        // select a fresh shared key
        let shared_key = InnerEdAffine::rand(rng); 

        // first, encrypt the shared key using ElGamal
        let elgamal_rand = InnerEdScalarField::rand(rng);
        let key_part = ElGamal::encrypt(&params.elgamal_params, pk, &shared_key, &Randomness(elgamal_rand)).unwrap();

        // then, encrypt the payload using Poseidon
        let nonce = Self::get_rand_nonce(rng);
        let data_part = Self::encrypt_with_shared_key(params, &shared_key, nonce, msg);

        let cipher = HybridPoseidonCiphertext {
            key_part,
            data_part
        };
        (cipher, elgamal_rand, shared_key)
    }

    pub fn decrypt_hybrid(params: &HybridPoseidonParams, cipher: &HybridPoseidonCiphertext, sk: &SecretKey<InnerEdProjective>) -> Result<Vec<OuterScalarField>, ()> {
        // first, decrypt the key part to get the shared key using ElGamal
        let shared_key = ElGamal::decrypt(&params.elgamal_params, sk, &cipher.key_part).unwrap();

        // then, decrypt the payload using Poseidon
        Self::decrypt_with_shared_key(params, &shared_key, cipher.data_part.nonce, &cipher.data_part.elems, cipher.data_part.msg_len)
    }

    pub fn encrypt_with_shared_key(params: &HybridPoseidonParams, key: &InnerEdAffine, nonce: OuterScalarField, msg: &[OuterScalarField]) -> PoseidonCiphertext {
        let len_pad = OuterScalarField::from(2).pow([128]);    // compute 2^128
        assert!(nonce < len_pad, "nonce too large");
        let msg_len = OuterScalarField::from(msg.len() as u64);
        let mut poseidon = PoseidonSponge::new(&params.poseidon_params);

        // initialize
        poseidon.absorb(&vec![key.x, key.y, nonce.add(&msg_len.mul(&len_pad))]);

        // process message in three-element-chunks
        let mut i = 0;
        let mut cipher = vec![];
        while i < msg.len() {
            // absorb three message elements (pad with zeroes)
            let msg_1 = msg[i];
            let msg_2 = *msg.get(i+1).unwrap_or(&OuterScalarField::zero());
            let msg_3 = *msg.get(i+2).unwrap_or(&OuterScalarField::zero());
            poseidon.absorb(&vec![msg_1, msg_2, msg_3]); // performs permute first

            // release three ciphertext elements
            cipher.push(poseidon.state[1]);
            cipher.push(poseidon.state[2]);
            cipher.push(poseidon.state[3]);

            i += 3;
        }

        // release last ciphertext element
        let last_cipher = poseidon.squeeze_native_field_elements(1);    // performs permute first
        cipher.push(last_cipher[0]);

        PoseidonCiphertext {
            elems: cipher,
            nonce,
            msg_len: msg.len()
        }
    }

    pub fn decrypt_with_shared_key(params: &HybridPoseidonParams,key: &InnerEdAffine, nonce: OuterScalarField, cipher: &[OuterScalarField], msg_len: usize) -> Result<Vec<OuterScalarField>, ()> {
        let len_pad = OuterScalarField::from(2).pow([128]);    // compute 2^128
        assert!(nonce < len_pad, "nonce too large");
        let msg_len_fe = OuterScalarField::from(msg_len as u64);
        let mut poseidon = PoseidonSponge::new(&params.poseidon_params);
        let padded_msg_len = ((msg_len + 2) / 3) * 3;     // round up to nearest multiple of 3
        assert_eq!(cipher.len(), padded_msg_len + 1);

        // initialize
        poseidon.absorb(&vec![key.x, key.y, nonce.add(&msg_len_fe.mul(&len_pad))]);

        // process cipher in three-element-chunks
        let mut i = 0;
        let mut msg = vec![];
        while i < padded_msg_len {
            let next_state = poseidon.squeeze_native_field_elements(3);    // performs permute first

            // release three message elements
            msg.push(cipher[i] - next_state[0]);
            msg.push(cipher[i+1] - next_state[1]);
            msg.push(cipher[i+2] - next_state[2]);

            // modify state
            poseidon.state[1] = cipher[i];
            poseidon.state[2] = cipher[i+1];
            poseidon.state[3] = cipher[i+2];

            i += 3;
        }
        // check zero padding
        for i in msg_len..padded_msg_len {
            if msg[i] != OuterScalarField::zero() {
                // decryption failed (incorrect key?)
                return Err(())
            }
        }

        // release last ciphertext element
        let last_cipher = poseidon.squeeze_native_field_elements(1);    // performs permute first
        if cipher[cipher.len()-1] != last_cipher[0] {
            // decryption failed (incorrect key?)
            return Err(())
        }

        Ok(msg[0..msg_len].to_vec())
    }

    pub fn get_rand_nonce<R: Rng>(rng: &mut R) -> OuterScalarField {
        // get 16 random bytes (= 128 bits)
        let bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
        // return a random nonce in [0..2^128-1]
        OuterScalarField::from_random_bytes(&bytes).unwrap()
    }
}

pub mod constraints {
    use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef};
    use ark_sponge::{poseidon::constraints::PoseidonSpongeVar, constraints::CryptographicSpongeVar};

    use super::*;

    pub struct PoseidonCipherGadget;

    impl PoseidonCipherGadget {
        pub fn encrypt_with_expanded_key(cs: &ConstraintSystemRef<OuterScalarField>,
            params: &PoseidonParameters<OuterScalarField>,
            key: &InnerEdVar,
            nonce: OuterScalarVar,
            msg: &[OuterScalarVar],
            msg_len: &OuterScalarVar
        ) -> Result<Vec<OuterScalarVar>, SynthesisError> {
            let mut poseidon = PoseidonSpongeVar::<OuterScalarField>::new(cs.clone(), params);
            let len_pad = OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(2).pow([128]))?;    // compute 2^128

            // ensure nonce small enough (< 2^128)
            let nonce_bits = nonce.to_bits_le()?;
            for i in 128..nonce_bits.len() {
                nonce_bits[i].enforce_equal(&Boolean::FALSE)?;
            }

            // initialize
            poseidon.absorb(&vec![key.x.clone(), key.y.clone(), nonce.add(&msg_len.mul(&len_pad))])?;

            // process message in three-element-chunks
            let mut i = 0;
            let mut cipher = vec![];
            while i < msg.len() {
                // absorb three message elements (pad with zeroes)
                let msg_1 = msg[i].clone();
                let msg_2 = msg.get(i+1).unwrap_or(&OuterScalarVar::zero()).clone();
                let msg_3 = msg.get(i+2).unwrap_or(&OuterScalarVar::zero()).clone();
                poseidon.absorb(&vec![msg_1, msg_2, msg_3]).unwrap(); // performs permute first

                // release three ciphertext elements
                cipher.push(poseidon.state[1].clone());
                cipher.push(poseidon.state[2].clone());
                cipher.push(poseidon.state[3].clone());

                i += 3;
            }

            // release last ciphertext element
            let last_cipher = poseidon.squeeze_field_elements(1)?;    // performs permute first
            cipher.push(last_cipher[0].clone());

            Ok(cipher)
        }
    }

}


#[cfg(test)]
mod test {
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;
    use ark_std::UniformRand;

    use super::*;
    use super::constraints::PoseidonCipherGadget;

    #[test]
    fn test_poseidon_encryption() {
        let mut rng = test_rng();
        let params = HybridPoseidonCipher::setup(&mut rng);
        let nonce = HybridPoseidonCipher::get_rand_nonce(&mut rng);
        let key = InnerEdAffine::rand(&mut rng);
        let msg: Vec<_> = (0..7).map(|_| OuterScalarField::rand(&mut rng)).collect();
        let c = HybridPoseidonCipher::encrypt_with_shared_key(&params, &key, nonce, &msg);
        let msg_check = HybridPoseidonCipher::decrypt_with_shared_key(&params, &key, c.nonce, &c.elems, c.msg_len).unwrap();
        assert_eq!(msg, msg_check);
    }

    #[test]
    fn test_poseidon_gadget() {
        let mut rng = test_rng();
        let msg_len: u64 = 7;

        // compute native
        let params = HybridPoseidonCipher::setup(&mut rng);
        let nonce = HybridPoseidonCipher::get_rand_nonce(&mut rng);
        let key = InnerEdAffine::rand(&mut rng);
        let msg: Vec<_> = (0..msg_len).map(|_| OuterScalarField::rand(&mut rng)).collect();
        let native_c = HybridPoseidonCipher::encrypt_with_shared_key(&params, &key, nonce, &msg);

        // use gadget
        let cs = ConstraintSystem::new_ref();
        let key_var = InnerEdVar::new_witness(cs.clone(), || Ok(key)).unwrap(); 
        let nonce_var = OuterScalarVar::new_witness(cs.clone(), || Ok(nonce)).unwrap();
        let msg_var: Vec<_> = msg.iter().map(|m| OuterScalarVar::new_witness(cs.clone(), || Ok(m)).unwrap()).collect();
        let msg_len_var = OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(msg_len)).unwrap();
        let gadget_c = PoseidonCipherGadget::encrypt_with_expanded_key(&cs, &params.poseidon_params, &key_var, nonce_var, &msg_var, &msg_len_var).unwrap();

        assert_eq!(native_c.elems.len(), gadget_c.len());
        for i in 0..gadget_c.len() {
            gadget_c[i].enforce_equal(&OuterScalarVar::new_constant(cs.clone(), native_c.elems[i]).unwrap()).unwrap();
        }
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_poseidon_hybrid_encryption() {
        let mut rng = test_rng();
        let params = HybridPoseidonCipher::setup(&mut rng);
        let (pk, sk) = ElGamal::<InnerEdProjective>::keygen(&params.elgamal_params, &mut rng).unwrap();

        let msg: Vec<_> = (0..7).map(|_| OuterScalarField::rand(&mut rng)).collect();
        let c = HybridPoseidonCipher::encrypt_hybrid(&params, &pk, &msg, &mut rng).0;
        let msg_check = HybridPoseidonCipher::decrypt_hybrid(&params, &c, &sk).unwrap();
        assert_eq!(msg, msg_check);
    }
}
