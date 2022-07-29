use ark_crypto_primitives::encryption::elgamal::SecretKey;
use ark_ff::UniformRand;
use log::debug;
use rand::Rng;

use crate::infrastructure::params::CryptoParams;

use crate::crypto::elgamal_ext::{ExtSecretKey, derive_pk_from_sk};
use crate::common::*;

use crate::infrastructure::derivations::{is_external_account, is_reconstructable, get_addr_for_pk};

#[derive(Clone, Default)]
pub struct Identity {
    pub is_external_account: bool,
    pub secret_key: ExtSecretKey<InnerEdProjective>,
    pub public_key: InnerEdAffine,
    pub address: OuterScalarField
}

impl Identity {
    pub fn from_coords(public_key_x: OuterScalarField, public_key_y: OuterScalarField, secret_key: InnerEdScalarField) -> Identity {
        let public_key = InnerEdAffine::new(public_key_x, public_key_y);
        let address = get_addr_for_pk(&public_key);
        let secret_key = ExtSecretKey(SecretKey(secret_key));
        Identity {
            is_external_account: is_external_account(&address),
            secret_key,
            public_key,
            address
        }
    }

    pub fn new_external<R: Rng>(rng: &mut R, params: &CryptoParams) -> Identity {
        let mut secret_key;
        let mut public_key;
        loop {
            // try random secret keys until its public key is an external account public key
            secret_key = ExtSecretKey::rand(rng);
            public_key = derive_pk_from_sk(&params.enc_params.elgamal_params, &secret_key.0);
            if is_reconstructable(&public_key) {
                if is_external_account(&get_addr_for_pk(&public_key)) {
                    debug!("successfully derived new user account with public key ({}, {}), secret key {}",
                        fe_to_be_hex_str(&public_key.x),
                        fe_to_be_hex_str(&public_key.y),
                        fe_to_be_hex_str(&secret_key.0.0));
                    break;
                }
            }
        }

        let address = get_addr_for_pk(&public_key);
        Identity {
            is_external_account: true,
            secret_key,
            public_key,
            address
        }
    }

    pub fn is_valid(&self, params: &CryptoParams) -> bool {
        let check_pk = derive_pk_from_sk(&params.enc_params.elgamal_params, &self.secret_key.0);
        if check_pk != self.public_key {
            debug!("invalid identity: public key does not match: {} vs. {}", check_pk, self.public_key);
            return false;
        }
        let check_addr = get_addr_for_pk(&self.public_key);
        if check_addr != self.address {
            debug!("invalid identity: address key does not match: {} vs. {}", check_addr, self.address);
            return false;
        }
        if is_external_account(&self.address) != self.is_external_account {
            debug!("invalid identity: external account flag does not match");
            return false;
        }
        true
    }
}
