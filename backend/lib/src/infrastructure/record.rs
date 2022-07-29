use std::io::{Read, Write};
use ark_crypto_primitives::encryption::elgamal;
use ark_ff::{ToBytes, FromBytes};
use ark_std::{One, Zero};
use std::fmt::Debug;
use rand::Rng;
use crate::common::{InnerEdScalarField, fe_to_be_hex_str};
use crate::crypto::elgamal_ext::ExtSecretKey;
use crate::crypto::poseidon::{HybridPoseidonParams, HybridPoseidonCipher, HybridPoseidonCiphertext, PoseidonCiphertext};
use crate::{common::{InnerEdAffine, OuterScalarField, InnerEdProjective}};
use crate::constants::*;

use super::processor::ObjectData;

pub type Serial = [u8; SN_BYTES];
pub type ObjectId = OuterScalarField;

/// The number of field elements required to represent a record
pub const RECORD_CHUNKS: usize = 6 + NOF_RECORD_PAYLOAD_ELEMENTS;

/// The number of field elements required to represent a record, padded to a multiple of 3
pub const RECORD_CHUNKS_PADDED: usize = ((RECORD_CHUNKS + 2) / 3) * 3;    // round up to nearest multiple of 3

/// The representation of an object's state
#[derive(Clone,PartialEq,Eq)]
pub struct Record {
    /// The serial number nonce used to consume the record
    pub serial_nonce: OuterScalarField,

    /// The id of the contract of which this record represents an instance of
    pub contract_id: OuterScalarField,

    /// The id of the instance represented by this record.
    /// This is `0` iff this is a dummy record not representing an actual object.
    pub object_id: OuterScalarField,

    /// The secret key of the object, used to decrypt objects owned by this object.
    /// This is an element of `InnerEdScalarField`.
    pub sk_object: OuterScalarField,

    /// The address of the object, used to encrypt objects owned by this object
    pub addr_object: OuterScalarField,

    /// The address of the object's owner, used to encrypt this record
    pub addr_owner: OuterScalarField,

    /// The payload of this object, including all fields except the owner address
    pub payload: [OuterScalarField; NOF_RECORD_PAYLOAD_ELEMENTS],
}

impl Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let p: Vec<_> = self.payload.iter().map(fe_to_be_hex_str).collect();
        f.debug_struct("Record")
            .field("serial_nonce", &fe_to_be_hex_str(&self.serial_nonce))
            .field("contract_id", &fe_to_be_hex_str(&self.contract_id))
            .field("object_id", &fe_to_be_hex_str(&self.object_id))
            .field("sk_object", &fe_to_be_hex_str(&self.sk_object))
            .field("addr_object", &fe_to_be_hex_str(&self.addr_object))
            .field("addr_owner", &fe_to_be_hex_str(&self.addr_owner))
            .field("payload", &p)
            .finish()
    }
}

pub type EncRandomness = (InnerEdScalarField, InnerEdAffine);

impl Record {
    pub fn is_dummy(&self) -> bool {
        self.object_id.is_zero()
    }

    pub fn encrypt<R: Rng>(&self, pk: &elgamal::PublicKey<InnerEdProjective>, params: &HybridPoseidonParams, rng: &mut R) -> (EncryptedRecord, EncRandomness) {
        let mut data = vec![
           self.serial_nonce,
           self.contract_id,
           self.object_id,
           self.sk_object,
           self.addr_object,
           self.addr_owner
        ];
        data.extend_from_slice(&self.payload);
        assert_eq!(data.len(), RECORD_CHUNKS);
        let (cipher, rand, shared_key) = HybridPoseidonCipher::encrypt_hybrid(params, pk, &data, rng);
        (EncryptedRecord(cipher), (rand, shared_key))
    }

    pub fn decrypt(enc_record: &EncryptedRecord, sk: &ExtSecretKey<InnerEdProjective>, params: &HybridPoseidonParams) -> Result<Record, ()> {
        let data = HybridPoseidonCipher::decrypt_hybrid(params, &enc_record.0, &sk.0)?;
        assert_eq!(data.len(), RECORD_CHUNKS);
        let mut payload = [OuterScalarField::default(); NOF_RECORD_PAYLOAD_ELEMENTS];
        payload.copy_from_slice(&data[RECORD_CHUNKS-NOF_RECORD_PAYLOAD_ELEMENTS..]);
        Ok(Record {
            serial_nonce: data[0],
            contract_id: data[1],
            object_id: data[2],
            sk_object: data[3],
            addr_object: data[4],
            addr_owner: data[5],
            payload,
        })
    }

    pub fn to_object_data(&self) -> ObjectData {
        // dedicated position of owner address
        let mut payload = vec![self.addr_owner];

        for j in 0..NOF_RECORD_PAYLOAD_ELEMENTS {
           payload.push(self.payload[j]);
        }

        ObjectData {
            is_empty: if self.object_id.is_zero() { OuterScalarField::one() } else { OuterScalarField::zero() },
            contract_id: self.contract_id,
            object_id: self.object_id,
            sk_object: self.sk_object,
            addr_object: self.addr_object,
            payload,
        }
    }

    pub fn from_object_data(data: &ObjectData) -> Record {
        let mut payload = [OuterScalarField::default(); NOF_RECORD_PAYLOAD_ELEMENTS];
        payload[..NOF_RECORD_PAYLOAD_ELEMENTS].clone_from_slice(&data.payload[1..(NOF_RECORD_PAYLOAD_ELEMENTS + 1)]);

        Record {
            serial_nonce: Default::default(),
            contract_id: data.contract_id,
            object_id: if data.is_empty.is_one() { OuterScalarField::zero() } else { data.object_id },
            sk_object: data.sk_object,
            addr_object: data.addr_object,
            addr_owner: data.payload[0],
            payload,
        }
    }
}

impl Default for Record {
    fn default() -> Self {
        Record {
            serial_nonce: OuterScalarField::zero(),
            contract_id: OuterScalarField::zero(),
            object_id: OuterScalarField::zero(),
            sk_object: OuterScalarField::zero(),
            addr_object: OuterScalarField::zero(),
            addr_owner: OuterScalarField::zero(),
            payload: [OuterScalarField::zero(); NOF_RECORD_PAYLOAD_ELEMENTS]
        }
    }
}

impl ToBytes for Record {
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.serial_nonce.write(&mut writer)?;
        self.contract_id.write(&mut writer)?;
        self.object_id.write(&mut writer)?;
        self.sk_object.write(&mut writer)?;
        self.addr_object.write(&mut writer)?;
        self.addr_owner.write(&mut writer)?;
        for p in self.payload.iter() {
            p.write(&mut writer)?;
        }
        Ok(())
    }
}

impl FromBytes for Record {
    fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let serial_nonce = OuterScalarField::read(&mut reader)?;
        let contract_id = OuterScalarField::read(&mut reader)?;
        let object_id = OuterScalarField::read(&mut reader)?;
        let sk_object = OuterScalarField::read(&mut reader)?;
        let addr_object = OuterScalarField::read(&mut reader)?;
        let addr_owner = OuterScalarField::read(&mut reader)?;
        let mut payload = [OuterScalarField::zero(); NOF_RECORD_PAYLOAD_ELEMENTS];
        for i in 0..NOF_RECORD_PAYLOAD_ELEMENTS {
            payload[i] = OuterScalarField::read(&mut reader)?;
        }
        Ok(
            Record {
                serial_nonce,
                contract_id,
                object_id,
                sk_object,
                addr_object,
                addr_owner,
                payload
            }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedRecord(pub HybridPoseidonCiphertext);

impl Default for EncryptedRecord {
    fn default() -> Self {
        // NOTE: this function must initialize the encrypted record with correct sizes, as it is used for the circuit setup phase
        EncryptedRecord(HybridPoseidonCiphertext{
            key_part: Default::default(),
            data_part: PoseidonCiphertext {
                elems: (0..RECORD_CHUNKS_PADDED+1).map(|_| OuterScalarField::default()).collect(),
                nonce: Default::default(),
                msg_len: RECORD_CHUNKS
            },
        })
    }
}

pub const ENC_RECORD_BYTES: usize = FE_BYTES * (5 + RECORD_CHUNKS_PADDED + 1);

impl ToBytes for EncryptedRecord {
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.0.key_part.0.write(&mut writer)?;
        self.0.key_part.1.write(&mut writer)?;
        self.0.data_part.nonce.write(&mut writer)?;
        for i in 0..RECORD_CHUNKS_PADDED+1 {   // +1 as ciphertext has one additional chunk
            self.0.data_part.elems[i].write(&mut writer)?;
        }
        // NOTE: as message length (RECORD_CHUNKS) is constant, so we do not serialize it
        Ok(())
    }
}

impl FromBytes for EncryptedRecord {
    fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let key_part_0 = InnerEdAffine::read(&mut reader)?;
        let key_part_1 = InnerEdAffine::read(&mut reader)?;
        let nonce = OuterScalarField::read(&mut reader)?;
        let mut elems = vec![];
        for _ in 0..RECORD_CHUNKS_PADDED+1 {   // +1 as ciphertext has one additional chunk
            elems.push(OuterScalarField::read(&mut reader)?);
        }
        Ok(EncryptedRecord(HybridPoseidonCiphertext {
            key_part: (key_part_0, key_part_1),
            data_part: PoseidonCiphertext {
                elems,
                nonce,
                msg_len: RECORD_CHUNKS,
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
    use ark_ff::to_bytes;
    use ark_std::test_rng;
    use ark_std::UniformRand;

    use crate::infrastructure::derivations::get_addr_for_pk;

    use super::*;

    fn get_record() -> Record {
        let mut rng = test_rng();
        let mut payload = [OuterScalarField::zero(); NOF_RECORD_PAYLOAD_ELEMENTS];
        for i in 0..NOF_RECORD_PAYLOAD_ELEMENTS {
            payload[i] = OuterScalarField::rand(&mut rng);
        }

        let serial_nonce = OuterScalarField::rand(&mut rng);
        let contract_id = OuterScalarField::rand(&mut rng);
        let object_id = OuterScalarField::rand(&mut rng);
        let sk_object = OuterScalarField::rand(&mut rng);
        let addr_object = OuterScalarField::rand(&mut rng);
        let addr_owner = OuterScalarField::rand(&mut rng);

        Record {
            serial_nonce,
            contract_id,
            object_id,
            sk_object,
            addr_object,
            addr_owner,
            payload
        }
    }

    #[test]
    fn test_record_to_from_bytes() {
        let record = get_record();
        let bytes = to_bytes!(record).unwrap();
        let check_record = Record::read(bytes.as_slice()).unwrap();
        assert_eq!(record, check_record);
    }

    #[test]
    fn test_encrypted_record_poseidon_to_from_bytes() {
        let mut rng = test_rng();
        let params = HybridPoseidonCipher::setup(&mut rng);
        let (pk, sk) = elgamal::ElGamal::<InnerEdProjective>::keygen(&params.elgamal_params, &mut rng).unwrap();
        let sk = ExtSecretKey(sk);

        let mut record = get_record();
        record.addr_owner = get_addr_for_pk(&pk);
        let enc_record = record.encrypt(&pk, &params, &mut rng).0;
        let bytes = to_bytes!(enc_record).unwrap();
        assert_eq!(bytes.len(), ENC_RECORD_BYTES);
        let check_enc_record = EncryptedRecord::read(bytes.as_slice()).unwrap();
        assert_eq!(enc_record, check_enc_record);
        let check_record = Record::decrypt(&check_enc_record, &sk, &params).unwrap();
        assert_eq!(record, check_record);
    }

    #[test]
    fn test_encrypt_decrypt_poseidon_record() {
        let mut rng = test_rng();

        let params = HybridPoseidonCipher::setup(&mut rng);
        let (pk, sk) = elgamal::ElGamal::<InnerEdProjective>::keygen(&params.elgamal_params, &mut rng).unwrap();
        let sk = ExtSecretKey(sk);

        let mut record = get_record();
        record.addr_owner = get_addr_for_pk(&pk);
        let enc_record = record.encrypt(&pk, &params, &mut rng).0;
        assert_eq!(enc_record.0.data_part.elems.len(), RECORD_CHUNKS_PADDED+1);
        let check_record = Record::decrypt(&enc_record, &sk, &params).unwrap();
        assert_eq!(record, check_record);
    }

    #[test]
    fn test_decrypt_poseidon_garbage() {
        let mut rng = test_rng();

        let params = HybridPoseidonCipher::setup(&mut rng);
        let (pk, _) = elgamal::ElGamal::<InnerEdProjective>::keygen(&params.elgamal_params, &mut rng).unwrap();
        let (_, sk_2) = elgamal::ElGamal::<InnerEdProjective>::keygen(&params.elgamal_params, &mut rng).unwrap();
        let sk_2 = ExtSecretKey(sk_2);

        let mut record = get_record();
        record.addr_owner = get_addr_for_pk(&pk);
        let enc_record = record.encrypt(&pk, &params, &mut rng).0;
        let res = Record::decrypt(&enc_record, &sk_2, &params);     // using wrong key, giving garbage
        assert!(res.is_err());
    }
}