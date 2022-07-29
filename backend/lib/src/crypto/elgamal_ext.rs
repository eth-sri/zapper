use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{FromBytes, ToBytes, UniformRand, Zero, fields::{Field, PrimeField}, to_bytes};
use ark_std::{io::{Read, Result as IoResult, Write}, rand::Rng};
use ark_std::marker::PhantomData;
use ark_crypto_primitives::encryption::elgamal::constraints::OutputVar;
use ark_crypto_primitives::encryption::elgamal::{SecretKey as OrigSecretKey, PublicKey, Parameters};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;

use crate::common::{InnerEdProjective, InnerEdScalarField};

pub type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

pub struct ExtSecretKey<C: ProjectiveCurve>(pub OrigSecretKey<C>);

impl ToBytes for ExtSecretKey<InnerEdProjective> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.0.0.write(&mut writer)?;
        Ok(())
    }
}

impl FromBytes for ExtSecretKey<InnerEdProjective> {
    fn read<R: Read>(reader: R) -> IoResult<Self> {
        Ok(ExtSecretKey(OrigSecretKey(InnerEdScalarField::read(reader).unwrap())))
    }
}

impl Default for ExtSecretKey<InnerEdProjective> {
    fn default() -> Self {
        Self(OrigSecretKey(InnerEdScalarField::default()))
    }
}

impl Clone for ExtSecretKey<InnerEdProjective> {
    fn clone(&self) -> Self {
        Self(OrigSecretKey(self.0.0.clone()))
    }
}

impl UniformRand for ExtSecretKey<InnerEdProjective> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        ExtSecretKey(OrigSecretKey(InnerEdScalarField::rand(rng)))
    }
}

pub fn derive_pk_from_sk<C: ProjectiveCurve>(
    pp: &Parameters<C>,
    sk: &OrigSecretKey<C>,
) -> PublicKey<C> {
    // compute secret_key*generator to derive the public key
    pp.generator.mul(sk.0).into()
}


#[derive(Clone, Debug)]
pub struct SecretKeyVar<F: Field>(pub Vec<UInt8<F>>);

impl<C, F> AllocVar<ExtSecretKey<C>, F> for SecretKeyVar<F>
    where
        C: ProjectiveCurve,
        F: PrimeField,
{
    fn new_variable<T: Borrow<ExtSecretKey<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let r = to_bytes![&f().map(|b| b.borrow().0.0).unwrap_or(C::ScalarField::zero())].unwrap();
        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&r))),
            AllocationMode::Input => UInt8::new_input_vec(cs, &r).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, &r).map(Self),
        }
    }
}

pub struct ElGamalDecGadget<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
    where
            for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    #[doc(hidden)]
    _curve: PhantomData<*const C>,
    _group_var: PhantomData<*const GG>,
}

impl<C, GG> ElGamalDecGadget<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField,
{
    pub fn decrypt(
        sk: &SecretKeyVar<ConstraintF<C>>,
        ciphertext: &OutputVar<C, GG>
    ) -> Result<GG, SynthesisError> {
        // flatten secret key to little-endian bit vector
        let sk: Vec<_> = sk.0.iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect();

        // compute s = secret_key * c1
        let s = ciphertext.c1.clone().scalar_mul_le(sk.iter())?;

        // compute message = c2 - s
        let m = ciphertext.c2.clone().sub(s);

        Ok(m)
    }
}

// TODO move these changes to ParametersVar
pub struct MyParametersVar<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
    where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub generator: GG,
    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Parameters<C>, ConstraintF<C>> for MyParametersVar<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let generator = GG::new_variable(cs, || f().map(|g| g.borrow().generator), mode)?;
        Ok(Self {
            generator,
            _curve: PhantomData,
        })
    }
}

pub struct ElGamalEncGadget<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
    where
            for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    #[doc(hidden)]
    _curve: PhantomData<*const C>,
    _group_var: PhantomData<*const GG>,
}

impl<C, GG> ElGamalEncGadget<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField,
{
    pub fn encrypt(
        parameters: &MyParametersVar<C, GG>,
        plaintext: &GG,
        randomness: &Vec<UInt8<ConstraintF<C>>>,
        public_key: &GG,
    ) -> Result<(GG, GG), SynthesisError> {
        // flatten randomness to little-endian bit vector
        let randomness = randomness
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        // compute s = randomness*pk
        let s = public_key.clone().scalar_mul_le(randomness.iter())?;

        // compute c1 = randomness*generator
        let c1 = parameters
            .generator
            .clone()
            .scalar_mul_le(randomness.iter())?;

        // compute c2 = m + s
        let c2 = plaintext.clone() + s;

        Ok((c1, c2))
    }
}

pub struct ElGamalKeyGadget<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
    where
            for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    #[doc(hidden)]
    _curve: PhantomData<*const C>,
    _group_var: PhantomData<*const GG>,
}

impl<C, GG> ElGamalKeyGadget<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField,
{
    pub fn derive_pk(
        sk: &SecretKeyVar<ConstraintF<C>>,
        pp: &MyParametersVar<C, GG>
    ) -> Result<GG, SynthesisError> {
        // flatten secret key to little-endian bit vector
        let sk: Vec<_> = sk.0.iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect();
        
        // compute pk = generator * secret_key
        let pk = pp.generator.clone().scalar_mul_le(sk.iter())?;

        Ok(pk)
    }
}

#[cfg(test)]
mod tests {
    use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
    use ark_crypto_primitives::encryption::elgamal::{ElGamal, Randomness};
    use ark_crypto_primitives::encryption::elgamal::constraints::{OutputVar, PlaintextVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;
    use crate::common::*;
    use super::*;

    type MyElgamal = ElGamal<InnerEdProjective>;
    type MyElgamalDecGadget = ElGamalDecGadget<InnerEdProjective, InnerEdVar>;

    #[test]
    fn test_check_decryption() {
        let rng = &mut test_rng();

        // compute primitive result
        let params = MyElgamal::setup(rng).unwrap();
        let (pk, sk) = MyElgamal::keygen(&params, rng).unwrap();
        let sk = ExtSecretKey(sk);
        let check_msg = InnerEdProjective::rand(rng).into();
        let other_msg = InnerEdProjective::rand(rng).into();
        let randomness = Randomness::rand(rng);
        let cipher = MyElgamal::encrypt(&params, &pk, &check_msg, &randomness).unwrap();
        let other_cipher = MyElgamal::encrypt(&params, &pk, &other_msg, &randomness).unwrap();

        // construct constraint system
        let cs = ConstraintSystem::<OuterScalarField>::new_ref();
        let cipher_var = OutputVar::new_witness(
            ark_relations::ns!(cs, "gadget_cipher"),
            || Ok(&cipher)
        ).unwrap();

        let sk_var = SecretKeyVar::new_constant(
            ark_relations::ns!(cs, "gadget_sk"),
            &sk
        ).unwrap();

        let check_msg_var = PlaintextVar::new_constant(
            ark_relations::ns!(cs, "gadget_check_msg"),
            &check_msg
        ).unwrap();

        let msg_var = MyElgamalDecGadget::decrypt(&sk_var, &cipher_var).unwrap();
        msg_var.enforce_equal(&check_msg_var.plaintext).unwrap();

        // check decryption of incorrect ciphertext
        let other_cipher_var = OutputVar::new_witness(
            ark_relations::ns!(cs, "gadget_cipher"),
            || Ok(&other_cipher)
        ).unwrap();

        let msg_var = MyElgamalDecGadget::decrypt(&sk_var, &other_cipher_var).unwrap();
        msg_var.enforce_not_equal(&check_msg_var.plaintext).unwrap();
    }
}