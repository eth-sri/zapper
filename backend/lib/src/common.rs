use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_bls12_381::Bls12_381;
use ark_ff::{Fp256, Fp256Parameters};
use ark_r1cs_std::{fields::fp::FpVar, boolean::Boolean, prelude::EqGadget, R1CSVar};
use ark_relations::r1cs::ConstraintSystemRef;
use ark_std::{One, Zero};

use log::LevelFilter;
use log4rs::{append::{file::FileAppender, console::ConsoleAppender}, Config, config::{Appender, Root}};

// proof circuit
pub type OuterPairing = Bls12_381;
pub type OuterScalarField = Fq;  // matches ark_bls12_381::Fr
pub type OuterScalarVar = FpVar<OuterScalarField>;

// for encryption (JubJub)
pub type InnerEdAffine = EdwardsAffine;
pub type InnerEdProjective = EdwardsProjective;
pub type InnerEdVar = EdwardsVar;
pub type InnerEdScalarField = Fr;

pub fn init_logging() {
    let stdout = ConsoleAppender::builder().build();
    let file = FileAppender::builder()
    .build("log/main.log")
    .unwrap();

    let config = Config::builder()
        .appender(Appender::builder().build("main", Box::new(file)))
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("main").appender("stdout").build(LevelFilter::Debug))
        .unwrap();

    log4rs::init_config(config).unwrap();
}

#[macro_export]
macro_rules! data_log {
    ($msg: expr) => {
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            let data_log_file_name = std::env::var("ZAPPER_BACKEND_DATA_LOG_FILE");
            if let Ok(file_name) = data_log_file_name {
                let mut file = OpenOptions::new().append(true).create(true).open(&file_name).unwrap_or_else(|_| panic!("could not open data log file '{}'", file_name));
                write!(file, "{}\n", $msg).unwrap();
            }
        }
    }
}

#[macro_export]
macro_rules! time_measure {
    ($name: expr, $body: stmt) => {
        let xx_time_measure_start = std::time::Instant::now();
        $body
        let xx_time_measure_elapsed = xx_time_measure_start.elapsed().as_secs_f32();
        log::debug!("{}: {} s", $name, xx_time_measure_elapsed);
        crate::data_log!(format!("{{\"time\": {{\"key\": \"{}\", \"elapsed_sec\": {}}}}}", $name, xx_time_measure_elapsed));
    }
}

// returns the value of a field element in standard base-10 string notation
pub fn fe_to_string<F: Fp256Parameters>(fe: &Fp256<F>) -> String {
    let e: num_bigint::BigUint = (*fe).into(); e.to_string()
}

/// converts a number represented in _big endian_ hexadecimal string format
/// to a field element
pub fn fe_from_be_hex_str<F: Fp256Parameters>(hex_str: &str) -> Fp256<F> {
    let bytes = hex::decode(hex_str).unwrap();
    let num = num_bigint::BigUint::from_bytes_be(&bytes);
    let max: num_bigint::BigUint = (Fp256::<F>::zero() - Fp256::<F>::one()).into();
    if num > max {
        // too large to fit inside Fp256<F>
        panic!("tried to construct field element from too large hex value");
    }
    Fp256::<F>::from(num)
}

/// converts a field element to its _big endian_ hexadecimal string format
pub fn fe_to_be_hex_str<F: Fp256Parameters>(fe: &Fp256<F>) -> String {
    let num: num_bigint::BigUint = (*fe).into();
    let bytes = num.to_bytes_be();
    hex::encode(bytes)
}

/// converts a number represented in _big endian_ hexadecimal string format
/// to an usize
pub fn usize_from_be_hex_str(hex_str: &str) -> usize {
    assert!(hex_str.len() <= 16);
    let padded_hex_str = String::from("0").repeat(16 - hex_str.len()) + hex_str;
    let mut bytes = [0u8; 8];
    hex::decode_to_slice(padded_hex_str, &mut bytes).unwrap();
    usize::from_be_bytes(bytes)
}

#[cfg(feature="circuit-trace")]
#[inline]
pub fn dbg_bytes(bytes: &[ark_r1cs_std::prelude::UInt8<OuterScalarField>]) {
    if !bytes[0].cs().is_in_setup_mode() {
        let mut l = vec![];
        for byte in bytes.iter() {
            let b: u8 = byte.value().unwrap();
            l.push(b);
        }
        println!("{:?}", l);
    }
}

#[cfg(not(feature="circuit-trace"))]
#[inline]
pub fn dbg_bytes(_bytes: &[ark_r1cs_std::prelude::UInt8<OuterScalarField>]) {
}

#[cfg(feature="circuit-trace")]
#[inline]
pub fn dbg_fe(fe: &OuterScalarField) {
    println!("{}", fe_to_string(fe));
}

#[cfg(not(feature="circuit-trace"))]
#[inline]
pub fn dbg_fe(_fe: &OuterScalarField) {
}

#[cfg(feature="circuit-trace")]
#[inline]
pub fn dbg_var(var: &OuterScalarVar) {
    if !var.cs().is_in_setup_mode() {
        let x: num_bigint::BigUint = var.value().unwrap().into();
        println!("{}", x.to_string());
    }
}

#[cfg(not(feature="circuit-trace"))]
#[inline]
pub fn dbg_var(_var: &OuterScalarVar) {
}

#[cfg(feature="circuit-trace")]
#[inline]
pub fn dbg_ensure_satisfied(cs: &ConstraintSystemRef<OuterScalarField>, msg: &str) {
    assert!(cs.is_in_setup_mode() || cs.is_satisfied().unwrap(), "circuit unsatisfied after: {}", msg)
}

#[cfg(not(feature="circuit-trace"))]
#[inline]
pub fn dbg_ensure_satisfied(_cs: &ConstraintSystemRef<OuterScalarField>, _msg: &str) {
}

#[inline]
pub fn enforce_true_with_info(bool: &Boolean<OuterScalarField>, info: &str) {
    assert!(bool.cs().is_in_setup_mode() || bool.value().unwrap(), "circuit unsatisfied at: {}", info);
    bool.enforce_equal(&Boolean::TRUE).unwrap();
}

pub struct FeConverter;

pub trait FeToLargerConverter<A, B> {
    /// Converts a field element of type `A` to an element of the larger field `B` with the same value
    /// This call always succeeds.
    fn to_larger(x: &A) -> B;
}

pub trait FeToSmallerConverter<A, B> {
    /// Converts a field element of type `A` to an element of the smaller field `B` with the same value.
    /// Returns `None` if the input `x` is larger than the field size of `B`.
    fn to_smaller(x: &A) -> Option<B>;
}

pub trait FeFromLeBytesConverter<A> {
    /// Converts little-endian bytes to a field element of type `A`.
    /// Returns `None` if the bytes are not valid (e.g., larger than the field modulus).
    fn from_le_bytes(bytes: &[u8]) -> Option<A>;
}

#[macro_export]
macro_rules! impl_fe_to_larger {
    ($in_type: ident, $out_type: ident) => {
        impl FeToLargerConverter<$in_type, $out_type> for FeConverter {
            fn to_larger(x: &$in_type) -> $out_type {
                let num: num_bigint::BigUint = x.clone().into();
                $out_type::from(num)
            }
        }
    }
}

#[macro_export]
macro_rules! impl_fe_to_smaller {
    ($in_type: ident, $out_type: ident) => {
        impl FeToSmallerConverter<$in_type, $out_type> for FeConverter {
            fn to_smaller(x: &$in_type) -> Option<$out_type> {
                let max: num_bigint::BigUint = ($out_type::zero() - $out_type::one()).into();
                let num: num_bigint::BigUint = x.clone().into();
                if num > max {
                    // too large to fit inside $in_type
                    return None;
                }
                Some($out_type::from(num))
            }
        }
    }
}

#[macro_export]
macro_rules! impl_from_le_bytes {
    ($out_type: ident) => {
        impl FeFromLeBytesConverter<$out_type> for FeConverter {
            fn from_le_bytes(bytes: &[u8]) -> Option<$out_type> {
                let max: num_bigint::BigUint = ($out_type::zero() - $out_type::one()).into();
                let num = num_bigint::BigUint::from_bytes_le(bytes);
                if num > max {
                    // too large to fit inside $in_type
                    return None;
                }
                Some($out_type::from(num))
            }
        }
    }
}

// converting smaller to larger fields (always succeed)
impl_fe_to_larger!(InnerEdScalarField, OuterScalarField);

// converting larger to smaller fields (only succeeds if value small enough)
impl_fe_to_smaller!(OuterScalarField, InnerEdScalarField);

// converting from little-endian bytes
impl_from_le_bytes!(OuterScalarField);
impl_from_le_bytes!(InnerEdScalarField);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ark_ff::to_bytes;

    use crate::constants::FE_BYTES;

    use super::*;

    #[test]
    fn test_field_element_handling() {
        let one = OuterScalarField::from(1);
        let one_2 = OuterScalarField::from(num_bigint::BigUint::from(1u64));
        let check_one = OuterScalarField::one();
        assert_eq!(one, check_one);
        assert_eq!(one_2, check_one);

        let large = OuterScalarField::from(num_bigint::BigUint::from_str("395739020857028346344640023").unwrap());
        let large_twice = large * OuterScalarField::from(2);
        let check_large_twice = OuterScalarField::from_str("791478041714056692689280046").unwrap();
        assert_eq!(large_twice, check_large_twice);
    }

    #[test]
    fn test_inner_outer_conversion() {
        let outer = OuterScalarField::from(num_bigint::BigUint::from_str("395739020857028346344640023").unwrap());
        let inner: InnerEdScalarField = FeConverter::to_smaller(&outer).unwrap();
        let outer: num_bigint::BigUint = outer.into();
        let inner: num_bigint::BigUint = inner.into();
        assert_eq!(inner, outer);

        let inner = InnerEdScalarField::from(num_bigint::BigUint::from_str("395739020857028346344640023").unwrap());
        let outer: OuterScalarField = FeConverter::to_larger(&inner);
        let inner: num_bigint::BigUint = inner.into();
        let outer: num_bigint::BigUint = outer.into();
        assert_eq!(inner, outer);
    }

    #[test]
    #[should_panic]
    fn test_inner_outer_conversion_too_large() {
        let too_large = OuterScalarField::from(num_bigint::BigUint::from(2usize).pow(260));
        let _inner: InnerEdScalarField = FeConverter::to_smaller(&too_large).unwrap();
    }

    #[test]
    fn test_field_to_from_bytes() {
        let one = OuterScalarField::from(1);
        let one_bytes = to_bytes!(one).unwrap();
        assert_eq!(one_bytes.len(), FE_BYTES);

        let mut check_one_bytes = [0; FE_BYTES].to_vec();
        check_one_bytes[0] = 1;
        assert_eq!(one_bytes, check_one_bytes);
        let check_one = FeConverter::from_le_bytes(&one_bytes).unwrap();
        assert_eq!(one, check_one);

        let med = OuterScalarField::from_str("41420").unwrap();  // binary big-endian: 1010 0001 1100 1100
        let mut med_bytes = [0; FE_BYTES].to_vec();
        med_bytes[0] = 0b11001100;  // least-significant byte
        med_bytes[1] = 0b10100001;
        let check_med = FeConverter::from_le_bytes(&med_bytes).unwrap();
        assert_eq!(med, check_med);
    }

    #[test]
    fn test_field_from_overflow_bytes() {
        let max = OuterScalarField::zero() - OuterScalarField::one();
        let mut max_bytes = to_bytes!(max).unwrap();
        max_bytes.push(100u8);  // make larger than field prime
        let check_max: Option<OuterScalarField> = FeConverter::from_le_bytes(&max_bytes);
        assert_eq!(check_max, None);
    }

    #[test]
    fn test_fe_from_to_hex_str() {
        let fe: OuterScalarField = fe_from_be_hex_str("10aa");
        assert_eq!(fe_to_string(&fe), "4266");

        let hex = fe_to_be_hex_str(&OuterScalarField::from(4266));
        assert_eq!(hex, "10aa");
    }

    #[test]
    fn test_usize_from_to_hex_str() {
        let u = usize_from_be_hex_str("10aa");
        assert_eq!(u, 4266);
    }
}