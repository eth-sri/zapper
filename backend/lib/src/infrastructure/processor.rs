use std::{ops::{Add, AddAssign, Mul, Sub}, cmp::Ordering, fmt::Debug, rc::Rc, cell::RefCell, collections::BTreeMap};

use ark_r1cs_std::{alloc::AllocVar, prelude::*};
use ark_ff::{One,Zero, to_bytes};
use ark_relations::r1cs::ConstraintSystemRef;
use log::debug;

use crate::{common::*, constants::{NOF_TX_RECORDS, NOF_TX_FRESH, NOF_RECORD_PAYLOAD_ELEMENTS, NOF_PROCESSOR_REGISTERS, MAX_BYTES_UINT}};

use super::{runtime::RuntimeStateView, record::ObjectId};

const NOF_OBJS: usize = NOF_TX_RECORDS;
const NOF_OBJ_PAYLOAD_ELEMS: usize = NOF_RECORD_PAYLOAD_ELEMENTS + 1;     // including addr_owner
const NOF_FRESH: usize = NOF_TX_FRESH;
const NOF_NEW_OBJS: usize = NOF_TX_FRESH;

// # PAYLOAD MEMORY LAYOUT
// [ owner_pk.x, owner_pk.y, other[0], ..., other[NOF_OBY_PAYLOAD_ELEMS-3] ]
//   ^ field 0   ^ field 1   ^ field 2 ... (for LOAD / STORE)

// # INSTRUCTIONS
//
// NOOP _ _ _               // (no op)
// MOV dst src_1 _          // tmp[dst] = val(src_1)
// CMOV dst src_1 src_2     // tmp[dst] = (val(src_1) == 1) ? val(src_2) : tmp[dst]
// ADD dst src_1 src_2      // tmp[dst] = val(src_1) + val(src_2)
// SUB dst src_1 src_2      // tmp[dst] = val(src_1) - val(src_2)
// MUL dst src_1 src_2      // tmp[dst] = val(src_1) * val(src_2)
// EQ dst src_1 src_2       // tmp[dst] = val(src_1) == val(src_2)
// LT dst src_1 src_2       // tmp[dst] = val(src_1) < val(src_2)
// REQ _ src_1 _            // assert(val(src_1) == 1)
// LOAD dst src_1 src_2     // tmp[dst] = obj(oid: val(src_1)).val(src_2)
// STORE dst src_1 src_2    // obj(oid: val(src_1)).val(src_2) = tmp[dst]
// CID dst src_1 _          // tmp[dst] = obj(oid: val(src_1)).cid
// NEW dst src_1 _          // tmp[dst] = oid of fresh object with cid = val(src_1)
// KILL _ src_1 _           // delete obj(oid: val(src_1))
// FRESH dst _ _            // tmp[dst] = freshly derived number
// NOW dst _ _              // tmp[dst] = current timestamp   
// PK dst src_1 _           // tmp[dst] = obj(oid: val(src_1)).addr_object

pub const OPCODE_NOOP: u8 = 0;
pub const OPCODE_MOV: u8 = 1;
pub const OPCODE_CMOV: u8 = 2;
pub const OPCODE_REQ: u8 = 3;
pub const OPCODE_LOAD: u8 = 4;
pub const OPCODE_STORE: u8 = 5;
pub const OPCODE_KILL: u8 = 6;
pub const OPCODE_PK: u8 = 7;
pub const OPCODE_NEW: u8 = 8;
pub const OPCODE_CID: u8 = 9;
pub const OPCODE_FRESH: u8 = 10;
pub const OPCODE_NOW: u8 = 11;
pub const OPCODE_ADD: u8 = 12;
pub const OPCODE_SUB: u8 = 13;
pub const OPCODE_MUL: u8 = 14;
pub const OPCODE_EQ: u8 = 15;
pub const OPCODE_LT: u8 = 16;

#[derive(Clone)]
pub enum RegOrConst {
    /// reference to a register
    Reg(usize),
    /// a constant
    Const(OuterScalarField)
}

#[derive(Clone)]
pub struct ZkInstruction {
    pub opcode: u8,
    pub dst: usize,
    pub src_1: RegOrConst,
    pub src_2: RegOrConst
}

impl Default for ZkInstruction {
    fn default() -> Self {
        Self {
            opcode: OPCODE_NOOP,
            dst: Default::default(),
            src_1: RegOrConst::Const(OuterScalarField::zero()),
            src_2: RegOrConst::Const(OuterScalarField::zero())
        }
    }
}

/// The representation of an object's state inside the processor
#[derive(Clone)]
pub struct ObjectData {
    /// Whether this object data slot is empty (`1` iff is empty, `0` otherwise)
    pub is_empty: OuterScalarField,

    /// The id of the contract which this object is an instance of
    pub contract_id: OuterScalarField,

    /// The id of this object
    pub object_id: OuterScalarField,

    /// The secret key of the object
    pub sk_object: OuterScalarField,
    
    /// The address of the object
    pub addr_object: OuterScalarField,

    /// The payload of this object, including the owner address and all other fields
    pub payload: Vec<OuterScalarField>,
}

impl Debug for ObjectData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[is_empty: {}, ", fe_to_string(&self.is_empty))?;
        write!(f, "contract_id: {}, ", fe_to_string(&self.contract_id))?;
        write!(f, "object_id: {}, ", fe_to_string(&self.object_id))?;
        write!(f, "sk_object: {}, ", fe_to_string(&self.sk_object))?;
        write!(f, "addr_object: {}, ", fe_to_string(&self.addr_object))?;
        write!(f, "payload: {:?}]", self.payload.iter().map(fe_to_string).collect::<Vec<_>>())?;
        Ok(())
    }
}

impl Default for ObjectData {
    fn default() -> Self {
        Self {
            is_empty: OuterScalarField::one(),  // empty by default
            contract_id: OuterScalarField::default(),
            object_id: OuterScalarField::default(),
            sk_object: OuterScalarField::default(),
            addr_object: OuterScalarField::default(),
            payload: (0..NOF_OBJ_PAYLOAD_ELEMS).map(|_| OuterScalarField::default()).collect()
        }
    }
}

#[derive(Clone)]
pub struct ZkProcessorPartialState {
    pub registers: Vec<OuterScalarField>,
    pub fresh_vals: Vec<OuterScalarField>,
    pub new_oids: Vec<OuterScalarField>,
    pub new_obj_sks: Vec<OuterScalarField>,
    pub new_obj_addrs: Vec<OuterScalarField>,
}

impl Debug for ZkProcessorPartialState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "regs: {:?} ", self.registers.iter().map(|fe| { fe_to_string(fe) }).collect::<Vec<_>>())?;
        write!(f, "fresh_vals: {:?} ", self.fresh_vals.iter().map(|fe| { fe_to_string(fe) }).collect::<Vec<_>>())?;
        write!(f, "new_oids: {:?} ", self.new_oids.iter().map(|fe| { fe_to_string(fe) }).collect::<Vec<_>>())?;
        write!(f, "new_obj_sks: {:?} ", self.new_obj_sks.iter().map(|fe| { fe_to_string(fe) }).collect::<Vec<_>>())?;
        write!(f, "new_obj_addrs: {:?} ", self.new_obj_addrs.iter().map(|fe| { fe_to_string(fe) }).collect::<Vec<_>>())?;
        Ok(())
    }
}

impl Default for ZkProcessorPartialState {
    fn default() -> Self {
        Self {
            registers:  (0..NOF_PROCESSOR_REGISTERS).map(|_| OuterScalarField::default()).collect(),
            fresh_vals: (0..NOF_FRESH).map(|_| OuterScalarField::default()).collect(),
            new_oids: (0..NOF_NEW_OBJS).map(|_| OuterScalarField::default()).collect(),
            new_obj_sks: (0..NOF_NEW_OBJS).map(|_| OuterScalarField::default()).collect(),
            new_obj_addrs: (0..NOF_NEW_OBJS).map(|_| OuterScalarField::default()).collect(),
        }
    }
}

fn val(state: &ZkProcessorPartialState, src: &RegOrConst) -> OuterScalarField {
    match *src {
        RegOrConst::Reg(idx) => state.registers[idx],
        RegOrConst::Const(c) => c
    }
}

#[derive(Clone)]
pub struct ZkProcessorState {
    pub obj_data: Vec<ObjectData>,
    pub partial: ZkProcessorPartialState
}

impl Debug for ZkProcessorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "obj_data: {:?} ", self.obj_data)?;
        write!(f, "partial: {:?} ", self.partial)?;
        Ok(())
    }
}

impl Default for ZkProcessorState {
    fn default() -> Self {
        Self {
            obj_data: (0..NOF_OBJS).map(|_| ObjectData::default()).collect(),
            partial: ZkProcessorPartialState::default()
        }
    }
}

pub trait Memory {
    fn get_data(&mut self, oid: &OuterScalarField) -> ObjectData;
    fn set_data(&mut self, oid: &OuterScalarField, data: ObjectData);
    fn get_new(&mut self, oid: &OuterScalarField) -> ObjectData;
    fn get_current_obj_state(&self) -> Vec<ObjectData>;
}

pub struct LinearMemory {
    obj_data: Vec<ObjectData>
}

impl Default for LinearMemory {
    fn default() -> Self {
        Self { obj_data: (0..NOF_OBJS).map(|_| ObjectData::default()).collect() }
    }
}

impl LinearMemory {
    fn find_object_idx(&self, oid: &OuterScalarField) -> usize {
        let mut found = false;
        let mut idx = 0;
        for i in 0..NOF_OBJS {
            if self.obj_data[i].is_empty.is_zero() && self.obj_data[i].object_id == *oid {
                if found { panic!("invalid access (multiple inputs with matching object id)"); }
                found = true;
                idx = i;
            }
        }
        if !found { panic!("invalid access (object id not found)"); }
        idx
    }

    fn find_next_empty_object(&self) -> usize {
        for i in 0..NOF_OBJS {
            if self.obj_data[i].is_empty.is_one() {
                return i;
            }
        }
         panic!("no empty object found");
    }
}

impl Memory for LinearMemory {
    fn get_data(&mut self, oid: &OuterScalarField) -> ObjectData {
        let idx = self.find_object_idx(oid);
        self.obj_data[idx].clone()
    }

    fn set_data(&mut self, oid: &OuterScalarField, data: ObjectData) {
        let idx = self.find_object_idx(oid);
        self.obj_data[idx] = data;
    }

    fn get_new(&mut self, oid: &OuterScalarField) -> ObjectData {
        let idx = self.find_next_empty_object();
        self.obj_data[idx].is_empty = OuterScalarField::zero();
        self.obj_data[idx].object_id = *oid;
        self.obj_data[idx].clone()
    }

    fn get_current_obj_state(&self) -> Vec<ObjectData> {
        self.obj_data.clone()
    }
}

pub struct StateBrokerMemory {
    prev_state_view: Rc<RefCell<RuntimeStateView>>,

    accessed_previous_objects: Vec<ObjectData>,

    data_for_oid: BTreeMap<ObjectId, ObjectData>
}

impl StateBrokerMemory {
    pub fn new(state_view: Rc<RefCell<RuntimeStateView>>) -> StateBrokerMemory {
        StateBrokerMemory {
            prev_state_view: state_view,
            accessed_previous_objects: vec![],
            data_for_oid: BTreeMap::new()
        }
    }

    pub fn get_linear_memory(&self) -> LinearMemory {
        assert!(self.accessed_previous_objects.len() <= NOF_OBJS, "too many accessed objects");

        let mut obj_data = vec![];
        for data in self.accessed_previous_objects.iter() {
            obj_data.push(data.clone());
        }
        for _ in 0..(NOF_OBJS - self.accessed_previous_objects.len()) {
            obj_data.push(ObjectData::default());
        }
        LinearMemory {
            obj_data
        }
    }
}

impl Memory for StateBrokerMemory {
    fn get_data(&mut self, oid: &OuterScalarField) -> ObjectData {
        let found = self.data_for_oid.get(oid);
        if let Some(data) = found {
            return data.clone();
        }
        let record = self.prev_state_view.borrow().get_record_for_oid(oid).unwrap_or_else(|_| panic!("unknown object id {}", fe_to_be_hex_str(oid)));
        let data = record.to_object_data();
        self.accessed_previous_objects.push(data.clone());
        self.data_for_oid.insert(*oid, data.clone());
        data
    }

    fn set_data(&mut self, oid: &OuterScalarField, data: ObjectData) {
        self.data_for_oid.insert(*oid, data);
    }

    fn get_new(&mut self, oid: &OuterScalarField) -> ObjectData {
        let mut data = ObjectData::default();
        data.is_empty = OuterScalarField::zero();
        data.object_id = *oid;
        self.data_for_oid.insert(*oid, data.clone());
        data
    }

    fn get_current_obj_state(&self) -> Vec<ObjectData> {
        return vec![];
    }
}


fn ensure_no_overflow(x: OuterScalarField) -> OuterScalarField {
    let upper_bytes = &to_bytes!(x).unwrap()[MAX_BYTES_UINT..];
    for b in upper_bytes {
        if *b != 0u8 {
            panic!("arithmetic under- or overflow detected")
        }
    }
    x
}


#[derive(Default)]
pub struct ZkProcessor {
    pub instructions: Vec<ZkInstruction>,
    pub states: Vec<ZkProcessorState>,
    pub current_time: OuterScalarField
}

impl ZkProcessor {
    pub fn run(&mut self,
        state_view: Rc<RefCell<RuntimeStateView>>,
        instructions: &[ZkInstruction],
        initial_state: ZkProcessorPartialState,
        current_time: OuterScalarField
    ) {
        // first, run with broker memory to access current state via state_view and find linear layout
        debug!("running processor with state broker memory...");
        let mut broker = StateBrokerMemory::new(state_view);
        self.run_with_memory(&mut broker, instructions.to_vec(), initial_state.clone(), current_time);
        debug!("execution consumes object ids: {:?}", broker.accessed_previous_objects.iter().map(|data| fe_to_string(&data.object_id)).collect::<Vec<_>>());      
        let mut linear = broker.get_linear_memory();

        // then, run with linear memory to get correct intermediate states
        debug!("running processor linear memory...");
        self.run_with_memory(&mut linear, instructions.to_vec(), initial_state, current_time);
    }

    fn get_next_nonzero(vals: &mut Vec<OuterScalarField>) -> OuterScalarField {
        for v in vals.iter_mut() {
            if !v.is_zero() {
                let val = *v;
                *v = OuterScalarField::zero();
                return val;
            }
        }
        panic!("no values left");
    }

    fn run_with_memory<I: Memory>(&mut self,
            memory: &mut I,
            instructions: Vec<ZkInstruction>,
            initial_state: ZkProcessorPartialState,
            current_time: OuterScalarField
    ) {
        self.instructions = instructions;
        self.states.clear();
        self.current_time = current_time;

        self.states.push(
            ZkProcessorState {
                obj_data:  memory.get_current_obj_state(),
                partial: initial_state.clone()
            });
        let mut state = initial_state;
        for inst in self.instructions.iter() {
            match inst.opcode {
                OPCODE_NOOP => {
                    debug!("NOOP");
                },
                OPCODE_MOV => {
                    let res = val(&state, &inst.src_1);
                    debug!("MOV {} {}", inst.dst, fe_to_string(&res));
                    state.registers[inst.dst] = val(&state, &inst.src_1);
                },
                OPCODE_CMOV => {
                    let cond_val = val(&state, &inst.src_1);
                    let src_val = val(&state, &inst.src_2);
                    debug!("CMOV {} {} {}", inst.dst, fe_to_string(&cond_val), fe_to_string(&src_val));
                    state.registers[inst.dst] = if cond_val.is_one() { src_val } else { state.registers[inst.dst] };
                },
                OPCODE_ADD => {
                    let src_1_val = val(&state, &inst.src_1);
                    let src_2_val = val(&state, &inst.src_2);
                    debug!("ADD {} {} {}", inst.dst, fe_to_string(&src_1_val), fe_to_string(&src_2_val));
                    state.registers[inst.dst] = ensure_no_overflow(src_1_val + src_2_val);
                },
                OPCODE_SUB => {
                    let src_1_val = val(&state, &inst.src_1);
                    let src_2_val = val(&state, &inst.src_2);
                    debug!("SUB {} {} {}", inst.dst, fe_to_string(&src_1_val), fe_to_string(&src_2_val));
                    state.registers[inst.dst] = ensure_no_overflow(src_1_val - src_2_val);
                },
                OPCODE_MUL => {
                    let src_1_val = val(&state, &inst.src_1);
                    let src_2_val = val(&state, &inst.src_2);
                    debug!("MUL {} {} {}", inst.dst, fe_to_string(&src_1_val), fe_to_string(&src_2_val));
                    state.registers[inst.dst] = ensure_no_overflow(src_1_val * src_2_val);
                },
                OPCODE_EQ => {
                    let src_1_val = val(&state, &inst.src_1);
                    let src_2_val = val(&state, &inst.src_2);
                    debug!("EQ {} {} {}", inst.dst, fe_to_string(&src_1_val), fe_to_string(&src_2_val));
                    state.registers[inst.dst] = if src_1_val == src_2_val { OuterScalarField::one() } else { OuterScalarField::zero() };
                },
                OPCODE_LT => {
                    let src_1_val = val(&state, &inst.src_1);
                    let src_2_val = val(&state, &inst.src_2);
                    debug!("LT {} {} {}", inst.dst, fe_to_string(&src_1_val), fe_to_string(&src_2_val));
                    state.registers[inst.dst] = if src_1_val < src_2_val { OuterScalarField::one() } else { OuterScalarField::zero() };
                },
                OPCODE_REQ => { 
                    let cond_val = val(&state, &inst.src_1);
                    debug!("REQ {}", fe_to_string(&cond_val));
                    if cond_val != OuterScalarField::one() { panic!("requirement failed")}
                },
                OPCODE_LOAD => {
                    let oid = val(&state, &inst.src_1);
                    let field: num_bigint::BigUint = val(&state, &inst.src_2).into();
                    let digits = field.to_u32_digits();
                    let field = if digits.is_empty() { 0usize } else { digits[0] as usize };
                    debug!("LOAD {} {} {}", inst.dst, fe_to_be_hex_str(&oid), field);
                    let data = memory.get_data(&oid);
                    state.registers[inst.dst] = data.payload[field];
                },
                OPCODE_STORE => {
                    let oid = val(&state, &inst.src_1);
                    let field: num_bigint::BigUint = val(&state, &inst.src_2).into();
                    let digits = field.to_u32_digits();
                    let field = if digits.is_empty() { 0usize } else { digits[0] as usize };
                    debug!("STORE {} {} {}", inst.dst, fe_to_be_hex_str(&oid), field);
                    let mut data = memory.get_data(&oid);
                    data.payload[field] = state.registers[inst.dst];
                    memory.set_data(&oid, data);
                },
                OPCODE_CID => {
                    let oid = val(&state, &inst.src_1);
                    debug!("CID {} {}", inst.dst, fe_to_be_hex_str(&oid));
                    let data = memory.get_data(&oid);
                    state.registers[inst.dst] = data.contract_id;
                },
                OPCODE_FRESH => {
                    let val = Self::get_next_nonzero(&mut state.fresh_vals);
                    debug!("FRESH {}", inst.dst);
                    state.registers[inst.dst] = val;
                },
                OPCODE_KILL => {
                    let oid = val(&state, &inst.src_1);
                    debug!("KILL {}", fe_to_be_hex_str(&oid));
                    let mut data = memory.get_data(&oid);
                    data.is_empty = OuterScalarField::one();
                    memory.set_data(&oid, data);
                },
                OPCODE_NEW => {
                    let cid = val(&state, &inst.src_1);
                    debug!("NEW {} {}", inst.dst, fe_to_string(&cid));
                    let oid = Self::get_next_nonzero(&mut state.new_oids);
                    let sk = Self::get_next_nonzero(&mut state.new_obj_sks);
                    let addr = Self::get_next_nonzero(&mut state.new_obj_addrs);
                    let mut data = memory.get_new(&oid);
                    state.registers[inst.dst] = oid;
                    data.contract_id = cid;
                    data.object_id = oid;
                    data.sk_object = sk;
                    data.addr_object = addr;
                    memory.set_data(&oid, data);
                },
                OPCODE_NOW => {
                    debug!("NOW {}", inst.dst);
                    state.registers[inst.dst] = self.current_time;
                },
                OPCODE_PK => {
                    let oid = val(&state, &inst.src_1);
                    debug!("PK {} {}", inst.dst, fe_to_be_hex_str(&oid));
                    let data = memory.get_data(&oid);
                    state.registers[inst.dst] = data.addr_object;
                }
                _ => panic!("unknown opcode")
            }

            self.states.push(
                ZkProcessorState {
                    obj_data:  memory.get_current_obj_state(),
                    partial: state.clone()
                });
        }
    }

    pub fn get_instructions_var(&self, cs: ConstraintSystemRef<OuterScalarField>, mode: AllocationMode) -> ark_relations::r1cs::Result<Vec<constraints::ZkInstructionVar>> {
        let mut inst_var = vec![];
        for inst in self.instructions.iter() {
            inst_var.push(constraints::ZkInstructionVar::new_variable(cs.clone(), || Ok(inst), mode)?);
        }
        Ok(inst_var)
    }

    pub fn get_states_var(&self, cs: ConstraintSystemRef<OuterScalarField>, mode: AllocationMode) -> ark_relations::r1cs::Result<Vec<constraints::ZkProcessorStateVar>> {
        let mut states_var = vec![];
        for state in self.states.iter() {
            states_var.push(constraints::ZkProcessorStateVar::new_variable(cs.clone(), || Ok(state), mode)?);
        }
        Ok(states_var)
    }

    pub fn get_current_time_var(&self, cs: ConstraintSystemRef<OuterScalarField>, mode: AllocationMode) -> ark_relations::r1cs::Result<OuterScalarVar> {
        let var = OuterScalarVar::new_variable(cs, || Ok(self.current_time), mode)?;
        Ok(var)
    }

    pub fn get_initial_state(&self) -> ZkProcessorState {
        self.states[0].clone()
    }

    pub fn get_result_state(&self) -> ZkProcessorState {
        self.states[self.states.len() - 1].clone()
    }
}

pub mod constraints {
    use ark_ff::ToConstraintField;

    use super::*;
        
    pub struct ObjectDataVar {
        pub is_empty: OuterScalarVar,
        pub contract_id: OuterScalarVar,
        pub object_id: OuterScalarVar,
        pub sk_object: OuterScalarVar,
        pub addr_object: OuterScalarVar,
        pub payload: Vec<OuterScalarVar>,   // includes addr_owner
    }

    pub struct ZkProcessorStateVar {
        pub obj_data: Vec<ObjectDataVar>,
        pub registers: Vec<OuterScalarVar>,
        pub fresh_vals: Vec<OuterScalarVar>,
        pub new_oids: Vec<OuterScalarVar>,
        pub new_obj_sks: Vec<OuterScalarVar>,
        pub new_obj_addrs: Vec<OuterScalarVar>,
    }

    impl AllocVar<ZkProcessorState, OuterScalarField> for ZkProcessorStateVar {
        fn new_variable<T: std::borrow::Borrow<ZkProcessorState>>(
            cs: impl Into<ark_relations::r1cs::Namespace<OuterScalarField>>,
            f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
            mode: AllocationMode,
        ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
            let cs = cs.into().cs();
            let state = f()?;

            let obj_data = (0..NOF_OBJS).map(|i| {
                ObjectDataVar {
                    is_empty: OuterScalarVar::new_variable(cs.clone(), || Ok(state.borrow().obj_data[i].is_empty), mode).unwrap(),
                    contract_id: OuterScalarVar::new_variable(cs.clone(), || Ok(state.borrow().obj_data[i].contract_id), mode).unwrap(),
                    object_id: OuterScalarVar::new_variable(cs.clone(), || Ok(state.borrow().obj_data[i].object_id), mode).unwrap(),
                    sk_object: OuterScalarVar::new_variable(cs.clone(), || Ok(state.borrow().obj_data[i].sk_object), mode).unwrap(),
                    addr_object: OuterScalarVar::new_variable(cs.clone(), || Ok(state.borrow().obj_data[i].addr_object), mode).unwrap(),
                    payload: state.borrow().obj_data[i].payload.iter().map(|e|  OuterScalarVar::new_variable(cs.clone(), || Ok(e), mode).unwrap()).collect()
                }
            }).collect();

            Ok(ZkProcessorStateVar {
                obj_data,
                registers: state.borrow().partial.registers.iter().map(|e| OuterScalarVar::new_variable(cs.clone(), || Ok(e), mode).unwrap()).collect(),
                fresh_vals: state.borrow().partial.fresh_vals.iter().map(|e| OuterScalarVar::new_variable(cs.clone(), || Ok(e), mode).unwrap()).collect(),
                new_oids: state.borrow().partial.new_oids.iter().map(|e| OuterScalarVar::new_variable(cs.clone(), || Ok(e), mode).unwrap()).collect(),
                new_obj_sks: state.borrow().partial.new_obj_sks.iter().map(|e| OuterScalarVar::new_variable(cs.clone(), || Ok(e), mode).unwrap()).collect(),
                new_obj_addrs: state.borrow().partial.new_obj_addrs.iter().map(|e| OuterScalarVar::new_variable(cs.clone(), || Ok(e), mode).unwrap()).collect(),
            })
        }
    }

    fn get_fe_for_reg_or_const(x: &RegOrConst) -> (OuterScalarField, OuterScalarField) {
        match x {
            RegOrConst::Reg(addr) => (OuterScalarField::from(*addr as u64), OuterScalarField::zero()),
            RegOrConst::Const(c) => (*c, OuterScalarField::one())
        }
    }

    pub struct ZkInstructionVar {
        pub dst: OuterScalarVar,
        pub src_1: OuterScalarVar,
        pub src_1_is_const: OuterScalarVar,
        pub src_2: OuterScalarVar,
        pub src_2_is_const: OuterScalarVar,

        pub op_is_mov: OuterScalarVar,
        pub op_is_cmov: OuterScalarVar,
        pub op_is_add: OuterScalarVar,
        pub op_is_sub: OuterScalarVar,
        pub op_is_mul: OuterScalarVar,
        pub op_is_eq: OuterScalarVar,
        pub op_is_lt: OuterScalarVar,
        pub op_is_req: OuterScalarVar,
        pub op_is_load: OuterScalarVar,
        pub op_is_store: OuterScalarVar,
        pub op_is_cid: OuterScalarVar,
        pub op_is_fresh: OuterScalarVar,
        pub op_is_kill: OuterScalarVar,
        pub op_is_new: OuterScalarVar,
        pub op_is_now: OuterScalarVar,
        pub op_is_pk: OuterScalarVar,
    }

    impl AllocVar<ZkInstruction, OuterScalarField> for ZkInstructionVar {
        fn new_variable<T: std::borrow::Borrow<ZkInstruction>>(
            cs: impl Into<ark_relations::r1cs::Namespace<OuterScalarField>>,
            f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
            mode: AllocationMode,
        ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
            let cs = cs.into().cs();
            let inst = f()?;

            let (src_1, src_1_is_const) = get_fe_for_reg_or_const(&inst.borrow().src_1);
            let (src_2, src_2_is_const) = get_fe_for_reg_or_const(&inst.borrow().src_2);

            let opcode_var = OuterScalarVar::new_variable(cs.clone(), || Ok(OuterScalarField::from(inst.borrow().opcode as u64)), mode)?;
            let dst_var = OuterScalarVar::new_variable(cs.clone(), || Ok(OuterScalarField::from(inst.borrow().dst as u64)), mode)?;
            let src_1_var = OuterScalarVar::new_variable(cs.clone(), || Ok(src_1), mode)?;
            let src_1_is_const_var = OuterScalarVar::new_variable(cs.clone(), || Ok(src_1_is_const), mode)?;
            let src_2_var = OuterScalarVar::new_variable(cs.clone(), || Ok(src_2), mode)?;
            let src_2_is_const_var =  OuterScalarVar::new_variable(cs.clone(), || Ok(src_2_is_const), mode)?;

            Ok(ZkInstructionVar {
                dst: dst_var,
                src_1: src_1_var,
                src_1_is_const: src_1_is_const_var,
                src_2: src_2_var,
                src_2_is_const: src_2_is_const_var,
                op_is_mov: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_MOV as u64))?)?.into(),
                op_is_cmov: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_CMOV as u64))?)?.into(),
                op_is_add: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_ADD as u64))?)?.into(),
                op_is_sub: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_SUB as u64))?)?.into(),
                op_is_mul: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_MUL as u64))?)?.into(),
                op_is_eq: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_EQ as u64))?)?.into(),
                op_is_lt: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_LT as u64))?)?.into(),
                op_is_req: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_REQ as u64))?)?.into(),
                op_is_load: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_LOAD as u64))?)?.into(),
                op_is_store: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_STORE as u64))?)?.into(),
                op_is_cid: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_CID as u64))?)?.into(),
                op_is_fresh: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_FRESH as u64))?)?.into(),
                op_is_kill: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_KILL as u64))?)?.into(),
                op_is_new: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_NEW as u64))?)?.into(),
                op_is_now: opcode_var.is_eq(&OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(OPCODE_NOW as u64))?)?.into(),
                op_is_pk: opcode_var.is_eq(&OuterScalarVar::new_constant(cs, OuterScalarField::from(OPCODE_PK as u64))?)?.into(),
            })
        }
    }

    impl ToConstraintField<OuterScalarField> for ZkInstruction {
        fn to_field_elements(&self) -> Option<Vec<OuterScalarField>> {
            let (src_1, src_1_is_const) = get_fe_for_reg_or_const(&self.src_1);
            let (src_2, src_2_is_const) = get_fe_for_reg_or_const(&self.src_2);
            Some(vec![
                OuterScalarField::from(self.opcode as u64),
                OuterScalarField::from(self.dst as u64),
                src_1,
                src_1_is_const,
                src_2,
                src_2_is_const
            ])
        }
    }

    pub fn const_fe(cs: &ConstraintSystemRef<OuterScalarField>, val: u64) -> OuterScalarVar {
        OuterScalarVar::new_constant(cs.clone(), OuterScalarField::from(val)).unwrap()
    }

    pub fn select_2(cond: &OuterScalarVar, x_1: &OuterScalarVar, x_0: &OuterScalarVar) -> ark_relations::r1cs::Result<OuterScalarVar> {
        Ok(OuterScalarVar::one().sub(cond).mul(x_0).add(cond.mul(x_1)))
    }

    pub fn get_register_val(mem: &[OuterScalarVar], idx: &OuterScalarVar) -> ark_relations::r1cs::Result<OuterScalarVar> {
        let mut x = OuterScalarVar::zero();
        for (i, mem_item) in mem.iter().enumerate() {
            let i_var = const_fe(&idx.cs(), i as u64);
            let is_eq_fe: OuterScalarVar = i_var.is_eq(idx)?.into();
            x.add_assign(is_eq_fe.mul(mem_item))
        }
        Ok(x)
    }

    pub fn get_obj_field(cycle: usize,
        obj_data: &[ObjectDataVar],
        oid: &OuterScalarVar,
        field: &OuterScalarVar,
        op_is_load: &OuterScalarVar,
        op_is_cid: &OuterScalarVar,
        op_is_pk: &OuterScalarVar
    ) -> ark_relations::r1cs::Result<OuterScalarVar> {
        let cs = &oid.cs();

        let mut x = OuterScalarVar::zero();
        let mut nof_matches = OuterScalarVar::zero();
        for i in 0..NOF_OBJS {
            let is_oid_match: OuterScalarVar = oid.clone().is_eq(&obj_data[i].object_id)?.and(&OuterScalarVar::zero().is_eq(&obj_data[i].is_empty)?)?.into();   dbg_var(&is_oid_match);

            // if match: count the match
            nof_matches.add_assign(&is_oid_match);
            dbg_var(&nof_matches);

            // if match and CID: store the contract id
            let oid_match_and_op_is_cid = is_oid_match.clone().mul(op_is_cid);   dbg_var(&oid_match_and_op_is_cid);
            x.add_assign(oid_match_and_op_is_cid.clone().mul(&obj_data[i].contract_id));

            // if match and PK: store the address
            let oid_match_and_op_is_pk = is_oid_match.clone().mul(op_is_pk);   dbg_var(&oid_match_and_op_is_pk);
            x.add_assign(oid_match_and_op_is_pk.mul(&obj_data[i].addr_object));

            for j in 0..NOF_OBJ_PAYLOAD_ELEMS {
                let is_field_match: OuterScalarVar = const_fe(cs, j as u64).is_eq(field)?.into();  dbg_var(&is_field_match);
                let oid_and_field_match_and_op_is_load = is_oid_match.clone().mul(&is_field_match).mul(op_is_load);

                // if match and LOAD: store the current value
                x.add_assign(oid_and_field_match_and_op_is_load.clone().mul(&obj_data[i].payload[j]));
                dbg_var(&x);
            }
        }
        // enforce that exactly one oid was matching (except if we neither do CID nor LOAD nor PK)
        let exactly_one_match = nof_matches.is_eq(&OuterScalarVar::one())?;
        let exactly_one_match_ok = exactly_one_match.or(
            &op_is_load.is_eq(&OuterScalarVar::zero())?.and(&op_is_cid.is_eq(&OuterScalarVar::zero())?)?.and(&op_is_pk.is_eq(&OuterScalarVar::zero())?)?
        )?;
        enforce_true_with_info(&exactly_one_match_ok, &format!("ZkProcessor - cycle {} - exactly_one_match_ok", cycle));
        Ok(x)
    }

    pub fn check_obj_data(
        cycle: usize,
        obj_data: &[ObjectDataVar],
        obj_data_next: &[ObjectDataVar],
        oid: &OuterScalarVar,
        field_or_cid: &OuterScalarVar,
        stored_val: &OuterScalarVar,
        new_obj_sk: &OuterScalarVar,
        new_obj_addr: &OuterScalarVar,
        op_is_store: &OuterScalarVar,
        op_is_kill: &OuterScalarVar,
        op_is_new: &OuterScalarVar
    ) -> ark_relations::r1cs::Result<()> {
        let cs = &oid.cs();
        let mut nof_store_matches = OuterScalarVar::zero();
        let mut nof_kill_matches = OuterScalarVar::zero();
        let mut found_match_and_new = OuterScalarVar::zero();

        for i in 0..NOF_OBJS {
            let is_oid_match: OuterScalarVar = oid.clone().is_eq(&obj_data[i].object_id)?.into();
            dbg_var(&is_oid_match);

            // check if this is the slot where KILL operates on (non-empty slot with matching oid)
            let is_match_and_kill = is_oid_match.clone().mul(op_is_kill).mul(&OuterScalarVar::one().sub(&obj_data[i].is_empty));
            dbg_var(&is_match_and_kill);

            // count the match
            nof_kill_matches.add_assign(&is_match_and_kill);
            dbg_var(&nof_kill_matches);

            // check if this is the slot where STORE operates on (non-empty slot with matching oid)
            let is_match_and_store = is_oid_match.clone().mul(op_is_store).mul(&OuterScalarVar::one().sub(&obj_data[i].is_empty));
            dbg_var(&is_match_and_store);

            // check if this is the slot where NEW operates on (first empty slot)
            let is_match_and_new = OuterScalarVar::one().sub(&found_match_and_new).mul(&obj_data[i].is_empty).mul(op_is_new);
            found_match_and_new.add_assign(&is_match_and_new);
            dbg_var(&is_match_and_new);

            // if match and NEW: correctly update contract_id, object_id, sk_object, addr_object
            // otherwise: enforce unchanged
            let expected_cid = OuterScalarVar::one().sub(&is_match_and_new).mul(&obj_data[i].contract_id)
                .add(&is_match_and_new.clone().mul(field_or_cid));
            dbg_var(&expected_cid);
            enforce_true_with_info(&obj_data_next[i].contract_id.is_eq(&expected_cid)?, &format!("ZkProcessor - cycle {} - check_obj_data - i = {} - expected_cid", cycle, i));

            let expected_oid = OuterScalarVar::one().sub(&is_match_and_new).mul(&obj_data[i].object_id)
                .add(&is_match_and_new.clone().mul(oid));
            dbg_var(&expected_oid);
            enforce_true_with_info(&obj_data_next[i].object_id.is_eq(&expected_oid)?, &format!("ZkProcessor - cycle {} - check_obj_data - i = {} - expected_oid", cycle, i));

            let expected_sk_object = OuterScalarVar::one().sub(&is_match_and_new).mul(&obj_data[i].sk_object)
                .add(&is_match_and_new.clone().mul(new_obj_sk));
            dbg_var(&expected_sk_object);
            enforce_true_with_info(&obj_data_next[i].sk_object.is_eq(&expected_sk_object)?, &format!("ZkProcessor - cycle {} - check_obj_data - i = {} - expected_sk_object", cycle, i));

            let expected_addr_object = OuterScalarVar::one().sub(&is_match_and_new).mul(&obj_data[i].addr_object)
                .add(&is_match_and_new.clone().mul(new_obj_addr));
            dbg_var(&expected_addr_object);
            enforce_true_with_info(&obj_data_next[i].addr_object.is_eq(&expected_addr_object)?, &format!("ZkProcessor - cycle {} - check_obj_data - i = {} - expected_addr_object", cycle, i));

            // if match and KILL: enforce is_empty set to 1
            // if match and NEW: enforce is_empty set to 0
            // otherwise: enforce is_empty unchanged
            let expected_is_empty = is_match_and_kill.clone().add(
                &OuterScalarVar::one().sub(&is_match_and_kill).mul(&OuterScalarVar::one().sub(&is_match_and_new).mul(&obj_data[i].is_empty))
            );
            dbg_var(&expected_is_empty);
            enforce_true_with_info(&expected_is_empty.is_eq(&obj_data_next[i].is_empty)?, &format!("ZkProcessor - cycle {} - check_obj_data - i = {} - expected_is_empty", cycle, i));

            // check payload
            for j in 0..NOF_OBJ_PAYLOAD_ELEMS {
                let is_field_match: OuterScalarVar = const_fe(cs, j as u64).is_eq(field_or_cid)?.into();
                dbg_var(&is_field_match);
                let is_field_match_for_store = is_match_and_store.clone().mul(&is_field_match);
                dbg_var(&is_field_match_for_store);

                // if match: count the match
                nof_store_matches.add_assign(&is_field_match_for_store);
                dbg_var(&nof_store_matches);

                // if is_field_match_for_store: must be updated to stored_val
                // otherwise: must be unchanged
                let entry_ok = is_field_match_for_store.is_eq(&OuterScalarVar::zero())?.and(&obj_data[i].payload[j].clone().is_eq(&obj_data_next[i].payload[j])?)?.or(
                    &is_field_match_for_store.is_eq(&OuterScalarVar::one())?.and(&stored_val.clone().is_eq(&obj_data_next[i].payload[j])?)?
                )?;
                enforce_true_with_info(&entry_ok, &format!("ZkProcessor - cycle {} - entry_ok - object {} - payload {}", cycle, i, j));
            }
        }

        // enforce that exactly one field was matching (for STORE)
        let exactly_one_store_match = nof_store_matches.is_eq(&OuterScalarVar::one())?;
        let exactly_one_store_match_ok = exactly_one_store_match.or(&op_is_store.is_eq(&OuterScalarVar::zero())?)?;
        enforce_true_with_info(&exactly_one_store_match_ok, &format!("ZkProcessor - cycle {} - exactly_one_store_match_ok", cycle));
        
        // enforce that exactly one object was matching (for KILL)
        let exactly_one_kill_match = nof_kill_matches.is_eq(&OuterScalarVar::one())?;
        let exactly_one_kill_match_ok = exactly_one_kill_match.or(&op_is_kill.is_eq(&OuterScalarVar::zero())?)?;
        enforce_true_with_info(&exactly_one_kill_match_ok, &format!("ZkProcessor - cycle {} - exactly_one_kill_match_ok", cycle));

        Ok(())
    }

    pub fn get_next_nonzero(
        cycle: usize,
        vals: &[OuterScalarVar],
        vals_next: &[OuterScalarVar],
        enforce_found: &OuterScalarVar
    ) -> ark_relations::r1cs::Result<OuterScalarVar> {
        let mut x = OuterScalarVar::zero();
        let mut first = OuterScalarVar::one();

        // find the first occurrence of a non-zero entry
        for i in 0..vals.len() {
            dbg_var(&vals[i]);
            dbg_var(&vals_next[i]);

            x.add_assign(&first.clone().mul(&vals[i]));   dbg_var(&x);
            let found_here = x.is_zero()?.not().and(&first.is_one()?)?; dbg_var(&found_here.clone().into());
            first = x.is_zero()?.into();    dbg_var(&first.clone());

            // check fresh_vals unchanged, except if found_here and enforce_found (in which case the entry should be set to zero)
            let entry_ok = enforce_found.clone().is_zero()?.or(&found_here.not())?.and(&vals[i].clone().is_eq(&vals_next[i])?)?
                .or(&enforce_found.is_one()?.and(&found_here)?.and(&vals_next[i].clone().is_zero()?)?)?;
            dbg_var(&entry_ok.clone().into());
            enforce_true_with_info(&entry_ok, &format!("ZkProcessor - cycle {} - get_next_nonzero - i = {} - entry_ok", i, cycle));
        }

        // ensure we found a non-zero value if enforce_found
        let enforce_found_ok = enforce_found.clone().is_zero()?.or(&first.is_zero()?)?;
        enforce_true_with_info(&enforce_found_ok, &format!("ZkProcessor - cycle {} - get_next_nonzero - enforce_found_ok", cycle));
        Ok(x)
    }

    pub fn is_in_range(val: &OuterScalarVar) -> ark_relations::r1cs::Result<Boolean<OuterScalarField>> {
        let bits = val.to_bits_le()?;
        let mut ok = Boolean::TRUE;
        for bit in &bits[MAX_BYTES_UINT*8..] {
            ok = ok.and(&bit.not())?
        }
        Ok(ok)
    }

    pub struct ZkProcessorGadget {
        pub cs: ConstraintSystemRef<OuterScalarField>,
        pub instructions: Vec<ZkInstructionVar>,
        pub states: Vec<ZkProcessorStateVar>,
        pub current_time: OuterScalarVar,
    }

    impl ZkProcessorGadget {
        pub fn new(cs: ConstraintSystemRef<OuterScalarField>,
            instructions: Vec<ZkInstructionVar>,
            states: Vec<ZkProcessorStateVar>,
            current_time: OuterScalarVar,
        ) -> ZkProcessorGadget {
            ZkProcessorGadget {
                cs,
                instructions,
                states,
                current_time
            }
        }

        pub fn run(&self) -> ark_relations::r1cs::Result<()>  {
            assert_eq!(self.instructions.len() + 1, self.states.len());
            for state in self.states.iter() {
                assert_eq!(state.obj_data.len(), NOF_OBJS);
                for data in state.obj_data.iter() {
                    assert_eq!(data.payload.len(), NOF_OBJ_PAYLOAD_ELEMS);
                }
                assert_eq!(state.registers.len(), NOF_PROCESSOR_REGISTERS);
                assert_eq!(state.fresh_vals.len(), NOF_FRESH);
                assert_eq!(state.new_oids.len(), NOF_NEW_OBJS);
                assert_eq!(state.new_obj_sks.len(), NOF_NEW_OBJS);
            }

            let zero_const = OuterScalarVar::zero();
            let one_const = OuterScalarVar::one();

            for cycle in 0..self.instructions.len() {
                let inst = &self.instructions[cycle];
                let state = &self.states[cycle];
                let state_next = &self.states[cycle + 1];

                // get the value of src_1 (access register or use constant)
                let src_1 = select_2(&inst.src_1_is_const,
                    &inst.src_1,
                    &get_register_val(&state.registers, &inst.src_1)?
                )?;
                dbg_var(&src_1);

                // get the value of src_2 (access register or use constant)
                let src_2 = select_2(&inst.src_2_is_const,
                    &inst.src_2,
                    &get_register_val(&state.registers, &inst.src_2)?
                )?;
                dbg_var(&src_2);

                // get the current and next value of the destination register
                let dst = get_register_val(&state.registers, &inst.dst)?;  dbg_var(&dst);
                let dst_next = get_register_val(&state_next.registers, &inst.dst)?;  dbg_var(&dst_next);

                // get the current value of the object field targeted by LOAD, or contract id in case of CID, or public key in case of PK
                let obj_field = get_obj_field(cycle, &state.obj_data, &src_1, &src_2, &inst.op_is_load, &inst.op_is_cid, &inst.op_is_pk)?; dbg_var(&obj_field);

                // get the next fresh value (for FRESH)
                let fresh_val = get_next_nonzero(cycle, &state.fresh_vals, &state_next.fresh_vals, &inst.op_is_fresh)?;   dbg_var(&fresh_val);

                // get the next new oid, sk and addr (for NEW)
                let new_oid = get_next_nonzero(cycle, &state.new_oids, &state_next.new_oids, &inst.op_is_new)?;    dbg_var(&new_oid);
                let new_obj_sk = get_next_nonzero(cycle, &state.new_obj_sks, &state_next.new_obj_sks, &inst.op_is_new)?;    dbg_var(&new_obj_sk);
                let new_obj_addr = get_next_nonzero(cycle, &state.new_obj_addrs, &state_next.new_obj_addrs, &inst.op_is_new)?;    dbg_var(&new_obj_addr);

                // check whether condition (stored at src_1) is true (for CMOV and REQ)
                let condition_ok: OuterScalarVar = src_1.clone().is_eq(&one_const)?.into(); dbg_var(&condition_ok);

                // assert that condition is true for REQ
                let require_ok = inst.op_is_req.clone().is_eq(&zero_const)?.or(&inst.op_is_req.clone().is_eq(&one_const)?.and(&condition_ok.is_eq(&one_const)?)?)?;
                enforce_true_with_info(&require_ok, &format!("ZkProcessor - cycle {} - require_ok", cycle));

                // compute the results of arithmetic operations and moves
                let mov_res = src_1.clone();  dbg_var(&mov_res);
                let cmov_res = src_2.clone().mul(&condition_ok).add(&dst.clone().mul(&one_const.clone().sub(&condition_ok.clone())));   dbg_var(&cmov_res);
                let add_res = src_1.clone().add(&src_2);  dbg_var(&add_res);
                let sub_res = src_1.clone().sub(&src_2);  dbg_var(&sub_res);
                let mul_res = src_1.clone().mul(&src_2);  dbg_var(&mul_res);
                let eq_res: OuterScalarVar = src_1.clone().is_eq(&src_2)?.into();  dbg_var(&eq_res);
                let lt_res: OuterScalarVar = src_1.clone().is_cmp_unchecked(&src_2, Ordering::Less, false)?.into(); dbg_var(&lt_res);

                // select the appropriate operation result (incl. LOAD)
                let op_res = mov_res.mul(&inst.op_is_mov)
                    .add(cmov_res.mul(&inst.op_is_cmov))
                    .add(add_res.mul(&inst.op_is_add))
                    .add(sub_res.mul(&inst.op_is_sub))
                    .add(mul_res.mul(&inst.op_is_mul))
                    .add(eq_res.mul(&inst.op_is_eq))
                    .add(lt_res.mul(&inst.op_is_lt))
                    .add(obj_field.mul(&inst.op_is_load.clone().add(&inst.op_is_cid).add(&inst.op_is_pk)))
                    .add(fresh_val.mul(&inst.op_is_fresh))
                    .add(new_oid.clone().mul(&inst.op_is_new))
                    .add(self.current_time.clone().mul(&inst.op_is_now));
                dbg_var(&op_res);

                // ensure operation did not result in an under- or overflow for ADD, MUL, SUB
                let op_res_in_range = is_in_range(&op_res)?;
                let op_res_ok = op_res_in_range.or(
                    &inst.op_is_add.clone().add(&inst.op_is_sub).add(&inst.op_is_mul).is_zero()?
                )?;
                enforce_true_with_info(&op_res_ok, &format!("ZkProcessor - cycle {} - op_res_ok", cycle));

                // check whether the current operation modifies the dst register (arithmetics, moves, LOAD, CID, FRESH, NEW)
                let is_write_dst = inst.op_is_mov.clone()
                    .add(&inst.op_is_cmov)
                    .add(&inst.op_is_add)
                    .add(&inst.op_is_sub)
                    .add(&inst.op_is_mul)
                    .add(&inst.op_is_eq)
                    .add(&inst.op_is_lt)
                    .add(&inst.op_is_load)
                    .add(&inst.op_is_cid)
                    .add(&inst.op_is_fresh)
                    .add(&inst.op_is_new)
                    .add(&inst.op_is_now)
                    .add(&inst.op_is_pk);
                dbg_var(&is_write_dst);
                
                // check correct update of dst (changed for dst-modifying operations, unchanged for all others)
                let dst_next_ok = is_write_dst.is_eq(&one_const)?.and(&op_res.is_eq(&dst_next)?)?.or(
                    &is_write_dst.is_eq(&zero_const)?.and(&dst.is_eq(&dst_next)?)?
                )?;
                enforce_true_with_info(&dst_next_ok, &format!("ZkProcessor - cycle {} - dst_next_ok", cycle));

                // check all registers other than dst are unchanged
                for i in 0..NOF_PROCESSOR_REGISTERS {
                    let i_var = const_fe(&self.cs, i as u64);
                    let unchanged = state.registers[i].is_eq(&state_next.registers[i])?;
                    let reg_ok = i_var.is_eq(&inst.dst)?.or(&unchanged)?;
                    enforce_true_with_info(&reg_ok, &format!("ZkProcessor - cycle {} - reg_ok", cycle));
                }

                // check correct updates to obj_data (correctly updated in case of STORE, KILL and NEW, unchanged otherwise)
                let oid = new_oid.mul(&inst.op_is_new).add(src_1.clone().mul(&one_const.clone().sub(&inst.op_is_new)));
                let field_or_cid = src_1.mul(&inst.op_is_new).add(src_2.mul(&one_const.clone().sub(&inst.op_is_new)));
                check_obj_data(cycle, &state.obj_data, &state_next.obj_data, &oid, &field_or_cid, &dst, &new_obj_sk, &new_obj_addr, &inst.op_is_store, &inst.op_is_kill, &inst.op_is_new)?;

                dbg_ensure_satisfied(&self.cs, &format!("processor - cycle {}", cycle));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_relations::r1cs::ConstraintSystem;

    use crate::constants::NOF_PROCESSOR_CYCLES;

    use super::*;
    use super::RegOrConst::*;
    use super::constraints::*;

    #[test]
    fn test_processor_count_constraints() {
        let mut processor = ZkProcessor::default();
        let initial_state = ZkProcessorPartialState::default();
        let instructions: Vec<_> = (0..NOF_PROCESSOR_CYCLES).map(|_| ZkInstruction::default()).collect();
        let mut memory = LinearMemory::default();
        processor.run_with_memory(&mut memory, instructions, initial_state, OuterScalarField::from(77));

        let cs: ConstraintSystemRef<OuterScalarField> = ConstraintSystem::new_ref();
        let gadget = ZkProcessorGadget::new(cs.clone(),
            processor.get_instructions_var(cs.clone(), AllocationMode::Witness).unwrap(),
            processor.get_states_var(cs.clone(), AllocationMode::Witness).unwrap(),
            processor.get_current_time_var(cs.clone(), AllocationMode::Input).unwrap());
        gadget.run().unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("number of registers:  {}", NOF_PROCESSOR_REGISTERS);
        println!("object memory size:  {}", NOF_OBJS*NOF_OBJ_PAYLOAD_ELEMS);
        println!("num_cycles:  {}", NOF_PROCESSOR_CYCLES);
        println!("num_constraints:  {}", cs.num_constraints());
    }

    #[test]
    fn test_processor_arith() {
        let mut processor = ZkProcessor::default();
        let mut initial_state = ZkProcessorPartialState::default();
        // --- args ---
        initial_state.registers[5] = OuterScalarField::from(39u64);
        // ------------

        // --- program ---
        let instructions = vec![
            ZkInstruction { opcode: OPCODE_MOV, dst: 0, src_1: Const(OuterScalarField::from(3u64)), src_2: Reg(0) },
            ZkInstruction { opcode: OPCODE_MOV, dst: 1, src_1: Const(OuterScalarField::from(5u64)), src_2: Reg(0) },
            ZkInstruction { opcode: OPCODE_MOV, dst: 2, src_1: Reg(5), src_2: Reg(0) },
            ZkInstruction { opcode: OPCODE_ADD, dst: 0, src_1: Reg(0), src_2: Reg(1) },
            ZkInstruction { opcode: OPCODE_MUL, dst: 0, src_1: Reg(1), src_2: Reg(0) },
            ZkInstruction { opcode: OPCODE_SUB, dst: 2, src_1: Reg(0), src_2: Reg(2) },
            ZkInstruction { opcode: OPCODE_NOOP, dst: 0, src_1: Reg(0), src_2: Reg(0) },
            ZkInstruction { opcode: OPCODE_LT, dst: 4, src_1: Reg(2), src_2: Reg(1) },
            ZkInstruction { opcode: OPCODE_REQ, dst: 0, src_1: Reg(4), src_2: Reg(0) },
            ZkInstruction { opcode: OPCODE_CMOV, dst: 3, src_1: Reg(2), src_2: Const(OuterScalarField::from(99u64))},
            ZkInstruction { opcode: OPCODE_EQ, dst: 1, src_1: Const(OuterScalarField::from(99u64)), src_2: Reg(3)},
            ZkInstruction { opcode: OPCODE_NOW, dst: 5, src_1: Reg(0), src_2: Reg(0)},
        ];
        // ---------------
        let mut memory = LinearMemory::default();
        processor.run_with_memory(&mut memory, instructions, initial_state, OuterScalarField::from(77));

        let res = processor.get_result_state();
        assert_eq!(res.partial.registers[0], OuterScalarField::from(40u64));
        assert_eq!(res.partial.registers[1], OuterScalarField::from(1u64));
        assert_eq!(res.partial.registers[2], OuterScalarField::from(1u64));
        assert_eq!(res.partial.registers[3], OuterScalarField::from(99u64));
        assert_eq!(res.partial.registers[4], OuterScalarField::from(1u64));
        assert_eq!(res.partial.registers[5], OuterScalarField::from(77u64));

        let cs: ConstraintSystemRef<OuterScalarField> = ConstraintSystem::new_ref();
        let gadget = ZkProcessorGadget::new(cs.clone(),
            processor.get_instructions_var(cs.clone(), AllocationMode::Witness).unwrap(),
            processor.get_states_var(cs.clone(), AllocationMode::Witness).unwrap(),
            processor.get_current_time_var(cs.clone(), AllocationMode::Input).unwrap());
        gadget.run().unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    #[should_panic]
    fn test_processor_arith_overflow() {
        let mut processor = ZkProcessor::default();
        let mut initial_state = ZkProcessorPartialState::default();
        initial_state.registers[4] = OuterScalarField::from(20u64);
        initial_state.registers[5] = OuterScalarField::from(39u64);
        let instructions = vec![
            ZkInstruction { opcode: OPCODE_SUB, dst: 0, src_1: Reg(4), src_2: Reg(5) },
   
        ];
        let mut memory = LinearMemory::default();
        processor.run_with_memory(&mut memory, instructions, initial_state, OuterScalarField::from(77));
    }

    #[test]
    fn test_processor_objects() {
        let mut processor = ZkProcessor::default();
        let mut initial_state = ZkProcessorPartialState::default();
        let mut memory = LinearMemory::default();

        initial_state.new_oids[1] = OuterScalarField::from(121212121212u64);
        initial_state.new_obj_sks[2] = OuterScalarField::from(34343434343434u64);
        initial_state.new_obj_addrs[2] = OuterScalarField::from(56565656565656u64);

        // --- args ---
        initial_state.registers[5] = OuterScalarField::from(222);
        // ------------

        // --- obj_data ---
        memory.obj_data[0].is_empty = OuterScalarField::zero();
        memory.obj_data[0].contract_id = OuterScalarField::from(12345);
        memory.obj_data[0].object_id = OuterScalarField::from(222);       // oid_0 = 222
        memory.obj_data[0].sk_object = OuterScalarField::from(9999999999999u64);
        memory.obj_data[0].addr_object = OuterScalarField::from(7007);
        memory.obj_data[0].payload[3] = OuterScalarField::from(5);    // oid_0.field(3) = 5

        memory.obj_data[2].is_empty = OuterScalarField::zero();
        memory.obj_data[2].contract_id = OuterScalarField::from(12345);
        memory.obj_data[2].object_id = OuterScalarField::from(444);       // oid_1 = 444
        memory.obj_data[2].sk_object = OuterScalarField::from(8888888888888u64);
        memory.obj_data[2].payload[2] = OuterScalarField::from(9);    // oid_1.field(2) = 9
        // --------------

        // --- program ---
        let instructions = vec![
            ZkInstruction { opcode: OPCODE_LOAD, dst: 1, src_1: Const(OuterScalarField::from(444)), src_2: Const(OuterScalarField::from(2)) },  
            ZkInstruction { opcode: OPCODE_STORE, dst: 1, src_1: Reg(5), src_2: Const(OuterScalarField::from(1)) }, 
            ZkInstruction { opcode: OPCODE_CID, dst: 2, src_1: Const(OuterScalarField::from(444)), src_2: Reg(0)},  
            ZkInstruction { opcode: OPCODE_NEW, dst: 3, src_1: Reg(2), src_2: Reg(0)},  
            ZkInstruction { opcode: OPCODE_KILL, dst: 0, src_1: Const(OuterScalarField::from(444)), src_2: Reg(0)}, 
            ZkInstruction { opcode: OPCODE_PK, dst: 0, src_1: Const(OuterScalarField::from(222)), src_2: Reg(0)},   
        ];
        // ---------------
        processor.run_with_memory(&mut memory, instructions, initial_state, OuterScalarField::from(77));

        let res = processor.get_result_state();
        assert_eq!(res.obj_data[0].payload[1], OuterScalarField::from(9));
        assert_eq!(res.obj_data[0].payload[3], OuterScalarField::from(5));
        assert_eq!(res.obj_data[1].is_empty, OuterScalarField::zero());
        assert_eq!(res.obj_data[1].contract_id, OuterScalarField::from(12345));
        assert_eq!(res.obj_data[1].object_id, OuterScalarField::from(121212121212u64));
        assert_eq!(res.obj_data[1].sk_object, OuterScalarField::from(34343434343434u64));
        assert_eq!(res.obj_data[1].addr_object, OuterScalarField::from(56565656565656u64));
        assert_eq!(res.partial.registers[3], OuterScalarField::from(121212121212u64));
        assert_eq!(res.partial.registers[2], OuterScalarField::from(12345));
        assert_eq!(res.partial.registers[0], OuterScalarField::from(7007));

        let cs: ConstraintSystemRef<OuterScalarField> = ConstraintSystem::new_ref();
        let gadget = ZkProcessorGadget::new(cs.clone(),
            processor.get_instructions_var(cs.clone(), AllocationMode::Witness).unwrap(),
            processor.get_states_var(cs.clone(), AllocationMode::Witness).unwrap(),
            processor.get_current_time_var(cs.clone(), AllocationMode::Input).unwrap());
        gadget.run().unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_processor_fresh() {
        let mut processor = ZkProcessor::default();
        let mut initial_state = ZkProcessorPartialState::default();
        let mut memory = LinearMemory::default();
        initial_state.fresh_vals[1] = OuterScalarField::from(6u64);
        initial_state.fresh_vals[2] = OuterScalarField::from(8u64);

         // --- program ---
        let instructions = vec![
            ZkInstruction { opcode: OPCODE_FRESH, dst: 0, src_1: Reg(0), src_2: Reg(0) },
            ZkInstruction { opcode: OPCODE_FRESH, dst: 1, src_1: Reg(0), src_2: Reg(0) },
        ];
        // ---------------
        processor.run_with_memory(&mut memory, instructions, initial_state, OuterScalarField::from(77));

        let res = processor.get_result_state();
        assert_eq!(res.partial.registers[0], OuterScalarField::from(6u64));
        assert_eq!(res.partial.registers[1], OuterScalarField::from(8u64));

        let cs: ConstraintSystemRef<OuterScalarField> = ConstraintSystem::new_ref();
        let gadget = ZkProcessorGadget::new(cs.clone(),
            processor.get_instructions_var(cs.clone(), AllocationMode::Witness).unwrap(),
            processor.get_states_var(cs.clone(), AllocationMode::Witness).unwrap(),
            processor.get_current_time_var(cs.clone(), AllocationMode::Input).unwrap());
        gadget.run().unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}