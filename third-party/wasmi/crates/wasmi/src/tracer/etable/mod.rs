pub(crate) mod pre;
pub mod step_info;

use crate::{
    engine::stack::ValueStackPtr,
    mtable::{imtable::IMTable, memory_event_of_step, MTable, VarType},
};
use serde::{Deserialize, Serialize};
use step_info::StepInfo;
use wasmi_core::UntypedValue;

pub fn from_untyped_value_to_u64_with_typ(vtype: VarType, val: UntypedValue) -> u64 {
    match vtype {
        VarType::I32 => val.to_bits(),
        VarType::I64 => val.to_bits(),
        VarType::F32 => val.to_bits(),
        VarType::F64 => val.to_bits(),
        _ => panic!("Unsupported type"),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ETEntry {
    pub eid: u32,
    pub allocated_memory_pages: usize,
    pub step_info: StepInfo,
    pub sp: ValueStackPtr,
}

#[derive(Debug, Default, Clone)]
pub struct ETable(Vec<ETEntry>);

impl ETable {
    pub fn new(entries: Vec<ETEntry>) -> Self {
        ETable(entries)
    }

    pub fn entries(&self) -> &Vec<ETEntry> {
        &self.0
    }

    pub fn entries_mut(&mut self) -> &mut Vec<ETEntry> {
        &mut self.0
    }
    pub fn push(&mut self, allocated_memory_pages: u32, step_info: StepInfo, sp: ValueStackPtr) {
        let etable_entry = ETEntry {
            eid: (self.entries().len() + 1).try_into().unwrap(),
            allocated_memory_pages: allocated_memory_pages as usize,
            step_info,
            sp,
        };

        self.entries_mut().push(etable_entry);
    }

    pub fn mtable(&self, imtable: &IMTable) -> MTable {
        let mentries = self
            .entries()
            .iter()
            .map(|eentry| memory_event_of_step(eentry, &mut 1))
            .collect::<Vec<Vec<_>>>()
            .concat();

        MTable::new_with_imtable(mentries, imtable)
    }
    /// Builds execution trace from the entries in the table
    pub fn plain_execution_trace(&self) -> Vec<StepInfo> {
        self.entries()
            .iter()
            .map(|e| e.step_info.clone())
            .collect::<Vec<_>>()
    }

    /// Converts the table into entries
    pub fn into_entries(self) -> Vec<ETEntry> {
        self.0
    }

    /// Get number of entries in the table
    pub fn len(&self) -> usize {
        self.entries().len()
    }
}
