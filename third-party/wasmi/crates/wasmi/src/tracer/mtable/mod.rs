pub mod imtable;

use std::vec;

use imtable::IMTable;
use serde::{Deserialize, Serialize};
use wasmi_core::ValueType;

use crate::{
    engine::stack::ValueStackPtr,
    etable::{step_info::StepInfo, ETEntry},
};

#[derive(Default, Debug, Clone)]
pub struct MTable(Vec<MemoryTableEntry>);

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct MemoryTableEntry {
    pub eid: u32,

    /// Emid is sub memory op id of eid.
    ///
    /// E.g. an opcode gets a value from stack top and changes it.
    ///
    /// This event has two memory ops on the same memory address,
    /// So we need emid to seq the r/w op, which is an incremental value starting from 1.
    pub emid: u32,
    pub addr: usize,
    pub ltype: LocationType,
    pub atype: AccessType,
    pub is_mutable: bool,
    pub value: u64,
}

impl MTable {
    pub fn new(entries: Vec<MemoryTableEntry>) -> Self {
        let mtable = MTable(entries);
        mtable
    }
    pub fn new_with_imtable(entries: Vec<MemoryTableEntry>, imtable: &IMTable) -> Self {
        let mut init_entries = MTable::push_accessed_memory_initialization(imtable);
        init_entries.extend(entries);
        let mtable = MTable(init_entries);
        mtable
    }

    fn push_accessed_memory_initialization(imtable: &IMTable) -> Vec<MemoryTableEntry> {
        let mut mem_op = vec![];
        for entry in imtable.entries() {
            mem_op.push(MemoryTableEntry {
                eid: 0,
                emid: 0,
                addr: entry.addr,
                ltype: entry.ltype,
                atype: AccessType::Init,
                is_mutable: true,
                value: entry.value,
            });
        }
        mem_op
    }

    pub fn entries(&self) -> &Vec<MemoryTableEntry> {
        &self.0
    }

    /// Return Mutable Vec<MemoryTableEntry>
    pub fn entries_mut(&mut self) -> &mut Vec<MemoryTableEntry> {
        &mut self.0
    }

    pub fn get_heap_entries(&self) -> Self {
        let entries = self
            .0
            .iter()
            .filter(|entry| entry.ltype == LocationType::Heap)
            .cloned()
            .collect();

        MTable(entries)
    }
}

fn mem_op_from_stack_only_step(
    sp_before_execution: ValueStackPtr,
    eid: u32,
    emid: &mut u32,
    pop_value: &[u64],
    push_value: &[u64],
) -> Vec<MemoryTableEntry> {
    let mut mem_op = vec![];
    let mut depth = 0;

    for i in 0..pop_value.len() {
        mem_op.push(MemoryTableEntry {
            eid,
            emid: *emid,
            addr: sp_before_execution.into_sub(depth + 1).get_addr(),
            ltype: LocationType::Stack,
            atype: AccessType::Read,
            is_mutable: true,
            value: pop_value[i],
        });
        *emid = (*emid).checked_add(1).unwrap();
        depth += 1;
    }

    for i in 0..push_value.len() {
        mem_op.push(MemoryTableEntry {
            eid,
            emid: *emid,
            addr: sp_before_execution.into_sub(depth).get_addr(),
            ltype: LocationType::Stack,
            atype: AccessType::Write,
            is_mutable: true,
            value: push_value[i],
        });
        if depth == 0 {
            break;
        }
        depth -= 1;
        *emid = (*emid).checked_add(1).unwrap();
    }

    mem_op
}

pub fn memory_event_of_step(event: &ETEntry, emid: &mut u32) -> Vec<MemoryTableEntry> {
    let eid = event.eid;
    let sp_before_execution = event.sp;

    match &event.step_info {
        StepInfo::Br { .. } => vec![],
        StepInfo::BrIfEqz { .. } => vec![],
        StepInfo::BrIfNez { .. } => vec![],
        StepInfo::BrAdjust { .. } => vec![],
        StepInfo::Return { drop, keep_values } => {
            let mut ops = vec![];
            for i in 0..keep_values.len() {
                ops.push(MemoryTableEntry {
                    eid,
                    emid: *emid,
                    addr: sp_before_execution.into_sub(i + 1).get_addr(),
                    ltype: LocationType::Stack,
                    atype: AccessType::Read,
                    is_mutable: true,
                    value: keep_values[i],
                });
                *emid = (*emid).checked_add(1).unwrap();
            }

            for i in 0..keep_values.len() {
                ops.push(MemoryTableEntry {
                    eid,
                    emid: *emid,
                    addr: sp_before_execution
                        .into_sub(i + 1 + *drop as usize)
                        .get_addr(),
                    ltype: LocationType::Stack,
                    atype: AccessType::Write,
                    is_mutable: true,
                    value: keep_values[i],
                });
                *emid = (*emid).checked_add(1).unwrap();
            }

            ops
        }
        StepInfo::Drop { .. } => vec![],
        StepInfo::Select {
            val1,
            val2,
            cond,
            result,
        } => {
            let mut depth = 1;
            let mut ops = vec![];

            ops.push(MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(depth).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *cond,
            });
            depth += 1;
            *emid = (*emid).checked_add(1).unwrap();

            ops.push(MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(depth).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *val2,
            });
            depth += 1;
            *emid = (*emid).checked_add(1).unwrap();

            ops.push(MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(depth).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *val1,
            });

            *emid = (*emid).checked_add(1).unwrap();

            ops.push(MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(depth).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Write,
                is_mutable: true,
                value: *result,
            });
            *emid = (*emid).checked_add(1).unwrap();

            ops
        }
        StepInfo::CallInternal { args } => {
            let mut ops = vec![];
            for i in 0..args.len() {
                ops.push(MemoryTableEntry {
                    eid,
                    emid: *emid,
                    addr: sp_before_execution.into_add(i).get_addr(),
                    ltype: LocationType::Stack,
                    atype: AccessType::Write,
                    is_mutable: true,
                    value: args[i],
                });
                *emid = (*emid).checked_add(1).unwrap();
            }
            ops
        }
        StepInfo::Call { args } => {
            let mut ops = vec![];
            for i in 0..args.len() {
                ops.push(MemoryTableEntry {
                    eid,
                    emid: *emid,
                    addr: sp_before_execution.into_add(i).get_addr(),
                    ltype: LocationType::Stack,
                    atype: AccessType::Write,
                    is_mutable: true,
                    value: args[i],
                });
                *emid = (*emid).checked_add(1).unwrap();
            }
            ops
        }
        StepInfo::LocalGet { depth, value } => {
            let read = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(*depth).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *value,
            };
            *emid = (*emid).checked_add(1).unwrap();

            let write = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Write,
                is_mutable: true,
                value: *value,
            };
            *emid = (*emid).checked_add(1).unwrap();
            vec![read, write]
        }
        StepInfo::SetLocal { depth, value } => {
            let read = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(1).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *value,
            };
            *emid = (*emid).checked_add(1).unwrap();

            let write = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(depth + 1).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Write,
                is_mutable: true,
                value: *value,
            };
            *emid = (*emid).checked_add(1).unwrap();

            vec![read, write]
        }
        StepInfo::TeeLocal { depth, value } => {
            let read = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(1).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *value,
            };

            *emid = (*emid).checked_add(1).unwrap();

            let write = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(*depth).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Write,
                is_mutable: true,
                value: *value,
            };
            *emid = (*emid).checked_add(1).unwrap();
            vec![read, write]
        }

        StepInfo::GetGlobal { idx, value, .. } => {
            let global_get = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: *idx as usize,
                ltype: LocationType::Global,
                atype: AccessType::Read,
                is_mutable: true,
                value: *value,
            };
            *emid = (*emid).checked_add(1).unwrap();

            let stack_write = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Write,
                is_mutable: true,
                value: *value,
            };
            *emid = (*emid).checked_add(1).unwrap();

            vec![global_get, stack_write]
        }
        StepInfo::SetGlobal { idx, value } => {
            let stack_read = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(1).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *value,
            };
            *emid = (*emid).checked_add(1).unwrap();

            let global_set = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: *idx as usize,
                ltype: LocationType::Global,
                atype: AccessType::Write,
                is_mutable: true,
                value: *value,
            };
            *emid = (*emid).checked_add(1).unwrap();

            vec![stack_read, global_set]
        }
        StepInfo::Load {
            load_size,
            raw_address,
            effective_address,
            value,
            block_value1,
            block_value2,
            ..
        } => {
            let load_address_from_stack = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(1).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *raw_address as u64,
            };
            *emid = (*emid).checked_add(1).unwrap();

            let load_value1 = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: (*effective_address) / 8,
                ltype: LocationType::Heap,
                atype: AccessType::Read,
                // Load u64 from address which align with 8
                is_mutable: true,
                // The value will be used to lookup within imtable, hence block_value is given here
                value: *block_value1,
            };

            let load_value2 = if *effective_address % 8 + load_size.byte_size() > 8 {
                *emid = (*emid).checked_add(1).unwrap();
                Some(MemoryTableEntry {
                    eid,
                    emid: *emid,
                    addr: *effective_address / 8 + 1,
                    ltype: LocationType::Heap,
                    atype: AccessType::Read,
                    is_mutable: true,
                    // The value will be used to lookup within imtable, hence block_value is given here
                    value: *block_value2,
                })
            } else {
                None
            };

            *emid = (*emid).checked_add(1).unwrap();
            let push_value = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(1).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Write,
                is_mutable: true,
                value: *value,
            };

            vec![
                vec![load_address_from_stack, load_value1],
                load_value2.map_or(vec![], |v| vec![v]),
                vec![push_value],
            ]
            .concat()
        }
        StepInfo::Store {
            store_size,
            raw_address,
            effective_address,
            value,
            pre_block_value1,
            updated_block_value1,
            pre_block_value2,
            updated_block_value2,
            ..
        } => {
            let load_value_from_stack = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(1).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *value,
            };
            *emid = (*emid).checked_add(1).unwrap();

            let load_address_from_stack = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(2).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *raw_address as u64,
            };
            *emid = (*emid).checked_add(1).unwrap();

            let load_value1 = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: *effective_address / 8,
                ltype: LocationType::Heap,
                atype: AccessType::Read,
                is_mutable: true,
                // The value will be used to lookup within imtable, hence block_value is given here
                value: *pre_block_value1,
            };
            *emid = (*emid).checked_add(1).unwrap();

            let write_value1 = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: *effective_address / 8,
                ltype: LocationType::Heap,
                atype: AccessType::Write,
                is_mutable: true,
                // The value will be used to lookup within imtable, hence block_value is given here
                value: *updated_block_value1,
            };

            if *effective_address % 8 + store_size.byte_size() > 8 {
                *emid = (*emid).checked_add(1).unwrap();
                let load_value2 = MemoryTableEntry {
                    eid,
                    emid: *emid,
                    addr: *effective_address / 8 + 1,
                    ltype: LocationType::Heap,
                    atype: AccessType::Read,
                    is_mutable: true,
                    // The value will be used to lookup within imtable, hence block_value is given here
                    value: *pre_block_value2,
                };

                *emid = (*emid).checked_add(1).unwrap();
                let write_value2 = MemoryTableEntry {
                    eid,
                    emid: *emid,
                    addr: *effective_address / 8 + 1,
                    ltype: LocationType::Heap,
                    atype: AccessType::Write,
                    is_mutable: true,
                    // The value will be used to lookup within imtable, hence block_value is given here
                    value: *updated_block_value2,
                };
                vec![
                    load_value_from_stack,
                    load_address_from_stack,
                    load_value1,
                    write_value1,
                    load_value2,
                    write_value2,
                ]
            } else {
                vec![
                    load_value_from_stack,
                    load_address_from_stack,
                    load_value1,
                    write_value1,
                ]
            }
        }
        StepInfo::MemorySize => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[],
            &[event.allocated_memory_pages as u32 as u64],
        ),
        StepInfo::MemoryGrow {
            grow_size,
            result,
            current_pages,
        } => {
            let mut mem_vec = mem_op_from_stack_only_step(
                sp_before_execution,
                eid,
                emid,
                &[*grow_size as u32 as u64],
                &[*result as u32 as u64],
            );

            let start = *current_pages as usize * 8192;

            for i in start..(start + *grow_size as usize * 8192) {
                let grow_mem = MemoryTableEntry {
                    eid,
                    emid: *emid,
                    addr: i,
                    ltype: LocationType::Heap,
                    atype: AccessType::Init,
                    is_mutable: true,
                    value: 0,
                };
                mem_vec.push(grow_mem);
                *emid = (*emid).checked_add(1).unwrap();
            }

            mem_vec
        }
        StepInfo::Const32 { value } => {
            mem_op_from_stack_only_step(sp_before_execution, eid, emid, &[], &[*value as u64])
        }
        StepInfo::ConstRef { value } => {
            mem_op_from_stack_only_step(sp_before_execution, eid, emid, &[], &[*value])
        }
        StepInfo::F32Const { value } => {
            mem_op_from_stack_only_step(sp_before_execution, eid, emid, &[], &[*value as u64])
        }
        StepInfo::F64Const { value } => {
            mem_op_from_stack_only_step(sp_before_execution, eid, emid, &[], &[*value])
        }
        StepInfo::I32BinShiftOp {
            left, right, value, ..
        }
        | StepInfo::I32BinBitOp {
            left, right, value, ..
        } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*right as u32 as u64, *left as u32 as u64],
            &[*value as u32 as u64],
        ),
        StepInfo::I32BinOp {
            left, right, value, ..
        } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*right as u32 as u64, *left as u32 as u64],
            &[*value as u32 as u64],
        ),
        StepInfo::I32Comp {
            left, right, value, ..
        } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*right as u32 as u64, *left as u32 as u64],
            &[*value as u32 as u64],
        ),

        StepInfo::I64BinOp {
            left, right, value, ..
        }
        | StepInfo::I64BinShiftOp {
            left, right, value, ..
        }
        | StepInfo::I64BinBitOp {
            left, right, value, ..
        } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*right as u64, *left as u64],
            &[*value as u64],
        ),

        StepInfo::I64Const { value } => {
            mem_op_from_stack_only_step(sp_before_execution, eid, emid, &[], &[*value as u64])
        }
        StepInfo::I64Comp {
            left, right, value, ..
        } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*right as u64, *left as u64],
            &[*value as u32 as u64],
        ),
        StepInfo::UnaryOp {
            operand, result, ..
        } => mem_op_from_stack_only_step(sp_before_execution, eid, emid, &[*operand], &[*result]),
        StepInfo::CompZ { value, result, .. } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*value],
            &[*result as u32 as u64],
        ),
        StepInfo::I32WrapI64 { value, result } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*value as u64],
            &[*result as u32 as u64],
        ),
        StepInfo::I64ExtendI32 { value, result, .. } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*value as u32 as u64],
            &[*result as u64],
        ),
        StepInfo::I32SignExtendI8 { value, result }
        | StepInfo::I32SignExtendI16 { value, result } => {
            mem_op_from_stack_only_step(sp_before_execution, eid, emid, &[*value], &[*result])
        }
        StepInfo::I64SignExtendI8 { value, result }
        | StepInfo::I64SignExtendI16 { value, result }
        | StepInfo::I64SignExtendI32 { value, result } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*value as u64],
            &[*result as u64],
        ),
        StepInfo::MemoryFill {
            offset,
            value,
            size,
            prev_val_vec,
            new_val_vec,
        } => {
            let mut mem_vec = vec![];
            let fill_size_from_stack = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(1).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *size,
            };
            mem_vec.push(fill_size_from_stack);
            *emid = (*emid).checked_add(1).unwrap();

            let fill_value_from_stack = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(2).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *value,
            };
            mem_vec.push(fill_value_from_stack);
            *emid = (*emid).checked_add(1).unwrap();

            let fill_offset_from_stack = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(3).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *offset as u64,
            };

            mem_vec.push(fill_offset_from_stack);
            *emid = (*emid).checked_add(1).unwrap();

            for (i, prev_val) in prev_val_vec.iter().enumerate() {
                let fill_read = MemoryTableEntry {
                    eid,
                    emid: *emid,
                    addr: (*offset as usize / 8 + i),
                    ltype: LocationType::Heap,
                    atype: AccessType::Read,
                    is_mutable: true,
                    value: *prev_val,
                };
                mem_vec.push(fill_read);
                *emid = (*emid).checked_add(1).unwrap();
            }

            for (i, new_val) in new_val_vec.iter().enumerate() {
                let fill_write = MemoryTableEntry {
                    eid,
                    emid: *emid,
                    addr: (*offset as usize / 8 + i),
                    ltype: LocationType::Heap,
                    atype: AccessType::Write,
                    is_mutable: true,
                    value: *new_val,
                };
                mem_vec.push(fill_write);
                *emid = (*emid).checked_add(1).unwrap();
            }
            mem_vec
        }

        StepInfo::MemoryCopy {
            num_bytes_to_copy,
            src,
            destination,
            prev_val_vec,
            new_val_vec,
        } => {
            let mut mem_vec = vec![];
            let num_bytes_to_copy_from_stack = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(1).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *num_bytes_to_copy,
            };
            mem_vec.push(num_bytes_to_copy_from_stack);
            *emid = (*emid).checked_add(1).unwrap();

            let copy_src_from_stack = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(2).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *src,
            };
            mem_vec.push(copy_src_from_stack);
            *emid = (*emid).checked_add(1).unwrap();

            let copy_dst_from_stack = MemoryTableEntry {
                eid,
                emid: *emid,
                addr: sp_before_execution.into_sub(3).get_addr(),
                ltype: LocationType::Stack,
                atype: AccessType::Read,
                is_mutable: true,
                value: *destination,
            };

            mem_vec.push(copy_dst_from_stack);
            *emid = (*emid).checked_add(1).unwrap();

            for (i, prev_val) in prev_val_vec.iter().enumerate() {
                let copy_read = MemoryTableEntry {
                    eid,
                    emid: *emid,
                    addr: (*src as usize / 8 + i),
                    ltype: LocationType::Heap,
                    atype: AccessType::Read,
                    is_mutable: true,
                    value: *prev_val,
                };
                *emid = (*emid).checked_add(1).unwrap();
                mem_vec.push(copy_read);
            }

            for (i, new_val) in new_val_vec.iter().enumerate() {
                let copy_write = MemoryTableEntry {
                    eid,
                    emid: *emid,
                    addr: (*destination as usize / 8 + i),
                    ltype: LocationType::Heap,
                    atype: AccessType::Write,
                    is_mutable: true,
                    value: *new_val,
                };
                *emid = (*emid).checked_add(1).unwrap();
                mem_vec.push(copy_write);
            }
            mem_vec
        }
        StepInfo::CallIndirect { .. } => vec![],
        StepInfo::F64ConvertI64 { value, result, .. } => {
            mem_op_from_stack_only_step(sp_before_execution, eid, emid, &[*value], &[*result])
        }
        StepInfo::F64ConvertI32 { value, result, .. } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*value as u64],
            &[*result as u64],
        ),
        StepInfo::F64BinOp {
            left, right, value, ..
        } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*right as u64, *left as u64],
            &[*value as u64],
        ),
        StepInfo::F32BinOp {
            left, right, value, ..
        } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*right as u64, *left as u64],
            &[*value as u64],
        ),
        StepInfo::F32Comp {
            left, right, value, ..
        } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*right as u32 as u64, *left as u32 as u64],
            &[*value as u32 as u64],
        ),
        StepInfo::F64Comp {
            left, right, value, ..
        } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*right as u64, *left as u64],
            &[*value as u32 as u64],
        ),
        StepInfo::F32DemoteF64 { value, result } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*value as u64],
            &[*result as u64],
        ),
        StepInfo::F64PromoteF32 { value, result } => mem_op_from_stack_only_step(
            sp_before_execution,
            eid,
            emid,
            &[*value as u64],
            &[*result as u64],
        ),
        _ => unimplemented!("eid: {}, {:?}", event.eid, event.step_info),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LocationType {
    Stack = 1,
    Heap = 2,
    Global = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq)]
pub enum AccessType {
    Read = 1,
    Write = 2,
    Init = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum MemoryReadSize {
    U8 = 1,
    S8,
    U16,
    S16,
    U32,
    S32,
    I64,
    F32,
    F64,
}

impl MemoryReadSize {
    pub fn byte_size(&self) -> usize {
        match self {
            MemoryReadSize::U8 => 1,
            MemoryReadSize::S8 => 1,
            MemoryReadSize::U16 => 2,
            MemoryReadSize::S16 => 2,
            MemoryReadSize::U32 => 4,
            MemoryReadSize::S32 => 4,
            MemoryReadSize::I64 => 8,
            MemoryReadSize::F32 => 4,
            MemoryReadSize::F64 => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum MemoryStoreSize {
    Byte8 = 1,
    Byte16,
    Byte32,
    Byte64,
}

impl MemoryStoreSize {
    pub fn byte_size(&self) -> usize {
        match self {
            MemoryStoreSize::Byte8 => 1,
            MemoryStoreSize::Byte16 => 2,
            MemoryStoreSize::Byte32 => 4,
            MemoryStoreSize::Byte64 => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
pub enum VarType {
    I64 = 0,
    I32 = 1,
    F32 = 2,
    F64 = 3,
    FuncRef = 4,
    ExternRef = 5,
}

impl From<ValueType> for VarType {
    fn from(v: ValueType) -> Self {
        match v {
            ValueType::I32 => Self::I32,
            ValueType::I64 => Self::I64,
            ValueType::F32 => Self::F32,
            ValueType::F64 => Self::F64,
            ValueType::FuncRef => Self::FuncRef,
            ValueType::ExternRef => Self::ExternRef,
        }
    }
}
