//! Utility functions for memory checking argument
//!
//! Prepare MTable for MCC
use std::collections::HashMap;

use ff::PrimeField;
use nova::gadgets::lookup::{Lookup, TableType};
use wasmi::mtable::{LocationType, MTable, MemoryTableEntry};

/// Turn raw WASMI memory addresses into string addresses
#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub(crate) struct StrAddr(String);

impl StrAddr {
  /// # Arguments:
  ///   * `u_addr` - usize: WASMI Memory address
  ///   * `ltype` - LocationType: WASMI Location type (Global, Stack, Heap) of the memory address
  ///
  /// # Returns:
  ///  * Self: StrAddr
  fn new(u_addr: usize, ltype: LocationType) -> Self {
    // Create a unique string address for each memory address
    let mut addr = String::new();
    match ltype {
      LocationType::Global => addr.push('G'),
      LocationType::Stack => addr.push('S'),
      LocationType::Heap => addr.push('H'),
    }
    addr.push_str(&u_addr.to_string());
    StrAddr(addr)
  }
}

/// Modify memory trace to have all memory addresses in linear order.
/// This allows for easy lookup in the R1CS lookup table.
///
/// # Arguments:
///  * `m_entry` - &mut MemoryTableEntry: Memory table entry
///  * `map` - &mut HashMap<StrAddr, u64>: HashMap of string addresses to linear addresses
pub(crate) fn set_linear_addr(m_entry: &mut MemoryTableEntry, map: &mut HashMap<StrAddr, u64>) {
  // Map memory address to linear address

  // Create a unique string address for each memory address
  let addr = StrAddr::new(m_entry.addr, m_entry.ltype);

  // If the address is already in the map, set the entries address to the new linear value in the
  // map
  if map.contains_key(&addr) {
    m_entry.addr = *map.get(&addr).unwrap() as usize;
  } else {
    // Else new address is the length of the map
    let new_addr = map.len() as u64;

    // Map the new address to the string address
    map.insert(addr, new_addr);

    // Set the memory entry address to the new linear address
    m_entry.addr = new_addr as usize;
  }
}

/// Create R1CS lookup table from memory table
pub fn create_lookup_table<F>(mut mtable: MTable) -> (Lookup<F>, Vec<MemoryTableEntry>, usize)
where
  F: PrimeField + Ord,
{
  let entries = mtable.entries_mut();
  let mut memory_trace = vec![];
  let mut addr_map = HashMap::new();

  let initial_table = {
    let mut ram = vec![];
    for entry in entries.iter_mut() {
      let addr_map_len = addr_map.len();
      set_linear_addr(entry, &mut addr_map);

      // Add new address to lookup table
      if addr_map.len() > addr_map_len {
        ram.push((F::from(addr_map_len as u64), F::from(0)));
      }

      memory_trace.push(entry.clone());
    }
    // Push dummy addr for IVC batching
    ram.push((F::from(ram.len() as u64), F::from(0)));
    ram
  };

  let last_addr = initial_table.len() - 1;

  let initial_lookup_table =
    Lookup::new(memory_trace.len() * 4, TableType::ReadWrite, initial_table);

  (initial_lookup_table, memory_trace, last_addr)
}
