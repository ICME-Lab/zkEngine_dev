use super::LocationType;

#[derive(Clone, Debug)]
pub struct IMTableEntry {
    pub ltype: LocationType,
    pub addr: usize,
    pub value: u64,
}

/// Initial Memory Table
#[derive(Debug, Default)]
pub struct IMTable(Vec<IMTableEntry>);

impl IMTable {
    pub fn push(&mut self, addr: usize, value: u64, ltype: LocationType) {
        self.0.push(IMTableEntry { addr, value, ltype })
    }

    pub fn entries(&self) -> &[IMTableEntry] {
        &self.0
    }
}
