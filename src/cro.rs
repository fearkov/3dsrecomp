//! reading CRO modules and the CRS that describes the main executable,
//! straight from their files.

use std::collections::BTreeSet;

use crate::discover::{Program, Source};
use crate::image;

pub struct Segment {
    pub offset: u32,
    pub size: u32,
    pub kind: u32,
}

pub struct Module {
    pub name: String,
    pub segments: Vec<Segment>,
    /// exported symbols by name, as segment tags.
    pub exports: Vec<(String, u32)>,
    /// exported symbols by index, as segment tags.
    pub indexed_exports: Vec<u32>,
    /// the addresses the module writes into itself when it is loaded.
    pub relocations: Vec<Relocation>,
    /// the places that get the addresses of what it imports, whose segment
    /// field means nothing.
    pub imports: Vec<Relocation>,
}

pub struct Relocation {
    /// where the address goes, as a segment tag.
    pub target: u32,
    pub kind: u8,
    /// the segment the address points into.
    pub segment: u32,
    pub addend: u32,
}

impl Relocation {
    /// whether the relocation stores the address itself rather than an
    /// offset or a branch.
    fn is_absolute(&self) -> bool {
        matches!(self.kind, 2 | 38)
    }
}

fn field(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

fn cstring(bytes: &[u8], offset: usize) -> String {
    let tail = bytes.get(offset..).unwrap_or_default();
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    String::from_utf8_lossy(&tail[..end]).into_owned()
}

/// a table of fixed size entries, from the header fields holding its offset
/// and its count.
fn table(bytes: &[u8], offset_field: usize, count_field: usize, entry_size: usize) -> Option<Vec<&[u8]>> {
    let offset = field(bytes, offset_field)? as usize;
    let count = field(bytes, count_field)? as usize;
    (0..count)
        .map(|i| bytes.get(offset + i * entry_size..offset + (i + 1) * entry_size))
        .collect()
}

pub fn parse(bytes: &[u8]) -> Option<Module> {
    if bytes.get(0x80..0x84)? != b"CRO0" {
        return None;
    }
    let word = |entry: &[u8], at: usize| u32::from_le_bytes(entry[at..at + 4].try_into().unwrap());
    let segments = table(bytes, 0xC8, 0xCC, 12)?
        .into_iter()
        .map(|entry| Segment { offset: word(entry, 0), size: word(entry, 4), kind: word(entry, 8) })
        .collect();
    let exports = table(bytes, 0xD0, 0xD4, 8)?
        .into_iter()
        .map(|entry| (cstring(bytes, word(entry, 0) as usize), word(entry, 4)))
        .collect();
    let indexed_exports = table(bytes, 0xD8, 0xDC, 4)?.into_iter().map(|entry| word(entry, 0)).collect();
    let relocation = |entry: &[u8]| Relocation {
        target: word(entry, 0),
        kind: entry[4],
        segment: entry[5] as u32,
        addend: word(entry, 8),
    };
    let relocations = table(bytes, 0x128, 0x12C, 12)?.into_iter().map(relocation).collect();
    let imports = table(bytes, 0xF8, 0xFC, 12)?.into_iter().map(relocation).collect();
    Some(Module {
        name: cstring(bytes, field(bytes, 0xC0)? as usize),
        segments,
        exports,
        indexed_exports,
        relocations,
        imports,
    })
}

/// the segment types holding code and holding zeros.
const CODE: u32 = 0;
const BSS: u32 = 3;

impl Module {
    /// the addresses of the exported symbols that sit in code.
    pub fn code_exports(&self) -> Vec<u32> {
        let named = self.exports.iter().map(|(_, tag)| *tag);
        named
            .chain(self.indexed_exports.iter().copied())
            .filter(|tag| self.segments.get((tag & 0xF) as usize).is_some_and(|s| s.kind == CODE))
            .filter_map(|tag| self.resolve(tag))
            .collect()
    }

    /// the address a segment tag points at, given where each segment lives.
    pub fn resolve(&self, tag: u32) -> Option<u32> {
        let segment = self.segments.get((tag & 0xF) as usize)?;
        let offset = tag >> 4;
        (offset < segment.size).then(|| segment.offset + offset)
    }

    /// the module as it looks loaded at base, its bss after the file and
    /// its relocations applied, for running it without a loader. everything
    /// it imports points at stub.
    pub fn image(&self, bytes: &[u8], base: u32, stub: u32) -> Vec<u8> {
        let bss = (bytes.len() as u32).next_multiple_of(0x1000);
        let bss_size: u32 = self.segments.iter().filter(|s| s.kind == BSS).map(|s| s.size).sum();
        let mut image = bytes.to_vec();
        image.resize((bss + bss_size) as usize, 0);
        let offset = |segment: &Segment| if segment.kind == BSS { bss } else { segment.offset };
        for relocation in self.relocations.iter().filter(|r| r.is_absolute()) {
            let Some(target) = self.segments.get((relocation.target & 0xF) as usize) else { continue };
            let Some(symbol) = self.segments.get(relocation.segment as usize) else { continue };
            let at = (offset(target) + (relocation.target >> 4)) as usize;
            let value = base + offset(symbol) + relocation.addend;
            if let Some(slot) = image.get_mut(at..at + 4) {
                slot.copy_from_slice(&value.to_le_bytes());
            }
        }
        for import in self.imports.iter().filter(|r| r.is_absolute()) {
            let Some(target) = self.segments.get((import.target & 0xF) as usize) else { continue };
            let at = (offset(target) + (import.target >> 4)) as usize;
            if let Some(slot) = image.get_mut(at..at + 4) {
                slot.copy_from_slice(&stub.wrapping_add(import.addend).to_le_bytes());
            }
        }
        image
    }

    fn is_code(&self, segment: u32) -> bool {
        self.segments.get(segment as usize).is_some_and(|s| s.kind == CODE)
    }

    /// the module's code as discovery sees it, at its offsets in the file
    /// with the code addresses its relocations store filled in. bytes is the
    /// whole file, where the stored addresses are still zero.
    pub fn program(&self, bytes: &[u8]) -> Option<Program> {
        let segment = self.segments.iter().find(|s| s.kind == CODE && s.size > 0)?;
        let range = segment.offset as usize..(segment.offset + segment.size) as usize;
        let mut text = image::Segment { base: segment.offset, bytes: bytes.get(range)?.to_vec() };

        let mut seeds: Vec<_> = self.code_exports().into_iter().map(|address| (address, Source::Export)).collect();
        let mut slots = BTreeSet::new();
        for relocation in self.relocations.iter().filter(|r| self.is_code(r.segment)) {
            let address = self.segments[relocation.segment as usize].offset + relocation.addend;
            seeds.push((address, Source::Relocation));
            let target = self.resolve(relocation.target).filter(|&t| text.contains(t) && t + 4 <= text.end());
            if let Some(target) = target.filter(|_| relocation.is_absolute()) {
                text.write32(target, address);
                slots.insert(target);
            }
        }
        Some(Program { text, seeds, slots: Some(slots) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover;

    /// a module with a header, a code segment at 0x200 and a data segment
    /// at 0x300, holding the code words and one relocation per pointer, each
    /// as (segment tag of the slot, offset in code).
    fn module(code: &[u32], pointers: &[(u32, u32)]) -> Vec<u8> {
        let mut bytes = vec![0; 0x400];
        let mut put = |at: usize, value: u32| bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        put(0x80, u32::from_le_bytes(*b"CRO0"));
        put(0xC8, 0x138);
        put(0xCC, 2);
        put(0x138, 0x200);
        put(0x13C, code.len() as u32 * 4);
        put(0x140, 0);
        put(0x144, 0x300);
        put(0x148, 0x100);
        put(0x14C, 2);
        put(0x128, 0x150);
        put(0x12C, pointers.len() as u32);
        for (i, &(slot, offset)) in pointers.iter().enumerate() {
            let entry = 0x150 + i * 12;
            put(entry, slot);
            put(entry + 4, 2);
            put(entry + 8, offset);
        }
        for (i, &word) in code.iter().enumerate() {
            put(0x200 + i * 4, word);
        }
        bytes
    }

    #[test]
    fn relocations_fill_in_code_pointers() {
        let bytes = module(
            &[
                0xE59F_0000, // ldr r0, [pc] (literal at 0x208)
                0xE12F_FF1E, // bx lr
                0,           // the literal, relocated to 0x210
                0xE12F_FF1E, // bx lr, only reached through the data
                0xE12F_FF1E, // bx lr, only reached through the literal
            ],
            // the literal (segment 0, offset 8) and a data word (segment 1)
            &[(8 << 4, 0x10), (1, 0xC)],
        );
        let program = parse(&bytes).unwrap().program(&bytes).unwrap();
        assert_eq!(program.text.read32(0x208), Some(0x210));
        assert_eq!(program.slots, Some(BTreeSet::from([0x208])));
        let analysis = discover::analyze(&program);
        assert!(analysis.functions.contains_key(&0x20C));
        assert!(analysis.functions.contains_key(&0x210));
    }
}
