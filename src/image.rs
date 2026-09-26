//! the executable image of a title, split into its segments at the addresses
//! the title expects to run at.

use zakuro_fs::{FsError, Title};

use crate::discover::{Program, Source};

const PAGE_SIZE: usize = 0x1000;

pub struct Segment {
    pub base: u32,
    pub bytes: Vec<u8>,
}

impl Segment {
    pub fn end(&self) -> u32 {
        self.base + self.bytes.len() as u32
    }

    pub fn contains(&self, address: u32) -> bool {
        address >= self.base && address < self.end()
    }

    pub fn read32(&self, address: u32) -> Option<u32> {
        let offset = address.checked_sub(self.base)? as usize;
        let bytes = self.bytes.get(offset..offset + 4)?;
        Some(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn write32(&mut self, address: u32, value: u32) {
        let offset = (address - self.base) as usize;
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    pub fn read16(&self, address: u32) -> Option<u16> {
        let offset = address.checked_sub(self.base)? as usize;
        let bytes = self.bytes.get(offset..offset + 2)?;
        Some(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// every aligned word in the segment, with its address.
    pub fn words(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.bytes
            .as_chunks::<4>()
            .0
            .iter()
            .enumerate()
            .map(|(i, word)| (self.base + i as u32 * 4, u32::from_le_bytes(*word)))
    }
}

pub struct Image {
    pub entry: u32,
    pub text: Segment,
    pub rodata: Segment,
    pub data: Segment,
}

impl Image {
    /// the segments sit one after another in the decompressed code, each
    /// padded to whole pages, the same way the loader maps them.
    pub fn from_title(title: &Title) -> Result<Image, FsError> {
        let code = title.code()?;
        let header = &title.exheader;
        let segment = |info: zakuro_fs::CodeSetInfo, offset: usize| Segment {
            base: info.address,
            bytes: code
                .get(offset..offset + info.size as usize)
                .unwrap_or_default()
                .to_vec(),
        };
        let rodata_offset = header.text.num_pages as usize * PAGE_SIZE;
        let data_offset = rodata_offset + header.rodata.num_pages as usize * PAGE_SIZE;
        Ok(Image {
            entry: header.text.address,
            text: segment(header.text, 0),
            rodata: segment(header.rodata, rodata_offset),
            data: segment(header.data, data_offset),
        })
    }

    /// the executable as discovery sees it, starting from the entry point,
    /// the exports and what modules take from it without a name. nothing
    /// says where it keeps pointers, so any word in the data segments that
    /// lands in the code is taken for one.
    pub fn into_program(self, exports: &[u32], imported: &[u32]) -> Program {
        let entry = std::iter::once((self.entry, Source::Entry));
        let exports = exports.iter().map(|&address| (address, Source::Export));
        let imported = imported.iter().map(|&address| (address, Source::Import));
        let pointers = [&self.rodata, &self.data]
            .into_iter()
            .flat_map(Segment::words)
            .filter(|&(_, value)| self.text.contains(value & !1))
            .map(|(_, value)| (value, Source::Pointer));
        let seeds = entry.chain(exports).chain(imported).chain(pointers).collect();
        Program { text: self.text, seeds, slots: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::{self, Mode};

    const BASE: u32 = 0x0010_0000;

    fn segment(base: u32, words: &[u32]) -> Segment {
        Segment { base, bytes: words.iter().flat_map(|w| w.to_le_bytes()).collect() }
    }

    #[test]
    fn pointers_in_data_become_functions() {
        let image = Image {
            entry: BASE,
            text: segment(BASE, &[0xE12F_FF1E, 0x4770_4770, 0xE12F_FF1E]),
            rodata: segment(0x0020_0000, &[BASE + 8, 12345]),
            data: segment(0x0030_0000, &[BASE + 5]),
        };
        let program = image.into_program(&[], &[]);
        assert_eq!(program.seeds.len(), 3);
        let analysis = discover::analyze(&program);
        assert_eq!(analysis.functions[&(BASE + 8)].source, Source::Pointer);
        assert_eq!(analysis.functions[&(BASE + 4)].mode, Mode::Thumb);
    }
}
