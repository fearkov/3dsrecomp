//! the executable image of a title, split into its segments at the addresses
//! the title expects to run at.

use zakuro_fs::{FsError, Title};

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
}
