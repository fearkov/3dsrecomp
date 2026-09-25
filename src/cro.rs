//! reading CRO modules and the CRS that describes the main executable,
//! straight from their files.

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
    Some(Module {
        name: cstring(bytes, field(bytes, 0xC0)? as usize),
        segments,
        exports,
        indexed_exports,
    })
}

/// the segment type holding code.
const CODE: u32 = 0;

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
}
