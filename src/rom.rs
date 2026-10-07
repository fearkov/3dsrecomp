//! reading a decrypted game dump, a .3ds cartridge image, a .cia or a bare .cxi,
//! for what recompiling needs, the code and its layout from the executable
//! partition, and the modules and their descriptions from its RomFS. only
//! what is read is loaded, dumps run to gigabytes.

use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

/// offsets and sizes in NCSD and NCCH headers count these.
const MEDIA_UNIT: u64 = 0x200;
const NCCH_HEADER_SIZE: u64 = 0x200;
const EXEFS_HEADER_SIZE: u64 = 0x200;
/// the RomFS tables' mark for no entry.
const NONE: u32 = 0xFFFF_FFFF;

#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error(error.to_string())
    }
}

fn error<T>(message: impl Into<String>) -> Result<T, Error> {
    Err(Error(message.into()))
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn ascii(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// where one segment of the code is mapped, from the exheader.
#[derive(Debug, Clone, Copy)]
pub struct CodeSetInfo {
    pub address: u32,
    /// the pages it is mapped in.
    pub num_pages: u32,
    /// the bytes it really has.
    pub size: u32,
}

impl CodeSetInfo {
    fn read(bytes: &[u8], offset: usize) -> CodeSetInfo {
        CodeSetInfo {
            address: u32_at(bytes, offset),
            num_pages: u32_at(bytes, offset + 4),
            size: u32_at(bytes, offset + 8),
        }
    }
}

/// the parts of the extended header recompiling cares about.
#[derive(Debug, Clone)]
pub struct ExHeader {
    pub title: String,
    /// the ExeFS .code is compressed.
    pub compress_code: bool,
    pub text: CodeSetInfo,
    pub rodata: CodeSetInfo,
    pub data: CodeSetInfo,
    #[cfg_attr(not(feature = "verify"), allow(dead_code))]
    pub bss_size: u32,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    first_child: u32,
    first_file: u32,
    next_sibling: u32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    next_sibling: u32,
    /// where its bytes start in the file data.
    data_offset: u64,
    pub data_size: u64,
    pub name: String,
}

/// the directory tree of a RomFS, the tables read in, the files left in
/// the dump.
pub struct RomFs {
    /// where the file data starts in the dump.
    data: u64,
    dirs: Vec<u8>,
    files: Vec<u8>,
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    String::from_utf16_lossy(&units)
}

impl RomFs {
    fn dir(&self, offset: u32) -> Option<DirEntry> {
        let at = offset as usize;
        let entry = self.dirs.get(at..at + 0x18)?;
        let length = u32_at(entry, 0x14) as usize;
        Some(DirEntry {
            next_sibling: u32_at(entry, 0x04),
            first_child: u32_at(entry, 0x08),
            first_file: u32_at(entry, 0x0C),
            name: utf16(self.dirs.get(at + 0x18..at + 0x18 + length)?),
        })
    }

    fn file(&self, offset: u32) -> Option<FileEntry> {
        let at = offset as usize;
        let entry = self.files.get(at..at + 0x20)?;
        let length = u32_at(entry, 0x1C) as usize;
        Some(FileEntry {
            next_sibling: u32_at(entry, 0x04),
            data_offset: u64_at(entry, 0x08),
            data_size: u64_at(entry, 0x10),
            name: utf16(self.files.get(at + 0x20..at + 0x20 + length)?),
        })
    }

    pub fn root(&self) -> Result<DirEntry, Error> {
        self.dir(0).ok_or(Error("the RomFS has no root".into()))
    }

    /// the folders in dir, with where each is in the table.
    pub fn subdirs(&self, dir: &DirEntry) -> Vec<(u32, DirEntry)> {
        let mut out = Vec::new();
        let mut cursor = dir.first_child;
        while cursor != NONE {
            let Some(entry) = self.dir(cursor) else { break };
            let next = entry.next_sibling;
            out.push((cursor, entry));
            cursor = next;
        }
        out
    }

    /// the files in dir, with where each is in the table.
    pub fn files(&self, dir: &DirEntry) -> Vec<(u32, FileEntry)> {
        let mut out = Vec::new();
        let mut cursor = dir.first_file;
        while cursor != NONE {
            let Some(entry) = self.file(cursor) else { break };
            let next = entry.next_sibling;
            out.push((cursor, entry));
            cursor = next;
        }
        out
    }

    /// a file by its path, / separated, the case ignored.
    pub fn lookup(&self, path: &str) -> Result<FileEntry, Error> {
        let missing = || Error(format!("{path} is not in the RomFS"));
        let mut dir = self.root()?;
        // the contents hang off a nameless folder under the root, which no
        // path spells out
        if let Some((_, nameless)) = self.subdirs(&dir).into_iter().find(|(_, d)| d.name.is_empty()) {
            dir = nameless;
        }
        let mut parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        let name = parts.pop().ok_or_else(missing)?;
        for part in parts {
            dir = self
                .subdirs(&dir)
                .into_iter()
                .find(|(_, d)| d.name.eq_ignore_ascii_case(part))
                .map(|(_, d)| d)
                .ok_or_else(missing)?;
        }
        self.files(&dir)
            .into_iter()
            .find(|(_, f)| f.name.eq_ignore_ascii_case(name))
            .map(|(_, f)| f)
            .ok_or_else(missing)
    }
}

/// a .cia's header size, which is also its first field.
const CIA_HEADER_SIZE: u32 = 0x2020;

/// where the executable content of a .cia starts. the header, certificates,
/// ticket, TMD and contents each start on 64 bytes, and the contents follow
/// in the order of the TMD's records, those the header's bitmap has.
fn cia_executable(header: &[u8], mut read: impl FnMut(u64, usize) -> Result<Vec<u8>, Error>) -> Result<u64, Error> {
    let align = |n: u64| n.next_multiple_of(0x40);
    let bitmap = read(0x20, 0x2000)?;
    let tmd_offset = align(align(align(CIA_HEADER_SIZE as u64) + u32_at(header, 0x08) as u64) + u32_at(header, 0x0C) as u64);
    let contents = align(tmd_offset + u32_at(header, 0x10) as u64);
    let tmd = read(tmd_offset, u32_at(header, 0x10) as usize)?;
    let be16 = |at: usize| u16::from_be_bytes([tmd[at], tmd[at + 1]]);
    let be64 = |at: usize| u64::from_be_bytes(tmd[at..at + 8].try_into().unwrap());
    // the signature's size goes by its type, padded to 64 bytes
    let signature = match u32::from_be_bytes(tmd[..4].try_into().unwrap()) & 0xFFFF {
        0x0000 | 0x0003 => 0x240,
        0x0001 | 0x0004 => 0x140,
        0x0002 | 0x0005 => 0x80,
        _ => return error("the .cia's TMD has an unknown signature"),
    };
    match be64(signature + 0x4C) >> 32 {
        0x0004_000E => return error("this .cia is an update, not a game"),
        0x0004_008C => return error("this .cia is downloadable content, not a game"),
        _ => {}
    }
    let mut offset = contents;
    for i in 0..be16(signature + 0x9E) as usize {
        let record = signature + 0xC4 + 64 * 0x24 + i * 0x30;
        let index = be16(record + 4) as usize;
        if bitmap[index / 8] & (0x80 >> (index % 8)) == 0 {
            continue;
        }
        if index == 0 {
            if be16(record + 6) & 1 != 0 {
                return error("the .cia is encrypted, it has to be decrypted first");
            }
            return Ok(offset);
        }
        offset = align(offset + be64(record + 8));
    }
    error("the .cia has no executable")
}

/// a game's executable partition.
pub struct Title {
    file: Mutex<File>,
    program_id: u64,
    pub exheader: ExHeader,
    /// where .code is in the dump, and how big.
    code: (u64, u64),
    pub romfs: Option<RomFs>,
}

impl Title {
    pub fn load(path: impl AsRef<Path>) -> Result<Title, Error> {
        let mut file = File::open(path)?;
        let read = |file: &mut File, offset: u64, len: usize| -> Result<Vec<u8>, Error> {
            let mut bytes = vec![0; len];
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut bytes)?;
            Ok(bytes)
        };

        // a cartridge image holds the executable as its first partition, a
        // .cia as its first content, and a .cxi is that partition by itself
        let start = read(&mut file, 0, 0x200)?;
        let ncch = match &start[0x100..0x104] {
            b"NCSD" => u32_at(&start, 0x120) as u64 * MEDIA_UNIT,
            b"NCCH" => 0,
            _ if u32_at(&start, 0) == CIA_HEADER_SIZE => cia_executable(&start, |offset, len| read(&mut file, offset, len))?,
            _ => return error("not a 3DS cartridge image, .cia or executable"),
        };
        let header = read(&mut file, ncch, NCCH_HEADER_SIZE as usize)?;
        if &header[0x100..0x104] != b"NCCH" {
            return error("the executable partition has no NCCH header");
        }
        let flags = &header[0x188..0x190];
        // the partition is readable as it is when it says so, or when it was
        // never encrypted
        if flags[7] & 0x04 == 0 && flags[3] != 0 {
            return error("the dump is encrypted, it has to be decrypted first");
        }
        let program_id = u64_at(&header, 0x118);
        let exefs = ncch + u32_at(&header, 0x1A0) as u64 * MEDIA_UNIT;
        let romfs_offset = ncch + u32_at(&header, 0x1B0) as u64 * MEDIA_UNIT;
        let has_romfs = u32_at(&header, 0x1B4) != 0 && flags[7] & 0x02 == 0;

        let ex = read(&mut file, ncch + NCCH_HEADER_SIZE, 0x400)?;
        let exheader = ExHeader {
            title: ascii(&ex[..8]),
            compress_code: ex[0x0D] & 1 != 0,
            text: CodeSetInfo::read(&ex, 0x10),
            rodata: CodeSetInfo::read(&ex, 0x20),
            data: CodeSetInfo::read(&ex, 0x30),
            bss_size: u32_at(&ex, 0x3C),
        };

        // ten files, a name, an offset past the header and a size each
        let table = read(&mut file, exefs, EXEFS_HEADER_SIZE as usize)?;
        let code = table
            .as_chunks::<16>()
            .0
            .iter()
            .take(10)
            .find(|entry| ascii(&entry[..8]) == ".code")
            .map(|entry| (exefs + EXEFS_HEADER_SIZE + u32_at(entry, 8) as u64, u32_at(entry, 12) as u64))
            .ok_or(Error("the ExeFS has no .code".into()))?;

        let romfs = if has_romfs { read_romfs(&mut file, romfs_offset, read).ok() } else { None };
        Ok(Title { file: Mutex::new(file), program_id, exheader, code, romfs })
    }

    pub fn program_id(&self) -> u64 {
        self.program_id
    }

    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, Error> {
        let mut file = self.file.lock().map_err(|_| Error("the dump was left half read".into()))?;
        let mut bytes = vec![0; len];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    /// the code, the three segments one after another, decompressed.
    pub fn code(&self) -> Result<Vec<u8>, Error> {
        let raw = self.read(self.code.0, self.code.1 as usize)?;
        if self.exheader.compress_code {
            decompress(&raw)
        } else {
            Ok(raw)
        }
    }

    /// up to len bytes of a RomFS file from offset.
    pub fn read_romfs(&self, file: &FileEntry, offset: u64, len: usize) -> Option<Vec<u8>> {
        let romfs = self.romfs.as_ref()?;
        let len = len.min(file.data_size.saturating_sub(offset) as usize);
        self.read(romfs.data + file.data_offset + offset, len).ok()
    }
}

/// the level 3 tables of the RomFS whose IVFC header is at offset.
fn read_romfs(
    file: &mut File,
    offset: u64,
    read: impl Fn(&mut File, u64, usize) -> Result<Vec<u8>, Error>,
) -> Result<RomFs, Error> {
    let ivfc = read(file, offset, 0x60)?;
    if &ivfc[..4] != b"IVFC" {
        return error("the RomFS has no IVFC header");
    }
    // level 3 starts after the header and the master hash, on a block of
    // its own size
    let master_hash = u32_at(&ivfc, 0x08) as u64;
    let block = 1u64 << u32_at(&ivfc, 0x0C + 2 * 0x18 + 0x10).min(31);
    let level3 = offset + (0x60 + master_hash).next_multiple_of(block);
    let header = read(file, level3, 0x28)?;
    if u32_at(&header, 0) != 0x28 {
        return error("the RomFS level 3 header is not 0x28 bytes");
    }
    let table = |file: &mut File, at: usize| -> Result<Vec<u8>, Error> {
        read(file, level3 + u32_at(&header, at) as u64, u32_at(&header, at + 4) as usize)
    };
    Ok(RomFs {
        dirs: table(file, 0x0C)?,
        files: table(file, 0x1C)?,
        data: level3 + u32_at(&header, 0x24) as u64,
    })
}

/// undoes the backwards LZSS the SDK compresses .code with, which works from
/// the end of the buffer towards its start.
pub fn decompress(compressed: &[u8]) -> Result<Vec<u8>, Error> {
    let size = compressed.len();
    if size < 8 {
        return error("compressed code shorter than its footer");
    }
    let out_size = size + u32_at(compressed, size - 4) as usize;
    let footer = u32_at(compressed, size - 8);
    // the high byte counts the footer and padding, the rest how far back the
    // compressed part starts
    let footer_size = (footer >> 24) as usize;
    let span = (footer & 0x00FF_FFFF) as usize;
    if footer_size > size || span > size {
        return error("the compressed code's footer points outside it");
    }

    let mut out = vec![0u8; out_size];
    out[..size].copy_from_slice(compressed);
    let mut index = size - footer_size;
    let stop = size - span;
    let mut cursor = out_size;
    while index > stop {
        index -= 1;
        let mut control = compressed[index];
        for _ in 0..8 {
            if index <= stop || index == 0 || cursor == 0 {
                break;
            }
            if control & 0x80 != 0 {
                if index < 2 {
                    return error("a back reference is cut short");
                }
                index -= 2;
                let pair = u16_at(compressed, index) as usize;
                // runs are never shorter than three, nor closer than two
                let (length, distance) = ((pair >> 12) + 3, (pair & 0xFFF) + 2);
                if cursor < length {
                    return error("a run goes past the start");
                }
                for _ in 0..length {
                    let from = cursor + distance;
                    let byte = *out.get(from).ok_or(Error("a run reads past the end".into()))?;
                    cursor -= 1;
                    out[cursor] = byte;
                }
            } else {
                index -= 1;
                cursor -= 1;
                out[cursor] = compressed[index];
            }
            control <<= 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// the id of the titles tests make, which no real title has.
    const PROGRAM_ID: u64 = 0x0004_0000_0FF3_DE00;

    fn put(out: &mut [u8], at: usize, bytes: &[u8]) {
        out[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// writes a decrypted .cxi to a file named after test and returns its
    /// path. code is all text, at 0x00100000, and a RomFS holds files at
    /// their paths when there are any.
    pub(crate) fn rom(test: &str, code: &[u8], files: &[(&str, &[u8])]) -> std::path::PathBuf {
        // the NCCH header, never encrypted, the exheader after it, and the
        // ExeFS at 0x600 with .code its only file
        let mut out = vec![0; 0x800];
        put(&mut out, 0x100, b"NCCH");
        put(&mut out, 0x118, &PROGRAM_ID.to_le_bytes());
        out[0x18F] = 0x04;
        put(&mut out, 0x1A0, &3u32.to_le_bytes());
        put(&mut out, 0x200, b"test");
        let text = [0x0010_0000, code.len().div_ceil(0x1000) as u32, code.len() as u32];
        put(&mut out, 0x210, &text.map(u32::to_le_bytes).concat());
        put(&mut out, 0x600, b".code");
        put(&mut out, 0x60C, &(code.len() as u32).to_le_bytes());
        out.extend_from_slice(code);
        if !files.is_empty() {
            let (at, romfs) = (out.len().next_multiple_of(MEDIA_UNIT as usize), romfs(files));
            put(&mut out, 0x1B0, &((at as u64 / MEDIA_UNIT) as u32).to_le_bytes());
            put(&mut out, 0x1B4, &((romfs.len() as u64).div_ceil(MEDIA_UNIT) as u32).to_le_bytes());
            out.resize(at, 0);
            out.extend(romfs);
        }
        let path = std::env::temp_dir().join(format!("3dsrecomp-{test}-{}.cxi", std::process::id()));
        std::fs::write(&path, out).unwrap();
        path
    }

    /// a RomFS without hashes, its IVFC header and then level 3, holding
    /// files at their paths in the folders those need.
    fn romfs(files: &[(&str, &[u8])]) -> Vec<u8> {
        // every folder's path and its parent, the root first, and every
        // file's folder, name and bytes
        let mut dirs: Vec<(String, usize)> = vec![(String::new(), 0)];
        let mut leaves = Vec::new();
        for &(path, bytes) in files {
            let (folder, name) = path.rsplit_once('/').unwrap_or(("", path));
            let (mut parent, mut at) = (0, String::new());
            for part in folder.split('/').filter(|part| !part.is_empty()) {
                at = if at.is_empty() { part.to_owned() } else { format!("{at}/{part}") };
                parent = match dirs.iter().position(|(known, _)| *known == at) {
                    Some(index) => index,
                    None => {
                        dirs.push((at.clone(), parent));
                        dirs.len() - 1
                    }
                };
            }
            leaves.push((parent, name, bytes));
        }
        let utf16 = |name: &str| -> Vec<u8> { name.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let dir_names: Vec<Vec<u8>> = dirs.iter().map(|(path, _)| utf16(path.rsplit('/').next().unwrap_or(""))).collect();
        let file_names: Vec<Vec<u8>> = leaves.iter().map(|(_, name, _)| utf16(name)).collect();
        // where each entry starts in its table
        let offsets = |names: &[Vec<u8>], header: usize| -> Vec<u32> {
            let mut end = 0;
            names
                .iter()
                .map(|name| {
                    let at = end;
                    end += header + name.len().next_multiple_of(4);
                    at as u32
                })
                .collect()
        };
        let (dir_at, file_at) = (offsets(&dir_names, 0x18), offsets(&file_names, 0x20));
        let first = |found: Option<usize>, at: &[u32]| found.map_or(NONE, |index| at[index]);

        let mut dir_table = Vec::new();
        for (index, &(_, parent)) in dirs.iter().enumerate() {
            let next = if index == 0 { None } else { (index + 1..dirs.len()).find(|&other| dirs[other].1 == parent) };
            let child = (1..dirs.len()).find(|&other| dirs[other].1 == index);
            let file = (0..leaves.len()).find(|&other| leaves[other].0 == index);
            let name = &dir_names[index];
            let words = [dir_at[parent], first(next, &dir_at), first(child, &dir_at), first(file, &file_at), NONE, name.len() as u32];
            dir_table.extend(words.iter().flat_map(|word| word.to_le_bytes()));
            dir_table.extend_from_slice(name);
            dir_table.resize(dir_table.len().next_multiple_of(4), 0);
        }
        let (mut file_table, mut data) = (Vec::new(), Vec::new());
        for (index, &(parent, _, bytes)) in leaves.iter().enumerate() {
            data.resize(data.len().next_multiple_of(16), 0);
            let next = (index + 1..leaves.len()).find(|&other| leaves[other].0 == parent);
            let name = &file_names[index];
            file_table.extend([dir_at[parent], first(next, &file_at)].iter().flat_map(|word| word.to_le_bytes()));
            file_table.extend([data.len() as u64, bytes.len() as u64].iter().flat_map(|word| word.to_le_bytes()));
            file_table.extend([NONE, name.len() as u32].iter().flat_map(|word| word.to_le_bytes()));
            file_table.extend_from_slice(name);
            file_table.resize(file_table.len().next_multiple_of(4), 0);
            data.extend_from_slice(bytes);
        }

        // the IVFC header, no master hash and level 3 in blocks of 16 bytes
        // right after it, then level 3, its header, the tables without the
        // hash tables, and the file data
        let mut out = vec![0; 0x60];
        put(&mut out, 0, b"IVFC");
        out[0x4C] = 4;
        let (dirs_at, files_at) = (0x28, 0x28 + dir_table.len());
        let data_at = (files_at + file_table.len()).next_multiple_of(16);
        let header = [0x28, dirs_at, 0, dirs_at, dir_table.len(), files_at, 0, files_at, file_table.len(), data_at];
        out.extend(header.iter().flat_map(|&word| (word as u32).to_le_bytes()));
        out.extend(dir_table);
        out.extend(file_table);
        out.resize(0x60 + data_at, 0);
        out.extend(data);
        out
    }

    /// the fixture reads back as the title it describes.
    #[test]
    fn a_title_made_for_tests_reads_back() {
        let path = rom("fixture", &[1, 2, 3, 4], &[("static.crs", b"crs"), ("cro/Battle.cro", b"battle"), ("cro/Field.cro", b"field")]);
        let title = Title::load(&path).unwrap();
        assert_eq!(title.program_id(), PROGRAM_ID);
        assert_eq!(title.code().unwrap(), [1, 2, 3, 4]);
        assert_eq!(title.exheader.text.address, 0x0010_0000);
        let romfs = title.romfs.as_ref().unwrap();
        let read = |path: &str| {
            let file = romfs.lookup(path).unwrap();
            title.read_romfs(&file, 0, file.data_size as usize).unwrap()
        };
        assert_eq!(read("static.crs"), b"crs");
        assert_eq!(read("cro/Battle.cro"), b"battle");
        assert_eq!(read("CRO/field.cro"), b"field");
        drop(title);
        std::fs::remove_file(path).unwrap();
    }

    /// a literal and a run, the smallest stream that exercises both.
    #[test]
    fn backwards_lzss_decompresses() {
        // the output ends in "abcabc", three literals, then a run of three
        // copying them from three bytes further on
        let mut stream = vec![0xFF, 0xFF];
        // the run, a length and an offset of zero, the shortest there is
        stream.extend_from_slice(&0x0000u16.to_le_bytes());
        stream.extend_from_slice(b"abc");
        // control, three literals then a run, read from the high bit
        stream.push(0b0001_0000);
        // footer, 8 bytes of footer, the compressed part spans all but the
        // two filler bytes, and three more bytes come out
        let span = (stream.len() + 8 - 2) as u32;
        stream.extend_from_slice(&((8u32 << 24) | span).to_le_bytes());
        stream.extend_from_slice(&3u32.to_le_bytes());
        let out = decompress(&stream).unwrap();
        assert_eq!(&out[out.len() - 6..], b"abcabc");
    }
}
