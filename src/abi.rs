//! the Rust side of recomp.h, the interface recompiled code runs against.

use std::ffi::c_void;
use std::path::Path;

pub type Code = unsafe extern "C" fn(*mut Context);

pub const ABI: u32 = 1;

pub const EXIT_SVC: u32 = 1;
pub const EXIT_BUDGET: u32 = 2;

#[repr(C)]
pub struct Host {
    pub read8: unsafe extern "C" fn(*mut Context, u32) -> u8,
    pub read16: unsafe extern "C" fn(*mut Context, u32) -> u16,
    pub read32: unsafe extern "C" fn(*mut Context, u32) -> u32,
    pub write8: unsafe extern "C" fn(*mut Context, u32, u8),
    pub write16: unsafe extern "C" fn(*mut Context, u32, u16),
    pub write32: unsafe extern "C" fn(*mut Context, u32, u32),
    pub interpret: unsafe extern "C" fn(*mut Context, u32, u32),
    pub lookup: unsafe extern "C" fn(*mut Context, u32) -> Option<Code>,
}

#[repr(C)]
pub struct Context {
    pub r: [u32; 16],
    pub n: u8,
    pub z: u8,
    pub c: u8,
    pub v: u8,
    pub q: u8,
    pub thumb: u8,
    pub ge: u8,
    pub pad: u8,
    pub budget: i32,
    pub exit: u32,
    pub svc: u32,
    pub depth: u32,
    pub read_pages: *const *mut u8,
    pub write_pages: *const *mut u8,
    pub host: *const Host,
    pub user: *mut c_void,
}

#[repr(C)]
pub struct Entry {
    pub address: u32,
    pub code: Code,
}

/// a library of recompiled code, loaded.
pub struct Library {
    entries: *const Entry,
    count: usize,
    _library: libloading::Library,
}

impl Library {
    pub fn open(path: &Path) -> Result<Library, String> {
        // SAFETY: the library is one build produced, whose symbols have the
        // types recomp.h gives them.
        unsafe {
            let library = libloading::Library::new(path).map_err(|e| e.to_string())?;
            let abi = **library.get::<*const u32>(b"recomp_abi").map_err(|e| e.to_string())?;
            if abi != ABI {
                return Err(format!("the library speaks version {abi} of the interface, not {ABI}"));
            }
            let count = **library.get::<*const u32>(b"recomp_entry_count").map_err(|e| e.to_string())?;
            let entries = *library.get::<*const Entry>(b"recomp_entries").map_err(|e| e.to_string())?;
            Ok(Library { entries, count: count as usize, _library: library })
        }
    }

    pub fn entries(&self) -> &[Entry] {
        // SAFETY: the table lives as long as the library does
        unsafe { std::slice::from_raw_parts(self.entries, self.count) }
    }

    /// the code that can run from address, bit 0 set for Thumb.
    pub fn lookup(&self, address: u32) -> Option<Code> {
        let entries = self.entries();
        entries.binary_search_by_key(&address, |entry| entry.address).ok().map(|i| entries[i].code)
    }
}
