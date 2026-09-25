//! the Rust side of recomp.h, the interface recompiled code runs against.

use std::cell::RefCell;
use std::ffi::{CStr, c_char, c_void};
use std::path::Path;

pub type Code = unsafe extern "C" fn(*mut Context);

pub const ABI: u32 = 3;

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
    pub vfp: *mut u32,
    pub fpscr: *mut u32,
    pub host: *const Host,
    pub user: *mut c_void,
}

#[repr(C)]
pub struct Entry {
    pub address: u32,
    pub code: Code,
}

/// a module's code, whose entries are offsets from where it gets loaded.
#[repr(C)]
pub struct Module {
    name: *const c_char,
    base: *mut u32,
    pub size: u32,
    count: u32,
    entries: *const Entry,
}

impl Module {
    pub fn name(&self) -> &str {
        // SAFETY: the generated table holds string literals
        unsafe { CStr::from_ptr(self.name) }.to_str().unwrap_or_default()
    }

    pub fn entries(&self) -> &[Entry] {
        // SAFETY: the table lives as long as the library does
        unsafe { std::slice::from_raw_parts(self.entries, self.count as usize) }
    }

}

/// a library of recompiled code, loaded.
pub struct Library {
    entries: *const Entry,
    count: usize,
    modules: *const Module,
    module_count: usize,
    /// the modules placed somewhere, as base, size and index.
    placed: RefCell<Vec<(u32, u32, usize)>>,
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
            let module_count = **library.get::<*const u32>(b"recomp_module_count").map_err(|e| e.to_string())?;
            let modules = *library.get::<*const Module>(b"recomp_modules").map_err(|e| e.to_string())?;
            Ok(Library {
                entries,
                count: count as usize,
                modules,
                module_count: module_count as usize,
                placed: RefCell::new(Vec::new()),
                _library: library,
            })
        }
    }

    pub fn entries(&self) -> &[Entry] {
        // SAFETY: the table lives as long as the library does
        unsafe { std::slice::from_raw_parts(self.entries, self.count) }
    }

    pub fn modules(&self) -> &[Module] {
        // SAFETY: the table lives as long as the library does
        unsafe { std::slice::from_raw_parts(self.modules, self.module_count) }
    }

    /// the code that can run from address, bit 0 set for Thumb, in the
    /// executable or in a module that is loaded.
    pub fn lookup(&self, address: u32) -> Option<Code> {
        let find = |entries: &[Entry], address: u32| {
            entries.binary_search_by_key(&address, |entry| entry.address).ok().map(|i| entries[i].code)
        };
        find(self.entries(), address).or_else(|| {
            let placed = self.placed.borrow();
            let &(base, _, index) = placed.iter().find(|&&(base, size, _)| address.wrapping_sub(base) < size)?;
            find(self.modules()[index].entries(), address - base)
        })
    }

    /// tells the code of module index where it was loaded, zero when it goes
    /// away.
    pub fn place(&self, index: usize, base: u32) {
        let module = &self.modules()[index];
        // SAFETY: base points at the module's variable in the library, which
        // the code only reads on entry
        unsafe { *module.base = base };
        let mut placed = self.placed.borrow_mut();
        placed.retain(|&(_, _, i)| i != index);
        if base != 0 {
            placed.push((base, module.size, index));
        }
    }
}
