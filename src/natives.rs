//! the C library functions that 3dsrecomp runs natively instead of as the
//! title's code: the integer divisions of ARM's C library, which every title
//! built with armcc links and which the ARM11 does with a loop, having no
//! divide instruction. they are found by their bytes, RVCT 4.1's as its
//! libraries have them, the ones a relocation fills in left out, and each
//! becomes an override that divides on the host, leaving division by zero
//! and the one quotient that overflows to the library's own code. Star Fox
//! 64 3D spends about 6% of its time in its 64-bit division.

use crate::image::Segment;

/// a division of the library's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// r0 / r1 unsigned, the quotient in r0 and the remainder in r1.
    Uidivmod,
    /// the same signed, rounding toward zero.
    Idivmod,
    /// r0:r1 / r2:r3 unsigned, the quotient in r0:r1 and the remainder in
    /// r2:r3.
    Uldivmod,
    /// the same signed.
    Ldivmod,
}

impl Kind {
    /// the name recomp.h's functions for it go by, native_<name>.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Uidivmod => "uidivmod",
            Kind::Idivmod => "idivmod",
            Kind::Uldivmod => "uldivmod",
            Kind::Ldivmod => "ldivmod",
        }
    }

    const ALL: [Kind; 4] = [Kind::Uidivmod, Kind::Idivmod, Kind::Uldivmod, Kind::Ldivmod];

    fn signature(self) -> (&'static [&'static str], &'static [usize]) {
        match self {
            Kind::Uidivmod => UIDIVMOD,
            Kind::Idivmod => IDIVMOD,
            Kind::Uldivmod => ULDIVMOD,
            Kind::Ldivmod => LDIVMOD,
        }
    }
}

/// one the title has, at an address, all of them ARM code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Native {
    pub address: u32,
    pub kind: Kind,
}

/// a signature's bytes, and a mask that is zero where a relocation filled
/// them in, the 24-bit offsets of the branches and calls.
fn pattern(kind: Kind) -> (Vec<u8>, Vec<u8>) {
    let (hex, relocated) = kind.signature();
    let hex: String = hex.concat();
    let bytes: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex")).collect();
    let mut mask = vec![0xFF; bytes.len()];
    for &at in relocated {
        mask[at..at + 3].fill(0);
    }
    (bytes, mask)
}

/// where a branch at address goes.
fn branch_target(address: u32, word: u32) -> u32 {
    let offset = ((word & 0x00FF_FFFF) << 8) as i32 >> 6;
    address.wrapping_add(8).wrapping_add(offset as u32)
}

/// the divisions in code, each where its bytes are. the unsigned 32-bit one
/// is only a way into the signed one's loop, so it counts when all of its
/// branches lead into a signed one found too.
pub fn find(text: &Segment) -> Vec<Native> {
    let mut found = Vec::new();
    for kind in Kind::ALL {
        let (bytes, mask) = pattern(kind);
        let anchor = &bytes[..bytes.iter().zip(&mask).take_while(|(_, m)| **m == 0xFF).count().min(16)];
        let code = &text.bytes;
        let mut start = 0;
        while let Some(at) = find_from(code, anchor, start) {
            start = at + 1;
            if at % 4 != 0 || at + bytes.len() > code.len() {
                continue;
            }
            let same = code[at..at + bytes.len()].iter().zip(&bytes).zip(&mask).all(|((c, b), m)| (c ^ b) & m == 0);
            if same {
                found.push(Native { address: text.base + at as u32, kind });
            }
        }
    }
    let signed: Vec<(u32, u32)> = found
        .iter()
        .filter(|native| native.kind == Kind::Idivmod)
        .map(|native| (native.address, native.address + pattern(Kind::Idivmod).0.len() as u32))
        .collect();
    let (_, relocated) = UIDIVMOD;
    found.retain(|native| {
        native.kind != Kind::Uidivmod
            || relocated.iter().all(|&at| {
                let address = native.address + at as u32;
                let word = text.read32(address).unwrap_or(0);
                let target = branch_target(address, word);
                signed.iter().any(|&(start, end)| (start..end).contains(&target))
            })
    });
    found.sort_by_key(|native| native.address);
    found
}

fn find_from(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    haystack.get(start..)?.windows(needle.len()).position(|window| window == needle).map(|at| at + start)
}

/// the overrides that run the natives found, as a C file next to the
/// generated code. one written by hand for the same address goes first.
pub fn source(natives: &[Native]) -> String {
    let mut out = String::from(
        "/* the C library's divisions, run on the host, see natives.rs. */\n\n#include \"overrides.h\"\n\n\
         /* a host sets this to 0 to have the library's own code run instead. */\n\
         RECOMP_EXPORT uint8_t recomp_natives = 1;\n",
    );
    for native in natives {
        let address = format!("0x{:08X}", native.address);
        let name = native.kind.name();
        out.push_str(&format!(
            "\nRECOMP_OVERRIDE({address}) {{\n    RECOMP_NATIVE({address}u, {name}, RECOMP_ORIGINAL({address}));\n}}\n"
        ));
    }
    out
}

/// `__aeabi_uldivmod`, which is `_ll_udiv`, from lludiv5.o.
const ULDIVMOD: (&[&str], &[usize]) = (
    &[
    "70402de90340a0e10250a0e10130a0e10020a0e1000054e304c0a01105c0a0011cef6fe101008ee21cc0a0e13fe07e12",
    "1fe07e028500004a000053e3131f6f11121f6f013f1071121f1071020e6051e08300004a040076528400005a20004ee2",
    "040050e335c08cd12ccea0e18f1f8fe20cc191e71f005ee320e04e8220606ee24000008a9c0581e01116a0e1301e81e1",
    "1006a0e1000070e20010e1e29c0181e001c08ce09c0581e01116a0e1301e81e11006a0e1000070e20010e1e2000053e3",
    "9c0181e001c08ce00700000a9c0581e01116a0e1301e81e11006a0e1000070e20010e1e29c0181e001c08ce09c1280e0",
    "0010a0e39c03a1e0300ea0e1110680e1906584e0311ea0e1914524e0062052e00430c3e0010053e3050052317080bd38",
    "9c4286e00040a0e39c63a4e00030a0e320c06ee2366ea0e1146c86e1344ea0e196e58ce0060090e00410a1e00e2042e0",
    "050052e17080bd38010090e20010a1e2052042e005c052e00c20a0210000b0e20010a1e205c052e00c20a0210000b0e2",
    "0010a1e27080bde89c1580e00010a0e39c04a1e01116a0e1301e81e11006a0e1000070e20010e1e29c0181e001c08ce0",
    "9c1580e00010a0e39c04a1e01116a0e1301e81e11006a0e1000070e20010e1e29c0181e001c08ce001c04ce29c1280e0",
    "0010a0e39c03a1e0310ea0e1906581e0062052e0901421e00130c3e0040053e1050052010010a0337080bd389c6281e0",
    "0060a0e39c13a6e00010a0e3366ea0e196e58ce0060080e00e2052e096c42ee00e30c3e0040053e1050052017080bd38",
    "010080e2052052e00430c3e07080bde80c002de90010a0e30000a0e3feffffeb7c80bde80010a0e30000a0e37080bde8",
    "20e066e20000a0e30010a0e31446a0e1354e84e11556a0e105e052e004c0d3e00000a0e00c30a0210e20a021016056e2",
    "7080bd38a440b0e16550a0e1f5ffffeaf0f0f0f0e3388ee3e53594d7ccccccccc3300cc3a28b2ebac84216b2aaaaaaaa",
    "3d0ad7a39dd8899ded25b4979224499208cb3d8d888888884208218400000080",
    ],
    &[604],
);

/// `__aeabi_ldivmod`, which is `_ll_sdiv`, from llsdiv.o.
const LDIVMOD: (&[&str], &[usize]) = (
    &[
    "10402de9c140b0e1a34024e00100005a000070e20010e1e2030013e10100005a002072e20030e3e2feffffeb010114e3",
    "0100000a000070e20010e1e2020114e30100000a002072e20030e3e21080bde8",
    ],
    &[40],
);

/// `__aeabi_idivmod`, which is `__aeabi_idiv`, from aeabi_sdivfast_rs.o.
const IDIVMOD: (&[&str], &[usize]) = (
    &[
    "013090e14d00004aa03071e04400003a0020b0e3203271e03400003a203471e02600003a203671e01700003a203871e0",
    "0900003a0114a0e1203871e0ff2482e3ff2882230114a021203671e00e00003a003071e27000002a2114a021a03771e0",
    "810740200220b2e0203771e0010740200220b2e0a03671e0810640200220b2e0203671e0010640200220b2e0a03571e0",
    "810540200220b2e0203571e0010540200220b2e0a03471e0810440200220b2e0203471e0010440200220b2e0e5ffff2a",
    "a03371e0810340200220b2e0203371e0010340200220b2e0a03271e0810240200220b2e0203271e0010240200220b2e0",
    "a03171e0810140200220b2e0203171e0010140200220b2e0a03071e0810040200220b2e0011050e00010a0310200a2e0",
    "1eff2fe1011050e00100003a0100b0e31eff2fe10010a0e10000b0e31eff2fe1022111e20010614240c032e000006022",
    "203271e01d00003a203471e00f00003a0113a0e1203471e03f2382e30b00003a0113a0e1203471e03f2682e30700003a",
    "0113a0e1203471e03f2982e30113a0213f2c8223003071e21d00002a2113a021a03371e0810340200220b2e0203371e0",
    "010340200220b2e0a03271e0810240200220b2e0203271e0010240200220b2e0a03171e0810140200220b2e0203171e0",
    "010140200220b2e0ebffff2aa03071e0810040200220b2e0011050e00010a0310200a2e0cccfb0e10000604200106122",
    "1eff2fe1cccfb0e10000604201402de90000b0e3feffffeb0280bde8",
    ],
    &[548],
);

/// `__aeabi_uidivmod`, which is `__aeabi_uidiv`, from aeabi_sdivfast.o and
/// aeabi_sdivfast_rs.o alike, a way in that branches into the division of
/// `__aeabi_idivmod`.
const UIDIVMOD: (&[&str], &[usize]) = (
    &[
    "0020b0e3203171e0feffff3aa03271e0feffff3a203471e0feffff3a203671e0feffff3a203871e0feffff3afeffffea",
    ],
    &[8, 16, 24, 32, 40, 44],
);

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 0x0010_0000;

    /// code with each division in it where the linker would put them, the
    /// relocated branches and calls pointing where they should.
    fn code(uidiv_into_signed: bool) -> (Segment, [u32; 4]) {
        let mut bytes = vec![0u8; 0x2000];
        let place = |bytes: &mut Vec<u8>, at: usize, kind: Kind| {
            let (pattern, _) = pattern(kind);
            bytes[at..at + pattern.len()].copy_from_slice(&pattern);
        };
        let (uldiv, ldiv, idiv, uidiv) = (0x100, 0x600, 0x800, 0x1800);
        place(&mut bytes, uldiv, Kind::Uldivmod);
        place(&mut bytes, ldiv, Kind::Ldivmod);
        place(&mut bytes, idiv, Kind::Idivmod);
        place(&mut bytes, uidiv, Kind::Uidivmod);
        // the way in branches into the signed loop, or nowhere near it
        for &at in UIDIVMOD.1 {
            let address = BASE + (uidiv + at) as u32;
            let target = if uidiv_into_signed { BASE + idiv as u32 + 0x40 } else { BASE + 0x1F00 };
            let offset = (target.wrapping_sub(address + 8) as i32 >> 2) as u32 & 0x00FF_FFFF;
            let word = u32::from_le_bytes(bytes[uidiv + at..uidiv + at + 4].try_into().unwrap());
            bytes[uidiv + at..uidiv + at + 4].copy_from_slice(&((word & 0xFF00_0000) | offset).to_le_bytes());
        }
        let addresses = [uldiv, ldiv, idiv, uidiv].map(|at| BASE + at as u32);
        (Segment { base: BASE, bytes }, addresses)
    }

    #[test]
    fn the_divisions_are_found_where_they_are() {
        let (text, [uldiv, ldiv, idiv, uidiv]) = code(true);
        let found = find(&text);
        assert_eq!(
            found,
            vec![
                Native { address: uldiv, kind: Kind::Uldivmod },
                Native { address: ldiv, kind: Kind::Ldivmod },
                Native { address: idiv, kind: Kind::Idivmod },
                Native { address: uidiv, kind: Kind::Uidivmod },
            ]
        );
    }

    #[test]
    fn an_unsigned_way_in_that_leads_elsewhere_is_not_a_division() {
        let (text, [_, _, _, uidiv]) = code(false);
        assert!(find(&text).iter().all(|native| native.address != uidiv));
    }

    #[test]
    fn a_changed_byte_is_not_a_division() {
        let (mut text, [uldiv, ..]) = code(true);
        text.bytes[(uldiv - BASE) as usize + 0x40] ^= 1;
        assert!(find(&text).iter().all(|native| native.kind != Kind::Uldivmod));
    }

    #[test]
    fn the_overrides_name_each_native_and_its_original() {
        let source = source(&[Native { address: 0x002E_A9FC, kind: Kind::Uldivmod }]);
        assert!(source.contains("RECOMP_OVERRIDE(0x002EA9FC) {"));
        assert!(source.contains("RECOMP_NATIVE(0x002EA9FCu, uldivmod, RECOMP_ORIGINAL(0x002EA9FC));"));
        let parsed = crate::overrides::parse(&source).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].address, 0x002E_A9FC);
    }
}
