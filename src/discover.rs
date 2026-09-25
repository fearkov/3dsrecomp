//! finding the code in an image. functions are found from the entry point by
//! following calls and branches, and from words elsewhere in the image that
//! point into the code, which is where vtables and callbacks live.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::arm::{self, Flow};
use crate::image::{Image, Segment};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    Entry,
    Call,
    /// a code address stored in a literal pool or in the data segments.
    Pointer,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub source: Source,
    pub instructions: usize,
}

/// what each byte of the text segment turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Byte {
    Unknown,
    Code,
    Literal,
}

pub struct Analysis {
    pub functions: BTreeMap<u32, Function>,
    /// entry points of Thumb code, not followed yet.
    pub thumb_entries: BTreeSet<u32>,
    pub map: Vec<Byte>,
    pub indirect_sites: usize,
    pub jump_tables: usize,
    pub svc_sites: usize,
}

impl Analysis {
    pub fn count(&self, kind: Byte) -> usize {
        self.map.iter().filter(|&&byte| byte == kind).count()
    }

    /// the longest runs of text nobody reached, as (start, length).
    pub fn largest_gaps(&self, base: u32, count: usize) -> Vec<(u32, usize)> {
        let mut gaps = Vec::new();
        let mut start = None;
        for (offset, &byte) in self.map.iter().chain(std::iter::once(&Byte::Code)).enumerate() {
            match (byte == Byte::Unknown, start) {
                (true, None) => start = Some(offset),
                (false, Some(s)) => {
                    gaps.push((base + s as u32, offset - s));
                    start = None;
                }
                _ => {}
            }
        }
        gaps.sort_by_key(|gap| std::cmp::Reverse(gap.1));
        gaps.truncate(count);
        gaps
    }
}

struct Discovery<'a> {
    text: &'a Segment,
    analysis: Analysis,
    queue: VecDeque<(u32, Source)>,
}

pub fn analyze(image: &Image) -> Analysis {
    let mut discovery = Discovery {
        text: &image.text,
        analysis: Analysis {
            functions: BTreeMap::new(),
            thumb_entries: BTreeSet::new(),
            map: vec![Byte::Unknown; image.text.bytes.len()],
            indirect_sites: 0,
            jump_tables: 0,
            svc_sites: 0,
        },
        queue: VecDeque::new(),
    };
    discovery.queue.push_back((image.entry, Source::Entry));
    discovery.run();

    // then whatever the data segments point at
    for segment in [&image.rodata, &image.data] {
        for (_, value) in segment.words() {
            discovery.code_pointer(value);
        }
    }
    discovery.run();
    discovery.analysis
}

impl Discovery<'_> {
    fn run(&mut self) {
        while let Some((entry, source)) = self.queue.pop_front() {
            if !self.analysis.functions.contains_key(&entry) {
                let instructions = self.explore(entry);
                self.analysis.functions.insert(entry, Function { source, instructions });
            }
        }
    }

    fn mark(&mut self, address: u32, size: u32, kind: Byte) {
        for byte in address..address + size {
            if let Some(offset) = byte.checked_sub(self.text.base) {
                if let Some(slot) = self.analysis.map.get_mut(offset as usize) {
                    // code wins over a literal guess
                    if *slot != Byte::Code {
                        *slot = kind;
                    }
                }
            }
        }
    }

    fn is_code(&self, address: u32) -> bool {
        self.analysis.map[(address - self.text.base) as usize] == Byte::Code
    }

    /// a value that may be the address of a function.
    fn code_pointer(&mut self, value: u32) {
        if !self.text.contains(value & !1) {
            return;
        }
        if value & 1 != 0 {
            self.analysis.thumb_entries.insert(value & !1);
        } else if value & 3 == 0 && !self.analysis.functions.contains_key(&value) {
            self.queue.push_back((value, Source::Pointer));
        }
    }

    fn call(&mut self, target: u32) {
        if self.text.contains(target) && !self.analysis.functions.contains_key(&target) {
            self.queue.push_back((target, Source::Call));
        }
    }

    /// follows every path through one function, returning how many
    /// instructions it decoded.
    fn explore(&mut self, entry: u32) -> usize {
        let mut blocks = vec![entry];
        let mut seen = BTreeSet::new();
        let mut decoded = 0;

        while let Some(start) = blocks.pop() {
            let mut address = start;
            while self.text.contains(address) && seen.insert(address) {
                if self.analysis.map[(address - self.text.base) as usize] == Byte::Literal {
                    // ran into a literal pool, the path is wrong or it ended
                    break;
                }
                let Some(word) = self.text.read32(address) else { break };
                let instruction = arm::decode(word, address);
                self.mark(address, 4, Byte::Code);
                decoded += 1;
                let conditional = instruction.is_conditional();

                match instruction.flow {
                    Flow::Branch { target, link: true } => self.call(target),
                    Flow::Branch { target, link: false } => {
                        if self.text.contains(target) {
                            blocks.push(target);
                        }
                        if !conditional {
                            break;
                        }
                    }
                    Flow::BranchToThumb { target } => {
                        self.analysis.thumb_entries.insert(target);
                    }
                    Flow::BranchRegister { link: true, .. } => self.analysis.indirect_sites += 1,
                    Flow::BranchRegister { link: false, .. } | Flow::IndirectJump => {
                        self.analysis.indirect_sites += 1;
                        if !conditional {
                            break;
                        }
                    }
                    Flow::Return => {
                        if !conditional {
                            break;
                        }
                    }
                    Flow::JumpTable => {
                        // the table is a run of branches starting right after
                        // the default case
                        self.analysis.jump_tables += 1;
                        let mut entry = address + 4;
                        while let Some(word) = self.text.read32(entry) {
                            match arm::decode(word, entry) {
                                arm::Instruction { condition: arm::ALWAYS, flow: Flow::Branch { target, link: false } } => {
                                    self.mark(entry, 4, Byte::Code);
                                    if self.text.contains(target) {
                                        blocks.push(target);
                                    }
                                    entry += 4;
                                }
                                _ => break,
                            }
                        }
                        break;
                    }
                    Flow::LoadPcLiteral { literal } => {
                        self.mark(literal, 4, Byte::Literal);
                        if let Some(target) = self.text.read32(literal) {
                            self.code_pointer(target);
                        }
                        if !conditional {
                            break;
                        }
                    }
                    Flow::LiteralLoad { literal, size } => {
                        if !self.text.contains(literal) || self.is_code(literal) {
                            // a load from inside the code that we already
                            // decoded as instructions, leave it be
                        } else {
                            self.mark(literal, size, Byte::Literal);
                            if size == 4 {
                                if let Some(value) = self.text.read32(literal) {
                                    self.code_pointer(value);
                                }
                            }
                        }
                    }
                    Flow::Svc => self.analysis.svc_sites += 1,
                    Flow::Other => {}
                }
                address += 4;
            }
        }
        decoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 0x0010_0000;

    fn image(words: &[u32]) -> Image {
        let bytes = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let empty = |base| Segment { base, bytes: Vec::new() };
        Image {
            entry: BASE,
            text: Segment { base: BASE, bytes },
            rodata: empty(0x0020_0000),
            data: empty(0x0030_0000),
        }
    }

    #[test]
    fn follows_calls_and_marks_literals() {
        let analysis = analyze(&image(&[
            0xEB00_0002, // bl 0x100010
            0xEF00_0000, // svc 0
            0xEAFF_FFFE, // b .
            0xDEAD_BEEF, // never reached
            0xE59F_0000, // ldr r0, [pc] (literal at 0x100018)
            0xE12F_FF1E, // bx lr
            0x0010_0000, // the literal
        ]));
        assert_eq!(analysis.functions.keys().copied().collect::<Vec<_>>(), [BASE, BASE + 0x10]);
        assert_eq!(analysis.functions[&(BASE + 0x10)].source, Source::Call);
        assert_eq!(analysis.count(Byte::Code), 5 * 4);
        assert_eq!(analysis.count(Byte::Literal), 4);
        assert_eq!(analysis.largest_gaps(BASE, 1), [(BASE + 0xC, 4)]);
        assert_eq!(analysis.svc_sites, 1);
    }

    #[test]
    fn a_switch_table_leads_to_every_case() {
        let analysis = analyze(&image(&[
            0xE350_0001, // cmp r0, 1
            0x908F_F100, // addls pc, pc, r0 lsl 2
            0xEA00_0002, // b default (0x100018)
            0xEA00_0002, // b case 0 (0x10001c)
            0xEA00_0002, // b case 1 (0x100020)
            0xE12F_FF1E, // bx lr, unreachable filler
            0xE12F_FF1E, // default
            0xE12F_FF1E, // case 0
            0xE12F_FF1E, // case 1
        ]));
        assert_eq!(analysis.jump_tables, 1);
        assert_eq!(analysis.count(Byte::Code), 8 * 4);
    }

    #[test]
    fn pointers_in_data_become_functions() {
        let mut image = image(&[0xE12F_FF1E, 0xE12F_FF1E, 0xE12F_FF1E]);
        image.rodata.bytes = [BASE + 8, BASE + 5].iter().flat_map(|w| w.to_le_bytes()).collect();
        let analysis = analyze(&image);
        assert_eq!(analysis.functions[&(BASE + 8)].source, Source::Pointer);
        assert!(analysis.thumb_entries.contains(&(BASE + 4)));
    }
}
