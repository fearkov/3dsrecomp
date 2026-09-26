//! finding the code in a program. functions are found from the entry points
//! by following calls and branches, and from words elsewhere that point into
//! the code, which is where vtables and callbacks live.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::arm::{self, Flow, Instruction};
use crate::image::Segment;
use crate::thumb;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    Entry,
    Call,
    /// a code address stored in a literal pool or in the data segments.
    Pointer,
    /// a symbol the program exports to other modules.
    Export,
    /// a code address a module's relocations store, in its vtables, jump
    /// tables and literal pools.
    Relocation,
    /// a code address another module takes from this one without a name.
    Import,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    Arm,
    Thumb,
}

impl Mode {
    fn other(self) -> Mode {
        match self {
            Mode::Arm => Mode::Thumb,
            Mode::Thumb => Mode::Arm,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Function {
    pub source: Source,
    pub mode: Mode,
    /// the address of every instruction, in order.
    pub instructions: Vec<u32>,
    /// where execution can enter the function's code, its entry, the
    /// targets of its branches and the instructions after calls and svc.
    pub labels: BTreeSet<u32>,
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
    pub map: Vec<Byte>,
    pub indirect_sites: usize,
    pub jump_tables: usize,
    pub svc_sites: usize,
    /// paths abandoned because they ran into something that cannot be code.
    pub dead_ends: usize,
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

/// a piece of code to analyze and what is known about it up front.
pub struct Program {
    pub text: Segment,
    /// addresses that may start functions and how each is known, odd for
    /// Thumb.
    pub seeds: Vec<(u32, Source)>,
    /// the words in the code that hold addresses, when relocations say
    /// exactly which ones they are. without them any literal that lands in
    /// the code is taken for a pointer.
    pub slots: Option<BTreeSet<u32>>,
}

struct Discovery<'a> {
    text: &'a Segment,
    slots: Option<&'a BTreeSet<u32>>,
    analysis: Analysis,
    queue: VecDeque<(u32, Mode, Source)>,
    /// pointers found in data, followed only once nothing surer is left.
    guesses: VecDeque<(u32, Mode, Source)>,
}

pub fn analyze(program: &Program) -> Analysis {
    let mut discovery = Discovery {
        text: &program.text,
        slots: program.slots.as_ref(),
        analysis: Analysis {
            functions: BTreeMap::new(),
            map: vec![Byte::Unknown; program.text.bytes.len()],
            indirect_sites: 0,
            jump_tables: 0,
            svc_sites: 0,
            dead_ends: 0,
        },
        queue: VecDeque::new(),
        guesses: VecDeque::new(),
    };
    // where relocations say the code holds data, it cannot be code
    for &slot in program.slots.iter().flatten() {
        discovery.mark(slot, 4, Byte::Literal);
    }
    for &(address, source) in &program.seeds {
        discovery.code_pointer(address, source);
    }
    discovery.run();
    discovery.analysis
}

impl Discovery<'_> {
    fn run(&mut self) {
        while let Some((entry, mode, source)) = self.queue.pop_front().or_else(|| self.guesses.pop_front()) {
            if !self.analysis.functions.contains_key(&entry) {
                let (instructions, labels) = self.explore(entry, mode);
                self.analysis.functions.insert(entry, Function { source, mode, instructions, labels });
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

    fn byte(&self, address: u32) -> Byte {
        self.analysis.map[(address - self.text.base) as usize]
    }

    /// whether the word at address may hold a code address.
    fn may_point(&self, address: u32) -> bool {
        self.slots.is_none_or(|slots| slots.contains(&address))
    }

    /// a value that may be the address of a function, odd for Thumb.
    fn code_pointer(&mut self, value: u32, source: Source) {
        let (address, mode) = if value & 1 != 0 {
            (value & !1, Mode::Thumb)
        } else if value & 3 == 0 {
            (value, Mode::Arm)
        } else {
            return;
        };
        if self.text.contains(address) && !self.analysis.functions.contains_key(&address) {
            if source == Source::Pointer {
                self.guesses.push_back((address, mode, source));
            } else {
                self.queue.push_back((address, mode, source));
            }
        }
    }

    fn call(&mut self, target: u32, mode: Mode) {
        if self.text.contains(target) && !self.analysis.functions.contains_key(&target) {
            self.queue.push_back((target, mode, Source::Call));
        }
    }

    fn decode(&self, address: u32, mode: Mode) -> Option<(Instruction, u32)> {
        match mode {
            Mode::Arm => Some((arm::decode(self.text.read32(address)?, address), 4)),
            Mode::Thumb => {
                let halfword = self.text.read16(address)?;
                Some(thumb::decode(halfword, self.text.read16(address + 2), address))
            }
        }
    }

    /// follows every path through one function, returning its instructions
    /// and labels.
    fn explore(&mut self, entry: u32, mode: Mode) -> (Vec<u32>, BTreeSet<u32>) {
        let mut blocks = vec![entry];
        let mut seen = BTreeSet::new();
        let mut code = BTreeSet::new();
        let mut labels = BTreeSet::new();

        while let Some(start) = blocks.pop() {
            labels.insert(start);
            let mut address = start;
            while self.text.contains(address) && seen.insert(address) {
                if self.byte(address) == Byte::Literal {
                    // ran into a literal pool, the path is wrong or it ended
                    break;
                }
                let Some((instruction, size)) = self.decode(address, mode) else { break };
                if instruction.flow == Flow::Undefined {
                    self.analysis.dead_ends += 1;
                    break;
                }
                self.mark(address, size, Byte::Code);
                code.insert(address);
                let conditional = instruction.is_conditional();

                let returns = matches!(
                    instruction.flow,
                    Flow::Branch { link: true, .. }
                        | Flow::CallOtherMode { .. }
                        | Flow::BranchRegister { link: true, .. }
                        | Flow::Svc
                );
                if returns {
                    // execution comes back after a call or an svc
                    labels.insert(address + size);
                }
                match instruction.flow {
                    Flow::Branch { target, link: true } => self.call(target, mode),
                    Flow::CallOtherMode { target } => self.call(target, mode.other()),
                    Flow::Branch { target, link: false } => {
                        if self.text.contains(target) {
                            blocks.push(target);
                        }
                        if !conditional {
                            break;
                        }
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
                        self.branch_table(address, &mut blocks);
                        break;
                    }
                    Flow::AddressTable { index } => {
                        self.address_table(address, index, &mut blocks);
                        if !conditional {
                            break;
                        }
                    }
                    Flow::LoadPcLiteral { literal } => {
                        self.mark(literal, 4, Byte::Literal);
                        if let Some(target) = self.text.read32(literal).filter(|_| self.may_point(literal)) {
                            self.code_pointer(target, Source::Pointer);
                        }
                        if !conditional {
                            break;
                        }
                    }
                    Flow::LiteralLoad { literal, size } => {
                        // a load from something already decoded as code is
                        // left alone
                        if self.text.contains(literal) && self.byte(literal) != Byte::Code {
                            self.mark(literal, size, Byte::Literal);
                            if size == 4 && self.may_point(literal) {
                                if let Some(value) = self.text.read32(literal) {
                                    self.code_pointer(value, Source::Pointer);
                                }
                            }
                        }
                    }
                    Flow::Svc => self.analysis.svc_sites += 1,
                    Flow::Undefined | Flow::Other => {}
                }
                address += size;
            }
        }
        labels.retain(|label| code.contains(label));
        (code.into_iter().collect(), labels)
    }

    /// add pc, pc, rm lsl 2 jumps into a run of branches that starts with
    /// the default case right after it.
    fn branch_table(&mut self, address: u32, blocks: &mut Vec<u32>) {
        self.analysis.jump_tables += 1;
        let mut entry = address + 4;
        while let Some(word) = self.text.read32(entry) {
            match arm::decode(word, entry) {
                Instruction { condition: arm::ALWAYS, flow: Flow::Branch { link: false, .. } } => {
                    blocks.push(entry);
                    entry += 4;
                }
                _ => break,
            }
        }
    }

    /// ldr pc, [pc, rm lsl 2] loads its target from the table of addresses
    /// right after the default branch. its size comes from the cmp just
    /// before it, or failing that from how far the entries keep pointing
    /// into the code.
    fn address_table(&mut self, address: u32, index: u32, blocks: &mut Vec<u32>) {
        self.analysis.jump_tables += 1;
        let entries = address
            .checked_sub(4)
            .and_then(|previous| self.text.read32(previous))
            .and_then(arm::compare_immediate)
            .filter(|&(register, _)| register == index)
            .map(|(_, limit)| limit as usize + 1);
        let table = address + 8;
        for i in 0..entries.unwrap_or(256) {
            let slot = table + i as u32 * 4;
            let Some(target) = self.text.read32(slot) else { break };
            if !self.text.contains(target & !1) || !self.may_point(slot) {
                break;
            }
            self.mark(slot, 4, Byte::Literal);
            if target & 3 == 0 {
                blocks.push(target);
            } else {
                self.code_pointer(target, Source::Pointer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 0x0010_0000;

    fn analyze_words(words: &[u32]) -> Analysis {
        analyze(&program(words))
    }

    fn program(words: &[u32]) -> Program {
        Program {
            text: Segment { base: BASE, bytes: words.iter().flat_map(|w| w.to_le_bytes()).collect() },
            seeds: vec![(BASE, Source::Entry)],
            slots: None,
        }
    }

    #[test]
    fn follows_calls_and_marks_literals() {
        let analysis = analyze_words(&[
            0xEB00_0002, // bl 0x100010
            0xEF00_0000, // svc 0
            0xEAFF_FFFE, // b .
            0xDEAD_BEEF, // never reached
            0xE59F_0000, // ldr r0, [pc] (literal at 0x100018)
            0xE12F_FF1E, // bx lr
            0x0010_0000, // the literal
        ]);
        assert_eq!(analysis.functions.keys().copied().collect::<Vec<_>>(), [BASE, BASE + 0x10]);
        assert_eq!(analysis.functions[&BASE].labels, BTreeSet::from([BASE, BASE + 4, BASE + 8]));
        assert_eq!(analysis.functions[&(BASE + 0x10)].source, Source::Call);
        assert_eq!(analysis.count(Byte::Code), 5 * 4);
        assert_eq!(analysis.count(Byte::Literal), 4);
        assert_eq!(analysis.largest_gaps(BASE, 1), [(BASE + 0xC, 4)]);
        assert_eq!(analysis.svc_sites, 1);
    }

    #[test]
    fn a_switch_table_leads_to_every_case() {
        let analysis = analyze_words(&[
            0xE350_0001, // cmp r0, 1
            0x908F_F100, // addls pc, pc, r0 lsl 2
            0xEA00_0002, // b default (0x100018)
            0xEA00_0002, // b case 0 (0x10001c)
            0xEA00_0002, // b case 1 (0x100020)
            0xE12F_FF1E, // bx lr, unreachable filler
            0xE12F_FF1E, // default
            0xE12F_FF1E, // case 0
            0xE12F_FF1E, // case 1
        ]);
        assert_eq!(analysis.jump_tables, 1);
        assert_eq!(analysis.count(Byte::Code), 8 * 4);
        let labels: Vec<_> = analysis.functions[&BASE].labels.iter().map(|l| l - BASE).collect();
        assert_eq!(labels, [0, 8, 0xC, 0x10, 0x18, 0x1C, 0x20]);
    }

    #[test]
    fn an_address_table_is_sized_by_its_compare() {
        let analysis = analyze_words(&[
            0xE350_0001, // cmp r0, 1
            0x979F_F100, // ldrls pc, [pc, r0 lsl 2]
            0xE12F_FF1E, // bx lr, the default case
            BASE + 0x14, // case 0
            BASE + 0x18, // case 1
            0xE12F_FF1E, // case 0
            0xE12F_FF1E, // case 1
        ]);
        assert_eq!(analysis.jump_tables, 1);
        assert_eq!(analysis.count(Byte::Literal), 8);
        assert_eq!(analysis.count(Byte::Code), 5 * 4);
    }

    #[test]
    fn blx_leads_into_thumb_code() {
        let analysis = analyze_words(&[
            0xFA00_0000, // blx 0x100008
            0xE12F_FF1E, // bx lr
            0x4770_2001, // movs r0, 1 then bx lr, in Thumb
        ]);
        let thumb = &analysis.functions[&(BASE + 8)];
        assert_eq!(thumb.mode, Mode::Thumb);
        assert_eq!(thumb.instructions, [BASE + 8, BASE + 10]);
    }

    #[test]
    fn pointer_seeds_become_functions() {
        let mut program = program(&[0xE12F_FF1E, 0x4770_4770, 0xE12F_FF1E]);
        program.seeds.extend([(BASE + 8, Source::Pointer), (BASE + 5, Source::Pointer)]);
        let analysis = analyze(&program);
        assert_eq!(analysis.functions[&(BASE + 8)].source, Source::Pointer);
        assert_eq!(analysis.functions[&(BASE + 4)].mode, Mode::Thumb);
    }

    #[test]
    fn with_slots_only_relocated_literals_are_pointers() {
        let words = [
            0xE59F_0000, // ldr r0, [pc] (literal at 0x100008)
            0xE12F_FF1E, // bx lr
            BASE + 0xC,  // looks like a code address
            0xE12F_FF1E, // bx lr
        ];
        assert!(analyze_words(&words).functions.contains_key(&(BASE + 0xC)));
        let mut program = program(&words);
        program.slots = Some(BTreeSet::new());
        assert!(!analyze(&program).functions.contains_key(&(BASE + 0xC)));
    }
}
