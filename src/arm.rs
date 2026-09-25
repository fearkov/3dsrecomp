//! just enough ARM decoding to follow control flow. every instruction that
//! does not change where execution goes, or point at data inside the code,
//! is simply Other.

/// the condition field value meaning always.
pub const ALWAYS: u32 = 0xE;
const PC: u32 = 15;
const LR: u32 = 14;
const SP: u32 = 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// b or bl to a known address.
    Branch { target: u32, link: bool },
    /// blx to a known address, which switches to Thumb.
    BranchToThumb { target: u32 },
    /// bx or blx through a register.
    BranchRegister { register: u32, link: bool },
    /// bx lr, pop with pc, mov pc lr and the like.
    Return,
    /// add pc, pc, rm lsl 2, followed by a table of branches.
    JumpTable,
    /// any other write to pc whose target is not known statically.
    IndirectJump,
    /// ldr pc from a literal, whose value is the target.
    LoadPcLiteral { literal: u32 },
    /// a load from a literal pool inside the code.
    LiteralLoad { literal: u32, size: u32 },
    Svc,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instruction {
    pub condition: u32,
    pub flow: Flow,
}

impl Instruction {
    pub fn is_conditional(self) -> bool {
        self.condition != ALWAYS
    }
}

fn sign_extend_24(value: u32) -> i32 {
    ((value << 8) as i32) >> 8
}

pub fn decode(word: u32, address: u32) -> Instruction {
    let condition = word >> 28;
    let pc = address.wrapping_add(8);
    let rd = (word >> 12) & 0xF;
    let rn = (word >> 16) & 0xF;

    let flow = if condition == 0xF {
        // the unconditional space, only blx immediate matters here
        if word & 0x0E00_0000 == 0x0A00_0000 {
            let half = (word >> 24) & 1;
            let offset = (sign_extend_24(word & 0x00FF_FFFF) << 2) + (half << 1) as i32;
            Flow::BranchToThumb { target: pc.wrapping_add(offset as u32) }
        } else {
            Flow::Other
        }
    } else if word & 0x0E00_0000 == 0x0A00_0000 {
        let offset = sign_extend_24(word & 0x00FF_FFFF) << 2;
        Flow::Branch { target: pc.wrapping_add(offset as u32), link: word & (1 << 24) != 0 }
    } else if word & 0x0FFF_FFD0 == 0x012F_FF10 {
        let register = word & 0xF;
        let link = word & (1 << 5) != 0;
        if register == LR && !link {
            Flow::Return
        } else {
            Flow::BranchRegister { register, link }
        }
    } else if word & 0x0F00_0000 == 0x0F00_0000 {
        Flow::Svc
    } else if word & 0x0C00_0000 == 0x0400_0000 {
        single_transfer(word, pc, rd, rn)
    } else if word & 0x0E00_0000 == 0x0800_0000 {
        // ldm with pc in the list
        let load = word & (1 << 20) != 0;
        if load && word & (1 << 15) != 0 {
            if rn == SP { Flow::Return } else { Flow::IndirectJump }
        } else {
            Flow::Other
        }
    } else if word & 0x0F30_0E00 == 0x0D10_0A00 && rn == PC {
        // vldr from a literal
        let offset = (word & 0xFF) * 4;
        let literal = if word & (1 << 23) != 0 { (pc & !3) + offset } else { (pc & !3) - offset };
        let size = if word & (1 << 8) != 0 { 8 } else { 4 };
        Flow::LiteralLoad { literal, size }
    } else if word & 0x0C00_0000 == 0 {
        data_processing(word, rd, rn)
    } else {
        Flow::Other
    };
    Instruction { condition, flow }
}

/// ldr and str with a word or byte.
fn single_transfer(word: u32, pc: u32, rd: u32, rn: u32) -> Flow {
    let load = word & (1 << 20) != 0;
    let register_offset = word & (1 << 25) != 0;
    if !load {
        return Flow::Other;
    }
    if rn == PC && !register_offset && word & (1 << 24) != 0 {
        let offset = word & 0xFFF;
        let literal = if word & (1 << 23) != 0 { pc + offset } else { pc - offset };
        let size = if word & (1 << 22) != 0 { 1 } else { 4 };
        return if rd == PC {
            Flow::LoadPcLiteral { literal }
        } else {
            Flow::LiteralLoad { literal, size }
        };
    }
    if rd == PC {
        // ldr pc, [sp], 4 is a pop
        if rn == SP && word & (1 << 24) == 0 { Flow::Return } else { Flow::IndirectJump }
    } else {
        Flow::Other
    }
}

fn data_processing(word: u32, rd: u32, rn: u32) -> Flow {
    let immediate = word & (1 << 25) != 0;
    // multiplies and the extra loads and stores share this space
    if !immediate && word & 0x90 == 0x90 {
        return Flow::Other;
    }
    let opcode = (word >> 21) & 0xF;
    let sets_flags = word & (1 << 20) != 0;
    // tst teq cmp cmn write no register, and without s they are misc instructions
    if (8..=11).contains(&opcode) || rd != PC {
        return Flow::Other;
    }
    let rm = word & 0xF;
    let shift = (word >> 4) & 0xFF;
    match opcode {
        // mov pc, lr
        0xD if !immediate && rm == LR && shift == 0 => Flow::Return,
        // add pc, pc, rm lsl 2
        0x4 if !immediate && rn == PC && shift == 0x10 && !sets_flags => Flow::JumpTable,
        _ => Flow::IndirectJump,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 0x0010_0000;

    fn flow(word: u32) -> Flow {
        decode(word, BASE).flow
    }

    #[test]
    fn branches_and_calls() {
        assert_eq!(flow(0xEA00_0000), Flow::Branch { target: BASE + 8, link: false });
        assert_eq!(flow(0xEB00_0001), Flow::Branch { target: BASE + 12, link: true });
        assert_eq!(flow(0xEAFF_FFFE), Flow::Branch { target: BASE, link: false });
        assert_eq!(flow(0xFB00_0000), Flow::BranchToThumb { target: BASE + 10 });
    }

    #[test]
    fn returns() {
        assert_eq!(flow(0xE12F_FF1E), Flow::Return); // bx lr
        assert_eq!(flow(0xE8BD_8010), Flow::Return); // pop r4, pc
        assert_eq!(flow(0xE1A0_F00E), Flow::Return); // mov pc, lr
        assert_eq!(flow(0xE49D_F004), Flow::Return); // ldr pc, [sp], 4
    }

    #[test]
    fn indirect_flow() {
        assert_eq!(flow(0xE12F_FF33), Flow::BranchRegister { register: 3, link: true }); // blx r3
        assert_eq!(flow(0x908F_F100), Flow::JumpTable); // addls pc, pc, r0 lsl 2
        assert_eq!(flow(0xE593_F000), Flow::IndirectJump); // ldr pc, [r3]
    }

    #[test]
    fn literals() {
        assert_eq!(flow(0xE59F_0004), Flow::LiteralLoad { literal: BASE + 12, size: 4 });
        assert_eq!(flow(0xE59F_F000), Flow::LoadPcLiteral { literal: BASE + 8 });
        assert_eq!(flow(0xED9F_0A01), Flow::LiteralLoad { literal: BASE + 12, size: 4 }); // vldr s0
    }

    #[test]
    fn ordinary_instructions_do_not_change_flow() {
        assert_eq!(flow(0xE350_0005), Flow::Other); // cmp r0, 5
        assert_eq!(flow(0xE081_0002), Flow::Other); // add r0, r1, r2
        assert_eq!(flow(0xE000_0291), Flow::Other); // mul r0, r1, r2
        assert_eq!(flow(0xEF00_0032), Flow::Svc);
    }
}
