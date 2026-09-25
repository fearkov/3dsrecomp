//! just enough Thumb decoding to follow control flow. the ARM11 is ARMv6K,
//! so this is Thumb-1, where only the bl and blx pairs take 32 bits.

use crate::arm::{Flow, Instruction, ALWAYS};

const LR: u16 = 14;

fn sign_extend(value: u32, bits: u32) -> i32 {
    ((value << (32 - bits)) as i32) >> (32 - bits)
}

/// decodes the instruction at address, returning it and its size in bytes.
/// next is the following halfword, which only the bl and blx pairs read.
pub fn decode(halfword: u16, next: Option<u16>, address: u32) -> (Instruction, u32) {
    let pc = address.wrapping_add(4);
    let always = |flow| Instruction { condition: ALWAYS, flow };
    let word = halfword as u32;

    match halfword >> 11 {
        // conditional branch, with svc and undefined in the last two conditions
        0b11010 | 0b11011 => {
            let condition = (word >> 8) & 0xF;
            let flow = match condition {
                0xF => Flow::Svc,
                0xE => Flow::Undefined,
                _ => Flow::Branch { target: pc.wrapping_add((sign_extend(word & 0xFF, 8) << 1) as u32), link: false },
            };
            (Instruction { condition, flow }, 2)
        }
        0b11100 => {
            let target = pc.wrapping_add((sign_extend(word & 0x7FF, 11) << 1) as u32);
            (always(Flow::Branch { target, link: false }), 2)
        }
        // the first half of bl or blx carries the upper offset
        0b11110 => {
            let high = sign_extend(word & 0x7FF, 11) << 12;
            let Some(second) = next else { return (always(Flow::Undefined), 2) };
            let low = ((second & 0x7FF) as i32) << 1;
            let target = pc.wrapping_add((high + low) as u32);
            match second >> 11 {
                0b11111 => (always(Flow::Branch { target, link: true }), 4),
                0b11101 => (always(Flow::CallOtherMode { target: target & !3 }), 4),
                _ => (always(Flow::Undefined), 2),
            }
        }
        // a lone second half means the decoding lost track
        0b11111 | 0b11101 => (always(Flow::Undefined), 2),
        // ldr rd, [pc, imm]
        0b01001 => {
            let literal = (pc & !3) + (word & 0xFF) * 4;
            (always(Flow::LiteralLoad { literal, size: 4 }), 2)
        }
        _ => (always(other(halfword)), 2),
    }
}

fn other(halfword: u16) -> Flow {
    // pop with pc
    if halfword & 0xFF00 == 0xBD00 {
        return Flow::Return;
    }
    // bx and blx through a register
    if halfword & 0xFF07 == 0x4700 {
        let register = ((halfword >> 3) & 0xF) as u32;
        let link = halfword & 0x80 != 0;
        return if register as u16 == LR && !link {
            Flow::Return
        } else {
            Flow::BranchRegister { register, link }
        };
    }
    // mov and add on high registers with pc as the destination
    if halfword & 0xFC87 == 0x4487 {
        let source = (halfword >> 3) & 0xF;
        let mov = halfword & 0x0300 == 0x0200;
        return if mov && source == LR { Flow::Return } else { Flow::IndirectJump };
    }
    Flow::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 0x0010_0000;

    fn flow(halfword: u16) -> Flow {
        decode(halfword, None, BASE).0.flow
    }

    #[test]
    fn branches() {
        assert_eq!(flow(0xE7FE), Flow::Branch { target: BASE, link: false }); // b .
        assert_eq!(flow(0xD001), Flow::Branch { target: BASE + 6, link: false }); // beq
        assert_eq!(decode(0xD001, None, BASE).0.condition, 0);
        assert_eq!(flow(0xDF01), Flow::Svc);
    }

    #[test]
    fn calls_take_two_halfwords() {
        // bl to BASE + 0x1000
        let (instruction, size) = decode(0xF000, Some(0xFFFE), BASE);
        assert_eq!(instruction.flow, Flow::Branch { target: BASE + 0x1000, link: true });
        assert_eq!(size, 4);
        // blx to ARM code, aligned down
        let (instruction, _) = decode(0xF000, Some(0xE802), BASE);
        assert_eq!(instruction.flow, Flow::CallOtherMode { target: BASE + 8 });
    }

    #[test]
    fn returns_and_indirect_jumps() {
        assert_eq!(flow(0x4770), Flow::Return); // bx lr
        assert_eq!(flow(0xBD10), Flow::Return); // pop r4, pc
        assert_eq!(flow(0x46F7), Flow::Return); // mov pc, lr
        assert_eq!(flow(0x4798), Flow::BranchRegister { register: 3, link: true }); // blx r3
        assert_eq!(flow(0x4487), Flow::IndirectJump); // add pc, r0
    }

    #[test]
    fn literals_are_word_aligned() {
        // ldr r0, [pc, 4] at BASE + 2 reads BASE + 8
        let (instruction, _) = decode(0x4801, None, BASE + 2);
        assert_eq!(instruction.flow, Flow::LiteralLoad { literal: BASE + 8, size: 4 });
    }
}
