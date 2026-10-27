#pragma once

#include "x86/decode32.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace kernex::x86 {

struct Cpu32 {
  // Register order: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI.
  std::uint32_t regs[8]{};
  std::uint32_t eip{};
  std::uint32_t eflags{0x2};
  std::uint32_t code_base{};
  std::uint32_t memory_base{};
  std::uint32_t stop_address{};
  bool stop_address_enabled{};
  std::vector<std::uint8_t> code;
  std::vector<std::uint8_t> memory;
  bool halted{};
  std::string error;

  explicit Cpu32(std::size_t memory_size = 1024 * 1024) : memory(memory_size, 0) {
    regs[4] = static_cast<std::uint32_t>(memory_size);
  }

  bool read32(std::uint32_t address, std::uint32_t& value) const {
    if (address < memory_base) return false;
    const std::uint64_t rel = static_cast<std::uint64_t>(address) - memory_base;
    if (rel > memory.size() || 4 > memory.size() - static_cast<std::size_t>(rel)) return false;
    const std::size_t at = static_cast<std::size_t>(rel);
    value = static_cast<std::uint32_t>(memory[at]) |
            (static_cast<std::uint32_t>(memory[at + 1]) << 8) |
            (static_cast<std::uint32_t>(memory[at + 2]) << 16) |
            (static_cast<std::uint32_t>(memory[at + 3]) << 24);
    return true;
  }

  bool write32(std::uint32_t address, std::uint32_t value) {
    if (address < memory_base) return false;
    const std::uint64_t rel = static_cast<std::uint64_t>(address) - memory_base;
    if (rel > memory.size() || 4 > memory.size() - static_cast<std::size_t>(rel)) return false;
    const std::size_t at = static_cast<std::size_t>(rel);
    for (unsigned i = 0; i < 4; ++i)
      memory[at + i] = static_cast<std::uint8_t>(value >> (i * 8));
    return true;
  }

  bool effective_address(const Instruction& ins, std::uint32_t& address) const {
    if (!ins.has_modrm || !ins.memory_operand) return false;
    std::uint32_t base = 0;
    if (ins.has_sib) {
      if (!(ins.mod == 0 && ins.sib_base == 5)) base = regs[ins.sib_base];
      if (ins.sib_index != 4)
        base += regs[ins.sib_index] << ins.sib_scale;
    } else if (!(ins.mod == 0 && ins.rm == 5)) {
      base = regs[ins.rm];
    }
    address = base + static_cast<std::uint32_t>(ins.displacement);
    return true;
  }

  bool read_operand(const Instruction& ins, std::uint32_t& value) const {
    if (!ins.memory_operand) { value = regs[ins.rm]; return true; }
    std::uint32_t address{};
    return effective_address(ins, address) && read32(address, value);
  }

  bool write_operand(const Instruction& ins, std::uint32_t value) {
    if (!ins.memory_operand) { regs[ins.rm] = value; return true; }
    std::uint32_t address{};
    return effective_address(ins, address) && write32(address, value);
  }

  void set_logic_flags(std::uint32_t value) {
    eflags &= ~std::uint32_t{0x8d5}; // CF, PF, AF, ZF, SF, OF
    if (value == 0) eflags |= 0x40;
    if (value & 0x80000000u) eflags |= 0x80;
    unsigned parity = 0;
    for (unsigned i = 0; i < 8; ++i) parity += (value >> i) & 1u;
    if ((parity & 1u) == 0) eflags |= 0x4;
  }

  void set_add_flags(std::uint32_t a, std::uint32_t b, std::uint32_t value) {
    set_logic_flags(value);
    if (static_cast<std::uint64_t>(a) + b > UINT32_MAX) eflags |= 0x1;
    if ((~(a ^ b) & (a ^ value) & 0x80000000u) != 0) eflags |= 0x800;
  }

  void set_sub_flags(std::uint32_t a, std::uint32_t b, std::uint32_t value) {
    set_logic_flags(value);
    if (a < b) eflags |= 0x1;
    if (((a ^ b) & (a ^ value) & 0x80000000u) != 0) eflags |= 0x800;
  }

  bool condition(std::uint8_t cc) const {
    const bool cf = (eflags & 0x001) != 0;
    const bool pf = (eflags & 0x004) != 0;
    const bool zf = (eflags & 0x040) != 0;
    const bool sf = (eflags & 0x080) != 0;
    const bool of = (eflags & 0x800) != 0;
    switch (cc) {
      case 0: return of; case 1: return !of;
      case 2: return cf; case 3: return !cf;
      case 4: return zf; case 5: return !zf;
      case 6: return cf || zf; case 7: return !cf && !zf;
      case 8: return sf; case 9: return !sf;
      case 10: return pf; case 11: return !pf;
      case 12: return sf != of; case 13: return sf == of;
      case 14: return zf || (sf != of); case 15: return !zf && (sf == of);
      default: return false;
    }
  }

  bool step() {
    if (halted) return false;
    if (eip < code_base) { error = "instruction pointer below code base"; return false; }
    const std::uint64_t rel = static_cast<std::uint64_t>(eip) - code_base;
    if (rel >= code.size()) { error = "instruction pointer outside code"; return false; }
    const auto ins = decode32(code, static_cast<std::size_t>(rel));
    if (ins.op == Op::invalid) { error = ins.error; return false; }
    const std::uint32_t next = eip + ins.length;
    switch (ins.op) {
      case Op::nop: eip = next; return true;
      case Op::int3: error = "INT3 breakpoint"; halted = true; return false;
      case Op::push_imm32: {
        if (regs[4] < memory_base + 4u) { error = "stack underflow"; return false; }
        const std::uint32_t sp = regs[4] - 4;
        if (!write32(sp, ins.immediate)) { error = "stack write outside memory"; return false; }
        regs[4] = sp; eip = next; return true;
      }
      case Op::leave: {
        std::uint32_t value{};
        if (!read32(regs[5], value)) { error = "frame read outside memory"; return false; }
        const std::uint32_t new_sp = regs[5] + 4;
        regs[5] = value; regs[4] = new_sp; eip = next; return true;
      }
      case Op::mov_reg_imm32: regs[ins.reg] = ins.immediate; eip = next; return true;
      case Op::push_reg: {
        if (regs[4] < 4) { error = "stack underflow"; return false; }
        const std::uint32_t sp = regs[4] - 4;
        if (!write32(sp, regs[ins.reg])) { error = "stack write outside memory"; return false; }
        regs[4] = sp; eip = next; return true;
      }
      case Op::pop_reg: {
        std::uint32_t value{};
        if (!read32(regs[4], value)) { error = "stack read outside memory"; return false; }
        // POP ESP is special: the popped value becomes ESP; the
        // implicit stack increment must not overwrite it.
        if (ins.reg == 4) regs[4] = value;
        else { regs[ins.reg] = value; regs[4] += 4; }
        eip = next; return true;
      }
      case Op::call_rel32: {
        if (regs[4] < 4) { error = "stack underflow"; return false; }
        const std::uint32_t sp = regs[4] - 4;
        if (!write32(sp, next)) { error = "stack write outside memory"; return false; }
        regs[4] = sp; eip = next + static_cast<std::uint32_t>(ins.displacement); return true;
      }
      case Op::jmp_rel32: case Op::jmp_rel8:
        eip = next + static_cast<std::uint32_t>(ins.displacement); return true;
      case Op::jcc_rel8:
        eip = condition(ins.condition) ? next + static_cast<std::uint32_t>(ins.displacement) : next;
        return true;
      case Op::ret: {
        std::uint32_t target{};
        if (!read32(regs[4], target)) { error = "return address outside memory"; return false; }
        regs[4] += 4; eip = target; return true;
      }
      case Op::mov_rm32_r32: {
        if (!write_operand(ins, regs[ins.reg])) { error = "MOV destination outside memory"; return false; }
        eip = next; return true;
      }
      case Op::mov_r32_rm32: {
        std::uint32_t value{};
        if (!read_operand(ins, value)) { error = "MOV source outside memory"; return false; }
        regs[ins.reg] = value; eip = next; return true;
      }
      case Op::add_rm32_r32: case Op::sub_rm32_r32: case Op::xor_rm32_r32:
      case Op::cmp_rm32_r32: case Op::test_rm32_r32: {
        std::uint32_t lhs{};
        if (!read_operand(ins, lhs)) { error = "ALU source outside memory"; return false; }
        const std::uint32_t rhs = regs[ins.reg];
        std::uint32_t value{};
        if (ins.op == Op::add_rm32_r32) { value = lhs + rhs; set_add_flags(lhs, rhs, value); }
        else if (ins.op == Op::sub_rm32_r32 || ins.op == Op::cmp_rm32_r32) { value = lhs - rhs; set_sub_flags(lhs, rhs, value); }
        else { value = lhs ^ rhs; set_logic_flags(value); }
        if (ins.op != Op::cmp_rm32_r32 && ins.op != Op::test_rm32_r32 &&
            !write_operand(ins, value)) { error = "ALU destination outside memory"; return false; }
        eip = next; return true;
      }
      case Op::add_r32_rm32: case Op::sub_r32_rm32: case Op::xor_r32_rm32:
      case Op::cmp_r32_rm32: {
        std::uint32_t rhs{};
        if (!read_operand(ins, rhs)) { error = "ALU source outside memory"; return false; }
        const std::uint32_t lhs = regs[ins.reg];
        std::uint32_t value{};
        if (ins.op == Op::add_r32_rm32) { value = lhs + rhs; set_add_flags(lhs, rhs, value); }
        else if (ins.op == Op::sub_r32_rm32 || ins.op == Op::cmp_r32_rm32) { value = lhs - rhs; set_sub_flags(lhs, rhs, value); }
        else { value = lhs ^ rhs; set_logic_flags(value); }
        if (ins.op != Op::cmp_r32_rm32) regs[ins.reg] = value;
        eip = next; return true;
      }
      case Op::add_eax_imm32: {
        const std::uint32_t lhs = regs[0], value = lhs + ins.immediate;
        regs[0] = value; set_add_flags(lhs, ins.immediate, value); eip = next; return true;
      }
      case Op::sub_eax_imm32: case Op::cmp_eax_imm32: {
        const std::uint32_t lhs = regs[0], value = lhs - ins.immediate;
        if (ins.op == Op::sub_eax_imm32) regs[0] = value;
        set_sub_flags(lhs, ins.immediate, value); eip = next; return true;
      }
      case Op::invalid: break;
    }
    error = "unsupported instruction";
    return false;
  }

  bool run(std::size_t instruction_budget = 100000) {
    if (stop_address_enabled && eip == stop_address) return true;
    for (std::size_t i = 0; i < instruction_budget; ++i) {
      if (halted) { if (error.empty()) error = "CPU halted without explicit exit"; return false; }
      if (stop_address_enabled && eip == stop_address) return true;
      if (eip < code_base || static_cast<std::uint64_t>(eip) - code_base >= code.size()) {
        error = "execution left code without reaching configured exit address";
        return false;
      }
      if (!step()) return false;
    }
    error = "instruction budget exhausted";
    return false;
  }
};

} // namespace kernex::x86
