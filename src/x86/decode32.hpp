#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace kernex::x86 {

enum class Op : std::uint8_t {
  invalid, nop, ret, int3, push_reg, pop_reg, push_imm32, leave, mov_reg_imm32,
  call_rel32, jmp_rel32, jmp_rel8, jcc_rel8,
  mov_rm32_r32, mov_r32_rm32, add_rm32_r32, add_r32_rm32,
  sub_rm32_r32, sub_r32_rm32, xor_rm32_r32, xor_r32_rm32,
  cmp_rm32_r32, cmp_r32_rm32, test_rm32_r32, test_r32_rm32,
  add_eax_imm32, sub_eax_imm32, cmp_eax_imm32, push_imm8, jcc_rel32
};

struct Instruction {
  Op op{Op::invalid};
  std::uint8_t length{};
  std::uint8_t reg{};
  std::uint8_t condition{};
  std::uint32_t immediate{};
  std::int32_t displacement{};
  std::uint8_t mod{};
  std::uint8_t rm{};
  bool has_modrm{};
  bool memory_operand{};
  std::uint8_t sib_scale{};
  std::uint8_t sib_index{4};
  std::uint8_t sib_base{5};
  bool has_sib{};
  std::string error;
};

inline Instruction decode32(const std::uint8_t* bytes, std::size_t size) {
  Instruction out;
  if (size == 0 || bytes == nullptr) {
    out.error = "empty instruction input";
    return out;
  }
  const std::uint8_t op = bytes[0];
  if (op == 0x90) { out.op = Op::nop; out.length = 1; return out; }
  if (op == 0xc3) { out.op = Op::ret; out.length = 1; return out; }
  if (op == 0xcc) { out.op = Op::int3; out.length = 1; return out; }
  if (op == 0xc9) { out.op = Op::leave; out.length = 1; return out; }
  if (op == 0x6a) {
    if (size < 2) { out.error = "truncated push imm8"; return out; }
    out.op = Op::push_imm8; out.length = 2;
    const std::int32_t value = bytes[1] < 0x80 ? bytes[1] : static_cast<std::int32_t>(bytes[1]) - 256;
    out.immediate = static_cast<std::uint32_t>(value);
    return out;
  }
  if (op == 0x68) {
    if (size < 5) { out.error = "truncated push imm32"; return out; }
    out.op = Op::push_imm32; out.length = 5;
    out.immediate = static_cast<std::uint32_t>(bytes[1]) |
                    (static_cast<std::uint32_t>(bytes[2]) << 8) |
                    (static_cast<std::uint32_t>(bytes[3]) << 16) |
                    (static_cast<std::uint32_t>(bytes[4]) << 24);
    return out;
  }
  if (op >= 0x50 && op <= 0x57) {
    out.op = Op::push_reg; out.reg = op - 0x50; out.length = 1; return out;
  }
  if (op >= 0x58 && op <= 0x5f) {
    out.op = Op::pop_reg; out.reg = op - 0x58; out.length = 1; return out;
  }
  if (op >= 0xb8 && op <= 0xbf) {
    if (size < 5) { out.error = "truncated mov reg, imm32"; return out; }
    out.op = Op::mov_reg_imm32; out.reg = op - 0xb8; out.length = 5;
    out.immediate = static_cast<std::uint32_t>(bytes[1]) |
                    (static_cast<std::uint32_t>(bytes[2]) << 8) |
                    (static_cast<std::uint32_t>(bytes[3]) << 16) |
                    (static_cast<std::uint32_t>(bytes[4]) << 24);
    return out;
  }
  // Common 32-bit integer operations. Decode ModRM/SIB and signed
  // displacement without reading beyond the provided instruction window.
  if (op == 0x89 || op == 0x8b || op == 0x01 || op == 0x03 ||
      op == 0x29 || op == 0x2b || op == 0x31 || op == 0x33 ||
      op == 0x39 || op == 0x3b || op == 0x85) {
    if (size < 2) { out.error = "truncated ModRM instruction"; return out; }
    const std::uint8_t m = bytes[1];
    out.mod = m >> 6; out.reg = (m >> 3) & 7; out.rm = m & 7;
    out.has_modrm = true; out.memory_operand = out.mod != 3;
    std::size_t at = 2;
    if (out.mod != 3 && out.rm == 4) {
      if (size < at + 1) { out.error = "truncated SIB byte"; return out; }
      const std::uint8_t sib = bytes[at++];
      out.has_sib = true; out.sib_scale = sib >> 6;
      out.sib_index = (sib >> 3) & 7; out.sib_base = sib & 7;
      if (out.mod == 0 && out.sib_base == 5) {
        if (size < at + 4) { out.error = "truncated SIB displacement"; return out; }
        const std::uint32_t d = static_cast<std::uint32_t>(bytes[at]) |
          (static_cast<std::uint32_t>(bytes[at+1]) << 8) |
          (static_cast<std::uint32_t>(bytes[at+2]) << 16) |
          (static_cast<std::uint32_t>(bytes[at+3]) << 24);
        out.displacement = static_cast<std::int32_t>(d); at += 4;
      }
    } else if (out.mod == 0 && out.rm == 5) {
      if (size < at + 4) { out.error = "truncated disp32"; return out; }
      const std::uint32_t d = static_cast<std::uint32_t>(bytes[at]) |
        (static_cast<std::uint32_t>(bytes[at+1]) << 8) |
        (static_cast<std::uint32_t>(bytes[at+2]) << 16) |
        (static_cast<std::uint32_t>(bytes[at+3]) << 24);
      out.displacement = static_cast<std::int32_t>(d); at += 4;
    }
    if (out.mod == 1) {
      if (size < at + 1) { out.error = "truncated disp8"; return out; }
      out.displacement += bytes[at] < 0x80 ? bytes[at] : static_cast<std::int32_t>(bytes[at]) - 256;
      ++at;
    } else if (out.mod == 2) {
      if (size < at + 4) { out.error = "truncated disp32"; return out; }
      const std::uint32_t d = static_cast<std::uint32_t>(bytes[at]) |
        (static_cast<std::uint32_t>(bytes[at+1]) << 8) |
        (static_cast<std::uint32_t>(bytes[at+2]) << 16) |
        (static_cast<std::uint32_t>(bytes[at+3]) << 24);
      out.displacement = static_cast<std::int32_t>(d); at += 4;
    }
    out.length = static_cast<std::uint8_t>(at);
    switch (op) {
      case 0x89: out.op = Op::mov_rm32_r32; break;
      case 0x8b: out.op = Op::mov_r32_rm32; break;
      case 0x01: out.op = Op::add_rm32_r32; break;
      case 0x03: out.op = Op::add_r32_rm32; break;
      case 0x29: out.op = Op::sub_rm32_r32; break;
      case 0x2b: out.op = Op::sub_r32_rm32; break;
      case 0x31: out.op = Op::xor_rm32_r32; break;
      case 0x33: out.op = Op::xor_r32_rm32; break;
      case 0x39: out.op = Op::cmp_rm32_r32; break;
      case 0x3b: out.op = Op::cmp_r32_rm32; break;
      default: out.op = Op::test_rm32_r32; break;
    }
    return out;
  }
  if (op == 0x05 || op == 0x2d || op == 0x3d) {
    if (size < 5) { out.error = "truncated accumulator immediate"; return out; }
    out.op = op == 0x05 ? Op::add_eax_imm32 : (op == 0x2d ? Op::sub_eax_imm32 : Op::cmp_eax_imm32);
    out.length = 5;
    out.immediate = static_cast<std::uint32_t>(bytes[1]) |
      (static_cast<std::uint32_t>(bytes[2]) << 8) |
      (static_cast<std::uint32_t>(bytes[3]) << 16) |
      (static_cast<std::uint32_t>(bytes[4]) << 24);
    return out;
  }
  if (op == 0x0f) {
    if (size < 2) { out.error = "truncated two-byte opcode"; return out; }
    if (bytes[1] >= 0x80 && bytes[1] <= 0x8f) {
      if (size < 6) { out.error = "truncated near conditional branch"; return out; }
      const std::uint32_t raw = static_cast<std::uint32_t>(bytes[2]) |
        (static_cast<std::uint32_t>(bytes[3]) << 8) |
        (static_cast<std::uint32_t>(bytes[4]) << 16) |
        (static_cast<std::uint32_t>(bytes[5]) << 24);
      out.op = Op::jcc_rel32; out.condition = bytes[1] & 0x0f;
      out.displacement = static_cast<std::int32_t>(raw); out.length = 6;
      return out;
    }
    out.error = "unsupported two-byte x86 opcode";
    return out;
  }
  if (op == 0xe8 || op == 0xe9) {
    if (size < 5) { out.error = "truncated rel32 branch"; return out; }
    out.op = op == 0xe8 ? Op::call_rel32 : Op::jmp_rel32;
    out.length = 5;
    const std::uint32_t raw = static_cast<std::uint32_t>(bytes[1]) |
                              (static_cast<std::uint32_t>(bytes[2]) << 8) |
                              (static_cast<std::uint32_t>(bytes[3]) << 16) |
                              (static_cast<std::uint32_t>(bytes[4]) << 24);
    out.displacement = static_cast<std::int32_t>(raw);
    return out;
  }
  if (op == 0xeb || (op >= 0x70 && op <= 0x7f)) {
    if (size < 2) { out.error = "truncated rel8 branch"; return out; }
    out.op = op == 0xeb ? Op::jmp_rel8 : Op::jcc_rel8;
    out.length = 2;
    out.displacement = bytes[1] < 0x80 ? static_cast<std::int32_t>(bytes[1])
                                             : static_cast<std::int32_t>(bytes[1]) - 256;
    if (out.op == Op::jcc_rel8) out.condition = op & 0x0f;
    return out;
  }
  out.error = "unsupported opcode in x86-32 baseline";
  return out;
}

inline Instruction decode32(const std::vector<std::uint8_t>& bytes, std::size_t offset = 0) {
  if (offset >= bytes.size()) {
    Instruction out; out.error = "instruction offset outside buffer"; return out;
  }
  return decode32(bytes.data() + offset, bytes.size() - offset);
}

} // namespace kernex::x86
