#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace kernex::x86 {

enum class Op : std::uint8_t {
  invalid, nop, ret, int3, push_reg, pop_reg, push_imm32, leave, mov_reg_imm32,
  call_rel32, jmp_rel32, jmp_rel8, jcc_rel8
};

struct Instruction {
  Op op{Op::invalid};
  std::uint8_t length{};
  std::uint8_t reg{};
  std::uint8_t condition{};
  std::uint32_t immediate{};
  std::int32_t displacement{};
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
