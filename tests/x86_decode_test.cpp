#include "x86/decode32.hpp"
#include <iostream>
#include <vector>
int main() {
  const std::vector<std::uint8_t> code{0xb8,0x78,0x56,0x34,0x12};
  const auto ins = kernex::x86::decode32(code);
  if (ins.op != kernex::x86::Op::mov_reg_imm32 || ins.immediate != 0x12345678u || ins.length != 5) return 1;
  const std::vector<std::uint8_t> bad{0xb8,0x01};
  if (kernex::x86::decode32(bad).op != kernex::x86::Op::invalid) return 2;
  std::cout << "decoder smoke passed\n";
  return 0;
}
