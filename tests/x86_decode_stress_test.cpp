#include "x86/decode32.hpp"

#include <cstdint>
#include <iostream>
#include <vector>

static std::uint32_t next_random(std::uint32_t& state) {
  state ^= state << 13;
  state ^= state >> 17;
  state ^= state << 5;
  return state;
}

int main() {
  using kernex::x86::Op;
  // Every opcode byte is checked with every short buffer length.
  for (unsigned opcode = 0; opcode < 256; ++opcode) {
    for (std::size_t size = 0; size <= 8; ++size) {
      std::vector<std::uint8_t> bytes(size, 0xa5);
      if (!bytes.empty()) bytes[0] = static_cast<std::uint8_t>(opcode);
      const auto ins = kernex::x86::decode32(bytes);
      if (ins.op != Op::invalid && (ins.length == 0 || ins.length > size)) {
        std::cerr << "invalid decoded length for opcode " << opcode
                  << " and size " << size << "\n";
        return 1;
      }
    }
  }

  // Deterministic stress pass: malformed and random byte streams must never
  // produce a decoded instruction extending beyond the supplied buffer.
  std::uint32_t state = 0x4b45524eu;
  for (std::size_t iteration = 0; iteration < 100000; ++iteration) {
    const std::size_t size = next_random(state) % 16;
    std::vector<std::uint8_t> bytes(size);
    for (auto& byte : bytes) byte = static_cast<std::uint8_t>(next_random(state));
    const auto ins = kernex::x86::decode32(bytes);
    if (ins.op != Op::invalid && (ins.length == 0 || ins.length > bytes.size())) {
      std::cerr << "decoder bounds invariant failed at iteration " << iteration << "\n";
      return 2;
    }
    if (ins.op == Op::invalid && ins.error.empty()) {
      std::cerr << "invalid instruction did not report an error\n";
      return 3;
    }
  }
  std::cout << "x86 decoder stress tests passed (102304 cases)\n";
  return 0;
}
