#include "x86/cpu32.hpp"

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
  std::uint32_t state = 0x4b45524eu;
  for (std::size_t iteration = 0; iteration < 20000; ++iteration) {
    const std::size_t length = 1 + next_random(state) % 64;
    kernex::x86::Cpu32 cpu(4096);
    cpu.code.resize(length);
    for (auto& byte : cpu.code) byte = static_cast<std::uint8_t>(next_random(state));
    cpu.code_base = 0x100000u;
    cpu.memory_base = 0x100000u;
    cpu.eip = cpu.code_base;
    cpu.regs[4] = cpu.memory_base + 4092;
    // Invalid, unsupported, and out-of-range programs must fail closed;
    // bounded execution prevents random branches from hanging the harness.
    (void)cpu.run(128);
    if (cpu.error.empty() && !cpu.halted &&
        !(cpu.stop_address_enabled && cpu.eip == cpu.stop_address)) {
      std::cerr << "random program ended without an explicit result at case "
                << iteration << "\n";
      return 1;
    }
  }
  std::cout << "x86 CPU deterministic execution stress passed\n";
  return 0;
}
