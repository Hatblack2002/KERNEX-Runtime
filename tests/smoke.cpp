#include <cassert>
#include <cstdint>
#include <iostream>

int main() {
  // Basic test harness sanity check. This is not an x86 semantic test.
  const std::uint32_t a = 0x12345678u;
  const std::uint32_t b = 0x01010101u;
  assert(static_cast<std::uint32_t>(a + b) == 0x13355779u);
  assert((0u & 0xffu) == 0u);
  std::cout << "KERNEX scaffold smoke test passed\n";
  return 0;
}