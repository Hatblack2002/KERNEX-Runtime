#include <cstdint>
#include <iostream>

int main() {
  // Explicit checks remain active in Release builds (unlike assert/NDEBUG).
  const std::uint32_t a = 0x12345678u;
  const std::uint32_t b = 0x01010101u;
  if (static_cast<std::uint32_t>(a + b) != 0x13355779u) {
    std::cerr << "addition smoke check failed\n";
    return 1;
  }
  if ((0u & 0xffu) != 0u) {
    std::cerr << "bitwise smoke check failed\n";
    return 1;
  }
  std::cout << "KERNEX scaffold smoke test passed\n";
  return 0;
}