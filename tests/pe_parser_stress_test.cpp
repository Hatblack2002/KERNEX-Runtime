#include "pe/pe_image.hpp"

#include <cstdint>
#include <iostream>
#include <vector>

static void put16(std::vector<std::uint8_t>& b, std::size_t o, std::uint16_t v) {
  b[o] = static_cast<std::uint8_t>(v);
  b[o + 1] = static_cast<std::uint8_t>(v >> 8);
}
static void put32(std::vector<std::uint8_t>& b, std::size_t o, std::uint32_t v) {
  for (unsigned i = 0; i < 4; ++i) b[o + i] = static_cast<std::uint8_t>(v >> (8 * i));
}
static std::uint32_t next_random(std::uint32_t& state) {
  state ^= state << 13;
  state ^= state >> 17;
  state ^= state << 5;
  return state;
}
static std::vector<std::uint8_t> valid_pe32() {
  std::vector<std::uint8_t> b(0x400, 0);
  put16(b, 0, 0x5a4d); put32(b, 0x3c, 0x80); put32(b, 0x80, 0x4550);
  put16(b, 0x84, 0x14c); put16(b, 0x86, 1); put16(b, 0x94, 224);
  const std::size_t o = 0x98;
  put16(b, o, 0x10b); put32(b, o + 16, 0x1000); put32(b, o + 28, 0x400000);
  put32(b, o + 32, 0x1000); put32(b, o + 36, 0x200);
  put32(b, o + 56, 0x2000); put32(b, o + 60, 0x200);
  const std::size_t s = o + 224;
  b[s] = '.'; b[s + 1] = 't'; b[s + 2] = 'e'; b[s + 3] = 'x'; b[s + 4] = 't';
  put32(b, s + 8, 0x100); put32(b, s + 12, 0x1000);
  put32(b, s + 16, 0x200); put32(b, s + 20, 0x200);
  put32(b, s + 36, 0x60000020);
  return b;
}
int main() {
  std::uint32_t state = 0x5045465au;
  const auto baseline = valid_pe32();
  std::size_t accepted_mutations = 0;

  // Test every truncation point of a valid fixture.
  for (std::size_t size = 0; size < baseline.size(); ++size) {
    std::vector<std::uint8_t> truncated(baseline.begin(), baseline.begin() + size);
    (void)kernex::pe::parse(truncated);
  }

  // Mutate valid headers and section data in a reproducible way.
  for (std::size_t iteration = 0; iteration < 20000; ++iteration) {
    auto bytes = baseline;
    const unsigned mutations = 1 + next_random(state) % 8;
    for (unsigned i = 0; i < mutations; ++i) {
      const std::size_t at = next_random(state) % bytes.size();
      bytes[at] = static_cast<std::uint8_t>(next_random(state));
    }
    const auto parsed = kernex::pe::parse(bytes);
    if (parsed.ok) {
      ++accepted_mutations;
      for (unsigned probe = 0; probe < 8; ++probe) {
        const auto rva = next_random(state);
        const auto length = next_random(state) % 32;
        std::size_t file_offset = 0;
        if (kernex::pe::rva_to_file_offset(parsed.image, bytes.size(), rva,
                                           length, file_offset) &&
            (file_offset > bytes.size() || length > bytes.size() - file_offset)) {
          std::cerr << "RVA mapping escaped file bounds at iteration " << iteration << "\n";
          return 1;
        }
      }
    }
  }

  // Random input sizes exercise early-return paths for arbitrary malformed files.
  for (std::size_t iteration = 0; iteration < 20000; ++iteration) {
    const std::size_t size = next_random(state) % 1025;
    std::vector<std::uint8_t> bytes(size);
    for (auto& byte : bytes) byte = static_cast<std::uint8_t>(next_random(state));
    (void)kernex::pe::parse(bytes);
  }

  std::cout << "PE parser stress tests passed (40000 mutations/random files; "
            << baseline.size() << " truncation lengths; accepted mutations="
            << accepted_mutations << ")\n";
  return 0;
}
