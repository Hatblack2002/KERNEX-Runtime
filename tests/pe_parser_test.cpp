#include "pe/pe_image.hpp"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

static void put16(std::vector<std::uint8_t>& b, std::size_t o, std::uint16_t v) {
  b.at(o) = static_cast<std::uint8_t>(v);
  b.at(o + 1) = static_cast<std::uint8_t>(v >> 8);
}
static void put32(std::vector<std::uint8_t>& b, std::size_t o, std::uint32_t v) {
  for (unsigned i = 0; i < 4; ++i) b.at(o + i) = static_cast<std::uint8_t>(v >> (8 * i));
}
static std::vector<std::uint8_t> make_pe32() {
  std::vector<std::uint8_t> b(0x400, 0);
  put16(b, 0, 0x5a4d);
  put32(b, 0x3c, 0x80);
  put32(b, 0x80, 0x00004550);
  put16(b, 0x84, 0x014c);
  put16(b, 0x86, 1);
  put16(b, 0x94, 224);
  put16(b, 0x96, 0x0102);
  const std::size_t o = 0x98;
  put16(b, o, 0x10b);
  put32(b, o + 16, 0x1000);
  put32(b, o + 28, 0x00400000);
  put32(b, o + 32, 0x1000);
  put32(b, o + 36, 0x200);
  put32(b, o + 56, 0x2000);
  put32(b, o + 60, 0x200);
  const std::size_t s = o + 224;
  const char name[] = ".text";
  for (std::size_t i = 0; i < sizeof(name) - 1; ++i) b[s + i] = static_cast<std::uint8_t>(name[i]);
  put32(b, s + 8, 0x10);
  put32(b, s + 12, 0x1000);
  put32(b, s + 16, 0x200);
  put32(b, s + 20, 0x200);
  put32(b, s + 36, 0x60000020);
  return b;
}
static std::vector<std::uint8_t> make_pe32_plus() {
  std::vector<std::uint8_t> b(0x400, 0);
  put16(b, 0, 0x5a4d);
  put32(b, 0x3c, 0x80);
  put32(b, 0x80, 0x00004550);
  put16(b, 0x84, 0x8664);
  put16(b, 0x86, 1);
  put16(b, 0x94, 240);
  put16(b, 0x96, 0x0022);
  const std::size_t o = 0x98;
  put16(b, o, 0x20b);
  put32(b, o + 16, 0x1000);
  // ImageBase = 0x0000000140000000
  put32(b, o + 24, 0x40000000);
  put32(b, o + 28, 0x00000001);
  put32(b, o + 32, 0x1000);
  put32(b, o + 36, 0x200);
  put32(b, o + 56, 0x2000);
  put32(b, o + 60, 0x200);
  const std::size_t s = o + 240;
  const char name[] = ".text";
  for (std::size_t i = 0; i < sizeof(name) - 1; ++i) b[s + i] = static_cast<std::uint8_t>(name[i]);
  put32(b, s + 8, 0x10);
  put32(b, s + 12, 0x1000);
  put32(b, s + 16, 0x200);
  put32(b, s + 20, 0x200);
  put32(b, s + 36, 0x60000020);
  return b;
}
static bool check(bool condition, const char* message) {
  if (!condition) std::cerr << "FAIL: " << message << "\n";
  return condition;
}
int main() {
  bool ok = true;
  auto bytes = make_pe32();
  auto parsed = kernex::pe::parse(bytes);
  ok &= check(parsed.ok, "synthetic PE32 parses");
  if (parsed.ok) {
    ok &= check(parsed.image.machine == 0x014c, "machine is x86");
    ok &= check(!parsed.image.is_pe32_plus, "kind is PE32");
    ok &= check(parsed.image.entry_point == 0x1000, "entry point parsed");
    ok &= check(parsed.image.image_base == 0x00400000, "image base parsed");
    ok &= check(parsed.image.sections.size() == 1, "one section parsed");
    ok &= check(parsed.image.sections[0].name == ".text", "section name parsed");
  }
  auto plus_bytes = make_pe32_plus();
  auto plus = kernex::pe::parse(plus_bytes);
  ok &= check(plus.ok, "synthetic PE32+ parses");
  if (plus.ok) {
    ok &= check(plus.image.is_pe32_plus, "kind is PE32+");
    ok &= check(plus.image.machine == 0x8664, "machine is x86-64");
    ok &= check(plus.image.image_base == 0x0000000140000000ull, "64-bit image base parsed");
  }
  std::vector<std::uint8_t> empty;
  ok &= check(!kernex::pe::parse(empty).ok, "empty input rejected");
  auto bad_sig = bytes;
  put32(bad_sig, 0x80, 0);
  ok &= check(!kernex::pe::parse(bad_sig).ok, "bad signature rejected");
  auto bad_section = bytes;
  put32(bad_section, 0x178 + 20, 0xfffffff0u);
  ok &= check(!kernex::pe::parse(bad_section).ok, "out-of-bounds section rejected");
  auto truncated = bytes;
  truncated.resize(0x90);
  ok &= check(!kernex::pe::parse(truncated).ok, "truncated PE rejected");
  if (ok) std::cout << "PE parser tests passed\n";
  return ok ? 0 : 1;
}