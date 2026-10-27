#include "pe/load_image.hpp"

#include <cstdint>
#include <iostream>
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
  put16(b, 0, 0x5a4d); put32(b, 0x3c, 0x80); put32(b, 0x80, 0x4550);
  put16(b, 0x84, 0x014c); put16(b, 0x86, 1); put16(b, 0x94, 224);
  const std::size_t o = 0x98;
  put16(b, o, 0x10b); put32(b, o + 16, 0x1000); put32(b, o + 28, 0x400000);
  put32(b, o + 32, 0x1000); put32(b, o + 36, 0x200);
  put32(b, o + 56, 0x3000); put32(b, o + 60, 0x200);
  const std::size_t s = o + 224;
  b[s] = '.'; b[s + 1] = 't'; b[s + 2] = 'e'; b[s + 3] = 'x'; b[s + 4] = 't';
  put32(b, s + 8, 0x180); put32(b, s + 12, 0x1000);
  put32(b, s + 16, 0x200); put32(b, s + 20, 0x200);
  put32(b, s + 36, 0x60000020);
  for (std::size_t i = 0; i < 0x200; ++i) b[0x200 + i] = static_cast<std::uint8_t>(i & 0xff);
  return b;
}
static bool check(bool condition, const char* message) {
  if (!condition) std::cerr << "FAIL: " << message << "\n";
  return condition;
}
int main() {
  bool ok = true;
  const auto file = make_pe32();
  const auto loaded = kernex::pe::load_image(file);
  ok &= check(loaded.ok, "valid PE32 image maps");
  if (loaded.ok) {
    ok &= check(loaded.memory.size() == 0x3000, "mapped buffer matches SizeOfImage");
    ok &= check(loaded.image.entry_point == 0x1000, "entry-point RVA preserved");
    ok &= check(loaded.memory[0] == 'M' && loaded.memory[1] == 'Z', "headers copied");
    ok &= check(loaded.memory[0x1000] == file[0x200] &&
                loaded.memory[0x11ff] == file[0x3ff], "raw section copied to virtual address");
    ok &= check(loaded.memory[0x1200] == 0 && loaded.memory[0x117f] == file[0x37f],
                "virtual tail remains zero-filled");
  }
  ok &= check(!kernex::pe::load_image(file, 0x1000).ok, "image allocation limit enforced");
  auto truncated = file;
  truncated.resize(0x210);
  ok &= check(!kernex::pe::load_image(truncated).ok, "truncated section rejected");
  auto bad_entry = file;
  put32(bad_entry, 0x98 + 16, 0x4000);
  ok &= check(!kernex::pe::load_image(bad_entry).ok, "entry point outside image rejected");
  auto bad_section = file;
  put32(bad_section, 0x178 + 12, 0x2f00);
  ok &= check(!kernex::pe::load_image(bad_section).ok, "section range outside image rejected");
  auto overlap = file;
  put16(overlap, 0x86, 2);
  const std::size_t second = 0x98 + 224 + 40;
  overlap[second] = '.'; overlap[second + 1] = 'd'; overlap[second + 2] = 'a'; overlap[second + 3] = 't'; overlap[second + 4] = 'a';
  put32(overlap, second + 8, 0x100); put32(overlap, second + 12, 0x1100);
  put32(overlap, second + 16, 0x100); put32(overlap, second + 20, 0x300);
  ok &= check(!kernex::pe::load_image(overlap).ok, "overlapping virtual sections rejected");
  if (ok) std::cout << "PE image mapping tests passed\n";
  return ok ? 0 : 1;
}
