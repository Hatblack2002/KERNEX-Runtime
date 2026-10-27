#include "pe/import_symbols.hpp"

#include <cstdint>
#include <iostream>
#include <vector>

static void put16(std::vector<std::uint8_t>& b, std::size_t o, std::uint16_t v) {
  b.at(o) = static_cast<std::uint8_t>(v);
  b.at(o + 1) = static_cast<std::uint8_t>(v >> 8);
}
static void put32(std::vector<std::uint8_t>& b, std::size_t o, std::uint32_t v) {
  for (unsigned i = 0; i < 4; ++i) b.at(o + i) = static_cast<std::uint8_t>(v >> (i * 8));
}
static std::vector<std::uint8_t> fixture() {
  std::vector<std::uint8_t> b(0x600, 0);
  put16(b, 0, 0x5a4d); put32(b, 0x3c, 0x80); put32(b, 0x80, 0x4550);
  put16(b, 0x84, 0x14c); put16(b, 0x86, 1); put16(b, 0x94, 224);
  const std::size_t o = 0x98;
  put16(b, o, 0x10b); put32(b, o + 16, 0x1000); put32(b, o + 28, 0x400000);
  put32(b, o + 32, 0x1000); put32(b, o + 36, 0x200);
  put32(b, o + 56, 0x2000); put32(b, o + 60, 0x200);
  put32(b, o + 92, 16); put32(b, o + 96 + 8, 0x1008); put32(b, o + 96 + 12, 40);
  const std::size_t s = o + 224;
  b[s] = '.'; b[s+1] = 't'; b[s+2] = 'e'; b[s+3] = 'x'; b[s+4] = 't';
  put32(b, s + 8, 0x400); put32(b, s + 12, 0x1000);
  put32(b, s + 16, 0x400); put32(b, s + 20, 0x200);
  put32(b, s + 36, 0x60000020);
  put32(b, 0x208, 0x1050); put32(b, 0x20c, 0); put32(b, 0x210, 0);
  put32(b, 0x214, 0x1040); put32(b, 0x218, 0x1070);
  const char dll[] = "KERNEL32.dll";
  for (std::size_t i = 0; i < sizeof(dll); ++i) b[0x240 + i] = dll[i];
  put32(b, 0x250, 0x1060); put32(b, 0x254, 0);
  put16(b, 0x260, 7);
  const char fn[] = "Sleep";
  for (std::size_t i = 0; i < sizeof(fn); ++i) b[0x262 + i] = fn[i];
  return b;
}
int main() {
  auto bytes = fixture();
  auto parsed = kernex::pe::parse(bytes);
  if (!parsed.ok) { std::cerr << parsed.error << "\n"; return 1; }
  auto symbols = kernex::pe::read_import_symbols(bytes, parsed.image);
  if (!symbols.ok || symbols.symbols.size() != 1) {
    std::cerr << "named import parse failed: " << symbols.error << "\n"; return 2;
  }
  const auto& named = symbols.symbols[0];
  if (named.module != "KERNEL32.dll" || named.name != "Sleep" ||
      named.hint != 7 || named.by_ordinal) return 3;

  put32(bytes, 0x250, 0x80000005u);
  put32(bytes, 0x254, 0);
  auto ordinal = kernex::pe::read_import_symbols(bytes, parsed.image);
  if (!ordinal.ok || ordinal.symbols.size() != 1 ||
      !ordinal.symbols[0].by_ordinal || ordinal.symbols[0].ordinal != 5) {
    std::cerr << "ordinal import parse failed: " << ordinal.error << "\n"; return 4;
  }

  put32(bytes, 0x250, 0x1060);
  put32(bytes, 0x254, 0x1060); // no null thunk before the bounded section ends
  auto malformed = kernex::pe::read_import_symbols(bytes, parsed.image, 256, 4);
  if (malformed.ok) { std::cerr << "unterminated thunk table accepted\n"; return 5; }
  std::cout << "PE import symbol tests passed\n";
  return 0;
}
