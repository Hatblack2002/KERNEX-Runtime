#include "pe/pe_image.hpp"
#include "pe/imports.hpp"

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
    std::size_t file_offset = 0;
    ok &= check(kernex::pe::rva_to_file_offset(parsed.image, bytes.size(), 0x1000, 4, file_offset) &&
                file_offset == 0x200, "section RVA maps to raw file offset");
    ok &= check(kernex::pe::rva_to_file_offset(parsed.image, bytes.size(), 0x1f0, 8, file_offset) &&
                file_offset == 0x1f0, "header RVA maps directly");
    ok &= check(!kernex::pe::rva_to_file_offset(parsed.image, bytes.size(), 0x11ff, 2, file_offset),
                "RVA range extending past raw section data rejected");
    ok &= check(!kernex::pe::rva_to_file_offset(parsed.image, bytes.size(), 0x3000, 1, file_offset),
                "unmapped RVA rejected");
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
  auto with_imports = bytes;
  put32(with_imports, 0x98 + 92, 16); // PE32 NumberOfRvaAndSizes
  put32(with_imports, 0x98 + 96 + 9 * 8, 0x1010); // TLS directory RVA (index 9)
  put32(with_imports, 0x98 + 96 + 9 * 8 + 4, 24);
  put32(with_imports, 0x98 + 96 + 13 * 8, 0x1020); // delay-import directory
  put32(with_imports, 0x98 + 96 + 13 * 8 + 4, 64);
  put32(with_imports, 0x98 + 96 + 8, 0x1008); // import directory RVA (index 1)
  put32(with_imports, 0x98 + 96 + 12, 40);
  auto dirs = kernex::pe::parse(with_imports);
  ok &= check(dirs.ok, "data-directory metadata parses");
  if (dirs.ok) {
    ok &= check(dirs.image.import_directory_rva == 0x1008 && dirs.image.import_directory_size == 40,
                "import directory extracted");
    ok &= check(dirs.image.tls_directory_rva == 0x1010 && dirs.image.tls_directory_size == 24,
                "TLS directory extracted");
    ok &= check(dirs.image.delay_import_directory_rva == 0x1020 && dirs.image.delay_import_directory_size == 64,
                "delay-import directory extracted");
  }
  auto imports_fixture = with_imports;
  // One IMAGE_IMPORT_DESCRIPTOR at RVA 0x1008; the second descriptor is null.
  put32(imports_fixture, 0x208 + 12, 0x1040);
  const char dll_name[] = "KERNEL32.dll";
  for (std::size_t i = 0; i < sizeof(dll_name); ++i)
    imports_fixture[0x240 + i] = static_cast<std::uint8_t>(dll_name[i]);
  auto import_image = kernex::pe::parse(imports_fixture);
  ok &= check(import_image.ok, "import module fixture parses");
  if (import_image.ok) {
    auto modules = kernex::pe::read_import_modules(imports_fixture, import_image.image);
    ok &= check(modules.ok, "import module name reader succeeds");
    ok &= check(modules.modules.size() == 1 && modules.modules[0] == "KERNEL32.dll",
                "import DLL name extracted");
    auto broken_imports = imports_fixture;
    put32(broken_imports, 0x208 + 12, 0xfffffff0u);
    auto broken_image = kernex::pe::parse(broken_imports);
    auto broken_modules = kernex::pe::read_import_modules(broken_imports, broken_image.image);
    ok &= check(!broken_modules.ok, "out-of-range import name rejected");
  }

  auto impossible_directory_count = bytes;
  put32(impossible_directory_count, 0x98 + 92, 0xffffffffu);
  ok &= check(!kernex::pe::parse(impossible_directory_count).ok,
              "data-directory count beyond optional header rejected");

  auto bad_sig = bytes;
  put32(bad_sig, 0x80, 0);
  ok &= check(!kernex::pe::parse(bad_sig).ok, "bad signature rejected");
  auto bad_offset = bytes;
  put32(bad_offset, 0x3c, 0xfffffff0u);
  ok &= check(!kernex::pe::parse(bad_offset).ok, "overflowing PE header offset rejected");
  auto bad_section = bytes;
  put32(bad_section, 0x178 + 20, 0xfffffff0u);
  ok &= check(!kernex::pe::parse(bad_section).ok, "out-of-bounds section rejected");
  auto truncated = bytes;
  truncated.resize(0x90);
  ok &= check(!kernex::pe::parse(truncated).ok, "truncated PE rejected");
  if (ok) std::cout << "PE parser tests passed\n";
  return ok ? 0 : 1;
}