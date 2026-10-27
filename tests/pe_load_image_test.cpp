#include "pe/load_image.hpp"
#include "runtime/execute_pe32.hpp"

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
  put32(b, o + 92, 16); // PE32 data-directory count
  put32(b, o + 96 + 5 * 8, 0x1100); // Base relocation directory RVA
  put32(b, o + 96 + 5 * 8 + 4, 12);
  const std::size_t s = o + 224;
  b[s] = '.'; b[s + 1] = 't'; b[s + 2] = 'e'; b[s + 3] = 'x'; b[s + 4] = 't';
  put32(b, s + 8, 0x180); put32(b, s + 12, 0x1000);
  put32(b, s + 16, 0x200); put32(b, s + 20, 0x200);
  put32(b, s + 36, 0x60000020);
  for (std::size_t i = 0; i < 0x200; ++i) b[0x200 + i] = static_cast<std::uint8_t>(i & 0xff);
  // A HIGHLOW relocation at RVA 0x1010; the block lives at RVA 0x1100.
  put32(b, 0x210, 0x00401234);
  put32(b, 0x300, 0x1000); put32(b, 0x304, 12);
  put16(b, 0x308, 0x3010); put16(b, 0x30a, 0);
  return b;
}

static std::vector<std::uint8_t> make_pe64() {
  std::vector<std::uint8_t> b(0x400, 0);
  put16(b, 0, 0x5a4d); put32(b, 0x3c, 0x80); put32(b, 0x80, 0x4550);
  put16(b, 0x84, 0x8664); put16(b, 0x86, 1); put16(b, 0x94, 240);
  const std::size_t o = 0x98;
  put16(b, o, 0x20b); put32(b, o + 16, 0x1000);
  put32(b, o + 24, 0x40000000); put32(b, o + 28, 1); // ImageBase 0x140000000
  put32(b, o + 32, 0x1000); put32(b, o + 36, 0x200);
  put32(b, o + 56, 0x3000); put32(b, o + 60, 0x200);
  put32(b, o + 108, 16);
  put32(b, o + 112 + 5 * 8, 0x1100);
  put32(b, o + 112 + 5 * 8 + 4, 12);
  const std::size_t s = o + 240;
  b[s] = '.'; b[s + 1] = 't'; b[s + 2] = 'e'; b[s + 3] = 'x'; b[s + 4] = 't';
  put32(b, s + 8, 0x180); put32(b, s + 12, 0x1000);
  put32(b, s + 16, 0x200); put32(b, s + 20, 0x200);
  put32(b, s + 36, 0x60000020);
  for (std::size_t i = 0; i < 0x200; ++i) b[0x200 + i] = static_cast<std::uint8_t>(i & 0xff);
  // A DIR64 relocation at RVA 0x1010; the block lives at RVA 0x1100.
  put32(b, 0x210, 0x40001234); put32(b, 0x214, 1);
  put32(b, 0x300, 0x1000); put32(b, 0x304, 12);
  put16(b, 0x308, 0xa010); put16(b, 0x30a, 0);
  return b;
}
static std::uint32_t next_random(std::uint32_t& state) {
  state ^= state << 13;
  state ^= state >> 17;
  state ^= state << 5;
  return state;
}
static bool check(bool condition, const char* message) {
  if (!condition) std::cerr << "FAIL: " << message << "\n";
  return condition;
}
int main() {
  bool ok = true;
  const auto file = make_pe32();
  const auto loaded = kernex::pe::load_image(file);
  auto executable_file = file;
  executable_file[0x200] = 0xb8; // MOV EAX, 42
  executable_file[0x201] = 42;
  executable_file[0x202] = 0;
  executable_file[0x203] = 0;
  executable_file[0x204] = 0;
  executable_file[0x205] = 0xc3; // RET to the harness sentinel
  const auto executable_image = kernex::pe::load_image(executable_file);
  const auto executed = kernex::runtime::execute_mapped_pe32(executable_image);
  ok &= check(executed.ok && executed.exit_code == 42,
              "mapped PE32 entrypoint executes through x86-32 interpreter");
  const auto budget_exhausted = kernex::runtime::execute_mapped_pe32(executable_image, 4096, 1);
  ok &= check(!budget_exhausted.ok, "PE32 execution instruction budget enforced");
  auto mapped64_for_execution = kernex::pe::load_image(make_pe64());
  ok &= check(!kernex::runtime::execute_mapped_pe32(mapped64_for_execution).ok,
              "PE32 interpreter rejects PE32+ image");
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
  const auto file64 = make_pe64();
  auto loaded64 = kernex::pe::load_image(file64);
  ok &= check(loaded64.ok && loaded64.image.is_pe32_plus, "valid PE32+ image maps");
  if (loaded64.ok) {
    std::string error64;
    ok &= check(kernex::pe::apply_base_relocations(loaded64, 0x180000000ull, &error64),
                "PE32+ DIR64 base relocation succeeds");
    std::uint64_t relocated64 = 0;
    ok &= check(kernex::pe::read_u64(loaded64.memory, 0x1010, relocated64) &&
                relocated64 == 0x180001234ull,
                "DIR64 relocation applies 64-bit base delta");
    auto wrong_type = kernex::pe::load_image(file64);
    put16(wrong_type.memory, 0x1108, 0x3010);
    const auto before_wrong_type = wrong_type.memory;
    ok &= check(!kernex::pe::apply_base_relocations(wrong_type, 0x180000000ull),
                "PE32 relocation type rejected for PE32+ image");
    ok &= check(wrong_type.memory == before_wrong_type,
                "bitness-incompatible relocation leaves image unchanged");
  }
  ok &= check(!kernex::pe::load_image(file, 0x1000).ok, "image allocation limit enforced");
  if (loaded.ok) {
    auto relocated = loaded;
    std::string relocation_error;
    ok &= check(kernex::pe::apply_base_relocations(relocated, 0x500000, &relocation_error),
                "PE32 HIGHLOW base relocation succeeds");
    if (relocated.memory.size() == 0x3000) {
      std::uint32_t relocated_value = 0;
      ok &= check(kernex::pe::read_u32(relocated.memory, 0x1010, relocated_value) &&
                  relocated_value == 0x00501234,
                  "HIGHLOW relocation applies base delta");
    }
    auto malformed = loaded;
    put32(malformed.memory, 0x1104, 7);
    const auto before = malformed.memory;
    ok &= check(!kernex::pe::apply_base_relocations(malformed, 0x500000, &relocation_error),
                "malformed relocation block rejected");
    ok &= check(malformed.memory == before, "failed relocation leaves mapped image unchanged");
    auto bad_page = loaded;
    put32(bad_page.memory, 0x1100, 0x1001);
    const auto before_bad_page = bad_page.memory;
    ok &= check(!kernex::pe::apply_base_relocations(bad_page, 0x500000),
                "misaligned relocation page RVA rejected");
    ok &= check(bad_page.memory == before_bad_page,
                "invalid relocation page leaves image unchanged");
    auto no_relocations = loaded;
    no_relocations.image.base_relocation_directory_rva = 0;
    no_relocations.image.base_relocation_directory_size = 0;
    ok &= check(!kernex::pe::apply_base_relocations(no_relocations, 0x500000),
                "rebasing without relocation directory rejected");
  }
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
  // Deterministic mutation and random-input stress with a strict allocation cap.
  std::uint32_t state = 0x4b45524eu;
  for (std::size_t iteration = 0; iteration < 10000; ++iteration) {
    auto candidate = file;
    const unsigned mutations = 1 + next_random(state) % 8;
    for (unsigned i = 0; i < mutations; ++i) {
      const std::size_t at = next_random(state) % candidate.size();
      candidate[at] = static_cast<std::uint8_t>(next_random(state));
    }
    auto mapped = kernex::pe::load_image(candidate, 0x4000);
    if (mapped.ok) {
      if (mapped.memory.size() != mapped.image.size_of_image) {
        std::cerr << "mapped image size invariant failed at mutation " << iteration << "\\n";
        return 10;
      }
      const std::uint64_t base = mapped.image.is_pe32_plus ? 0x180000000ull : 0x500000ull;
      (void)kernex::pe::apply_base_relocations(mapped, base);
    }
  }
  for (std::size_t iteration = 0; iteration < 5000; ++iteration) {
    std::vector<std::uint8_t> random_file(next_random(state) % 1025);
    for (auto& byte : random_file) byte = static_cast<std::uint8_t>(next_random(state));
    const auto mapped = kernex::pe::load_image(random_file, 0x4000);
    if (mapped.ok && mapped.memory.size() != mapped.image.size_of_image) {
      std::cerr << "random image size invariant failed at input " << iteration << "\\n";
      return 11;
    }
  }
  if (ok) std::cout << "PE image mapping tests passed (15000 stress inputs)\\n";
  return ok ? 0 : 1;
}
