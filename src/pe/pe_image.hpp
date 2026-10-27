#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace kernex::pe {

struct Section {
  std::string name;
  std::uint32_t virtual_size{};
  std::uint32_t virtual_address{};
  std::uint32_t raw_size{};
  std::uint32_t raw_offset{};
  std::uint32_t characteristics{};
};

struct ImageInfo {
  bool is_pe32_plus{};
  std::uint16_t machine{};
  std::uint16_t section_count{};
  std::uint16_t optional_header_size{};
  std::uint16_t characteristics{};
  std::uint32_t entry_point{};
  std::uint64_t image_base{};
  std::uint32_t section_alignment{};
  std::uint32_t file_alignment{};
  std::uint32_t size_of_image{};
  std::uint32_t size_of_headers{};
  std::vector<Section> sections;
};

struct ParseResult {
  bool ok{};
  ImageInfo image;
  std::string error;
};

inline bool range_ok(std::size_t size, std::uint64_t offset, std::uint64_t length) {
  return offset <= size && length <= static_cast<std::uint64_t>(size) - offset;
}

inline bool read_u16(const std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t& out) {
  if (!range_ok(b.size(), off, 2)) return false;
  out = static_cast<std::uint16_t>(b[off]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(b[off + 1]) << 8);
  return true;
}

inline bool read_u32(const std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t& out) {
  if (!range_ok(b.size(), off, 4)) return false;
  out = static_cast<std::uint32_t>(b[off]) |
        (static_cast<std::uint32_t>(b[off + 1]) << 8) |
        (static_cast<std::uint32_t>(b[off + 2]) << 16) |
        (static_cast<std::uint32_t>(b[off + 3]) << 24);
  return true;
}

inline bool read_u64(const std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t& out) {
  std::uint32_t lo{}, hi{};
  if (!read_u32(b, off, lo) || !read_u32(b, off + 4, hi)) return false;
  out = static_cast<std::uint64_t>(lo) | (static_cast<std::uint64_t>(hi) << 32);
  return true;
}

inline ParseResult parse(const std::vector<std::uint8_t>& b) {
  ParseResult result;
  auto fail = [&](const char* message) -> ParseResult {
    result.ok = false;
    result.error = message;
    result.image.sections.clear();
    return result;
  };

  std::uint16_t mz{};
  if (!read_u16(b, 0, mz) || mz != 0x5a4d) return fail("missing or truncated DOS MZ header");

  std::uint32_t pe_offset{};
  if (!read_u32(b, 0x3c, pe_offset)) return fail("truncated e_lfanew field");
  if (!range_ok(b.size(), pe_offset, 24)) return fail("truncated PE/COFF header");

  std::uint32_t signature{};
  if (!read_u32(b, pe_offset, signature) || signature != 0x00004550)
    return fail("invalid PE signature");

  std::uint16_t machine{}, section_count{}, optional_size{}, characteristics{};
  if (!read_u16(b, pe_offset + 4, machine) ||
      !read_u16(b, pe_offset + 6, section_count) ||
      !read_u16(b, pe_offset + 20, optional_size) ||
      !read_u16(b, pe_offset + 22, characteristics))
    return fail("truncated COFF header");

  const std::uint64_t optional = static_cast<std::uint64_t>(pe_offset) + 24;
  if (!range_ok(b.size(), optional, optional_size)) return fail("truncated optional header");
  std::uint16_t magic{};
  if (optional_size < 2 || !read_u16(b, static_cast<std::size_t>(optional), magic))
    return fail("missing optional-header magic");
  if (magic != 0x10b && magic != 0x20b) return fail("unsupported optional-header magic");

  const bool plus = magic == 0x20b;
  const std::size_t minimum = plus ? 112 : 96;
  if (optional_size < minimum) return fail("optional header too small for required fields");

  ImageInfo image;
  image.is_pe32_plus = plus;
  image.machine = machine;
  image.section_count = section_count;
  image.optional_header_size = optional_size;
  image.characteristics = characteristics;

  std::uint32_t entry{}, section_align{}, file_align{}, size_image{}, size_headers{};
  if (!read_u32(b, static_cast<std::size_t>(optional) + 16, entry) ||
      !read_u32(b, static_cast<std::size_t>(optional) + 32, section_align) ||
      !read_u32(b, static_cast<std::size_t>(optional) + 36, file_align) ||
      !read_u32(b, static_cast<std::size_t>(optional) + 56, size_image) ||
      !read_u32(b, static_cast<std::size_t>(optional) + 60, size_headers))
    return fail("truncated optional-header fields");

  std::uint64_t image_base{};
  const bool base_ok = plus
      ? read_u64(b, static_cast<std::size_t>(optional) + 24, image_base)
      : [&]() {
          std::uint32_t base32{};
          if (!read_u32(b, static_cast<std::size_t>(optional) + 28, base32)) return false;
          image_base = base32;
          return true;
        }();
  if (!base_ok) return fail("truncated image base");

  const std::uint64_t section_table = optional + optional_size;
  const std::uint64_t section_bytes = static_cast<std::uint64_t>(section_count) * 40;
  if (!range_ok(b.size(), section_table, section_bytes)) return fail("truncated section table");

  image.entry_point = entry;
  image.image_base = image_base;
  image.section_alignment = section_align;
  image.file_alignment = file_align;
  image.size_of_image = size_image;
  image.size_of_headers = size_headers;

  for (std::uint16_t i = 0; i < section_count; ++i) {
    const auto off = static_cast<std::size_t>(section_table + static_cast<std::uint64_t>(i) * 40);
    Section s;
    for (std::size_t j = 0; j < 8 && b[off + j] != 0; ++j) s.name.push_back(static_cast<char>(b[off + j]));
    if (!read_u32(b, off + 8, s.virtual_size) ||
        !read_u32(b, off + 12, s.virtual_address) ||
        !read_u32(b, off + 16, s.raw_size) ||
        !read_u32(b, off + 20, s.raw_offset) ||
        !read_u32(b, off + 36, s.characteristics))
      return fail("truncated section entry");
    if (s.raw_size != 0 && !range_ok(b.size(), s.raw_offset, s.raw_size))
      return fail("section raw data exceeds file bounds");
    image.sections.push_back(s);
  }

  result.ok = true;
  result.image = std::move(image);
  return result;
}

} // namespace kernex::pe
