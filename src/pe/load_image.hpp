#pragma once

#include "pe/pe_image.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace kernex::pe {

struct LoadResult {
  bool ok{};
  ImageInfo image;
  std::vector<std::uint8_t> memory;
  std::string error;
};

// Maps headers and section raw data into a zero-initialized image-layout buffer.
// This is not a Windows loader: import binding, TLS callbacks, permissions, and
// execution remain outside this mapping primitive.
inline LoadResult load_image(const std::vector<std::uint8_t>& file,
                             std::size_t max_image_size = 256u * 1024u * 1024u) {
  LoadResult result;
  const auto parsed = parse(file);
  if (!parsed.ok) {
    result.error = "PE parse failed: " + parsed.error;
    return result;
  }

  const auto& image = parsed.image;
  if (image.size_of_image == 0 ||
      static_cast<std::uint64_t>(image.size_of_image) > max_image_size) {
    result.error = "image size is zero or exceeds configured limit";
    return result;
  }
  if (image.size_of_headers == 0 || image.size_of_headers > file.size() ||
      image.size_of_headers > image.size_of_image) {
    result.error = "header size is inconsistent with file or image bounds";
    return result;
  }
  if (image.entry_point >= image.size_of_image && image.entry_point != 0) {
    result.error = "entry point lies outside image bounds";
    return result;
  }

  struct Span { std::uint64_t begin; std::uint64_t end; };
  std::vector<Span> spans;
  spans.reserve(image.sections.size());
  for (const auto& section : image.sections) {
    const std::uint64_t mapped_size = std::max(section.virtual_size, section.raw_size);
    const std::uint64_t begin = section.virtual_address;
    const std::uint64_t end = begin + mapped_size;
    if (end > image.size_of_image || end > 0x100000000ull) {
      result.error = "section virtual range exceeds image bounds";
      return result;
    }
    if (mapped_size != 0 && begin < image.size_of_headers) {
      result.error = "section virtual range overlaps mapped headers";
      return result;
    }
    if (mapped_size != 0) spans.push_back({begin, end});
  }
  std::sort(spans.begin(), spans.end(), [](const Span& a, const Span& b) {
    return a.begin < b.begin;
  });
  for (std::size_t i = 1; i < spans.size(); ++i) {
    if (spans[i].begin < spans[i - 1].end) {
      result.error = "overlapping section virtual ranges";
      return result;
    }
  }

  result.memory.assign(static_cast<std::size_t>(image.size_of_image), 0);
  std::copy_n(file.begin(), image.size_of_headers, result.memory.begin());
  for (const auto& section : image.sections) {
    if (section.raw_size == 0) continue;
    const std::size_t destination = static_cast<std::size_t>(section.virtual_address);
    if (!range_ok(result.memory.size(), destination, section.raw_size) ||
        !range_ok(file.size(), section.raw_offset, section.raw_size)) {
      result.memory.clear();
      result.error = "section copy exceeds file or image bounds";
      return result;
    }
    std::copy_n(file.begin() + section.raw_offset, section.raw_size,
                result.memory.begin() + destination);
  }

  result.image = image;
  result.ok = true;
  return result;
}


 
// Apply PE32 HIGHLOW or PE32+ DIR64 base relocations to a successfully mapped image.
// A relocated copy is committed only after the entire relocation directory validates.
inline bool apply_base_relocations(LoadResult& loaded, std::uint64_t actual_base,
                                   std::string* error = nullptr) {
  auto fail = [&](const char* message) {
    if (error) *error = message;
    return false;
  };
  if (!loaded.ok || loaded.memory.size() != loaded.image.size_of_image)
    return fail("image must be successfully mapped before relocation");

  const auto& image = loaded.image;
  if (actual_base == image.image_base) {
    if (error) error->clear();
    return true;
  }
  if (image.is_pe32_plus) {
    if (actual_base > UINT64_MAX - image.size_of_image)
      return fail("actual image address range overflows 64-bit address space");
  } else {
    if (actual_base > UINT32_MAX ||
        image.size_of_image > (std::uint64_t{1} << 32) - actual_base)
      return fail("actual image address range exceeds PE32 address space");
  }

  const std::uint32_t directory_rva = image.base_relocation_directory_rva;
  const std::uint32_t directory_size = image.base_relocation_directory_size;
  if (directory_rva == 0 || directory_size == 0)
    return fail("image has no base relocation directory for requested base");

  std::vector<std::uint8_t> relocated = loaded.memory;
  if (!range_ok(relocated.size(), directory_rva, directory_size))
    return fail("base relocation directory exceeds mapped image");

  const std::uint32_t expected_type = image.is_pe32_plus ? 10u : 3u;
  const std::uint64_t delta = actual_base - image.image_base;
  std::uint64_t cursor = directory_rva;
  const std::uint64_t directory_end = cursor + directory_size;
  if (directory_end > relocated.size())
    return fail("base relocation directory end exceeds mapped image");

  while (cursor < directory_end) {
    if (directory_end - cursor < 8)
      return fail("truncated base relocation block header");
    std::uint32_t page_rva{}, block_size{};
    if (!read_u32(relocated, static_cast<std::size_t>(cursor), page_rva) ||
        !read_u32(relocated, static_cast<std::size_t>(cursor + 4), block_size))
      return fail("unreadable base relocation block header");
    if (block_size < 8 || (block_size & 1u) != 0 ||
        block_size > directory_end - cursor)
      return fail("invalid base relocation block size");
    if ((page_rva & 0x0fffu) != 0 || page_rva >= image.size_of_image)
      return fail("invalid base relocation page RVA");

    for (std::uint64_t entry = cursor + 8; entry < cursor + block_size; entry += 2) {
      std::uint16_t item{};
      if (!read_u16(relocated, static_cast<std::size_t>(entry), item))
        return fail("truncated base relocation entry");
      const std::uint32_t type = item >> 12;
      if (type == 0) continue;
      if (type != expected_type)
        return fail("unsupported or bitness-incompatible base relocation type");
      const std::uint64_t target = static_cast<std::uint64_t>(page_rva) + (item & 0x0fffu);
      const std::uint64_t width = image.is_pe32_plus ? 8u : 4u;
      if (!range_ok(relocated.size(), target, width))
        return fail("base relocation target exceeds mapped image");
      if (image.is_pe32_plus) {
        std::uint64_t value{};
        if (!read_u64(relocated, static_cast<std::size_t>(target), value))
          return fail("unreadable DIR64 relocation target");
        value += delta;
        for (unsigned i = 0; i < 8; ++i)
          relocated[static_cast<std::size_t>(target) + i] =
              static_cast<std::uint8_t>(value >> (i * 8));
      } else {
        std::uint32_t value{};
        if (!read_u32(relocated, static_cast<std::size_t>(target), value))
          return fail("unreadable HIGHLOW relocation target");
        value += static_cast<std::uint32_t>(delta);
        for (unsigned i = 0; i < 4; ++i)
          relocated[static_cast<std::size_t>(target) + i] =
              static_cast<std::uint8_t>(value >> (i * 8));
      }
    }
    cursor += block_size;
  }

  loaded.memory.swap(relocated);
  if (error) error->clear();
  return true;
}

} // namespace kernex::pe
