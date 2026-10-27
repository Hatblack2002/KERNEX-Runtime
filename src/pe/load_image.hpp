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
// This is not a Windows loader: relocations, imports, TLS callbacks, permissions,
// and execution are intentionally outside this first mapping primitive.
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

} // namespace kernex::pe
