#pragma once

#include "pe/pe_image.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace kernex::pe {

struct ImportModulesResult {
  bool ok{};
  std::vector<std::string> modules;
  std::string error;
};

inline ImportModulesResult read_import_modules(const std::vector<std::uint8_t>& bytes,
                                               const ImageInfo& image,
                                               std::size_t max_modules = 256,
                                               std::size_t max_name_bytes = 4096) {
  ImportModulesResult result;
  const auto fail = [&](const char* message) {
    result.ok = false;
    result.error = message;
    result.modules.clear();
    return result;
  };

  const std::uint32_t directory_rva = image.import_directory_rva;
  const std::uint32_t directory_size = image.import_directory_size;
  if (directory_rva == 0 && directory_size == 0) {
    result.ok = true;
    return result;
  }
  if (directory_rva == 0 || directory_size < 20)
    return fail("invalid import-directory range");

  std::size_t directory_offset = 0;
  if (!rva_to_file_offset(image, bytes.size(), directory_rva, directory_size, directory_offset))
    return fail("import directory is not fully backed by file data");

  const std::size_t descriptor_count = directory_size / 20;
  bool terminated = false;
  for (std::size_t i = 0; i < descriptor_count; ++i) {
    const std::size_t descriptor = directory_offset + i * 20;
    std::uint32_t original_thunk{}, timestamp{}, forwarder{}, name_rva{}, first_thunk{};
    if (!read_u32(bytes, descriptor, original_thunk) ||
        !read_u32(bytes, descriptor + 4, timestamp) ||
        !read_u32(bytes, descriptor + 8, forwarder) ||
        !read_u32(bytes, descriptor + 12, name_rva) ||
        !read_u32(bytes, descriptor + 16, first_thunk))
      return fail("truncated import descriptor");

    if (original_thunk == 0 && timestamp == 0 && forwarder == 0 &&
        name_rva == 0 && first_thunk == 0) {
      terminated = true;
      break;
    }
    if (name_rva == 0) return fail("import descriptor has no module-name RVA");
    if (result.modules.size() >= max_modules) return fail("import module limit exceeded");

    std::string name;
    bool name_terminated = false;
    for (std::size_t j = 0; j < max_name_bytes; ++j) {
      const std::uint64_t current_rva = static_cast<std::uint64_t>(name_rva) + j;
      if (current_rva > 0xffffffffull) return fail("import module name RVA overflow");
      std::size_t char_offset = 0;
      if (!rva_to_file_offset(image, bytes.size(), static_cast<std::uint32_t>(current_rva),
                              1, char_offset))
        return fail("import module name points outside file-backed data");
      const auto ch = bytes[char_offset];
      if (ch == 0) {
        name_terminated = true;
        break;
      }
      if (ch < 0x20 || ch > 0x7e) return fail("import module name contains non-ASCII bytes");
      name.push_back(static_cast<char>(ch));
    }
    if (!name_terminated) return fail("unterminated or oversized import module name");
    if (name.empty()) return fail("empty import module name");
    result.modules.push_back(std::move(name));
  }

  if (!terminated) return fail("import descriptor table has no null terminator");
  result.ok = true;
  return result;
}

} // namespace kernex::pe
