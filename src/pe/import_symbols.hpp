#pragma once

#include "pe/pe_image.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace kernex::pe {

struct ImportSymbol {
  std::string module;
  std::string name;
  std::uint16_t hint{};
  std::uint16_t ordinal{};
  bool by_ordinal{};
};

struct ImportSymbolsResult {
  bool ok{};
  std::vector<ImportSymbol> symbols;
  std::string error;
};

inline ImportSymbolsResult read_import_symbols(
    const std::vector<std::uint8_t>& bytes, const ImageInfo& image,
    std::size_t max_modules = 256, std::size_t max_symbols = 65536,
    std::size_t max_name_bytes = 4096) {
  ImportSymbolsResult result;
  const auto fail = [&](const char* message) {
    result.ok = false;
    result.error = message;
    result.symbols.clear();
    return result;
  };

  const auto module_result = read_import_modules(bytes, image, max_modules, max_name_bytes);
  if (!module_result.ok) return fail("invalid import module table");
  if (image.import_directory_rva == 0 && image.import_directory_size == 0) {
    result.ok = true;
    return result;
  }

  std::size_t directory_offset = 0;
  if (!rva_to_file_offset(image, bytes.size(), image.import_directory_rva,
                          image.import_directory_size, directory_offset))
    return fail("import directory is not fully backed by file data");

  const std::size_t descriptor_count = image.import_directory_size / 20;
  std::size_t module_index = 0;
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
    if (module_index >= module_result.modules.size())
      return fail("import module table is inconsistent");
    const std::uint32_t lookup_rva = original_thunk != 0 ? original_thunk : first_thunk;
    if (lookup_rva == 0) return fail("import descriptor has no lookup thunk");

    const std::size_t width = image.is_pe32_plus ? 8 : 4;
    const std::uint64_t ordinal_flag = image.is_pe32_plus
        ? 0x8000000000000000ull : 0x80000000ull;
    bool thunk_terminated = false;
    for (std::size_t j = 0; j < max_symbols; ++j) {
      const std::uint64_t thunk_rva64 = static_cast<std::uint64_t>(lookup_rva) + j * width;
      if (thunk_rva64 > 0xffffffffull) return fail("import thunk RVA overflow");
      std::size_t thunk_offset = 0;
      if (!rva_to_file_offset(image, bytes.size(), static_cast<std::uint32_t>(thunk_rva64),
                              static_cast<std::uint32_t>(width), thunk_offset))
        return fail("import thunk points outside file-backed data");

      std::uint64_t thunk{};
      if (image.is_pe32_plus) {
        if (!read_u64(bytes, thunk_offset, thunk)) return fail("truncated 64-bit import thunk");
      } else {
        std::uint32_t thunk32{};
        if (!read_u32(bytes, thunk_offset, thunk32)) return fail("truncated 32-bit import thunk");
        thunk = thunk32;
      }
      if (thunk == 0) {
        thunk_terminated = true;
        break;
      }
      if (result.symbols.size() >= max_symbols)
        return fail("import symbol limit exceeded");

      ImportSymbol symbol;
      symbol.module = module_result.modules[module_index];
      if ((thunk & ordinal_flag) != 0) {
        if ((thunk & ~(ordinal_flag | 0xffffull)) != 0)
          return fail("ordinal import thunk has reserved bits set");
        symbol.by_ordinal = true;
        symbol.ordinal = static_cast<std::uint16_t>(thunk & 0xffffu);
        if (symbol.ordinal == 0) return fail("invalid zero import ordinal");
      } else {
        if (thunk > 0xffffffffull) return fail("import-by-name RVA exceeds PE range");
        std::size_t hint_offset = 0;
        if (!rva_to_file_offset(image, bytes.size(), static_cast<std::uint32_t>(thunk),
                                2, hint_offset))
          return fail("import-by-name hint points outside file-backed data");
        if (!read_u16(bytes, hint_offset, symbol.hint))
          return fail("truncated import-by-name hint");
        const std::uint64_t name_rva64 = thunk + 2;
        if (name_rva64 > 0xffffffffull) return fail("import symbol name RVA overflow");
        bool name_terminated = false;
        for (std::size_t k = 0; k < max_name_bytes; ++k) {
          const std::uint64_t current_rva = name_rva64 + k;
          if (current_rva > 0xffffffffull) return fail("import symbol name RVA overflow");
          std::size_t char_offset = 0;
          if (!rva_to_file_offset(image, bytes.size(), static_cast<std::uint32_t>(current_rva),
                                  1, char_offset))
            return fail("import symbol name points outside file-backed data");
          const auto ch = bytes[char_offset];
          if (ch == 0) { name_terminated = true; break; }
          if (ch < 0x21 || ch > 0x7e)
            return fail("import symbol name contains non-printable ASCII");
          symbol.name.push_back(static_cast<char>(ch));
        }
        if (!name_terminated) return fail("unterminated or oversized import symbol name");
        if (symbol.name.empty()) return fail("empty import symbol name");
      }
      result.symbols.push_back(std::move(symbol));
    }
    if (!thunk_terminated) return fail("import thunk table has no null terminator");
    ++module_index;
  }
  if (!terminated) return fail("import descriptor table has no null terminator");
  if (module_index != module_result.modules.size())
    return fail("import module and descriptor counts differ");
  result.ok = true;
  return result;
}

} // namespace kernex::pe
