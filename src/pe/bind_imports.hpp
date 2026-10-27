#pragma once

#include "pe/import_symbols.hpp"
#include "pe/load_image.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace kernex::pe {

struct ImportBindingResult {
  bool ok{};
  std::size_t bound_count{};
  std::string error;
};

using ImportResolver = std::function<bool(const ImportSymbol&, std::uint64_t&)>;

// Bind parsed imports into the mapped image's IAT. Resolution policy (including
// Windows API shims and ordinal lookup) is supplied by the embedding runtime.
inline ImportBindingResult bind_imports(LoadResult& loaded,
                                        const std::vector<std::uint8_t>& file,
                                        const ImportResolver& resolver) {
  ImportBindingResult result;
  auto fail = [&](const char* message) {
    result.ok = false;
    result.error = message;
    result.bound_count = 0;
    return result;
  };
  if (!loaded.ok || loaded.memory.size() != loaded.image.size_of_image)
    return fail("image must be successfully mapped before import binding");
  if (!resolver) return fail("import resolver callback is empty");

  const auto imports = read_import_symbols(file, loaded.image);
  if (!imports.ok) return fail("import symbol table is invalid");

  std::vector<std::uint8_t> patched = loaded.memory;
  const std::size_t width = loaded.image.is_pe32_plus ? 8 : 4;
  for (const auto& symbol : imports.symbols) {
    std::uint64_t address = 0;
    if (!resolver(symbol, address))
      return fail("import resolver could not resolve a symbol");
    if (!loaded.image.is_pe32_plus && address > UINT32_MAX)
      return fail("resolved address does not fit a PE32 IAT slot");
    if (!range_ok(patched.size(), symbol.iat_rva, width))
      return fail("IAT slot exceeds mapped image bounds");
    for (std::size_t i = 0; i < width; ++i)
      patched[static_cast<std::size_t>(symbol.iat_rva) + i] =
          static_cast<std::uint8_t>(address >> (i * 8));
    ++result.bound_count;
  }

  loaded.memory.swap(patched);
  result.ok = true;
  result.error.clear();
  return result;
}

} // namespace kernex::pe
