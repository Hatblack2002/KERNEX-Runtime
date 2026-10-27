#pragma once

#include "pe/bind_imports.hpp"
#include "pe/load_image.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace kernex::runtime {

struct PreparedImage {
  bool ok{};
  pe::LoadResult image;
  std::string error;
};

// Performs the deterministic loader stages that are implemented today:
// map image, optionally rebase it, then bind every regular import through an
// explicit guest-address resolver. This does not initialize TLS, process
// delay imports, set section protections, or emulate Windows APIs.
inline PreparedImage prepare_image(const std::vector<std::uint8_t>& file,
                                   const pe::ImportResolver& resolver,
                                   std::uint64_t actual_base = 0,
                                   std::size_t max_image_size = 256u * 1024u * 1024u) {
  PreparedImage result;
  auto fail = [&](const std::string& message) {
    result.ok = false;
    result.error = message;
    return result;
  };

  result.image = pe::load_image(file, max_image_size);
  if (!result.image.ok) return fail(result.image.error);

  if (actual_base == 0) actual_base = result.image.image.image_base;
  if (actual_base != result.image.image.image_base &&
      !pe::apply_base_relocations(result.image, actual_base, &result.error))
    return fail(result.error);

  const auto binding = pe::bind_imports(result.image, file, resolver);
  if (!binding.ok) return fail(binding.error);

  result.ok = true;
  result.error.clear();
  return result;
}

} // namespace kernex::runtime
