#pragma once

#include "pe/load_image.hpp"
#include "x86/cpu32.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

namespace kernex::runtime {

struct ExecutionResult {
  bool ok{};
  std::uint32_t exit_code{};
  std::string error;
};

// Executes only the currently implemented x86-32 instruction subset from a
// mapped PE32 image. It supplies a synthetic return address and a separate
// stack region; this is not a Windows process startup or API compatibility layer.
inline ExecutionResult execute_mapped_pe32(const pe::LoadResult& mapped,
                                           std::size_t stack_size = 64u * 1024u,
                                           std::size_t instruction_budget = 100000) {
  ExecutionResult result;
  auto fail = [&](const std::string& message) {
    result.ok = false;
    result.error = message;
    return result;
  };
  if (!mapped.ok || mapped.memory.size() != mapped.image.size_of_image)
    return fail("PE image must be mapped successfully before execution");
  if (mapped.image.is_pe32_plus)
    return fail("x86-32 interpreter cannot execute PE32+ images");
  if (mapped.image.entry_point == 0 || mapped.image.entry_point >= mapped.memory.size())
    return fail("PE32 entry point is zero or outside mapped image");
  if (stack_size < 4 || stack_size > UINT32_MAX - mapped.memory.size())
    return fail("configured stack size is invalid for 32-bit address space");

  const std::size_t total_size = mapped.memory.size() + stack_size;
  x86::Cpu32 cpu(total_size);
  std::copy(mapped.memory.begin(), mapped.memory.end(), cpu.memory.begin());
  cpu.code = mapped.memory;
  cpu.eip = mapped.image.entry_point;
  cpu.regs[4] = static_cast<std::uint32_t>(total_size - 4);
  if (!cpu.write32(cpu.regs[4], static_cast<std::uint32_t>(cpu.code.size())))
    return fail("could not initialize synthetic return address");

  if (!cpu.run(instruction_budget))
    return fail("x86-32 execution failed: " + cpu.error);
  result.ok = true;
  result.exit_code = cpu.regs[0];
  return result;
}

} // namespace kernex::runtime
