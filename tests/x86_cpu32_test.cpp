#include "x86/cpu32.hpp"
#include <iostream>
#include <vector>
int main() {
  kernex::x86::Cpu32 cpu(4096);
  cpu.code = {0xb8,0x2a,0,0,0,0x50,0x5b,0x90};
  if (!cpu.step() || cpu.regs[0] != 42 || cpu.eip != 5) return 1;
  if (!cpu.step() || cpu.regs[4] != 4092) return 2;
  if (!cpu.step() || cpu.regs[3] != 42 || cpu.regs[4] != 4096) return 3;
  if (!cpu.step() || cpu.eip != 8) return 4;
  kernex::x86::Cpu32 pop_esp(64);
  pop_esp.code = {0x5c}; // POP ESP
  pop_esp.regs[4] = 16;
  if (!pop_esp.write32(16, 0x12345678u)) return 11;
  if (!pop_esp.step() || pop_esp.regs[4] != 0x12345678u) return 12;
  kernex::x86::Cpu32 branch(4096);
  branch.code = {0x75,0x02,0xb8,0x01,0,0,0,0xb8,0x2a,0,0,0};
  branch.eflags |= 0x40; // ZF=1, JNZ not taken
  if (!branch.step() || branch.eip != 2) return 5;
  if (!branch.step() || branch.regs[0] != 1) return 6;
  kernex::x86::Cpu32 frame(4096);
  frame.code = {0x68,0x78,0x56,0x34,0x12,0xc9};
  frame.regs[5] = 4092;
  if (!frame.step() || frame.regs[4] != 4092) return 8;
  if (!frame.step() || frame.regs[5] != 0x12345678u || frame.regs[4] != 4096) return 9;
  kernex::x86::Cpu32 bad_frame(16);
  bad_frame.code = {0xc9}; bad_frame.regs[5] = 16;
  if (bad_frame.step() || bad_frame.error.empty()) return 10;
  kernex::x86::Cpu32 invalid(16);
  invalid.code = {0x0f};
  if (invalid.step() || invalid.error.empty()) return 7;
  // Guest instruction pointers and stack pointers can be real 32-bit VAs.
  kernex::x86::Cpu32 va_cpu(64);
  va_cpu.code = {0xb8,0x2a,0,0,0,0xc3};
  va_cpu.code_base = 0x00400000u;
  va_cpu.memory_base = 0x00400000u;
  va_cpu.eip = va_cpu.code_base;
  va_cpu.regs[4] = va_cpu.memory_base + 60;
  va_cpu.stop_address = va_cpu.code_base + static_cast<std::uint32_t>(va_cpu.code.size());
  va_cpu.stop_address_enabled = true;
  if (!va_cpu.write32(va_cpu.regs[4], va_cpu.stop_address)) return 13;
  if (!va_cpu.run(8) || va_cpu.regs[0] != 42 || va_cpu.eip != va_cpu.stop_address) return 14;
  kernex::x86::Cpu32 fallthrough(64);
  fallthrough.code = {0x90};
  if (fallthrough.run(4) || fallthrough.error.empty()) return 15;
  kernex::x86::Cpu32 bad_va(64);
  bad_va.code = {0x90};
  bad_va.code_base = 0x00400000u;
  bad_va.eip = 0x003fffffu;
  if (bad_va.step() || bad_va.error.empty()) return 16;
  // ModRM register arithmetic, absolute disp32 memory operands, and flags.
  kernex::x86::Cpu32 alu(256);
  alu.code = {
    0xb8,5,0,0,0,             // mov eax,5
    0xb9,7,0,0,0,             // mov ecx,7
    0x03,0xc1,                // add eax,ecx
    0x2d,2,0,0,0,             // sub eax,2 => 10
    0x89,0x05,0x20,0,0,0,     // mov [0x20],eax
    0x8b,0x15,0x20,0,0,0,     // mov edx,[0x20]
    0x3d,10,0,0,0,            // cmp eax,10 => ZF
    0x74,0x02,                // jz over failure instruction
    0xcc,                     // int3 must be skipped
    0x90
  };
  alu.stop_address = static_cast<std::uint32_t>(alu.code.size());
  alu.stop_address_enabled = true;
  if (!alu.run(32) || alu.regs[0] != 10 || alu.regs[2] != 10 ||
      (alu.eflags & 0x40u) == 0) return 17;
  std::uint32_t stored{};
  if (!alu.read32(0x20, stored) || stored != 10) return 18;

  // SIB addressing: mov [eax+ecx*4+8], edx; then read it back.
  kernex::x86::Cpu32 sib(256);
  sib.code = {0xb8,0x20,0,0,0, 0xb9,2,0,0,0, 0xba,0x78,0x56,0x34,0x12,
              0x89,0x54,0x88,0x08, 0x8b,0x7c,0x88,0x08};
  sib.regs[4] = 256;
  if (!sib.step() || !sib.step() || !sib.step() || !sib.step() || !sib.step()) return 19;
  if (sib.regs[7] != 0x12345678u) return 20;

  std::cout << "x86 interpreter baseline tests passed\n";
  return 0;
}
