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

  kernex::x86::Cpu32 signed_push(64);
  signed_push.code = {0x6a,0xff,0x58}; // push -1; pop eax
  if (!signed_push.step() || !signed_push.step() || signed_push.regs[0] != 0xffffffffu) return 21;

  kernex::x86::Cpu32 near_branch(64);
  near_branch.code = {0x0f,0x84,0x01,0,0,0,0xcc,0x90}; // JZ skips INT3
  near_branch.eflags |= 0x40u;
  if (!near_branch.step() || near_branch.eip != 7) return 22;
  if (!near_branch.step() || near_branch.eip != 8) return 23;

  kernex::x86::Cpu32 test_flags(64);
  test_flags.code = {0xb8,0x0c,0,0,0, 0xb9,0x0a,0,0,0, 0x85,0xc8};
  if (!test_flags.step() || !test_flags.step() || !test_flags.step()) return 24;
  if (test_flags.regs[0] != 12 || test_flags.regs[1] != 10 ||
      (test_flags.eflags & 0x40u) != 0) return 25;

  // Immediate groups: C7 /0, ADD/SUB/CMP r/m32,imm32 and sign-extended imm8.
  kernex::x86::Cpu32 immediates(256);
  immediates.code = {
    0xb8,0x10,0,0,0,             // mov eax,16
    0x83,0xc0,0xf8,              // add eax,-8 => 8
    0x83,0xe8,0x03,              // sub eax,3 => 5
    0x83,0xf8,0x05,              // cmp eax,5 => ZF
    0xc7,0x05,0x40,0,0,0,0x78,0x56,0x34,0x12, // mov [0x40],0x12345678
    0x81,0x05,0x40,0,0,0,0x88,0,0,0 // add [0x40],136
  };
  immediates.stop_address = static_cast<std::uint32_t>(immediates.code.size());
  immediates.stop_address_enabled = true;
  if (!immediates.run(32) || immediates.regs[0] != 5 ||
      (immediates.eflags & 0x40u) == 0) return 26;
  std::uint32_t immediate_memory{};
  if (!immediates.read32(0x40, immediate_memory) || immediate_memory != 0x12345700u) return 27;

  kernex::x86::Cpu32 bad_group(64);
  bad_group.code = {0x81,0xc8,1,0,0,0}; // unsupported OR group extension
  if (bad_group.step() || bad_group.error.empty()) return 28;
  kernex::x86::Cpu32 truncated_group(64);
  truncated_group.code = {0x83,0xc0};
  if (truncated_group.step() || truncated_group.error.empty()) return 29;

  std::cout << "x86 interpreter baseline tests passed\n";
  return 0;
}
