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
  kernex::x86::Cpu32 branch(4096);
  branch.code = {0x75,0x02,0xb8,0x01,0,0,0,0xb8,0x2a,0,0,0};
  branch.eflags |= 0x40; // ZF=1, JNZ not taken
  if (!branch.step() || branch.eip != 2) return 5;
  if (!branch.step() || branch.regs[0] != 1) return 6;
  kernex::x86::Cpu32 frame(4096);
  frame.code = {0x68,0x78,0x56,0x34,0x12,0xc9};
  frame.regs[5] = 4088;
  if (!frame.step() || frame.regs[4] != 4092) return 8;
  if (!frame.step() || frame.regs[5] != 0x12345678u || frame.regs[4] != 4092) return 9;
  kernex::x86::Cpu32 bad_frame(16);
  bad_frame.code = {0xc9}; bad_frame.regs[5] = 16;
  if (bad_frame.step() || bad_frame.error.empty()) return 10;
  kernex::x86::Cpu32 invalid(16);
  invalid.code = {0x0f};
  if (invalid.step() || invalid.error.empty()) return 7;
  std::cout << "x86 interpreter baseline tests passed\n";
  return 0;
}
