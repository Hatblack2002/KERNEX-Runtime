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
  kernex::x86::Cpu32 invalid(16);
  invalid.code = {0x0f};
  if (invalid.step() || invalid.error.empty()) return 7;
  std::cout << "x86 interpreter baseline tests passed\n";
  return 0;
}
