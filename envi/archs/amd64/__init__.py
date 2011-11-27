"""
The envi architecuture module for the AMD 64 platform.
"""
import envi
import envi.bits as e_bits
import envi.registers as e_reg
import envi.archs.i386 as e_i386

from envi.archs.amd64.regs import *
from envi.archs.amd64.disasm import *

# NOTE: The REX prefixes don't end up with displayed names
# NOTE: the REX prefix must be the *last* non escape (0f) prefix

# EMU NOTES:
# In 64 bit mode, all 32 bit dest regs get 0 extended into the rest of the bits
# In 64 bit mode, all 8/16 bit accesses do NOT modify the upper bits
# In 64 bit mode, all near branches, and implicit RSP (push pop) use RIP even w/o REX
# In 64 bit mode, if mod/rm is mod=0 and r/m is 5, it's RIP relative IMM32

class Amd64Module(e_i386.i386Module):

    def __init__(self):
        envi.ArchitectureModule.__init__(self, "amd64")
        self._arch_dis = Amd64Disasm()

    def getEmulator(self):
        return Amd64Emulator()

    def getPointerSize(self):
        return 8

    def pointerString(self, va):
        return "0x%.8x" % va

    def archGetRegCtx(self):
        return Amd64RegisterContext()

class Amd64Call(envi.CallingConvention):

    def getCallArgs(self, emu, count):
        ret = []
        if count == 0: return ret
        ret.append(emu.getRegister(REG_RCX))
        if count == 1: return ret
        ret.append(emu.getRegister(REG_RDX))
        if count == 2: return ret
        ret.append(emu.getRegister(REG_R8))
        if count == 3: return ret
        ret.append(emu.getRegister(REG_R9))
        if count == 4: return ret
        rsp = emu.getStackCounter()
        stargs = emu.readMemoryFormat(rsp, "<12Q")
        ret.extend(stargs[4:])
        return ret[:count]

    def setReturnValue(self, emu, value, argc):
        rsp = emu.getStackCounter()
        rsp += 8
        emu.setStackCounter(rsp)
        emu.setRegister(REG_RAX, value)

amd64call = Amd64Call()

class Amd64Emulator(Amd64Module, Amd64RegisterContext, e_i386.IntelEmulator):
    def __init__(self):
        e_i386.IntelEmulator.__init__(self)
        # The above sets up the intel reg context, so we smash over it
        Amd64RegisterContext.__init__(self)
        Amd64Module.__init__(self)
        # For the format calls in reading memory
        self.imem_psize = 8
        self.addCallingConvention("amd64call", amd64call)



