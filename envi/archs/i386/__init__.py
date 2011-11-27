
import envi
import envi.bits as e_bits

#TODO
# f0 0f c7 4d 00 75 f0 5d 5b - this is NOT right in disasm

import copy
import struct
import traceback

# Gank in our bundled libdisassemble
import opcode86

from envi.archs.i386.regs import *
from envi.archs.i386.disasm import *

class IntelCall(envi.CallingConvention):

    def getCallArgs(self, emu, count):
        """
        Standard intel stack arg parsing
        """
        esp = emu.getRegister(REG_ESP)
        esp += 4 # For the saved eip
        return struct.unpack("<%dI" % count, emu.readMemory(esp, 4*count))

    def setReturnValue(self, emu, value, argc):
        """
        A return routine which cleans up it's stack args.
        """
        esp = emu.getRegister(REG_ESP)
        eip = emu.readMemoryFormat(esp, '<I')[0]
        esp += 4 # For the saved eip
        esp += (4 * argc) # Cleanup saved args

        emu.setRegister(REG_ESP, esp)
        emu.setRegister(REG_EAX, value)
        emu.setProgramCounter(eip)

class StdCall(IntelCall): pass

class Cdecl(IntelCall):

    def setReturnValue(self, emu, value, argc):
        """
        A base non-cleanup stackarg return
        """
        esp = emu.getRegister(REG_ESP)
        eip = struct.unpack("<I", emu.readMemory(esp, 4))[0]
        esp += 4 # For the saved eip

        emu.setRegister(REG_EAX, value)
        emu.setStackCounter(esp)
        emu.setProgramCounter(eip)

class ThisCall(StdCall):

    def getCallArgs(self, emu, count):
        ret = [emu.getRegister(REG_ECX),]
        count -= 1
        esp = emu.getRegister(REG_ESP)
        esp += 4 # For the saved eip
        if count:
            ret.extend(struct.unpack("<%dI" % count, emu.readMemory(esp, 4*count)))
        return ret

    def setReturnValue(self, emu, value, argc):
        argc -= 1 # One for the ECX...
        return StdCall.setReturnValue(self, emu, value, argc)

class FastCall(envi.CallingConvention):

    def __init__(self, reglist):
        self.reglist = reglist

    def getCallArgs(self, emu, count):

        ret = []
        for i in xrange(count):
            if len(self.reglist) <= i:
                break
            regid = self.reglist[i]
            ret.append(emu.getRegister(regid))
            count -= 1

        if count > 0:
            esp = emu.getRegister(REG_ESP)
            esp += 4 # For the saved eip
            ret.extend(struct.unpack("<%dI" % count, emu.readMemory(esp, 4*count)))
        return ret

    def setReturnValue(self, emu, value, argc):
        esp = emu.getRegister(REG_ESP)
        eip = emu.readMemoryFormat(esp, '<I')[0]
        esp += 4

        if argc > len(self.reglist):
            cbytes = (argc - len(self.reglist)) * 4
            esp += cbytes

        emu.setRegister(REG_EAX, value)
        emu.setStackCounter(esp)
        emu.setProgramCounter(eip)

class MsFastCall(FastCall):
    def __init__(self):
        FastCall.__init__(self, (REG_ECX, REG_EDX))

class BFastCall(FastCall):
    def __init__(self):
        FastCall.__init__(self, (REG_EAX, REG_EDX, REG_ECX))

# Pre-make these and use the same instances for speed
stdcall = StdCall()
thiscall = ThisCall()
cdecl = Cdecl()
msfastcall = MsFastCall()
bfastcall = BFastCall()

class i386Module(envi.ArchitectureModule):

    def __init__(self):
        envi.ArchitectureModule.__init__(self, "i386")
        self._arch_dis = i386Disasm()
        # Add our known calling conventions
        self.addCallingConvention('stdcall', stdcall)
        self.addCallingConvention('thiscall', thiscall)
        self.addCallingConvention('cdecl', cdecl)
        self.addCallingConvention('msfastcall', msfastcall)
        self.addCallingConvention('bfastcall', bfastcall)

    def archGetRegCtx(self):
        return i386RegisterContext()

    def archGetBreakInstr(self):
        return "\xcc"

    def getPointerSize(self):
        return 4

    def pointerString(self, va):
        return "0x%.8x" % va

    def prdisp(self, o):
        # Just a displacement print helper
        dabs = abs(o.disp)
        if dabs > 4096:
            if o.disp < 0:
                return "- 0x%.8x" % dabs
            else:
                return "+ 0x%.8x" % dabs
        else:
            if o.disp < 0:
                return "- %d" % dabs
            else:
                return "+ %d" % dabs

    def makeOpcode(self, bytes, offset=0, va=0):
        """
        Parse a sequence of bytes out into an envi.Opcode instance.
        """
        return self._arch_dis.disasm(bytes, offset, va)

    def getEmulator(self):
        return IntelEmulator()

# NOTE: This one must be after the definition of i386Module
from envi.archs.i386.emu import *

