import envi
import envi.bits as e_bits
import envi.archs.i386 as e_i386
import envi.archs.i386.opcode86 as opcode86

from envi.archs.amd64.regs import *

# Pre generate these for fast lookup. Because our REX prefixes have the same relative
# bit relationship to eachother, we can cheat a little...
amd64_prefixes = list(e_i386.i386_prefixes)
amd64_prefixes[0x40] = (0x10 << 16)
amd64_prefixes[0x41] = (0x11 << 16)
amd64_prefixes[0x42] = (0x12 << 16)
amd64_prefixes[0x43] = (0x13 << 16)
amd64_prefixes[0x44] = (0x14 << 16)
amd64_prefixes[0x45] = (0x15 << 16)
amd64_prefixes[0x46] = (0x16 << 16)
amd64_prefixes[0x47] = (0x17 << 16)
amd64_prefixes[0x48] = (0x18 << 16)
amd64_prefixes[0x49] = (0x19 << 16)
amd64_prefixes[0x4a] = (0x1a << 16)
amd64_prefixes[0x4b] = (0x1b << 16)
amd64_prefixes[0x4c] = (0x1c << 16)
amd64_prefixes[0x4d] = (0x1d << 16)
amd64_prefixes[0x4e] = (0x1e << 16)
amd64_prefixes[0x4f] = (0x1f << 16)

# NOTE: some notes from the intel manual...
# REX.W overrides 66, but alternate registers (via REX.B etc..) can have 66 to be 16 bit..
# REX.R only modifies reg for GPR/SSE(SIMD)/ctrl/debug addressing modes.
# REX.X only modifies the SIB index value
# REX.B modifies modrm r/m field, or SIB base (if SIB present), or opcode reg.
# We inherit all the regular intel prefixes...
PREFIX_REX   = 0x100000 # Shows that the rex prefix is present
PREFIX_REX_B = 0x010000 # Bit 0 in REX prefix (0x41) means ModR/M r/m field, SIB base, or opcode reg
PREFIX_REX_X = 0x020000 # Bit 1 in REX prefix (0x42) means SIB index extension
PREFIX_REX_R = 0x040000 # Bit 2 in REX prefix (0x44) means ModR/M reg extention
PREFIX_REX_W = 0x080000 # Bit 3 in REX prefix (0x48) means 64 bit operand

REX_BUMP = 8
MODE_16 = 0
MODE_32 = 1
MODE_64 = 2

class Amd64RipRelOper(envi.DerefOper):
    def __init__(self, imm, tsize):
        self.imm = imm
        self.tsize = tsize
        self._is_deref = True

    def getOperValue(self, op, emu=None):
        if self._is_deref == False: # Special lea behavior
            return self.getOperAddr(op)
        if emu == None: return None
        return emu.readMemValue(self.getOperAddr(op, emu), self.tsize)

    def setOperValue(self, op, emu, val):
        emu.writeMemValue(self.getOperAddr(op, emu), val, self.tsize)

    def getOperAddr(self, op, emu=None):
        return op.va + op.size + self.imm

    def isDeref(self):
        # The disassembler may reach in and set this (if lea...)
        return self._is_deref

    def render(self, mcanv, op, idx):
        destva = op.va + op.size + self.imm
        sym = mcanv.syms.getSymByAddr(destva)

        mcanv.addNameText(e_i386.sizenames[self.tsize])
        mcanv.addText(" [")
        mcanv.addNameText("rip", typename="registers")

        if self.imm > 0:
            mcanv.addText(" + ")
            if sym != None:
                mcanv.addVaText("$%s" % repr(sym), destva)
            else:
                mcanv.addNameText(str(self.imm))
        elif self.imm < 0:
            mcanv.addText(" - ")
            if sym != None:
                mcanv.addVaText("$%s" % repr(sym), destva)
            else:
                mcanv.addNameText(str(abs(self.imm)))
        mcanv.addText("]")

    def repr(self, op):
        return "[rip + %d]" % self.imm

class Amd64Disasm(e_i386.i386Disasm):

    def __init__(self):
        e_i386.i386Disasm.__init__(self)
        self._dis_prefixes = amd64_prefixes
        self._dis_regctx = Amd64RegisterContext()

        # Over-ride these which are in use by the i386 version of the ASM
        self.ROFFSET_MMX   = e_i386.getRegOffset(amd64regs, "mm0")
        self.ROFFSET_SIMD  = e_i386.getRegOffset(amd64regs, "xmm0")
        self.ROFFSET_DEBUG = e_i386.getRegOffset(amd64regs, "debug0")
        self.ROFFSET_CTRL  = e_i386.getRegOffset(amd64regs, "ctrl0")
        self.ROFFSET_TEST  = e_i386.getRegOffset(amd64regs, "test0")
        self.ROFFSET_SEG   = e_i386.getRegOffset(amd64regs, "es")
        self.ROFFSET_FPU   = e_i386.getRegOffset(amd64regs, "st0")

    # NOTE: Technically, the REX must be the *last* prefix specified

    def _dis_calc_tsize(self, opertype, prefixes):
        """
        Use the oper type and prefixes to decide on the tsize for
        the operand.
        """

        mode = MODE_32

        sizelist = opcode86.OPERSIZE.get(opertype, None)
        if sizelist == None:
            raise "OPERSIZE FAIL"

        # NOTE: REX takes precedence over 66
        # (see section 2.2.1.2 in Intel 2a)
        if prefixes & PREFIX_REX_W:

            mode = MODE_64

        elif prefixes & e_i386.PREFIX_OP_SIZE:

            mode = MODE_16

        return sizelist[mode]

    def byteRegOffset(self, val):
        # NOTE: Override this because there is no AH etc in 64 bit mode
        return val + e_i386.RMETA_LOW8

    def extended_parse_modrm(self, bytes, offset, opersize, regbase=0):
        """
        Return a tuple of (size, Operand)
        """
        size = 1
        # FIXME this would be best to not parse_modrm twice.  tweak it.
        mod,reg,rm = self.parse_modrm(ord(bytes[offset]))
        if mod == 0 and rm == 5:
            imm = e_bits.parsebytes(bytes, offset + size, 4, sign=True)
            size += 4
            return(size, Amd64RipRelOper(imm, 4))

        return e_i386.i386Disasm.extended_parse_modrm(self, bytes, offset, opersize, regbase)

    # NOTE: Override a bunch of the address modes to account for REX
    def ameth_0(self, operflags, operval, tsize, prefixes):
        o = e_i386.i386Disasm.ameth_0(self, operflags, operval, tsize, prefixes)
        # If it has a builtin register, we need to check for bump prefix
        if prefixes & PREFIX_REX_B and isinstance(o, e_i386.i386RegOper):
            o.reg += REX_BUMP
        return o

    def ameth_g(self, bytes, offset, tsize, prefixes):
        osize, oper = e_i386.i386Disasm.ameth_g(self, bytes, offset, tsize, prefixes)
        if oper.tsize == 4 and oper.reg != REG_RIP:
            oper.reg += RMETA_LOW32
        if prefixes & PREFIX_REX_R:
            oper.reg += REX_BUMP
        return osize, oper

    def ameth_c(self, bytes, offset, tsize, prefixes):
        osize, oper = e_i386.i386Disasm.ameth_c(self, bytes, offset, tsize, prefixes)
        if prefixes & PREFIX_REX_R:
            oper.reg += REX_BUMP
        return osize,oper

    def ameth_d(self, bytes, offset, tsize, prefixes):
        osize, oper = e_i386.i386Disasm.ameth_d(self, bytes, offset, tsize, prefixes)
        if prefixes & PREFIX_REX_R:
            oper.reg += REX_BUMP
        return osize,oper

    def ameth_v(self, bytes, offset, tsize, prefixes):
        osize, oper = e_i386.i386Disasm.ameth_v(self, bytes, offset, tsize, prefixes)
        if prefixes & PREFIX_REX_R:
            oper.reg += REX_BUMP
        return osize,oper

    # NOTE: The ones below are the only ones to which REX.X or REX.B can apply (besides ameth_0)
    def _dis_rex_exmodrm(self, oper, prefixes):
        # REMEMBER: all extended mod RM reg fields come from the r/m part.  If it
        #           were actually just the reg part, it'd be in one of the above
        #           addressing modes...
        if getattr(oper, "index", None) != None:
            if oper.tsize == 4:
                oper.index += RMETA_LOW32
            if prefixes & PREFIX_REX_X:
                oper.index += REX_BUMP
            # Adjust the size if needed

        # oper.reg will be r/m or SIB base
        if getattr(oper, "reg", None) != None:
            # Adjust the size if needed
            if oper.tsize == 4:
                oper.reg += RMETA_LOW32

            if prefixes & PREFIX_REX_B:
                oper.reg += REX_BUMP

    def ameth_e(self, bytes, offset, tsize, prefixes):
        osize, oper = e_i386.i386Disasm.ameth_e(self, bytes, offset, tsize, prefixes)
        self._dis_rex_exmodrm(oper, prefixes)
        return osize, oper

    def ameth_w(self, bytes, offset, tsize, prefixes):
        osize, oper = e_i386.i386Disasm.ameth_w(self, bytes, offset, tsize, prefixes)
        self._dis_rex_exmodrm(oper, prefixes)
        return osize,oper



if __name__ == '__main__':
    import sys
    d = Amd64Disasm()
    b = file(sys.argv[1], 'rb').read()
    offset = 0
    va = 0x41414141
    while offset < len(b):
        op = d.disasm(b, offset, va+offset)
        print '0x%.8x %s %s' % (va+offset, b[offset:offset+len(op)].encode('hex').ljust(16), repr(op))
        offset += len(op)

