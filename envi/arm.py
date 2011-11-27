
"""
The initial arm module.
"""

import struct

import envi

# FIXME put this in envi bits.
def binary(s):
    x = 0
    for c in s:
        x = (x << 1) + int(c)
    return x

# Universal opcode things:
# len
# mode

IF_PSR_S = 0x100

COND_EQ     = 0x0        # z==1  (equal)
COND_NE     = 0x1        # z==0  (not equal)
COND_CS     = 0x2        # c==1  (carry set/unsigned higher or same)
COND_CC     = 0x3        # c==0  (carry clear/unsigned lower)
COND_MI     = 0x4        # n==1  (minus/negative)
COND_PL     = 0x5        # n==0  (plus/positive or zero)
COND_VS     = 0x6        # v==1  (overflow)
COND_VC     = 0x7        # v==0  (no overflow)
COND_HI     = 0x8        # c==1 and z==0  (unsigned higher)
COND_LO     = 0x9        # c==0  or z==1  (unsigned lower or same)
COND_GE     = 0xA        # n==v  (signed greater than or equal)  (n==1 and v==1) or (n==0 and v==0)
COND_LT     = 0xB        # n!=v  (signed less than)  (n==1 and v==0) or (n==0 and v==1)
COND_GT     = 0xC        # z==0 and n==v (signed greater than)
COND_LE     = 0xD        # z==1 and n!=v (signed less than or equal)
COND_AL     = 0xE        # always
COND_EXTENDED = 0xF        # special case - see conditional 0b1111

COND_EQ = 0
COND_NE = 1
COND_CS = 2
COND_CC = 3
COND_MI = 4
COND_PL = 5
COND_VS = 6
COND_VC = 7
COND_HI = 8
COND_LS = 9
COND_GE = 10
COND_LT = 11
COND_GT = 12
COND_LE = 13
COND_AL = 14
COND_EXTENDED = 15

cond_codes = {
COND_EQ:"EQ", # Equal Z set 
COND_NE:"NE", # Not equal Z clear 
COND_CS:"CS", #/HS Carry set/unsigned higher or same C set 
COND_CC:"CC", #/LO Carry clear/unsigned lower C clear 
COND_MI:"MI", # Minus/negative N set 
COND_PL:"PL", # Plus/positive or zero N clear 
COND_VS:"VS", # Overflow V set 
COND_VC:"VC", # No overflow V clear 
COND_HI:"HI", # Unsigned higher C set and Z clear 
COND_LS:"LS", # Unsigned lower or same C clear or Z set 
COND_GE:"GE", # Signed greater than or equal N set and V set, or N clear and V clear (N == V) 
COND_LT:"LT", # Signed less than N set and V clear, or N clear and V set (N!= V) 
COND_GT:"GT", # Signed greater than Z clear, and either N set and V set, or N clear and V clear (Z == 0,N == V) 
COND_LE:"LE", # Signed less than or equal Z set, or N set and V clear, or N clear and V set (Z == 1 or N!= V) 
COND_AL:"AL", # Always (unconditional) - 
COND_EXTENDED:"EXTENDED", # See extended opcode table
}

INST_ENC_DP_IMM = 0 # Data Processing Immediate Shift
INST_ENC_MISC   = 1 # Misc Instructions

# Instruction encodings in arm v5
IENC_DP_IMM_SHIFT = 0 # Data processing immediate shift
IENC_MISC         = 1 # Miscellaneous instructions
IENC_DP_REG_SHIFT = 2 # Data processing register shift
IENC_MISC1        = 3 # Miscellaneous instructions again
IENC_MULT         = 4 # Multiplies & Extra load/stores
IENC_DP_IMM       = 5 # Data processing immediate
IENC_UNDEF        = 6 # Undefined instruction
IENC_MOV_IMM_STAT = 7 # Move immediate to status register
IENC_LOAD_IMM_OFF = 8 # Load/Store immediate offset
IENC_LOAD_REG_OFF = 9 # Load/Store register offset
IENC_MEDIA        = 10 # Media instructions
IENC_ARCH_UNDEF   = 11 # Architecturally undefined
IENC_LOAD_MULT    = 12 # Load/Store Multiple
IENC_BRANCH       = 13 # Branch
IENC_COPROC_LOAD  = 14 # Coprocessor load/store and double reg xfers
IENC_COPROC_DP    = 15 # Coprocessor data processing
IENC_COPROC_REG_XFER = 16 # Coprocessor register transfers
IENC_SWINT        = 17 # Sofware interrupts

####################################################################
# Parsers for the multiply family of instruction encodings

def chopmul(opcode):
    op1 = (opcode >> 20) & 0xff
    a = (opcode >> 16) & 0xf
    b = (opcode >> 12) & 0xf
    c = (opcode >> 8)  & 0xf
    d = (opcode >> 4)  & 0xf
    e = opcode & 0xf
    return (op1<<4)+d,(a,b,c,d,e)

# The keys in this table are made of the
# concat of bits 27-21 and 7-4 (only when
# ienc == mul!
iencmul_codes = {
    # Basic multiplication opcodes
    binary("000000001001"): ("mul",(0,4,2), 0),
    binary("000000011001"): ("mul",(0,4,2), IF_PSR_S),
    binary("000000101001"): ("mla",(0,4,2,1), 0),
    binary("000000111001"): ("mla",(0,4,2,1), IF_PSR_S),
    binary("000001001001"): ("umaal",(1,0,4,2), 0),
    binary("000010001001"): ("umull",(1,0,4,2), 0),
    binary("000010011001"): ("umull",(1,0,4,2), IF_PSR_S),
    binary("000010101001"): ("umlal",(1,0,4,2), 0),
    binary("000010111001"): ("umlal",(1,0,4,2), IF_PSR_S),
    binary("000011001001"): ("smull",(1,0,4,2), 0),
    binary("000011011001"): ("smull",(1,0,4,2), IF_PSR_S),
    binary("000011101001"): ("smlal",(1,0,4,2), 0),
    binary("000011111001"): ("smlal",(1,0,4,2), IF_PSR_S),

    # multiplys with <x><y>
    # "B"
    binary("000100001000"): ("smlabb", (0,4,2,1), 0),
    binary("000100001010"): ("smlatb", (0,4,2,1), 0),
    binary("000100001100"): ("smlabt", (0,4,2,1), 0),
    binary("000100001110"): ("smlatt", (0,4,2,1), 0),
    binary("000100101010"): ("smulwb", (0,4,2), 0),
    binary("000100101110"): ("smulwt", (0,4,2), 0),
    binary("000100101000"): ("smlawb", (0,4,2), 0),
    binary("000100101100"): ("smlawt", (0,4,2), 0),
    binary("000101001000"): ("smlalbb", (1,0,4,2), 0),
    binary("000101001010"): ("smlaltb", (1,0,4,2), 0),
    binary("000101001100"): ("smlalbt", (1,0,4,2), 0),
    binary("000101001110"): ("smlaltt", (1,0,4,2), 0),
    binary("000101101000"): ("smulbb", (0,4,2), 0),
    binary("000101101010"): ("smultb", (0,4,2), 0),
    binary("000101101100"): ("smulbt", (0,4,2), 0),
    binary("000101101110"): ("smultt", (0,4,2), 0),

    # type 2 multiplys

    binary("011100000001"): ("smuad", (0,4,2), 0),
    binary("011100000011"): ("smuadx", (0,4,2), 0),
    binary("011100000101"): ("smusd", (0,4,2), 0),
    binary("011100000111"): ("smusdx", (0,4,2), 0),
    binary("011100000001"): ("smlad", (0,4,2), 0),
    binary("011100000011"): ("smladx", (0,4,2), 0),
    binary("011100000101"): ("smlsd", (0,4,2), 0),
    binary("011100000111"): ("smlsdx", (0,4,2), 0),
    binary("011101000001"): ("smlald", (0,4,2), 0),
    binary("011101000011"): ("smlaldx", (0,4,2), 0),
    binary("011101000101"): ("smlsld", (0,4,2), 0),
    binary("011101000111"): ("smlsldx", (0,4,2), 0),
    binary("011101010001"): ("smmla", (0,4,2,1), 0),
    binary("011101010011"): ("smmlar", (0,4,2,1), 0),
    binary("011101011101"): ("smmls", (0,4,2,1), 0),
    binary("011101011111"): ("smmlsr", (0,4,2,1), 0),
    binary("011101010001"): ("smmul", (0,4,2), 0),
    binary("011101010011"): ("smmulr", (0,4,2), 0),
}

####################################################################
# Mnemonic tables for opcode based mnemonic lookup

# Dataprocessing mnemonics
dp_mnem = ("and","eor","sub","rsb","add","adc","sbc","rsc","tst","teq","cmp","cmn","orr","mov","bic","mvn"),
misc_mnem = ("mrs","msr","bxj")

def dpbase(opval):
    """
    Parse and return opcode,sflag,Rn,Rd for a standard
    dataprocessing instruction.
    """
    ocode = (opval >> 21) & 0xf
    sflag = (opval >> 20) & 0x1
    Rn = (opval >> 16) & 0xf
    Rd = (opval >> 12) & 0xf
    #print "DPBASE:",ocode,sflag,Rn,Rd
    return ocode,sflag,Rn,Rd

####################################################################
# Parser functions for each of the instruction encodings

def p_dp_imm_shift(opval):
    ocode,sflag,Rn,Rd = dpbase(opval)
    Rm = opval & 0xf
    shtype = (opval >> 5) & 0x3
    shval = (opval >> 7) & 0x1f

    olist = [
        ArmOperand(OM_REG, Rn),
        ArmOperand(OM_REG, Rd),
        ArmOperand(OM_REG, Rm, shtype=shtype, shval=shval),
    ]

    opcode = (IENC_DP_IMM_SHIFT << 16) + ocode
    return ArmOpcode(opcode, dp_mnem[ocode], olist)

def p_misc(opval):
    pass

def p_dp_reg_shift(opval):
    ocode,sflag,Rn,Rd = dpbase(opval)
    Rm = opval & 0xf
    shtype = (opval >> 5) & 0x3
    Rs = (opval >> 8) & 0xf

    olist = [
        ArmOperand(OM_REG, Rn),
        ArmOperand(OM_REG, Rd),
        ArmOperand(OM_REG, Rm, oflags=OFLAG_SHIFT_REG, shtype=shtype, shval=shval),
    ]

    opcode = (IENC_DP_IMM_SHIFT << 16) + ocode
    return ArmOpcode(opcode, dp_mnem[ocode], olist)

def p_misc1(opval):
    pass

def p_mult(opval):
    ocode, vals = chopmul(opval)
                             
    mnem, opindexes, flags = iencmul_codes.get(ocode)

    olist = []
    for i in opindexes:
        olist.append(ArmOperand(OM_REG, vals[i]))

    opcode = (IENC_MULT << 16) + ocode
    return ArmOpcode(opcode, mnem, olist, iflags=flags)

def p_dp_imm(opval):
    ocode,sflag,Rn,Rd = dpbase(opval)
    imm = opval & 0xff
    rot = (opval >> 8) & 0xf

def p_undef(opval):
    pass

def p_mov_imm_stat(opval):
    pass

def p_load_imm_off(opval):
    pass

def p_load_reg_off(opval):
    pass

def p_media(opval):
    pass

def p_arch_undef(opval):
    pass

def p_load_mult(opval):
    pass

def p_branch(opval):
    pass

def p_coproc_load(opval):
    pass

def p_coproc_dp(opval):
    pass

def p_coproc_reg_xfer(opval):
    pass

def p_swint(opval):
    pass

####################################################################
# Table of the parser functions

ienc_parsers = (
    p_dp_imm_shift,
    p_misc,
    p_dp_reg_shift,
    p_misc1,
    p_mult,
    p_dp_imm,
    p_undef,
    p_mov_imm_stat,
    p_load_imm_off,
    p_load_reg_off,
    p_media,
    p_arch_undef,
    p_load_mult,
    p_branch,
    p_coproc_load,
    p_coproc_dp,
    p_coproc_reg_xfer,
    p_swint,
)

####################################################################

# the primary table is index'd by the 3 bits following the
# conditional and are structured as follows:
# ( ENC, nexttable )
# If ENC != None, those 3 bits were enough for us to know the
# encoding type, otherwise move on to the second table.

# The secondary tables have the format:
# (mask, value, ENC).  If the opcode is masked with "mask"
# resulting in "value" we have found the instruction encoding.
# NOTE: All entries in these tables *must* be from most specific
# to least!

# Table for initial 3 bit == 0
s_0_table = (
    # Order is critical here...
    (binary("00000001100100000000000000010000"), binary("00000001000000000000000000000000"), IENC_MISC),
    (binary("00000000000000000000000000010000"), binary("00000000000000000000000000000000"), IENC_DP_IMM_SHIFT),
    (binary("00000000000000000000000010010000"), binary("00000000000000000000000010010000"), IENC_MULT),
    (binary("00000001100000000000000010010000"), binary("00000001000000000000000000010000"), IENC_MISC1),
    (binary("00000000000000000000000010010000"), binary("00000000000000000000000000010000"), IENC_DP_REG_SHIFT),
)

s_1_table = (
    (binary("00000001100110000000000000000000"), binary("00000001000000000000000000000000"), IENC_UNDEF),
    (binary("00000001100110000000000000000000"), binary("00000001001000000000000000000000"), IENC_MOV_IMM_STAT),
    (0,0, IENC_DP_IMM),
)

s_3_table = (
    (binary("00000001111100000000000011110000"),binary("00000001111100000000000011110000"), IENC_ARCH_UNDEF),
    (binary("00000000000000000000000000010000"),binary("00000000000000000000000000010000"), IENC_MEDIA),
    (0,0, IENC_LOAD_REG_OFF),
)

s_7_table = (
    (binary("00000001000000000000000000000000"),binary("00000001000000000000000000000000"), IENC_SWINT),
    (binary("00000001000000000000000000010000"),binary("00000000000000000000000000010000"), IENC_COPROC_REG_XFER),
    (0, 0, IENC_COPROC_DP),
)

# Initial 3 (non conditional) primary table
inittable = [
    (None, s_0_table),
    (None, s_1_table),
    (IENC_LOAD_IMM_OFF, None), # Load or store an immediate
    (None, s_3_table),
    (IENC_LOAD_MULT, None),
    (IENC_BRANCH, None),
    (IENC_COPROC_LOAD, None),
    (None, s_7_table),
]

OFLAG_SHIFT_REG = 1 # Is the shval a register?

# The supported types of operand shifts (by the 2 bit field)
S_LSL = 0
S_LSR = 1
S_ASR = 2
S_ROR = 3
S_RRX = 4 # FIXME HACK XXX add this

shift_names = ["lsl", "lsr", "asr", "ror", "rrx"]

# FIXME for emulation...
#def s_lsl(val, shval):
    #pass

#def s_lsr(val, shval):
    #pass

# These are indexed by the 2 bit "shift" value in some DP encodings
#shift_handlers = (
    #s_lsl,
    #s_lsr,
    #s_asr,
    #s_ror,
#)

endian_names = ("LE","BE")

class ArmOpcode(envi.Opcode):

    def __init__(self, opcode, mnem, opers, cond=COND_AL, iflags=0):
        envi.Opcode.__init__(self, opcode, mnem, 0, 4, opers, iflags)
        self.cond = cond

    def __repr__(self):
        x = [self.mnem, cond_codes.get(self.cond)]
        # FIXME put in S flag!
        for o in self.opers:
            x.append(repr(o))
        return " ".join(x)

# Arm specific opcode flags
IF_PSR_S = 0x100    # Instruction updates S field in PSR (for some opcodes it's optional)

OM_IMM = 0          # imm (with possible shift and offset)
OM_REG = 1          # reg (with possible shift and offset)
OM_REG_MULT = 2     # reg is regmask of effected registers
OM_PSR = 3          # Process state register (like intel elfags)
OM_ENDIAN = 4       # boolean operand used in one instruction... *sigh*...
OM_COPROC_OP = 5    # The subsequent opcode for a coprocessing instruction

class ArmOperand(envi.Operand):
    def __init__(self, mode, val, oflags=0, shtype=None, shval=None):
        envi.Operand.__init__(self, mode)
        self.val = val # depending on mode, this is reg/imm
        self.oflags = oflags
        self.shval = shval
        self.shtype = shtype

    def __eq__(self, oper):
        if not envi.Operand.__eq__(self, oper):
            return False
        if self.val != oper.val:
            return False
        if self.oflags != oper.oflags:
            return False
        if self.shval != oper.shval:
            return False
        if self.shtype != oper.shtype:
            return False
        return True

    def __repr__(self):
        if self.mode == OM_IMM:
            return "#%d" % self.val

        if self.mode == OM_REG:
            base = "r%d" % self.val
            if self.shtype != None:
                if self.oflags & OFLAG_SHIFT_REG:
                    base = "%s %s %s" % (base, shift_names[self.shtype], "r%d" % self.shval) # FIXME regnames
                else:
                    base = "%s %s %s" % (base, shift_names[self.shtype], "#%d" % self.shval) # FIXME regnames
            return base

        if self.mode == OM_PSR:
            return "FIXME DO PSR"

        if self.mode == OM_ENDIAN:
            return endian_names[self.val]

        if self.mode == OM_REG_MULT:
            return "FIXME REG MULT"

class ArmModule(envi.ArchitectureModule):

    def __init__(self):
        envi.ArchitectureModule.__init__(self, "armv5", maxinst=4)

    def makeOpcode(self, bytes, offset):
        opval = struct.unpack("<L", bytes[offset:offset+4])[0]

        cond = opval >> 28

        if cond == COND_EXTENDED:
            return "FIXME - make extended opcode parser"

        # Begin the table lookup sequence with the first 3 non-cond bits
        encfam = (opval >> 25) & 0x7
        enc,nexttab = inittable[encfam]
        if nexttab != None: # we have to sub-parse...
            for mask,val,penc in nexttab:
                if (opval & mask) == val:
                    enc = penc
                    break

        # If we don't know the encoding by here, we never will ;)
        if enc == None:
            raise InvalidInstruction("omg")

        #print "ENCFAM",encfam
        #print "COND",cond
        #print "ENCODING",enc

        op = ienc_parsers[enc](opval)
        op.cond = cond

        return op

a = ArmModule()
#a.makeOpcode("\x0d\xc0\xa0\xe1", 0)
#e2833004 add r3, r3, #4
print repr(a.makeOpcode("\x92\x10\x93\x00", 0))
print repr(a.makeOpcode("\x04\x30\x83\xe2", 0))

