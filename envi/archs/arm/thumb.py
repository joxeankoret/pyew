
import envi.bits as e_bits
from envi.bits import binary
import envi.bintree as e_btree

import envi.archs.arm.disasm as arm_dis
import envi.archs.arm.regs as arm_reg

thumb_32 = [
        binary('11101'),
        binary('11110'),
        binary('11111'),
]

O_REG = 0
O_IMM = 1

def shmaskval(value, shval, mask):  #FIXME: unnecessary to make this another fn call.  will be called a bajillion times.
    return (value >> shval) & mask

class simpleops:
    def __init__(self, *operdef):
        self.operdef = operdef

    def __call__(self, va, value):
        ret = []
        for otype, shval, mask in self.operdef:
            oval = shmaskval(value, shval, mask)

            ret.append( (value >> shval) )

imm5_rm_rd  = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7), (O_IMM, 6, 0x1f))
rm_rn_rd    = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7), (O_REG, 6, 0x7))
imm3_rn_rd  = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7), (O_IMM, 6, 0x7))
imm8_rd     = simpleops((O_REG, 8, 0x7), (O_IMM, 0, 0xff))
rm_rd       = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7))
rn_rdm      = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7))
rm_rdn      = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7))
rm_rd_imm0  = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7), (O_IMM, 0, 0))
rm4_shift3  = simpleops((O_REG, 3, 0xf))
rm_rn_rt    = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7), (O_REG, 6, 0x7))
imm8        = simpleops((O_IMM, 8, 0xff))
imm11       = simpleops((O_IMM, 11, 0x7ff))

sh4_imm1    = simpleops((O_IMM, 3, 0x1))

def d1_rm4_rd3(va, value):
    # 0 1 0 0 0 1 0 0 DN(1) Rm(4) Rdn(3)
    rdbit = shmaskval(value, 4, 0x8)
    rd = shmaskval(value, 0, 0x7) + rdbit
    rm = shmaskval(value, 3, 0xf)
    return ArmRegOper(rd),ArmRegOper(rn)

def rm_rn_rt(va, value):
    rt = shmask(value, 0, 0x7) # target
    rn = shmask(value, 3, 0x7) # base
    rm = shmask(value, 6, 0x7) # offset
    oper0 = arm_dis.ArmRegOper(rt)
    oper1 = arm_dis.ArmRegOffsetOper(rn, rm, va)
    return oper0,oper1

def imm5_rn_rt(va, value):
    imm = shmask(value, 6, 0x1f)
    rn = shmask(value, 3, 0x7)
    rt = shmask(value, 0, 0x7)
    oper0 = arm_dis.ArmRegOper(rt)
    oper1 = arm_dis.ArmImmOffsetOper(rn, imm, va)
    return oper0,oper1

def rd_sp_imm8(va, value):
    rd = shmask(value, 8, 0x7)
    imm = shmask(value, 0, 0xff)
    oper0 = arm_dis.ArmRegOper(rd)
    # pre-compute PC relative addr
    oper1 = arm_dis.ArmImmOffsetOper(REG_SP, imm)
    return oper0,oper1

def rd_pc_imm8(va, value):
    rd = shmask(value, 8, 0x7)
    imm = shmask(value, 0, 0xff)
    oper0 = arm_dis.ArmRegOper(rd)
    # pre-compute PC relative addr
    oper1 = arm_dis.ArmImmOper(va+imm)
    return oper0,oper1

def rt_pc_imm8(va, value):
    rt = shmask(value, 8, 0x7)
    imm = shmask(value, 0, 0xff)
    oper0 = arm_dis.ArmRegOper(rt)
    oper1 = arm_dis.ArmImmOffsetOper() # FIXME offset from PC
    return oper0,oper1

def ldmia(va, value): 
    rd = shmask(value, 8, 0x7)
    reg_list = value & 0xff
    oper0 = arm_dis.ArmRegOper(rd)
    oper1 = arm_dis.ArmRegListOper(reg_list)
    flags = 1<<11   # W flag indicating that write back should occur (marked by "!")
    return oper0,oper1

def sp_sp_imm7(va, value):
    imm = shmask(value, 0, 0x7f)
    o0 = arm_dis.ArmRegOper(arm_reg.REG_SP)
    o1 = arm_dis.ArmRegOper(arm_reg.REG_SP)
    o2 = arm_dis.ArmImmOper(imm*4)
    return o0,o1,o2

def rm_reglist(va, value):
    rm = shmask(value, 8, 0x7)
    reglist = value & 0xff
    oper0 = arm_dis.ArmRegOper(rm)
    oper1 = arm_dis.ArmReglistOper(reglist)
    return oper0,oper1


# opinfo is:
# ( <mnem>, <operdef>, <flags> )
# operdef is:
# ( (otype, oshift, omask), ...)
thumb_table = [
    ('00000',       ('lsl',     imm5_rm_rd, 0)), # LSL<c> <Rd>,<Rm>,#<imm5>
    ('00001',       ('lsr',     imm5_rm_rd, 0)), # LSR<c> <Rd>,<Rm>,#<imm>
    ('00010',       ('asr',     imm5_rm_rd, 0)), # ASR<c> <Rd>,<Rm>,#<imm>
    ('0001100',     ('add',     rm_rn_rd,   0)), # ADD<c> <Rd>,<Rn>,<Rm>
    ('0001101',     ('sub',     rm_rn_rd,   0)), # SUB<c> <Rd>,<Rn>,<Rm>
    ('0001110',     ('add',     imm3_rn_rd, 0)), # ADD<c> <Rd>,<Rn>,#<imm3>
    ('0001111',     ('sub',     imm3_rn_rd, 0)), # SUB<c> <Rd>,<Rn>,#<imm3>
    ('00100',       ('mov',     imm8_rd,    0)), # MOV<c> <Rd>,#<imm8>
    ('00101',       ('cmp',     imm8_rd,    0)), # CMP<c> <Rn>,#<imm8>
    ('00110',       ('add',     imm8_rd,    0)), # ADD<c> <Rdn>,#<imm8>
    ('00111',       ('sub',     imm8_rd,    0)), # SUB<c> <Rdn>,#<imm8>
    # Data processing instructions
    ('0100000000',  ('and',     rm_rdn,     0)), # AND<c> <Rdn>,<Rm>
    ('0100000001',  ('eor',     rm_rdn,     0)), # EOR<c> <Rdn>,<Rm>
    ('0100000010',  ('lsl',     rm_rdn,     0)), # LSL<c> <Rdn>,<Rm>
    ('0100000011',  ('lsr',     rm_rdn,     0)), # LSR<c> <Rdn>,<Rm>
    ('0100000100',  ('asr',     rm_rdn,     0)), # ASR<c> <Rdn>,<Rm>
    ('0100000101',  ('adc',     rm_rdn,     0)), # ADC<c> <Rdn>,<Rm>
    ('0100000110',  ('sbc',     rm_rdn,     0)), # SBC<c> <Rdn>,<Rm>
    ('0100000111',  ('ror',     rm_rdn,     0)), # ROR<c> <Rdn>,<Rm>
    ('0100001000',  ('tst',     rm_rd,      0)), # TST<c> <Rn>,<Rm>
    ('0100001001',  ('rsb',     rm_rd_imm0, 0)), # RSB<c> <Rd>,<Rn>,#0
    ('0100001010',  ('cmp',     rm_rd,      0)), # CMP<c> <Rn>,<Rm>
    ('0100001011',  ('cmn',     rm_rd,      0)), # CMN<c> <Rn>,<Rm>
    ('0100001100',  ('orr',     rm_rdn,     0)), # ORR<c> <Rdn>,<Rm>
    ('0100001101',  ('mul',     rn_rdm,     0)), # MUL<c> <Rdm>,<Rn>,<Rdm>
    ('0100001110',  ('bic',     rm_rdn,     0)), # BIC<c> <Rdn>,<Rm>
    ('0100001111',  ('mvn',     rm_rd,      0)), # MVN<c> <Rd>,<Rm>
    # Special data instructions and branch and exchange
    ('0100010000',  ('add',     d1_rm4_rd3, 0)), # ADD<c> <Rdn>,<Rm>
    ('0100010001',  ('add',     d1_rm4_rd3, 0)), # ADD<c> <Rdn>,<Rm>
    ('010001001',   ('add',     d1_rm4_rd3, 0)), # ADD<c> <Rdn>,<Rm>
    ('0100010101',  ('cmp',     d1_rm4_rd3, 0)), # CMP<c> <Rn>,<Rm>
    ('010001011',   ('cmp',     d1_rm4_rd3, 0)), # CMP<c> <Rn>,<Rm>
    ('0100011000',  ('mov',     d1_rm4_rd3, 0)), # MOV<c> <Rd>,<Rm>
    ('0100011001',  ('mov',     d1_rm4_rd3, 0)), # MOV<c> <Rd>,<Rm>
    ('0100011010',  ('mov',     d1_rm4_rd3, 0)), # MOV<c> <Rd>,<Rm>
    ('010001110',   ('bx',      rm4_shift3, 0)), # BX<c> <Rm>
    ('010001111',   ('blx',     rm4_shift3, 0)), # BLX<c> <Rm>
    # Load from Literal Pool
    ('01001',       ('ldr',     rt_pc_imm8, 0)), # LDR<c> <Rt>,<label>
    # Load/Stor single data item
    ('0101000',     ('str',     rm_rn_rt,   0)), # STR<c> <Rt>,[<Rn>,<Rm>]
    ('0101001',     ('strh',    rm_rn_rt,   0)), # STRH<c> <Rt>,[<Rn>,<Rm>]
    ('0101010',     ('strb',    rm_rn_rt,   0)), # STRB<c> <Rt>,[<Rn>,<Rm>]
    ('0101011',     ('ldrsb',   rm_rn_rt,   0)), # LDRSB<c> <Rt>,[<Rn>,<Rm>]
    ('0101100',     ('ldr',     rm_rn_rt,   0)), # LDR<c> <Rt>,[<Rn>,<Rm>]
    ('0101101',     ('ldrh',    rm_rn_rt,   0)), # LDRH<c> <Rt>,[<Rn>,<Rm>]
    ('0101110',     ('ldrb',    rm_rn_rt,   0)), # LDRB<c> <Rt>,[<Rn>,<Rm>]
    ('0101111',     ('ldrsh',   rm_rn_rt,   0)), # LDRSH<c> <Rt>,[<Rn>,<Rm>]
    ('01100',       ('str',     imm5_rn_rt, 0)), # STR<c> <Rt>, [<Rn>{,#<imm5>}]
    ('01101',       ('ldr',     imm5_rn_rt, 0)), # LDR<c> <Rt>, [<Rn>{,#<imm5>}]
    ('01110',       ('strb',    imm5_rn_rt, 0)), # STRB<c> <Rt>,[<Rn>,#<imm5>]
    ('01111',       ('ldrb',    imm5_rn_rt, 0)), # LDRB<c> <Rt>,[<Rn>{,#<imm5>}]
    ('10000',       ('strh',    imm5_rn_rt, 0)), # STRH<c> <Rt>,[<Rn>{,#<imm>}]
    ('10001',       ('ldrh',    imm5_rn_rt, 0)), # LDRH<c> <Rt>,[<Rn>{,#<imm>}]
    ('10010',       ('str',     imm5_rn_rt, 0)), # STR<c> <Rt>, [<Rn>{,#<imm>}]
    ('10011',       ('ldr',     imm5_rn_rt, 0)), # LDR<c> <Rt>, [<Rn>{,#<imm>}]
    # Generate PC relative address
    ('10100',       ('add',     rd_pc_imm8, 0)), # ADD<c> <Rd>,<label>
    # Generate SP relative address
    ('10101',       ('add',     rd_sp_imm8, 0)), # ADD<c> <Rd>,SP,#<imm>
    # Miscellaneous instructions
    ('10110110010', ('setend',  sh4_imm1,   0)), # SETEND <endian_specifier>
    ('10110110011', ('cps',     simpleops(),0)), # CPS<effect> <iflags> FIXME
    ('1011101000',  ('rev',     rn_rdm,     0)), # REV Rd, Rn
    ('1011101001',  ('rev16',   rn_rdm,     0)), # REV16 Rd, Rn
    ('1011101011',  ('revsh',   rn_rdm,     0)), # REVSH Rd, Rn
    ('101100000',   ('add',     sp_sp_imm7, 0)), # ADD<c> SP,SP,#<imm>
    ('101100001',   ('sub',     sp_sp_imm7, 0)), # SUB<c> SP,SP,#<imm>
    ('10111110',    ('bkpt',    imm8,       0)), # BKPT <blahblah>
    # Load / Store Multiple
    ('11000',       ('stmia',   rm_reglist, 0x800)), # LDMIA Rd!, reg_list
    ('11001',       ('ldmia',   rm_reglist, 0x800)), # STMIA Rd!, reg_list
    # Conditional Branches
    ('11010000',    ('b',       imm8,       0)),
    ('11010001',    ('bn',      imm8,       0)),
    ('11010010',    ('bz',      imm8,       0)),
    ('11010011',    ('bnz',     imm8,       0)),
    ('11010100',    ('bc',      imm8,       0)),
    ('11010101',    ('bnc',     imm8,       0)),
    ('11010100',    ('bzc',     imm8,       0)),
    ('11010111',    ('bnzc',    imm8,       0)),
    ('11011000',    ('bv',      imm8,       0)),
    ('11011001',    ('bnv',     imm8,       0)),
    ('11011010',    ('bzv',     imm8,       0)),
    ('11011011',    ('bnzv',    imm8,       0)),
    ('11011100',    ('bcv',     imm8,       0)),
    ('11011101',    ('bncv',    imm8,       0)),
    ('11011110',    ('bzcv',    imm8,       0)),
    ('11011111',    ('bnzcv',   imm8,       0)),
    # Software Interrupt
    ('11011111',    ('swi',     imm8,       0)), # SWI <blahblah>
    ('11100',       ('b',       imm11,      0)), # B <addr11> 
    ('11101',       ('blx',     imm11,      0)), # BLX suffix <addr11>  -- SEE p542 of 14218.pdf manual for how this if gonna fuck with emulation. 
    ('11110',       ('bl',      imm11,      0)), # BL/BLX prefix <addr11> -- SEE p542 of 14218.pdf manual for how this if gonna fuck with emulation. 
    ('11111',       ('blx',     imm11,      0)), # BL suffix <addr11>   -- SEE p542 of 14218.pdf manual for how this if gonna fuck with emulation.
]

ttree = e_btree.BinaryTree()
for binstr, opinfo in thumb_table:
    ttree.addBinstr(binstr, opinfo)

thumb32mask = binary('11111')
thumb32min  = binary('11100')

def is_thumb32(val):
    '''
    Take a 16 bit integer (opcode) value and determine
    if it is really the first 16 bits of a 32 bit
    instruction.
    '''
    bval = val >> 11
    return (bval & thumb32mask) > thumb32min


class ThumbOpcode(arm_dis.ArmOpcode):
    pass

class ArmThumbDisasm(arm_dis.ArmDisasmChild):
    def disasm(self, bytes, offset, va, trackMode=True):
        val = struct.unpack("<L", bytes[offset:offset+2])
        mnem, opermkr, flags = ttree.getInstr(val)
        olist = opermkr(va, val)

        op = ThumbOpcode(va, opcode, mnem, 0xe, 2, olist, flags)
        return op
        raise Exception("ummm. you could try Implementing disasm first... duh.")
