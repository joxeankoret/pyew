
import envi.bits as e_bits
import envi.bintree as e_btree

from envi.bits import binary

from envi.archs.arm.armdisasm import *

thumb_32 = [
        binary('11101'),
        binary('11110'),
        binary('11111'),
]


O_REG = 0
O_IMM = 1

OperType = (
    ArmRegOper,
    ArmImmOper,
    )
def shmaskval(value, shval, mask):  #FIXME: unnecessary to make this another fn call.  will be called a bajillion times.
    return (value >> shval) & mask

class simpleops:
    def __init__(self, *operdef):
        self.operdef = operdef

    def __call__(self, va, value):
        ret = []
        for otype, shval, mask in self.operdef:
            oval = shmaskval(value, shval, mask)
            oper = OperType[otype]((value >> shval) & mask)
            ret.append( oper )
        return ret

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
    return ArmRegOper(rd),ArmRegOper(rm)

def rm_rn_rt(va, value):
    rt = shmaskval(value, 0, 0x7) # target
    rn = shmaskval(value, 3, 0x7) # base
    rm = shmaskval(value, 6, 0x7) # offset
    oper0 = ArmRegOper(rt)
    oper1 = ArmRegOffsetOper(rn, rm, va)
    return oper0,oper1

def imm5_rn_rt(va, value):
    imm = shmaskval(value, 6, 0x1f)
    rn = shmaskval(value, 3, 0x7)
    rt = shmaskval(value, 0, 0x7)
    oper0 = ArmRegOper(rt)
    oper1 = ArmImmOffsetOper(rn, imm, va)
    return oper0,oper1

def rd_sp_imm8(va, value):
    rd = shmaskval(value, 8, 0x7)
    imm = shmaskval(value, 0, 0xff) * 4
    oper0 = ArmRegOper(rd)
    # pre-compute PC relative addr
    oper1 = ArmImmOffsetOper(REG_SP, imm, va)
    return oper0,oper1

def rd_pc_imm8(va, value):
    rd = shmaskval(value, 8, 0x7)
    imm = shmaskval(value, 0, 0xff) * 4
    oper0 = ArmRegOper(rd)
    # pre-compute PC relative addr
    oper1 = ArmImmOper(va+imm)
    return oper0,oper1

def rt_pc_imm8(va, value):
    rt = shmaskval(value, 8, 0x7)
    imm = shmaskval(value, 0, 0xff) * 4
    oper0 = ArmRegOper(rt)
    oper1 = ArmImmOffsetOper(rt, imm, va) # FIXME offset from PC
    return oper0,oper1

def ldmia(va, value): 
    rd = shmaskval(value, 8, 0x7)
    reg_list = value & 0xff
    oper0 = ArmRegOper(rd)
    oper1 = ArmRegListOper(reg_list)
    flags = 1<<11   # W flag indicating that write back should occur (marked by "!")
    return oper0,oper1

def sp_sp_imm7(va, value):
    imm = shmaskval(value, 0, 0x7f)
    o0 = ArmRegOper(REG_SP)
    o1 = ArmRegOper(REG_SP)
    o2 = ArmImmOper(imm*4)
    return o0,o1,o2

def rm_reglist(va, value):
    rm = shmaskval(value, 8, 0x7)
    reglist = value & 0xff
    oper0 = ArmRegOper(rm)
    oper1 = ArmRegListOper(reglist)
    return oper0,oper1


# opinfo is:
# ( <mnem>, <operdef>, <flags> )
# operdef is:
# ( (otype, oshift, omask), ...)
thumb_table = [
    ('00000',       ( 0,'lsl',     imm5_rm_rd, 0)), # LSL<c> <Rd>,<Rm>,#<imm5>
    ('00001',       ( 1,'lsr',     imm5_rm_rd, 0)), # LSR<c> <Rd>,<Rm>,#<imm>
    ('00010',       ( 2,'asr',     imm5_rm_rd, 0)), # ASR<c> <Rd>,<Rm>,#<imm>
    ('0001100',     ( 3,'add',     rm_rn_rd,   0)), # ADD<c> <Rd>,<Rn>,<Rm>
    ('0001101',     ( 4,'sub',     rm_rn_rd,   0)), # SUB<c> <Rd>,<Rn>,<Rm>
    ('0001110',     ( 5,'add',     imm3_rn_rd, 0)), # ADD<c> <Rd>,<Rn>,#<imm3>
    ('0001111',     ( 6,'sub',     imm3_rn_rd, 0)), # SUB<c> <Rd>,<Rn>,#<imm3>
    ('00100',       ( 7,'mov',     imm8_rd,    0)), # MOV<c> <Rd>,#<imm8>
    ('00101',       ( 8,'cmp',     imm8_rd,    0)), # CMP<c> <Rn>,#<imm8>
    ('00110',       ( 9,'add',     imm8_rd,    0)), # ADD<c> <Rdn>,#<imm8>
    ('00111',       (10,'sub',     imm8_rd,    0)), # SUB<c> <Rdn>,#<imm8>
    # Data processing instructions
    ('0100000000',  (11,'and',     rm_rdn,     0)), # AND<c> <Rdn>,<Rm>
    ('0100000001',  (12,'eor',     rm_rdn,     0)), # EOR<c> <Rdn>,<Rm>
    ('0100000010',  (13,'lsl',     rm_rdn,     0)), # LSL<c> <Rdn>,<Rm>
    ('0100000011',  (14,'lsr',     rm_rdn,     0)), # LSR<c> <Rdn>,<Rm>
    ('0100000100',  (15,'asr',     rm_rdn,     0)), # ASR<c> <Rdn>,<Rm>
    ('0100000101',  (16,'adc',     rm_rdn,     0)), # ADC<c> <Rdn>,<Rm>
    ('0100000110',  (17,'sbc',     rm_rdn,     0)), # SBC<c> <Rdn>,<Rm>
    ('0100000111',  (18,'ror',     rm_rdn,     0)), # ROR<c> <Rdn>,<Rm>
    ('0100001000',  (19,'tst',     rm_rd,      0)), # TST<c> <Rn>,<Rm>
    ('0100001001',  (20,'rsb',     rm_rd_imm0, 0)), # RSB<c> <Rd>,<Rn>,#0
    ('0100001010',  (21,'cmp',     rm_rd,      0)), # CMP<c> <Rn>,<Rm>
    ('0100001011',  (22,'cmn',     rm_rd,      0)), # CMN<c> <Rn>,<Rm>
    ('0100001100',  (23,'orr',     rm_rdn,     0)), # ORR<c> <Rdn>,<Rm>
    ('0100001101',  (24,'mul',     rn_rdm,     0)), # MUL<c> <Rdm>,<Rn>,<Rdm>
    ('0100001110',  (25,'bic',     rm_rdn,     0)), # BIC<c> <Rdn>,<Rm>
    ('0100001111',  (26,'mvn',     rm_rd,      0)), # MVN<c> <Rd>,<Rm>
    # Special data in2tructions and branch and exchange
    ('0100010000',  (27,'add',     d1_rm4_rd3, 0)), # ADD<c> <Rdn>,<Rm>
    ('0100010001',  (28,'add',     d1_rm4_rd3, 0)), # ADD<c> <Rdn>,<Rm>
    ('010001001',   (29,'add',     d1_rm4_rd3, 0)), # ADD<c> <Rdn>,<Rm>
    ('0100010101',  (30,'cmp',     d1_rm4_rd3, 0)), # CMP<c> <Rn>,<Rm>
    ('010001011',   (31,'cmp',     d1_rm4_rd3, 0)), # CMP<c> <Rn>,<Rm>
    ('0100011000',  (32,'mov',     d1_rm4_rd3, 0)), # MOV<c> <Rd>,<Rm>
    ('0100011001',  (33,'mov',     d1_rm4_rd3, 0)), # MOV<c> <Rd>,<Rm>
    ('0100011010',  (34,'mov',     d1_rm4_rd3, 0)), # MOV<c> <Rd>,<Rm>
    ('010001110',   (35,'bx',      rm4_shift3, 0)), # BX<c> <Rm>
    ('010001111',   (36,'blx',     rm4_shift3, 0)), # BLX<c> <Rm>
    # Load from Litera7 Pool
    ('01001',       (37,'ldr',     rt_pc_imm8, 0)), # LDR<c> <Rt>,<label>
    # Load/Stor single data item
    ('0101000',     (38,'str',     rm_rn_rt,   0)), # STR<c> <Rt>,[<Rn>,<Rm>]
    ('0101001',     (39,'strh',    rm_rn_rt,   0)), # STRH<c> <Rt>,[<Rn>,<Rm>]
    ('0101010',     (40,'strb',    rm_rn_rt,   0)), # STRB<c> <Rt>,[<Rn>,<Rm>]
    ('0101011',     (41,'ldrsb',   rm_rn_rt,   0)), # LDRSB<c> <Rt>,[<Rn>,<Rm>]
    ('0101100',     (42,'ldr',     rm_rn_rt,   0)), # LDR<c> <Rt>,[<Rn>,<Rm>]
    ('0101101',     (43,'ldrh',    rm_rn_rt,   0)), # LDRH<c> <Rt>,[<Rn>,<Rm>]
    ('0101110',     (44,'ldrb',    rm_rn_rt,   0)), # LDRB<c> <Rt>,[<Rn>,<Rm>]
    ('0101111',     (45,'ldrsh',   rm_rn_rt,   0)), # LDRSH<c> <Rt>,[<Rn>,<Rm>]
    ('01100',       (46,'str',     imm5_rn_rt, 0)), # STR<c> <Rt>, [<Rn>{,#<imm5>}]
    ('01101',       (47,'ldr',     imm5_rn_rt, 0)), # LDR<c> <Rt>, [<Rn>{,#<imm5>}]
    ('01110',       (48,'strb',    imm5_rn_rt, 0)), # STRB<c> <Rt>,[<Rn>,#<imm5>]
    ('01111',       (49,'ldrb',    imm5_rn_rt, 0)), # LDRB<c> <Rt>,[<Rn>{,#<imm5>}]
    ('10000',       (50,'strh',    imm5_rn_rt, 0)), # STRH<c> <Rt>,[<Rn>{,#<imm>}]
    ('10001',       (51,'ldrh',    imm5_rn_rt, 0)), # LDRH<c> <Rt>,[<Rn>{,#<imm>}]
    ('10010',       (52,'str',     imm5_rn_rt, 0)), # STR<c> <Rt>, [<Rn>{,#<imm>}]
    ('10011',       (53,'ldr',     imm5_rn_rt, 0)), # LDR<c> <Rt>, [<Rn>{,#<imm>}]
    # Generate PC rel54ive address
    ('10100',       (54,'add',     rd_pc_imm8, 0)), # ADD<c> <Rd>,<label>
    # Generate SP rel5tive address
    ('10101',       (55,'add',     rd_sp_imm8, 0)), # ADD<c> <Rd>,SP,#<imm>
    # Miscellaneous in6tructions
    ('10110110010', (56,'setend',  sh4_imm1,   0)), # SETEND <endian_specifier>
    ('10110110011', (57,'cps',     simpleops(),0)), # CPS<effect> <iflags> FIXME
    ('1011101000',  (58,'rev',     rn_rdm,     0)), # REV Rd, Rn
    ('1011101001',  (59,'rev16',   rn_rdm,     0)), # REV16 Rd, Rn
    ('1011101011',  (60,'revsh',   rn_rdm,     0)), # REVSH Rd, Rn
    ('101100000',   (61,'add',     sp_sp_imm7, 0)), # ADD<c> SP,SP,#<imm>
    ('101100001',   (62,'sub',     sp_sp_imm7, 0)), # SUB<c> SP,SP,#<imm>
    ('10111110',    (63,'bkpt',    imm8,       0)), # BKPT <blahblah>
    # Load / Store Mu64iple
    ('11000',       (64,'stmia',   rm_reglist, 0x800)), # LDMIA Rd!, reg_list
    ('11001',       (65,'ldmia',   rm_reglist, 0x800)), # STMIA Rd!, reg_list
    # Conditional Bran6hes
    ('11010000',    (66,'b',       imm8,       0)),
    ('11010001',    (67,'bn',      imm8,       0)),
    ('11010010',    (68,'bz',      imm8,       0)),
    ('11010011',    (69,'bnz',     imm8,       0)),
    ('11010100',    (70,'bc',      imm8,       0)),
    ('11010101',    (71,'bnc',     imm8,       0)),
    ('11010100',    (72,'bzc',     imm8,       0)),
    ('11010111',    (73,'bnzc',    imm8,       0)),
    ('11011000',    (74,'bv',      imm8,       0)),
    ('11011001',    (75,'bnv',     imm8,       0)),
    ('11011010',    (76,'bzv',     imm8,       0)),
    ('11011011',    (77,'bnzv',    imm8,       0)),
    ('11011100',    (78,'bcv',     imm8,       0)),
    ('11011101',    (79,'bncv',    imm8,       0)),
    ('11011110',    (80,'bzcv',    imm8,       0)),
    ('11011111',    (81,'bnzcv',   imm8,       0)),
    # Software Interru2t
    ('11011111',    (82,'swi',     imm8,       0)), # SWI <blahblah>
    ('11100',       (83,'b',       imm11,      0)), # B <addr11> 
    ('11101',       (84,'blx',     imm11,      0)), # BLX suffix <addr11>  -- SEE p542 of 14218.pdf manual for how this if gonna fuck with emulation. 
    ('11110',       (85,'bl',      imm11,      0)), # BL/BLX prefix <addr11> -- SEE p542 of 14218.pdf manual for how this if gonna fuck with emulation. 
    ('11111',       (86,'blx',     imm11,      0)), # BL suffix <addr11>   -- SEE p542 of 14218.pdf manual for how this if gonna fuck with emulation.
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


class ThumbOpcode(ArmOpcode):
    pass

class ArmThumbDisasm:

    def disasm(self, bytes, offset, va, trackMode=True):
        val, = struct.unpack("H", bytes[offset:offset+2])
        opcode, mnem, opermkr, flags = ttree.getInstr(val)
        olist = opermkr(va, val)
        op = ThumbOpcode(va, opcode, mnem, 0xe, 2, olist, flags)
        return op

