
# The opcode tables were taken from Mammon_'s Guide to Writing Disassemblers in Perl, You Morons!"
# and the bastard project. http://www.eccentrix.com/members/mammon/

INSTR_PREFIX=      0xF0000000L
PREFIX_LOCK =      0x00100000
PREFIX_REPNZ=      0x00200000
PREFIX_REPZ =      0x00400000
PREFIX_REP  =      0x00800000
PREFIX_REP_SIMD=   0x01000000
PREFIX_OP_SIZE=    0x02000000
PREFIX_ADDR_SIZE=  0x04000000
PREFIX_SIMD=       0x08000000
PREFIX_CS  =       0x10000000
PREFIX_SS  =       0x20000000
PREFIX_DS  =       0x30000000
PREFIX_ES  =       0x40000000
PREFIX_FS  =       0x50000000
PREFIX_GS  =       0x60000000
PREFIX_REG_MASK=   0xF0000000L

ADDRMETH_MASK =     0x00FF0000L
ADDRMETH_A=   0x00010000    #   Direct address with segment prefix
ADDRMETH_C=   0x00020000    #   MODRM reg field defines control register
ADDRMETH_D=   0x00030000    #   MODRM reg field defines debug register
ADDRMETH_E=   0x00040000    #   MODRM byte defines reg/memory address
ADDRMETH_F=   0x00050000    #   EFLAGS/RFLAGS register
ADDRMETH_G=   0x00060000    #   MODRM byte defines general-purpose reg
ADDRMETH_I=   0x00070000    #   Immediate data follows
ADDRMETH_J=   0x00080000    #   Immediate value is relative to EIP
ADDRMETH_M=   0x00090000    #   MODRM mod field can refer only to memory
ADDRMETH_N=   0x000A0000    #   R/M field of MODRM selects a packed-quadword, MMX register
ADDRMETH_O=   0x000B0000    #   Displacement follows (without modrm/sib)
ADDRMETH_P=   0x000C0000    #   MODRM reg field defines MMX register
ADDRMETH_Q=   0x000D0000    #   MODRM defines MMX register or memory
ADDRMETH_R=   0x000E0000    #   MODRM mod field can only refer to register
ADDRMETH_S=   0x000F0000    #   MODRM reg field defines segment register
ADDRMETH_U=   0x00100000    #   MODRM reg field defines test register
ADDRMETH_V=   0x00110000    #   MODRM reg field defines XMM register
ADDRMETH_W=   0x00120000    #   MODRM defines XMM register or memory
ADDRMETH_X=   0x00130000    #   Memory addressed by DS:rSI
ADDRMETH_Y=   0x00140000    #   Memory addressd by ES:rDI

OPTYPE_a   = 0x01000000     # 2/4   two one-word operands in memory or two double-word operands in memory (operand-size attribute)   
OPTYPE_b   = 0x02000000     # 1     always 1 byte
OPTYPE_c   = 0x03000000     # 1/2   byte or word, depending on operand
OPTYPE_d   = 0x04000000     # 4     double-word
OPTYPE_dq  = 0x05000000     # 16    double quad-word
OPTYPE_p   = 0x06000000     # 4/6   32-bit or 48-bit pointer
OPTYPE_pi  = 0x07000000     # 8     quadword MMX register
OPTYPE_ps  = 0x08000000     # 16    128-bit single-precision float
OPTYPE_pd  = 0x08000000     # ??    should be a double-precision float?
OPTYPE_q   = 0x09000000     # 8     quad-word
OPTYPE_s   = 0x0A000000     # 6     6-byte pseudo descriptor
OPTYPE_ss  = 0x0B000000     # ??    Scalar of 128-bit single-precision float
OPTYPE_si  = 0x0C000000     # 4     Doubleword integer register
OPTYPE_sd  = 0x0C000000     #   ???  
OPTYPE_v   = 0x0D000000     # 2/4   word or double-word, depending on operand
OPTYPE_w   = 0x0E000000     # 2     always word
OPTYPE_z   = 0x0F000000     # 2/4   is this OPTYPE_z?  word for 16-bit operand size or doubleword for 32 or 64-bit operand-size

OPTYPE_fs= 0x10000000L      #   
OPTYPE_fd= 0x20000000L      #   
OPTYPE_fe= 0x30000000L      #   
OPTYPE_fb= 0x40000000L      #   
OPTYPE_fv= 0x50000000L      #   

# FIXME this should probably be a list rather than a dictionary

OPERSIZE = {
             0        : (2,4,8),           # We will only end up here on regs embedded in opcodes
             OPTYPE_a : (2,4,4),
             OPTYPE_b : (1,1,1),
             OPTYPE_c : (1,2,2),           # 1/2   byte or word, depending on operand
             OPTYPE_d : (4,4,4),           # 4     double-word
             OPTYPE_dq: (16,16,16),        # 16    double quad-word
             OPTYPE_p : (4,6,6),           # 4/6   32-bit or 48-bit pointer
             OPTYPE_pi: (8,8,8),           # 8     quadword MMX register
             OPTYPE_ps: (16,16,16),        # 16    128-bit single-precision float
             OPTYPE_pd: (16,16,16),        # ??    should be a double-precision float?
             OPTYPE_q : (8,8,8),           # 8     quad-word
             OPTYPE_s : (6,10,10),         # 6     6-byte pseudo descriptor
             OPTYPE_ss: (0,0,0),           # ??    Scalar of 128-bit single-precision float
             OPTYPE_si: (4,4,4),           # 4     Doubleword integer register
             OPTYPE_sd: (4,4,4),           #   ???
             OPTYPE_v : (2,4,8),           # 2/4   word or double-word, depending on operand
             OPTYPE_w : (2,2,2),           # 2     always word
             OPTYPE_z : (2,4,4),           #  word for 16-bit operand size or doubleword for 32 or 64-bit operand-size
             # Floating point crazyness FIXME these are mostly wrong
             OPTYPE_fs: (4,4,4),
             OPTYPE_fd: (8,8,8),
             OPTYPE_fe: (10,10,10),
             OPTYPE_fb: (10,10,10),
             OPTYPE_fv: (14,14,28),
}


INS_EXEC =               0x1000
INS_ARITH=               0x2000
INS_LOGIC=               0x3000
INS_STACK=               0x4000
INS_COND =               0x5000
INS_LOAD =               0x6000
INS_ARRAY=               0x7000
INS_BIT  =       	 0x8000
INS_FLAG =               0x9000
INS_FPU  =      	 0xA000
INS_TRAPS=               0xD000
INS_SYSTEM = 	     	 0xE000
INS_OTHER=               0xF000

INS_BRANCH  =    INS_EXEC | 0x01 
INS_BRANCHCC=    INS_EXEC | 0x02 
INS_CALL    =    INS_EXEC | 0x03
INS_CALLCC  =    INS_EXEC | 0x04 
INS_RET     =    INS_EXEC | 0x05 
INS_LOOP    =    INS_EXEC | 0x06 
                                                                                
INS_ADD=         INS_ARITH | 0x01
INS_SUB=         INS_ARITH | 0x02
INS_MUL=         INS_ARITH | 0x03
INS_DIV=         INS_ARITH | 0x04
INS_INC=         INS_ARITH | 0x05        
INS_DEC=         INS_ARITH | 0x06 
INS_SHL=         INS_ARITH | 0x07 
INS_SHR=         INS_ARITH | 0x08
INS_ROL=         INS_ARITH | 0x09
INS_ROR=         INS_ARITH | 0x0A

INS_AND=         INS_LOGIC | 0x01
INS_OR =         INS_LOGIC | 0x02
INS_XOR=         INS_LOGIC | 0x03
INS_NOT=         INS_LOGIC | 0x04
INS_NEG=         INS_LOGIC | 0x05
                                                                                
INS_PUSH=                INS_STACK | 0x01
INS_POP =        INS_STACK | 0x02
INS_PUSHREGS=    INS_STACK | 0x03 
INS_POPREGS=     INS_STACK | 0x04  
INS_PUSHFLAGS=   INS_STACK | 0x05 
INS_POPFLAGS=    INS_STACK | 0x06 
INS_ENTER=               INS_STACK | 0x07   
INS_LEAVE =              INS_STACK | 0x08

INS_TEST  =              INS_COND | 0x01
INS_CMP   =      INS_COND | 0x02
                                                                                
INS_MOV    =     INS_LOAD | 0x01
INS_MOVCC  =             INS_LOAD | 0x02
INS_XCHG   =             INS_LOAD | 0x03
INS_XCHGCC =     INS_LOAD | 0x04
INS_LEA    =     INS_LOAD | 0x05
                                                                                
INS_STRCMP  =    INS_ARRAY | 0x01
INS_STRLOAD =    INS_ARRAY | 0x02
INS_STRMOV  =    INS_ARRAY | 0x03
INS_STRSTOR =    INS_ARRAY | 0x04
INS_XLAT    =            INS_ARRAY | 0x05
                                                                                
INS_BITTEST =    INS_BIT | 0x01
INS_BITSET  =    INS_BIT | 0x02
INS_BITCLR  =    INS_BIT | 0x03

INS_CLEARCF  =   INS_FLAG | 0x01
INS_CLEARZF  =   INS_FLAG | 0x02 
INS_CLEAROF  =   INS_FLAG | 0x03
INS_CLEARDF  =   INS_FLAG | 0x04
INS_CLEARSF  =   INS_FLAG | 0x05 
INS_CLEARPF  =   INS_FLAG | 0x06 
INS_SETCF    =           INS_FLAG | 0x07
INS_SETZF    =           INS_FLAG | 0x08
INS_SETOF    =           INS_FLAG | 0x09
INS_SETDF    =           INS_FLAG | 0x0A
INS_SETSF    =           INS_FLAG | 0x0B
INS_SETPF    =           INS_FLAG | 0x0C
INS_TOGCF    =           INS_FLAG | 0x10 #/* toggle */
INS_TOGZF    =           INS_FLAG | 0x20
INS_TOGOF    =           INS_FLAG | 0x30
INS_TOGDF    =           INS_FLAG | 0x40
INS_TOGSF    =           INS_FLAG | 0x50
INS_TOGPF    =           INS_FLAG | 0x60

INS_TRAP  =              INS_TRAPS | 0x01  #/* generate trap */
INS_TRAPCC=      INS_TRAPS | 0x02          #/* conditional trap gen */
INS_TRET  =              INS_TRAPS | 0x03  #/* return from trap */
INS_BOUNDS=      INS_TRAPS | 0x04          #/* gen bounds trap */
INS_DEBUG =              INS_TRAPS | 0x05  #/* gen breakpoint trap */
INS_TRACE  =             INS_TRAPS | 0x06  #/* gen single step trap */
INS_INVALIDOP=   INS_TRAPS | 0x07          #     /* gen invalid instruction */
INS_OFLOW    =           INS_TRAPS | 0x08  #      /* gen overflow trap */
                                                                                
#/* INS_SYSTEM */
INS_HALT    =            INS_SYSTEM | 0x01 #               /* halt machine */
INS_IN      =    INS_SYSTEM | 0x02         #      /* input form port */
INS_OUT     =    INS_SYSTEM | 0x03         #      /* output to port */
INS_CPUID   =            INS_SYSTEM | 0x04 #              /* iden

INS_NOP     =    INS_OTHER | 0x01
INS_BCDCONV =    INS_OTHER | 0x02        #/* convert to/from BCD */
INS_SZCONV  =    INS_OTHER | 0x03        #/* convert size of operand */


OP_R=         0x001    
OP_W=         0x002 
OP_X=         0x004  
OP_UNK=       0x000  
OP_REG=       0x100   
OP_IMM=       0x200  
OP_REL=       0x300   
OP_ADDR=      0x400 
OP_EXPR=      0x500   
OP_PTR =      0x600 
OP_OFF =      0x700   

OP_SIGNED=    0x001000  
OP_STRING=    0x002000  
OP_CONST =    0x004000

# NOTE: These are junk and can't be used because
#       they overlap with the addressing modes.
OP_EXTRASEG=  0x010000 
OP_CODESEG =  0x020000
OP_STACKSEG=  0x030000
OP_DATASEG =  0x040000
OP_DATA1SEG=  0x050000
OP_DATA2SEG=  0x060000

ARG_NONE = 0
cpu_8086 =        0x00001000
cpu_80286=        0x00002000
cpu_80386=        0x00003000
cpu_80387=        0x00004000
cpu_80486=        0x00005000
cpu_PENTIUM=      0x00006000
cpu_PENTPRO=      0x00007000
cpu_PENTMMX=      0x00008000
cpu_PENTIUM2=     0x00009000
cpu_AMD64=        0x0000a000

x86_MAIN =0
x86_0F   =1
x86_80   =2

#import envi.archs.i386.regs as e_i386_regs
# Relative import priority...
import regs as e_i386_regs
                                                                                
"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodenane", op0Register, op1Register, op2Register)
"""
tbl32_Main = [
( 0, INS_ADD, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0),
( 0, INS_ADD, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0),
( 0, INS_ADD, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0),
( 0, INS_ADD, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0),
( 0, INS_ADD, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "add", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_ADD, OP_REG | OP_W, ADDRMETH_I | OPTYPE_z | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "add", e_i386_regs.REG_EAX, 0, 0),  
(0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_ES, 0, 0),  
(0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_ES, 0, 0),  
( 0, INS_OR, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0),  
( 0, INS_OR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0),  
( 0, INS_OR, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0),  
( 0, INS_OR, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0),  
( 0, INS_OR, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "or", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_OR, OP_REG | OP_W, ADDRMETH_I | OPTYPE_z | OP_R, ARG_NONE, cpu_80386, "or", e_i386_regs.REG_EAX, 0, 0),  
(0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_CS, 0, 0),  
(1, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  # 0x0f
# 0x10
( 0, INS_ADD, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0),  
( 0, INS_ADD, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "adc", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_ADD, OP_REG | OP_W, ADDRMETH_I | OPTYPE_z | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "adc", e_i386_regs.REG_EAX, 0, 0),  
(0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_SS, 0, 0),  
(0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_SS, 0, 0),  
( 0, INS_SUB, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0),  
( 0, INS_SUB, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "sbb", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_SUB, OP_REG | OP_W, ADDRMETH_I | OPTYPE_z | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "sbb", e_i386_regs.REG_EAX, 0, 0),  
(0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_DS, 0, 0),  
(0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_DS, 0, 0),  
# 0x20
( 0, INS_AND, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0),  
( 0, INS_AND, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "and", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_AND, OP_REG | OP_W, ADDRMETH_I | OPTYPE_z | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "and", e_i386_regs.REG_EAX, 0, 0),  
( 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(0, INS_BCDCONV, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "daa", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0),  
( 0, INS_SUB, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "sub", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_SUB, OP_REG | OP_W, ADDRMETH_I | OPTYPE_z | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "sub", e_i386_regs.REG_EAX, 0, 0),  
( 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(0, INS_BCDCONV, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "das", 0, 0, 0),  
# 0x30
( 0, INS_XOR, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0),  
( 0, INS_XOR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0),  
( 0, INS_XOR, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0),  
( 0, INS_XOR, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0),  
( 0, INS_XOR, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "xor", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_XOR, OP_REG | OP_W, ADDRMETH_I | OPTYPE_z | OP_R, ARG_NONE, cpu_80386, "xor", e_i386_regs.REG_EAX, 0, 0),  
( 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(0, INS_BCDCONV, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "aaa", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_E | OPTYPE_b | OP_R, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_G | OPTYPE_b | OP_R, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0),  
( 0, INS_CMP, OP_REG | OP_R, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "cmp", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_CMP, OP_REG | OP_R, ADDRMETH_I | OPTYPE_z | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "cmp", e_i386_regs.REG_EAX, 0, 0),  
( 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(0, INS_BCDCONV, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "aas", 0, 0, 0),  
# 0x40
( 0, INS_INC, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", e_i386_regs.REG_EAX, 0, 0),  
( 0, INS_INC, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", e_i386_regs.REG_ECX, 0, 0),  
( 0, INS_INC, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", e_i386_regs.REG_EDX, 0, 0),  
( 0, INS_INC, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", e_i386_regs.REG_EBX, 0, 0),  
( 0, INS_INC, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", e_i386_regs.REG_ESP, 0, 0),  
( 0, INS_INC, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", e_i386_regs.REG_EBP, 0, 0),  
( 0, INS_INC, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", e_i386_regs.REG_ESI, 0, 0),  
( 0, INS_INC, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", e_i386_regs.REG_EDI, 0, 0),  

( 0, INS_DEC, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", e_i386_regs.REG_EAX, 0, 0),  
( 0, INS_DEC, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", e_i386_regs.REG_ECX, 0, 0),  
( 0, INS_DEC, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", e_i386_regs.REG_EDX, 0, 0),  
( 0, INS_DEC, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", e_i386_regs.REG_EBX, 0, 0),  
( 0, INS_DEC, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", e_i386_regs.REG_ESP, 0, 0),  
( 0, INS_DEC, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", e_i386_regs.REG_EBP, 0, 0),  
( 0, INS_DEC, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", e_i386_regs.REG_ESI, 0, 0),  
( 0, INS_DEC, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", e_i386_regs.REG_EDI, 0, 0),  
# 0x50
( 0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_EAX, 0, 0),  
( 0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_ECX, 0, 0),  
( 0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_EDX, 0, 0),  
( 0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_EBX, 0, 0),  
( 0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_ESP, 0, 0),  
( 0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_EBP, 0, 0),  
( 0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_ESI, 0, 0),  
( 0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_EDI, 0, 0),  

( 0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_EAX, 0, 0),
( 0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_ECX, 0, 0),
( 0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_EDX, 0, 0),
( 0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_EBX, 0, 0),
( 0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_ESP, 0, 0),
( 0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_EBP, 0, 0),
( 0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_ESI, 0, 0),
( 0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_EDI, 0, 0),
# 0x60
( 0, INS_PUSHREGS, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "pushad", 0, 0, 0),  
( 0, INS_POPREGS, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "popad", 0, 0, 0),  
( 0, INS_BOUNDS, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_M | OPTYPE_a | OP_R, ARG_NONE, cpu_80386, "bound", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_R, ADDRMETH_G | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "arpl", 0, 0, 0),  
( 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
( 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(44, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  # 0x66
( 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
( 0, INS_PUSH, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OP_SIGNED |OPTYPE_z | OP_R, cpu_80386, "imul", 0, 0, 0),  
(0, INS_PUSH, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I |  OP_SIGNED | OP_R | OPTYPE_b, cpu_80386, "imul", 0, 0, 0),  
(0, INS_IN,  ADDRMETH_Y | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "insb", 0, e_i386_regs.REG_EDX, 0),  
(0, INS_IN,  ADDRMETH_Y | OPTYPE_z | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "insd", 0, e_i386_regs.REG_EDX, 0),  
(0, INS_OUT,  OP_REG | OP_W, ADDRMETH_X | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "outsb", e_i386_regs.REG_EDX, 0, 0),  
(0, INS_OUT,  OP_REG | OP_W, ADDRMETH_X | OPTYPE_z | OP_R, ARG_NONE, cpu_80386, "outsd", e_i386_regs.REG_EDX, 0, 0),  
# 0x70
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jo", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jno", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jc", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnc", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jz", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnz", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jbe", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "ja", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "js", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jns", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpe", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpo", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jl", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jge", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jle", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jg", 0, 0, 0),  
# 0x80
(2, 0, ADDRMETH_E | OPTYPE_b, ADDRMETH_I | OPTYPE_b, ARG_NONE,cpu_80386, 0, 0, 0, 0),  
(3, 0, ADDRMETH_E | OPTYPE_v, ADDRMETH_I | OPTYPE_v, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(4, 0, ADDRMETH_E | OPTYPE_v, ADDRMETH_I | OPTYPE_b, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(5, 0,  ADDRMETH_E | OPTYPE_v, ADDRMETH_I | OPTYPE_b, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
( 0, INS_TEST, ADDRMETH_E | OPTYPE_b | OP_R, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "test", 0, 0, 0),  
( 0, INS_TEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "test", 0, 0, 0),  
( 0, INS_XCHG, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_W, ARG_NONE, cpu_80386, "xchg", 0, 0, 0),  
( 0, INS_XCHG, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_W, ARG_NONE, cpu_80386, "xchg", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_E | OPTYPE_w | OP_W, ADDRMETH_S | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_LEA, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "lea", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_S | OPTYPE_w | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_POP, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 0, 0, 0),  
# 0x90
(0, INS_NOP, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "nop", 0, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", e_i386_regs.REG_EAX, e_i386_regs.REG_ECX, 0),  
( 0, INS_XCHG, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", e_i386_regs.REG_EAX, e_i386_regs.REG_EDX, 0),  
( 0, INS_XCHG, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", e_i386_regs.REG_EAX, e_i386_regs.REG_EBX, 0),  
( 0, INS_XCHG, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", e_i386_regs.REG_EAX, e_i386_regs.REG_ESP, 0),  
( 0, INS_XCHG, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", e_i386_regs.REG_EAX, e_i386_regs.REG_EBP, 0),  
( 0, INS_XCHG, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", e_i386_regs.REG_EAX, e_i386_regs.REG_ESI, 0),  
( 0, INS_XCHG, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", e_i386_regs.REG_EAX, e_i386_regs.REG_EDI, 0),  
( 0, INS_SZCONV, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cwde", 0, 0, 0),  
( 0, INS_SZCONV, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cdq", 0, 0, 0),  
( 0, INS_CALL, ADDRMETH_A | OPTYPE_p | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "callf", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "wait", 0, 0, 0),  
( 0, INS_PUSHFLAGS, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "pushfd", 0, 0, 0),  
( 0, INS_POPFLAGS, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "popfd", 0, 0, 0),  
(0, INS_MOV, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "sahf", 0, 0, 0),  
(0, INS_MOV, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "lahf", 0, 0, 0),  
# 0xa0
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_O | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_O | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_EAX, 0, 0),  
( 0, INS_MOV, ADDRMETH_O | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "mov", 0, e_i386_regs.REG_AL, 0),  
( 0, INS_MOV, ADDRMETH_O | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "mov", 0, e_i386_regs.REG_EAX, 0),  
(0, INS_STRMOV, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "movsb", 0, 0, 0),  
( 0, INS_STRMOV, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "movsd", 0, 0, 0),  
(0, INS_STRCMP, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cmpsb", 0, 0, 0),  
( 0, INS_STRCMP, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cmpsd", 0, 0, 0),  
( 0, INS_TEST, OP_REG | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "test", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_TEST, OP_REG | OP_R, ADDRMETH_I | OPTYPE_z | OP_R, ARG_NONE, cpu_80386, "test", e_i386_regs.REG_EAX, 0, 0),  
(0, INS_STRSTOR, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "stosb", 0, 0, 0),  
( 0, INS_STRSTOR, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "stosd", 0, 0, 0),  
(0, INS_STRLOAD, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "lodsb", 0, 0, 0),  
( 0, INS_STRLOAD, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "lodsd", 0, 0, 0),  
(0, INS_STRCMP, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "scasb", 0, 0, 0),  
( 0, INS_STRCMP, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "scasd", 0, 0, 0),  
# 0xb0
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_CL, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_DL, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_BL, 0, 0),  
# FIXME 64
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_AH, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_CH, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_DH, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_BH, 0, 0),  

( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_EAX, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_ECX, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_EDX, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_EBX, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_ESP, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_EBP, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_ESI, 0, 0),  
( 0, INS_MOV, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", e_i386_regs.REG_EDI, 0, 0),  
# 0xc0
(6, 0,  ADDRMETH_E | OPTYPE_b, ADDRMETH_I | OPTYPE_b, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(7, 0,  ADDRMETH_E | OPTYPE_v, ADDRMETH_I | OPTYPE_b, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
( 0, INS_RET, ADDRMETH_I | OPTYPE_w | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "ret", 0, 0, 0),  
( 0, INS_RET, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "ret", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p | OP_R, ARG_NONE, cpu_80386, "les", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p | OP_R, ARG_NONE, cpu_80386, "lds", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_z | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_ENTER, ADDRMETH_I | OPTYPE_w | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "enter", 0, 0, 0),  
(0, INS_LEAVE, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "leave", 0, 0, 0),  
( 0, INS_RET, ADDRMETH_I | OPTYPE_w | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "retf", 0, 0, 0),  
( 0, INS_RET, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "retf", 0, 0, 0),  
(0, INS_DEBUG, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "int3", 0, 0, 0),  
( 0, INS_TRAP, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "int", 0, 0, 0),  
(0, INS_OFLOW, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "into", 0, 0, 0),  
( 0, INS_TRET, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "iret", 0, 0, 0),  
# 0xd0
(8, 0,  ADDRMETH_E | OPTYPE_b, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 1, 0),  
(9, 0, ADDRMETH_E | OPTYPE_v, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 1, 0),  
(10, 0, ADDRMETH_E | OPTYPE_b, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, e_i386_regs.REG_CL, 0),  
(11, 0, ADDRMETH_E | OPTYPE_v, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, e_i386_regs.REG_CL, 0),  
( 0, INS_BCDCONV, ADDRMETH_I | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "aam", 0, 0, 0),  
( 0, INS_BCDCONV, ADDRMETH_I | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "aad", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(0, INS_XLAT, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "xlat", 0, 0, 0),  
(26, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(28, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(30, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(32, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(34, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(36, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(38, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(40, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
# 0xf0
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "loopnz", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "loopz", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "loop", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jecxz", 0, 0, 0),  
( 0, INS_IN, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "in", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_IN, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "in", e_i386_regs.REG_EAX, 0, 0),  
( 0, INS_OUT, ADDRMETH_I | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "out", 0, e_i386_regs.REG_AL, 0),  
( 0, INS_OUT, ADDRMETH_I | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "out", 0, e_i386_regs.REG_EAX, 0),  
( 0, INS_CALL, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "call", 0, 0, 0),  
( 0, INS_BRANCH, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jmp", 0, 0, 0),  
( 0, INS_BRANCH, ADDRMETH_A | OPTYPE_p | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jmp", 0, 0, 0),  
( 0, INS_BRANCH, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jmp", 0, 0, 0),  
(0, INS_IN, OP_REG | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "in", e_i386_regs.REG_AL, e_i386_regs.REG_DX, 0),  
( 0, INS_IN, OP_REG | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "in", e_i386_regs.REG_EAX, e_i386_regs.REG_DX, 0),  
(0, INS_OUT, OP_REG | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "out", e_i386_regs.REG_DX, e_i386_regs.REG_AL, 0),  
( 0, INS_OUT, OP_REG | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "out", e_i386_regs.REG_DX, e_i386_regs.REG_EAX, 0),  
( 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "lock:", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
( 45, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "repne:", 0, 0, 0),  
( 46, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "rep:", 0, 0, 0),  
(0, INS_HALT, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "hlt", 0, 0, 0),  
(0, INS_TOGCF, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cmc", 0, 0, 0),  
(12, 0,  ADDRMETH_E | OPTYPE_b, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(13, 0, ADDRMETH_E | OPTYPE_v, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(0, INS_CLEARCF, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "clc", 0, 0, 0),  
(0, INS_SETCF, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "stc", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cli", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "sti", 0, 0, 0),  
(0, INS_CLEARDF, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cld", 0, 0, 0),  
(0, INS_SETDF, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "std", 0, 0, 0),  
(14, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(15, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0   )
]



"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_0F = [
# 0f00
(16, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(17, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "lar", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "lsl", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_AMD64, "syscall", 0, 0, 0),
( 0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "clts", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_AMD64, "sysret", 0, 0, 0),
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "invd", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "wbinvd", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "ud2", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_E | OPTYPE_v, ARG_NONE, ARG_NONE, cpu_80386, "NOP", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
# 0f10
( 0, INS_MOV, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movups", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_W | OPTYPE_ps | OP_W, ADDRMETH_V | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movups", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_V | OPTYPE_q | OP_W, ADDRMETH_M | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movlps", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_M | OPTYPE_q | OP_W, ADDRMETH_V | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movlps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "unpcklps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "unpckhps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_q | OP_W, ADDRMETH_M | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movhps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_M | OPTYPE_q | OP_W, ADDRMETH_V | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movhps", 0, 0, 0),  
(18, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_E | OPTYPE_v, ARG_NONE, ARG_NONE, cpu_80386, "NOP", 0, 0, 0),  
# 0f20
( 0, INS_MOV, ADDRMETH_R | OPTYPE_d | OP_W, ADDRMETH_C | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_R | OPTYPE_d | OP_W, ADDRMETH_D | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_C | OPTYPE_d | OP_W, ADDRMETH_R | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_D | OPTYPE_d | OP_W, ADDRMETH_R | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movaps", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_W | OPTYPE_ps | OP_W, ADDRMETH_V | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movaps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_R, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "cvtpi2ps", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_M | OPTYPE_ps | OP_W, ADDRMETH_V | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movntps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_Q | OPTYPE_q | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "cvttps2pi", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_Q | OPTYPE_q | OP_R, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "cvtps2pi", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ss | OP_W, ADDRMETH_W | OPTYPE_ss | OP_R, ARG_NONE, cpu_PENTIUM2, "ucomiss", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_W, ARG_NONE, cpu_PENTIUM2, "comiss", 0, 0, 0),  
# 0f30
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "wrmsr", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "rdtsc", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "rdmsr", 0, 0, 0),  
(0, INS_OTHER, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTPRO, "rdpmc", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "sysenter", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "sysexit", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  # 3-byte escape 28
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  # 3-byte escape 2a
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
# 0f40
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovo", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovno", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovc", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovnc", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovz", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovnz", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovbe", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmova", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovs", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovns", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovpe", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovpo", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovl", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovge", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovle", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovg", 0, 0, 0),  
# 0f50
( 0, INS_MOV, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_U | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movmskps", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "sqrtps", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "rsqrtps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "rcpps", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "andps", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "andnps", 0, 0, 0),  
( 0, INS_OR, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "orps", 0, 0, 0),  
( 0, INS_XOR, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "xorps", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "addps", 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_V | OPTYPE_ps | OP_R, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "mulps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "cvtps2pd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_dq |OP_R, ARG_NONE, cpu_PENTIUM2, "cvtdq2ps", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "subps", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "minps", 0, 0, 0),  
( 0, INS_DIV, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "divps", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "maxps", 0, 0, 0),  
# 0f60
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpcklbw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpcklwd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckldq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "packsswb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "packuswb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhbw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhwd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhdq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "packssdw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_P | OPTYPE_d | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "movd", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "movq", 0, 0, 0),  
# 0f70
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ADDRMETH_I |  OPTYPE_b | OP_R, cpu_PENTIUM2, "pshufw", 0, 0, 0),  
(19, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  
(20, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  
(21, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqb", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqw", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqd", 0, 0, 0),  
(0, INS_OTHER, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, "emms", 0, 0, 0),  
(0, INS_SYSTEM, ADDRMETH_E | OPTYPE_d | OP_W, ADDRMETH_G | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTIUM2, "vmread", 0, 0, 0),  
(0, INS_SYSTEM, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTIUM2, "vmwrite", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_E | OPTYPE_d | OP_W, ADDRMETH_P | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "movd", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_Q | OPTYPE_q | OP_W, ADDRMETH_P | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "movq", 0, 0, 0),  
# 0f80
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jo", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jno", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jc", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnc", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jz", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnz", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jbe", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "ja", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "js", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jns", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpe", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpo", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jl", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jge", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jle", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jg", 0, 0, 0),  
# 0f90
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "seto", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setno", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setc", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setnc", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setz", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setnz", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setbe", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "seta", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "sets", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setns", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setpe", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setpo", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setl", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setge", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setle", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setg", 0, 0, 0),  
# 0fa0
(0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_FS, 0, 0),  
(0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_FS, 0, 0),  
(0, INS_CPUID, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "cpuid", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bt", 0, 0, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_80386, "shld", 0, 0, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, OP_R | OP_REG, cpu_80386, "shld", 0, 0, e_i386_regs.REG_CL), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_GS, 0, 0),  
(0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_GS, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "rsm", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bts", 0, 0, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_80386, "shrd", 0, 0, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, OP_R | OP_REG, cpu_80386, "shrd", 0, 0, e_i386_regs.REG_CL), 
(22, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, 0, 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "imul", 0, 0, 0),  
# 0fb0
( 0, INS_XCHGCC, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_W, ARG_NONE, cpu_80486, "cmpxchg", 0, 0, 0),  
( 0, INS_XCHGCC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_W, ARG_NONE, cpu_80486, "cmpxchg", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p | OP_R, ARG_NONE, cpu_80386, "lss", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "btr", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p| OP_R, ARG_NONE, cpu_80386, "lfs", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p | OP_R, ARG_NONE, cpu_80386, "lgs", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "movzx", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "movzx", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "ud1", 0, 0, 0),  #### GROUP 10?
(23, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "btc", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_G | OPTYPE_v | OP_R | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bsf", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_G | OPTYPE_v | OP_R | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bsr", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "movsx", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "movsx", 0, 0, 0),  
# 0fc0
( 0, INS_ADD, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_W, ARG_NONE, cpu_80486, "xadd", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v, ARG_NONE, cpu_80486, "xadd", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_V | OPTYPE_ps| OP_W, ADDRMETH_W | OPTYPE_ps| OP_W, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "cmpps", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_M | OPTYPE_q | OP_W, ADDRMETH_G | OPTYPE_q |OP_R, ARG_NONE, cpu_PENTIUM2, "movnti", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "pinsrw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_N | OPTYPE_q | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "pextrw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "shufps", 0, 0, 0),  
(24, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  # group 9
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EAX, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_ECX, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EDX, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EBX, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_ESP, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EBP, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_ESI, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EDI, 0, 0),  
# 0fd0
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrlw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrld", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrlq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmullw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_N | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmovmskb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubusb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubusw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pminub", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pand", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddusb", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddusw", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmaxub", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pandn", 0, 0, 0),  
# 0ff0
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pavgb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psraw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrad", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pavgw", 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmulhuw", 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmulhw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_M | OPTYPE_dq | OP_W, ADDRMETH_V | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "movntq", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubsb", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubsw", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pminsw", 0, 0, 0),  
( 0, INS_OR, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "por", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddsb", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddsw", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmaxsw", 0, 0, 0),  
( 0, INS_XOR, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pxor", 0, 0, 0),  
    (0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psllw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pslld", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psllq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmuludq", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmaddwd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "psadbw", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_N | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "maskmovq", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubb", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubw", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubd", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubq", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddb", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddw", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddd", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ) 
]

"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_660F = [
(16, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),
(17, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),
( 0, INS_SYSTEM, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "lar", 0, 0, 0),
( 0, INS_SYSTEM, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "lsl", 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
( 0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "clts", 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "invd", 0, 0, 0),
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "wbinvd", 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "ud2", 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
( 0, INS_OTHER, ADDRMETH_E | OPTYPE_v, ARG_NONE, ARG_NONE, cpu_80386, "NOP", 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
    ( 0, INS_MOV, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "movupd", 0, 0, 0),  #
( 0, INS_MOV, ADDRMETH_W | OPTYPE_pd | OP_W, ADDRMETH_V | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "movupd", 0, 0, 0),  #
( 0, INS_MOV, ADDRMETH_V | OPTYPE_q | OP_W, ADDRMETH_M | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movlpd", 0, 0, 0),  #
( 0, INS_MOV, ADDRMETH_M | OPTYPE_q | OP_W, ADDRMETH_V | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movlpd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "unpcklpd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "unpckhpd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_q | OP_W, ADDRMETH_M | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movhpd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_M | OPTYPE_q | OP_W, ADDRMETH_V | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movhpd", 0, 0, 0),  #
(18, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_E | OPTYPE_v, ARG_NONE, ARG_NONE, cpu_80386, "NOP", 0, 0, 0),
    ( 0, INS_MOV, ADDRMETH_R | OPTYPE_d | OP_W, ADDRMETH_C | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),
( 0, INS_MOV, ADDRMETH_R | OPTYPE_d | OP_W, ADDRMETH_D | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),
( 0, INS_MOV, ADDRMETH_C | OPTYPE_d | OP_W, ADDRMETH_R | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),
( 0, INS_MOV, ADDRMETH_D | OPTYPE_d | OP_W, ADDRMETH_R | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "movapd", 0, 0, 0),  #
( 0, INS_MOV, ADDRMETH_W | OPTYPE_pd | OP_W, ADDRMETH_V | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "movapd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_pd | OP_R, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "cvtpi2pd", 0, 0, 0),  #
( 0, INS_MOV, ADDRMETH_M | OPTYPE_pd | OP_W, ADDRMETH_V | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "movntpd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_Q | OPTYPE_dq | OP_R, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "cvttpd2pi", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_Q | OPTYPE_dq | OP_R, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "cvtpd2pi", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_sd | OP_W, ADDRMETH_W | OPTYPE_sd | OP_R, ARG_NONE, cpu_PENTIUM2, "ucomisd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_sd | OP_W, ARG_NONE, cpu_PENTIUM2, "comisd", 0, 0, 0),  #
    (0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "wrmsr", 0, 0, 0),
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "rdtsc", 0, 0, 0),
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "rdmsr", 0, 0, 0),
(0, INS_OTHER, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTPRO, "rdpmc", 0, 0, 0),
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "sysenter", 0, 0, 0),
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "sysexit", 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  # 3-byte escape 28
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  # 3-byte escape 2a
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
    ( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovo", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovno", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovc", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovnc", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovz", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovnz", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovbe", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmova", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovs", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovns", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovpe", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovpo", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovl", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovge", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovle", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovg", 0, 0, 0),
    ( 0, INS_MOV, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_U | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "movmskpd", 0, 0, 0),  #
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "sqrtpd", 0, 0, 0),  #
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "rsqrtpd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "rcppd", 0, 0, 0),  #
( 0, INS_AND, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "andpd", 0, 0, 0),  #
( 0, INS_AND, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "andnpd", 0, 0, 0),  #
( 0, INS_OR, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "orpd", 0, 0, 0),  #
( 0, INS_XOR, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "xorpd", 0, 0, 0),  #
( 0, INS_ADD, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "addpd", 0, 0, 0),  #
( 0, INS_MUL, ADDRMETH_V | OPTYPE_pd | OP_R, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "mulpd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_pd | OP_R, ADDRMETH_Q | OPTYPE_q, ARG_NONE, 0, "cvtpd2pd", 0, 0, 0),  #
( 0, INS_MOV, ADDRMETH_M | OPTYPE_pd, ADDRMETH_V | OPTYPE_pd, ARG_NONE, 0, "movntpd", 0, 0, 0),  #
( 0, INS_SUB, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "subpd", 0, 0, 0),  #
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "minpd", 0, 0, 0),  #
( 0, INS_DIV, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "divpd", 0, 0, 0),  #
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTIUM2, "maxpd", 0, 0, 0),  #
    ( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "punpcklbw", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_Q | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "punpcklwd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_Q | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "punpckldq", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_Q | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "packsswb", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_Q | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtb", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_Q | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtw", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_Q | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_Q | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "packuswb", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_dq | OP_W, ADDRMETH_Q | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhbw", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_dq | OP_W, ADDRMETH_Q | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhwd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_dq | OP_W, ADDRMETH_Q | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhdq", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_dq | OP_W, ADDRMETH_Q | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "packssdw", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "punpcklqdq", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhqdq", 0, 0, 0),  #
#VISI
( 0, INS_MOV, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_E | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "movd", 0, 0, 0),  #
( 0, INS_MOV, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_E | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "movq", 0, 0, 0),  # FIXME HORKED
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ADDRMETH_I |  OPTYPE_b | OP_R, cpu_PENTIUM2, "pshufd", 0, 0, 0),  #
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  
(54, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  # 66 0f 73
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqb", 0, 0, 0),  #
( 0, INS_CMP, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqw", 0, 0, 0),  #
( 0, INS_CMP, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqd", 0, 0, 0),  #
(0, INS_OTHER, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, "emms", 0, 0, 0),
(0, INS_SYSTEM, ADDRMETH_E | OPTYPE_d | OP_W, ADDRMETH_G | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTIUM2, "vmread", 0, 0, 0),
(0, INS_SYSTEM, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTIUM2, "vmwrite", 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTMMX, "haddpd", 0, 0, 0),  #
( 0, INS_MOV, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTMMX, "hsubpd", 0, 0, 0),  #
( 0, INS_MOV, ADDRMETH_E | OPTYPE_d | OP_W, ADDRMETH_V | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "movd", 0, 0, 0),  #
( 0, INS_MOV, ADDRMETH_Q | OPTYPE_q | OP_W, ADDRMETH_P | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "movq", 0, 0, 0),

( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jo", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jno", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jc", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnc", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jz", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnz", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jbe", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "ja", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "js", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jns", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpe", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpo", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jl", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jge", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jle", 0, 0, 0),
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jg", 0, 0, 0),
    ( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "seto", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setno", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setc", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setnc", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setz", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setnz", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setbe", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "seta", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "sets", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setns", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setpe", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setpo", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setl", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setge", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setle", 0, 0, 0),
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setg", 0, 0, 0),
    (0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_FS, 0, 0),
(0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_FS, 0, 0),
(0, INS_CPUID, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "cpuid", 0, 0, 0),
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bt", 0, 0, 0),
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_80386, "shld", 0, 0, 0),
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, OP_R | OP_REG, cpu_80386, "shld", 0, 0, e_i386_regs.REG_CL),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_GS, 0, 0),
(0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_GS, 0, 0),
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "rsm", 0, 0, 0),
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bts", 0, 0, 0),
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_80386, "shrd", 0, 0, 0),
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, OP_R | OP_REG, cpu_80386, "shrd", 0, 0, e_i386_regs.REG_CL),
(22, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, 0, 0, 0, 0),
( 0, INS_MUL, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "imul", 0, 0, 0),
    ( 0, INS_XCHGCC, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_W, ARG_NONE, cpu_80486, "cmpxchg", 0, 0, 0),
( 0, INS_XCHGCC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_W, ARG_NONE, cpu_80486, "cmpxchg", 0, 0, 0),
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p | OP_R, ARG_NONE, cpu_80386, "lss", 0, 0, 0),
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "btr", 0, 0, 0),
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p| OP_R, ARG_NONE, cpu_80386, "lfs", 0, 0, 0),
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p | OP_R, ARG_NONE, cpu_80386, "lgs", 0, 0, 0),
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "movzx", 0, 0, 0),
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "movzx", 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "ud1", 0, 0, 0),  #### GROUP 10?
(23, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "btc", 0, 0, 0),
( 0, INS_BITTEST, ADDRMETH_G | OPTYPE_v | OP_R | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bsf", 0, 0, 0),
( 0, INS_BITTEST, ADDRMETH_G | OPTYPE_v | OP_R | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bsr", 0, 0, 0),
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "movsx", 0, 0, 0),
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "movsx", 0, 0, 0),
    ( 0, INS_ADD, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_W, ARG_NONE, cpu_80486, "xadd", 0, 0, 0),
( 0, INS_ADD, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v, ARG_NONE, cpu_80486, "xadd", 0, 0, 0),
( 0, INS_CMP, ADDRMETH_V | OPTYPE_pd| OP_W, ADDRMETH_W | OPTYPE_pd| OP_W, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "cmppd", 0, 0, 0),  #
( 0, INS_MOV, ADDRMETH_M | OPTYPE_q | OP_W, ADDRMETH_G | OPTYPE_q |OP_R, ARG_NONE, cpu_PENTIUM2, "movnti", 0, 0, 0),
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "pinsrw", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_U | OPTYPE_dq | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "pextrw", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "shufps", 0, 0, 0),  #
(47, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  # 660FC7 table #
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EAX, 0, 0),
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_ECX, 0, 0),
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EDX, 0, 0),
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EBX, 0, 0),
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_ESP, 0, 0),
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EBP, 0, 0),
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_ESI, 0, 0),
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EDI, 0, 0),
    ( 0, INS_ADD, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTMMX, "addsubpd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psrlw", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psrld", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psrlq", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "paddq", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pmullw", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_W | OPTYPE_q | OP_W, ADDRMETH_V | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "movq", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_U | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "pmovmskb", 0, 0, 0), #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psubusb", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psubusw", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "pminub", 0, 0, 0),  #
( 0, INS_AND, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pand", 0, 0, 0),  #
( 0, INS_ADD, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "paddusb", 0, 0, 0),  #
( 0, INS_ADD, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "paddusw", 0, 0, 0),  #
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "pmaxub", 0, 0, 0),  #
( 0, INS_AND, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pandn", 0, 0, 0),  #
    ( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "pavgb", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psraw", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psrad", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "pavgw", 0, 0, 0),  #
( 0, INS_MUL, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "pmulhuw", 0, 0, 0),  #
( 0, INS_MUL, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pmulhw", 0, 0, 0),  #
( 0, INS_MUL, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_pd | OP_R, ARG_NONE, cpu_PENTMMX, "cvttpd2dq", 0, 0, 0),  #
( 0, INS_MOV, ADDRMETH_M | OPTYPE_dq | OP_W, ADDRMETH_V | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "movntdq", 0, 0, 0),  #
( 0, INS_SUB, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psubsb", 0, 0, 0),  #
( 0, INS_SUB, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psubsw", 0, 0, 0),  #
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "pminsw", 0, 0, 0),  #
( 0, INS_OR, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "por", 0, 0, 0),  #
( 0, INS_ADD, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "paddsb", 0, 0, 0),  #
( 0, INS_ADD, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "paddsw", 0, 0, 0),  #
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "pmaxsw", 0, 0, 0),  #
( 0, INS_XOR, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pxor", 0, 0, 0),  #
    (0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psllw", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pslld", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psllq", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pmuludq", 0, 0, 0),  #
( 0, INS_ADD, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "pmaddwd", 0, 0, 0),  #
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "psadbw", 0, 0, 0),  #
( 0, INS_MOV, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_U | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "maskmovq", 0, 0, 0),  #
( 0, INS_SUB, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psubb", 0, 0, 0),  #
( 0, INS_SUB, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psubw", 0, 0, 0),  #
( 0, INS_SUB, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psubd", 0, 0, 0),  #
( 0, INS_SUB, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "psubq", 0, 0, 0),  #
( 0, INS_ADD, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "paddb", 0, 0, 0),  #
( 0, INS_ADD, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "paddw", 0, 0, 0),  #
( 0, INS_ADD, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_W | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTMMX, "paddd", 0, 0, 0),  #
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ) 
]

"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_F20F = [
(16, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(17, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "lar", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "lsl", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "clts", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "invd", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "wbinvd", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "ud2", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_E | OPTYPE_v, ARG_NONE, ARG_NONE, cpu_80386, "NOP", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
    ( 0, INS_MOV, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movups", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_W | OPTYPE_ps | OP_W, ADDRMETH_V | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movups", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_V | OPTYPE_q | OP_W, ADDRMETH_M | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movlps", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_M | OPTYPE_q | OP_W, ADDRMETH_V | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movlps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "unpcklps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "unpckhps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_q | OP_W, ADDRMETH_M | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movhps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_M | OPTYPE_q | OP_W, ADDRMETH_V | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movhps", 0, 0, 0),  
(18, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_E | OPTYPE_v, ARG_NONE, ARG_NONE, cpu_80386, "NOP", 0, 0, 0),  
    ( 0, INS_MOV, ADDRMETH_R | OPTYPE_d | OP_W, ADDRMETH_C | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_R | OPTYPE_d | OP_W, ADDRMETH_D | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_C | OPTYPE_d | OP_W, ADDRMETH_R | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_D | OPTYPE_d | OP_W, ADDRMETH_R | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movaps", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_W | OPTYPE_ps | OP_W, ADDRMETH_V | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movaps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_R, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "cvtpi2ps", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_M | OPTYPE_ps | OP_W, ADDRMETH_V | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movntps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_Q | OPTYPE_q | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "cvttps2pi", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_Q | OPTYPE_q | OP_R, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "cvtps2pi", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ss | OP_W, ADDRMETH_W | OPTYPE_ss | OP_R, ARG_NONE, cpu_PENTIUM2, "ucomiss", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_W, ARG_NONE, cpu_PENTIUM2, "comiss", 0, 0, 0),  
    (0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "wrmsr", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "rdtsc", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "rdmsr", 0, 0, 0),  
(0, INS_OTHER, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTPRO, "rdpmc", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "sysenter", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "sysexit", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  # 3-byte escape 28
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  # 3-byte escape 2a
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
    ( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovo", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovno", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovc", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovnc", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovz", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovnz", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovbe", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmova", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovs", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovns", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovpe", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovpo", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovl", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovge", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovle", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovg", 0, 0, 0),  
    ( 0, INS_MOV, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_U | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movmskps", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "sqrtps", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "rsqrtps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "rcpps", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "andps", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "andnps", 0, 0, 0),  
( 0, INS_OR, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "orps", 0, 0, 0),  
( 0, INS_XOR, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "xorps", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "addps", 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_V | OPTYPE_ps | OP_R, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "mulps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "cvtps2pd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_dq |OP_R, ARG_NONE, cpu_PENTIUM2, "cvtdq2ps", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "subps", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "minps", 0, 0, 0),  
( 0, INS_DIV, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "divps", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "maxps", 0, 0, 0),  
    ( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpcklbw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpcklwd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckldq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "packsswb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "packuswb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhbw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhwd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhdq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "packssdw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_P | OPTYPE_d | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "movd", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "movq", 0, 0, 0),  
    ( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ADDRMETH_I |  OPTYPE_b | OP_R, cpu_PENTIUM2, "pshufw", 0, 0, 0),  
(19, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  
(20, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  
(21, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqb", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqw", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqd", 0, 0, 0),  
(0, INS_OTHER, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, "emms", 0, 0, 0),  
(0, INS_SYSTEM, ADDRMETH_E | OPTYPE_d | OP_W, ADDRMETH_G | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTIUM2, "vmread", 0, 0, 0),  
(0, INS_SYSTEM, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTIUM2, "vmwrite", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_E | OPTYPE_d | OP_W, ADDRMETH_P | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "movd", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_Q | OPTYPE_q | OP_W, ADDRMETH_P | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "movq", 0, 0, 0),  
    ( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jo", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jno", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jc", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnc", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jz", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnz", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jbe", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "ja", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "js", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jns", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpe", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpo", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jl", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jge", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jle", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jg", 0, 0, 0),  
    ( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "seto", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setno", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setc", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setnc", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setz", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setnz", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setbe", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "seta", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "sets", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setns", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setpe", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setpo", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setl", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setge", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setle", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setg", 0, 0, 0),  
    (0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_FS, 0, 0),  
(0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_FS, 0, 0),  
(0, INS_CPUID, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "cpuid", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bt", 0, 0, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_80386, "shld", 0, 0, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, OP_R | OP_REG, cpu_80386, "shld", 0, 0, e_i386_regs.REG_CL), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_GS, 0, 0),  
(0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_GS, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "rsm", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bts", 0, 0, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_80386, "shrd", 0, 0, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, OP_R | OP_REG, cpu_80386, "shrd", 0, 0, e_i386_regs.REG_CL), 
(22, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, 0, 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "imul", 0, 0, 0),  
    ( 0, INS_XCHGCC, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_W, ARG_NONE, cpu_80486, "cmpxchg", 0, 0, 0),  
( 0, INS_XCHGCC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_W, ARG_NONE, cpu_80486, "cmpxchg", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p | OP_R, ARG_NONE, cpu_80386, "lss", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "btr", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p| OP_R, ARG_NONE, cpu_80386, "lfs", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p | OP_R, ARG_NONE, cpu_80386, "lgs", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "movzx", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "movzx", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "ud1", 0, 0, 0),  #### GROUP 10?
(23, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "btc", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_G | OPTYPE_v | OP_R | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bsf", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_G | OPTYPE_v | OP_R | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bsr", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "movsx", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "movsx", 0, 0, 0),  
    ( 0, INS_ADD, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_W, ARG_NONE, cpu_80486, "xadd", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v, ARG_NONE, cpu_80486, "xadd", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_V | OPTYPE_ps| OP_W, ADDRMETH_W | OPTYPE_ps| OP_W, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "cmpps", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_M | OPTYPE_q | OP_W, ADDRMETH_G | OPTYPE_q |OP_R, ARG_NONE, cpu_PENTIUM2, "movnti", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "pinsrw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_N | OPTYPE_q | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "pextrw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "shufps", 0, 0, 0),  
(25, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  # group 9
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EAX, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_ECX, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EDX, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EBX, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_ESP, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EBP, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_ESI, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EDI, 0, 0),  
    (0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrlw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrld", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrlq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmullw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_N | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmovmskb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubusb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubusw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pminub", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pand", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddusb", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddusw", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmaxub", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pandn", 0, 0, 0),  
    ( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pavgb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psraw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrad", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pavgw", 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmulhuw", 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmulhw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_M | OPTYPE_dq | OP_W, ADDRMETH_V | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "movntq", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubsb", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubsw", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pminsw", 0, 0, 0),  
( 0, INS_OR, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "por", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddsb", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddsw", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmaxsw", 0, 0, 0),  
( 0, INS_XOR, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pxor", 0, 0, 0),  
    (0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psllw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pslld", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psllq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmuludq", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmaddwd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "psadbw", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_N | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "maskmovq", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubb", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubw", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubd", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubq", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddb", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddw", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddd", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_F30F = [
(16, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0), 
(17, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "lar", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "lsl", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "clts", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "invd", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "wbinvd", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "ud2", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_E | OPTYPE_v, ARG_NONE, ARG_NONE, cpu_80386, "NOP", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
    ( 0, INS_MOV, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movups", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_W | OPTYPE_ps | OP_W, ADDRMETH_V | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movups", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_V | OPTYPE_q | OP_W, ADDRMETH_M | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movlps", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_M | OPTYPE_q | OP_W, ADDRMETH_V | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movlps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "unpcklps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "unpckhps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_q | OP_W, ADDRMETH_M | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movhps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_M | OPTYPE_q | OP_W, ADDRMETH_V | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movhps", 0, 0, 0),  
(18, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_E | OPTYPE_v, ARG_NONE, ARG_NONE, cpu_80386, "NOP", 0, 0, 0),  
    ( 0, INS_MOV, ADDRMETH_R | OPTYPE_d | OP_W, ADDRMETH_C | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_R | OPTYPE_d | OP_W, ADDRMETH_D | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_C | OPTYPE_d | OP_W, ADDRMETH_R | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_D | OPTYPE_d | OP_W, ADDRMETH_R | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movaps", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_W | OPTYPE_ps | OP_W, ADDRMETH_V | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movaps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_R, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "cvtpi2ps", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_M | OPTYPE_ps | OP_W, ADDRMETH_V | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movntps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_Q | OPTYPE_q | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "cvttps2pi", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_Q | OPTYPE_q | OP_R, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "cvtps2pi", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ss | OP_W, ADDRMETH_W | OPTYPE_ss | OP_R, ARG_NONE, cpu_PENTIUM2, "ucomiss", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_W, ARG_NONE, cpu_PENTIUM2, "comiss", 0, 0, 0),  
    (0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "wrmsr", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "rdtsc", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "rdmsr", 0, 0, 0),  
(0, INS_OTHER, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTPRO, "rdpmc", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "sysenter", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "sysexit", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  # 3-byte escape 28
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  # 3-byte escape 2a
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
    ( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovo", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovno", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovc", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovnc", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovz", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovnz", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovbe", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmova", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovs", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovns", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovpe", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovpo", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovl", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovge", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovle", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovg", 0, 0, 0),  
    ( 0, INS_MOV, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_U | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movmskps", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "sqrtps", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "rsqrtps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "rcpps", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "andps", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "andnps", 0, 0, 0),  
( 0, INS_OR, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "orps", 0, 0, 0),  
( 0, INS_XOR, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "xorps", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "addps", 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_V | OPTYPE_ps | OP_R, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "mulps", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_pd | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "cvtps2pd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_dq |OP_R, ARG_NONE, cpu_PENTIUM2, "cvtdq2ps", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "subps", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "minps", 0, 0, 0),  
( 0, INS_DIV, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "divps", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "maxps", 0, 0, 0),  
    ( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpcklbw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpcklwd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckldq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "packsswb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "packuswb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhbw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhwd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhdq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "packssdw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_P | OPTYPE_d | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "movd", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "movq", 0, 0, 0),  
    ( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ADDRMETH_I |  OPTYPE_b | OP_R, cpu_PENTIUM2, "pshufw", 0, 0, 0),  
(19, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  
(20, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  
(21, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqb", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqw", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqd", 0, 0, 0),  
(0, INS_OTHER, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, "emms", 0, 0, 0),  
(0, INS_SYSTEM, ADDRMETH_E | OPTYPE_d | OP_W, ADDRMETH_G | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTIUM2, "vmread", 0, 0, 0),  
(0, INS_SYSTEM, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTIUM2, "vmwrite", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_E | OPTYPE_d | OP_W, ADDRMETH_P | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "movd", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_Q | OPTYPE_q | OP_W, ADDRMETH_P | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "movq", 0, 0, 0),  
    ( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jo", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jno", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jc", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnc", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jz", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnz", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jbe", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "ja", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "js", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jns", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpe", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpo", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jl", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jge", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jle", 0, 0, 0),  
( 0, INS_BRANCHCC, ADDRMETH_J | OPTYPE_z | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jg", 0, 0, 0),  
    ( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "seto", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setno", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setc", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setnc", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setz", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setnz", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setbe", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "seta", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "sets", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setns", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setpe", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setpo", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setl", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setge", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setle", 0, 0, 0),  
( 0, INS_MOVCC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setg", 0, 0, 0),  
    (0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_FS, 0, 0),  
(0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_FS, 0, 0),  
(0, INS_CPUID, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "cpuid", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bt", 0, 0, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_80386, "shld", 0, 0, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, OP_R | OP_REG, cpu_80386, "shld", 0, 0, e_i386_regs.REG_CL), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, INS_PUSH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", e_i386_regs.REG_GS, 0, 0),  
(0, INS_POP, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", e_i386_regs.REG_GS, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "rsm", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bts", 0, 0, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_80386, "shrd", 0, 0, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, OP_R | OP_REG, cpu_80386, "shrd", 0, 0, e_i386_regs.REG_CL), 
(22, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, 0, 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "imul", 0, 0, 0),  
    ( 0, INS_XCHGCC, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_W, ARG_NONE, cpu_80486, "cmpxchg", 0, 0, 0),  
( 0, INS_XCHGCC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_W, ARG_NONE, cpu_80486, "cmpxchg", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p | OP_R, ARG_NONE, cpu_80386, "lss", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "btr", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p| OP_R, ARG_NONE, cpu_80386, "lfs", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p | OP_R, ARG_NONE, cpu_80386, "lgs", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "movzx", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "movzx", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "ud1", 0, 0, 0),  #### GROUP 10?
(23, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "btc", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_G | OPTYPE_v | OP_R | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bsf", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_G | OPTYPE_v | OP_R | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bsr", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "movsx", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "movsx", 0, 0, 0),  
    ( 0, INS_ADD, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_W, ARG_NONE, cpu_80486, "xadd", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v, ARG_NONE, cpu_80486, "xadd", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_V | OPTYPE_ps| OP_W, ADDRMETH_W | OPTYPE_ps| OP_W, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "cmpps", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_M | OPTYPE_q | OP_W, ADDRMETH_G | OPTYPE_q |OP_R, ARG_NONE, cpu_PENTIUM2, "movnti", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "pinsrw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_N | OPTYPE_q | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "pextrw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "shufps", 0, 0, 0),  
(25, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0),  # group 9
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EAX, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_ECX, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EDX, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EBX, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_ESP, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EBP, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_ESI, 0, 0),  
( 0, INS_XCHG, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", e_i386_regs.REG_EDI, 0, 0),  
    (0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrlw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrld", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrlq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmullw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_N | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmovmskb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubusb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubusw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pminub", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pand", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddusb", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddusw", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmaxub", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pandn", 0, 0, 0),  
    ( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pavgb", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psraw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrad", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pavgw", 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmulhuw", 0, 0, 0),  
( 0, INS_MUL, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmulhw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_M | OPTYPE_dq | OP_W, ADDRMETH_V | OPTYPE_dq | OP_R, ARG_NONE, cpu_PENTIUM2, "movntq", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubsb", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubsw", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pminsw", 0, 0, 0),  
( 0, INS_OR, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "por", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddsb", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddsw", 0, 0, 0),  
( 0, INS_ARITH, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmaxsw", 0, 0, 0),  
( 0, INS_XOR, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pxor", 0, 0, 0),  
    (0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psllw", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pslld", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psllq", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmuludq", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmaddwd", 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "psadbw", 0, 0, 0),  
( 0, INS_MOV, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_N | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "maskmovq", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubb", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubw", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubd", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubq", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddb", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddw", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddd", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""

tbl32_0F00 = [
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "sldt", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "str", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lldt", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "ltr", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "verr", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "verw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""

tbl32_0F01_00BF = [
( 0, INS_SYSTEM, ADDRMETH_M | OPTYPE_s | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "sgdt", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_M | OPTYPE_s | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "sidt", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_M | OPTYPE_s | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lgdt", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_M | OPTYPE_s | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lidt", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "smsw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lmsw", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_M | OPTYPE_b | OP_R, ARG_NONE, ARG_NONE, cpu_80486, "invlpg", 0, 0, 0   )
]

tbl32_0F01_rest = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "vmcall", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "vmlaunch", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "vmresume", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "vmxoff", 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "smsw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lmsw", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "monitor", 0, 0, 0),  
(0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "mwait", 0, 0, 0),    
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
 (0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "smsw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lmsw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
 (0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "smsw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lmsw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
 (0, INS_OTHER, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "swapgs", 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "smsw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lmsw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_0F18 = [
( 0, INS_SYSTEM,  OP_W | ADDRMETH_M, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "prefetch", 0, 0, 0),  
( 0, INS_SYSTEM, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "prefetch", e_i386_regs.REG_TEST0, 0, 0),
( 0, INS_SYSTEM, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "prefetch", e_i386_regs.REG_TEST1, 0, 0),
( 0, INS_SYSTEM, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "prefetch", e_i386_regs.REG_TEST2, 0, 0),
#( 0, INS_SYSTEM, OP_REG | OP_W | ADDRMETH_M, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "prefetch", 0 + REG_TEST_OFFSET, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_0F71 = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_N | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psrlw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_N | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psraw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_N | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psllw", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_0F72 = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_N | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psrld", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_N | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psrad", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_OTHER, ADDRMETH_N | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "pslld", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_0F73 = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
( 0, INS_OTHER, ADDRMETH_N | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psrlq", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
( 0, INS_OTHER, ADDRMETH_N | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psllq", 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ) 
]

"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
#FIXME there are more...  like 660F72 and all the VM ones...
tbl32_660F73 = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
#( 0, INS_OTHER, ADDRMETH_V | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psrlq", 0, 0, 0),
( 0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psrlq", 0, 0, 0),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
#(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
#(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ) 
(0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psllq", 0, 0, 0),
(0, INS_OTHER, ADDRMETH_V | OPTYPE_dq | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psldq", 0, 0, 0),
]

"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_0FAE_00BF = [	# IA32 manuals don't list an actual address method... guessing by trial/error
( 0, INS_FPU, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_PENTMMX, "fxsave", 0, 0, 0),  
( 0, INS_FPU, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, ARG_NONE, cpu_PENTMMX, "fxrstor", 0, 0, 0),  
( 0, INS_FPU, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "ldmxcsr", 0, 0, 0),  
( 0, INS_FPU, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "stmxcsr", 0, 0, 0),  
( 0, INS_FPU, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, 'xsave', 0, 0, 0  ), 
( 0, INS_FPU, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, 'xrstor', 0, 0, 0  ), 
#( 0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
#( 0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
( 0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
( 0, INS_FPU, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "clflush", 0, 0, 0  )
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_0FAE_rest = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
( 0, INS_FPU, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "lfence", 0, 0, 0  ),
( 0, INS_FPU, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "mfence", 0, 0, 0  ),
( 0, INS_FPU, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "sfence", 0, 0, 0  )
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_0FBA = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0  ), 
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "bt", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "bts", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "btr", 0, 0, 0),  
( 0, INS_BITTEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "btc", 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_0FC2 = [
( 0, INS_XCHGCC, ADDRMETH_M | OPTYPE_q | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM, "cmpxch8b", 0, 0, 0   ),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, INS_SYSTEM, ADDRMETH_M | OPTYPE_q | OP_W, ARG_NONE, ARG_NONE, 0, "vmptrld", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_0FC7_00BF = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
( 0, INS_XCHGCC, ADDRMETH_M | OPTYPE_q | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM, "cmpxch8b", 0, 0, 0   ),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, INS_SYSTEM, ADDRMETH_M | OPTYPE_q | OP_W, ARG_NONE, ARG_NONE, 0, "vmptrld", 0, 0, 0),  
(0, INS_SYSTEM, ADDRMETH_M | OPTYPE_q | OP_W, ARG_NONE, ARG_NONE, 0, "vmptrst", 0, 0, 0)  
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_0FC7_rest = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_660FC7_00BF = [
( 0, INS_XCHGCC, ADDRMETH_M | OPTYPE_q | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM, "cmpxch8b", 0, 0, 0   ),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, INS_SYSTEM, ADDRMETH_M | OPTYPE_q | OP_W, ARG_NONE, ARG_NONE, 0, "vmclear", 0, 0, 0),  
(0, INS_SYSTEM, ADDRMETH_M | OPTYPE_q | OP_W, ARG_NONE, ARG_NONE, 0, "vmptrst", 0, 0, 0)  
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_660FC7_rest = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_F20FC7_00BF = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_F20FC7_rest = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_F30FC7_00BF = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, INS_SYSTEM, ADDRMETH_M | OPTYPE_q | OP_W, ARG_NONE, ARG_NONE, 0, "vmclear", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_F30FC7_rest = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_F30FC7_00BF = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, INS_SYSTEM, ADDRMETH_M | OPTYPE_q | OP_W, ARG_NONE, ARG_NONE, 0, "vmxon", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_F30FC7_rest = [
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_80 = [
( 0, INS_ADD, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0),  
( 0, INS_OR,  ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0),  
( 0, INS_XOR, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_E | OPTYPE_b | OP_R, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_81 = [
( 0, INS_ADD, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_z | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0),  
( 0, INS_OR,  ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_z | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_z | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_z | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_z | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_z | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0),  
( 0, INS_XOR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_z | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_z | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_82 = [
( 0, INS_ADD, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0),  
( 0, INS_OR,  ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0),  
( 0, INS_XOR, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_E | OPTYPE_b | OP_R, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_83 = [
( 0, INS_ADD, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0),  
( 0, INS_OR,  ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0),  
( 0, INS_ADD, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0),  
( 0, INS_AND, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0),  
( 0, INS_SUB, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0),  
( 0, INS_XOR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0),  
( 0, INS_CMP, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_C0 = [
( 0, INS_ROL, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "rol", 0, 0, 0),  
( 0, INS_ROR, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "ror", 0, 0, 0),  
( 0, INS_ROL, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "rcl", 0, 0, 0),  
( 0, INS_ROR, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "rcr", 0, 0, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "shl", 0, 0, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "shr", 0, 0, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sal", 0, 0, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sar", 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_C1 = [
( 0, INS_ROL, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "rol", 0, 0, 0),  
( 0, INS_ROR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "ror", 0, 0, 0),  
( 0, INS_ROL, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "rcl", 0, 0, 0),  
( 0, INS_ROR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "rcr", 0, 0, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "shl", 0, 0, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "shr", 0, 0, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sal", 0, 0, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sar", 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_D0 = [
( 0, INS_ROL, ADDRMETH_E | OPTYPE_b | OP_W, OP_IMM  | OP_R, ARG_NONE, cpu_80386, "rol", 0, 1, 0),  
( 0, INS_ROR, ADDRMETH_E | OPTYPE_b | OP_W, OP_IMM  | OP_R, ARG_NONE, cpu_80386, "ror", 0, 1, 0),  
( 0, INS_ROL, ADDRMETH_E | OPTYPE_b | OP_W, OP_IMM  | OP_R, ARG_NONE, cpu_80386, "rcl", 0, 1, 0),  
( 0, INS_ROR, ADDRMETH_E | OPTYPE_b | OP_W, OP_IMM  | OP_R, ARG_NONE, cpu_80386, "rcr", 0, 1, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_b | OP_W, OP_IMM  | OP_R, ARG_NONE, cpu_80386, "shl", 0, 1, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_b | OP_W, OP_IMM  | OP_R, ARG_NONE, cpu_80386, "shr", 0, 1, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_b | OP_W, OP_IMM  | OP_R, ARG_NONE, cpu_80386, "sal", 0, 1, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_b | OP_W, OP_IMM  | OP_R, ARG_NONE, cpu_80386, "sar", 0, 1, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_D1 = [
( 0, INS_ROL, ADDRMETH_E | OPTYPE_v | OP_W, OP_IMM | OP_R, ARG_NONE, cpu_80386, "rol", 0, 1, 0),  
( 0, INS_ROR, ADDRMETH_E | OPTYPE_v | OP_W, OP_IMM | OP_R, ARG_NONE, cpu_80386, "ror", 0, 1, 0),  
( 0, INS_ROL, ADDRMETH_E | OPTYPE_v | OP_W, OP_IMM | OP_R, ARG_NONE, cpu_80386, "rcl", 0, 1, 0),  
( 0, INS_ROR, ADDRMETH_E | OPTYPE_v | OP_W, OP_IMM | OP_R, ARG_NONE, cpu_80386, "rcr", 0, 1, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, OP_IMM | OP_R, ARG_NONE, cpu_80386, "shl", 0, 1, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, OP_IMM | OP_R, ARG_NONE, cpu_80386, "shr", 0, 1, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, OP_IMM | OP_R, ARG_NONE, cpu_80386, "sal", 0, 1, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, OP_IMM | OP_R, ARG_NONE, cpu_80386, "sar", 0, 1, 0   ) 
]
#( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OP_IMM | OP_R, ARG_NONE, cpu_80386, "sar", 0, 1, 0   ) 


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_D2 = [
( 0, INS_ROL, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "rol", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_ROR, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "ror", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_ROL, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "rcl", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_ROR, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "rcr", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "shl", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "shr", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "sal", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "sar", 0, e_i386_regs.REG_CL, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_D3 = [
( 0, INS_ROL, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "rol", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_ROR, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "ror", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_ROL, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "rcl", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_ROR, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "rcr", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "shl", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "shr", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_SHL, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "sal", 0, e_i386_regs.REG_CL, 0),  
( 0, INS_SHR, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "sar", 0, e_i386_regs.REG_CL, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_F6 = [
( 0, INS_TEST, ADDRMETH_E | OPTYPE_b | OP_R, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "test", 0, 0, 0),  
( 0, INS_TEST, ADDRMETH_E | OPTYPE_b | OP_R, ADDRMETH_I | OPTYPE_b | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "test", 0, 0, 0),  
( 0, INS_NOT, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "not", 0, 0, 0),  
( 0, INS_NEG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "neg", 0, 0, 0),  
( 0, INS_MUL, OP_REG | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mul", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_MUL, OP_REG | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "imul", e_i386_regs.REG_AL, 0, 0),  
( 0, INS_DIV, OP_REG | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "div", e_i386_regs.REG_AL, 0, 0),  
#( 0, INS_DIV, OP_REG | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "idiv", e_i386_regs.REG_AL, 0, 0   ) 
( 0, INS_DIV, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "idiv", e_i386_regs.REG_AL, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_F7 = [
( 0, INS_TEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_z | OP_R, ARG_NONE, cpu_80386, "test", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ),
#( 0, INS_TEST, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_z | OP_SIGNED | OP_R, ARG_NONE, cpu_80386, "test", 0, 0, 0),  
( 0, INS_NOT, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "not", 0, 0, 0),  
( 0, INS_NEG, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "neg", 0, 0, 0),  
( 0, INS_MUL, OP_REG | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mul", e_i386_regs.REG_EAX, 0, 0),  
( 0, INS_MUL, OP_REG | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "imul", e_i386_regs.REG_EAX, 0, 0),  
( 0, INS_DIV, OP_REG | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "div", e_i386_regs.REG_EAX, 0, 0),  
#( 0, INS_DIV, OP_REG | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "idiv", e_i386_regs.REG_EAX, 0, 0) 
( 0, INS_DIV, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "idiv", e_i386_regs.REG_EAX, 0, 0) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_FE = [
( 0, INS_INC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "inc", 0, 0, 0),  
( 0, INS_DEC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", 0, 0, 0), 
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ),
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_FF = [
( 0, INS_INC, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "inc", 0, 0, 0),  
( 0, INS_DEC, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", 0, 0, 0),  
( 0, INS_CALL, ADDRMETH_E | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "call", 0, 0, 0),  
( 0, INS_CALL, ADDRMETH_E | OPTYPE_p | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "call", 0, 0, 0),  
( 0, INS_BRANCH, ADDRMETH_E | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jmp", 0, 0, 0),  
( 0, INS_BRANCH, ADDRMETH_E | OPTYPE_p | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jmp", 0, 0, 0),  
( 0, INS_PUSH, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 0, 0, 0),  
(0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuD8_00BF = [
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fs|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fadd",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fs|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fmul",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fs|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fcom",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fs|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fcomp",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fs|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fsub",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fs|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fsubr",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fs|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fdiv",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fs|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fdivr",0,0,0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuD8_rest = [
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcom",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcom",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcom",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcom",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcom",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcom",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcom",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcom",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 )
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuD9_00BF = [
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fs|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fld",0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fs|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fst",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fs|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstp",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fv|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fldenv",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fldcw",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fv|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstenv",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstcw",0,0,0 )
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuD9_rest = [
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fld",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fld",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fld",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fld",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fld",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fld",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fld",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fld",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  

( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fxch",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fxch",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fxch",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fxch",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fxch",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fxch",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fxch",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fxch",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fnop",0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fchs",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fabs",0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"ftst",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fxam",0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fld1",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fldl2t",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fldl2e",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fldpi",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fldlg2",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fldln2",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fldz",0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"f2xm1",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fyl2x",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fptan",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fpatan",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fxtract",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fprem1",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fdecstp",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fincstp",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fprem",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fyl2xp1",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fsqrt",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fsincos",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"frndint",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fscale",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fsin",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fcos",0,0,0 )
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuDA_00BF = [
( 0,INS_FPU,ADDRMETH_M|OPTYPE_d|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fiadd",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_d|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fimul",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_d|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"ficom",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_d|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"ficomp",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_d|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fisub",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_d|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fisubr",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_d|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fidiv",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_d|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fidivr",0,0,0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuDA_rest = [
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmove",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmove",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmove",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmove",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmove",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmove",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmove",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmove",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fucompp",0,0,0 ), 
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 )
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuDB_00BF = [
( 0,INS_FPU,ADDRMETH_M|OPTYPE_d|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fild",0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_d|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fist",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_d|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fistp",0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fe|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fld",0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fe|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstp",0,0,0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuDB_rest = [
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnb",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovne",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovne",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovne",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovne",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovne",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovne",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovne",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovne",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnbe",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcmovnu",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fclex",0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"finit",0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomi",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 )
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuDC_00BF = [
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fd|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fadd",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fd|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fmul",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fd|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fcom",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fd|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fcomp",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fd|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fsub",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fd|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fsubr",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fd|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fdiv",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fd|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fdivr",0,0,0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuDC_rest = [
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST1,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST2,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST3,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST4,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST5,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST6,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fadd",e_i386_regs.REG_ST7,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST1,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST2,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST3,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST4,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST5,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST6,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmul",e_i386_regs.REG_ST7,e_i386_regs.REG_ST0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST1,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST2,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST3,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST4,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST5,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST6,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubr",e_i386_regs.REG_ST7,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST1,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST2,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST3,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST4,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST5,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST6,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsub",e_i386_regs.REG_ST7,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST1,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST2,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST3,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST4,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST5,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST6,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivr",e_i386_regs.REG_ST7,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST1,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST2,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST3,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST4,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST5,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST6,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdiv",e_i386_regs.REG_ST7,e_i386_regs.REG_ST0,0 )
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuDD_00BF = [
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fd|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fld",0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fd|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fst",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fd|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstp",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fv|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"frstor",0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fv|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fsave",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstsw",0,0,0 )
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuDD_rest = [
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"ffree",e_i386_regs.REG_ST0,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"ffree",e_i386_regs.REG_ST1,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"ffree",e_i386_regs.REG_ST2,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"ffree",e_i386_regs.REG_ST3,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"ffree",e_i386_regs.REG_ST4,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"ffree",e_i386_regs.REG_ST5,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"ffree",e_i386_regs.REG_ST6,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"ffree",e_i386_regs.REG_ST7,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fst",e_i386_regs.REG_ST0,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fst",e_i386_regs.REG_ST1,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fst",e_i386_regs.REG_ST2,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fst",e_i386_regs.REG_ST3,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fst",e_i386_regs.REG_ST4,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fst",e_i386_regs.REG_ST5,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fst",e_i386_regs.REG_ST6,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fst",e_i386_regs.REG_ST7,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstp",e_i386_regs.REG_ST0,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstp",e_i386_regs.REG_ST1,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstp",e_i386_regs.REG_ST2,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstp",e_i386_regs.REG_ST3,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstp",e_i386_regs.REG_ST4,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstp",e_i386_regs.REG_ST5,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstp",e_i386_regs.REG_ST6,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fstp",e_i386_regs.REG_ST7,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucom",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucom",e_i386_regs.REG_ST1,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucom",e_i386_regs.REG_ST2,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucom",e_i386_regs.REG_ST3,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucom",e_i386_regs.REG_ST4,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucom",e_i386_regs.REG_ST5,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucom",e_i386_regs.REG_ST6,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucom",e_i386_regs.REG_ST7,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fucomp",e_i386_regs.REG_ST0,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fucomp",e_i386_regs.REG_ST1,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fucomp",e_i386_regs.REG_ST2,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fucomp",e_i386_regs.REG_ST3,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fucomp",e_i386_regs.REG_ST4,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fucomp",e_i386_regs.REG_ST5,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fucomp",e_i386_regs.REG_ST6,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fucomp",e_i386_regs.REG_ST7,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 )
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuDE_00BF = [
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fiadd",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fimul",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"ficom",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"ficomp",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fisub",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fisubr",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fidiv",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fidivr",0,0,0)
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuDE_rest = [
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"faddp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"faddp",e_i386_regs.REG_ST1,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"faddp",e_i386_regs.REG_ST2,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"faddp",e_i386_regs.REG_ST3,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"faddp",e_i386_regs.REG_ST4,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"faddp",e_i386_regs.REG_ST5,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"faddp",e_i386_regs.REG_ST6,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"faddp",e_i386_regs.REG_ST7,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmulp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmulp",e_i386_regs.REG_ST1,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmulp",e_i386_regs.REG_ST2,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmulp",e_i386_regs.REG_ST3,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmulp",e_i386_regs.REG_ST4,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmulp",e_i386_regs.REG_ST5,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmulp",e_i386_regs.REG_ST6,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fmulp",e_i386_regs.REG_ST7,e_i386_regs.REG_ST0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,"fcompp",0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubrp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubrp",e_i386_regs.REG_ST1,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubrp",e_i386_regs.REG_ST2,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubrp",e_i386_regs.REG_ST3,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubrp",e_i386_regs.REG_ST4,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubrp",e_i386_regs.REG_ST5,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubrp",e_i386_regs.REG_ST6,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubrp",e_i386_regs.REG_ST7,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubp",e_i386_regs.REG_ST1,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubp",e_i386_regs.REG_ST2,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubp",e_i386_regs.REG_ST3,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubp",e_i386_regs.REG_ST4,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubp",e_i386_regs.REG_ST5,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubp",e_i386_regs.REG_ST6,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fsubp",e_i386_regs.REG_ST7,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivrp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivrp",e_i386_regs.REG_ST1,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivrp",e_i386_regs.REG_ST2,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivrp",e_i386_regs.REG_ST3,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivrp",e_i386_regs.REG_ST4,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivrp",e_i386_regs.REG_ST5,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivrp",e_i386_regs.REG_ST6,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivrp",e_i386_regs.REG_ST7,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivp",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivp",e_i386_regs.REG_ST1,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivp",e_i386_regs.REG_ST2,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivp",e_i386_regs.REG_ST3,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivp",e_i386_regs.REG_ST4,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivp",e_i386_regs.REG_ST5,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivp",e_i386_regs.REG_ST6,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fdivp",e_i386_regs.REG_ST7,e_i386_regs.REG_ST0,0 )
]



"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuDF_00BF = [ 
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fild",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fisttp",0,0,0),
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fist",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_w|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fistp",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fb|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fbld",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_q|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fild",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_fb|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fbstp",0,0,0 ),  
( 0,INS_FPU,ADDRMETH_M|OPTYPE_q|OP_W,ARG_NONE,ARG_NONE,cpu_80387,"fistp",0,0,0 ) 
]


"""
(optable, optype, operand 0, operand 1, operand 2, CPU required, "opcodename", op0Register, op1Register, op2Register)
"""
tbl32_fpuDF_rest = [ 
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,OP_REG,ARG_NONE,ARG_NONE,cpu_80387,"fstsw",e_i386_regs.REG_AX,0,0 ),
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fucomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST0,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST1,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST2,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST3,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST4,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST5,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST6,0 ),  
( 0,INS_FPU,OP_REG | OP_W,OP_REG | OP_R,ARG_NONE,cpu_80387,"fcomip",e_i386_regs.REG_ST0,e_i386_regs.REG_ST7,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 ),  
( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,cpu_80387,0,0,0,0 )]


tbl_INVALID = [ ( 0,0,ARG_NONE,ARG_NONE,ARG_NONE,0,0,0,0,0 ) ]

"""
        ### These values allow an opcode to be sliced and diced to make it fit correctly into the current lookup table.
        #
        #   (tbl32_0F, 0, 0xff, 0, 0xff),
        #   (tbl32_80, 3, 0x07, 0, 0xff, 4),
        #
        #           Table pointer
        #           shift bits right        (eg.  >> 4 makes each line in the table valid for 16 numbers... ie 0xc0-0xcf are all one entry in the table)
        #           mask part of the byte   (eg.  & 0x7 only makes use of the 00000111 bits...)
        #           simple subtraction
        #           highest acceptable value
        #           tables86 entry to handle the falloff (from the previous check)
"""
tables86=[
(tbl32_Main,0,0xff,0,0xff),              #0
(tbl32_0F,0,0xff,0,0xff),                #1
(tbl32_80,3,0x07,0,0xff),                #2
(tbl32_81,3,0x07,0,0xff),                #3
(tbl32_82,3,0x07,0,0xff),                #4
(tbl32_83,3,0x07,0,0xff),                #5
(tbl32_C0,3,0x07,0,0xff),                #6
(tbl32_C1,3,0x07,0,0xff),                #7
(tbl32_D0,3,0x07,0,0xff),                #8
(tbl32_D1,3,0x07,0,0xff),                #9
(tbl32_D2,3,0x07,0,0xff),                #10
(tbl32_D3,3,0x07,0,0xff),                #11
(tbl32_F6,3,0x07,0,0xff),                #12
(tbl32_F7,3,0x07,0,0xff),                #13
(tbl32_FE,3,0x07,0,0xff),                #14
(tbl32_FF,3,0x07,0,0xff),                #15
(tbl32_0F00,3,0x07,0,0xff),              #16
(tbl32_0F01_00BF,3,0x07,0,0xbf,42),      #17
(tbl32_0F18,3,0x07,0,0xff),              #18
(tbl32_0F71,3,0x07,0,0xff),              #19
(tbl32_0F72,3,0x07,0,0xff),              #20
(tbl32_0F73,3,0x07,0,0xff),              #21
(tbl32_0FAE_00BF,3,0x07,0,0xbf, 53),     #22
(tbl32_0FBA,3,0x07,0,0xff),              #23
(tbl32_0FC7_00BF,3,0x07,0,0xbf, 25),     #24
(tbl32_0FC7_rest,0,0x07,0xc0,0xff),      #25
(tbl32_fpuD8_00BF,3,0x07,0,0xbf, 27),    #26
(tbl32_fpuD8_rest,0,0xff,0xc0,0xff),     #27
(tbl32_fpuD9_00BF,3,0x07,0,0xbf, 29),    #28
(tbl32_fpuD9_rest,0,0xff,0xc0,0xff),     #29
(tbl32_fpuDA_00BF,3,0x07,0,0xbf, 31),    #30
(tbl32_fpuDA_rest,0,0xff,0xc0,0xff),     #31
(tbl32_fpuDB_00BF,3,0x07,0,0xbf, 33),    #32
(tbl32_fpuDB_rest,0,0xff,0xc0,0xff),     #33
(tbl32_fpuDC_00BF,3,0x07,0,0xbf, 35),    #34
(tbl32_fpuDC_rest,0,0xff,0xc0,0xff),     #35
(tbl32_fpuDD_00BF,3,0x07,0,0xbf, 37),    #36
(tbl32_fpuDD_rest,0,0xff,0xc0,0xff),     #37
(tbl32_fpuDE_00BF,3,0x07,0,0xbf, 39),    #38
(tbl32_fpuDE_rest,0,0xff,0xc0,0xff),     #39
(tbl32_fpuDF_00BF,3,0x07,0,0xbf, 41),    #40
(tbl32_fpuDF_rest,0,0xff,0xc0,0xff),     #41
(tbl32_0F01_rest,0,0x0f,0xc0,0xff),      #42
(tbl_INVALID, 0,0x00, 0, 0xff),          #43
(tbl32_660F,0,0xff,0,0xff),              #44
(tbl32_F20F,0,0xff,0,0xff),              #45
(tbl32_F30F,0,0xff,0,0xff),              #46
(tbl32_660FC7_00BF,3,0x07,0,0xff, 48),   #47
(tbl32_660FC7_rest,3,0x07,0xc0,0xff),    #48
(tbl32_F20FC7_00BF,3,0x07,0,0xff, 50),   #49
(tbl32_F20FC7_rest,3,0x07,0xc0,0xff),    #50
(tbl32_F30FC7_00BF,3,0x07,0,0xff, 50),   #51
(tbl32_F30FC7_rest,3,0x07,0xc0,0xff),    #52
(tbl32_0FAE_rest,3,0x07,0xc0,0xff),      #53
(tbl32_660F73,3,0x7,0,0xff)              #54
]

regs=[
        ("eax", "REG_GENERAL,REG_RET", 4),
        ("ecx", "REG_GENERAL,REG_COUNT", 4),
        ("edx", "REG_GENERAL", 4),
        ("ebx", "REG_GENERAL", 4),
        ("esp", "REG_SP", 4),
        ("ebp", "REG_GENERAL,REG_FP", 4),
        ("esi", "REG_GENERAL,REG_SRC", 4),
        ("edi", "REG_GENERAL,REG_DEST", 4),
        ("ax", "REG_GENERAL,REG_RET", 2),
        ("cx", "REG_GENERAL,REG_COUNT", 2),
        ("dx", "REG_GENERAL", 2),
        ("bx", "REG_GENERAL", 2),
        ("sp", "REG_SP", 2),
        ("bp", "REG_GENERAL,REG_FP", 2),
        ("si", "REG_GENERAL,REG_SRC", 2),
        ("di", "REG_GENERAL,REG_DEST", 2),
        ("al", "REG_GENERAL", 1),
        ("cl", "REG_GENERAL", 1),
        ("dl", "REG_GENERAL", 1),
        ("bl", "REG_GENERAL", 1),
        ("ah", "REG_GENERAL", 1),
        ("ch", "REG_GENERAL", 1),
        ("dh", "REG_GENERAL", 1),
        ("bh", "REG_GENERAL", 1),
        ("mm0", "REG_SIMD", 4),
        ("mm1", "REG_SIMD", 4),
        ("mm2", "REG_SIMD", 4),
        ("mm3", "REG_SIMD", 4),
        ("mm4", "REG_SIMD", 4),
        ("mm5", "REG_SIMD", 4),
        ("mm6", "REG_SIMD", 4),
        ("mm7", "REG_SIMD", 4),
        ("xmm0", "REG_SIMD", 4),
        ("xmm1", "REG_SIMD", 4),
        ("xmm2", "REG_SIMD", 4),
        ("xmm3", "REG_SIMD", 4),
        ("xmm4", "REG_SIMD", 4),
        ("xmm5", "REG_SIMD", 4),
        ("xmm6", "REG_SIMD", 4),
        ("xmm7", "REG_SIMD", 4),
        ("dr0", "REG_DEBUG", 4),
        ("dr1", "REG_DEBUG", 4),
        ("dr2", "REG_DEBUG", 4),
        ("dr3", "REG_DEBUG", 4),
        ("dr4", "REG_DEBUG", 4),
        ("dr5", "REG_DEBUG", 4),
        ("dr6", "REG_DEBUG,REG_SYS", 4),
        ("dr7", "REG_DEBUG,REG_SYS", 4),
        ("cr0", "REG_SYS", 4),
        ("cr1", "REG_SYS", 4),
        ("cr2", "REG_SYS", 4),
        ("cr3", "REG_SYS", 4),
        ("cr4", "REG_SYS", 4),
        ("cr5", "REG_SYS", 4),
        ("cr6", "REG_SYS", 4),
        ("cr7", "REG_SYS", 4),
        ("tr0", "REG_SYS", 4),
        ("tr1", "REG_SYS", 4),
        ("tr2", "REG_SYS", 4),
        ("tr3", "REG_SYS", 4),
        ("tr4", "REG_SYS", 4),
        ("tr5", "REG_SYS", 4),
        ("tr6", "REG_SYS", 4),
        ("tr7", "REG_SYS", 4),
        ("es", "REG_DATASEG", 2),
        ("cs", "REG_CODESEG", 2),
        ("ss", "REG_STACKSEG", 2),
        ("ds", "REG_DATASEG", 2),
        ("fs", "REG_DATASEG", 2),
        ("gs", "REG_DATASEG", 2),
        (" ", "REG_INVALID", 0),
        (" ", "REG_INVALID", 0),
        ("st(0)", "REG_FPU", "OPSIZE_FPREG"),
        ("st(1)", "REG_FPU", "OPSIZE_FPREG"),
        ("st(2)", "REG_FPU", "OPSIZE_FPREG"),
        ("st(3)", "REG_FPU", "OPSIZE_FPREG"),
        ("st(4)", "REG_FPU", "OPSIZE_FPREG"),
        ("st(5)", "REG_FPU", "OPSIZE_FPREG"),
        ("st(6)", "REG_FPU", "OPSIZE_FPREG"),
        ("st(7)", "REG_FPU", "OPSIZE_FPREG"),
        ("eflags", "REG_CC", "OPSIZE_FPREG"),
        ("fpctrl", "REG_FPU,REG_SYS", 2),
        ("fpstat", "REG_FPU,REG_SYS", 2),
        ("fptag", "REG_FPU,REG_SYS", 2),
        ("eip", "REG_PC", 4),
        ("ip", "REG_PC", 2) ]


prefix_table = {
    0xF0 : PREFIX_LOCK ,
    0xF2: PREFIX_REPNZ,
    0xF3: PREFIX_REP,
    0x2E: PREFIX_CS,
    0x36: PREFIX_SS,
    0x3E: PREFIX_DS,
    0x26: PREFIX_ES,
    0x64: PREFIX_FS,
    0x65: PREFIX_GS,
    0x66: PREFIX_OP_SIZE,
    0x67: PREFIX_ADDR_SIZE,
    0:    0
}

#eventually, change this for your own codes
#ADDEXP_SCALE_OFFSET= 0 
#ADDEXP_INDEX_OFFSET= 8
#ADDEXP_BASE_OFFSET = 16
#ADDEXP_DISP_OFFSET = 24
#MODRM_EA =  1
#MODRM_reg=  0
ADDRMETH_MASK =     0x00FF0000
OPTYPE_MASK   =     0xFF000000L
OPFLAGS_MASK  =     0x0000FFFF

