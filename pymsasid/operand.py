# -----------------------------------------------------------------------------
# operand.py
#
# author: matthieu.kaczmarek@mines-nancy.org
# Mainly rewrited from udis86 -- Vivek Mohan <vivek@sig9.com>
# -----------------------------------------------------------------------------

MAX_INSN_LENGTH = 15
NULL = 0

GPR = { 
 'T_NONE': [
        None,
        ],
  # 8 bit GPRs 
  8:[
        'al',	'cl',	'dl',	'bl',
        'ah',	'ch',	'dh',	'bh',
        'spl',	'bpl',	'sil',	'dil',
        'r8b',	'r9b',	'r10b',	'r11b',
        'r12b',	'r13b',	'r14b',	'r15b',
        ],
  # 16 bit GPRs 
  16:[
        'ax',	'cx',	'dx',	'bx',
        'sp',	'bp',	'si',	'di',
        'r8w',	'r9w',	'r10w',	'r11w',
        'r12w',	'r13w',	'r14w',	'r15w',
	],
  # 32 bit GPRs 
  32:[
        'eax',	'ecx',	'edx',	'ebx',
        'esp',	'ebp',	'esi',	'edi',
        'r8d',	'r9d',	'r10d',	'r11d',
        'r12d',	'r13d',	'r14d',	'r15d',
	],
  # 64 bit GPRs
  64:[
        'rax',	'rcx',	'rdx',	'rbx',
        'rsp',	'rbp',	'rsi',	'rdi',
        'r8',	'r9',	'r10',	'r11',
        'r12',	'r13',	'r14',	'r15',
        ],
  # segment registers 
  'T_SEG':[
        'es',	'cs',	'ss',	'ds',
        'fs',	'gs',	
        ],

  # control registers
  'T_CRG':[
        'cr0',	'cr1',	'cr2',	'cr3',
        'cr4',	'cr5',	'cr6',	'cr7',
        'cr8',	'cr9',	'cr10',	'cr11',
        'cr12',	'cr13',	'cr14',	'cr15',
        ],
	
  # debug registers 
  'T_DBG':[
        'dr0',	'dr1',	'dr2',	'dr3',
        'dr4',	'dr5',	'dr6',	'dr7',
        'dr8',	'dr9',	'dr10',	'dr11',
        'dr12',	'dr13',	'dr14',	'dr15',
        ],

  # mmx registers 
  'T_MMX':[
        'mm0',	'mm1',	'mm2',	'mm3',
        'mm4',	'mm5',	'mm6',	'mm7',
        ],

  # x87 registers 
  'T_ST':[
        'st0',	'st1',	'st2',	'st3',
        'st4',	'st5',	'st6',	'st7', 
        ],

  # extended multimedia registers 
  'T_XMM':[
        'xmm0',	 'xmm1',  'xmm2',  'xmm3',
        'xmm4',	 'xmm5',  'xmm6',  'xmm7',
        'xmm8',	 'xmm9',  'xmm10', 'xmm11',
        'xmm12', 'xmm13', 'xmm14', 'xmm15',
        ],

  # program counter
  'IP':[
        'rip',
        ],

  # Operand Types 
  'OP':[
        'OP_REG',	'OP_MEM',	'OP_PTR',	'OP_IMM',	
        'OP_JIMM',	'OP_CONST',
        ],
}

# itab prefix bits 

P_none =         ( 0 )
P_c1 =           ( 1 << 0 )
P_rexb  =        ( 1 << 1 )
P_depM  =        ( 1 << 2 )
P_c3 =           ( 1 << 3 )
P_inv64 =        ( 1 << 4 )
P_rexw  =        ( 1 << 5 )
P_c2 =           ( 1 << 6 )
P_def64 =        ( 1 << 7 )
P_rexr =         ( 1 << 8 )
P_oso =          ( 1 << 9 )
P_aso =          ( 1 << 10 )
P_rexx =         ( 1 << 11 )
P_ImpAddr =      ( 1 << 12 )


def P_C0(n) :
    return (( n >> 0 ) & 1 )
def P_REXB(n) :
    return ( ( n >> 1 ) & 1 )
def P_DEPM(n) :
    return ( ( n >> 2 ) & 1 )
def P_C2(n) :
    return ( ( n >> 3 ) & 1 )
def P_INV64(n) : 
    return ( ( n >> 4 ) & 1 )
def P_REXW(n) :
    return ( ( n >> 5 ) & 1 )
def P_C1(n) :
    return ( ( n >> 6 ) & 1 )
def P_DEF64(n) :
    return ( ( n >> 7 ) & 1 )
def P_REXR(n) :
    return ( ( n >> 8 ) & 1 )
def P_OSO(n) :
    return ( ( n >> 9 ) & 1 )
def P_ASO(n) :
    return ( ( n >> 10 ) & 1 )
def P_REXX(n) :
    return ( ( n >> 11 ) & 1 )
def P_IMPADDR(n) :
    return ( ( n >> 12 ) & 1 )

# rex prefix bits 
def REX_W(r) :       
    return ( ( 0xF & ( r ) )  >> 3 )
def REX_R(r) :  
    return ( ( 0x7 & ( r ) )  >> 2 )
def REX_X(r) :
    return ( ( 0x3 & ( r ) )  >> 1 )
def REX_B(r) :
    return ( ( 0x1 & ( r ) )  >> 0 )
def REX_PFX_MASK(n) :
    return ( ( P_REXW(n) << 3 ) | 
             ( P_REXR(n) << 2 ) | 
             ( P_REXX(n) << 1 ) | 
             ( P_REXB(n) << 0 ) )

# scable-index-base bits 
def SIB_S(b) :
    return ( ( b ) >> 6 )
def SIB_I(b) :
    return ( ( ( b ) >> 3 ) & 7 )
def SIB_B(b) :
    return ( ( b ) & 7 )

# modrm bits 
def MODRM_REG(b) :   
    return ( ( ( b ) >> 3 ) & 7 )
def MODRM_NNN(b) : 
    return ( ( ( b ) >> 3 ) & 7 )
def MODRM_MOD(b) : 
    return ( ( ( b ) >> 6 ) & 3 )
def MODRM_RM(b) :   
    return ( ( b ) & 7 )


# operand types 

OP_NONE = 0;

OP_A = 1
OP_E = 2
OP_M = 3
OP_G = 4 
OP_I = 5

OP_AL = 6
OP_CL = 7
OP_DL = 8
OP_BL = 9
OP_AH = 10
OP_CH = 11
OP_DH = 12
OP_BH = 13

OP_ALr8b = 14
OP_CLr9b = 15
OP_DLr10b = 16
OP_BLr11b = 17
OP_AHr12b = 18
OP_CHr13b = 19
OP_DHr14b = 20
OP_BHr15b = 21


OP_AX = 22
OP_CX = 23
OP_DX = 24
OP_BX = 25
OP_SI = 26
OP_DI = 27
OP_SP = 28
OP_BP = 29

OP_rAX = 30
OP_rCX = 31
OP_rDX = 32
OP_rBX = 33  
OP_rSP = 34
OP_rBP = 35
OP_rSI = 36
OP_rDI = 37

OP_rAXr8 =  38
OP_rCXr9 =  39
OP_rDXr10 = 40
OP_rBXr11 = 41
OP_rSPr12 = 42
OP_rBPr13 = 43
OP_rSIr14 = 44
OP_rDIr15 = 45

OP_eAX = 46
OP_eCX = 47
OP_eDX = 48
OP_eBX = 49
OP_eSP = 50
OP_eBP = 51
OP_eSI = 52
OP_eDI = 53

OP_ES = 54
OP_CS = 55
OP_SS = 56
OP_DS = 57
OP_FS = 58
OP_GS = 59

OP_ST0 = 60
OP_ST1 = 61
OP_ST2 = 62
OP_ST3 = 63
OP_ST4 = 64
OP_ST5 = 65
OP_ST6 = 66
OP_ST7 = 67

OP_J = 68
OP_S = 69
OP_O = 70
OP_I1 = 71
OP_I3 = 72
OP_V = 73
OP_W = 74
OP_Q = 75
OP_P = 76
OP_R = 77
OP_C = 78
OP_D = 79
OP_VR = 80
OP_PR = 81

# operand size constants 
SZ_NA  = 0
SZ_Z   = 1
SZ_V   = 2
SZ_P   = 3
SZ_WP  = 4
SZ_DP  = 5
SZ_MDQ = 6
SZ_RDQ = 7

# the following values are used as is,
# and thus hard-coded. changing them 
# will break internals 
SZ_B   = 8
SZ_W   = 16
SZ_D   = 32
SZ_Q   = 64
SZ_T   = 80

# A single operand of an entry in the instruction table. 
# (internal use only)
class itab_entry_operand :
    type = 0
    size = 0
    def __init__ (self, type, size):
        self.type = type
        self.size = size

# itab entry operand definitions
O_rSPr12  = itab_entry_operand ( OP_rSPr12,   SZ_NA    )
O_BL      = itab_entry_operand ( OP_BL,       SZ_NA    )
O_BH      = itab_entry_operand ( OP_BH,       SZ_NA    )
O_BP      = itab_entry_operand ( OP_BP,       SZ_NA    )
O_AHr12b  = itab_entry_operand ( OP_AHr12b,   SZ_NA    )
O_BX      = itab_entry_operand ( OP_BX,       SZ_NA    )
O_Jz      = itab_entry_operand ( OP_J,        SZ_Z     )
O_Jv      = itab_entry_operand ( OP_J,        SZ_V     )
O_Jb      = itab_entry_operand ( OP_J,        SZ_B     )
O_rSIr14  = itab_entry_operand ( OP_rSIr14,   SZ_NA    )
O_GS      = itab_entry_operand ( OP_GS,       SZ_NA    )
O_D       = itab_entry_operand ( OP_D,        SZ_NA    )
O_rBPr13  = itab_entry_operand ( OP_rBPr13,   SZ_NA    )
O_Ob      = itab_entry_operand ( OP_O,        SZ_B     )
O_P       = itab_entry_operand ( OP_P,        SZ_NA    )
O_Ow      = itab_entry_operand ( OP_O,        SZ_W     )
O_Ov      = itab_entry_operand ( OP_O,        SZ_V     )
O_Gw      = itab_entry_operand ( OP_G,        SZ_W     )
O_Gv      = itab_entry_operand ( OP_G,        SZ_V     )
O_rDX     = itab_entry_operand ( OP_rDX,      SZ_NA    )
O_Gx      = itab_entry_operand ( OP_G,        SZ_MDQ   )
O_Gd      = itab_entry_operand ( OP_G,        SZ_D     )
O_Gb      = itab_entry_operand ( OP_G,        SZ_B     )
O_rBXr11  = itab_entry_operand ( OP_rBXr11,   SZ_NA    )
O_rDI     = itab_entry_operand ( OP_rDI,      SZ_NA    )
O_rSI     = itab_entry_operand ( OP_rSI,      SZ_NA    )
O_ALr8b   = itab_entry_operand ( OP_ALr8b,    SZ_NA    )
O_eDI     = itab_entry_operand ( OP_eDI,      SZ_NA    )
O_Gz      = itab_entry_operand ( OP_G,        SZ_Z     )
O_eDX     = itab_entry_operand ( OP_eDX,      SZ_NA    )
O_DHr14b  = itab_entry_operand ( OP_DHr14b,   SZ_NA    )
O_rSP     = itab_entry_operand ( OP_rSP,      SZ_NA    )
O_PR      = itab_entry_operand ( OP_PR,       SZ_NA    )
O_NONE    = itab_entry_operand ( OP_NONE,     SZ_NA    )
O_rCX     = itab_entry_operand ( OP_rCX,      SZ_NA    )
O_jWP     = itab_entry_operand ( OP_J,        SZ_WP    )
O_rDXr10  = itab_entry_operand ( OP_rDXr10,   SZ_NA    )
O_Md      = itab_entry_operand ( OP_M,        SZ_D     )
O_C       = itab_entry_operand ( OP_C,        SZ_NA    )
O_G       = itab_entry_operand ( OP_G,        SZ_NA    )
O_Mb      = itab_entry_operand ( OP_M,        SZ_B     )
O_Mt      = itab_entry_operand ( OP_M,        SZ_T     )
O_S       = itab_entry_operand ( OP_S,        SZ_NA    )
O_Mq      = itab_entry_operand ( OP_M,        SZ_Q     )
O_W       = itab_entry_operand ( OP_W,        SZ_NA    )
O_ES      = itab_entry_operand ( OP_ES,       SZ_NA    )
O_rBX     = itab_entry_operand ( OP_rBX,      SZ_NA    )
O_Ed      = itab_entry_operand ( OP_E,        SZ_D     )
O_DLr10b  = itab_entry_operand ( OP_DLr10b,   SZ_NA    )
O_Mw      = itab_entry_operand ( OP_M,        SZ_W     )
O_Eb      = itab_entry_operand ( OP_E,        SZ_B     )
O_Ex      = itab_entry_operand ( OP_E,        SZ_MDQ   )
O_Ez      = itab_entry_operand ( OP_E,        SZ_Z     )
O_Ew      = itab_entry_operand ( OP_E,        SZ_W     )
O_Ev      = itab_entry_operand ( OP_E,        SZ_V     )
O_Ep      = itab_entry_operand ( OP_E,        SZ_P     )
O_FS      = itab_entry_operand ( OP_FS,       SZ_NA    )
O_Ms      = itab_entry_operand ( OP_M,        SZ_W     )
O_rAXr8   = itab_entry_operand ( OP_rAXr8,    SZ_NA    )
O_eBP     = itab_entry_operand ( OP_eBP,      SZ_NA    )
O_Isb     = itab_entry_operand ( OP_I,        SZ_B    )
O_eBX     = itab_entry_operand ( OP_eBX,      SZ_NA    )
O_rCXr9   = itab_entry_operand ( OP_rCXr9,    SZ_NA    )
O_jDP     = itab_entry_operand ( OP_J,        SZ_DP    )
O_CH      = itab_entry_operand ( OP_CH,       SZ_NA    )
O_CL      = itab_entry_operand ( OP_CL,       SZ_NA    )
O_R       = itab_entry_operand ( OP_R,        SZ_RDQ   )
O_V       = itab_entry_operand ( OP_V,        SZ_NA    )
O_CS      = itab_entry_operand ( OP_CS,       SZ_NA    )
O_CHr13b  = itab_entry_operand ( OP_CHr13b,   SZ_NA    )
O_eCX     = itab_entry_operand ( OP_eCX,      SZ_NA    )
O_eSP     = itab_entry_operand ( OP_eSP,      SZ_NA    )
O_SS      = itab_entry_operand ( OP_SS,       SZ_NA    )
O_SP      = itab_entry_operand ( OP_SP,       SZ_NA    )
O_BLr11b  = itab_entry_operand ( OP_BLr11b,   SZ_NA    )
O_SI      = itab_entry_operand ( OP_SI,       SZ_NA    )
O_eSI     = itab_entry_operand ( OP_eSI,      SZ_NA    )
O_DL      = itab_entry_operand ( OP_DL,       SZ_NA    )
O_DH      = itab_entry_operand ( OP_DH,       SZ_NA    )
O_DI      = itab_entry_operand ( OP_DI,       SZ_NA    )
O_DX      = itab_entry_operand ( OP_DX,       SZ_NA    )
O_rBP     = itab_entry_operand ( OP_rBP,      SZ_NA    )
O_Gvw     = itab_entry_operand ( OP_G,        SZ_MDQ   )
O_I1      = itab_entry_operand ( OP_I1,       SZ_NA    )
O_I3      = itab_entry_operand ( OP_I3,       SZ_NA    )
O_DS      = itab_entry_operand ( OP_DS,       SZ_NA    )
O_ST4     = itab_entry_operand ( OP_ST4,      SZ_NA    )
O_ST5     = itab_entry_operand ( OP_ST5,      SZ_NA    )
O_ST6     = itab_entry_operand ( OP_ST6,      SZ_NA    )
O_ST7     = itab_entry_operand ( OP_ST7,      SZ_NA    )
O_ST0     = itab_entry_operand ( OP_ST0,      SZ_NA    )
O_ST1     = itab_entry_operand ( OP_ST1,      SZ_NA    )
O_ST2     = itab_entry_operand ( OP_ST2,      SZ_NA    )
O_ST3     = itab_entry_operand ( OP_ST3,      SZ_NA    )
O_E       = itab_entry_operand ( OP_E,        SZ_NA    )
O_AH      = itab_entry_operand ( OP_AH,       SZ_NA    )
O_M       = itab_entry_operand ( OP_M,        SZ_NA    )
O_AL      = itab_entry_operand ( OP_AL,       SZ_NA    )
O_CLr9b   = itab_entry_operand ( OP_CLr9b,    SZ_NA    )
O_Q       = itab_entry_operand ( OP_Q,        SZ_NA    )
O_eAX     = itab_entry_operand ( OP_eAX,      SZ_NA    )
O_VR      = itab_entry_operand ( OP_VR,       SZ_NA    )
O_AX      = itab_entry_operand ( OP_AX,       SZ_NA    )
O_rAX     = itab_entry_operand ( OP_rAX,      SZ_NA    )
O_Iz      = itab_entry_operand ( OP_I,        SZ_Z     )
O_rDIr15  = itab_entry_operand ( OP_rDIr15,   SZ_NA    )
O_Iw      = itab_entry_operand ( OP_I,        SZ_W     )
O_Iv      = itab_entry_operand ( OP_I,        SZ_V     )
O_Ap      = itab_entry_operand ( OP_A,        SZ_P     )
O_CX      = itab_entry_operand ( OP_CX,       SZ_NA    )
O_Ib      = itab_entry_operand ( OP_I,        SZ_B     )
O_BHr15b  = itab_entry_operand ( OP_BHr15b,   SZ_NA    )

# A single entry in an instruction table. 
# (internal use only)

