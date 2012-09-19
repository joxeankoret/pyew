# -----------------------------------------------------------------------------
# decode.py
#
# author: matthieu.kaczmarek@mines-nancy.org
# Mainly rewrited from udis86 -- Vivek Mohan <vivek@sig9.com>
# -----------------------------------------------------------------------------

from common import DecodeException, VENDOR_INTEL, VENDOR_AMD
from inst import Inst, Operand, Ptr, ie_invalid, ie_pause, ie_nop


# this is intended: hundreds of constants used
from itab import *
from operand import *

# Extracts instruction prefixes.
def get_prefixes(u, inst):
    have_pfx = 1

    # if in error state, bail out
    if u.error:
        return -1

    # keep going as long as there are prefixes available
    i = 0
    while have_pfx:

        # Get next byte.
        u.input.next() 
        if u.error: 
            return -1
        curr = u.input.current()

        # rex prefixes in 64bit mode
        if u.dis_mode == 64 and (curr & 0xF0) == 0x40:
            inst.pfx.rex = curr
        else:
            if curr == 0x2E:
                inst.pfx.seg = 'cs' 
                inst.pfx.rex = 0
            elif curr == 0x36:     
                inst.pfx.seg = 'ss' 
                inst.pfx.rex = 0
            elif curr == 0x3E: 
                inst.pfx.seg = 'ds' 
                inst.pfx.rex = 0
            elif curr == 0x26: 
                inst.pfx.seg = 'es' 
                inst.pfx.rex = 0
            elif curr == 0x64: 
                inst.pfx.seg = 'fs' 
                inst.pfx.rex = 0
            elif curr == 0x65: 
                inst.pfx.seg = 'gs' 
                inst.pfx.rex = 0
            elif curr == 0x67: #adress-size override prefix  
                inst.pfx.adr = 0x67
                inst.pfx.rex = 0
            elif curr == 0xF0: 
                inst.pfx.lock = 0xF0
                inst.pfx.rex  = 0
            elif curr == 0x66: 
                # the 0x66 sse prefix is only effective if no other sse prefix
                # has already been specified.
                if inst.pfx.insn == 0:
                    inst.pfx.insn = 0x66
                inst.pfx.opr = 0x66           
                inst.pfx.rex = 0
            elif curr == 0xF2:
                inst.pfx.insn  = 0xF2
                inst.pfx.repne = 0xF2 
                inst.pfx.rex   = 0
            elif curr == 0xF3:
                inst.pfx.insn = 0xF3
                inst.pfx.rep  = 0xF3 
                inst.pfx.repe = 0xF3 
                inst.pfx.rex  = 0
            else: 
                # No more prefixes
                have_pfx = 0

        # check if we reached max instruction length
        if(i + 1) == MAX_INSN_LENGTH:
            u.error = 1
        i += 1

    # return status
    if u.error:
        return -1 

    # rewind back one byte in stream, since the above loop 
    # stops with a non-prefix byte. 
    u.input.back()

    # speculatively determine the effective operand mode,
    # based on the prefixes and the current disassembly
    # mode. This may be inaccurate, but useful for mode
    # dependent decoding.
    if u.dis_mode == 64:
        if REX_W(inst.pfx.rex):
            inst.opr_mode = 64 
        elif inst.pfx.opr:
            inst.opr_mode = 16
        elif(P_DEF64(inst.itab_entry.prefix)):
            inst.opr_mode = 64
        else:
            inst.opr_mode = 32
        if inst.pfx.adr:
            inst.adr_mode = 32 
        else: 
            inst.adr_mode = 64 
    elif u.dis_mode == 32:
        if inst.pfx.opr:
            inst.opr_mode = 16
        else:
            inst.opr_mode = 32
        if inst.pfx.adr:
            inst.adr_mode = 16 
        else: 
            inst.adr_mode = 32 
    elif u.dis_mode == 16:
        if inst.pfx.opr:
            inst.opr_mode = 32
        else:
            inst.opr_mode = 16
        if inst.pfx.adr:
            inst.adr_mode = 32 
        else: 
            inst.adr_mode = 16 
    return 0


# Searches the instruction tables for the right entry.
def search_itab(u, inst):
    # if in state of error, return 
    did_peek = 0
    if u.error:
        return -1

    # get first byte of opcode
    u.input.next() 
    if u.error:
        return -1
    curr = u.input.current() 
    if curr == None :
        inst.itab_entry = ie_invalid
        inst.operator = inst.itab_entry.operator
        return 0        

    # resolve xchg, nop, pause crazyness
    if 0x90 == curr:
        if not(u.dis_mode == 64 and REX_B(inst.pfx.rex)):
            if(inst.pfx.rep):
                inst.pfx.rep = 0
                e = ie_pause
            else:
                e = ie_nop
            inst.itab_entry = e
            inst.operator = inst.itab_entry.operator
            return 0

    # get top-level table
    elif 0x0F == curr:
        table = ITAB__0F
        curr  = u.input.next()
        if u.error:
            return -1
        # 2byte opcodes can be modified by 0x66, F3, and F2 prefixes
        if 0x66 == inst.pfx.insn:
            if itab_list[ITAB__PFX_SSE66__0F][curr].operator != 'invalid':
                table = ITAB__PFX_SSE66__0F
                inst.pfx.opr = 0
        elif 0xF2 == inst.pfx.insn:
            if itab_list[ITAB__PFX_SSEF2__0F][curr].operator != 'invalid':
                table = ITAB__PFX_SSEF2__0F
                inst.pfx.repne = 0
        elif 0xF3 == inst.pfx.insn:
            if itab_list[ITAB__PFX_SSEF3__0F][curr].operator != 'invalid':
                table = ITAB__PFX_SSEF3__0F
                inst.pfx.repe = 0
                inst.pfx.rep  = 0
    # pick an instruction from the 1byte table
    else:
        table = ITAB__1BYTE

    index = curr

    while True:
        e = itab_list[ table ][ index ]

        # if operator constant is a standard instruction constant
        # our search is over.
        
        if e.operator in operator:
            if e.operator == 'invalid':
                if did_peek:
                    u.input.next() 
                    if u.input.error:
                        raise DecodeException('error') 
                        #return -1
            inst.itab_entry = e
            inst.operator = inst.itab_entry.operator
            return 0
    
        table = e.prefix
    
        if e.operator ==  'grp_reg':
            peek     = u.input.peek()
            did_peek = 1
            index    = MODRM_REG(peek)
        elif e.operator ==  'grp_mod':
            peek     = u.input.peek()
            did_peek = 1
            index    = MODRM_MOD(peek)
            if index == 3:
                index = ITAB__MOD_INDX__11
            else:
                index = ITAB__MOD_INDX__NOT_11
        elif e.operator ==  'grp_rm':
            curr = u.input.next()
            did_peek = 0
            if u.error:
                return -1
            index = MODRM_RM(curr)
    
        elif e.operator ==  'grp_x87':
            curr     = u.input.next()
            did_peek = 0
            if u.error:
                return -1
            index    = curr - 0xC0
    
        elif e.operator ==  'grp_osize':
            if inst.opr_mode == 64:
                index = ITAB__MODE_INDX__64
            elif inst.opr_mode == 32: 
                index = ITAB__MODE_INDX__32
            else:
                index = ITAB__MODE_INDX__16
     
        elif e.operator ==  'grp_asize':
            if inst.adr_mode == 64:
                index = ITAB__MODE_INDX__64
            elif inst.adr_mode == 32: 
                index = ITAB__MODE_INDX__32
            else:
                index = ITAB__MODE_INDX__16
    
        elif e.operator ==  'grp_mode':
            if u.dis_mode == 64:
                index = ITAB__MODE_INDX__64
            elif u.dis_mode == 32:
                index = ITAB__MODE_INDX__32
            else:
                index = ITAB__MODE_INDX__16
    
        elif e.operator ==  'grp_vendor':
            if u.vendor == VENDOR_INTEL: 
                index = ITAB__VENDOR_INDX__INTEL
            elif u.vendor == VENDOR_AMD:
                index = ITAB__VENDOR_INDX__AMD
            else:
                raise DecodeException('unrecognized vendor id')
    
        elif e.operator ==  'd3vil':
            raise DecodeException('invalid instruction operator constant Id3vil')
        else:
            raise DecodeException('invalid instruction operator constant')
    
    inst.itab_entry = e
    inst.operator = inst.itab_entry.operator
    return 0

def resolve_operand_size(u, inst, s):
    if s ==  SZ_V:
        return inst.opr_mode
    elif s ==  SZ_Z:  
        if inst.opr_mode == 16:
            return 16
        else:
            return 32
    elif s ==  SZ_P:  
        if inst.opr_mode == 16:
            return SZ_WP
        else:
            return SZ_DP
    elif s ==  SZ_MDQ:
        if inst.opr_mode == 16:
            return 32
        else:
            return inst.opr_mode
    elif s ==  SZ_RDQ:
        if u.dis_mode == 64:
            return 64
        else:
            return 32
    else:
        return s


def resolve_operator(u, inst):
    # far/near flags 
    inst.branch_dist = None
    # readjust operand sizes for call/jmp instrcutions 
    if inst.operator == 'call' or inst.operator == 'jmp':
        # WP: 16bit pointer 
        if inst.operand[0].size == SZ_WP:
            inst.operand[0].size = 16
            inst.branch_dist = 'far'
        # DP: 32bit pointer
        elif inst.operand[0].size == SZ_DP:
            inst.operand[0].size = 32
            inst.branch_dist = 'far'
        elif inst.operand[0].size == 8:
            inst.branch_dist = 'near'
    # resolve 3dnow weirdness 
    elif inst.operator == '3dnow': 
        inst.operator = itab_list[ITAB__3DNOW][u.input.current()].operator
    # SWAPGS is only valid in 64bits mode
    if inst.operator == 'swapgs' and u.dis_mode != 64:
        u.error = 1
        return -1
    return 0

def decode_a(u, inst, op):
    """Decodes operands of the type seg:offset."""
    if inst.opr_mode == 16:  
        # seg16:off16 
        op.type = 'OP_PTR'
        op.size = 32
        op.lval = Ptr(u.input.read(16), u.input.read(16))
    else:
        # seg16:off32 
        op.type = 'OP_PTR'
        op.size = 48
        op.lval = Ptr(u.input.read(32), u.input.read(16))

def decode_gpr(u, inst, s, rm):
    """Returns decoded General Purpose Register."""
    s = resolve_operand_size(u, inst, s)
          
    if s == 64:
        return GPR[64][rm]
    elif s == SZ_DP or s == 32:
        return GPR[32][rm]
    elif s == SZ_WP or s == 16:
        return GPR[16][rm]
    elif s ==  8:
        if u.dis_mode == 64 and inst.pfx.rex:
            if rm >= 4:
                return GPR[8][rm+4]
            return GPR[8][rm]
        else: 
            return GPR[8][rm]
    else:
        return None

def resolve_gpr64(u, inst, gpr_op):
    """64bit General Purpose Register-Selection."""
    if gpr_op in  range(OP_rAXr8, OP_rDIr15) :
        index = (gpr_op - OP_rAXr8) |(REX_B(inst.pfx.rex) << 3)          
    else:
        index = gpr_op - OP_rAX
    if inst.opr_mode == 16:
        return GPR[16][index]
    elif u.dis_mode == 32 or not(inst.opr_mode == 32 and REX_W(inst.pfx.rex) == 0):
        return GPR[32][index]
    return GPR[64][index]

def resolve_gpr32(u, inst, gpr_op):
    """32bit General Purpose Register-Selection."""
    index = gpr_op - OP_eAX
    if(inst.opr_mode == 16):
        return GPR[16][index]
    return GPR[32][index]

def resolve_reg(regtype, i):
    """Resolves the register type."""
    return GPR[regtype][i]

def decode_imm(u, inst, s, op):
    """Decodes Immediate values."""
    op.size = resolve_operand_size(u, inst, s)
    op.type = 'OP_IMM'
    op.lval = u.input.read(op.size) 

def decode_modrm(u, inst, op, s, rm_type, opreg, reg_size, reg_type):
    """Decodes ModRM Byte."""
    u.input.next()

    # get mod, r/m and reg fields
    mod = MODRM_MOD(u.input.current())
    rm  = (REX_B(inst.pfx.rex) << 3) | MODRM_RM(u.input.current())
    reg = (REX_R(inst.pfx.rex) << 3) | MODRM_REG(u.input.current())

    op.size = resolve_operand_size(u, inst, s)

    # if mod is 11b, then the m specifies a gpr/mmx/sse/control/debug 
    if mod == 3:
        op.type = 'OP_REG'
        if rm_type ==  'T_GPR':
            op.base = decode_gpr(u, inst, op.size, rm)
        else:   
            op.base = resolve_reg(rm_type, (REX_B(inst.pfx.rex) << 3) |(rm&7))

    # else its memory addressing 
    else: 
        op.type = 'OP_MEM'
        op.seg = inst.pfx.seg
        # 64bit addressing 
        if inst.adr_mode == 64:

            op.base = GPR[64][rm]

            # get offset type
            if mod == 1:
                op.offset = 8
            elif mod == 2:
                op.offset = 32
            elif mod == 0 and(rm & 7) == 5:          
                op.base = 'rip'
                op.offset = 32
            else:
                op.offset = 0

            # Scale-Index-Base(SIB)
            if rm & 7 == 4:
                u.input.next()
                
                op.scale = (1 << SIB_S(u.input.current())) & ~1
                op.index = GPR[64][(SIB_I(u.input.current()) |(REX_X(inst.pfx.rex) << 3))]
                op.base  = GPR[64][(SIB_B(u.input.current()) |(REX_B(inst.pfx.rex) << 3))]

                # special conditions for base reference
                if op.index == 'rsp':
                    op.index = None
                    op.scale = 0

                if op.base == 'rbp' or op.base == 'r13':
                    if mod == 0: 
                        op.base = None
                    if mod == 1:
                        op.offset = 8
                    else:
                        op.offset = 32

        # 32-Bit addressing mode 
        elif inst.adr_mode == 32:

            # get base 
            op.base = GPR[16][rm]

            # get offset type 
            if mod == 1:
                op.offset = 8
            elif mod == 2:
                op.offset = 32
            elif mod == 0 and rm == 5:
                op.base = None
                op.offset = 32
            else:
                op.offset = 0

            # Scale-Index-Base(SIB)
            if(rm & 7) == 4:
                u.input.next()

                op.scale = (1 << SIB_S(u.input.current())) & ~1
                op.index = GPR[32][SIB_I(u.input.current()) |(REX_X(inst.pfx.rex) << 3)]
                op.base  = GPR[32][SIB_B(u.input.current()) |(REX_B(inst.pfx.rex) << 3)]

                if op.index == 'esp':
                    op.index = None
                    op.scale = 0

                # special condition for base reference 
                if op.base == 'ebp':
                    if mod == 0:
                        op.base = None
                    if mod == 1:
                        op.offset = 8
                    else:
                        op.offset = 32

        # 16bit addressing mode 
        else:
            if rm == 0: 
                op.base = 'bx'
                op.index = 'si'
            elif rm == 1: 
                op.base = 'bx'
                op.index = 'di'
            elif rm == 2: 
                op.base = 'bp'
                op.index = 'si'
            elif rm == 3: 
                op.base = 'bp'
                op.index = 'di'
            elif rm == 4: 
                op.base = 'si'
            elif rm == 5: 
                op.base = 'di'
            elif rm == 6: 
                op.base = 'bp'
            elif rm == 7: 
                op.base = 'bx'
                
            if mod == 0 and rm == 6:
                op.offset = 16
                op.base = None
            elif mod == 1:
                op.offset = 8
            elif mod == 2: 
                op.offset = 16

    # extract offset, if any 
    if op.offset in [8, 16, 32, 64]: 
        op.lval  = u.input.read(op.offset)
        bound = pow(2, op.offset - 1)
        if op.lval > bound:
            op.lval = -(((2 * bound) - op.lval) % bound)

    # resolve register encoded in reg field
    if opreg:
        opreg.type = 'OP_REG'
        opreg.size = resolve_operand_size(u, inst, reg_size)
        if reg_type == 'T_GPR': 
            opreg.base = decode_gpr(u, inst, opreg.size, reg)
        else:
            opreg.base = resolve_reg(reg_type, reg)

def decode_o(u, inst, s, op):
    """Decodes offset."""
    op.seg = inst.pfx.seg
    op.offset = inst.adr_mode 
    op.lval = u.input.read(inst.adr_mode) 
    op.type = 'OP_MEM'
    op.size = resolve_operand_size(u, inst, s)

def disasm_operands(u, inst):
    """Disassembles Operands."""
    # get type
    def get_mopt(x): return x.type
    mopt = map(get_mopt, inst.itab_entry.operand)
    # get size
    def get_mops(x): return x.size
    mops = map(get_mops, inst.itab_entry.operand)

    if mopt[2] != OP_NONE:
        inst.operand = [Operand(), Operand(), Operand()]
    elif mopt[1] != OP_NONE:
        inst.operand = [Operand(), Operand()] 
    elif mopt[0] != OP_NONE:
        inst.operand = [Operand()]
    
    # iop = instruction operand 
    #iop = inst.operand
        
    if mopt[0] == OP_A:
        decode_a(u, inst, inst.operand[0])    
    # M[b] ... 
    # E, G/P/V/I/CL/1/S 
    elif mopt[0] == OP_M or mopt[0] == OP_E:
        if mopt[0] == OP_M and MODRM_MOD(u.input.peek()) == 3:
            u.error = 1
        if mopt[1] == OP_G:
            decode_modrm(u, inst, inst.operand[0], mops[0], 'T_GPR', inst.operand[1], mops[1], 'T_GPR')
            if mopt[2] == OP_I:
                decode_imm(u, inst, mops[2], inst.operand[2])
            elif mopt[2] == OP_CL:
                inst.operand[2].type = 'OP_REG'
                inst.operand[2].base = 'cl'
                inst.operand[2].size = 8
        elif mopt[1] == OP_P:
            decode_modrm(u, inst, inst.operand[0], mops[0], 'T_GPR', inst.operand[1], mops[1], 'T_MMX')
        elif mopt[1] == OP_V:
            decode_modrm(u, inst, inst.operand[0], mops[0], 'T_GPR', inst.operand[1], mops[1], 'T_XMM')
        elif mopt[1] == OP_S:
            decode_modrm(u, inst, inst.operand[0], mops[0], 'T_GPR', inst.operand[1], mops[1], 'T_SEG')
        else:
            decode_modrm(u, inst, inst.operand[0], mops[0], 'T_GPR', NULL, 0, 'T_NONE')
            if mopt[1] == OP_CL:
                inst.operand[1].type = 'OP_REG'
                inst.operand[1].base = 'cl'
                inst.operand[1].size = 8
            elif mopt[1] == OP_I1:
                inst.operand[1].type = 'OP_IMM'
                inst.operand[1].lval = 1
            elif mopt[1] == OP_I:
                decode_imm(u, inst, mops[1], inst.operand[1])

    # G, E/PR[,I]/VR 
    elif mopt[0] == OP_G:
        if mopt[1] == OP_M:
            if MODRM_MOD(u.input.peek()) == 3:
                u.error = 1
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_GPR', inst.operand[0], mops[0], 'T_GPR')
        elif mopt[1] == OP_E:
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_GPR', inst.operand[0], mops[0], 'T_GPR')
            if mopt[2] == OP_I:
                decode_imm(u, inst, mops[2], inst.operand[2])
        elif mopt[1] == OP_PR:
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_MMX', inst.operand[0], mops[0], 'T_GPR')
            if mopt[2] == OP_I:
                decode_imm(u, inst, mops[2], inst.operand[2])
        elif mopt[1] == OP_VR:
            if MODRM_MOD(u.input.peek()) != 3:
                u.error = 1
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_XMM', inst.operand[0], mops[0], 'T_GPR')
        elif mopt[1] == OP_W:
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_XMM', inst.operand[0], mops[0], 'T_GPR')

    # AL..BH, I/O/DX 
    elif mopt[0] in [OP_AL, OP_CL, OP_DL, OP_BL,
                   OP_AH, OP_CH, OP_DH, OP_BH]:
        inst.operand[0].type = 'OP_REG'
        inst.operand[0].base = GPR[8][mopt[0] - OP_AL]
        inst.operand[0].size = 8

        if mopt[1] == OP_I:
            decode_imm(u, inst, mops[1], inst.operand[1])
        elif mopt[1] == OP_DX:
            inst.operand[1].type = 'OP_REG'
            inst.operand[1].base = 'dx'
            inst.operand[1].size = 16
        elif mopt[1] == OP_O:
            decode_o(u, inst, mops[1], inst.operand[1])

    # rAX[r8]..rDI[r15], I/rAX..rDI/O
    elif mopt[0] in [OP_rAXr8, OP_rCXr9, OP_rDXr10, OP_rBXr11,
                   OP_rSPr12, OP_rBPr13, OP_rSIr14, OP_rDIr15,
                   OP_rAX, OP_rCX, OP_rDX, OP_rBX,
                   OP_rSP, OP_rBP, OP_rSI, OP_rDI]:
        inst.operand[0].type = 'OP_REG'
        inst.operand[0].base = resolve_gpr64(u, inst, mopt[0])

        if mopt[1] == OP_I:
            decode_imm(u, inst, mops[1], inst.operand[1])
        elif mopt[1] in [OP_rAX, OP_rCX, OP_rDX, OP_rBX,
                       OP_rSP, OP_rBP, OP_rSI, OP_rDI]:
            inst.operand[1].type = 'OP_REG'
            inst.operand[1].base = resolve_gpr64(u, inst, mopt[1])
        elif mopt[1] == OP_O:
            decode_o(u, inst, mops[1], inst.operand[1])  
            inst.operand[0].size = resolve_operand_size(u, inst, mops[1])

    elif mopt[0] in [OP_ALr8b, OP_CLr9b, OP_DLr10b, OP_BLr11b,
                   OP_AHr12b, OP_CHr13b, OP_DHr14b, OP_BHr15b]:
        gpr = (mopt[0] - OP_ALr8b +(REX_B(inst.pfx.rex) << 3))
        if gpr in ['ah',	'ch',	'dh',	'bh',
                   'spl',	'bpl',	'sil',	'dil',
                   'r8b',	'r9b',	'r10b',	'r11b',
                   'r12b',	'r13b',	'r14b',	'r15b',
                   ] and inst.pfx.rex: 
            gpr = gpr + 4
        inst.operand[0].type = 'OP_REG'
        inst.operand[0].base = GPR[8][gpr]
        if mopt[1] == OP_I:
            decode_imm(u, inst, mops[1], inst.operand[1])

    # eAX..eDX, DX/I 
    elif mopt[0] in [OP_eAX, OP_eCX, OP_eDX, OP_eBX,
                   OP_eSP, OP_eBP, OP_eSI, OP_eDI]:
        inst.operand[0].type = 'OP_REG'
        inst.operand[0].base = resolve_gpr32(u, inst, mopt[0])
        if mopt[1] == OP_DX:
            inst.operand[1].type = 'OP_REG'
            inst.operand[1].base = 'dx'
            inst.operand[1].size = 16
        elif mopt[1] == OP_I:
            decode_imm(u, inst, mops[1], inst.operand[1])

    # ES..GS 
    elif mopt[0] in [OP_ES, OP_CS, OP_DS,
                   OP_SS, OP_FS, OP_GS]:

        # in 64bits mode, only fs and gs are allowed 
        if u.dis_mode == 64:
            if mopt[0] != OP_FS and mopt[0] != OP_GS:
                u.error = 1
        inst.operand[0].type = 'OP_REG'
        inst.operand[0].base = GPR['T_SEG'][mopt[0] - OP_ES]
        inst.operand[0].size = 16

    # J 
    elif mopt[0] == OP_J:
        decode_imm(u, inst, mops[0], inst.operand[0])
        # MK take care of signs
        bound = pow(2, inst.operand[0].size - 1)
        if inst.operand[0].lval > bound:
            inst.operand[0].lval = -(((2 * bound) - inst.operand[0].lval) % bound)
        inst.operand[0].type = 'OP_JIMM'

    # PR, I 
    elif mopt[0] == OP_PR:
        if MODRM_MOD(u.input.peek()) != 3:
            u.error = 1
        decode_modrm(u, inst, inst.operand[0], mops[0], 'T_MMX', NULL, 0, 'T_NONE')
        if mopt[1] == OP_I:
            decode_imm(u, inst, mops[1], inst.operand[1])

    # VR, I 
    elif mopt[0] == OP_VR:
        if MODRM_MOD(u.input.peek()) != 3:
            u.error = 1
        decode_modrm(u, inst, inst.operand[0], mops[0], 'T_XMM', NULL, 0, 'T_NONE')
        if mopt[1] == OP_I:
            decode_imm(u, inst, mops[1], inst.operand[1])

    # P, Q[,I]/W/E[,I],VR 
    elif mopt[0] == OP_P:
        if mopt[1] == OP_Q:
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_MMX', inst.operand[0], mops[0], 'T_MMX')
            if mopt[2] == OP_I:
                decode_imm(u, inst, mops[2], inst.operand[2])
        elif mopt[1] == OP_W:
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_XMM', inst.operand[0], mops[0], 'T_MMX')
        elif mopt[1] == OP_VR:
            if MODRM_MOD(u.input.peek()) != 3:
                u.error = 1
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_XMM', inst.operand[0], mops[0], 'T_MMX')
        elif mopt[1] == OP_E:
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_GPR', inst.operand[0], mops[0], 'T_MMX')
            if mopt[2] == OP_I:
                decode_imm(u, inst, mops[2], inst.operand[2])

    # R, C/D 
    elif mopt[0] == OP_R:
        if mopt[1] == OP_C:
            decode_modrm(u, inst, inst.operand[0], mops[0], 'T_GPR', inst.operand[1], mops[1], 'T_CRG')
        elif mopt[1] == OP_D:
            decode_modrm(u, inst, inst.operand[0], mops[0], 'T_GPR', inst.operand[1], mops[1], 'T_DBG')

    # C, R 
    elif mopt[0] == OP_C:
        decode_modrm(u, inst, inst.operand[1], mops[1], 'T_GPR', inst.operand[0], mops[0], 'T_CRG')

    # D, R 
    elif mopt[0] == OP_D:
        decode_modrm(u, inst, inst.operand[1], mops[1], 'T_GPR', inst.operand[0], mops[0], 'T_DBG')

    # Q, P 
    elif mopt[0] == OP_Q:
        decode_modrm(u, inst, inst.operand[0], mops[0], 'T_MMX', inst.operand[1], mops[1], 'T_MMX')

    # S, E 
    elif mopt[0] == OP_S:
        decode_modrm(u, inst, inst.operand[1], mops[1], 'T_GPR', inst.operand[0], mops[0], 'T_SEG')

    # W, V 
    elif mopt[0] == OP_W:
        decode_modrm(u, inst, inst.operand[0], mops[0], 'T_XMM', inst.operand[1], mops[1], 'T_XMM')

    # V, W[,I]/Q/M/E 
    elif mopt[0] == OP_V:
        if mopt[1] == OP_W:
            # special cases for movlps and movhps 
            if MODRM_MOD(u.input.peek()) == 3:
                if inst.operator == 'movlps':
                    inst.operator = 'movhlps'
                elif inst.operator == 'movhps':
                    inst.operator = 'movlhps'
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_XMM', inst.operand[0], mops[0], 'T_XMM')
            if mopt[2] == OP_I:
                decode_imm(u, inst, mops[2], inst.operand[2])
        elif mopt[1] == OP_Q:
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_MMX', inst.operand[0], mops[0], 'T_XMM')
        elif mopt[1] == OP_M:
            if MODRM_MOD(u.input.peek()) == 3:
                u.error = 1
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_GPR', inst.operand[0], mops[0], 'T_XMM')
        elif mopt[1] == OP_E:
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_GPR', inst.operand[0], mops[0], 'T_XMM')
        elif mopt[1] == OP_PR:
            decode_modrm(u, inst, inst.operand[1], mops[1], 'T_MMX', inst.operand[0], mops[0], 'T_XMM')

    # DX, eAX/AL
    elif mopt[0] == OP_DX:
        inst.operand[0].type = 'OP_REG'
        inst.operand[0].base = 'dx'
        inst.operand[0].size = 16

        if mopt[1] == OP_eAX:
            inst.operand[1].type = 'OP_REG'    
            inst.operand[1].base = resolve_gpr32(u, inst, mopt[1])
        elif mopt[1] == OP_AL:
            inst.operand[1].type = 'OP_REG'
            inst.operand[1].base = 'al'
            inst.operand[1].size = 8

    # I, I/AL/eAX
    elif mopt[0] == OP_I:
        decode_imm(u, inst, mops[0], inst.operand[0])
        if mopt[1] == OP_I:
            decode_imm(u, inst, mops[1], inst.operand[1])
        elif mopt[1] == OP_AL:
            inst.operand[1].type = 'OP_REG'
            inst.operand[1].base = 'al'
            inst.operand[1].size = 16
        elif mopt[1] == OP_eAX:
            inst.operand[1].type = 'OP_REG'    
            inst.operand[1].base = resolve_gpr32(u, inst, mopt[1])

    # O, AL/eAX
    elif mopt[0] == OP_O:
        decode_o(u, inst, mops[0], inst.operand[0])
        inst.operand[1].type = 'OP_REG'
        inst.operand[1].size = resolve_operand_size(u, inst, mops[0])
        if mopt[1] == OP_AL:
            inst.operand[1].base = 'al' 
        elif mopt[1] == OP_eAX:
            inst.operand[1].base = resolve_gpr32(u, inst, mopt[1])
        elif mopt[1] == OP_rAX:
            inst.operand[1].base = resolve_gpr64(u, inst, mopt[1])      

    # 3
    elif mopt[0] == OP_I3:
        inst.operand[0].type = 'OP_IMM'
        inst.operand[0].lval = 3

    # ST(n), ST(n) 
    elif mopt[0] in [OP_ST0, OP_ST1, OP_ST2, OP_ST3,
                   OP_ST4, OP_ST5, OP_ST6, OP_ST7]:
        inst.operand[0].type = 'OP_REG'
        inst.operand[0].base = GPR['T_ST'][mopt[0] - OP_ST0]
        inst.operand[0].size = 0

        if mopt[1] in [OP_ST0, OP_ST1, OP_ST2, OP_ST3,
                     OP_ST4, OP_ST5, OP_ST6, OP_ST7]:
            inst.operand[1].type = 'OP_REG'
            inst.operand[1].base = GPR['T_ST'][mopt[1] - OP_ST0]
            inst.operand[1].size = 0

    # AX 
    elif mopt[0] == OP_AX:
        inst.operand[0].type = 'OP_REG'
        inst.operand[0].base = 'ax'
        inst.operand[0].size = 16

    # none 
    else:
        for op in inst.operand:
            op.type = None

    return 0


def do_mode(u, inst):
    # if in error state, bail out 
    if u.error:
        return -1 

    # propagate perfix effects 
    if u.dis_mode == 64:  # set 64bit-mode flags
        # Check validity of  instruction m64 
        if P_INV64(inst.itab_entry.prefix):
            u.error = 1
            return -1

        # effective rex prefix is the  effective mask for the 
        # instruction hard-coded in the opcode map.
        inst.pfx.rex = ((inst.pfx.rex & 0x40) 
                        |(inst.pfx.rex & REX_PFX_MASK(inst.itab_entry.prefix)))

        # calculate effective operand size 
        if REX_W(inst.pfx.rex) or P_DEF64(inst.itab_entry.prefix):
            inst.opr_mode = 64
        elif inst.pfx.opr:
            inst.opr_mode = 16
        else:
            inst.opr_mode = 32

        # calculate effective address size
        if inst.pfx.adr:
            inst.adr_mode = 32 
        else:
            inst.adr_mode = 64
    elif u.dis_mode == 32: # set 32bit-mode flags 
        if inst.pfx.opr:
            inst.opr_mode = 16 
        else:
            inst.opr_mode = 32
        if inst.pfx.adr:
            inst.adr_mode = 16 
        else: 
            inst.adr_mode = 32
    elif u.dis_mode == 16: # set 16bit-mode flags 
        if inst.pfx.opr:
            inst.opr_mode = 32 
        else: 
            inst.opr_mode = 16
        if inst.pfx.adr:
            inst.adr_mode = 32 
        else: 
            inst.adr_mode = 16
    # These flags determine which operand to apply the operand size
    # cast to.
    cast = [P_C0, P_C1, P_C2]
    for i in range(len(inst.operand)):
        inst.operand[i].cast = cast[i](inst.itab_entry.prefix)

    return 0

def decode(self):
    """Instruction decoder. Returns the number of bytes decoded."""
    inst = Inst(myInput = self.input, add = self.pc, mode = self.dis_mode, syntax = self.syntax)
    self.error = 0
    self.input.start ()
    if get_prefixes(self, inst) != 0:
        pass # ;print('prefixes error') # error 
    elif search_itab(self, inst) != 0:
        pass #; print('itab error') # error 
    elif do_mode(self, inst) != 0:
        pass #; print('mode error') # error 
    elif disasm_operands(self, inst) != 0:
        pass #; print('operand error') # error 
    elif resolve_operator(self, inst) != 0:
        pass #; print('operator error') # error 
    # Handle decode error.
    if self.error:
        inst.clear()
    inst.size = self.input.ctr + 1
    inst.raw = self.input.buffer[0:inst.size]
    inst.set_pc(inst.add + inst.size)
    return inst
