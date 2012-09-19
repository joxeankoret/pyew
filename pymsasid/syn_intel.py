 # -----------------------------------------------------------------------------
 # syn-intel.pyx
 #
 # author: matthieu.kaczmarek@mines-nancy.org
 # Mainly rewrited from udis86 -- Vivek Mohan <vivek@sig9.com>
 # -----------------------------------------------------------------------------

from operand import P_OSO, P_ASO, P_IMPADDR
from common import DecodeException

def intel_operand_cast(op):
    """Returns operand casts."""
    ret = {
        8: 'byte ',
        16: 'word ',
        32: 'dword ',
        64: 'qword ',
        84: 'tword '
    }
    try:
        return ret[op.size]
    except KeyError:
        raise DecodeException('unknown operand size: ' + str(op.size))

def intel_operand_syntax(op):
    """Generates assembly output for operands."""
    #return op.value
    if op.type == None:
        return ''

    ret = ''

    if op.type == 'OP_REG':
        ret += op.base
        return ret

    if op.cast:
        ret += intel_operand_cast(op)
        
    if op.type == 'OP_MEM':
        op_f = 0
        ret += '['

        if op.seg:
            ret += op.seg + ':'

        if op.base and op.base != None:
            ret += op.base
            op_f = 1

        if op.index and op.index != None:
            if op_f:
                ret += '+'
            ret += op.index
            op_f = 1

        if op.scale:
            ret += str(op.scale)

        if op.offset in [8, 16, 32, 64]:
            if(op.lval < 0):
                ret += '-' + hex(-op.lval)
            else:
                if op_f:
                    # MK ???
                    if op.lval == 0.0:
                        op.lval = 0                    
                    ret += '+' + hex(op.lval)
                else:
                    ret += hex(op.lval)
        ret += ']'

    elif op.type == 'OP_IMM':
        ret += hex(op.lval)

    elif op.type == 'OP_JIMM':
        val = op.pc + op.lval
        ret += hex(val)

    elif op.type == 'OP_PTR':
        ret += 'word ' + hex(op.lval.seg) + ':' + hex(op.lval.off)
    return ret

def intel_syntax(self):
    """translates to intel syntax"""
    ret = ''
    # -- prefixes -- 

    # check if P_OSO prefix is used 
    if not P_OSO(self.itab_entry.prefix) and self.pfx.opr:
        if self.dis_mode == 16: 
            ret += 'o32 '
        elif self.dis_mode in [32, 64]:
            ret += 'o16 '

    # check if P_ASO prefix was used 
    if not P_ASO(self.itab_entry.prefix) and self.pfx.adr:
        if self.dis_mode == 16: 
            ret += 'a32 '
        elif self.dis_mode == 32:
            ret += 'a16 '
        elif self.dis_mode == 64:
            ret += 'a32 '

    if self.pfx.lock:
        ret += 'lock '
    if self.pfx.rep:
        ret += 'rep '
    if self.pfx.repne:
        ret += 'repne '
    if P_IMPADDR(self.itab_entry.prefix) and self.pfx.seg:
        ret += self.pfx.seg

    # print the instruction operator 
    ret += self.operator + ' '
    if self.branch_dist:
        ret += self.branch_dist + ' '
    for op in self.operand:
        ret += intel_operand_syntax(op) + ' '

    return ret
