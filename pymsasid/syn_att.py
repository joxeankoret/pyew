# -----------------------------------------------------------------------------
# syn-att.c
#
# author: matthieu.kaczmarek@mines-nancy.org
# Mainly rewrited from udis86 -- Vivek Mohan <vivek@sig9.com>
# -----------------------------------------------------------------------------

from operand import *

# -----------------------------------------------------------------------------
# opr_cast() - Prints an operand cast.
# -----------------------------------------------------------------------------

def opr_cast(u, op) :
    if op.size in [16, 32] :
        mkasm(u, "*")

# -----------------------------------------------------------------------------
# gen_operand() - Generates assembly output for each operand.
# -----------------------------------------------------------------------------

def gen_operand(u, op) :
    if op.type == "OP_REG" :
        mkasm(u, "%%" + op.base)

    elif op.type == "OP_MEM" :
        if u.inst.br_far :
            opr_cast(u, op)
            if u.inst.pfx.seg :
                mkasm(u, "%%:" + u.inst.pfx.seg)
            if op.offset == 8 :
                if op.lval < 0 :
                    mkasm(u, "-" + hex(-op.lval))
                else :
                    mkasm(u, heax(op.lval))
            elif op.offset == 16 : 
                mkasm(u, hex(op.lval))
            elif op.offset == 32 :
                mkasm(u, hex(op.lval))
            elif op.offset == 64 : 
                mkasm(u, hex(op.lval))
                if op.base :
                    mkasm(u, "(%%" + op.base)
                if op.index :
                    if op.base :
                        mkasm(u, ",")
                    else :
                        mkasm(u, "(")
                    mkasm(u, "%%" + op.index)
                if op.scale :
                    mkasm(u, "," + str(op.scale))
                if op.base or op.index :
                    mkasm(u, ")")

        elif op.type == "OP_IMM" :
            mkasm(u, "$" + hex(op.lval))

        elif op.type == "OP_JIMM":
            val = u.pc + op.lval
            if val < 0 :
                val += pow (2, u.inst.adr_mode) 
            mkasm(u, hex(val))

        if op.type == "OP_PTR":
            mkasm(u, "$" + hex (op.lval.seg) + ", $" + hex(op.lval.off))

# =============================================================================
# translates to AT&T syntax 
# =============================================================================
def translate_att(u) :
    size = 0
  # check if P_OSO prefix is used 
    if not P_OSO(u.inst.itab_entry.prefix) and u.inst.pfx.opr :
        if u.dis_mode == 16 : 
            mkasm(u, "o32 ")
        elif u.dis_mode in [32, 64] :
            mkasm(u, "o16 ")

  # check if P_ASO prefix was used 
    if not P_ASO(u.inst.itab_entry.prefix) and u.inst.pfx.adr :
        if u.dis_mode == 16: 
            mkasm(u, "a32 ")
        elif u.dis_mode == 32:
            mkasm(u, "a16 ")
        elif u.dis_mode == 64:
            mkasm(u, "a32 ")

    if u.inst.pfx.lock :
        mkasm(u,  "lock ")
    if u.inst.pfx.rep :
        mkasm(u,  "rep ")
    if u.inst.pfx.repne :
        mkasm(u,  "repne ")

    # special instructions 
    if u.inst.operator == "retf" : 
        mkasm(u, "lret ") 
    elif u.inst.operator == "db":
        mkasm(u, ".byte " + hex(u.inst.operand[0].lval.ubyte))
        return
    elif u.inst.operator in ["jmp", "call"]:
        if u.inst.br_far : 
            mkasm(u,  "l") 
        mkasm(u, lookup_operator(u.inst.operator))
    elif u.inst.operator in ["bound", "enter"] :
        if u.inst.operand[0].type != None :
            gen_operand(u, u.inst.operand[0])
        if u.inst.operand[1].type != None :
            mkasm(u, ",")
            gen_operand(u, u.inst.operand[1])
        return
    else:
        mkasm(u, lookup_operator(u.inst.operator))  

    if P_C1(u.inst.itab_entry.prefix):
        size = u.inst.operand[0].size
    elif P_C2(u.inst.itab_entry.prefix) :
        size = u.inst.operand[1].size
    elif P_C3(u.inst.itab_entry.prefix) :
        size = u.inst.operand[2].size

    if size == 8 :
        mkasm(u, "b")
    elif size == 16 :
        mkasm(u, "w")
    elif size == 64 :
        mkasm(u, "q")

    mkasm(u, " ")
    
    if u.inst.operand[2].type != None :
        gen_operand(u, u.inst.operand[2])
        mkasm(u, ", ")  

    if u.inst.operand[1].type != None :
        gen_operand(u, u.inst.operand[1])
        mkasm(u, ", ")
  
    if u.inst.operand[0].type != None :
        gen_operand(u, u.inst.operand[0])

