from operand import O_NONE, P_none
import syn_intel as intel
#hack MK
from syn_intel import intel_operand_syntax
#from syn_att import *

operator_list_invalid = [ 'invalid']

operator_list_call = ['syscall', 
                      'call', 
                      'vmcall', 
                      'vmmcall']

operator_list_ret = ['sysret',
                     'iretw',
                     'iretd',
                     'iretq',
                     'ret',
                     'retf']

operator_list_jmp = ['jmp']

operator_list_jcc = ['jo',
                     'jno',
                     'jb',
                     'jae',
                     'jz',
                     'jnz',
                     'jbe',
                     'ja',
                     'js',
                     'jns',
                     'jp',
                     'jnp',
                     'jl',
                     'jge',
                     'jle',
                     'jg',
                     'jcxz',
                     'jecxz',
                     'jrcxz',
                     'loopnz',
                     'loope',
                     'loop']

operator_list_hlt = ['hlt']

class itab_entry:
    def __init__(self, 
                 operator = None, 
                 op1 = O_NONE, op2 = O_NONE, op3 = O_NONE, 
                 pfx = 0):
        self.operator = operator
        self.operand = [op1, op2, op3]
        self.prefix = pfx

ie_invalid = itab_entry('invalid', O_NONE, O_NONE, O_NONE, P_none)
ie_pause = itab_entry('pause', O_NONE, O_NONE,    O_NONE, P_none)
ie_nop = itab_entry('nop', O_NONE, O_NONE, O_NONE, P_none)

class Prefix:
    def __init__(self):
        self.rex = 0
        self.seg = ''
        self.opr = 0
        self.adr = 0
        self.lock = 0
        self.rep = 0
        self.repe = 0
        self.repne = 0
        self.insn = 0
        
    def clear(self):
        self.seg     = ''
        self.opr     = 0
        self.adr     = 0
        self.lock    = 0
        self.repne = 0
        self.rep     = 0
        self.repe    = 0
        self.rex     = 0
        self.insn    = 0

class Ptr:
    def __init__(self, off = 0, seg = 0):
        self.off = off
        self.seg = seg

class Operand:
    def __init__(self):
        self.seg = None
        self.type = None
        self.size = 0
        self.lval = 0
        self.base = None
        self.index = None
        self.offset = 0
        self.scale = 0
        self.cast = 0
        self.pc = 0
        self.value = None
        self.ref = None

    def clear(self):
        self.__init__()
         
    def __str__(self):
        return intel_operand_syntax (self)
    
    def __repr__(self):
        return self.__str__()

class Inst:
    def __init__(self, myInput, add = 0, mode = 16, syntax = intel.intel_syntax):
        self.input = myInput
        self.dis_mode = mode
        self.size = 0
        self.add = add
        self.pc = 0
        self.syntax = syntax
        self.my_syntax = None
        self.itab_entry = ie_invalid
        self.operator = 'invalid'
        self.operand = [] 
        self.pfx = Prefix()
        self.opr_mode = 0 
        self.adr_mode = 0 
        self.branch_dist = None 
        
    def clear(self):
        self.pfx.clear()
        self.itab_entry = ie_invalid
        self.operator = self.itab_entry.operator
        for op in self.operand:
            op.clear()
 
    def __str__(self):
        if(self.my_syntax == None):
            self.my_syntax = self.syntax(self) # wtf ?
        return self.my_syntax

    def __repr__(self):
        return str(self)

    def set_pc(self, pc):
        self.pc = pc
        for op in self.operand:
            op.pc = pc
            
    def branch(self):
        if(self.operator in operator_list_invalid 
               or self.operator in operator_list_ret 
               or self.operator in operator_list_hlt):
            return []
        elif self.operator in operator_list_jmp:
            return [self.target_add()]
        elif self.operator in operator_list_call or self.operator in operator_list_jcc:
            return [self.next_add(), self.target_add()]
        return [self.next_add()]

    def next_add(self):
        return long(self.pc)
        
    def target_add(self):
        if(self.operand[0].type == 'OP_JIMM' 
                or self.operand[0].type == 'OP_IMM'):
            ret = self.add + self.size + self.operand[0].lval
        elif self.operand[0].type == 'OP_PTR':
            ret = ((self.operand[0].lval.seg << 4) 
                   + self.operand[0].lval.off)
        elif self.operand[0].type == 'OP_MEM':
            self.input.seek(self.operand[0].lval)
            ret = long (self.input.hook.base_address + self.input.read(self.operand[0].size))
        else:
            ret = str(self.operand[0])
        if(type(ret) == str):
            return ret
        return long(ret)

    def flow_label(self):
        if self.operator in operator_list_invalid:
            return 'invd'
        elif self.operator in operator_list_call:
            return 'call'
        elif self.operator in operator_list_jmp:
            return 'jmp'
        elif self.operator in operator_list_jcc:
            return 'jcc'
        elif self.operator in operator_list_ret:
            return 'ret'
        elif self.operator in operator_list_hlt:
            return 'hlt'
        else:
            return 'seq'

