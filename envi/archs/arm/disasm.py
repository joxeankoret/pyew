#import sys
#import struct
#import traceback

import envi
#import envi.bits as e_bits
#from envi.bits import binary

from envi.archs.arm.const import *
from envi.archs.arm.armdisasm import ArmStdDisasm
from envi.archs.arm.thumbdisasm import ArmThumbDisasm
from envi.archs.arm.regs import *

# Universal opcode things:
# len
# mode

#FIXME: TODO
# FIXME ldm sp, { pc } seems to not get marked NOFALL
# FIXME ldm sp, { pc } should probably be marked IF_RET too...
# FIXME b lr / bx lr should be marked IF_RET as well!
# FIXME encoding for swi instruction ( <4 cond> 1111 <24 bytes immediate> ) is totally horked (it's in p_uncond)
# FIXME some arm opcode values are ENC << and some are ENC and some are etc..
#       (make all be ENC_FOO << 16 + <their index>

# FIXME the following things dont decode correctly
# 5346544e    cmppl   r6, #1308622848

#
# Possible future extensions: 
#   * VectorPointFloat subsystem (coproc 10+11)
#   * Debug subsystem (coproc 14)
#   * other 'default' coprocs we can handle and add value?


####################################################################
# Parsers for the multiply family of instruction encodings



class ArmDisasm:

    def __init__(self):
        self.jzl_enabled = False
        self._dis_regctx = ArmRegisterContext()
        self._disasm = None
        self._disasms = (
            ArmStdDisasm(),
            ArmThumbDisasm(),
            ArmJazDisasm(),
        )
        self.loclookup = {}
        
        self.setMode(MODE_ARM)
        
    def setMode(self, mode_num):
        self._disasm = self._disasms[mode_num]
    
    def disasm(self, bytes, offset, va, trackMode=True, mode=None):

        # hack to make sure parsing odd addresses kicks to thumb
        if va & 1 == 1:
            self.setMode( MODE_THUMB )
        else:
            self.setMode( MODE_ARM )

        op = self._disasm.disasm(bytes, offset, va, trackMode)
        return op
        
class ArmJazDisasm:
    def disasm(self, bytes, offset, va, trackMode=True):
        raise Exception('Jaz Not Supported Yet!')
    
