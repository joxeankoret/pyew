#-----------------------------------------------------------------------------
# pymasid
#
# author: matthieu.kaczmarek@mines-nancy.org
# Mainly rewrited from udis86 -- Vivek Mohan <vivek@sig9.com>
# -----------------------------------------------------------------------------

# this is intended, we need every public class in input to be in pymsasid's namespace
from input import *

from inst import Inst
from common import DecodeException, VENDOR_INTEL, VENDOR_AMD
import decode as dec
import syn_intel as intel

class Pymsasid:
    def __init__(self, 
                 mode = None, 
                 source = '', 
                 syntax = intel.intel_syntax,
                 vendor = VENDOR_INTEL,
                 hook = BufferHook):
        self.error = 0
        self.vendor = self.set_vendor(vendor)
        self.input = Input(hook, source) 
        self.entry_point = self.pc = long(self.input.hook.entry_point)
        if mode == None:
            self.dis_mode = self.input.hook.dis_mode
        else:
            self.dis_mode = mode
        self.syntax = syntax

    def disassemble(self, add):
        try:
            self.seek(add)
            return self.decode()
        except DecodeException:
            return Inst(self.input)
            
    def set_vendor(self, vendor):
        if vendor in [VENDOR_INTEL, VENDOR_AMD]:
            self.vendor = vendor
        else:
            raise Exception('call to Pymsasid.set_vendor() with unknown vendor:' + str(vendor))
            
    def seek(self, add):
        self.input.hook.seek(add)
        self.pc = add

    def decode(self):
        return dec.decode(self)
