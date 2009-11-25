#!/usr/bin/env python

import sys

class CX86CodeAnalyzer:
    
    pyew = None
    type = "PE"
    functions = {}
    functions_address = {}
    xrefs = {}
    queue = []
    analyzed = []
    checking = []
    
    def __init__(self, pyew, type="PE"):
        self.pyew = pyew
        self.pe = type

    def addXref(self, afrom , ato):
        if self.xrefs.has_key(afrom):
            self.xrefs[afrom].append(ato)
        else:
            self.xrefs[afrom] = [ato]

    def doCodeAnalysis(self):
        self.functions[self.pyew.ep] = "start"
        self.doAnalyzeFunction(self.pyew.ep)
        
        while 1:
            if len(self.queue) == 0:
                break
            
            pos = self.queue.pop()
            self.doAnalyzeFunction(pos)
        
        self.pyew.names.update(self.functions)
        self.pyew.functions = self.functions
        self.pyew.functions_address = self.functions_address
        self.pyew.xrefs = self.xrefs
        self.pyew.seek(0)

    def doAnalyzeFunction(self, offset):
        
        if offset in self.analyzed:
            return
        
        if self.pyew.maxsize <= offset:
            return
        
        if offset in self.checking:
            return
        
        self.checking.append(offset)
        
        lines = self.pyew.disasm(offset, self.pyew.processor, self.pyew.type, self.pyew.lines, self.pyew.maxsize)
        i = 0
        prev = ""
        info = ""
        
        for l in lines:
            i += 1
            mnem = str(l.mnemonic)
            
            if mnem == "CALL":
                """
                We found a new function, mark it to be analyzed.
                """
                ops = self.pyew.resolveName(l.operands)
                #print ops
                
                try:
                    #print "OPS",repr(ops)
                    ops = int(ops, 16)
                    #print "Adding to queue 0x%x" % ops
                    self.queue.append(ops)
                    self.addXref(l.offset, ops)
                    self.functions[ops] = "sub_%08x" % ops
                except ValueError, TypeError:
                    pass
            elif mnem == "JMP" and i == 1:
                """ In example, it can be the following:
                    
                        JMP msvcrt.dll!__getmainargs
                    
                    So, we create a new name with name:
                    
                        j_msvcrt.dll!__getmainargs
                """
                ops = self.pyew.resolveName(l.operands)
                self.addXref(l.offset, ops)
                
                if self.pyew.names.has_key(ops) or True:
                    self.functions[offset] = "j_" + ops
                else:
                    self.doAnalyzeFunction(ops)
                self.analyzed.append(offset)
            elif mnem.startswith("J"):
                try:
                    new_offset = int(self.pyew.resolveName(l.operands), 16)
                except ValueError, TypeError:
                    continue
                
                #print "Jump to 0x%08x" % new_offset
                self.addXref(l.offset, new_offset)
                self.doAnalyzeFunction(new_offset)
                self.analyzed.append(new_offset)
            elif mnem.startswith("RET"):
                if prev == "PUSH":
                    self.addXref(l.offset, info)
                    self.doAnalyzeFunction(info)
            elif mnem.startswith("RET"):
                return
            else:
                prev = mnem
                info = str(l.operands)
        
        name = self.pyew.resolveName(offset)
        self.functions_address[name] = [offset, l.offset + offset]
        self.checking.remove(offset)
        self.analyzed.append(offset)
