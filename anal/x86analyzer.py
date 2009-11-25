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

    def addFunction(self, offset, name=None):
        if self.functions.has_key(offset):
            return False
        
        self.queue.append(offset)
        if not name:
            name = "sub_%08x" % offset
        
        print "Adding function %s" % name
        self.functions[offset] = name
        
        return True

    def doCodeAnalysis(self):
        #self.functions[self.pyew.ep] = "start"
        self.addFunction(self.pyew.ep, "start")
        self.doAnalyzeFunction(self.pyew.ep)
        
        while 1:
            if len(self.queue) == 0:
                break
            
            pos = self.queue.pop()
            if type(pos) is str:
                try:
                    pos = int(pos, 16)
                except ValueError, TypeError:
                    continue
            
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
        
        if self.functions.has_key(offset) and len(self.functions) > 1:
            return
        
        self.checking.append(offset)
        lines = self.pyew.disasm(offset, self.pyew.processor, self.pyew.type, self.pyew.lines, 16000)
        i = 0
        prev = ""
        info = ""
        
        for l in lines:
            i += 1
            
            if i > 1000:
                break
            else:
                self.checking.append(l.offset)
            
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
                    self.addXref(l.offset, ops)
                    self.addFunction(ops)
                except ValueError, TypeError:
                    pass
            elif mnem == "JMP" and i == 1:
                ops = self.pyew.resolveName(l.operands)
                self.addXref(l.offset, ops)
                
                if self.pyew.names.has_key(ops) or True:
                    try:
                        self.addFunction(ops, "j_" % ops)
                    except:
                        continue
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
                    try:
                        info = int(str(info), 16)
                    except ValueError, TypeError:
                        continue
                    
                    self.addXref(l.offset, info)
                    self.doAnalyzeFunction(info)
                    self.addFunction(info, "ret_%08x" % info)
                    return
            elif mnem.startswith("RET"):
                return
            else:
                prev = mnem
                info = str(l.operands)
        
        name = self.pyew.resolveName(offset)
        self.functions_address[name] = [offset, l.offset + offset]
        self.checking.remove(offset)
        self.analyzed.append(offset)
