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
    tocheck = []

    def __init__(self, pyew, type="PE"):
        self.pyew = pyew
        self.pe = type

    def addXref(self, afrom , ato):
        if self.xrefs.has_key(ato):
            self.xrefs[ato].append(afrom)
        else:
            self.xrefs[ato] = [afrom]

    def addFunction(self, offset, name=None, tocheck=None):
        if self.functions.has_key(offset):
            if self.functions[offset] != name and name is not None:
                self.functions[offset] = name
                return True
            return False
        
        if offset >= self.pyew.maxsize:
            return False
        
        if tocheck:
            self.tocheck.append(offset)
        
        self.queue.append(offset)
        if not name:
            name = "sub_%08x" % offset
        
        if self.pyew.debug:
            print "Adding function %s" % name
        self.functions[offset] = name
        
        return True

    def doCodeAnalysis(self):
        self.addFunction(self.pyew.ep, "start")
        self.doAnalyzeFunction(self.pyew.ep)
        
        while 1:
            if len(self.queue) == 0:
                if self.pyew.debug:
                    print "NO more elements in queue"
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
            if offset in self.tocheck:
                self.tocheck.remove(offset)
            if offset in self.queue:
                self.queue.remove(offset)
                
            if self.pyew.debug:
                print "Too big 0x%08x" % offset
            return
        
        if offset in self.checking:
            return
        
        if (self.functions.has_key(offset) and len(self.functions) > 1) and \
           offset not in self.tocheck:
            return
        elif offset in self.tocheck:
            self.tocheck.remove(offset)
        
        self.checking.append(offset)
        self.analyzed.append(offset)
        lines = self.pyew.disasm(offset, self.pyew.processor, self.pyew.type, self.pyew.lines, 16000)
        i = 0
        prev = ""
        info = ""
        
        for l in lines:
            i += 1
            if i >= 100:
                break
            self.checking.append(l.offset)
            
            mnem = str(l.mnemonic)
            
            if mnem == "CALL":
                """
                We found a new function, mark it to be analyzed.
                """
                ops = self.pyew.resolveName(l.operands)
                
                try:
                    ops = int(ops, 16)
                    
                    if ops != l.offset + l.size:
                        self.addXref(l.offset, ops)
                        if not self.addFunction(ops, tocheck=True):
                            pass
                except ValueError, TypeError:
                    pass
            elif mnem == "JMP" and i == 1:
                ops = self.pyew.resolveName(l.operands)
                self.addXref(l.offset, ops)
                
                if self.pyew.names.has_key(ops) or True:
                    try:
                        tmp = "j_" + str(ops)
                        if not self.addFunction(l.offset, tmp, tocheck=True):
                            pass # Already added
                    except:
                        pass
                else:
                    self.queue.add(ops)
                
                self.analyzed.append(offset)
                break
            elif mnem.startswith("J"):
                try:
                    new_offset = int(self.pyew.resolveName(l.operands), 16)
                except ValueError, TypeError:
                    continue
                
                self.addXref(l.offset, new_offset)
                self.doAnalyzeFunction(new_offset)
                self.analyzed.append(new_offset)
                if new_offset in self.queue:
                    self.queue.remove(new_offset)
                if new_offset in self.tocheck:
                    self.tocheck.remove(new_offset)
            elif mnem.startswith("RET"):
                """if prev == "PUSH":
                    try:
                        info = int(str(info), 16)
                    except ValueError, TypeError:
                        continue
                    self.addXref(l.offset, info)
                    self.doAnalyzeFunction(info)
                    #print l.offset, l
                    self.addFunction(info, "ret_%08x" % info, tocheck=True)"""
                break
            else:
                prev = mnem
                info = str(l.operands)
        
        name = self.pyew.resolveName(offset)
        self.functions_address[name] = [offset, l.offset + offset]
        self.checking.remove(offset)
        self.analyzed.append(offset)
