#!/usr/bin/env python

"""
This file is part of Pyew

Copyright (C) 2009, Joxean Koret

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

import sys
import time

class CX86BasicBlock:
    def __init__(self):
        self.instructions = {}

class CX86CodeAnalyzer:
    def __init__(self, pyew, type="PE"):
        self.type = "PE"
        self.names = {}
        self.functions = {}
        self.functions_address = {}
        self.xrefs_to = {}
        self.xrefs_from = {}
        self.queue = []
        self.analyzed = []
        self.checking = []
        self.tocheck = []
        self.antidebug = []
        self.function_stats = {}
        self.basic_blocks = {}
        
        # Helper
        self._current_function = None
        
        self.last_msg_size = 0

        self.pyew = pyew
        self.pe = type
        self.timeout = 300
        self.start_time = 0
        self.max_level = 500

    def doCodeAnalysis(self, ep=True, addr=None):
        try:
            self.start_time = time.time()
            if ep:
                self.mDoCodeAnalysis()
            else:
                self.mDoCodeAnalysis(ep=False, addr=addr)
        except KeyboardInterrupt:
            pass
        
        # Calcule statistics
        self.calculeStats()
        
        self.pyew.antidebug = self.antidebug
        self.pyew.names.update(self.functions)
        self.pyew.names.update(self.names)
        self.pyew.functions = self.functions
        self.pyew.functions_address = self.functions_address
        self.pyew.xrefs_to = self.xrefs_to
        self.pyew.xrefs_from = self.xrefs_from
        self.pyew.basic_blocks = self.basic_blocks
        self.pyew.function_stats = self.function_stats
        self.pyew.seek(0)
        
        if not self.pyew.batch:
            sys.stdout.write("\b"*100 + " "*100)

    def belongsTo(self, offset, func):
        if not self.basic_blocks.has_key(func):
            return False
        
        for x in self.basic_blocks[func]:
            for n in x.instructions:
                if n == offset:
                    return True
        
        return False

    def calculeStats(self):
        ccs = []
        bbs = 0
        
        # Iterate over all functions
        for func in self.functions:
            indegree = 0
            outdegree = 0
            edges = 0
            nodes = 0
            
            if not self.basic_blocks.has_key(func):
                continue
            
            to_checked = []
            from_checked = []
            
            for bb in self.basic_blocks[func]:
                nodes += 1
                bbs += 1
                i = 0
                for ins in bb.instructions:
                    x = bb.instructions[ins]
                    if self.xrefs_to.has_key(x.offset):
                        if i == 0:
                            indegree += 1
                        
                        if not x.offset in to_checked:
                            to_checked.append(x.offset)
                    if self.xrefs_from.has_key(x.offset) and \
                       not x.offset in from_checked:
                        if self.belongsTo(x.offset, func) and \
                           x.offset != bb.instructions.keys()[0]:
                            edges += 1
                        from_checked.append(x.offset)
                    i += 1
                
                if self.xrefs_from.has_key(x.offset):
                    outdegree += 1
            
            p = indegree + outdegree
            cc = edges - nodes + p
            ccs.append(cc)
            
            self.function_stats[func] = (nodes, edges, cc)
            
            if self.pyew.debug:
                print
                print "Function 0x%08x -> Nodes %d Edges %d Ciclomatic Complexity %d " % \
                      (func, nodes, edges, cc)
        
        if self.pyew.debug:
            print 
            print "Ciclomatic Complexity -> Max %d Min %d Media %2.2f" % (max(ccs), min(ccs), sum(ccs)/len(ccs)*1.00)
            print "Total functions %d Total basic blocks %d" % (len(self.functions), bbs)

    def mDoCodeAnalysis(self, ep = True, addr = None):
        if ep:
            self._current_function = self.pyew.ep
            self.addFunction(self.pyew.ep, "start")
            self.doAnalyzeFunction(self.pyew.ep)
        else:
            self._current_function = addr
            self.addFunction(addr, "sub_%08x" % addr)
            self.doAnalyzeFunction(addr)
        
        for func in self.pyew.exports:
            self._current_function = func
            if self.pyew.debug:
                print " Current function 0x%08x" % self._current_function
            self.addFunction(func, self.pyew.exports[func])
            self.doAnalyzeFunction(func)
        
        while 1:
            if len(self.queue) == 0:
                if self.pyew.debug:
                    print
                    print "NO more elements in queue"
                break
            
            pos = self.queue.pop()
            if type(pos) is str:
                try:
                    pos = int(pos, 16)
                except ValueError, TypeError:
                    continue
            
            self._current_function = pos
            if self.pyew.debug:
                print " Current function 0x%08x" % self._current_function
            self.doAnalyzeFunction(pos)

    def addXref(self, afrom , ato):
        if self.xrefs_to.has_key(ato):
            self.xrefs_to[ato].append(afrom)
        else:
            self.xrefs_to[ato] = [afrom]
        
        if self.xrefs_from.has_key(afrom):
            self.xrefs_from[afrom].append(ato)
        else:
            self.xrefs_from[afrom] = [ato]

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
            print " Adding function %s" % name
        self.functions[offset] = name
        
        return True

    def doAnalyzeFunction(self, offset, level=0):
        
        if self.start_time != 0 and time.time() > self.start_time + self.timeout:
            return
        
        if level >= self.max_level:
            return
        
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
        
        if self.last_msg_size > 0:
            pass
        else:
            if not self.pyew.batch:
                msg = "Analyzing address 0x%08x" % offset
                print "\b"*self.last_msg_size + " "*self.last_msg_size + "\b"*self.last_msg_size
                self.last_msg_size = len(msg)
                sys.stdout.write(msg)
                sys.stdout.flush()
        
        self.checking.append(offset)
        # Fix for a bug in PyDistorm
        lines = self.pyew.disasm(offset, self.pyew.processor, self.pyew.type, 100, 1600)
        last = lines[len(lines)-1]
        lines.extend(self.pyew.disasm(last.offset+last.size, self.pyew.processor, self.pyew.type, 100, 1600))
        i = 0
        prev = ""
        info = ""
        null_instructions = 0
        bblock = CX86BasicBlock()
        bblock.instructions = {}
        
        for l in lines:
            i += 1
            
            if l.offset in self.analyzed:
                break
            else:
                self.analyzed.append(offset)
            
            if not self.pyew.batch:
                sys.stdout.write("\b"*10 + "0x%08x" % l.offset)
            
            # Fill the current basic block
            if l.offset not in bblock.instructions:
                bblock.instructions[l.offset] = l
                
            self.checking.append(l.offset)
            
            mnem = str(l.mnemonic)
            
            if mnem == "CALL":
                """
                We found a new function, mark it to be analyzed.
                """
                prev = mnem
                info = str(l.operands)
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
                
                if ops in self.pyew.names.values():
                    try:
                        tmp = "j_" + str(ops)
                        self.names[l.offset] = tmp
                        #if not self.addFunction(l.offset, tmp, tocheck=True):
                        #    pass # Already added
                    except:
                        pass
                else:
                    self.queue.append(ops)
                
                self.analyzed.append(offset)
                # XXX: FIXME
                prev = mnem
                info = str(l.operands)
                break
            elif mnem.startswith("J"):
                try:
                    new_offset = int(self.pyew.resolveName(l.operands), 16)
                except ValueError, TypeError:
                    # XXX: FIXME
                    prev = mnem
                    info = str(l.operands)
                    continue
                
                self.addXref(l.offset, new_offset)
                self.doAnalyzeFunction(new_offset, level+1)
                self.analyzed.append(new_offset)
                if new_offset in self.queue:
                    self.queue.remove(new_offset)
                if new_offset in self.tocheck:
                    self.tocheck.remove(new_offset)
            elif mnem.startswith("RET"):
                if prev == "PUSH":
                    try:
                        info = int(str(info), 16)
                    except ValueError, TypeError:
                        # XXX: FIXME
                        prev = mnem
                        info = str(l.operands)
                        continue
                    
                    if info >= self.pyew.maxsize or info <= 0:
                        # XXX: FIXME
                        prev = mnem
                        info = str(l.operands)
                        continue
                    
                    self.addXref(l.offset, info)
                    self.doAnalyzeFunction(info, level+1)
                    self.addFunction(info, "ret_%08x" % info, tocheck=True)
                break
            elif mnem.startswith("JMP"):
                self.doAnalyzeFunction(info, level+1)
                break
            elif mnem.startswith("INT") or mnem.startswith("UD") or \
                 mnem.startswith("RDTSC") or mnem.find("IDT") > -1:
                self.antidebug.append((l.offset, str(l.mnemonic)))
            else:
                prev = mnem
                info = str(l.operands)
                
                """ Makes no sense in real apps a code like:
                
                    MOV [EAX], AL
                    MOV [EAX], AL
                    
                    So exit from this function"""
                if str(l.instructionHex) == "0000":
                    null_instructions += 1
                    
                    if null_instructions >= 2:
                        break
                else:
                    null_instructions = 0
        
        # Add the basic block
        if not self.basic_blocks.has_key(self._current_function):
            self.basic_blocks[self._current_function] = []
        
        self.basic_blocks[self._current_function].append(bblock)
        name = self.pyew.resolveName(offset)
        # Isn't a f*cking basic block?
        self.functions_address[name] = [offset, l.offset + offset]
        self.checking.remove(offset)
        self.analyzed.append(offset)
        
        if mnem.startswith("RET") and False:
            self.addFunction(offset+l.size, tocheck=True)
