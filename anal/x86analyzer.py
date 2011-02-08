#!/usr/bin/env python

"""
This file is part of Pyew

Copyright (C) 2009, 2010 Joxean Koret

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

class CX86CallGraph(object):
    def __init__(self):
        self.functions = []
        self.connections = []

class CX86Function(object):
    def __init__(self, addr):
        self.address = addr
        self.basic_blocks = []
        self.edges = []
        self.connections = []
        self.stats = []

    def addOutConnection(self, conn):
        if conn not in self.connections:
            self.connections.append(conn)

class CX86BasicBlock(object):
    def __init__(self):
        self.instructions = []
        self.inrefs = []
        self.connections = []
        self.offset = 0
    
    def addConnection(self, afrom, ato):
        if (afrom, ato) not in self.connections:
            self.connections.append((afrom, ato))

class CX86CodeAnalyzer:
    def __init__(self, pyew, type="PE"):
        self.pyew = pyew
        self.type = type
        self.names = {}
        self.queue = ()
        self._imports = self.pyew.imports.values()
        self.analyzed = []
        self.functions = {}
        self.function_stats = {}
        self.basic_blocks = {}
        self.xrefs_to = {}
        self.xrefs_from = {}
        self.antidebug = []
        self.timeout = None
        
        self.timeout = 300
        self.last_msg_size = 0
        self.start_time = 0

    def belongsTo(self, offset, func):
        if not self.functions.has_key(func):
            return False
        
        for x in self.functions[func].basic_blocks:
            for n in x.instructions:
                if n == offset:
                    return True
        
        return False

    def resolveAddress(self, addr):
        addr = str(addr)
        if addr.find("[") > -1:
            addr = addr.strip("[").strip("]")
            if addr.find("+") > -1 or addr.find("-") > -1:
                return addr, False, True
            
            name = self.pyew.resolveName(addr)
            if name in self._imports:
                return addr, True, False
        else:
            try:
                addr = int(addr, 16)
            except:
                # It's a CALL REG or something like this...
                return None, False, True
        
        return addr, False, False

    def addXref(self, afrom , ato):
        if self.xrefs_to.has_key(ato):
            self.xrefs_to[ato].append(afrom)
        else:
            self.xrefs_to[ato] = [afrom]
        
        if self.xrefs_from.has_key(afrom):
            self.xrefs_from[afrom].append(ato)
        else:
            self.xrefs_from[afrom] = [ato]

    def createFunction(self, addr):
        if self.timeout != 0 and time.time() > self.start_time + self.timeout:
            raise Exception("Code analysis for x86 timed-out")
        
        if addr in self.analyzed or addr in self.functions:
            #print "Function %08x already analyzed" % addr
            return
        
        self.names[addr] = "sub_%08x" % addr
        f = CX86Function(addr)
        lines = self.pyew.disasm(addr, self.pyew.processor, self.pyew.type, 100, 1500)
        bb = CX86BasicBlock()
        bb.offset = addr
        flow = []
        
        # Possible values for break_bb are:
        #
        #   0 = Do nothing
        #   1 = Break the basic block
        #   2 = Break the basic block and clear 'lines'
        #
        break_bb = 0
        analyzed_total = 0
        
        i = 0
        
        #
        # Iterate while there is at least one more line of code
        # or there is some address to follow (in list flow)
        #
        while len(lines) > 0 or len(flow) > 0:
            if len(lines) > 0:
                l = lines[0]
                lines = lines[1:]
                if l.offset in self.analyzed:
                    # Already analyzed
                    """analyzed_total += 1
                    if analyzed_total > 16:
                        lines = []"""
                    
                    if l.offset in self.basic_blocks:
                        lines = []
                        if len(bb.instructions) > 0:
                            bb.addConnection(bb.instructions[-1].offset, l.offset)
                            # Save the current basic block
                            f.basic_blocks.append(bb)
                            self.basic_blocks[bb.instructions[0].offset] = bb
                        # Create a new one
                        bb = CX86BasicBlock()
                        continue
                    else:
                        continue
                else:
                    analyzed_total = 0
            else:
                #flow.reverse()
                naddr = flow.pop()
                #print "Previously saved %08x" % naddr
                if naddr in self.analyzed:
                    # Already analyzed
                    continue
                
                # Create a new basic block
                bb = CX86BasicBlock()
                # And fill the assembly lines
                lines = self.pyew.disasm(naddr, self.pyew.processor, self.pyew.type, 100, 1500)
                l = lines[0]
                #print "%08x" % lines[0].offset, lines[0].mnemonic, lines[0].operands
            
            # Does the address belong to any already analyzed basic block?
            if not self.basic_blocks.has_key(l.offset):
                bb.instructions.append(l)
            
            if bb.offset == 0:
                bb.offset = l.offset
            
            mnem = str(l.mnemonic).upper()
            # Set the current offset as already analyzed
            self.analyzed.append(l.offset)
            
            # Check for typical antidebuggin/antiemulation techniques before
            # doing anything else
            if mnem.startswith("INT") or mnem.startswith("UD") or \
                 mnem.startswith("RDTSC") or mnem.find("IDT") > -1 or \
                 mnem.startswith("CPU") or mnem.find("GDT") > -1 or \
                 mnem.startswith("SYS") or (mnem == "NOP" and str(l.operands) != ""):
                self.antidebug.append((l.offset, str(l.mnemonic)))
            
            if self.basic_blocks.has_key(l.offset):
                break_bb = 2
            elif mnem.find("CALL") > -1: # JMP?
                #
                # Resolve the address of the call/jmp and check
                # if it's an import and if it breaks the current
                # basic block
                #
                val, isimport, isbreak = self.resolveAddress(l.operands)
                self.addXref(l.offset, val)
                # Register the connections for both the basic block and the
                # current function
                if val is None:
                    conn = str(l.operands)
                else:
                    conn = val
                
                #bb.addConnection(l.offset, conn)
                f.addOutConnection(conn)
                
                if isbreak and mnem == "JMP":
                    # We can't resolve the address, break the basic block
                    break_bb = 2
                elif not isimport:
                    if mnem.find("CALL") > -1 and val is not None and val < self.pyew.maxsize:
                        #if val !=
                        if val not in self.queue and val not in self.analyzed and \
                           val != l.offset + l.size:
                            #print "Adding to queue %08x" % val
                            self.queue.append(val)
                    elif mnem == "JMP":
                        # Follow the jump if resolvable
                        #if type(val) is int:
			if str(val).isdigit():
                            lines = self.pyew.disasm(val, self.pyew.processor, self.pyew.type, 100, 1500)
                        else:
                            break_bb = 2
            elif mnem.startswith("J") or mnem.startswith("LOOP"):
                # Break the basic block without clearing 'lines' as we will set
                # the value here
                break_bb = 1
                # Follow the flow
                val, isimport, isbreak = self.resolveAddress(l.operands)
                self.addXref(l.offset, val)
                # Register the connection only for the basic block
                bb.addConnection(l.offset, val)
                
                if mnem != "JMP" and val < self.pyew.maxsize and val is not None:
                    lines = self.pyew.disasm(val, self.pyew.processor, self.pyew.type, 100, 1500)
                
                if mnem != "JMP":
                    bb.addConnection(l.offset, l.offset + l.size)
                    if l.offset + l.size not in self.analyzed:
                        # Save the next instruction for later analysis
                        flow.append(l.offset + l.size)
                else:
                    if isbreak or isimport:
                        break_bb = 2
                    else:
                        # Follow the jump if resolvable
			if str(val).isdigit():
                        #if type(val) is int:
                            lines = self.pyew.disasm(val, self.pyew.processor, self.pyew.type, 100, 1500)
                        else:
                            break_bb = 2
            elif mnem.startswith("RET") or mnem.startswith("HLT") or \
                 mnem.startswith("UD"):
                # Break the basic block and clear 'lines', we don't want to
                # continue analyzing the next assembler lines
                break_bb = 2
            
            i += 1
            # Do we have to clear anything?
            if break_bb != 0:
                if len(bb.instructions) > 0:
                    # Save the current basic block
                    f.basic_blocks.append(bb)
                    self.basic_blocks[bb.instructions[0].offset] = bb
                # Create a new one
                bb = CX86BasicBlock()
                if break_bb == 2:
                    # ...and clear 'lines' if required
                    lines = []
                    i = 0
                
                break_bb = 0
        
        if len(bb.instructions) > 0:
            f.basic_blocks.append(bb)
            self.basic_blocks[bb.instructions[0].offset] = bb
        
        """
        for bb in f.basic_blocks:
            for i in bb.instructions:
                try:
                    x = "0x%08x" % self.pyew.getVirtualAddressFromOffset(int(str(i[2]), 16))
                except:
                    x = i[2]
                print "%08x" % self.pyew.getVirtualAddressFromOffset(int(i[0])), i[1], x
            print "--"
        raw_input("Guay?")
        """
        self.functions[f.address] = f
        addr = None

    def calculateFunctionStats(self, addr):
        if not self.functions.has_key(addr):
            #raw_input("Function doesn't exists?")
            return
        
        for bb in self.functions[addr].basic_blocks:
            self.functions[addr].connections += bb.connections
        
        nodes = len(self.functions[addr].basic_blocks)
        edges = len(self.functions[addr].connections)
        p = 2 # I know, I know...
        cc = edges - nodes + p
        self.functions[addr].stats = (nodes, edges, cc)
        self.function_stats[addr] = (nodes, edges, cc)

    def analyzeArea(self, addr):
        if len(self.queue) == 0:
            self.queue = [addr]
        else:
            self.queue.append(addr)
        
        while addr is not None and len(self.queue) > 0:
            if self.timeout != 0 and time.time() > self.start_time + self.timeout:
                raise Exception("Code analysis for x86 timed-out")
            
            addr = self.queue.pop()
            if addr not in self.analyzed:
                #print "Creating function 0x%08x" % addr
                self.createFunction(addr)
                self.calculateFunctionStats(addr)
                
                if not self.pyew.batch:
                    msg = "\b"*self.last_msg_size + "Analyzing address 0x%08x" % addr + " - %d in queue / %d total" % (len(self.queue), len(self.functions))
                    #print "\b"*self.last_msg_size + " "*self.last_msg_size + "\b"*self.last_msg_size
                    self.last_msg_size = len(msg)
                    sys.stdout.write(msg)
                    sys.stdout.flush()
                #print self.queue
        
        for f in self.functions:
            if len(self.functions[f].basic_blocks) == 1:
                if len(self.functions[f].basic_blocks[0].instructions) >= 1:
                    x = self.functions[f].basic_blocks[0].instructions[0]
                    #   if x.mnemonic == "JMP":
                    addr, isimport, isbreak = self.resolveAddress(x.operands)
                    try:
                        addr = int(addr, 16)
                        self.names[f] = "j_" + self.pyew.names[addr]
                    except:
                        continue
        
        #self.calculeStats()
        
        if not self.pyew.batch:
            #sys.stdout.write("\b"*self.last_msg_size + " "*self.last_msg_size + "\b"*self.last_msg_size)
            pass
        
        return True

    def analyzeEntryPoint(self):
        try:
            exports = self.pyew.exports
            self.queue = self.pyew.exports.keys()
        except:
            # Just ignore the exception
            pass
        
        self.analyzeArea(self.pyew.ep)

    def doCodeAnalysis(self, ep=True, addr=None):
        self.start_time = time.time()
        if ep:
            self.analyzeEntryPoint()
        else:
            self.analyzeArea(addr)
        
        self.pyew.antidebug = self.antidebug
        self.pyew.names.update(self.functions)
        self.pyew.names.update(self.names)
        self.pyew.names[self.pyew.ep] = "start"
        
        try:
            for exp in self.pyew.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    addr = self.pyew.pe.get_offset_from_rva(exp.address)
                except:
                    addr = exp.address
                
                if exp.name and exp.name != "":
                    self.pyew.names[addr] = exp.name
                else:
                    self.pyew.names[addr] = expordinal
        except:
            pass
        
        self.pyew.functions = self.functions
        self.pyew.xrefs_to = self.xrefs_to
        self.pyew.xrefs_from = self.xrefs_from
        self.pyew.basic_blocks = self.basic_blocks
        self.pyew.function_stats = self.function_stats
        self.pyew.program_stats = self.calculeStats()
        self.pyew.seek(0)

    def calculeStats(self):
        nodes = []
        edges = []
        ccs = []
        
        for f in self.functions:
            n, e, c = self.functions[f].stats
            nodes.append(n)
            edges.append(e)
            ccs.append(c)
        
        hash = {}
        hash["nodes"] = {}
        hash["nodes"]["max"] = max(nodes)
        hash["nodes"]["min"] = min(nodes)
        hash["nodes"]["avg"] = sum(nodes)/len(nodes)*1.00
        hash["nodes"]["total"] = sum(nodes)
        hash["edges"] = {}
        hash["edges"]["max"] = max(edges)
        hash["edges"]["min"] = min(edges)
        hash["edges"]["avg"] = sum(edges)/len(edges)*1.00
        hash["edges"]["total"] = sum(edges)
        hash["ccs"] = {}
        hash["ccs"]["max"] = max(ccs)
        hash["ccs"]["min"] = min(ccs)
        hash["ccs"]["avg"] = sum(ccs)/len(ccs)*1.00
        hash["ccs"]["total"] = sum(ccs)
        
        if self.pyew.debug:
            print 
            print "Ciclomatic Complexity -> Max %d Min %d Media %2.2f" % (max(ccs), min(ccs), sum(ccs)/len(ccs)*1.00)
            print "Total functions %d Total basic blocks %d" % (len(self.functions), len(nodes))
        
        return hash

def test():
    """
    sys.path.append("..")
    from pyew import CPyew
    pyew = CPyew(batch=False)
    pyew.loadFile("test.exe")
    """
    pass

if __name__ == "__main__":
    test()

