#!/usr/bin/env python

"""
This file is part of Pyew

Copyright (C) 2009, 2010, 2011, 2012 Joxean Koret

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

from collections import deque

from graphs import CNode, CGraph

try:
    import code, traceback, signal
    signal_handler = True
    # The signal module is available on Windows but there is no SIGUSR1
    # there so disable it for platforms where SIGUSR1 does not exists.
    # NOTE: I'm not checking the os.platform because I don't know if it
    # may happen tomorrow in other platforms (mobiles?)
    signal_handler = 'SIGUSR1' in dir(signal)
except:
    signal_handler = False

def debug(sig, frame):
    """Interrupt running process, and provide a python prompt for
    interactive debugging."""
    d={'_frame':frame}         # Allow access to frame object.
    d.update(frame.f_globals)  # Unless shadowed by global
    d.update(frame.f_locals)
    
    i = code.InteractiveConsole(d)
    message  = "Signal recieved : entering python shell.\nTraceback:\n"
    message += ''.join(traceback.format_stack(frame))
    print
    print message
    print
    i.interact(message)

def listen():
    signal.signal(signal.SIGUSR1, debug)  # Register handler

if signal_handler:
    listen()

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
        self.inrefs = set()
        self.connections = []
        self.offset = 0
    
    def addConnection(self, afrom, ato):
        if (afrom, ato) not in self.connections:
            self.connections.append((afrom, ato))

class CX86CodeAnalyzer:
    timeout=300
    def __init__(self, pyew, _type="PE"):
        self.pyew = pyew
        self.type = _type
        self.names = {}
        self.queue = set()
        self._imports = self.pyew.imports.values()
        self.analyzed = set()
        self.functions = {}
        self.function_stats = {}
        self.basic_blocks = {}
        self.xrefs_to = {}
        self.xrefs_from = {}
        self.antidebug = set()
        
        self.last_msg_size = 0
        self.start_time = None

    def resolveAddress(self, addr, ignore_brace=False):
        addr = str(addr)
        if addr.find("[") > -1 and not ignore_brace:
            addr = addr.strip(" ")
            addr = addr.strip("[").strip("]")
            pos = addr.find("[0x")
            if pos > -1:
                addr = addr[pos+3:]
            pos = addr.find("]")
            if pos > -1:
                addr = addr[:pos]
            if addr.find("+") > -1 or addr.find("-") > -1:
                # horrible!!!!
                return self.resolveAddress(addr, True)

            try:
                addr = int(addr, 16)
            except:
                pass

            name = self.pyew.resolveName(addr)
            if name in self._imports:
                return addr, True, False
        elif addr.find(",") > -1:
            part = addr.split(",")
            if len(part) == 2:
                try:
                    addr = int(part[1], 16)
                except:
                    return None, False, True
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

    def breakBasicBlock(self, bbaddr, l, lines, f):
        bb_addrs = set()
        # Removed addresses belonging to the new basic block and fill new one
        new_bb = CX86BasicBlock()
        new_bb.offset = l.offset
        i = 0
        for ins in self.basic_blocks[bbaddr].instructions:
            bb_addrs.add(ins.offset)
            if ins.offset < l.offset:
                self.basic_blocks[bbaddr].instructions = self.basic_blocks[bbaddr].instructions[:i+1]
            else:
                new_bb.instructions.append(ins)
            i += 1
        
        # Modify basic block's connections
        conns = self.basic_blocks[bbaddr].connections
        self.basic_blocks[bbaddr].connections = [(ins.offset, l.offset)]
        for conn in conns:
            afrom, ato = conn
            if afrom <= l.offset:
                self.basic_blocks[bbaddr].connections.append((afrom, ato))
            else:
                new_bb.connections.append((afrom, ato))
        f.basic_blocks.append(new_bb)
        
        # Remove the next lines from 'lines'
        while len(lines) > 0:
            if len(lines) > 0:
                tmp_line = lines[0]
                if tmp_line.offset in bb_addrs:
                    lines = lines[1:]
                else:
                    break
        return lines, f

    def createFunction(self, addr):
        if self.timeout != 0 and time.time() > self.start_time + self.timeout:
            raise Exception("Code analysis for x86 timed-out")
        
        if addr in self.analyzed or addr in self.functions:
            #print "Function %08x already analyzed" % addr
            return

        # First, create a function object. Then, disassemble the 1st 100 lineal
        # instructions given an offset (addr)
        #
        self.names[addr] = "sub_%08x" % addr
        f = CX86Function(addr)
        lines = self.pyew.disasm(abs(addr), self.pyew.processor, self.pyew.type, 100, 1500)
        bb = CX86BasicBlock()
        bb.offset = addr
        flow = deque() # set()
        
        # Possible values for break_bb are:
        #
        #   0 = Do nothing
        #   1 = Break the basic block
        #   2 = Break the basic block and clear 'lines'
        #
        break_bb = 0
        
        # Iterate while there is at least one more line of code
        # or there is some address to follow (in list flow)
        #
        while len(lines) > 0 or len(flow) > 0:
            if self.timeout != 0 and time.time() > self.start_time + self.timeout:
                raise Exception("Code analysis for x86 timed-out")

            if len(lines) > 0:
                # Extract and remove the fist element in the list of lineally
                # disassembled instructions
                l = lines[0]
                lines = lines[1:]
                
                # Was it previously analyzed?
                if l.offset in self.analyzed:
                    # Already analyzed
                    if l.offset in self.basic_blocks:
                        lines = set()
                        if len(bb.instructions) > 0:
                            bb.addConnection(bb.instructions[-1].offset, l.offset)
                            # Save the current basic block
                            f.basic_blocks.append(bb)
                            self.basic_blocks[bb.instructions[0].offset] = bb
                        # Create a new one
                        bb = CX86BasicBlock()
                        continue
                    else:
                        # OK, the address is already analyzed, it's a jump or the
                        # like and we may jump inside a basic block so, in this
                        # case split the basic block into smaller, but correct,
                        # basic blocks
                        for bbaddr in list(self.basic_blocks):
                            if self.timeout != 0 and time.time() > self.start_time + self.timeout:
                                raise Exception("Code analysis for x86 timed-out")

                            bb_start = bbaddr
                            bb_end = self.basic_blocks[bbaddr].instructions[-1].offset
                            if l.offset > bb_start and l.offset < bb_end:
                                lines, f = self.breakBasicBlock(bbaddr, l, lines, f)
                                break
                        continue
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
            if mnem.find(" ") > -1:
                mnem = mnem.split(" ")[-1]

            # Set the current offset as already analyzed
            self.analyzed.add(l.offset)
            
            # Check for typical antidebugging/antiemulation techniques before
            # doing anything else
            if mnem.startswith("INT") or mnem.startswith("UD") or \
               mnem.startswith("RDTSC") or mnem.find("IDT") > -1 or \
               mnem.startswith("CPU") or mnem.find("GDT") > -1 or \
               mnem.startswith("SYS") or (mnem == "NOP" and \
               str(l.operands) != ""):
                self.antidebug.append((l.offset, str(l.mnemonic)))
            
            if self.basic_blocks.has_key(l.offset):
                break_bb = 2
            elif mnem.find("CALL") > -1: # JMP?:
                if l.operands.startswith("FAR"):
                  pos = l.operands.find(":")
                  if pos > -1:
                    l.operands = l.operands[pos+1:]
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
                
                if not isimport:
                    if val is not None and val < self.pyew.maxsize:
                        #if val !=
                        if val not in self.queue and val not in self.analyzed and \
                           val != l.offset + l.size:
                            #print "Adding to queue %08x" % val
                            self.queue.add(val)
            
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
            elif mnem.startswith("MOV") or mnem.startswith("PUSH"):
                if mnem == "PUSH":
                    val, isimport, isbreak = self.resolveAddress(l.operands)
                else:
                    val, isimport, isbreak = self.resolveAddress(l.operands)
                
                if val is not None:
                    addr = val
                    if self.pyew.executableMemory(addr):
                        offset = self.pyew.getOffsetFromVirtualAddress(addr)
                        f.addOutConnection(offset)
                        self.queue.add(offset)
            
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
                    lines = set()
                
                break_bb = 0
        
        if len(bb.instructions) > 0:
            f.basic_blocks.append(bb)
            self.basic_blocks[bb.instructions[0].offset] = bb
        
        self.functions[f.address] = f
        addr = None

    def calculateFunctionStats(self, addr):
        if not self.functions.has_key(addr):
            raw_input("Function doesn't exists?")
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
            self.queue = set([addr])
        else:
            self.queue.add(addr)

        while addr is not None and len(self.queue) > 0:
            if self.timeout != 0 and time.time() > self.start_time + self.timeout:
                raise Exception("Code analysis for x86 timed-out")
            
            addr = self.queue.pop()
            if addr not in self.analyzed:
                self.createFunction(addr)
                self.calculateFunctionStats(addr)
                
                if not self.pyew.batch:
                    msg = "\b"*self.last_msg_size + "Analyzing address 0x%08x" % addr + " - %d in queue / %d total" % (len(self.queue), len(self.functions))
                    if len(msg) < 80:
                      size = 80 - len(msg)
                      msg += " "*size + "\b"*size
                    self.last_msg_size = len(msg)
                    sys.stdout.write(msg)
                    sys.stdout.flush()
        
        for f in self.functions:
            if self.timeout != 0 and time.time() > self.start_time + self.timeout:
                raise Exception("Code analysis for x86 timed-out")

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
            self.queue = set(self.pyew.exports.keys())
        except:
            # Just ignore the exception
            pass
        
        self.analyzeArea(self.pyew.ep)

    def buildCallGraph(self):
        g = CGraph()
        ep = self.pyew.ep
        
        try:
            l = set(self.pyew.exports.keys())
            l.add(self.pyew.ep)
        except:
            print "Error:", sys.exc_info()[1]
            l = set([self.pyew.ep])
            raise
        
        functions = []
        nodes = {}
        
        """ Compute the entry points initial graph """
        for ep in l:
            if self.pyew.functions.has_key(ep):
                fep = self.pyew.functions[ep]
                for c in fep.connections:
                    if c in self.pyew.functions:
                        if c not in functions:
                            functions.append(c)
                        
                        if self.pyew.names[ep] not in nodes:
                            n1 = CNode(self.pyew.names[ep])
                            nodes[self.pyew.names[ep]] = n1
                        else:
                            n1 = nodes[self.pyew.names[ep]]
                        
                        if self.pyew.names[c] not in nodes:
                            n2 = CNode(self.pyew.names[c])
                            nodes[self.pyew.names[c]] = n2
                        else:
                            n2 = nodes[self.pyew.names[c]]
                        g.addEdge(n1, n2)
        
        """ Add all the remaining functions """
        dones = set()
        while len(functions) > 0:
            addr = functions.pop()
            f = self.pyew.functions[addr]
            for c in f.connections:
                if c in self.pyew.functions and c not in dones:
                    functions.append(c)
                    dones.add(c)
                    
                    if self.pyew.names[addr] not in nodes:
                        n1 = CNode(self.pyew.names[addr])
                        nodes[self.pyew.names[addr]] = n1
                    else:
                        n1 = nodes[self.pyew.names[addr]]
                    
                    if self.pyew.names[c] not in nodes:
                        n2 = CNode(self.pyew.names[c])
                        nodes[self.pyew.names[c]] = n2
                    else:
                        n2 = nodes[self.pyew.names[c]]
                    g.addEdge(n1, n2)
        return g

    def buildFlowGraph(self, f):
        fg = CGraph()
        func = self.pyew.functions[f]
        bbs = {}
        nodes = {}
        for bb in func.basic_blocks:
            instructions = set()
            bb_start = bb.instructions[0].offset
            end_offset = bb.instructions[-1].offset
            bb_end = end_offset + bb.instructions[-1].size
            
            buf = self.pyew.getBytes(bb_start, bb_end-bb_start)
            instructions = self.pyew.disassemble(buf=buf, baseoffset=bb_start, marker=False)
            instructions = instructions.split("\n")
            if instructions[-1] == "":
                del instructions[len(instructions)-1]
            
            bbs[bb_start] = instructions
            bbs[end_offset] = instructions
            
            n = CNode(str(bb.offset), data=instructions)
            fg.addNode(n)
            nodes[bb.offset] = n
        
        for bb in func.basic_blocks:
            next_head = self.pyew.NextHead(bb.instructions[-1].offset)
            for conn in bb.connections:
                a, b = conn
                if nodes.has_key(b) and nodes.has_key(bb.offset):
                    if len(bb.connections) == 1:
                        color = 0 # edge always
                    elif next_head == b:
                        color = 2 # edge false or unknown
                    else:
                        color = 1 # edge true
                    
                    fg.addEdge(nodes[bb.offset], nodes[b], value=color)
        
        return fg

    def buildFlowGraphs(self):
        fg = {}
        for f in self.functions:
            fg[f] = self.buildFlowGraph(f)
        return fg

    def doCodeAnalysis(self, ep=True, addr=None):
        if self.start_time == None:
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
                if addr in self.pyew.names:
                    continue

                try:
                    addr = self.pyew.pe.get_offset_from_rva(exp.address)
                except:
                    addr = exp.address
                
                if exp.name and exp.name != "":
                    self.pyew.names[addr] = exp.name
                else:
                    self.pyew.names[addr] = exp.ordinal
        except:
            pass
        
        self.pyew.functions = self.functions
        self.pyew.xrefs_to = self.xrefs_to
        self.pyew.xrefs_from = self.xrefs_from
        self.pyew.basic_blocks = self.basic_blocks
        self.pyew.function_stats = self.function_stats
        self.pyew.program_stats = self.calculeStats()
        self.pyew.callgraph = self.buildCallGraph()
        self.pyew.flowgraphs = self.buildFlowGraphs()
        self.pyew.seek(0)

    def calculeStats(self):
        nodes = []
        edges = []
        ccs = []
        
        for f in self.functions:
            n, e, c = self.functions[f].stats
            if n > 0 and e > 0 and c > 0:
              nodes.append(n)
              edges.append(e)
              ccs.append(c)

        hash = {}
        hash["nodes"] = {}
        if len(nodes) > 0:
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
        if len(ccs) > 0:
          hash["ccs"]["max"] = max(ccs)
          hash["ccs"]["min"] = min(ccs)
          hash["ccs"]["avg"] = sum(ccs)/len(ccs)*1.00
          hash["ccs"]["total"] = sum(ccs)
        
        if self.pyew.debug and len(ccs) > 0:
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

