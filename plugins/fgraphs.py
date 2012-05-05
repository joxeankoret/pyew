#!/usr/bin/env python

"""
Pyew! A Python Tool like the populars *iew

Copyright (C) 2009,2010 Joxean Koret

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

import os
import sys
import thread
import tempfile
import webbrowser

try:
    from PIL import Image
    hasPil = True
except ImportError:
    hasPil = False

from diagrams import CDotDiagram, CNode

class CCallGraphGenerator(object):
    def __init__(self, pyew):
        self.pyew = pyew

    def generateDot(self, func=None):
        if func is None:
            return self.pyew.callgraph.toDot()
        
        dot = CDotDiagram()
        if func is None:
            ep = self.pyew.ep
        else:
            ep = func
        
        if func is None:
            try:
                l = self.pyew.exports.keys()
                l.append(self.pyew.ep)
            except:
                print "Error:", sys.exc_info()[1]
                l = [self.pyew.ep]
        else:
            l = [ep]
        
        functions = []
        
        for ep in l:
            if self.pyew.functions.has_key(ep):
                fep = self.pyew.functions[ep]
                for c in fep.connections:
                    if c in self.pyew.functions:
                        if c not in functions:
                            functions.append(c)
                        
                        n1 = CNode(self.pyew.names[ep], self.pyew.names[ep])
                        n2 = CNode(self.pyew.names[c], self.pyew.names[c])
                        dot.addConnectedNode(n1, n2)
        
        dones = []
        while len(functions) > 0:
            addr = functions.pop()
            f = self.pyew.functions[addr]
            for c in f.connections:
                if c in self.pyew.functions and c not in dones:
                    functions.append(c)
                    dones.append(c)
                    
                    n1 = CNode(self.pyew.names[addr], self.pyew.names[addr])
                    n2 = CNode(self.pyew.names[c], self.pyew.names[c])
                    dot.addConnectedNode(n1, n2)
                    
        x = dot.generateDot()
        return x

class CFlowGraphGenerator(object):
    def __init__(self, pyew):
        self.pyew = pyew

    def generateDot(self, f):
        dot = CDotDiagram()
        func = self.pyew.functions[f]
        bbs = {}
        nodes = {}
        for bb in func.basic_blocks:
            instructions = []
            bb_start = bb.instructions[0].offset
            end_offset = bb.instructions[-1].offset
            bb_end = end_offset + bb.instructions[-1].size
            
            buf = self.pyew.getBytes(bb_start, bb_end-bb_start)
            instructions = self.pyew.disassemble(buf=buf, baseoffset=bb_start, marker=False)
            instructions = instructions.replace("\r", "").replace("\n", "\\l")
            instructions = instructions.replace('"', '\"')
            
            bbs[bb_start] = instructions
            bbs[end_offset] = instructions
            
            n = CNode(bb.offset, instructions)
            dot.addNode(n)
            nodes[bb.offset] = n
        
        for bb in func.basic_blocks:
            for conn in bb.connections:
                a, b = conn
                next_head = self.pyew.NextHead(bb.instructions[-1].offset)
                if nodes.has_key(b) and nodes.has_key(bb.offset):
                    if len(bb.connections) == 1:
                        color = "blue"
                    elif next_head == b:
                        color = "red"
                    else:
                        color = "green"
                    
                    dot.addConnectedNode(nodes[bb.offset], nodes[b], color)
        
        return dot.generateDot()

def showDotInXDot(buf):
    try:    
        import gtk, thread
        from xdot import DotWindow
        
        win = DotWindow()
        win.connect('destroy', gtk.main_quit)
        win.set_filter("dot")
        win.set_dotcode(buf)
        try:
            thread.start_new_thread(gtk.main, None)
        except:
            pass
    except ImportError:
        print "Python-GTK is not installed"

def showCallGraph(pyew, doprint=True, addr=None, args=None):
    """ Show the callgraph of the whole program or the specified function """
    dot = CCallGraphGenerator(pyew)
    if args is not None:
        buf = []
        for arg in args:
            f = pyew.getFunction(arg)
            if f is None:
                print "Invalid function %s" % repr(arg)
                break
            
            buf.append(dot.generateDot(func=f))
    else:
        buf = dot.generateDot()

    if doprint:
        if type(buf) is type([]):
            for b in buf:
                showDotInXDot(b)
        else:
            showDotInXDot(buf)

    return buf

def showFlowGraph(pyew, doprint=True, args=None):
    """ Show the flowgraph of the specified function or the current on """
    if args is None:
        args = [str(pyew.offset)]

    dot = CFlowGraphGenerator(pyew)
    buf = []
    for arg in args:
        f = pyew.getFunction(arg)
        if f is None:
            print "Invalid function %s" % repr(arg)
            break
        
        buf.append(dot.generateDot(f))

    if doprint:
        for b in buf:
            showDotInXDot(b)

    return buf

def showBinaryImage(pyew, doprint=True, args=None):
    """ Show an image representing the current opened file """

    buf = pyew.getBuffer()
    size = len(buf)**(1./3)+1
    img = Image.new("RGB", (int(size), int(size)), "red")
    putpixel = img.putpixel
    i = 0

    for y in range(int(size)):
        for x in range(int(size)):
            if i > len(buf) or len(buf)-i <= 3:
                break
            
            value = (ord(buf[i:i+1]), ord(buf[i+1:i+2]), ord(buf[i+3:i+4]))
            i += 3
            putpixel((x, y), value)

    n, filename = tempfile.mkstemp(suffix=".png")
    img.save(filename)

    if doprint:
        webbrowser.open(filename)

    return filename

functions = {"cgraph":showCallGraph,
             "fgraph":showFlowGraph}

if hasPil:
    functions["binvi"] = showBinaryImage
