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

    def generateDot(self):
        dot = CDotDiagram()
        ep = self.pyew.ep
        try:
            l = self.pyew.exports.keys()
            l.append(self.pyew.ep)
        except:
            print "Error:", sys.exc_info()[1]
            l = [self.pyew.ep]
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

def showCallGraph(pyew, doprint=True, addr=None):
    """ Show the callgraph of the whole program """
    dot = CCallGraphGenerator(pyew)
    buf = dot.generateDot()

    if doprint:
        showDotInXDot(buf)

    return buf

def showBinaryImage(pyew, doprint=True):
    """ Show an image representing the current opened file """

    buf = pyew.getBuffer()
    size = len(buf)**(1./3)+1
    img = Image.new("RGB", (size, size), "red")
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

if hasPil:
    functions = {"cgraph":showCallGraph,
             "binvi":showBinaryImage}
else:
    functions = {"cgraph":showCallGraph}

