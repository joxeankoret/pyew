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

class CNode:
    name = None
    label = None

    def __init__(self, name, label):
        self.name = name
        self.label = label

class CDotDiagram:
    def __init__(self):
        self.index = 0
        self.identifiers = {}
        self.nodes = {}
        self.connections = {}
        self.antirules = []
        self._verbose = False

    def addNode(self, node):
        
        if not self.nodes.has_key(node.name):
            self.index += 1
            self.nodes[node.name] = node.label
            self.identifiers[node.name] = self.index

    def addConnectedNode(self, node1, node2):
        if node1.name == node2.name:
            return
        
        if self.connections.has_key(node1.name):
            if self.connections[node1.name] == node2.name:
                print "Connection ignored (already exists)"
                return
        
        if self.connections.has_key(node2.name):
            if self.connections[node2.name] == node1.name:
                print "Connection ignored (already exists)"
                return
        
        self.addNode(node1)
        self.addNode(node2)
        
        if not self.connections.has_key(node1.name):
            self.connections[node1.name] = [node2.name]
        else:
            self.connections[node1.name].append(node2.name)
    
    def generateDot(self):
        buf = 'digraph G {\n graph [overlap=scale]; node [fontname=Courier]; \n'
        
        if self._verbose:
            print "Total of %d node(s)" % len(self.nodes)
        
        for node in self.nodes:
            buf += ' a%s [shape=box, label = "%s", color="blue"]\n' % (self.identifiers[node], self.nodes[node])
        buf += "\n"
        
        if self._verbose:
            print "Total of %d connections(s)" % len(self.connections)
    
        i = 0
        for conn in self.connections:
            i += 1
            if self._verbose:
                print "Connections for %s are %d" % (str(conn), len(self.connections[conn]))
                total = len(self.connections)
                print "Done %d out of %d (%f%%)" % (i, total, (i*100.00/total*1.00))
                
                if i*100.00/total*1.00 >= 101:
                    break
            
            for x in self.connections[conn]:
                parent = self.identifiers[x]
                child  = self.identifiers[conn]
                rule = str(parent) + "-" + str(child)
                antirule = str(child) + "-" + str(parent)
                
                if antirule not in self.antirules and rule not in self.antirules:
                    buf += " a%s -> a%s [style = bold, color=red]\n" % (child, parent)
                    self.antirules.append(rule)
                    self.antirules.append(antirule)
                else:
                    pass
                    #print "antirule"
            
        buf += "}"
        return buf

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
                #print "XRefs from entry point %s" % self.pyew.names[self.pyew.ep]
                for c in fep.connections:
                    if c in self.pyew.functions:
                        if c not in functions:
                            functions.append(c)
                        
                        n1 = CNode(self.pyew.names[ep], self.pyew.names[ep])
                        n2 = CNode(self.pyew.names[c], self.pyew.names[c])
                        dot.addConnectedNode(n1, n2)
                        #print "  %s" % self.pyew.names[c]
        
        dones = []
        while len(functions) > 0:
            addr = functions.pop()
            f = self.pyew.functions[addr]
            #print "XRefs from %s" % self.pyew.names[addr]
            for c in f.connections:
                if c in self.pyew.functions and c not in dones:
                    functions.append(c)
                    dones.append(c)
                    
                    n1 = CNode(self.pyew.names[addr], self.pyew.names[addr])
                    n2 = CNode(self.pyew.names[c], self.pyew.names[c])
                    dot.addConnectedNode(n1, n2)
                    #print "  %s" % self.pyew.names[c]
        return dot.generateDot()

def showCallGraph(pyew, doprint=True, addr=None):
    """ Show the callgraph of the whole program """
    dot = CCallGraphGenerator(pyew)
    buf = dot.generateDot()

    if doprint:
        try:    
            import gtk
            from xdot import DotWindow
            
            win = DotWindow()
            win.connect('destroy', gtk.main_quit)
            win.set_filter("dot")
            win.set_dotcode(buf)
            gtk.main()
        except ImportError:
            print "Python-GTK is not installed"

    return buf

functions = {"cgraph":showCallGraph}
