#!/usr/bin/env python

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
        self.colors = {}
        self.antirules = []
        self._verbose = False

    def addNode(self, node):
        
        if not self.nodes.has_key(node.name):
            self.index += 1
            self.nodes[node.name] = node.label
            self.identifiers[node.name] = self.index

    def addConnectedNode(self, node1, node2, color="red"):
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
        
        self.colors[(self.identifiers[node1.name], self.identifiers[node2.name])] = color

    def generateDot(self):
        buf = 'digraph G {\n graph [overlap=scale]; node [fontname=Courier, center=false]; \n'
        
        if self._verbose:
            print "Total of %d node(s)" % len(self.nodes)
        
        for node in self.nodes:
            buf += ' a%s [fontname="Courier", shape=box, label="%s", color="blue" url="%s"]\n' % (self.identifiers[node], self.nodes[node], node)
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
                buf += " a%s -> a%s [style = bold, color=%s]\n" % (child, parent, self.colors[(child, parent)])
            
        buf += "}"
        return buf
