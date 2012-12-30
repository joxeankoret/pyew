#!/usr/bin/env python

import random

class CGmlGraph:
    def __init__(self, g):
        self.g = g

    def generate(self):
        buf = "graph [ \n"
        nodes = self.g.nodes()
        
        for node in nodes:
            name = node.name
            num = nodes.index(node)
            
            buf += 'node [ id %s \n label "%s"\n fill "blue" \n type "oval"\n LabelGraphics [ type "text" ] ] \n' % (num, name)
        buf += "\n"

        for parent in self.g.d:
            p = nodes.index(parent)
            for child in self.g.d[parent]:
                c = nodes.index(child)
                buf += " edge [ source %s \n target %s ]\n" % (p, c)
        
        buf += "]"
        return buf

class CDotGraph:
    def __init__(self, g):
        self.g = g

    def generate(self):
        buf = 'digraph G {\n graph [overlap=scale]; node [fontname=Courier]; \n\n'
        nodes = self.g.nodes()
        
        for node in nodes:
            name = node.name.replace('"', r'\"')
            num = nodes.index(node)
            
            buf += ' a%s [shape=box, label = "%s", color="blue"]\n' % (num, name)
        buf += "\n"

        for parent in self.g.d:
            p = nodes.index(parent)
            for child in self.g.d[parent]:
                c = nodes.index(child)
                val = self.g.weights[parent,child]
                if val is None:
                    color = "red"
                elif val == 0:
                    color = "blue"
                elif val == 1:
                    color = "green"
                else:
                    color = "red"
                buf += " a%s -> a%s [style = bold, color=%s]\n" % (p, c, color)
        
        buf += "}"
        return buf

class CNode(object):
    def __init__(self, name, data=None, label=None):
        self.name = name
        self.data = data
        self.label = label

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()

class CGraph(object):
    def __init__(self):
        self.d = {}
        self.weights = {}

    def __str__(self):
        return str(self.d)

    def __repr__(self):
        return self.__str__()

    def clear(self):
        self.d.clear()

    def setDict(self, d):
        self.d = d

    def has_key(self, x):
        return self.d.has_key(x)

    def hash(self):
        ret = []
        keys = self.d.keys()
        keys.sort()
        for key in keys:
            values = map(str, self.d[key])
            values.sort()
            copy_values = []
            for value in values:
                copy_values.append("'%s'" % str(value))
            v = "'%s':[%s]" % (key, ", ".join(copy_values))
            ret.append(v)
        return "{" + ",".join(ret) + "}"
    
    def checkHash(self, d):
        if type(d) is not dict:
            raise Exception("Invalid hash")
        
        d2 = eval(self.hash())
        return d == d2

    def addNode(self, node):
        self.d[node] = []
    
    def delNode(self, n):
        if self.d.has_key(n):
            del self.d[n]
        
        for n2 in list(self.d):
            if n in self.d[n2]:
                self.d[n2].remove(n)

    def addVertex(self, edge):
        self.addNode(edge)

    def addEdge(self, n1, n2, check_dups=False, value=None):
        if not self.d.has_key(n1):
            self.d[n1] = []
        
        if check_dups:
            if n2 in self.d[n1]:
                return
        
        self.d[n1].append(n2)
        self.weights[(n1, n2)] = value

    def getWeight(self, n1, n2):
        if self.weights.has_key((n1, n2)):
            return self.weights[(n1, n2)]
        else:
            return None

    def hasChildren(self, n):
        return len(self.d[n]) > 0

    def hasParents(self, n):
        for n2 in self.d:
            if n in self.d[n2]:
                return True
        return False

    def node(self, name):
        for n in self.d:
            if n.name == name:
                return n
        
        return None

    def searchPath(self, start, end, path=[]):
        path = path + [start]
        if start == end:
            return path
        
        if not self.d.has_key(start):
            return None
        
        for node in self.d[start]:
            if node not in path:
                newpath = self.searchPath(node, end, path)
                if newpath:
                    return newpath
        
        return None

    def searchAllPaths(self, start, end, path=[]):
        path = path + [start]
        
        if start == end:
            yield path
        elif not self.d.has_key(start):
            yield None
        else:
            for node in self.d[start]:
                if node not in path:
                    newpaths = self.searchAllPaths(node, end, path)
                    for newpath in newpaths:
                        yield newpath

    def searchLongestPath(self, astart, aend):
        longest = None
        l = self.searchAllPaths(astart, aend)
        
        for path in l:
            if path is None:
                continue
            
            if longest is None or len(path) > len(longest):
                longest = path
        
        return longest

    def searchShortestPath(self, start, end, path=[]):
        path = path + [start]
        if start == end:
            return path
        if not self.d.has_key(start):
            return None
        
        shortest = None
        for node in self.d[start]:
            if node not in path:
                newpath = self.searchPath(node, end, path)
                if newpath:
                    if not shortest or len(shortest) > len(newpath):
                        shortest = newpath
        
        return shortest

    def addGraph(self, g2):
        for key in list(g2.d):
            if not self.d.has_key(key):
                self.d[key] = []
            
            for value in list(g2.d[key]):
                self.d[key].append(value)

    def nodes(self):
        l = []
        for father in self.d:
            if father not in l:
                l.append(father)
            
            for child in self.d[father]:
                if child not in l:
                    l.append(child)
        return l

    def toAdjacencyList(self):
        l = ()
        for father in self.d:
            for child in self.d[father]:
                l += ((father, child), )
        
        return l

    def fromAdjacencyList(self, l):
        for element in l:
            k, v = element
            if not self.d.has_key(k):
                self.d[k] = []
            
            if v not in self.d[k]:
                self.d[k].append(v)

    def toAdjacencyMatrix(self):
        nodes = self.nodes()
        nodes.sort()
        
        x = []
        for n1 in nodes:
            y = []
            for n2 in nodes:
                if not self.d.has_key(n2) or n1 not in self.d[n2]:
                    v = 0
                else:
                    v = 1
                y.append(v)
            
            x.append(y)
        
        return nodes, x

    def toGml(self):
        gml = CGmlGraph(self)
        return gml.generate()
    
    def toDot(self):
        dot = CDotGraph(self)
        return dot.generate()

    def isSubgraph(self, g2):
        for node in g2.d:
            if node not in self.d:
                return False
            
            for subnode in g2.d[node]:
                if subnode not in self.d[node]:
                    return False
        
        return True

    def intersect(self, g):
        l1 = set(self.toAdjacencyList())
        l2 = set(g.toAdjacencyList())        
        r = l1.intersection(l2)
        
        return r

    def union(self, g):
        l1 = set(self.toAdjacencyList())
        l2 = set(g.toAdjacencyList())        
        r = l1.union(l2)
        
        return r

    def difference(self, g):
        l1 = set(self.toAdjacencyList())
        l2 = set(g.toAdjacencyList())        
        r = l1.difference(l2)
        
        return r
    
    def symmetricDifference(self, g):
        l1 = set(self.toAdjacencyList())
        l2 = set(g.toAdjacencyList())        
        r = l1.symmetric_difference(l2)
        
        return r

def test1():    
    assert str(CNode("x")) == "x"

    g = CGraph()
    n1 = CNode("a")
    n2 = CNode("b")
    n3 = CNode("c")
    n4 = CNode("d")
    
    g.addEdge(n1, n2)
    g.addEdge(n1, n3)
    g.addEdge(n2, n4)
    g.addEdge(n3, n4)
    
    print "Printing a graph with 4 nodes"
    print g
    
    
    print "Searching path between n1 and n1"
    print g.searchPath(n1, n1)
    print "Searching path between n1 and n2"
    print g.searchPath(n1, n2)
    print "Searching path between n1 and n4"
    print g.searchPath(n1, n4)

    print "Creating a graph with 6 nodes"
    g = CGraph()
    a = CNode("a")
    b = CNode("b")
    c = CNode("c")
    d = CNode("d")
    e = CNode("e")
    f = CNode("f")
    
    g.addEdge(a, b)
    g.addEdge(b, c)
    g.addEdge(c, a)
    g.addEdge(d, e)
    g.addEdge(e, f)
    print "1# Searching a path between a and f"
    print g.searchPath(a, f)

    g.addEdge(c, d)
    print "2# Searching a path between a and f"
    print g.searchPath(a, f)
    
    g.addEdge(b, f)
    g.addEdge(c, f)
    g.addEdge(a, e)
    print "Searching all paths between a and f"
    print list(g.searchAllPaths(a, f))
    
    print "Searching the shortest path between a and f"
    print g.searchShortestPath(a, f)
    
    print "Clearing the graph"
    g.clear()
    print g

def test2():
    #print "Creating 2 graphs with 3 and 5 nodes"
    a = CNode("a")
    b = CNode("b")
    c = CNode("c")
    n = CNode("n")
    x = CNode("x")
    y = CNode("y")

    g1 = CGraph()
    g2 = CGraph()

    g1.addEdge(a, b)
    g1.addEdge(a, c)

    g2.addEdge(a, n)
    g2.addEdge(n, y)
    g2.addEdge(b, x)
    g2.addEdge(x, y)

    #print "Graph 1"
    #print g1
    #print "Graph 2"
    #print g2
    #print "Adding graph 2 to graph 1"
    g1.addGraph(g2)

    #print "Resulting graph"
    #print g1
    
    #print "Adjacency list"
    print g1.toAdjacencyList()
    
    #print "Adjacency matrix"
    #print g1.nodes()
    print g1.toAdjacencyMatrix()

def test3():
    a = CNode("a")
    b = CNode("b")
    c = CNode("c")
    n = CNode("n")
    x = CNode("x")
    y = CNode("y")

    g1 = CGraph()
    g2 = CGraph()

    g1.addEdge(a, b)
    g1.addEdge(a, c)

    g2.addEdge(a, n)
    g2.addEdge(n, y)
    g2.addEdge(b, x)
    g2.addEdge(x, y)

    g1.addGraph(g2)
    dot = g1.toDot()
    print dot
    gml = g1.toGml()
    print gml

def randomGraph(totally=False):
    if totally:
        node_count = random.randint(0, 50)
    else:
        node_count = 50
    nodes = {}
    
    for x in range(node_count):
        name = "n%d" % x
        nodes[name] = CNode(name)
    
    g = CGraph()
    
    for x in nodes:
        for y in nodes:
            if random.randint(0, 10) == 0:
                g.addEdge(nodes[x], nodes[y])

    print g.toDot()

def randomGraph2():
    node_count = random.randint(0, 50)
    nodes = {}
    
    for x in range(node_count):
        name = "n%d" % x
        nodes[name] = CNode(name)
    
    g = CGraph()
    
    for x in nodes:
        for y in nodes:
            if random.randint(0, 1) == 1:
                g.addEdge(nodes[x], nodes[y])

    for i in range(100):
        n1 = random.choice(nodes.keys())
        n2 = random.choice(nodes.keys())
        
        #print "Searching a path between %s and %s in a %d nodes graph" % (n1, n2, node_count)
        path = g.searchPath(n1, n2)
        if path:
            print "Path found between %s and %s in a %d nodes graph" % (n1, n2, node_count)
            print path

def testRandomGraph():
    node_count = random.randint(2, 20)
    nodes = {}
    
    g = CGraph()
    
    for x in range(node_count):
        name = "n%d" % x
        nodes[name] = CNode(name)

    for x in nodes:
        for y in nodes:
            if random.randint(0, 4) == 1:
                g.addEdge(nodes[x], nodes[y])

    print "Graph"
    print g
    print
    print "Searching paths"
    for n1 in g.nodes():
        if g.has_key(n1):
            for n2 in g.d[n1]:
                print n1, n2
                print "Shortest", g.searchShortestPath(n1, n2)
                print "Longest", g.searchLongestPath(n1, n2)
                print "All paths: Total %d" % len(list(g.searchAllPaths(n1, n2)))

def testIsSubgraph():
    """
    Graph 1
                 A
                / \
               B   C
              / \ / \
             D  E F  G
    
    Graph 2
                 A
                / 
               B
              / \
             D  E
    """

    a = CNode("a")
    b = CNode("b")
    c = CNode("c")
    d = CNode("d")
    e = CNode("e")
    f = CNode("f")
    g = CNode("g")

    g1 = CGraph()
    g1.addEdge(a, b)
    g1.addEdge(a, c)
    g1.addEdge(b, d)
    g1.addEdge(b, e)
    g1.addEdge(c, f)
    g1.addEdge(c, g)

    g2 = CGraph()
    print g2
    g2.addEdge(a, b)
    g2.addEdge(b, d)
    g2.addEdge(b, e)

    print g1
    print "g", g2
    # Check if it's a subgraph
    assert g1.isSubgraph(g2) 
    
    # Change the graph and check again
    g2.addEdge(a, d)
    assert g1.isSubgraph(g2) == False

def testRandomSubgraph():
    #import random
    
    node_count = random.randint(0, 512)
    nodes = {}
    
    for x in range(node_count):
        name = "n%d" % x
        nodes[name] = CNode(name)
    
    g = CGraph()
    i = 0
    for x in nodes:
        for y in nodes:
            if random.randint(0, 1) == 1:
                g.addEdge(nodes[x], nodes[y])
            i += 1
            if i <= node_count/2:
                g1 = g
    
    assert g.isSubgraph(g1) == True

def testOperations():
    a = CNode("a")
    b = CNode("b")
    c = CNode("c")
    d = CNode("d")
    e = CNode("e")
    f = CNode("f")
    g = CNode("g")

    g1 = CGraph()
    g1.addEdge(a, b)
    g1.addEdge(a, c)
    g1.addEdge(b, d)
    g1.addEdge(b, e)
    g1.addEdge(c, f)
    g1.addEdge(c, g)

    g2 = CGraph()
    g2.addEdge(a, b)
    g2.addEdge(b, d)
    g2.addEdge(b, e)
    
    g3 = CGraph()
    al = g1.intersect(g2)

    g3.fromAdjacencyList(al)
    print g3
    
    al = g1.union(g2)
    g3.clear()
    g3.addEdge(f, a)
    
    g3.fromAdjacencyList(al)
    print g3
    
    print g3.toAdjacencyMatrix()
    
    print g3.difference(g1)
    print g2.difference(g1)
    print g3.difference(g2)
    
    al1 = g1.union(g2)
    al2 = g2.union(g3)
    new_graph = CGraph()
    new_graph.fromAdjacencyList(al1)
    new_graph.fromAdjacencyList(al2)
    
    print new_graph

def testNode():
    g = CGraph()
    n = g.node("kk")
    if not n:
        n = CNode("kk")
    
    g.addNode(n)

def testAll():
    test1()
    test2()
    test3()
    """randomGraph()
    randomGraph2()
    testRandomGraph()"""
    testIsSubgraph()
    testNode()
    """testRandomSubgraph()
    testOperations()"""
    print "Done!"

if __name__ == "__main__":
    testAll()
    pass
    
