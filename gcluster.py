#!/usr/bin/env python

"""
A program's clusterization tool based on Pyew

Copyright (C) 2010, Joxean Koret

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

import os, sys

from hashlib import sha256
from pyew_core import CPyew

def primes(n): 
    if n==2: return [2]
    elif n<2: return []
    s=range(3,n+1,2)
    mroot = n ** 0.5
    half=(n+1)/2-1
    i=0
    m=3
    while m <= mroot:
        if s[i]:
            j=(m*m-3)/2
            s[j]=0
            while j<half:
                s[j]=0
                j+=m
        i=i+1
        m=2*i+3
    return [2]+[x for x in s if x]

class CAdjacencyList(object):
    def __init__(self, data):
        self.data = data
        self.adjacency_lists = {}

    def createAdjacencyList(self, pyew):
        al = []
        ep = pyew.ep
        try:
            l = pyew.exports.keys()
            l.append(pyew.ep)
        except:
            print "Error:", sys.exc_info()[1]
            l = [pyew.ep]
        functions = []
        
        for ep in l:
            if pyew.functions.has_key(ep):
                fep = pyew.functions[ep]
                for c in fep.connections:
                    if c in pyew.functions:
                        if c not in functions:
                            functions.append(c)
                        
                        al.append((pyew.function_stats[ep], pyew.function_stats[c]))
        
        dones = []
        while len(functions) > 0:
            addr = functions.pop()
            f = pyew.functions[addr]
            for c in f.connections:
                if c in pyew.functions and c not in dones:
                    functions.append(c)
                    dones.append(c)
                    
                    al.append((pyew.function_stats[addr], pyew.function_stats[c]))
        
        return al

    def getSimilarity(self, s1, s2):
        m = max(len(s1), len(s2))
        
        diff1 = len(s1.difference(s2))
        diff2 = len(s2.difference(s1))
        diff = (diff1 + diff2)*100./m
        
        simil1 = len(s1.intersection(s2))
        simil = simil1*100. / m
        
        metric = simil + diff
        diff = diff * 100. / metric
        
        return diff

    def compareTwoSets(self, set1, set2):
        pyew1 = set1.values()[0]
        pyew2 = set2.values()[0]
        al1 = self.createAdjacencyList(pyew1)
        al2 = self.createAdjacencyList(pyew2)
        
        if al1 == al2:
            return 0
        else:
            s1 = set(al1)
            s2 = set(al2)
            diff = len(s1.difference(s2)) + len(s2.difference(s1))
            total = max(len(s1), len(s2))
            simil = diff * 100. / total
            
            return simil

    def cluster(self):
        if len(self.data) == 2:
            set1 = self.data[0]
            set2 = self.data[1]
            return self.compareTwoSets(set1, set2)

class CPrimesCluster(object):
    def __init__(self, data):
        self.primes = primes(1024*1024)
        self.data = data

    def generateHash(self, pyew):
        val = 1.
        dones = []
        primes_done = []
        for f in pyew.functions:
            nodes, edges, cc = pyew.function_stats[f]
            if cc > 1 and (nodes, edges, cc) not in dones:
                p = self.primes[cc]
                if p not in primes_done:
                    val *= p
                    primes_done.append(p)
                dones.append((nodes, edges, cc))
        
        return val, dones

    def compareManySets(self, sets):
        files = {}
        primes = {}
        values = {}
        print "File1;File2;Difference"
        for s in sets:
            pyew = s.values()[0]
            val, prime = self.generateHash(pyew)
            hash = sha256(pyew.getBuffer()).hexdigest()
            
            primes[hash] = prime
            values[hash] = val
            files[hash] = pyew.filename
            del pyew
        
        dones = []
        size = len(primes)
        for h1 in values:
            for h2 in values:
                if h1 == h2 or (h1, h2) in dones or (h2, h1) in dones:
                    continue
                
                if values[h1] == values[h2]:
                    print "%s;%s;0" % (files[h1], files[h2])
                    dones.append((h1, h2))
                    dones.append((h2, h1))
                else:
                    dones.append((h1, h2))
                    dones.append((h2, h1))
                    s1 = set(primes[h1])
                    s2 = set(primes[h2])
                    diff = self.getSimilarity(s1, s2)
                    
                    print "%s;%s;%f" % (files[h1], files[h2], diff)

    def getSimilarity(self, s1, s2):
        m = max(len(s1), len(s2))
        
        diff1 = len(s1.difference(s2))
        diff2 = len(s2.difference(s1))
        diff = (diff1 + diff2)*100./m
        
        simil1 = len(s1.intersection(s2))
        simil = simil1*100. / m
        
        metric = simil + diff
        diff = diff * 100. / metric
        
        return diff

    def compareTwoSets(self, set1, set2):
        pyew1 = set1.values()[0]
        val1, primes1 = self.generateHash(pyew1)
        pyew2 = set2.values()[0]
        val2, primes2 = self.generateHash(pyew2)
        s1 = set(primes1)
        s2 = set(primes2)
        
        if val1 == val2:
            return 0
        else:
            diff = self.getSimilarity(s1, s2)
            return diff

    def cluster(self):
        if len(self.data) == 2:
            set1 = self.data[0]
            set2 = self.data[1]
            return self.compareTwoSets(set1, set2)
        else:
            return self.compareManySets(self.data)

class CExpertCluster(object):
    def __init__(self, data):
        self.data = data

    def compareTwoSets(self, set1, set2):
        # Get the ciclomatic complexity statistical data of the 2 samples
        ccs1 = set1.values()[0].program_stats["ccs"]
        ccs2 = set2.values()[0].program_stats["ccs"]
        
        avg_cc_distance = abs(ccs1["avg"] - ccs2["avg"])
        max_cc_distance = abs(ccs1["max"] - ccs2["max"])
        min_cc_distance = abs(ccs1["min"] - ccs2["min"])
        total_functions = abs(len(set1.values()[0].functions) - len(set2.values()[0].functions))
        
        difference = avg_cc_distance*0.5 + \
                     max_cc_distance*0.3 + \
                     min_cc_distance*0.1 + \
                     total_functions*0.1
        return difference

    def cluster(self):
        set1 = self.data[0]
        set2 = self.data[1]
        return self.compareTwoSets(set1, set2)

class CGraphCluster(object):
    def __init__(self):
        self.clear()
        self.deep = True
        self.timeout = 0

    def addFile(self, filename):
        self.files.append(filename)

    def clear(self):
        self.files = []
        self.results = []
        self.data = []

    def processFile(self, filename):
        #print "[+] Analyzing file %s" % filename
        pyew = CPyew(batch=True)
        pyew.deepcodeanalysis = self.deep
        pyew.analysis_timeout = 0
        pyew.loadFile(filename)
        
        if pyew.format in ["PE", "ELF"]:
            hash = sha256(pyew.getBuffer()).hexdigest()
            self.data.append({hash:pyew})
        else:
            sys.stderr.writelines("Not a PE/ELF file")
            sys.stderr.flush()

    def comparePrimes(self):
        cluster = CPrimesCluster(self.data)
        val = cluster.cluster()
        
        if val == 0:
            print "Primes system: Programs are 100% equals"
        else:
            print "Primes system: Programs differs in", val, "% percent"

    def compareAdjacencyLists(self):
        cluster = CAdjacencyList(self.data)
        val = cluster.cluster()
        
        if val == 0:
            print "ALists system: Programs are 100% equals"
        else:
            print "ALists System: Programs differs in %f%%" % val

    def compareExpert(self):
        cluster = CExpertCluster(self.data)
        val = cluster.cluster()
        
        if val == 0:
            print "Expert system: Programs are 100% equals"
        else:
            print "Expert system: Programs differs in %f%s" % (round(val, 1), "%")
        
        return val

    def processFiles(self):
        for f in self.files:
            self.processFile(f)

def main(prog1, prog2):
    cluster = CGraphCluster()
    cluster.addFile(prog1)
    cluster.addFile(prog2)
    cluster.processFiles()
    cluster.compareExpert()
    cluster.comparePrimes()
    cluster.compareAdjacencyLists()

def compareDirectory(path):
    cluster = CGraphCluster()
    cprimes = CPrimesCluster([])
    alist = CAdjacencyList([])

    if os.path.isdir(path):
        for root, dirs, files in os.walk(path, topdown=False):
            for name in files:
                fname = os.path.join(root, name)
                cluster.addFile(fname)
    else:
        cluster.addFile(path)
    cluster.processFiles()

    print "hash:filename:primes_hash:nodes_total:nodes_max:nodes_avg:nodes_min:edges_total:edges_max:edges_avg:edges_min:ccs_total:ccs_max:ccs_avg:ccs_min:functions:adjacency_list"
    for x in cluster.data:
        hash = x.keys()[0]
        pyew = x.values()[0]
        data = ""
        for stat in pyew.program_stats:
            data = data + ":".join(map(str, pyew.program_stats[stat].values())).replace(".", ",") + ":"
        phash, dones = cprimes.generateHash(pyew)
        print "%s:%s:%s:%s%d:%s" % (hash, pyew.f.name, str(phash.as_integer_ratio()[0]), data, len(pyew.functions), str(alist.adjacency_lists(pyew)))

def usage():
    print "Usage:", sys.argv[0], "<prog 1> <prog 2> | <directory>"
    print
    print "When comparing 2 binaries the difference between them is printed out."
    print "When comparing a directory, a csv file with all the relevant data is printed out."
    print
    print "Examples:"
    print "%s /bin/ls /bin/cp" % sys.argv[0]
    print "%s /bin" % sys.argv[0]
    print

if __name__ == "__main__":
    if len(sys.argv) == 1:
        usage()
    elif len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])
    else:
        compareDirectory(sys.argv[1])

