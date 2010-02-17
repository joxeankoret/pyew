#!/usr/bin/python

import os
import sys
import time
import hashlib

from pyew_core import CPyew

def printData(pyew, path, msg):
    buf = pyew.getBuffer()
    
    print "File  :", path
    print "MD5   :", hashlib.md5(buf).hexdigest()
    print "SHA1  :", hashlib.sha1(buf).hexdigest()
    print "SHA256:", hashlib.sha256(buf).hexdigest() 
    print "Found :", msg

def checkAntidebug(path):
    t = time.time()

    pyew = CPyew(batch=True)
    pyew.codeanalysis = True
    try:
        pyew.loadFile(path)
    except KeyboardInterrupt:
        print "Abort"
        sys.exit(0)
    except:
        print "ERROR loading file %s" % path
        return

    if pyew.format not in ["PE", "ELF"]:
        return

    msg = pyew.antidebug

    if len(antidebug) > 0:
        print
        printData(pyew, path, msg)
        print "Time to analyze %f" % (time.time() - t)
        print

def doChecks(path):
    do_basic_graph_analysis(path)

def main(path):
    buf = ""
    for root, dirs, files in os.walk(path):
        for x in files:
            filepath = os.path.join(root, x)
            sys.stdout.write("\b"*len(buf) + " "*len(buf) + "\b"*len(buf))
            buf = "Analyzing file %s ..." % filepath
            sys.stdout.write(buf)
            sys.stdout.flush()
            doChecks(filepath)
    print

def usage():
    print "Usage:", sys.argv[0], "<path>"

if __name__ == "__main__":
    if len(sys.argv) == 1:
        usage()
    else:
        main(sys.argv[1])