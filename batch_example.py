#!/usr/bin/python

"""
This is an example batch script for Pyew. It uses many APIs exported by Pyew like
getBytes, getMnems, disasm, getBuffer or hexdump.
"""

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

def checkMebroot(path):
    pyew = CPyew(batch=True)
    pyew.codeanalysis = True
    
    try:
        pyew.loadFile(path)
    except:
        print "ERROR loading file %s" % path
        return 

    if pyew.format == "PE":
        # Get 6 bytes at offset 0xB8
        if pyew.getBytes(0xB8, 6) != "Rich;\x2E":
            return
        printData(pyew, path, "Mebroot downloader")
        print

def checkMnemonics(path):
    pyew = CPyew(batch=True)
    pyew.codeanalysis = True
    
    try:
        pyew.loadFile(path)
    except:
        print "ERROR loading file %s" % path
        return 

    # Is it a PE file?
    if pyew.format == "PE":
        # The most common x86 mnemonics
        commons = ["PUSH", "MOV", "SUB", "ADD", "LEA", "CALL", "JMP", "JZ", "JNZ", \
                   "OR", "XOR", "NOT", "POP", "AND", "TEST", "JL", "JG", "JE", \
                   "JLE", "CMP", "LEAVE", "RET", "NOP", "PUSHF", "POPF", "INC", \
                   "INT 3", "DEC", "PUSHA", "POPA"]
        
        try:
            # Get the 30 first mnemonics
            mnems = pyew.GetMnems(pyew.ep, 30)
        except:
            print "ERROR scanning file %s" % path
            return
        
        ret = []
        for x in mnems:
            if x not in commons and x not in ret:
                ret.append(x)
        
        if len(ret) > 0:
            printData(pyew, path, "Uncommon mnemonics")
            print "Mnemonics:", ",".join(ret)
            print
            # Seek to the entry point
            pyew.seek(pyew.ep)
            # Hexdump the first 64 bytes at the entry point
            print pyew.hexdump(pyew.buf, length=16, bsize=64)

def entryPointCalls(path):
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

    if pyew.format != "PE":
        return
    
    calls = []
    # Get the disassembl of the first 100 lines
    l = pyew.disasm(pyew.ep, processor=pyew.processor, type=pyew.type, lines=100, bsize=1600)
    for i in l:
        mnem = str(i.mnemonic)
        
        # Is it a direct or indirect jump or call?
        if mnem == "CALL" or mnem.startswith("J") or mnem.startswith("LOOP"):
            operands = str(i.operands).replace("[", "").replace("]", "")
            
            try:
                if pyew.imports.has_key(int(operands, 16)):
                    x = pyew.imports[int(operands, 16)]
                    
                    if x not in calls:
                        calls.append(x)
            except:
                pass

    if len(calls) > 0:
        printData(pyew, path, "Library calls at Entry Point")
        print "Library Calls:", ",".join(calls)
        print

def doChecks(path):
    # Example usage to check for the Mebroot downloader
    checkMebroot(path)
    # Example to extract the first (non common) mnemonics from the entry point
    checkMnemonics(path)
    # Example to print the API calls at the entry point
    entryPointCalls(path)

def main(path):
    for root, dirs, files in os.walk(path):
        for x in files:
            filepath = os.path.join(root, x)
            print "Analyzing file %s" % filepath
            t = time.time()
            doChecks(filepath)
            print "Time to analyze %f" % (time.time() - t)

def usage():
    print "Usage:", sys.argv[0], "<path>"

if __name__ == "__main__":
    if len(sys.argv) == 1:
        usage()
    else:
        main(sys.argv[1])
