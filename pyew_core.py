#!/usr/bin/python
# -*- coding: latin-1 -*-

"""
Pyew! A Python Tool like the populars radare and *iew

Copyright (C) 2009, Joxean Koret

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

import re
import os
import sys
import dis
import time
import pickle
import pprint
import urllib
import operator
import StringIO

from gzip import GzipFile

from config import CODE_ANALYSIS, DEEP_CODE_ANALYSIS, CONFIG_ANALYSIS_TIMEOUT
from hashlib import md5, sha1, sha224, sha256, sha384, sha512, new as hashlib_new
from safer_pickle import SafeUnpickler

try:
    import pefile
    hasPefile = True
except ImportError:
    hasPefile = False
    
try:
    from Elf import Elf
    hasElf = True
except ImportError:
    hasElf = False

from binascii import unhexlify, hexlify

try:
    from pydistorm import Decode, Decode16Bits, Decode32Bits, Decode64Bits
except:
    try:
        from distorm import Decode, Decode16Bits, Decode32Bits, Decode64Bits
    except:
        pass

from anal.x86analyzer import CX86CodeAnalyzer

from config import PLUGINS_PATH

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def to_unicode(buf):
    ret = ""
    for c in buf:
        ret += c + "\x00"
    return ret

class CDisObj:
    def __init__(self):
        self.offset = None
        self.size = None
        self.mnemonic = None
        self.instructionHex = None
        self.operands = None

class EUnknownDisassemblyType(Exception):
    pass

class CStrings:
    def __init__(self, buf=None):
        self.buf = buf

    def getStrings(self, buf=None, unicode=False):
        if buf:
            self.buf = buf
        
        scanner = re.compile('[\w| |{|}|\[|\]|,|\||\,|.|\-|_|?|/|\$|@|"|''|!|\\|&|\(|\)|\<|\>|\*|\+|\;|\:|\^|\=|\%|\#|\~|\`|\ñ|\ç|\€]{4,}',
                            re.MULTILINE | re.IGNORECASE)
        ret = scanner.findall(self.buf)
        return ret

class COffsetString:
    
    def __init__(self):
        self.buf = None
        self.minsize = 3
        self.offset = 4
    
    def searchForStringAt(self, i):
        initial = i
        ret = self.buf[i:i+1]
        
        while 1:
            i += self.offset
            tmp = self.buf[i:i+1]
            if tmp.isalpha():
                ret += tmp
            elif tmp == "\x00":
                if len(ret) > self.minsize:
                    return (ret, initial)
                else:
                    return None
            elif tmp == "":
                return None
            else:
                return None

    def findall(self):
        i = 0
        ret = []
        while 1:
            c = self.buf[i:i+1]
            
            if not c:
                break
            
            if c.isalpha():
                s = self.searchForStringAt(i)
                if s is not None:
                    ret.append(s)
                    i += len(s[0])*4
                else:
                    i += 1
            else:
                i += 1
        
        return ret

class CPyew:

    def __init__(self, plugins=True, batch=False):
        self.debug = False
        self.batch = False
        self.antidebug = []
        self.virtual = False
        self.codeanalysis = CODE_ANALYSIS
        self.deepcodeanalysis = DEEP_CODE_ANALYSIS
        self.offset = 0
        self.previousoffset = []
        self.lastasmoffset = 0
        self.minoffsetsize = 4
        self.deltaoffset = 4
        self.physical = False
        self.format = "raw"
        self.buf = None
        self.mode = None
        self.filename = None
        self.processor="intel"
        self.f = None
        self.type=32
        self.lines=40
        self.bsize=512
        self.hexcolumns=16
        self.maxfilesize=1024*1024*1024
        self.pe = None
        self.elf = None
        self.calls = []
        self.plugins = {}
        self.maxsize = None
        self.names = {}
        self.imports = {}
        self.exports = {}
        self.ep = 0
        self.case = 'high'
        
        self.database = None
        self.names = {}
        self.functions = {}
        self.functions_address = {}
        self.xrefs_to = {}
        self.xrefs_from = {}
        self.queue = []
        self.analyzed = []
        self.checking = []
        self.tocheck = []
        self.antidebug = []
        self.function_stats = {}
        self.basic_blocks = {}
        self.analysis_timeout = CONFIG_ANALYSIS_TIMEOUT
        self.warnings = []
        
        self.batch = batch
        self.loadPlugins()

    def __del__(self):
        if self.f:
            self.f.close()

    def log(self, msg=None, *args):
        if not self.batch:
            if msg and args:
                print msg, " ".join(map(str, args))
            elif msg:
                print msg
            else:
                print

    def NextHead(self, offset):
        obj = self.disasm(offset, self.processor, self.type, 1)
        return offset + obj.size

    def GetMnem(self, offset):
        return self.GetMnems(offset, num)

    def GetMnems(self, offset, num):
        obj = self.disasm(offset, self.processor, self.type, num)
        ret = []
        for x in obj:
            ret.append(str(x.mnemonic))
        
        return ret

    def getByte(self, offset):
        return self.getBytes(offset, 1)
    
    def getBytes(self, offset, num):
        moffset = self.offset
        self.f.seek(offset)
        buf = self.f.read(num)
        self.seek(moffset)
        return buf

    def getVirtualAddressFromOffset(self, offset):
        ret = None
        if self.format == "PE":
            try:
                ret = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.get_rva_from_offset(offset)
            except:
                pass
        elif self.format == "ELF":
            # XXX: FIXME!!!
            ret = offset
        
        return ret

    def getOffsetFromVirtualAddress(self, va):
        if self.format == "PE":
            try:
                ret = self.pe.get_offset_from_rva(va-self.pe.OPTIONAL_HEADER.ImageBase)
            except:
                print sys.exc_info()[1]
                return None
        
        return None

    def showSettings(self):
        for x in dir(self):
            if x.startswith("_") or x in ["pe", "elf", "buf"] or operator.isCallable(eval("self." + x)) \
               or x in ["plugins", "names", "imports", "exports", "functions_address", \
                        "names", "functions", "xrefs_from", "xrefs_to", "antidebug", \
                        "function_stats", "basic_blocks"]:
                continue
            else:
                self.log("pyew." + x.ljust(16) + ":", eval("self." + x))
        self.log()
        self.log("Pyew Plugins:")
        self.log()
        for x in self.plugins:
            self.log(x.ljust(8), self.plugins[x].__doc__)

    def loadFile(self, filename, mode="rb"):
        self.filename = filename
        self.mode = mode
        
        if self.filename.lower().startswith("http://") or \
           self.filename.lower().startswith("https://") or \
           self.filename.lower().startswith("ftp://"):
            self.physical = False
            tmp = urllib.urlopen(self.filename).read()
            self.f = StringIO.StringIO(tmp)
            self.maxsize = len(tmp)
        else:
            self.physical = True
            self.f = file(filename, mode)
            self.maxsize = os.path.getsize(filename)
        
        self.seek(0)
        self.fileTypeLoad()
        self.offset = 0

    def loadFromBuffer(self, buf, filename="<memory>"):
        f = StringIO.StringIO(buf)
        self.f = f
        self.physical = False
        self.filename = filename
        self.maxsize = len(buf)
        self.buf = buf[:self.bsize]
        self.fileTypeLoad()

    def saveDatabase(self, database):
        self.database = database
        try:
            old_pyew = self
            self.filename = old_pyew.f.name
            self.f = None
            self.plugins = {}
            pickle.dump(self, GzipFile(database, "wb"))
            self.f = old_pyew.f
            self.plugins = old_pyew.plugins
        except:
            print "Error loading database: %s" % str(sys.exc_info()[1])
            self = old_pyew

    @staticmethod
    def openDatabase(database, mode="rb"):
        p = SafeUnpickler(GzipFile(database, "rb"))
        new_pyew = p.load()
        new_pyew.f = open(new_pyew.filename, mode)
        return new_pyew

    def fileTypeLoad(self):
        try:
            if self.buf.startswith("MZ") and hasPefile:
                self.loadPE()
            elif self.buf.startswith("\x7FELF") and hasElf:
                self.loadElf()
            elif self.buf.startswith("\xB3\xF2\x0D\x0A"):
                self.loadPython()
            elif self.buf[:255].find("%PDF-") > -1:
                self.loadPDF()
            elif self.buf.startswith("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
                self.loadOle2()
        except:
            print "Error loading file:", sys.exc_info()[1]
            if self.debug or self.batch:
                raise

    def loadPDF(self):
        self.format = "PDF"
        if self.batch:
            return
        self.log("PDF File")
        self.log()
        self.plugins["pdf"](self)

    def loadOle2(self):
        self.format = "OLE2"
        if self.batch:
            return
        self.log("OLE2 File")
        self.log()
        self.plugins["ole2"](self)

    def loadPython(self):
        self.format = "PYC"
        if self.batch:
            return
        self.log("Python Compiled File")
        self.log()
        self.processor="python"

    def createIntelFunctionsByPrologs(self):
        total = 0
        
        anal=CX86CodeAnalyzer(self)
        anal.timeout = self.analysis_timeout
        anal.antidebug = self.antidebug
        anal.names.update(self.functions)
        anal.names.update(self.names)
        anal.functions = self.functions
        anal.functions_address = self.functions_address
        anal.xrefs_to = self.xrefs_to
        anal.xrefs_from = self.xrefs_from
        anal.basic_blocks = self.basic_blocks
        anal.function_stats = self.function_stats
        
        if self.type == 32:
            prologs = ["8bff558b", "5589e5"]
        else:
            prologs = ["40554883ec", "554889e5"]
        hints = []
        for prolog in prologs:
            hints += self.dosearch(self.f, "x", prolog, cols=60, doprint=False, offset=0)
        self.log("\b"*80 + "Found %d possible function(s) using method #1" % len(hints) + " "*20 + "\b"*80)
        for hint in hints:
            anal.doCodeAnalysis(ep = False, addr = int(hint.keys()[0]))
        
        prologs = ["558bec"]
        for prolog in prologs:
            hints += self.dosearch(self.f, "x", prolog, cols=60, doprint=False, offset=0)
        self.log("\b"*80 + "Found %d possible function(s) using method #2" % len(hints) + " "*20)
        for hint in hints:
            anal.doCodeAnalysis(ep = False, addr = int(hint.keys()[0]))
        self.log("\n")

    def resolveName(self, ops):
        orig = str(ops)
        ops = str(ops)
        if ops.startswith("["):
            ops = ops.replace("[", "").replace("]", "")
        
        try:
            ops = int(ops, 16)
        except ValueError:
            return orig
        
        if ops in self.names:
            return self.names[ops]
        else:
            return orig

    def findIntelFunctions(self):
        anal = CX86CodeAnalyzer(self, self.type)
        anal.timeout = self.analysis_timeout
        anal.doCodeAnalysis()
        
        if self.deepcodeanalysis:
            self.log("\b"*80 + "Searching typical function's prologs..." + " "*20)
            self.createIntelFunctionsByPrologs()

    def findFunctions(self, proc):
        if proc == "intel":
            t = time.time()
            self.log("Code Analysis ...")
            self.findIntelFunctions()
            if self.debug:
                self.log("")
                self.log("Total time %f second(s)" % (time.time()-t))

    def loadElf(self):
        if self.physical:
            self.elf = Elf(self.filename)
        else:
            self.elf = Elf(self.getBuffer())
        
        self.format = "ELF"
        self.log("ELF Information")
        self.log()
        
        if self.elf.e_machine == 62: # x86_64
            self.type = 64
            self.processor = "intel"
        elif self.elf.e_machine == 3: # x86
            self.type = 32
            self.processor = "intel"
        else:
            self.log("Warning! Unsupported architecture, defaulting to Intel x86 (32 bits)")
            self.type = 32
        
        for x in self.elf.secnames:
            if self.elf.e_entry >= self.elf.secnames[x].sh_addr and self.elf.e_entry < self.elf.secnames[x].sh_addr + self.elf.secnames[x].sh_size:
                self.ep = self.elf.secnames[x].sh_offset
            #self.log("\t", self.elf.secnames[x].name, "0x%08x" % self.elf.secnames[x].sh_addr, self.elf.secnames[x].sh_size)
        #self.log()
        
        self.log("Entry Point at 0x%x" % self.ep)
        if self.database is None:
            self.loadElfFunctions(self.elf)
        self.log()

    def loadElfFunctions(self, elf):
        try:
            for x in self.elf.relocs:
                self.names[x.r_offset] = x.name
                self.imports[x.r_offset] = x.name
            
            for x in self.elf.symbols:
                if x.name != "" and x.st_value != 0:
                    self.names[name] = x.st_value
        except:
            pass
        
        if self.codeanalysis:
            if self.processor == "intel":
                self.findFunctions(self.processor)

    def loadPeFunctions(self, pe):
        imps = False
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name
                    else:
                        name = "#" + str(imp.ordinal)
                    self.names[imp.address] = str(entry.dll) + "!" + str(name)
                    self.imports[imp.address] = str(entry.dll) + "!" + str(name)
            imps = True
        except:
            if not self.batch:
                print "***Error loading imports", sys.exc_info()[1]
            self.warnings.append("Error loading imports: %s" % sys.exc_info()[1])
            
        try:
            addr = None
            
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                
                try:
                    addr = self.pe.get_offset_from_rva(exp.address)
                except:
                    addr = exp.address
                
                if exp.name and exp.name != "":
                    self.names[addr] = exp.name
                    self.exports[addr] = exp.name
                else:
                    self.names[addr] = expordinal
                    self.exports[addr] = "#" + str(expordinal)
        except:
            pass
        
        if self.codeanalysis:
            if self.processor == "intel":
                self.findFunctions(self.processor)
                if not imps or len(self.functions) <= 1 and self.deepcodeanalysis:
                    self.createIntelFunctionsByPrologs()

    def loadPE(self):
        try:
            if self.physical:
                self.pe = pefile.PE(self.filename)
            else:
                self.f.seek(0)
                buf = self.f.read()
                self.pe = pefile.PE(data=buf)
                self.seek(0)
            
            self.format = "PE"
            self.log("PE Information")
            self.log()
            
            self.virtual = True
            
            if self.pe.FILE_HEADER.Machine == 0x14C: # IMAGE_FILE_MACHINE_I386
                self.processor="intel"
                self.type = 32
            elif self.pe.FILE_HEADER.Machine == 0x8664: # IMAGE_FILE_MACHINE_AMD64
                self.processor="intel"
                self.type = 64
                self.log("64 Bits binary")
            
            self.log("Sections:")
            for section in self.pe.sections:
                self.log("  ", section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)
            self.log()
            x = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            for s in self.pe.sections:
                if x >= s.VirtualAddress and x <= s.VirtualAddress + s.SizeOfRawData:
                    break
            
            x = x - s.VirtualAddress
            x += s.PointerToRawData
            ep = x
            self.log("Entry Point at 0x%x" % x)
            try:
                self.log("Virtual Address is 0x%0x" % (self.pe.OPTIONAL_HEADER.ImageBase + self.pe.get_rva_from_offset(x)))
                self.offset = x
                self.ep = x
            except:
                self.log(sys.exc_info()[1])
            
            if self.database is None:
                self.loadPeFunctions(self.pe)
            self.log()
        except:
            if self.batch:
                raise
            self.log("PEFILE:", sys.exc_info()[1])
            raise

    def loadPlugins(self):
        path = PLUGINS_PATH
        sys.path.append(path)
        
        for f in os.listdir(path):
            if f.startswith("_") or f.startswith(".") or not f.endswith(".py"):
                continue
            
            f = f.rstrip(".py")
            try:
                m = __import__(f)
                
                if not "functions" in dir(m):
                    continue
                
                if self.plugins == {}:
                    self.plugins = m.functions
                else:
                    self.plugins.update(m.functions)
            except:
                if self.debug:
                    raise

    def seek(self, pos):
        if pos > self.maxsize:
            self.log("End of file reached")
            self.offset = self.maxsize
        elif pos < 0:
            self.log("Begin of file reached")
            self.offset = 0
        else:
            self.offset = pos
        self.f.seek(self.offset)
        self.buf = self.f.read(self.bsize)

    def hexdump(self, src=None, length=8, baseoffset=0, bsize=512):
        """ Show hexadecimal dump for the the given buffer """
        
        if not src:
            src = self.buf[:bsize]
        
        N=0; result=''
        while src:
            s,src = src[:length],src[length:]
            hexa = ' '.join(["%02X"%ord(x) for x in s])
            s = s.translate(FILTER)
            result += "%04X   %-*s   %s\n" % (N+baseoffset, length*3, hexa, s)
            N+=length
            if N>=bsize:
                break
        return result

    def belongToSection(self, x):
        if self.format == "PE":
            for s in self.pe.sections:
                if x >= s.VirtualAddress and x <= s.VirtualAddress + s.SizeOfRawData:
                    return s
            return None

    def getDisassembleObject(self, obj, idx=0):
        if type(obj) is tuple:
            ret = CDisObj()
            ret.offset = obj[0]
            ret.size = obj[1]
            ret.mnemonic = "".join(obj[2])
            ret.mnemonic = ret.mnemonic.split(" ")[0]
            
            data = obj[2].split(" ")
            if len(data) > 1:
                operands = ""
                for x in data[1:]:
                    operands += x + " "
            else:
                operands = ""
            
            ret.operands = operands
            ret.instructionHex = obj[3]
            return ret
        else:
            ret = CDisObj()
            ret.offset = obj.offset
            ret.size = obj.size
            ret.mnemonic = obj.mnemonic
            ret.operands = obj.operands
            ret.instructionHex = obj.instructionHex
            return ret
            #return obj
    
    def disasm(self, offset=0, processor="intel", mtype=32, lines=1, bsize=512):
        if processor == "intel":
            if mtype == 32:
                decode = Decode32Bits
            elif mtype == 16:
                decode = Decode16Bits
            elif mtype == 64:
                decode = Decode64Bits
            else:
                raise EUnknownDisassemblyType()
            
            ret = []
            self.calls = []
            i = None
            ilines = 0
            try:
                buf = self.getBytes(offset, bsize)
            except OverflowError:
                # OverflowError: long int too large to convert to int
                return []
            
            for i in Decode(offset, buf, decode):
                i = self.getDisassembleObject(i, ilines)
                ret.append(i)
                
                ilines += 1
                
                if ilines == lines:
                    break
                
            return ret

    def disassemble(self, buf, processor="intel", type=32, lines=40, bsize=512, baseoffset=0):
        """ Disassemble a given buffer using Distorm """
        if processor == "intel":
            if type == 32:
                decode = Decode32Bits
            elif type == 16:
                decode = Decode16Bits
            elif type == 64:
                decode = Decode64Bits
            else:
                raise EUnknownDisassemblyType()
            
            pos = 0
            ret = ""
            index = 0
            self.calls = []
            offset = 0
            i = None
            
            for i in Decode(baseoffset, buf, decode):
                i = self.getDisassembleObject(i)
                pos += 1
                ops = str(i.operands)
                comment = ""
                func = ""
                
                if str(i.mnemonic).lower().startswith("call") or \
                   str(i.mnemonic).lower().startswith("j") or \
                   str(i.mnemonic).lower().startswith("loop"):
                    try:
                        if str(i.operands).startswith("["):
                            ops = str(i.operands).replace("[", "").replace("]", "")
                        else:
                            ops = str(i.operands)
                        
                        ops = int(ops, 16)
                        
                        if self.names.has_key(ops):
                            func = self.names[ops]
                        
                        if self.maxsize >= ops and ops > 0:
                            index += 1
                            comment = "\t; %d %s" % (index, func)
                            self.calls.append(ops)
                            ops = "0x%08x" % ops
                        else:
                            #comment = "\t; %s" % func
                            if func != "":
                                ops = func
                            else:
                                ops = "0x%08x" % ops
                            
                            comment = ""
                    except:
                        ops = str(i.operands)
                elif str(i.operands).find("[") > -1:
                    tmp = re.findall("\[(0x[0-9A-F]+)\]", str(i.operands), re.IGNORECASE)
                    if len(tmp) > 0:
                        tmp = int(tmp[0], 16)
                        if self.names.has_key(tmp):
                            
                            if self.imports.has_key(tmp):
                                comment = "\t; %s" % self.names[tmp]
                            else:
                                index += 1
                                comment = "\t; %d %s" % (index, self.names[tmp])
                else:
                    if self.names.has_key(i.offset):
                        mxrefs = []
                        if self.xrefs_to.has_key(i.offset):
                            tmpidx = 0
                            for tmp in self.xrefs_to[i.offset]:
                                tmpidx += 1
                                if self.names.has_key(tmp):
                                    mxrefs.append(self.names[tmp])
                                else:
                                    mxrefs.append("sub_%08x" % tmp)
                                
                                if tmpidx == 3:
                                    mxrefs.append("...")
                                    break
                        
                        pos += 1
                        if len(mxrefs) > 0:
                            ret += "0x%08x ; FUNCTION %s\t XREFS %s\n" % (i.offset, self.names[i.offset], ", ".join(mxrefs))
                        else:
                            ret += "0x%08x ; FUNCTION %s\n" % (i.offset, self.names[i.offset])
                        #comment = "\t; Function %s" % self.names[i.offset]
                    else:
                        comment = ""

                if self.case == 'high':
                    ret += "0x%08x (%02x) %-20s %s%s\n" % (i.offset, i.size, i.instructionHex, str(i.mnemonic) + " " + str(ops), comment)
                # if pyew.case is 'low' or wrong 
                else:
                    ret += "0x%08x (%02x) %-20s %s%s\n" % (i.offset, i.size, i.instructionHex, str(i.mnemonic).lower() + " " + str(ops).lower(), comment)
                if str(i.mnemonic).lower().startswith("j") or \
                   str(i.mnemonic).lower() == "ret" or \
                   str(i.mnemonic).lower().find("loop") > -1:
                    pos += 1
                    ret += "0x%08x " % i.offset + "-"*70 + "\n"
                
                if pos >= lines:
                    break
            
            if i:
                self.lastasmoffset = i.offset + i.size
        elif processor == "python":
            moffset = self.offset
            self.seek(0)
            buf = self.f.read()
            self.log(dis.dis(buf))
            self.seek(moffset)
            ret = ""
        
        return ret

    def strings(self, buf, doprint=True, offset=0):
        strs = CStrings(buf)
        ret = strs.getStrings()
        
        hints = []
        
        for x in ret:
            pos = buf.find(x)
            hints.append({pos+offset:x})
            if doprint:
                self.log("HINT[0x%08x]: %s" % (pos, x))
        
        return hints

    def extract(self, buf, strre, doprint=True, offset=0):
        obj = re.compile(strre, re.IGNORECASE | re.MULTILINE)
        ret = obj.findall(buf)
        
        hints = []
        
        for x in ret:
            pos = buf.find(x)
            hints.append({pos+offset:x})
            if doprint:
                self.log("HINT[0x%08x]: %s" % (pos, x))
        
        return hints

    def extractoffsetstring(self, buf, doprint=True, offset=0):
        strs = COffsetString()
        strs.minsize = self.minoffsetsize
        strs.offset = self.deltaoffset
        strs.buf = buf
        l = strs.findall()
        if doprint:
            for x in l:
                pos = x[1]+offset
                val = x[0]
                self.log("HINT[0x%08x]: %s" % (pos, val))
        return l

    def dosearch(self, f, mtype, search, cols=32, doprint=True, offset=0):
        if (search == None or search == "") and mtype not in ["s", "o"]:
            return []
        
        oldpos = f.tell()
        f.seek(offset)
        buf = f.read()
        moffset = 0
        hints = []
        
        if mtype == "s" and search=="":
            hints = self.strings(buf, doprint, offset=offset)
        elif mtype == "u" and search == "":
            hints = self.strings(buf, doprint, offset=offset)
        elif mtype == "r":
            hints = self.extract(buf, strre=search, doprint=doprint, offset=offset)
        elif mtype == "o":
            hints = self.extractoffsetstring(buf, doprint=doprint, offset=offset)
        
        else:
            try:
                self.calls = []
                while 1:
                    if mtype == "s":
                        pos = buf.find(search)
                    elif mtype == "i":
                        pos = buf.lower().find(search.lower())
                    elif mtype == "x":
                        pos = buf.find(unhexlify(search))
                    elif mtype == "X":
                        pos = buf.lower().find(unhexlify(search).lower())
                    elif mtype == "u":
                        pos = buf.find(to_unicode(search))
                    elif mtype == "U":
                        pos = buf.lower().find(to_unicode(search.lower()))
                    else:
                        self.log("Unknown search type!")
                        break
                    
                    if pos > -1:
                        if doprint:
                            s = buf[pos:pos+cols]
                            s = s.translate(FILTER)
                            tmp = moffset+pos+offset
                            self.calls.append(tmp)
                            self.log("HINT[0x%08x]: %s" % (tmp, s))
                        hints.append({moffset+pos+offset:buf[pos:pos+cols]})
                        moffset += pos + len(search)
                        buf = buf[pos+len(search):]
                        
                        if buf == "":
                            break
                    else:
                        break
            except KeyboardInterrupt:
                self.log("Aborted")
            except:
                self.log("Error:", sys.exc_info()[1])
                raise
            
        f.seek(oldpos)
        return hints

    def getBuffer(self):
        moffset = self.offset
        self.f.seek(0)
        buf = self.f.read()
        self.seek(moffset)
        
        return buf
