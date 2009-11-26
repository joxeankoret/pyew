#!/usr/bin/python
# -*- coding: latin-1 -*-

"""
Pyew! A Python Tool like the populars *iew

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
import pprint
import urllib
import operator
import StringIO

from hashlib import md5, sha1, sha224, sha256, sha384, sha512, new as hashlib_new

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

try:
    from jdisasm import ParseClass
    hasJdisasm = True
except:
    hasJdisasm = False

from config import PLUGINS_PATH

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def to_unicode(buf):
    ret = ""
    for c in buf:
        ret += c + "\x00"
    return ret

class CDisObj:
    offset = None
    size = None
    mnemonic = None
    instructionHex = None
    operands = None

class EUnknownDisassemblyType(Exception):
    pass

class CStrings:
    buf = None

    def __init__(self, buf=None):
        self.buf = buf

    def getStrings(self, buf=None, unicode=False):
        if buf:
            self.buf = buf
        
        scanner = re.compile('[\w| |{|}|\[|\]|,|\||\,|.|\-|_|?|/|\$|@|"|''|!|\\|&|\(|\)|\<|\>|\*|\+|\;|\:|\^|\=|\%|\#|\~|\`|\ñ|\ç|\€]{4,}',
                            re.MULTILINE | re.IGNORECASE)
        ret = scanner.findall(self.buf)
        return ret

class CPyew:
    debug = False
    batch = False
    antidebug = []
    virtual = False
    codeanalysis = True
    offset = 0
    previousoffset = []
    lastasmoffset = 0
    physical = False
    format = "raw"
    buf = None
    mode = None
    filename = None
    processor="intel"
    f = None
    type=32
    lines=40
    bsize=512
    hexcolumns=16
    maxfilesize=1024*1024*1024
    pe = None
    elf = None
    calls = []
    plugins = {}
    maxsize = None
    names = {}
    imports = {}
    exports = {}
    ep = 0

    def __init__(self, plugins=True, batch=False):
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
                ret = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.get_rva_from_offset(self.offset)
            except:
                pass
        
        return ret

    def getOffsetFromVirtualAddress(self, va):
        if self.format == "PE":
            try:
                ret = self.pe.get_offset_from_rva(self.offset)
            except:
                print sys.exc_info()[1]
                return None
        
        return None

    def showSettings(self):
        for x in dir(self):
            if x.startswith("_") or x in ["pe", "elf", "buf"] or operator.isCallable(eval("self." + x)) \
               or x in ["plugins", "names", "imports", "exports", "functions_address", \
                        "names", "functions", "xrefs_from", "xrefs_to", "antidebug"]:
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
        
        if self.filename.lower().startswith("http://") or self.filename.lower().startswith("ftp://"):
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

    def fileTypeLoad(self):
        if self.buf.startswith("MZ") and hasPefile:
            self.loadPE()
        elif self.buf.startswith("\x7FELF") and hasElf:
            self.loadElf()
        elif self.buf.startswith("\xB3\xF2\x0D\x0A"):
            self.loadPython()
        elif self.buf.startswith("\xCA\xFE\xBA\xBE"):
            self.loadJava()
        elif self.buf.startswith("%PDF-"):
            self.loadPDF()
        elif self.buf.startswith("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
            self.loadOle2()

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
    
    def loadJava(self):
        self.format = "JAVA"
        if self.batch:
            return
        self.log("JAVA Class")
        self.log()
        self.processor="java"

    def createIntelFunctionsByPrologs(self):
        total = 0
        
        if self.type == 32:
            prologs = ["8bff558b", "5589e5"]
        else:
            prologs = ["40554883ec"]
        
        for prolog in prologs:
            hints = self.dosearch(self.f, "x", prolog, cols=60, doprint=False, offset=0)
        
        for hint in hints:
            if not self.names.has_key(hint.keys()[0]):
                total += 1
                self.names[hint.keys()[0]] = "sub_%08x" % hint.keys()[0]
        
        if total == 0:
            prologs = ["558bec"]
            for prolog in prologs:
                hints = self.dosearch(self.f, "x", prolog, cols=60, doprint=False, offset=0)
            
            for hint in hints:
                if not self.names.has_key(hint.keys()[0]):
                    total += 1
                    self.names[hint.keys()[0]] = "sub_%08x" % hint.keys()[0]

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
        from anal.x86analyzer import CX86CodeAnalyzer
        
        anal = CX86CodeAnalyzer(self, self.type)
        anal.doCodeAnalysis()
        #self.createIntelFunctionsByPrologs()

    def findFunctions(self, proc):
        if proc == "intel":
            t = time.time()
            self.log("Code Analysis ...")
            self.findIntelFunctions()
            if self.debug:
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
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    self.names[imp.address] = entry.dll + "!" + imp.name
                    #self.names[imp.address] = imp.name
                    self.imports[imp.address] = entry.dll + "!" + imp.name
        except:
            pass
            
        try:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name and exp.name != "":
                    self.names[exp.address] = exp.name
                    self.exports[exp.address] = exp.name
                else:
                    self.names[exp.address] = expordinal
                    self.exports[exp.address] = "#" + str(expordinal)
        except:
            pass
        
        if self.codeanalysis:
            if self.processor == "intel":
                self.findFunctions(self.processor)

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
            self.log("Virtual Address is 0x%0x" % (self.pe.OPTIONAL_HEADER.ImageBase + self.pe.get_rva_from_offset(x)))
            self.offset = x
            self.ep = x
            
            self.loadPeFunctions(self.pe)
            self.log()
        except:
            self.log("PEFILE:", sys.exc_info()[1])
            raise

    def loadPlugins(self):
        path = PLUGINS_PATH
        sys.path.append(path)
        
        for f in os.listdir(path):
            if f.startswith("_") or f.endswith("pyc"):
                continue
            
            f = f.rstrip(".py")
            m = __import__(f)
            
            if not "functions" in dir(m):
                continue
            
            if self.plugins == {}:
                self.plugins = m.functions
            else:
                self.plugins.update(m.functions)

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

    def getDisassembleObject(self, obj):
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
            return obj
    
    def disasm(self, offset=0, processor="intel", type=32, lines=1, bsize=512):
        if processor == "intel":
            if type == 32:
                decode = Decode32Bits
            elif type == 16:
                decode = Decode16Bits
            elif type == 64:
                decode = Decode64Bits
            else:
                raise EUnknownDisassemblyType()
            
            ret = []
            self.calls = []
            i = None
            ilines = 0
            buf = self.getBytes(offset, bsize)
            
            for i in Decode(offset, buf, decode):
                i = self.getDisassembleObject(i)
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
                
                if str(i.mnemonic).lower() in ["call"] or str(i.mnemonic).lower().startswith("j"):
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
                else:
                    if self.names.has_key(i.offset):
                        comment = "\t; Function %s" % self.names[i.offset]
                    else:
                        comment = ""
                
                ret += "0x%08x (%02x) %-20s %s%s\n" % (i.offset, i.size, i.instructionHex, str(i.mnemonic) + " " + str(ops), comment)
                if pos == lines:
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
        elif processor == "java":
            moffset = self.offset
            self.seek(0)
            buf = self.f.read(0)
            ParseClass(self.filename)
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

    def dosearch(self, f, mtype, search, cols=32, doprint=True, offset=0):
        if (search == None or search == "") and mtype not in ["s"]:
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
                #raise
            
        f.seek(oldpos)
        return hints

    def getBuffer(self):
        moffset = self.offset
        self.f.seek(0)
        buf = self.f.read()
        self.seek(moffset)
        
        return buf
