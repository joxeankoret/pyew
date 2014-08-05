#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Pyew! A Python Tool for malware analysis

Copyright (C) 2009-2013 Joxean Koret

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
import urllib
import operator
import StringIO

from gzip import GzipFile
from datetime import datetime

from config import CODE_ANALYSIS, DEEP_CODE_ANALYSIS, CONFIG_ANALYSIS_TIMEOUT, \
                   ANALYSIS_FUNCTIONS_AT_END, PURE_PYTHON_DISASM, DISTORM_VERSION
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

try:
    from vtrace import vtrace
    hasDebug = True
except ImportError:
    hasDebug = False

from binascii import unhexlify

has_pydistorm = has_distorm = False

# we may want to switch to the pure python disasssembler, for some reason...
if not PURE_PYTHON_DISASM:

  if DISTORM_VERSION == 3:
    try:
      from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits
      has_distorm = True
    except:
      has_distorm = False
  else:
    try:
        from pydistorm import Decode, Decode16Bits, Decode32Bits, Decode64Bits
        has_pydistorm = True
    except ImportError:
        has_pydistorm = False
  
    if not has_pydistorm and not has_distorm:
        try:
            from distorm import Decode, Decode16Bits, Decode32Bits, Decode64Bits
            has_distorm = True
        except ImportError:
            has_distorm = False

else:
    has_distorm = False
    has_pydistorm = False

if not has_distorm and not has_pydistorm or PURE_PYTHON_DISASM:
    try:
        from pyms_iface import Decode, Decode16Bits, Decode32Bits, Decode64Bits
        has_pyms = True
    except ImportError:
        has_pyms = False
else:
    has_pyms = False

from config import PLUGINS_PATH
from anal.x86analyzer import CX86CodeAnalyzer

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
        self.maxfilesize=1024*1024*512
        # when reading files embedded in other files this will be the maximum
        # number of bytes read
        self.embedsize = 1024*1024*5
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
        self.queue = set()
        self.analyzed = []
        self.checking = []
        self.tocheck = []
        self.antidebug = []
        self.function_stats = {}
        self.basic_blocks = {}
        self.analysing = False
        self.analysis_timeout = CONFIG_ANALYSIS_TIMEOUT
        self.warnings = []
        
        if hasDebug:
            self.has_debug = True
            self.loadDebugger()
        else:
            self.has_debug = False
        
        self._anal = None
        
        self.batch = batch
        self.loadPlugins()

    def __del__(self):
        if self.f:
            self.f.close()
        
        if self.has_debug:
            self.dbg.release()

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
        return offset + obj[0].size

    def GetMnems(self, offset, num):
        obj = self.disasm(offset, self.processor, self.type, num)
        ret = []
        for x in obj:
            ret.append(str(x.mnemonic))
        
        return ret

    def getByte(self, offset):
        return self.getBytes(offset, 1)
    
    def getBytes(self, offset, num):
        try:
            self.f.seek(offset)
            buf = self.f.read(num)
            self.seek(self.offset)
            return buf
        except:
            return ""

    def getVirtualAddressFromOffset(self, offset):
        ret = None
        if self.format == "PE":
            try:
                ret = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.get_rva_from_offset(offset)
            except:
                pass
        elif self.format == "ELF":
            ret = offset
            for x in self.elf.secnames:
                if offset >= self.elf.secnames[x].sh_offset and offset < self.elf.secnames[x].sh_offset + self.elf.secnames[x].sh_size:
                    rel = offset - self.elf.secnames[x].sh_offset
                    ret = self.elf.secnames[x].sh_addr + rel
                    break
        return ret

    def isVirtualAddress(self, va):
        ret = False
        if self.format == "PE":
            try:
                self.pe.get_offset_from_rva(va-self.pe.OPTIONAL_HEADER.ImageBase)
                return True
            except:
                return False
        elif self.format == "ELF":
            for x in self.elf.secnames:
                if self.elf.secnames[x].sh_addr > 0 and va >= self.elf.secnames[x].sh_addr \
                   and va < self.elf.secnames[x].sh_addr + self.elf.secnames[x].sh_size:
                    ret = True
                    break
        
        return ret

    def getOffsetFromVirtualAddress(self, va):
        ret = None
        if self.format == "PE":
            try:
                ret = self.pe.get_offset_from_rva(va-self.pe.OPTIONAL_HEADER.ImageBase)
            except:
                print sys.exc_info()[1]
        elif self.format == "ELF":
            for x in self.elf.secnames:
                if va >= self.elf.secnames[x].sh_addr and va < self.elf.secnames[x].sh_addr + self.elf.secnames[x].sh_size:
                    tmp = va - self.elf.secnames[x].sh_addr
                    ret = self.elf.secnames[x].sh_offset + tmp
        return ret

    def executableMemory(self, va):
        ret = False
        if self.format == "PE":
            IMAGE_SCN_MEM_EXECUTE = 0x20000000
            for x in self.pe.sections:
                min_addr = self.pe.OPTIONAL_HEADER.ImageBase+x.VirtualAddress
                max_addr = self.pe.OPTIONAL_HEADER.ImageBase+x.SizeOfRawData
                if va >= min_addr and va <= max_addr:
                    if x.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0:
                        return True
        elif self.format == "ELF":
            for x in self.elf.secnames:
                if va >= self.elf.secnames[x].sh_addr and va < self.elf.secnames[x].sh_addr + self.elf.secnames[x].sh_size:
                    SHF_EXECINSTR = 0x4
                    ret = self.elf.secnames[x].sh_flags & SHF_EXECINSTR != 0
        return ret

    def showSettings(self):
        for x in dir(self):
            if x.startswith("_") or x.upper() in ["PE", "ELF", "BOOT", "BIOS", "BUF"] or operator.isCallable(eval("self." + x)) \
               or x in ["plugins", "names", "imports", "exports", "functions_address", \
                        "names", "functions", "xrefs_from", "xrefs_to", "antidebug", \
                        "function_stats", "basic_blocks", "flowgraphs", "callgraph"]:
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

    def loadBootSector(self):
        self.format = "BOOT"
        self.processor = "intel"
        old_deep_value = self.deepcodeanalysis
        self.deepcodeanalysis = True
        self.ep = 0
        self.type = 16  
        try:
            self.log("x86 Boot Sector")
            self.findFunctions("intel")
        finally:
            self.deepcodeanalysis = old_deep_value

    def loadBiosFile(self):
        self.format = "BIOS"
        self.processor = "intel"
        
        old_deep_value = self.deepcodeanalysis
        self.deepcodeanalysis = False
        self.ep = 0
        self.type = 16
        try:
            self.log("BIOS file")
            self.printBiosInformation()
            if self.codeanalysis:
                self.findFunctions("intel")
        finally:
            self.deepcodeanalysis = old_deep_value

    def printBiosInformation(self):
        bios_date = datetime.strptime(self.getBytes(0xfff5, 8), "%m/%d/%y")
        bios_id = self.getBytes(0xf478, 40)
        bios_name = self.getBytes(0xF400, 16)
        bios_banner = self.getBytes(0xF500, 64)
        self.log("%s %s %s" % (bios_name, bios_id, bios_date))
        self.log(bios_banner)
        self.log("")

    def seemsBios(self):
        try:
            datetime.strptime(self.getBytes(0xfff5, 8), "%m/%d/%y")
            return True
        except:
            return False

    def fileTypeLoad(self):
        try:
            if self.buf.startswith("MZ") and hasPefile:
                self.loadPE()
            elif self.buf.startswith("\x7fELF") and hasElf:
                self.loadElf()
            elif self.buf.startswith("\xB3\xF2\x0D\x0A"):
                self.loadPython()
            elif self.buf[:255].find("%PDF-") > -1:
                self.loadPDF()
            elif self.buf.startswith("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
                self.loadOle2()
            elif self.getBytes(0x1fe, 2) == "\x55\xAA": # bootsector:
                self.loadBootSector()
            elif self.seemsBios():
                self.loadBiosFile()
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

    def getAnalysisObject(self):
        if self._anal is not None:
            return self._anal

        try:
            self.analysing = True

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
            self._anal = anal
        finally:
            self.analysing = False

        return anal

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

    def getEndingBasicBlocks(self, func):
        bbs = []
        for bb in func.nodes():
            if func.hasParents(bb) and not func.hasChildren(bb):
                off = int(bb.name)
                if off not in self.basic_blocks:
                    # this is an error, fixme!
                    pass
                else:
                    bbs.append(self.basic_blocks[int(bb.name)])
            elif not func.hasParents(bb) and not func.hasChildren(bb):
                off = int(bb.name)
                if off not in self.basic_blocks:
                    # this is an error, fixme!
                    pass
                else:
                    bbs.append(self.basic_blocks[int(bb.name)])
        
        return bbs

    def getBasicBlockSize(self, bb):
        size = 0
        for ins in bb.instructions:
            size += ins.size
        return size

    def getFunctionEnd(self, f):
        func = self.flowgraphs[f]
        end_bbs = self.getEndingBasicBlocks(func)
        
        max_offset = f
        for bb in end_bbs:
            last_offset = bb.offset + self.getBasicBlockSize(bb)
            if last_offset > max_offset:
                max_offset = last_offset
        return max_offset

    def createIntelFunctionsAtEnd(self):
        anal = self.getAnalysisObject()
        dones = []
        while 1:
            f = None
            self.checkAnalysisTimeout()
            funcs = list(self.functions)
            for f in funcs:
                self.checkAnalysisTimeout()
                f_end = self.getFunctionEnd(f)
                buf1 = self.getBytes(f_end, 16)
                # strip the typical padding characters
                buf2 = buf1.lstrip("\xCC").lstrip("\x90")

                # ignore all the 0xCC/0x90 characters used for padding
                # and, also, do not analyse if the next byte starts
                # with a 0x00 because it's probably not an instruction
                if buf1 != buf2 and not buf2.startswith("\x00"):
                    off = f_end + len(buf1)-len(buf2)
                    if off not in self.functions and off not in dones:
                        f = off
                        anal.queue.add(f)
                    dones.append(off)

            if f is not None:
                anal.doCodeAnalysis(ep = False, addr = f)

            total = len(self.functions)
            if total == len(funcs):
                break

    def checkAnalysisTimeout(self):
        anal = self._anal
        if anal.timeout != 0 and time.time() > anal.start_time + anal.timeout:
            raise Exception("Code analysis for x86 timed-out")

    def createIntelFunctionsByPrologs(self):
        anal = self.getAnalysisObject()
        
        if self.type == 32:
            prologs = ["8bff558b", "5589e5", "558bec"]
        else:
            prologs = ["40554883ec", "554889e5"]
        hints = []
        for prolog in prologs:
            hints += self.dosearch(self.f, "x", prolog, cols=60, doprint=False, offset=0)
        self.log("\b"*80 + "Found %d possible function(s)" % len(hints) + " "*20 + "\b"*80)
        
        f = None
        if len(hints) > 0:
            for hint in hints:
                f = int(hint.keys()[0])
                anal.queue.add(f)
            anal.doCodeAnalysis(ep = False, addr = f)
        self.log("\n")

    def findIntelFunctions(self):
        anal = self.getAnalysisObject()
        anal.timeout = self.analysis_timeout
        anal.doCodeAnalysis()
        if self.deepcodeanalysis:
            self.log("\b"*80 + "Searching typical function's prologs..." + " "*20)
            self.createIntelFunctionsByPrologs()
            
            if ANALYSIS_FUNCTIONS_AT_END:
                self.log("\b"*80 + "Searching function's starting at the end of known functions..." + " "*20)
                self.createIntelFunctionsAtEnd()

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
            self.elf = Elf(self.f)
        else:
            sio = StringIO.StringIO(self.getBuffer())
            self.elf = Elf(sio)
        
        self.format = "ELF"
        self.log("ELF Information")
        self.log()
        
        self.virtual = True
        
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
                    self.names[x.name] = x.st_value
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

            if 'DIRECTORY_ENTRY_EXPORT' in dir(pe):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:                
                    try:
                        addr = self.pe.get_offset_from_rva(exp.address)
                    except:
                        addr = exp.address
                    
                    if exp.name and exp.name != "":
                        self.names[addr] = exp.name
                        self.exports[addr] = exp.name
                    else:
                        self.names[addr] = exp.ordinal
                        self.exports[addr] = "#" + str(exp.ordinal)
        except:
            pass
        
        if self.codeanalysis:
            if self.processor == "intel":
                self.findFunctions(self.processor)
                if (not imps or len(self.functions) <= 1) and self.deepcodeanalysis:
                    self.createIntelFunctionsByPrologs()
        self.seek(0)

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
            
            s = None
            for s in self.pe.sections:
                if x >= s.VirtualAddress and x <= s.VirtualAddress + s.SizeOfRawData:
                    break

            if s is not None:
              x = x - s.VirtualAddress
              x += s.PointerToRawData

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

    def loadDebugger(self):
        self.dbg = vtrace.getTrace()
        self.last_regs = {}

    def printIp(self, all=False):
        addr = None
        regs = self.dbg.getRegisters()
        
        last_regs = self.last_regs
        for reg in regs:
            if reg.lower().find("ip") > -1:
                addr = regs[reg]
            
            if reg.find("ctrl") == -1 and reg.find("mm") == -1 and \
               reg.find("st") == -1 and reg.find("test") == -1 and \
               reg.find("debug") == -1:
                if all or len(self.last_regs) == 0 or (self.last_regs.has_key(reg) and self.last_regs[reg] != regs[reg]):
                    print reg, "\t", "%16x" % regs[reg]
                last_regs[reg] = regs[reg]
        
        self.last_regs = last_regs
        print
        print self.disassemble(self.dbg.readMemory(addr, self.bsize), type=self.type, baseoffset=addr, lines=self.lines/2, marker=True)

    def debugHandler(self, command):
        cmds = command.split(" ")
        if len(cmds) == 0:
            return False
        
        ret = True
        if cmds[0] == "status":
            print self.dbg
        elif cmds[0].startswith("run"):
            if not self.dbg.isAttached():
                self.dbg.execute(self.filename)
            
            if cmds[0] == "runhere":
                va = self.getVirtualAddressFromOffset(self.offset)
                self.last_regs = {}
                self.dbg.run(va)
                ip = True
            elif len(cmds) == 1:
                self.last_regs = {}
                self.dbg.run()
                ip = False
            else:
                self.last_regs = {}
                addr = int(cmds[1], 16)
                self.dbg.run(addr)
                ip = True
            
            if ip:
                self.printIp()
        elif cmds[0] == "ps":
            filter = ""
            if len(cmds) > 1:
                filter = cmds[1]
            
            for x in self.dbg.ps():
                if x[1].find(filter) > -1:
                    print x[0], "\t", x[1]
        elif cmds[0] == "stepi":
            self.dbg.stepi()
            self.printIp()
        elif cmds[0] == "stepl":
            self.dbg.steploop()
            self.printIp()
        elif cmds[0] == "maps":
            maps = self.dbg.getMemoryMaps()
            if len(maps) > 0:
                biggest = 0
                for amap in maps:
                    if len(amap[3]) > biggest:
                        biggest = len(amap[3])
                
                print "Name".ljust(biggest), "Address".ljust(16), "Size"
                print
                for amap in maps:
                    print amap[3].ljust(biggest), ("0x%x" % amap[0]).ljust(16), str(amap[1])
        elif cmds[0] == "attach":
            if len(cmds) == 1:
                print "No pid to attach"
            else:
                pid = int(cmds[1])
                self.dbg.attach(pid)
                self.printIp()
        elif cmds[0] == "detach":
            self.dbg.detach()
        elif cmds[0] == "regs" or cmds[0] == "ir":
            self.last_regs = {}
            self.printIp(all)
        elif cmds[0] == "cont":
            self.dbg.run()
            if self.dbg.isAttached():
                self.printIp(all=True)
        elif cmds[0] == "bpt":
            if len(cmds) == 1:
                print self.dbg.getBreakpoints()
            else:
                addr = int(cmds[1], 16)
                self.dbg.addBreakByAddr(addr)
        elif cmds[0] == "pid":
            print self.dbg.pid
        else:
            ret = False
        
        return ret

    def debugHelp(self):
        print
        print "Debugger commands:"
        print
        print "ps [str]                          Show process list (optionally filtered by str)"
        print "attach                            Attach to a currently running program"
        print "detach                            Detach from the currently attached program"
        print "run [addr]                        Run the program (optionally up to addr)"
        print "runhere                           Run until the current position"
        print "stepi                             Step one instruction"
        print "stepl                             Step over one loop"
        print "cont                              Continue running the debugged program"
        print "bpt addr                          Add a breakpoint"
        print "regs                              Show registers"
        print "maps                              Print memory map"
        print "pid                               Print the pid of the process"
        print "status                            Print the status of the program"

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

    def vseek(self, pos):
        if self.virtual:
            pos = self.getOffsetFromVirtualAddress(pos)
        self.seek(pos)

    def hexdump(self, src=None, length=8, baseoffset=0, bsize=512):
        """ Show hexadecimal dump for the the given buffer """
        
        if not src:
            src = self.buf[:bsize]
        
        N=0
        result=[]
        while src:
            s,src = src[:length],src[length:]
            hexa = ' '.join(["%02X"%ord(x) for x in s])
            s = s.translate(FILTER)
            result.append("%04X   %-*s   %s" % (N+baseoffset, length*3, hexa, s))
            N+=length
            if N>=bsize:
                break
        return "\n".join(result)

    def belongToSection(self, x):
        if self.format == "PE":
            for s in self.pe.sections:
                if x >= s.VirtualAddress and x <= s.VirtualAddress + s.SizeOfRawData:
                    return s
            return None

    def getDisassembleObject(self, obj, idx=-1):
        #print obj, type(obj), repr("".join(obj[2]).split(" "))
        #raw_input("?")
        if type(obj) is tuple:
            ret = CDisObj()
            ret.offset = obj[0]
            ret.size = obj[1]
            ret.mnemonic = str("".join(obj[2]))
            
            mnems = ret.mnemonic.split(" ")
            ret.mnemonic = str(mnems[0])
            if mnems[0].startswith("REP") or mnems[0] == "LOCK":
              mnem_size = 2
              ret.mnemonic += " " + mnems[1]
            else:
              mnem_size = 1
            
            data = obj[2].split(" ")
            if len(data) > mnem_size:
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
            ret.mnemonic = str(obj.mnemonic)
            ret.operands = str(obj.operands)
            ret.instructionHex = obj.instructionHex
            return ret

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

            if has_pyms:
              offset = self.ep

            for i in Decode(offset, buf, decode):
                if self.analysing:
                    self.checkAnalysisTimeout()
                i = self.getDisassembleObject(i, ilines)
                ret.append(i)
                ilines += 1
                
                if ilines == lines:
                    break

            return ret

    def getDecoder(self, processor, type):
        if type == 32:
            decode = Decode32Bits
        elif type == 16:
            decode = Decode16Bits
        elif type == 64:
            decode = Decode64Bits
        else:
            raise EUnknownDisassemblyType()
        
        return decode

    def disassemble(self, buf, processor="intel", type=32, lines=40, bsize=512, baseoffset=0, marker=False):
        """ Disassemble a given buffer using Distorm """
        if processor == "intel":
            decode = self.getDecoder(processor, type)
            
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

                        hex_pos = ops.find("[0x")
                        if hex_pos > -1:
                          ops = ops[hex_pos+3:]
                        hex_pos = ops.find("]")

                        if hex_pos > -1:
                          ops = ops[:hex_pos]
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
                            if self.format == "PE":
                                base = self.pe.OPTIONAL_HEADER.ImageBase
                                strdata = self.pe.get_string_at_rva(tmp-base)
                                if strdata is not None and strdata != "":
                                    comment = "\t; %s" % repr(strdata)
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
                        ana = self.getAnalysisObject()
                        val, isimport, isbreak = ana.resolveAddress(ops)
                        if val is not None and str(val).isdigit():
                            addr = int(val)
                            if self.isVirtualAddress(addr):
                                offset = self.getOffsetFromVirtualAddress(addr)
                                if self.names.has_key(offset):
                                    func = self.names[offset]
                                    index += 1
                                    comment = "\t; %d %s" % (index, func)
                                    self.calls.append(offset)
                                elif not self.executableMemory(addr):
                                    data = self.getBytes(offset, 40)
                                    data = data[:data.find("\x00")]
                                    if len(data) == 40:
                                        data = data[:30] + "..."
                                    if data != "":
                                        comment = "\t; %s" % repr(data)
                
                if self.case == 'high':
                    ret += "0x%08x (%02x) %-22s %s%s" % (i.offset, i.size, i.instructionHex, str(i.mnemonic) + " " + str(ops), comment)
                # if pyew.case is 'low' or wrong 
                else:
                    ret += "0x%08x (%02x) %-22s %s%s" % (i.offset, i.size, i.instructionHex, str(i.mnemonic).lower() + " " + str(ops).lower(), comment)
                if str(i.mnemonic).lower().startswith("j") or \
                   str(i.mnemonic).lower().startswith("ret") or \
                   str(i.mnemonic).lower().find("loop") > -1:
                    pos += 1
                    ret += "\n0x%08x " % i.offset + "-"*70
                
                if pos == 1 and marker:
                    ret += "\t  <---------------------"
                ret += "\n"
                
                if pos >= lines:
                    break
            
            if i:
                self.lastasmoffset = i.offset + i.size
        elif processor == "python":
            self.seek(0)
            buf = self.f.read()
            self.log(dis.dis(buf))
            self.seek(self.offset)
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
        f.seek(0, 2)
        bigfile = False
        filesize = f.tell()
        if filesize > self.maxfilesize:
            bigfile = True
        
        f.seek(offset)
        if not bigfile:
            buf = f.read()
        
        moffset = 0
        hints = []
        
        if bigfile:
            if mtype in ["s", "u", "o"] and search == "":
                print "Sorry, this search type is not supported for big files"
                return []
            elif mtype == "r":
                print "BUG: Regular expression searchs aren't supported for big files, sorry"
                return []
        
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
                # For big files, search in chunks of 512 MBs
                if bigfile:
                    buf = f.read(self.maxfilesize)
                
                while 1:
                    self.calls = []
                    cmd_type = mtype[0]
                    while 1:
                        if cmd_type == "s":
                            pos = buf.find(search)
                        elif cmd_type == "i":
                            pos = buf.lower().find(search.lower())
                        elif cmd_type == "x":
                            search = search.strip(" ")
                            pos = buf.find(unhexlify(search))
                        elif cmd_type == "X":
                            search = search.strip(" ")
                            pos = buf.lower().find(unhexlify(search).lower())
                        elif cmd_type == "u":
                            pos = buf.find(to_unicode(search))
                        elif cmd_type == "U":
                            pos = buf.lower().find(to_unicode(search.lower()))
                        else:
                            self.log("Unknown search type!")
                            break
                        
                        if pos > -1:
                            if doprint:
                                hexa = False
                                if len(mtype) > 1:
                                    # Hexadecimal output?
                                    hexa = mtype[1] == "h"
                                
                                # For non hexadecimal representations,
                                # print an ASCII like representation.
                                if not hexa:
                                    s = buf[pos:pos+cols]
                                    s = s.translate(FILTER)
                                else:
                                    s = buf[pos:pos+cols]
                                    s = ''.join(["%02X"%ord(x) for x in buf[pos:pos+cols]])

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
                    
                    if not bigfile:
                        break
                    elif f.tell() == filesize:
                        break
            except KeyboardInterrupt:
                self.log("Aborted")
            except:
                self.log("Error:", sys.exc_info()[1])
                raise
            
        f.seek(oldpos)
        return hints

    def getBuffer(self):
        self.f.seek(0)
        buf = self.f.read()
        self.seek(self.offset)
        
        return buf

    def getFunction(self, arg):
        f = None
        if arg.startswith("0x"):
            f = int(arg, 16)
        elif arg.isdigit():
            f = int(arg)
        else:
            for addr in self.names:
                if self.names[addr] == arg:
                    f = addr
        
        return f

