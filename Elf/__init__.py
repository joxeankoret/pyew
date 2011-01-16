"""
Kenshoto's Elf parser

This package will let you use programatic ninja-fu
when trying to parse Elf binaries.  The API is based
around several objects representing constructs in the
Elf binary format.  The Elf object itself contains
parsed metadata and lists of things like section headers
and relocation entries.  Additionally, most of the
objects implement repr() in some form or another which
allows you a bunch of readelf-like functionality.

*Eventually* this API will allow you to modify Elf binaries
and spit them back out in working order (not complete, you
may notice some of the initial code).

Send bug reports to Invisigoth or Metr0.

"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import os
import sys
import struct
import traceback
import zlib

from stat import *
from Elf.elf_lookup import *

verbose = False

class Elf:

    """
    An Elf object representation which allows manipulation
    and parsing of Elf executables.  Brought to you by
    kenshoto.
    """

    def __init__(self, initstr):
        """
        Constructacon: initstr can be a filename, or a big hunka Elf lovin
        (If you only give it 52 bytes, it'll just parse the header, if you give it
        more, it *will* assume it has the whole thing...
        """
        self.sections = []
        self.pheaders = []
        self.secnames = {}
        self.symbols = []
        self.symbols_by_name = {}
        self.symbols_by_addr = {}
        self.e_ident = "NOTHINGHEREATALL"
        self.e_type = 0
        self.e_machine = 0
        self.e_version = 0
        self.e_entry = 0
        self.e_phoff = 0
        self.e_shoff = 0
        self.e_flags = 0
        self.e_ehsize = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shstrndx = 0

        self.fmt = "2HI3LI6H"
        self.hdrlen = struct.calcsize(self.fmt) + 16

        self.myname = "unknown"

        bytes = initstr
        pbase = self.hdrlen
        sbase = self.hdrlen

        if len(initstr) > 0:
            if not '\000' in initstr and os.path.exists(initstr):
                bytes = file(initstr, "rb").read()
                self.myname = initstr

            self.initFromBytes(bytes)

            # If we only got the 52 bytes, we have
            # no symbols to parse etc...
            if len(bytes) == self.hdrlen:
                return

        if self.e_shoff < self.e_phoff:
            raise Exception("ERROR: we only support <elf hdr><pgrm hdrs><data><sec hdrs> format now")

        # Load up any program headers we find
        if self.e_phoff:
            pbase = self.e_phoff
            plen = self.e_phentsize
            for i in range(self.e_phnum):
                if self.bits == 32:
                    pgm = Elf32Pheader(bytes[pbase:pbase+plen],elf=self)
                else:
                    pgm = Elf64Pheader(bytes[pbase:pbase+plen],elf=self)
                self.pheaders.append(pgm)
                pbase += plen

        # Load up all the section headers
        if self.e_shoff:
            # Load up the sections
            sbase = self.e_shoff
            # FIXME this assumes static sized section headers
            slen = self.e_shentsize
            for i in range(self.e_shnum):
                if self.bits == 32:
                    sec = Elf32Section(bytes[sbase:sbase+slen],elf=self)
                else:
                    sec = Elf64Section(bytes[sbase:sbase+slen],elf=self)
                self.sections.append(sec)
                sbase += slen

            # Populate the section names
            strsec = self.sections[self.e_shstrndx]
            names = bytes[strsec.sh_offset:strsec.sh_offset+strsec.sh_size]
            for sec in self.sections:
                name = names[sec.sh_name:].split("\x00")[0]
                if len(name) > 0:
                    sec.setName(name)
                    self.secnames[name] = sec

        self.parseSymbols()
        self.parseDynamic()
        self.parseRelocs()

    def getName(self):
        return self.myname

    def __str__(self):
        """  Calls toString() to obtain a string summary of this ELF.  Since no additional parameters make sense, default verbosity for the module is used
        """
        return self.toString(verbose)

    def toString(self, verbose=False):
        """  Returns a string summary of this ELF.  If (verbose) the summary will include Symbols, Relocs, Dynamics and Dynamic Symbol tables"""
        mystr = "ELF HEADER OBJECT:" + self.myname

        mystr+= "\n= Intimate Details:"
        mystr+= "\n==Magic:\t\t\t\t"       + self.e_ident
        mystr+= "\n==Type:\t\t\t\t\t"        + e_types.get(self.e_type)
        mystr+= "\n==Machine Arch:\t\t\t\t"  + e_machine_types.get(self.e_machine)
        mystr+= "\n==Version:\t\t\t\t%d"     % (self.e_version)
        mystr+= "\n==Entry:\t\t\t\t0x%.8x"      % (self.e_entry)
        mystr+= "\n==Program Headers(offset):\t\t%d (0x%x) bytes" % (self.e_phoff, self.e_phoff)
        mystr+= "\n==Section Headers(offset):\t\t%d (0x%x) bytes" % (self.e_shoff, self.e_shoff)
        mystr+= "\n==Flags:\t\t\t\t" + repr(self.e_flags) + " "
        mystr+= "\n==Elf Header Size:\t\t\t" + repr(self.e_ehsize) + " (" + hex(self.e_ehsize) + " bytes)"
        mystr+= "\n==Program Header Size:\t\t\t" + repr(self.e_phentsize) + " (" + hex(self.e_phentsize) + " bytes)"
        mystr+= "\n==Program Header Count:\t\t\t" + repr(self.e_phnum) + " (" + hex(self.e_phnum)+ ")"
        mystr+= "\n==Section Header Size:\t\t\t" + repr(self.e_shentsize) + " (" + hex(self.e_shentsize) + " bytes)"
        mystr+= "\n==Section Header Count:\t\t\t" + repr(self.e_shnum) + " (" + hex(self.e_shnum) + ")"
        mystr+= "\n==Section Header String Index\t\t" + repr(self.e_shstrndx) + " (" + hex(self.e_shstrndx) + " bytes)"

        mystr+= "\n\n= Sections:"
        for sec in self.sections:
            mystr+= "\n"+repr(sec)

        mystr+= "\n\n= Program Headers:"
        for ph in self.pheaders:
            mystr+= "\n"+repr(ph)

        if (verbose):

            mystr+= "\n\n= Symbols table:"
            for sym in self.symbols:
                mystr+= "\n"+repr(sym)

            mystr+= "\n\n= Relocation table:"
            for reloc in self.relocs:
                mystr+= "\n"+repr(reloc)

            mystr+= "\n\n= Dynamics table:"
            for dyn in self.dynamics:
                mystr+= "\n"+repr(dyn)

            mystr+= "\n\n= Dynamic Symbols table:"
            for dyn in self.dynamic_symbols:
                mystr+= "\n"+repr(dyn)

        return mystr
 

    def getStrtabString(self, offset, section=".strtab"):
        bytes = self.getSection(section).getBytes()
        index = bytes.find("\x00", offset)
        return bytes[offset:index]

    def initFromBytes(self, bytes):

        if len(bytes) < self.hdrlen:
            raise Exception("Elf format error: Not even a full Elf header (%d bytes)", self.hdrlen)

        if bytes[:4] <> "\x7fELF":
            raise Exception("Elf format error: Elf magic not found")

        self.e_ident = bytes[:16]

        (self.e_type,
        self.e_machine,
        self.e_version,
        self.e_entry,
        self.e_phoff,
        self.e_shoff,
        self.e_flags,
        self.e_ehsize,
        self.e_phentsize,
        self.e_phnum,
        self.e_shentsize,
        self.e_shnum,
        self.e_shstrndx) = struct.unpack(self.fmt, bytes[16:self.hdrlen])

        if self.e_machine in e_machine_32:
            self.bits = 32
        elif self.e_machine in e_machine_64:
            self.bits = 64
        else:
            raise Exception("ERROR - Unknown 32/64 bit e_machine: %d.  Add to e_machine_XX" % self.e_machine)

        self.data = bytes

    def buildHeader(self):
        """
        Return the byte representation for *just* the elf header
        for this elf.
        """
        hdr = struct.pack(self.fmt,
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx)
        return self.e_ident + hdr

    def serialize(self, filename=None):
        """
        If filename is specified, serialize this elf object to the specified
        file, otherwise return the bytes (read string) for this elf object
        """
        # Get the Elf header
        buf = self.buildHeader()
        # Get the program headers
        #FIXME assumes order
        for pgm in self.pheaders:
            buf += pgm.serialize()

        phlen = self.e_phentsize * self.e_phnum

        # Append the actual file data
        buf += self.data[self.e_ehsize+phlen:self.e_shoff]

        # Append the section headers
        for sec in self.sections:
            buf += sec.serialize()

        if filename:
            f = file(filename,'wb')
            f.write(buf)
            f.close()
            return

        return buf

    def lookupSymbolName(self, name):
        """
        Lookup symbol entries in this elf binary by name.  The result is
        a long representing the address for the given symbol. Or None if
        it's not found.
        """
        return self.symbols_by_name.get(name, None)

    def lookupSymbolAddr(self, address):
        """
        lookup symbols from this elf binary by address.
        This returns the name for the given symbol or None for not found
        """
        return self.symbols_by_addr.get(address, None)

    def getBytes(self, offset, size, file_offset=True):
        """
        Modification to the bytes this returns will NOT
        be saved to the file bytes.
        """
        return self.data[offset:offset+size]

    def insertBytes(self, offset, bytes,section=None,file_offset=True):
        """
        Insert the bytes argument at offset in the data.
        The default will insert the bytes at that offset
        from the beginning of the file (to ease calculations
        that are based on header values).  The caller may optionally
        specify file_offset=False to have the offset be from
        the beginning of self.data.  If the inserted data falls
        directly on a section boundary,
        The optional "section" argument specifies which section
        you would like to "own" the data (aka. which one gets his
        length updated.  If none, the bytes will push other data down
        essentially into padding between sections...

        THIS CODE DOES NOT WORK YET!

        """

        ilen = len(bytes)

        if section:
            if ( offset < section.sh_offset or
                 offset > (section.sh_offset+section.sh_size)):
                raise Exception("ERROR - Specified section in insertBytes has wrong offset/size: offset: %d" % offset)
            section.sh_size += ilen

        if file_offset:
            offset -= self.getDataOffset()

        self.data = self.data[:offset] + bytes + self.data[offset:]

        #FIXME deal with program headers...
        #for pgm in self.pheaders:

        for sec in self.sections:
            if offset <= (sec.sh_offset-self.getDataOffset()):
                sec.sh_offset += ilen
                if sec.sh_offset % sec.sh_addralign:
                    align = sec.sh_addralign - (sec.sh_offset % sec.sh_addralign)
                    off = sec.sh_offset - self.getDataOffset()
                    # Insert the pad bytes if this insert messes up alignment
                    self.data = self.data[:off] + "\x00" * align + self.data[off:]
                    sec.sh_offset += align
                    ilen += align

        if offset < self.e_shoff:
            self.e_shoff += ilen

        print "INSERTED: ",ilen," bytes"
            
    def getDataOffset(self):
        return self.hdrlen + (self.e_phentsize * self.e_phnum)

    def modifyBytes(self, offset, bytes, file_offset=True):
        """
        Arguments are the same as insertBytes() except that
        this method will OVERWRITE the bytes at that location
        (which shouldn't cause any recalculation)
        """
        blen = len(bytes)
        if file_offset:
            offset -= self.getDataOffset()

        self.data = self.data[:offset] + bytes + self.data[offset+blen:]
        

    def appendSection(self, section, name=None):
        """
        Append the section to the Elf.  The optional
        name will be put into the shstrtab...
        """
        strtab = self.getSection(".shstrtab")
        if not strtab and name:
            raise Exception("ERROR - .shstrtab not found (and name specified)")

        if name:
            section.sh_name = strtab.sh_size
            self.insertBytes(strtab.sh_offset+strtab.sh_size, name+"\x00", strtab)
            self.secnames[name] = section

        section.elf = self
        self.sections.append(section)
        self.e_shnum += 1

        print repr(strtab.getBytes())

    def getSection(self, secname):
        return self.secnames.get(secname,None)

    def getSections(self):
        """
        Return the array of sections for this Elf
        """
        return list(self.sections)

    def getPheaders(self):
        """
        Return a list of the program headers for this elf
        """
        return list(self.pheaders)

    def addSymbol(self, symbol):
        self.symbols.append(symbol)
        self.symbols_by_name[symbol.getName()] = symbol
        self.symbols_by_addr[symbol.st_value] = symbol

    def getSymbols(self):
        return self.symbols

    def parseSymbols(self):
        """
        Parse out the symbols that this elf binary has for us.
        """
        for sec in self.sections:
            if sec.sh_type == SHT_SYMTAB:
                symtab = sec.getBytes()
                while symtab:
                    if self.bits == 32:
                        newsym = Elf32Symbol(symtab)
                    else:
                        newsym = Elf64Symbol(symtab)

                    #FIXME this is dorked!
                    if newsym.st_name:
                        name = self.getStrtabString(newsym.st_name, ".strtab")
                        newsym.setName(name)
                    self.addSymbol(newsym)
                    symtab = symtab[len(newsym):]

    def parseRelocs(self):
        """
        Parse all the relocation entries out of any sections with
        sh_type == SHT_REL
        """
        self.relocs = []
        for sec in self.sections:
            if sec.sh_type == SHT_REL:
                bytes = sec.getBytes()
                while bytes:
                    if self.bits == 32:
                        reloc = Elf32Reloc(bytes)
                    else:
                        reloc = Elf64Reloc(bytes)
                    index = reloc.getSymTabIndex()
                    try:
                        sym = self.dynamic_symbols[index]
                        reloc.setName(sym.getName())
                    except:
                        traceback.print_exc()
                    self.relocs.append(reloc)
                    bytes = bytes[len(reloc):]

            elif sec.sh_type == SHT_RELA:
                bytes = sec.getBytes()
                while bytes:
                    if self.bits == 32:
                        reloc = Elf32Reloca(bytes)
                    else:
                        print "WARNING: 64bits ELF programs aren't supported yet"
                        return
                    
                    index = reloc.getSymTabIndex()
                    try:
                        sym = self.dynamic_symbols[index]
                        reloc.setName(sym.getName())
                    except:
                        traceback.print_exc()
                    self.relocs.append(reloc)
                    bytes = bytes[len(reloc):]

    def parseDynamic(self):
        self.dynamic_symbols = []
        self.dynamics = []
        sec = self.getSection(".dynsym")
        if not sec:
            return

        symtab = sec.getBytes()

        while symtab:
            if self.bits == 32:
                newsym = Elf32Symbol(symtab)
            else:
                newsym = Elf64Symbol(symtab)
            if newsym.st_name:
                name = self.getStrtabString(newsym.st_name, ".dynstr")
                newsym.setName(name)
            self.dynamic_symbols.append(newsym)
            symtab = symtab[len(newsym):]

        dynsec = self.getSection(".dynamic")
        dynbytes = dynsec.getBytes()
        while dynbytes:
            if self.bits == 32:
                dyn = Elf32Dynamic(dynbytes)
            else:
                dyn = Elf64Dynamic(dynbytes)

            if dyn.d_tag in Elf32Dynamic.has_string:
                name = self.getStrtabString(dyn.d_value, ".dynstr")
                dyn.setName(name)

            self.dynamics.append(dyn)
            if dyn.d_tag == DT_NULL: # Represents the end
                break
            dynbytes = dynbytes[len(dyn):]

    def getDynamics(self):
        return self.dynamics

    def getDynSyms(self):
        return self.dynamic_symbols

    def getRelocs(self):
        return self.relocs

class Elf32Dynamic:

    has_string = [DT_NEEDED,DT_SONAME]

    """
    An object to represent an Elf dynamic entry.
    (linker/loader directives)
    """

    def __init__(self, bytes=None):
        self.name = ""
        self.d_tag = 0
        self.d_value = 0
        if bytes:
            self.initFromBytes(bytes)

    def __repr__(self):
        name = self.getName()
        if not name:
            name = hex(self.d_value)
        return "%s %s" % (name,self.getTypeName())

    def initFromBytes(self, bytes):
        self.d_tag,self.d_value = struct.unpack("2L", bytes[:len(self)])

    def getName(self):
        return self.name

    def setName(self, name):
        self.name = name

    def getTypeName(self):
        return dt_types.get(self.d_tag,"Unknown: %s"%hex(self.d_tag))

    def __len__(self):
        return struct.calcsize("2L")

class Elf64Dynamic(Elf32Dynamic):
    pass

class Elf32Reloc:
    """
    Elf relocation entries consist mostly of "fixup" address which
    are taken care of by the loader at runtime.  Things like
    GOT entries, PLT jmp codes etc all have an Elf relocation
    entry.
    """

    def __init__(self, bytes=None):
        self.name = ""
        self.r_offset = 0
        self.r_info = 0
        if bytes:
            self.initFromBytes(bytes)

    def __repr__(self):
        return "%s %s <%s>" % (hex(self.r_offset),self.getName(),self.getTypeName())

    def initFromBytes(self,bytes):
        (self.r_offset, self.r_info) = struct.unpack("2L",bytes[:len(self)])

    def setName(self, name):
        self.name = name

    def getName(self):
        return self.name

    def getType(self):
        return self.r_info & 0xff

    def getSymTabIndex(self):
        return self.r_info >> 8

    def getTypeName(self):
        return r_types_386.get(self.getType(),"")

    def __len__(self):
        return struct.calcsize("2L")

class Elf32Reloca(Elf32Reloc):
    def __init__(self, bytes=None):
        self.r_addend = 0
        Elf32Reloc.__init__(self, bytes)

    def initFromBytes(self, bytes):
        (self.r_offset, self.r_info, self.r_addend) = struct.unpack("3L", bytes[:len(self)])

    def __len__(self):
        return struct.calcsize("3L")

class Elf64Reloc(Elf32Reloc):
    pass

class Elf32Symbol:
    """
    An object which represents an Elf Symbol.  It has the
    following attributes (which are created/parsed by init:
    st_name
    st_value
    st_size
    st_info
    st_other
    st_shndx
    """
    
    def __init__(self, bytes=None):
        self.name = ""
        self.st_name = 0
        self.st_value = 0
        self.st_size = 0
        self.st_info = 0
        self.st_other = 0
        self.st_shndx = 0

        if bytes:
            self.initFromBytes(bytes)

    def getInfoType(self):
        return self.st_info & 0xf

    def getInfoBind(self):
        return self.st_info >> 4

    def __cmp__(self, other):
        if self.st_value > other.st_value:
            return 1
        return -1

    def initFromBytes(self,bytes):
        (self.st_name,
        self.st_value,
        self.st_size,
        self.st_info,
        self.st_other,
        self.st_shndx) = struct.unpack("3L2BH",bytes[:len(self)])

    def serialize(self):
        return struct.pack("3L2BH",
            self.st_name,
            self.st_value,
            self.st_size,
            self.st_info,
            self.st_other,
            self.st_shndx)

    def setName(self,name):
        self.name = name

    def getName(self):
        return self.name

    def __repr__(self):
        return "0x%.8x %d %s" % (self.st_value, self.st_size, self.name)

    def __len__(self):
        return struct.calcsize("3L2BH")

class Elf64Symbol(Elf32Symbol):

    def initFromBytes(self,bytes):
        fmt = "IBBHLL"
        (self.st_name,
        self.st_info,
        self.st_other,
        self.st_shndx,
        self.st_value,
        self.st_size,
        ) = struct.unpack(fmt,bytes[:len(self)])

    def serialize(self):
        return struct.pack("IBBHLL",
            self.st_name,
            self.st_value,
            self.st_size,
            self.st_info,
            self.st_other,
            self.st_shndx)

    def __len__(self):
        return struct.calcsize("IBBHLL")

class Elf32Pheader:
    """
    An object to represent ELF_Phdr structures and the segments they represent
    """

    def __init__(self, bytes=None, elf=None):
        self.elf = elf
        self.p_type = 0
        self.p_offset = 0
        self.p_vaddr = 0
        self.p_paddr = 0
        self.p_filesz = 0
        self.p_memsz = 0
        self.p_flags = 0
        self.p_align = 0

        if bytes:
            self.initFromBytes(bytes)

    def __repr__(self):
        return "[%35s] VMA: 0x%.8x  offset: %8d  memsize: %8d  align: %8d  (filesz: %8d)  flags: %x" % (
            self.getTypeName(),
            self.p_vaddr,
            self.p_offset,
            self.p_memsz,
            self.p_align,
            self.p_filesz,
            self.p_flags)

    def getTypeName(self):
        return ph_types.get(self.p_type, "Unknown")

    def initFromBytes(self, bytes):
        (
        self.p_type,
        self.p_offset,
        self.p_vaddr,
        self.p_paddr,
        self.p_filesz,
        self.p_memsz,
        self.p_flags,
        self.p_align,
        ) = struct.unpack("8L",bytes[:32])

    def serialize(self):
        hdr = struct.pack("8L",
            self.p_type,
            self.p_offset,
            self.p_vaddr,
            self.p_paddr,
            self.p_filesz,
            self.p_memsz,
            self.p_flags,
            self.p_align)
        return hdr

    def __len__(self):
        return struct.calcsize("8L")

class Elf64Pheader(Elf32Pheader):

    def initFromBytes(self, bytes):
        fmt = "2I6L"
        (
        self.p_type,
        self.p_flags,
        self.p_offset,
        self.p_vaddr,
        self.p_paddr,
        self.p_filesz,
        self.p_memsz,
        self.p_align,
        ) = struct.unpack(fmt,bytes[:len(self)])

    def serialize(self):
        fmt = "2I6L"
        hdr = struct.pack(fmt,
            self.p_type,
            self.p_flags,
            self.p_offset,
            self.p_vaddr,
            self.p_paddr,
            self.p_filesz,
            self.p_memsz,
            self.p_align)
        return hdr

    def __len__(self):
        return struct.calcsize("2I6L")

class Elf32Section:

    """
    An object to represent the elf sections in the Elf binary.  Constructor
    takes a string representing the contents of the Elf section.
        self.sh_name
        self.sh_type
        self.sh_flags
        self.sh_addr
        self.sh_offset
        self.sh_size
        self.sh_link
        self.sh_info
        self.sh_addralign
        self.sh_entsize
    """
    def __init__(self, initbytes=None, elf=None):
        self.elf = elf
        self.name = ""
        self.bytes = "" # The actual data section
        self.sh_name = 0 # Section name index
        self.sh_type = 0
        self.sh_flags = 0
        self.sh_addr = 0
        self.sh_offset = 0
        self.sh_size = 0
        self.sh_link = 0
        self.sh_info = 0
        self.sh_addralign = 0
        self.sh_entsize = 0
        self.extrajunx = "" # Stuff held in extended section headers

        if initbytes:
            self.initFromBytes(initbytes)

    def __repr__(self):
        return "Elf Section: [%20s] VMA: 0x%.8x  offset: %8d  ent/size: %8d/%8d  align: %8d" % (
                self.name,
                self.sh_addr,
                self.sh_offset,
                self.sh_entsize,
                self.sh_size,
                self.sh_addralign)

    def getPadSize(self, offset):
        """
        Calculate the pad necissary for this section
        based on the file offset given as an arg
        """
        ret = 0
        myalign = self.sh_addralign
        if myalign > 1:
            mymod = offset % myalign
            if mymod:
                ret = myalign-mymod

        return ret

    def initFromBytes(self, bytes):

        (
        self.sh_name,
        self.sh_type,
        self.sh_flags,
        self.sh_addr,
        self.sh_offset,
        self.sh_size,
        self.sh_link,
        self.sh_info,
        self.sh_addralign,
        self.sh_entsize,
        ) = struct.unpack("10L", bytes[:40])

        if len(bytes) > 40:
            self.extrajunx = bytes[40:]

    def serialize(self):
        hdr = struct.pack("10L",
            self.sh_name,
            self.sh_type,
            self.sh_flags,
            self.sh_addr,
            self.sh_offset,
            self.sh_size,
            self.sh_link,
            self.sh_info,
            self.sh_addralign,
            self.sh_entsize)

        return hdr + self.extrajunx

    def getBytes(self):
        """
        Get the bytes described by this section.  Changes
        to these bytes will NOT be changed in the Elf file data!
        """
        if self.elf:
            if self.sh_type == SHT_NOBITS:
                return "\x00" * self.sh_size
            return self.elf.getBytes(self.sh_offset,self.sh_size)
        else:
            raise Exception("ERROR - Section.getBytes() called when section has no elf!")

    def getUncompressed(self):
        """
        Get the bytes described by this section.  If sh_entsize != sh_size, run uncompress before returning 
        """
        if self.elf:
            if (self.sh_entsize > 0 and self.sh_size != self.sh_entsize):
                return zlib.decompress(self.elf.getBytes(self.sh_offset,self.sh_size))
            return self.elf.getBytes(self.sh_offset,self.sh_size)

        else:
            raise Exception("ERROR - Section.getBytes() called when section has no elf!")

    def setName(self, name):
        """
        The name of a section is not going to be known until
        the sections have been parsed (to know which one is the
        strtab)
        """
        self.name = name

    def getName(self):
        return self.name

    def __len__(self):
        return struct.calcsize("10L")

class Elf64Section(Elf32Section):
    """
    Elf binary section on 64 bit platforms
    """
    def initFromBytes(self, bytes):

        fmt = "2I4L2I2L"
        (
        self.sh_name,
        self.sh_type,
        self.sh_flags,
        self.sh_addr,
        self.sh_offset,
        self.sh_size,
        self.sh_link,
        self.sh_info,
        self.sh_addralign,
        self.sh_entsize,
        ) = struct.unpack(fmt, bytes[:len(self)])

        if len(bytes) > len(self):
            self.extrajunx = bytes[len(self):]

    def serialize(self):
        fmt = "2I4L2I2L"
        hdr = struct.pack(fmt,
            self.sh_name,
            self.sh_type,
            self.sh_flags,
            self.sh_addr,
            self.sh_offset,
            self.sh_size,
            self.sh_link,
            self.sh_info,
            self.sh_addralign,
            self.sh_entsize)

        return hdr + self.extrajunx

    def __len__(self):
        return struct.calcsize("2I4L2I2L")

def getRelocType(val):
    return val & 0xff

def getRelocSymTabIndex(val):
    return val >> 8

