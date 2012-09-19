 # =============================================================================
 # input.py
 #
 # author: matthieu.kaczmarek@mines-nancy.fr 
 # Mainly rewrited from udis86 -- Vivek Mohan <vivek@sig9.com>
 # =============================================================================

CACHE_SIZE = 64

class Hook:
    def __init__(self, source, base_address):
        self.dis_mode = 32

    def hook(self):
        raise NotImplementedError('abstract method: Hook.hook() should not be called directly')

    def seek(self, add):
        raise NotImplementedError('abstract method: Hook.seek() should not be called directly')

    def symbols(self):
        return {}

class BufferHook(Hook):
    """Hook for buffered inputs."""
    def __init__(self, source, base_address):
        Hook.__init__(self, source, base_address)
        self.source = source
        self.pos = 0
        self.set_source(source)
        self.entry_point = self.base_address = base_address

    def set_source(self, source):
        self.source = source
        self.pos = 0

    def hook(self):
        if self.pos != None and self.pos >= 0 and self.pos < len(self.source):
            ret = self.source[self.pos]
            self.pos += 1
            #print(hex(self.pos) + ' ' + hex(ord(ret)))
            return ord(ret)
        else:
            self.pos = None
        
    def seek(self, add):
        pos = add - self.base_address
        if pos >= 0 and pos <= len(self.source):
            self.pos = pos
        else:
            self.pos = None

class PEStringHook(BufferHook):
    def __init__(self, source, base_address):
        BufferHook.__init__(self, source, base_address)
        try :
            import pefile
        except :
            print('pefile module not found. see http://code.google.com/p/pefile/')
            exit()
        self.pe = pefile.PE(data = source)
        self.source = self.pe.get_memory_mapped_image()
        self.base_address = self.pe.OPTIONAL_HEADER.ImageBase
        self.entry_point = (self.base_address 
                            + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        self.pos = 0
        self.seek(self.base_address + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        if self.pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:
            self.dis_mode = 32
        elif self.pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
            self.dis_mode = 64

    def seek(self, add):
        pos = add - self.base_address
        if pos >= 0 and pos <= len(self.source):
            self.pos = pos
        else:
            self.pos = None

    def symbols(self):
        ret = {}
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    ret[imp.address] = imp.name
#                print(hex(imp.address) + ':' + imp.name)
        # commented this out, or else we have unreachable code
        # return ret
        try:
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                key = self.pe.OPTIONAL_HEADER.ImageBase + exp.address
                ret[key] = exp.name # exp.ordinal        
        except:
            pass
        return ret
            
class PEFileHook(BufferHook):
    def __init__(self, source, base_address):
        BufferHook.__init__(self, source, base_address)
        try :
            import pefile
        except :
            print('pefile module not found. see http://code.google.com/p/pefile/')
            exit()
        self.pe = pefile.PE(name = source)
        self.source = self.pe.get_memory_mapped_image()
        self.pos = self.base_address = base_address
        self.base_address = self.pe.OPTIONAL_HEADER.ImageBase
        self.entry_point = (self.base_address 
                                                + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        self.seek(self.base_address + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)


class HexstringHook(Hook):
    """Hook for hex string inputs."""
    def __init__(self, source, base_address = 0):
        Hook.__init__(self, source, base_address)
        self.set_source(source)
        self.entry_point = self.base_address = base_address

    def set_source(self, source):
        self.source = source.strip().split(' ')
        self.pos = 0

    def hook(self):
        ret = -1
        if self.pos != None and self.pos < len(self.source):
            ret = int(self.source[self.pos], 16)
            self.pos += 1
        return ret

    def seek(self, add):
        pos = add - self.base_address
        if pos >= 0 and pos < len(self.source):
            self.pos = pos
        else:
            self.pos = None


class FileHook(Hook):
    """Hook for FILE inputs."""
    def __init__(self, source, base_address):
        Hook.__init__(self, source, base_address)
        self.source = source
        self.entry_point = self.base_address = base_address
    
    def set_source(self, source):
        self.source = source

    def hook(self):
        s = self.source.read(1)
        if s == '':
            return -1
        return s[0]

    def seek(self, add):
        pos = add - self.base_address
        if pos >= 0:
            self.source.seek(pos)
        else:
            self.pos = None

class Input:
    def __init__(self, hook, source, base_address = 0):
        self.hook = hook(source, base_address)
        self.symbols = self.hook.symbols()
        self.start ()

    def start (self) :
        self.ctr = -1
        self.fill = -1
        self.error = 0
        self.buffer = []

    def seek(self, add):
        self.hook.seek(add)
        if self.hook.pos == None :
            self.error = 1

    def current(self):
        if self.ctr >= 0:
            return self.buffer[self.ctr]
        else:
            return -1

    def next(self):
        if self.error == 1 :
            return -1
        if self.ctr < self.fill:
            self.ctr += 1
            return self.current()
        c = self.hook.hook()
        if c != -1:
            self.ctr += 1
            self.fill += 1
            self.buffer.append(c)
        else:
            self.error = 1
        return c

    def back(self):
        """Move back a single byte in the stream."""
        if self.ctr >= 0:
            self.ctr -= 1

    def peek(self):
        """Peek into the next byte in source."""
        r = self.next()
        # Don't backup if there was an error    return r
        if not self.error:
            self.back()    
        return long(r)

    def read(self, n):
        if self.error == 1:
            return -1
        """read uint of n bits from source"""
        if n < 8:
            print('minimal size of addressable memory is 8 bits(' + n +')')
        elif n == 8:
            return self.next()
        else:
            n /= 2
            a = self.read(n)
            b = self.read(n)
            return a |(b << n)
