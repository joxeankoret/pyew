"""
The API describing what it means to be an envi compliant
symbol resolver.
"""

import types

class Symbol:

    def __init__(self, name, value, size=0, fname=None):
        self.name = name
        self.value = value
        self.size = size
        self.fname = fname

    def __eq__(self, other):
        if not isinstance(other, Symbol):
            return False
        return long(self) == long(other)

    def __coerce__(self, value):
        t = type(value)
        if t == types.NoneType:
            return (True, False)
        return (value, t(self.value))

    def __long__(self):
        return long(self.value)

    def __int__(self):
        return int(self.value)

    def __len__(self):
        return self.size

    def __str__(self):
        if self.fname != None:
            return "%s.%s" % (self.fname, self.name)
        return self.name

    def __repr__(self):
        return str(self)

class SymbolResolver:

    """
    NOTE: Nothing should reach directly into a SymbolResolver!
    """

    def __init__(self, width=4, casesens=True):
        self.width = width
        self.widthmask = (2**(width*8))-1
        self.casesens = casesens
        # Lets use 4096 byte buckes for now
        self.bucketsize = 4096
        self.bucketmask = self.widthmask ^ (self.bucketsize-1)
        self.buckets = {}
        self.symnames = {}
        self.symaddrs = {}

    def delSymbol(self, sym):
        """
        Delete a symbol from the resolver's namespace
        """
        symval = long(sym)
        self.symaddrs.pop(symval, None)

        bbase = symval & self.bucketmask
        while bbase < symval:
            bucket = self.buckets.get(bbase)
            bucket.remove(sym)
            bbase += self.bucketsize

        subres = None
        if sym.fname != None:
            subres = self.symnames.get(sym.fname)

        # Potentially del it from the sub resolver's namespace
        if subres != None:
            subres.delSymbol(sym)

        # Otherwise del it from our namespace
        else:
            symname = sym.name
            if not self.casesens:
                symname = symname.lower()
            self.symnames.pop(symname, None)

    def addSymbol(self, sym):
        """
        Add a symbol to the resolver.
        """
        # If the symbol has an fname, add it to the namespace
        # for the FileSymbol inside us rather than our namespace.

        symval = long(sym)
        self.symaddrs[symval] = sym

        bbase = symval & self.bucketmask
        while bbase < symval:
            bucket = self.buckets.get(bbase)
            if bucket == None:
                bucket = []
                self.buckets[bbase] = bucket
            bucket.append(sym)
            bbase += self.bucketsize

        subres = None
        if sym.fname != None:
            subres = self.symnames.get(sym.fname)

        # Potentially add it to the sub resolver's namespace
        if subres != None:
            subres.addSymbol(sym)

        # Otherwise add it to our namespace
        else:
            symname = sym.name
            if not self.casesens:
                symname = symname.lower()
            self.symnames[symname] = sym

    def getSymByName(self, name):
        if not self.casesens:
            name = name.lower()
        return self.symnames.get(name)

    def getSymByAddr(self, va, exact=True):
        """
        Return a symbol object for the given virtual address.
        """
        va = va & self.widthmask
        sym = self.symaddrs.get(va)

        if sym != None:
            return sym

        if not exact:
            b = va & self.bucketmask
            best = 999999999
            while sym == None:
                bucket = self.buckets.get(b)
                if bucket != None:
                    for s in bucket:
                        sva = long(s)
                        if sva > va:
                            continue
                        offset = va - sva
                        if offset < best:
                            best = offset
                            sym = s
                # If we get more than 8k away, just get out...
                if va - b > 8192:
                    break
                # Move back to the previous bucket.
                b -= self.bucketsize

        # If we resolve a sub-resolver, see if he
        # has finer resolution than we do...
        if isinstance(sym, SymbolResolver):
            ssym = sym.getSymByAddr(va, exact=exact)
            if ssym != None:
                return ssym

        return sym

    def getSymList(self):
        """
        Return a list of the symbols which are contained in this resolver.
        """
        return self.symaddrs.values()

    def getSymHint(self, va, hidx):
        """
        May be used by symbol resolvers who know what type they are
        resolving to store and retrieve "hints" with indexes.

        Used specifically by opcode render methods to resolve
        any memory dereference info for a given operand.

        NOTE: These are mostly symbolic references to FRAME LOCAL
              names....
        """
        return None

# Some extension types

class FunctionSymbol(Symbol):
    """
    Used to represent functions.
    """
    def __repr__(self):
        return "%s.%s()" % (self.fname, self.name)

class SectionSymbol(Symbol):
    """
    Used for file sections/segments.
    """
    def __repr__(self):
        return "%s[%s]" % (self.fname,self.name)

class FileSymbol(Symbol,SymbolResolver):
    """
    A file symbol is both a symbol resolver of it's own, and
    a symbol.

    File symbols are used to do heirarchal symbol lookups and don't
    actually add anything but the name to their lookup (it is assumed
    that the parent Resolver of the FileSymbol takes care of addr lookups.
    """
    def __init__(self, fname, base, size, width=4):
        SymbolResolver.__init__(self, width=width)
        Symbol.__init__(self, fname, base, size)

    def __getattr__(self, name):
        """
        File symbols may be dereferenced like python objects to resolve
        symbols within them.
        """
        ret = self.getSymByName(name)
        if ret == None:
            raise AttributeError("%s has no symbol %s" % (self.name,name))
        return ret

    def __getitem__(self, name):
        """
        Allow dictionary style access for mangled incompatible names...
        """
        ret = self.getSymByName(name)
        if ret == None:
            raise KeyError("%s has no symbol %s" % (self.name,name))
        return ret

