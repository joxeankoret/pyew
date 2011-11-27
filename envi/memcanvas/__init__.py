
import traceback

import sys
import envi
import envi.memory as e_mem
import envi.resolver as e_resolv

class MemoryRenderer:
    """
    A top level object for all memory renderers
    """

    def rendSymbol(self, mcanv, va):
        """
        If there is a symbolic name for the current va, print it...
        """
        sym = mcanv.syms.getSymByAddr(va)
        if sym != None:
            mcanv.addVaText("%s:\n" % repr(sym), va)

    def rendVa(self, mcanv, va):
        tag = mcanv.getVaTag(va)
        mcanv.addText("%.8x:" % va, tag=tag)

    def rendChars(self, mcanv, bytes):
        for b in bytes:
            val = ord(b)
            bstr = "%.2x" % val
            if val < 0x20 or val > 0x7e:
                b = "."
            mcanv.addNameText(b, bstr)

    def render(self, mcanv, va):
        """
        Render one "unit" and return the size you ate.
        mcanv will be a MemoryCanvas extender and va
        is the virtual address you are expected to render.
        """
        raise Exception("Implement render!")


class MemoryCanvas:
    """
    A memory canvas is a place where the textual representation
    of memory will be displayed. The methods implemented here show
    how a memory canvas which simply prints would be implemented.
    """
    def __init__(self, mem, syms=None):
        if syms == None:
            syms = e_resolv.SymbolResolver()
        self.mem = mem
        self.syms = syms
        self.currend = None
        self.renderers = {}

    def write(self, msg):
        # So a canvas can act like simple standard out
        self.addText(msg)

    def addRenderer(self, name, rend):
        self.renderers[name] = rend
        self.currend = rend

    def getRenderer(self, name):
        return self.renderers.get(name)

    def getRendererNames(self):
        ret = self.renderers.keys()
        ret.sort()
        return ret

    def setRenderer(self, name):
        rend = self.renderers.get(name)
        if rend == None:
            raise Exception("Unknown renderer: %s" % name)
        self.currend = rend

    def getTag(self, typename):
        """
        Retrieve a non-named tag (doesn't highlight or do
        anything particularly special, but allows color
        by typename).
        """
        return None

    def getNameTag(self, name, typename=None):
        """
        Retrieve a "tag" object for a name.  "Name" tags will
        (if possible) be highlighted in the rendered interface
        """
        return None # No highlighting in plain text

    def getVaTag(self, va):
        """
        Retrieve a tag object suitable for showing that the text
        added with this tag should link through to the specified
        virtual address in the memory canvas.
        """
        return None # No linking in plain text

    def addText(self, text, tag=None):
        """
        Add text to the canvas with a specified tag.
        """
        sys.stdout.write(text.encode(sys.stdout.encoding,'replace'))

    def addNameText(self, text, name=None, typename=None):
        if name == None:
            name = text
        tag = self.getNameTag(name, typename=typename)
        self.addText(text, tag=tag)

    def addVaText(self, text, va):
        tag = self.getVaTag(va)
        self.addText(text, tag=tag)

    def render(self, va, size, rend=None):
        if rend == None:
            rend = self.currend

        try:
            maxva = va + size
            while va < maxva:
                va += rend.render(self, va)
        except Exception, e:
            s = traceback.format_exc()
            self.addText("\nException At %s: %s\n" % (hex(va),s))

class StringMemoryCanvas(MemoryCanvas):

    def __init__(self, mem, syms=None):
        MemoryCanvas.__init__(self, mem, syms=None)
        self.strval = ""

    def addText(self, text, tag=None):
        self.strval += text

    def __str__(self):
        return self.strval

class HtmlMemoryCanvas(MemoryCanvas):

    def __init__(self, fd, memobj, syms=None):
        MemoryCanvas.__init__(self, memobj, syms=syms)
        self.fd = fd

    def getVaTag(self, va):
        return va

    def addText(self, text, tag=None):
        if tag != None:
            text = '<a href="#%.8x">%s</a>' % (tag,text)
    
        text = text.replace("\n","<br>\n")
        self.fd.write(text)

    def render(self, va, size, rend=None):
        if rend == None:
            rend = self.currend

        self.fd.write("<html><body>")

        maxva = va + size
        while va < maxva:
            self.fd.write('<a name="#%.8x">' % va)
            va += rend.render(self, va)
            self.fd.write('</a>')
        self.fd.write('<body><html>')

