
"""
Some of the basic/universal memory renderers.
"""

import struct

import envi.memcanvas as e_canvas

class ByteRend(e_canvas.MemoryRenderer):

    __fmt_char__ = "B"

    def __init__(self, bigend=False):

        self.fmtbase = "<"
        if bigend:
            self.fmtbase = ">"

        self.width = struct.calcsize("%s%s" % (self.fmtbase,self.__class__.__fmt_char__))
        self.dispfmt = "%%.%dx" % (self.width*2)
        cnt = 16 / self.width
        self.packfmt = self.fmtbase + (self.__class__.__fmt_char__ * cnt)

    def render(self, mcanv, va):
        bytes = mcanv.mem.readMemory(va, 16)
        self.rendVa(mcanv, va)
        mcanv.addText("  ")

        for val in mcanv.mem.readMemoryFormat(va, self.packfmt):
            bstr = self.dispfmt % val
            if mcanv.mem.isValidPointer(val):
                mcanv.addVaText(bstr, val)
            else:
                mcanv.addNameText(bstr)

            mcanv.addText(" ")

        mcanv.addText("  ")
        self.rendChars(mcanv, bytes)
        mcanv.addText("\n")
        return 16

class ShortRend(ByteRend):

    __fmt_char__ = "H"

class LongRend(ByteRend):

    __fmt_char__ = "L"

class QuadRend(ByteRend):
    __fmt_char__ = "Q"

