#!/usr/bin/env python

"""
This file is part of Pyew

Copyright (C) 2009, 2010 Joxean Koret

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

import sys

try:
    import libemu
    hasLibEmu = True
except:
    hasLibEmu = False

def shellcodeSearch(pyew):
    """ Search for shellcode """

    moffset = pyew.offset
    buf = pyew.f.read()

    if hasLibEmu:
        emu = libemu.Emulator()
        ret = emu.test(pyew.buf)
        
        if ret:
            if ret > 0:
                print "HINT[emu:0x%x] %x" % (moffset + ret, repr(buf[ret:ret+options.cols]))
                pyew.disassemble(buf[ret:ret+options.cols], pyew.processor, pyew.type, 4, pyew.bsize, baseoffset=pyew.offset)
            else:
                print "Error with libemu: 0x%x" % ret
        else:
            print "***No shellcode detected via emulation"

    pyew.seek(moffset)

functions = {"sc":shellcodeSearch}
