#!/usr/bin/env python

"""
This file is part of Pyew

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

import sys
import tempfile

try:
    from pdfid_PL import PDFiD2String, PDFiD
except:
    pass

def pdfInfo(pyew):
    """ Get the information about the PDF """
    if not pyew.physical:
       filename = tempfile.mkstemp("pyew")[1]
       f = file(filename, "wb")
       f.write(pyew.getBuffer())
       f.close()
    else:
        filename = pyew.filename
    
    print PDFiD2String(PDFiD(filename, False, True, False, False), False)

functions = {"pdf":pdfInfo}

