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
import StringIO
import tempfile

try:
    from OleFileIO_PL import OleFileIO, DEFECT_INCORRECT, STGTY_STREAM
except:
    pass

def ole2Explore(pyew):
    """ Get the OLE2 directory """
    if not pyew.physical:
       filename = tempfile.mkstemp("pyew")[1]
       f = file(filename, "wb")
       f.write(pyew.getBuffer())
       f.close()
    else:
        filename = pyew.filename

    ole = OleFileIO(filename, raise_defects=DEFECT_INCORRECT)
    ole.dumpdirectory()
    i = 0
    for streamname in ole.listdir():
        if streamname[-1][0] == "\005":
            print streamname, ": properties"
            props = ole.getproperties(streamname)
            props = props.items()
            props.sort()
            for k, v in props:
                #[PL]: avoid to display too large or binary values:
                if isinstance(v, basestring):
                    if len(v) > 50:
                        v = v[:50]
                    # quick and dirty binary check:
                    for c in (1,2,3,4,5,6,7,11,12,14,15,16,17,18,19,20,
                        21,22,23,24,25,26,27,28,29,30,31):
                        if chr(c) in v:
                            v = '(binary data)'
                            break
                print "   ", k, v
                
        
    # Read all streams to check if there are errors:
    print '\nChecking streams...'
    for streamname in ole.listdir():
        # print name using repr() to convert binary chars to \xNN:
        print '-', repr('/'.join(streamname)),'-',
        st_type = ole.get_type(streamname)
        if st_type == STGTY_STREAM:
            print 'size %d' % ole.get_size(streamname)
            # just try to read stream in memory:
            ole.openstream(streamname)
        else:
            print 'NOT a stream : type=%d' % st_type
    print ''

    #[PL] Test a few new methods:
    root = ole.get_rootentry_name()
    print 'Root entry name: "%s"' % root
    if ole.exists('worddocument'):
        print "This is a Word document."
        print "type of stream 'WordDocument':", ole.get_type('worddocument')
        print "size :", ole.get_size('worddocument')
        if ole.exists('macros/vba'):
            print "This document may contain VBA macros."

functions = {"ole2":ole2Explore}
