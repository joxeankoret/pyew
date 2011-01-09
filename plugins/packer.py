#!/usr/bin/env python

"""
Pyew! A Python Tool like the populars *iew

Copyright (C) 2009,2010 Joxean Koret

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

import os
import sys
import pefile
import peutils

def checkPacker(pyew, doprint=True):
    """ Check if the PE file is packed """
    if pyew.pe is None:
        return

    sig = peutils.SignatureDatabase(os.path.join(os.path.dirname(__file__), "UserDB.TXT"))
    matches = sig.match_all(pyew.pe, ep_only = True)
    if not matches:
        if doprint:
            print "***No match"
        return

    if doprint:
        for match in matches:
            print "".join(match)

    if len(matches) == 0:
        if doprint:
            print "***No match"
        return
    
    return matches

functions = {"packer":checkPacker}
