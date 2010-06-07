#!/usr/bin/env python

import os
import sys
import pefile
import peutils

def checkPacker(pyew, doprint=True):
    """ Check if the PE file is packed """
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
    
    return match

functions = {"packer":checkPacker}
