"""
Unified config object for all vtoys.
"""

import os
import sys

from ConfigParser import ConfigParser
from cStringIO import StringIO

def gethomedir(*paths):
    path = None
    if sys.platform == "win32":
        homepath = os.getenv("HOMEPATH")
        homedrive = os.getenv("HOMEDRIVE")
        if homedrive != None and homepath != None:
            path = os.path.join(homedrive, homepath, *paths)
    else:
        home = os.getenv("HOME")
        if home != None:
            path = os.path.join(home, *paths)

    if path != None and not os.path.exists(path):
        os.makedirs(path)

    return path

def getusername():
    u = os.getenv('USERNAME')
    if u != None:
        return u
    u = os.getenv('USER')
    if u != None:
        return u
    return 'UnknownUser'

class EnviConfig(ConfigParser):

    def __init__(self, filename=None, defaults=None):
        ConfigParser.__init__(self)
        if defaults != None:
            self.readstr(defaults)
            
        self.filename = filename
        if filename != None:
            self.read(filename)

    def readstr(self, s):
        self.readfp(StringIO(s))

    def syncFile(self):
        if self.filename != None:
            f = file(self.filename, "wb")
            self.write(f)
            f.close()

    def set(self, sec, opt, val):
        ConfigParser.set(self, sec, opt, val)
        self.syncFile()

    def remove_option(self, sec, opt):
        ConfigParser.remove_option(self, sec, opt)
        self.syncFile()

    #def __getattr__(self, name):

    #def __setattr__(self, name, value):

