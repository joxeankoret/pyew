#!/usr/bin/python

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

import re
import os
import sys
import hashlib
import urllib

class CVirusTotalScanner:
    
    printResults = False
    filename = None
    baseUrl = "http://www.virustotal.com/vt/en/consultamd5"
    matches = {}
    md5 = None

    def scan(self, filename, argmd5 = None):
        
        if argmd5:
            strmd5 = argmd5
        else:
            strmd5 = md5.md5(file(filename, "rb").read()).hexdigest()
        
        params = urllib.urlencode({"hash":strmd5})
        headers = {"Content-type": "application/x-www-form-urlencoded", "accept":"Text/Plain"}
        data = urllib.urlopen(self.baseUrl, params).read()
        
        self.filename = filename
        self.md5 = strmd5
        matches = {}
        
        if data.find("<b>Error:</b>") > -1:
            if self.printResults:
                print "***No match"
            else:
                return
        else:
            
            matches = re.findall("""\<td\>(.*)\<\/td\>\s*\<td\>.*\<\/td\>\s*\<td\>.*\<\/td\>\s*\<td class=\"positive\"\>(.*)\<\/td\>""",
                                 data, re.MULTILINE or re.IGNORECASE)
            self.matches = {}
            
            for match in matches:
                self.matches[match[0]] = match[1]
            
            if self.printResults:
                self.printSummary()
        
        return matches

    def printSummary(self):
        msg = "File %s with MD5 %s" % (self.filename, self.md5)
        print msg
        print "-"*len(msg)
        print
        
        for match in self.matches:
            print match.ljust(25) + ": " + self.matches[match]
        
        if match:
            print

def virusTotalSearch(pyew):
    """ Search the sample in Virus Total """
    buf = pyew.getBuffer()
    x = hashlib.md5(buf).hexdigest()
    
    scanner = CVirusTotalScanner()
    scanner.printResults = True
    scanner.scan(pyew.filename, argmd5=x)

functions={"vt":virusTotalSearch}

