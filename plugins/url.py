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

import re
import sys
import urllib

def toUnicode(buf):
    ret = ""
    for c in buf:
        ret += c + "\x00"
    return ret

def urlExtract(pyew, doprint=True):
    """ Search URLs in the current document """

    urlfinders = [
        re.compile("((http|ftp|mailto|telnet|ssh)(s){0,1}\:\/\/[\w|\/|\.|\#|\?|\&|\=|\-|\%]+)+", re.IGNORECASE | re.MULTILINE)
    ]

    moffset = pyew.offset
    pyew.offset = 0
    pyew.seek(0)
    buf = pyew.f.read()
    ret = []
    
    for x in urlfinders:
        ret += doFind(x, buf)

    if doprint and len(ret) > 0:
        print "ASCII URLs"
        print
        for url in ret:
            print url

    buf = buf.replace("\x00", "")
    uniret = []
    for x in urlfinders:
        uniret += doFind(x, buf)

    if doprint and len(uniret) > 0:
        i = 0
        for url in ret:
            if url not in ret:
                if i == 0:
                    print "UNICODE URLs"
                    print
                i += 1
                print url

    tmp = {}
    for x in ret:
        tmp[x] = x
    ret = tmp.values()

    pyew.seek(moffset)
    return ret

def doFind(x, buf):
    ret = []
    for l in x.findall(buf, re.IGNORECASE | re.MULTILINE):
        for url in l:
            if len(url) > 8 and url not in ret:
                ret.append(url)
    
    return ret

def checkUrls(pyew, doprint=True):
    """ Check URLs of the current file """
    
    oks = []
    urls = urlExtract(pyew, doprint=False)
    
    if len(urls) == 0:
        print "***No URLs found"
        return

    for url in urls:
        try:
            if doprint:
                sys.stdout.write("Checking %s ... " % url)
                sys.stdout.flush()
            r = urllib.urlopen(url)
            
            if doprint:
                sys.stdout.write("OK\n")
                sys.stdout.flush()
            
            oks.append(url)
        except KeyboardInterrupt:
            print "Aborted"
            break
        except:
            sys.stdout.write("DOWN\n")
            sys.stdout.flush()
        
    return oks

def checkBad(pyew, doprint=True):
    """ Check for known bad URLs """
    
    returls = []
    
    url = "http://www.malware.com.br/cgi/submit?action=list_adblock"
    try:
        l = urllib.urlopen(url).readlines()
    except:
        print "***Error fetching URL list from www.malware.com.br:", sys.exc_info()[1]
        return

    urls = urlExtract(pyew, doprint=False)
    
    if len(urls) == 0:
        print "***No URLs found"
        return

    for url in urls:
        for badurl in l:
            if badurl.startswith("["):
                continue
            badurl = badurl.strip("\n").strip("\r")
            if url.lower().find(badurl) > -1:
                if doprint:
                    print "***Found bad URL: %s" % url
                
                returls.append(url)
                break

    return returls

functions = {"url":urlExtract, "chkurl":checkUrls, "chkbad":checkBad}

