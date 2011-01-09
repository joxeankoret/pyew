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

import os
import re
import sys
import zlib
import urllib
import binascii
import tempfile

from easygui import textbox, codebox, ccbox

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

try:
    from pdfid_PL import PDFiD2String, PDFiD
except:
    pass

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

# Shamelessly ripped from pyPDF
def ASCII85Decode(data):
    retval = ""
    group = []
    x = 0
    hitEod = False
    # remove all whitespace from data
    data = [y for y in data if not (y in ' \n\r\t')]
    while not hitEod:
        c = data[x]
        if len(retval) == 0 and c == "<" and data[x+1] == "~":
            x += 2
            continue
        #elif c.isspace():
        #    x += 1
        #    continue
        elif c == 'z':
            assert len(group) == 0
            retval += '\x00\x00\x00\x00'
            continue
        elif c == "~" and data[x+1] == ">":
            if len(group) != 0:
                # cannot have a final group of just 1 char
                assert len(group) > 1
                cnt = len(group) - 1
                group += [ 85, 85, 85 ]
                hitEod = cnt
            else:
                break
        else:
            c = ord(c) - 33
            assert c >= 0 and c < 85
            group += [ c ]
        if len(group) >= 5:
            b = group[0] * (85**4) + \
                group[1] * (85**3) + \
                group[2] * (85**2) + \
                group[3] * 85 + \
                group[4]
            assert b < (2**32 - 1)
            c4 = chr((b >> 0) % 256)
            c3 = chr((b >> 8) % 256)
            c2 = chr((b >> 16) % 256)
            c1 = chr(b >> 24)
            retval += (c1 + c2 + c3 + c4)
            if hitEod:
                retval = retval[:-4+hitEod]
            group = []
        x += 1
    return retval

# Shamelessly ripped from pdfminerr http://code.google.com/p/pdfminerr
def RunLengthDecode(data):
    """
    RunLength decoder (Adobe version) implementation based on PDF Reference
    version 1.4 section 3.3.4:
        The RunLengthDecode filter decodes data that has been encoded in a
        simple byte-oriented format based on run length. The encoded data
        is a sequence of runs, where each run consists of a length byte
        followed by 1 to 128 bytes of data. If the length byte is in the
        range 0 to 127, the following length + 1 (1 to 128) bytes are
        copied literally during decompression. If length is in the range
        129 to 255, the following single byte is to be copied 257 - length
        (2 to 128) times during decompression. A length value of 128
        denotes EOD.
    >>> s = "\x05123456\xfa7\x04abcde\x80junk"
    >>> rldecode(s)
    '1234567777777abcde'
    """
    decoded = []
    i=0
    while i < len(data):
        #print "data[%d]=:%d:" % (i,ord(data[i]))
        length = ord(data[i])
        if length == 128:
            break
        if length >= 0 and length < 128:
            run = data[i+1:(i+1)+(length+1)]
            #print "length=%d, run=%s" % (length+1,run)
            decoded.append(run)
            i = (i+1) + (length+1)
        if length > 128:
            run = data[i+1]*(257-length)
            #print "length=%d, run=%s" % (257-length,run)
            decoded.append(run)
            i = (i+1) + 1
    return ''.join(decoded)

def unescape(buf):
    buf = buf.replace("#", "%")
    buf = urllib.unquote(buf)
    return buf

# Shamelessly ripped from pdfminerr http://code.google.com/p/pdfminerr
class LZWDecoder(object):

    debug = 0

    def __init__(self, fp):
        self.fp = fp
        self.buff = 0
        self.bpos = 8
        self.nbits = 9
        self.table = None
        self.prevbuf = None
        return

    def readbits(self, bits):
        v = 0
        while 1:
            # the number of remaining bits we can get from the current buffer.
            r = 8-self.bpos
            if bits <= r:
                # |-----8-bits-----|
                # |-bpos-|-bits-|  |
                # |      |----r----|
                v = (v<<bits) | ((self.buff>>(r-bits)) & ((1<<bits)-1))
                self.bpos += bits
                break
            else:
                # |-----8-bits-----|
                # |-bpos-|---bits----...
                # |      |----r----|
                v = (v<<r) | (self.buff & ((1<<r)-1))
                bits -= r
                x = self.fp.read(1)
                if not x: raise EOFError
                self.buff = ord(x)
                self.bpos = 0
        return v

    def feed(self, code):
        x = ''
        if code == 256:
            self.table = [ chr(c) for c in xrange(256) ] # 0-255
            self.table.append(None) # 256
            self.table.append(None) # 257
            self.prevbuf = ''
            self.nbits = 9
        elif code == 257:
            pass
        elif not self.prevbuf:
            x = self.prevbuf = self.table[code]
        else:
            if code < len(self.table):
                x = self.table[code]
                self.table.append(self.prevbuf+x[0])
            else:
                self.table.append(self.prevbuf+self.prevbuf[0])
                x = self.table[code]
            l = len(self.table)
            if l == 511:
                self.nbits = 10
            elif l == 1023:
                self.nbits = 11
            elif l == 2047:
                self.nbits = 12
            self.prevbuf = x
        return x

    def run(self):
        while 1:
            try:
                code = self.readbits(self.nbits)
            except EOFError:
                break
            x = self.feed(code)
            yield x
            if self.debug:
                print >>stderr, ('nbits=%d, code=%d, output=%r, table=%r' %
                                 (self.nbits, code, x, self.table[258:]))
        return

# lzwdecode
def LZWDecode(data):
    """
    >>> lzwdecode('\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01')
    '\x2d\x2d\x2d\x2d\x2d\x41\x2d\x2d\x2d\x42'
    """
    fp = StringIO(data)
    return ''.join(LZWDecoder(fp).run())

def pdfInfo(pyew, doprint=True):
    """ Get the information about the PDF """
    if not pyew.physical:
       filename = tempfile.mkstemp("pyew")[1]
       f = file(filename, "wb")
       f.write(pyew.getBuffer())
       f.close()
    else:
        filename = pyew.filename
    
    print PDFiD2String(PDFiD(filename, False, True, False, False), False)

def pdfStreams(pyew, doprint=True, get_buf=False):
    """ Get information about the streams """
    buf = pyew.getBuffer()
    tokens = re.split("[,<>;\[\](:)'\r\n\t/ ]", buf)

    bfilters = False
    filters = []
    stream_filters = {}
    streams = 0

    for token in tokens:
        if token == '':
            continue
        
        token = unescape(token)
        
        if token == "Filter":
            bfilters = True
        elif token == "stream":
            streams += 1
        elif token == "endstream":
            bfilters = False
            if filters != []:
                stream_filters[streams] = filters
                filters = []
        elif bfilters and token.lower().find("decode") > -1:
            filters.append(token)

    if doprint:
        for stream in stream_filters:
            for filter in stream_filters[stream]:
                print "Stream %d uses %s" % (stream, filter.replace("[", "").replace("]", ""))

    if not get_buf:
        return stream_filters
    else:
        return stream_filters, buf

def pdfViewStreams(pyew, doprint=True, stream_id=-1, gui=False):
    """ Show decoded streams """
    streams_filters, buf = pdfStreams(pyew, doprint=False, get_buf=True)

    streams = 0

    while 1:
        pos = buf.find("stream")
        if pos == -1:
            break
        streams += 1
        pos2 = buf.find("endstream")
        # -8 means -len("stream")
        #tmp = buf[pos+8:pos2-1]
        tmp = buf[pos+6:pos2]
        tmp = tmp.lstrip(" ")
        failed = False
        dones = []
        if stream_id == -1 or streams == stream_id:
            if streams_filters.has_key(streams):
                for filter in streams_filters[streams]:
                    try:
                        print "Applying Filter %s ..." % filter
                        if filter in dones:
                            print pyew.hexdump(tmp, pyew.hexcolumns)
                            msg = "The filter %s is already applied, it seems to be a PDF Bomb."
                            msg += os.linesep + "Do you want to apply it? "
                            ret = raw_input(msg % filter)
                            if ret != "y":
                                continue
                        else:
                            dones.append(filter)
                        
                        if filter == "FlateDecode":
                            tmp = zlib.decompress(tmp.strip("\r").strip("\n"))
                        elif filter == "ASCIIHexDecode":
                            tmp = binascii.unhexlify(tmp.replace("\r", "").replace("\n", "").replace(" ", "").strip("<").strip(">"))
                        elif filter == "ASCII85Decode":
                            tmp = ASCII85Decode(tmp.strip("\r").strip("\n"))
                        elif filter == "RunLengthDecode":
                            tmp = RunLengthDecode(tmp)
                        elif filter == "LZWDecode":
                            tmp = LZWDecode(tmp)
                    except:
                        failed = True
                        print "Error applying filter %s" % filter, sys.exc_info()[1]
                
                print "Encoded Stream %d" % streams
            else:
                print "Stream %d" % streams
            
            if not gui:
                print "-"*80
                if tmp.find("\x00") == -1:
                    print tmp
                else:
                    print pyew.hexdump(tmp, pyew.hexcolumns)
                print "-"*80
            else:
                if tmp.find("\x00") == -1:
                    textbox("Stream %d" % streams, "Stream", tmp)
                else:
                    codebox("Stream %d" % streams, "Stream", pyew.hexdump(tmp, pyew.hexcolumns))
            
            if tmp.find("\x00") > -1 and not failed and not gui:
                res = raw_input("Show disassembly (y/n)? [n]: ")
                if res == "y":
                    print pyew.disassemble(tmp)
        
        buf = buf[pos2+11:]
        if buf.find("stream") == -1:
            break
        
        if stream_id == -1:
            try:
                if not gui:
                    res = raw_input("Continue? ")
                    
                    if res in ["q", "n"]:
                        break
                else:
                    if not ccbox("Do you want to continue?", "Streams Viewer"):
                        break
            except:
                break
        elif stream_id == streams:
            break

def pdfViewGui(pyew, doprint=True, stream_id=-1):
    """ Show decoded streams (in a GUI) """
    return pdfViewStreams(pyew, doprint=doprint, stream_id=stream_id, gui=True)

def pdfObj(pyew, doprint=True):
    """ Show object's list """
    pyew.dosearch(pyew.f, "r", "\d+ \d+ obj.*", cols=60, doprint=True, offset=0)

def pdfStream(pyew, doprint=True):
    """ Show streams list """
    l = []
    hits = pyew.dosearch(pyew.f, "s", "stream", cols=60, doprint=False, offset=0)
    buf = pyew.getBuffer()
    for hit in hits:
        key, value = hit.keys()[0], hit.values()[0]
        if buf[key-1:key] != "d":
            l.append(key)
            if doprint:
                print "HINT[0x%08x]: %s" % (key, value.translate(FILTER))

    return l

def pdfSeekObj(pyew, args=None):
    """ Seek to one object """
    if args == None:
        print "An argument is required"
        return False
    
    num = args[0].strip(" ")
    d = pyew.dosearch(pyew.f, "r", "\d+ \d+ obj.*", cols=60, doprint=False, offset=0)
    
    for element in d:
        pos = element.keys()[0]
        if element.values()[0].split(" ")[0] == num:
            pyew.seek(pos)
            return True

    print "Object not found"
    return False

def pdfSeekStream(pyew, args = None):
    """ Seek to one stream """
    if not args:
        print "An argument is required"
        return False
    
    l = pdfStream(pyew, doprint=False)
    num = int(args[0])-1
    if num > len(l):
        print "Last stream is %d" % len(l)
    else:
        pyew.seek(l[num])

functions = {"pdf":pdfInfo,
             "pdfilter":pdfStreams,
             "pdfvi":pdfViewStreams,
             "pdfview":pdfViewGui,
             "pdfobj":pdfObj,
             "pdfstream":pdfStream,
             "pdfso":pdfSeekObj,
             "pdfss":pdfSeekStream}

