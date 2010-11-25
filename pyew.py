#!/usr/bin/python
# -*- coding: latin-1 -*-

"""
Pyew! A Python Tool like the populars *iew

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

import os
import sys
import code
import pprint
import sqlite3
import StringIO

from binascii import unhexlify
from hashlib import md5, sha1, sha224, sha256, sha384, sha512, new as hashlib_new
from config import PLUGINS_PATH, DATABASE_PATH

try:
    import psyco
    psyco.log()
    psyco.full()
except ImportError:
    pass

try:
    import readline
    
    histfile = os.path.join(os.environ["HOME"], ".pyew")
    try:
        readline.read_history_file(histfile)
    except IOError:
        pass
    import atexit
    atexit.register(readline.write_history_file, histfile)
except:
    pass

try:
    import pefile
    hasPefile = True
except ImportError:
    hasPefile = False
    
try:
    from Elf import Elf
    hasElf = True
except ImportError:
    hasElf = False

from pyew_core import CPyew

PROGRAM="PYEW! A Python tool like radare or *iew"
VERSION=0x01020000
HUMAN_VERSION="1.2.0.0"

def showHelp(pyew):
    print PROGRAM, "0x%x" % VERSION, "(%s)" % HUMAN_VERSION
    print
    print "Commands:"
    print
    print "?/help                            Show this help"
    print "x/dump/hexdump                    Show hexadecimal dump"
    print "s/seek                            Seek to a new offset"
    print "b                                 Return to previous offset"
    print "g/G                               Goto BOF (g) or EOF (G)"
    print "+/-                               Go forward/backward one block (specified by pyew.bsize)"
    print "c/d/dis/pd                        Show disassembly"
    print "a                                 Do code analysis"
    print "r/repr                            Show string representation"
    print "ls                                List scripts available or launch one if used with an argument"
    print "p                                 Print the buffer"
    print "buf                               Print as a python buffer"
    print "byte                              Print as a C byte array"
    print "/x expr                           Search hexadecimal string"
    print "/s expr                           Search strings"
    print "/i expr                           Search string ignoring case"
    print "/r expr                           Search regular expression"
    print "/u expr                           Search unicode expression"
    print "/U expr                           Search unicode expression ignoring case"
    print "edit                              Reopen the file for reading and writting"
    print "wx data                           Write hexadecimal data to file"
    print "wa data                           Write ASCII data to file"
    print "file                              Load as new file the buffer from the current offset"
    print "ret                               Return to the original file (use after 'file')"
    print "interact                          Open an interactive Python console"
    print
    print "Cryptographic functions: md5, sha1, sha224, sha256, sha384, sha512"
    print
    print "Examples:"
    print "[0x0]> md5"
    print "md5: d37b6d42a04cbc04cb2988ed947a5b0d"
    print "[0x0]> md5(pyew.buf[0:7])"
    print "581fd4acfc2214aa246f0b47c8ae8a4e"
    print "[0x0]> md5(pyew.buf[15:35])"
    print "a73b2882dd918070c6e8dfd9081fb600"
    print
    if pyew.pe:
        print "PE specific commands:"
        print
        print "imports                           Show the import table"
        print "exports                           Show the export table (if any)"
        print

    print "Current configuration options:"
    print
    pyew.showSettings()
    print
    print "Any other expression will be evaled as a Python expression"
    print

def createSchema(db):
    try:
        sql = """create table samples (id integer not null primary key,
                                       md5, sha1, sha256, filename, type)"""
        db.execute(sql)
        
        sql = """create table function_stats (
                        id integer not null primary key,
                        sample_id, addr, nodes, edges, cc)"""
        db.execute(sql)
        
        sql = """create table antidebugs (
                        id integer not null primary key,
                        sample_id, addr, mnemonic
                        )"""
        db.execute(sql)
    except:
        pass

def saveSample(db, pyew, buf, amd5):
    try:
        asha1 = sha1(buf).hexdigest()
        asha256 = sha256(buf).hexdigest()
        name = pyew.filename
        format = pyew.format
        
        cur = db.cursor()
        sql = """ insert into samples (md5, sha1, sha256, filename, type)
                               values (?, ?, ?, ?, ?)"""
        cur.execute(sql, (amd5, asha1, asha256, name, format))
        rid = cur.lastrowid
        
        sql = """ insert into function_stats (sample_id, addr, nodes, edges, cc)
                                      values (?, ?, ?, ?, ?) """
        for f in pyew.function_stats:
            addr = "0x%08x" % f
            nodes, edges, cc = pyew.function_stats[f]
            cur.execute(sql, (rid, addr, nodes, edges, cc))
        
        sql = """ insert into antidebugs (sample_id, addr, mnemonic) values (?, ?, ?) """
        for antidbg in pyew.antidebug:
            addr, mnem = antidbg
            addr = "0x%08x" % addr
            cur.execute(sql, (rid, addr, mnem))
        
        db.commit()
    except:
        print sys.exc_info()[1]
        pass

def saveAndCompareInDatabase(pyew):
    db = sqlite3.connect(DATABASE_PATH)
    createSchema(db)
    cur = db.cursor()
    bcontinue = True
    
    try:
        buf = pyew.getBuffer()
        amd5 = md5(buf).hexdigest()
        name = pyew.filename
        sql = """ select * from samples where md5 = ? """
        cur.execute(sql, (amd5, ))
        
        for row in cur.fetchall():
            if row[4] != name:
                print "NOTICE: File was previously analyzed (%s)" % row[4]
                print
            bcontinue = False
        cur.close()
        
        if bcontinue:
            saveSample(db, pyew, buf, amd5)
    except:
        print sys.exc_info()[1]
        raise

def setupAutoCompletion(pyew):

    # Settings
    commands = {"pyew": pyew}
    # Plugins
    for plugin in pyew.plugins:
        commands[plugin.ljust(8)] = 0
    # Crypto
    cryptos = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
    for crypto in cryptos:
        commands[crypto] = 0

    try:
        import rlcompleter
        
        readline.set_completer(rlcompleter.Completer(commands).complete)
        readline.parse_and_bind("tab: complete")
    except:
        pass


def main(filename):
    pyew = CPyew()
    if os.getenv("PYEW_DEBUG"):
        pyew.debug=True
    else:
        pyew.debug = False

    pyew.loadFile(filename, "rb")

    if pyew.format in ["PE", "ELF"]:
        saveAndCompareInDatabase(pyew)

    pyew.offset = 0
    print pyew.hexdump(pyew.buf, pyew.hexcolumns)

    oldpyew = None
    cmd = ""
    last_cmd = ""
    pyew.previousoffset = []

    # Add global object's references for easier usage
    pe = pyew.pe
    elf = pyew.elf

    # Set AutoCompletion
    setupAutoCompletion(pyew)

    # Check if there is runme.py file
    if os.path.exists('runme.py'):
        f = open('runme.py', 'r')
        commands = f.readlines()
        f.close()

    while 1:
        try:
            last_cmd = cmd
            
            if len(pyew.previousoffset) > 0:
                if pyew.previousoffset[len(pyew.previousoffset)-1] != pyew.offset:
                    pyew.previousoffset.append(pyew.offset)
            else:
                pyew.previousoffset.append(pyew.offset)
            
            va = None
            if pyew.virtual:
                va = pyew.getVirtualAddressFromOffset(pyew.offset)
            
            if va:
                prompt = "[0x%08x:0x%08x]> " % (pyew.offset, va)
            else:
                prompt = "[0x%08x]> " % pyew.offset
            
            try:
                cmd = commands[0].rstrip()
                commands.pop(0)
            except:
                cmd = raw_input(prompt)
            
            if cmd in ["", "b"] and (last_cmd in ["b", "x", "c", "d", "dump", "hexdump", "dis", "pd", "p", "r", "buf"] or last_cmd.isdigit()):
                if cmd == "b":
                    tmp = pyew.previousoffset.pop()
                    
                    if len(pyew.previousoffset) > 0:
                        tmp = pyew.previousoffset[len(pyew.previousoffset)-1]
                    else:
                        tmp = 0
                        
                    pyew.offset = tmp
                    pyew.lastasmoffset = tmp
                    pyew.seek(tmp)
                    if last_cmd.isdigit():
                        last_cmd = "c"
                    
                elif cmd == "b" and last_cmd == "b":
                    if len(pyew.previousoffset) < 2:
                        continue
                    
                    tmp = pyew.previousoffset.pop()
                    tmp = pyew.previousoffset[len(pyew.previousoffset)-1]
                    pyew.seek(tmp)
                    continue
                elif last_cmd in ["c", "d", "pd"] or last_cmd.isdigit():
                    pyew.offset = pyew.lastasmoffset
                    pyew.seek(pyew.offset)
                    if last_cmd.isdigit():
                        last_cmd = "c"
                else:
                    pyew.offset = pyew.offset+pyew.bsize
                    pyew.seek(pyew.offset)
                cmd = last_cmd
        except EOFError:
            break
        except KeyboardInterrupt:
            break
        
        try:
            if cmd.strip(" ") == "":
                continue
            
            if cmd.lower() in ["exit", "quit", "q"]:
                break
            elif cmd.lower() in ["a", "anal"]:
                pyew.findFunctions(pyew.processor)
                print
            elif cmd.lower() in ["x", "dump", "hexdump"]:
                print pyew.hexdump(pyew.buf, pyew.hexcolumns, baseoffset=pyew.offset)
            elif cmd.split(" ")[0] in ["s", "seek"]:
                data = cmd.split(" ")
                if len(data) > 1:
                    if data[1].lower() in ["ep", "entrypoint"]:
                        if pyew.ep:
                            pyew.offset = pyew.ep
                    else:
                        pyew.names.has_key(data[1].lower())
                        
                        if data[1].lower()[0] in ["+", "-"]:
                            pyew.offset += int(data[1])
                        elif data[1].lower().startswith("0x"):
                            pyew.offset = int(data[1], 16)
                        elif data[1] in pyew.names.values():
                            for x in pyew.names:
                                if pyew.names[x] == data[1]:
                                    pyew.offset = x
                                    break
                        else:
                            pyew.offset = int(data[1])
                        
                pyew.seek(pyew.offset)
            elif cmd.lower().split(" ")[0] in ["c", "d", "dis", "pd"]:
                data = cmd.lower().split(" ")
                if len(data) > 1:
                    if not data[1].startswith("/"):
                        type = int(data[1])
                        dis = pyew.disassemble(pyew.buf, pyew.processor, pyew.type, pyew.lines, pyew.bsize, baseoffset=pyew.offset)
                        print dis
                    else:
                        cmd = data[1:]
                        if len(cmd) > 1:
                            ret = pyew.dosearch(pyew.f, cmd[0][1:2], cmd[1], cols=60, doprint=False, offset=pyew.offset)
                        else:
                            ret = pyew.dosearch(pyew.f, cmd[0][1:2], "", cols=60, doprint=False, offset=pyew.offset)
                        
                        for x in ret:
                            dis = pyew.disassemble(x.values()[0], pyew.processor, pyew.type, pyew.lines, pyew.bsize, baseoffset=x.keys()[0])
                            print dis
                else:
                    dis = pyew.disassemble(pyew.buf, pyew.processor, pyew.type, pyew.lines, pyew.bsize, baseoffset=pyew.offset)
                    print dis
            elif cmd.isdigit() and int(cmd) < len(pyew.calls)+1 and int(cmd) > 0:
                pyew.offset = pyew.calls[int(cmd)-1]
                pyew.seek(pyew.offset)
                dis = pyew.disassemble(pyew.buf, pyew.processor, pyew.type, pyew.lines, pyew.bsize, baseoffset=pyew.offset)
                print dis
            elif cmd == "buf":
                lines = 0
                line = ""
                for c in pyew.buf:
                    line += c
                    if len(line) == pyew.hexcolumns:
                        print repr(line)
                        line = ""
                
                if line != "":
                    print repr(line)
            elif cmd == "byte":
                lines = 0
                line = ""
                for c in pyew.buf:
                    line += "0x%x, " % ord(c)
                    if len(line) >= pyew.hexcolumns / (1.00/4.00):
                        print line
                        line = ""
                
                if line != "":
                    print "%s" % line
            elif cmd.lower().split(" ")[0] in ["r", "repr"]:
                print repr(pyew.buf)
            elif cmd.lower().split(" ")[0] in ["p"]:
                print pyew.buf
            elif cmd.lower() in ["settings", "options"]:
                pyew.showSettings()
            elif cmd.startswith("/"):
                ret = pyew.dosearch(pyew.f, cmd[1:2], cmd[3:], cols=60, offset=pyew.offset)
            elif cmd.lower() in ["?", "help"]:
                showHelp(pyew)
            elif cmd.lower() in ["imports"]:
                if pyew.format == "PE":
                    for entry in pyew.pe.DIRECTORY_ENTRY_IMPORT:
                        print entry.dll
                        for imp in entry.imports:
                            print '\t', hex(imp.address), imp.name
                elif pyew.format == "ELF":
                    for x in pyew.elf.relocs:
                        print x
            elif cmd.lower() in ["exports"]:
                if pyew.format == "PE":
                    for exp in pyew.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        print hex(pyew.pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal
                elif pyew.format == "ELF":
                    print "Not yet implemented"
            elif cmd.lower() in ["sections"]:
                if pyew.format == "PE":
                    for x in pyew.pe.sections:
                        print x
                elif pyew.format == "ELF":
                    for x in pyew.elf.secnames:
                        print pyew.elf.secnames[x]
            elif cmd.lower() in ["elf", "pe"]:
                if cmd.lower() == "elf":
                    print pyew.elf
                else:
                    print pyew.pe
            elif cmd.lower() == "g":
                if cmd == "g":
                    pyew.offset = 0
                else:
                    pyew.offset = pyew.maxsize - pyew.bsize
                    if pyew.offset < 0:
                        pyew.offset = pyew.maxsize - 32
                pyew.seek(pyew.offset)
            elif cmd in ["-", "+"]:
                if cmd == "+":
                    pyew.offset += pyew.bsize
                else:
                    pyew.offset -= pyew.bsize
                pyew.seek(pyew.offset)
            elif pyew.plugins.has_key(cmd.split(" ")[0]):
                plg = cmd.split(" ")
                if len(plg) == 1:
                    pyew.plugins[plg[0]](pyew)
                else:
                    pyew.plugins[plg[0]](pyew, plg[1:])
            elif cmd.lower().split(" ")[0] in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]:
                func = eval(cmd)
                print "%s: %s" % (cmd, func(pyew.getBuffer()).hexdigest())
            elif cmd.startswith("!"):
                os.system(cmd[1:])
            elif cmd == "ret" and oldpyew is not None:
                pyew = oldpyew
                pyew.seek(pyew.offset)
                oldpyew = None
            elif cmd == "file":
                oldpyew = pyew
                del pyew
                pyew = CPyew()
                buf = oldpyew.getBytes(oldpyew.offset, oldpyew.maxsize)
                pyew.loadFromBuffer(buf, oldpyew.filename + "[embed]")
            elif cmd == "interact":
                code.interact(local=locals())
            elif cmd == "edit":
                pyew.f.close()
                pyew.f = open(filename, "r+wb")
                pyew.seek(0)
            elif cmd.split(" ")[0] in ["ls"]:
                data = cmd.split(" ")
                if len(data) == 2:
                    #print "parsing script file:", data[1]
                    f = open('scripts/' + data[1], 'r')
                    commands = f.readlines()
                    f.close()
                else:
                    scripts = os.listdir('scripts/')
                    print "Scripts available:"
                    for script in scripts:
                        print "\t", script
            elif cmd.split(" ")[0] in ["wx", "wa"]:
                if cmd.split(" ")[0] == "wx":
                    data = unhexlify(cmd.split(" ")[1])
                else:
                    data = cmd.split(" ")[1]
                
                pyew.f.seek(pyew.offset)
                pyew.f.write(data)
                pyew.seek(pyew.offset)
            else:
                if cmd.find("=") > -1 or cmd.startswith("print") or cmd.startswith("import "):
                    exec(cmd)
                else:
                    x = eval(cmd)
                    if "hexdigest" in dir(x):
                        print "%s: %s" % (cmd, x.hexdigest())
                    else:
                        pprint.pprint(x)
        except:
            print "Error:", sys.exc_info()[1]
            if pyew.debug:
                raise

def mainBatch(directory):
    pass

def usage():
    print "%s Version 0x%08x (%s)" % (PROGRAM, VERSION, HUMAN_VERSION)
    print
    print "Usage:", sys.argv[0], "<filename>"

if __name__ == "__main__":
    if len(sys.argv) == 1:
        usage()
    else:
        main(sys.argv[1])
