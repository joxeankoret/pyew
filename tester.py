#!/usr/bin/python

import os
import sys
import json
import pprint
import sqlite3

from hashlib import md5

from pyew_core import CPyew

#-----------------------------------------------------------------------
DATABASE="test.db"
SCHEMA="CREATE TABLE files (MD5, stats)"

#-----------------------------------------------------------------------
class CExecutableStats:
  def __init__(self, deep=False):
    self.deep = deep
    self.db = sqlite3.connect(DATABASE)
    self.create_tables()
    
    self.current_file = None
    self.current_stats = None

  def create_tables(self):
    try:
      cur = self.db.cursor()
      cur.execute(SCHEMA)
    except:
      pass # Just ignore

  def check_or_update(self, md5_hash, ps):
    cur = self.db.cursor()
    sql = "SELECT stats FROM FILES WHERE MD5 = ?"
    cur.execute(sql, (md5_hash,))
    row = cur.fetchone()
    if not row:
      # If there was not previous data (the sample is new)
      print "[INFO] Adding data for file %s (%s)" % (self.current_file, md5_hash)
      sql = "INSERT INTO FILES VALUES (?, ?)"
      cur.execute(sql, (md5_hash, json.dumps(ps)))
      self.db.commit()
      return True

    # If there was previous data, verify it's the same
    stats = json.loads(row[0])
    self.current_stats = stats
    return stats == ps

  def show_reason(self, ps):
    for x in ps:
      print "PROPERTY", x
      print "CURRENT VALUE"
      pprint.pprint(ps[x])
      print "STORED VALUE (ORIGINAL)"
      pprint.pprint(self.current_stats[x])

  def check_file(self, filename):
    self.current_file = filename

    pyew = CPyew(batch=True, plugins=True)
    pyew.codeanalysis = True
    pyew.deepcodeanalysis = self.deep

    try:
      pyew.loadFile(filename)
    except:
      raise Exception("Error loading file: %s" % str(sys.exc_info()[1]))

    if pyew.format not in ["PE", "ELF", "BOOT", "BIOS"]:
      sys.stderr.write("[INFO] Ignoring non supported executable file\n")
      sys.stderr.flush()
      return

    program_stats = pyew.program_stats
    md5_hash = md5(pyew.getBuffer()).hexdigest()
    if self.check_or_update(md5_hash, program_stats):
      print "[OK] Test %s (%s)"  % (filename, md5_hash)
    else:
      msg = "[FAILED] *** Test %s (%s)"
      print msg  % (filename, md5_hash)
      self.show_reason(program_stats)

#-----------------------------------------------------------------------
def usage():
  print "Usage:", sys.argv[0], "[<arguments>] <file|directory>"
  print
  print "-deep, --deep-code-analysis        Enable deep code analysis"
  print "-ndeep,--no-deep-code-analyis      Disable deep code analysis [default]"
  print
  print "If the given argument is a file, only this file will be checked."
  print "If the given argument is a directory, all files in the directory will be checked"

#-----------------------------------------------------------------------
def main(args):
  deep = False
  for arg in args:
    if os.path.isfile(arg):
      stats = CExecutableStats(deep)
      stats.check_file(arg)
    elif os.path.isdir(arg):
      for root, dirs, files in os.walk(arg):
        for name in files:
          stats = CExecutableStats(deep)
          stats.check_file(os.path.join(root, name))
    elif arg in ["-deep", "--deep-code-analysis"]:
      self.deep = True
    elif arg in ["-ndeep", "--no-deep-code-analysis"]:
      self.deep = False
    else:
      print "Invalid option %s" % repr(arg)
      return 

if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()
  else:
    main(sys.argv[1:])
