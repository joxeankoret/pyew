#!/usr/bin/env python

import sys
import pickle
import StringIO
 
class SafeUnpickler(pickle.Unpickler):
    PICKLE_SAFE = {
        "copy_reg": set(['_reconstructor']),
        "__builtin__": set(['object']),
        "pyew_core":set(["CPyew", "CDisObj"]),
        "anal.x86analyzer":set(["CX86Function", "CX86BasicBlock"]),
        "_ctypes":["_unpickle"],
        "pydistorm":["_WString"],
        "Elf":["Elf", "Elf64Dynamic", "Elf32Dynamic", "Elf64Section", "Elf32Section",
               "Elf64Pheader", "Elf32Pheader", "Elf64Symbol", "Elf32Symbol", "Elf64Reloca"],  
        "pefile":["PE", "Structure", "SectionStructure", "ImportDescData", "ImportData",
                  "ResourceDirData", "ResourceDirEntryData", "ResourceDataEntryData"],
    }
    def find_class(self, module, name):
        if not module in self.PICKLE_SAFE:
            raise pickle.UnpicklingError(
                'Attempting to unpickle unsafe module %s' % module
            )
        __import__(module)
        mod = sys.modules[module]
        if not name in self.PICKLE_SAFE[module]:
            raise pickle.UnpicklingError(
                'Attempting to unpickle unsafe class %s of module %s' % (name, module)
            )
        klass = getattr(mod, name)
        return klass
 
    @classmethod
    def loads(cls, pickle_string):
        return cls(StringIO.StringIO(pickle_string)).load()

