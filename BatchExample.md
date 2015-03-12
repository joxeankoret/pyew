# Introduction #

Pyew can be used as an standalone command line tool or as a framework to analyze binaries. As of version 1.1.1, a batch\_example script is supplied to show how to use Pyew in batch mode. In the following lines I will explain the example analysis used in the batch\_example.py script.

## Mebroot Downloader Checker ##

Following with our friend [mebroot](AnalysisMebroot.md), I will create a simple function to detect the downloader:

```
from pyew_core import CPyew
(...)
def checkMebroot(path):
    pyew = CPyew(batch=True)
    pyew.codeanalysis = False
    
    try:
        pyew.loadFile(path)
    except:
        print "ERROR loading file %s" % path
        return 

    if pyew.format == "PE":
        # Get 6 bytes at offset 0xB8
        if pyew.getBytes(0xB8, 6) != "Rich;\x2E":
            return
        printData(pyew, path, "Mebroot downloader")
        print
(...)
```

Some Mebroot downloaders have a fixed string ("Rich;\x2E") in the offset 0xB8 so just check for this string in the specified position. To do this we need, first, to import the CPyew class from the the pyew\_core module and create a new CPyew object giving the argument "batch=True" to specify that we're using it in batch mode:

```
from pyew_core import CPyew

pyew = CPyew(batch=True)
```

Next action: Load the file to be analized using the method `loadFile`:

```
    try:
        pyew.loadFile(path)
    except:
        print "ERROR loading file %s" % path
        return 
```

NOTE: Remember to enclose it in a try/except construction as it may raise errors (well, it isn't "expected behaviour", but you may find a bug). After this, just read the needed bytes at the offset needed to check for the string we're looking for but do it only if the file's format is PE:

```
    if pyew.format == "PE":
        # Get 6 bytes at offset 0xB8
        if pyew.getBytes(0xB8, 6) != "Rich;\x2E":
            return
        printData(pyew, path, "Mebroot downloader")
        print
```

That's all! I know, I know: It's too easy so, let's continue with the next example:

## Library (API) Calls at Entry Point ##

OK, the following example prints the API calls made from the entry point's first 100 lines. The code is the following:

```
def entryPointCalls(path):
    pyew = CPyew(batch=True)
    pyew.codeanalysis = False
    try:
        pyew.loadFile(path)
    except KeyboardInterrupt:
        print "Abort"
        sys.exit(0)
    except:
        print "ERROR loading file %s" % path
        return

    if pyew.format != "PE":
        return
    
    calls = []
    # Get the disassembl of the first 100 lines
    l = pyew.disasm(pyew.ep, processor=pyew.processor, type=pyew.type, lines=100, bsize=1600)
    for i in l:
        mnem = str(i.mnemonic)
        
        # Is it a direct or indirect jump or call?
        if mnem == "CALL" or mnem.startswith("J") or mnem.startswith("LOOP"):
            operands = str(i.operands).replace("[", "").replace("]", "")
            
            try:
                if pyew.imports.has_key(int(operands, 16)):
                    x = pyew.imports[int(operands, 16)]
                    
                    if x not in calls:
                        calls.append(x)
            except:
                pass

    if len(calls) > 0:
        printData(pyew, path, "Library calls at Entry Point")
        print "Library Calls:", ",".join(calls)
        print
```

After creating a new CPyew object instance, specifying that we're in batch mode and that we don't want to do code analysis, we load the file using the `loadFile` method and disassemble the first 100 lines at entry point (`pyew.ep`). For each disassembly line we check the mnemonic looking for "CALL", "J`*`", "LOOP`*`" instructions. When a conditional or inconditional jump is found we then search the operand in the imports table (pyew.imports) and, if it's found, we have a call to a library function.

## Check for non common instructions at entry point ##

To check for non common instructions we create a common mnemonics list and check the first 30 mnemonics at entry point with this list. If some mnemonic isn't in the list of common mnemonics we print them out and also an hexadecimal dump at this offset:

```
def checkMnemonics(path):
    pyew = CPyew(batch=True)
    pyew.codeanalysis = True
    
    try:
        pyew.loadFile(path)
    except:
        print "ERROR loading file %s" % path
        return 

    # Is it a PE file?
    if pyew.format == "PE":
        # The most common x86 mnemonics
        commons = ["PUSH", "MOV", "SUB", "ADD", "LEA", "CALL", "JMP", "JZ", "JNZ", \
                   "OR", "XOR", "NOT", "POP", "AND", "TEST", "JL", "JG", "JE", \
                   "JLE", "CMP", "LEAVE", "RET", "NOP", "PUSHF", "POPF", "INC", \
                   "INT 3", "DEC", "PUSHA", "POPA"]
        
        try:
            # Get the 30 first mnemonics
            mnems = pyew.GetMnems(pyew.ep, 30)
        except:
            print "ERROR scanning file %s" % path
            return
        
        ret = []
        for x in mnems:
            if x not in commons and x not in ret:
                ret.append(x)
        
        if len(ret) > 0:
            printData(pyew, path, "Uncommon mnemonics")
            print "Mnemonics:", ",".join(ret)
            print
            # Seek to the entry point
            pyew.seek(pyew.ep)
            # Hexdump the first 64 bytes at the entry point
            print pyew.hexdump(pyew.buf, length=16, bsize=64)
```