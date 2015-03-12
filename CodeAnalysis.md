# Introduction #

When you open a PE file or an ELF file Pyew does, by default, code analysis by recursively traversing every entry point and following all jumps and direct/indirect calls. In the latest versions, if you have set DEEP\_CODE\_ANALYSIS to True in config.py, Pyew tries to search new functions by searching typical function prologs (x86 and x86\_64) and, also, by recursively traversing every function discovered this way.

# Details #

The code analysis algorithm used in Pyew is similar to the algorithm used in IDA Pro. Basically it works the following way:

  * Put every entry point in a queue to be analyzed and consider them as functions.
  * Trace every jump and call from the entry point(s) and follow them.
    * For each "call" or "push offset"+"ret" create a function.
  * The analysis of a function stops when all possible code paths are over.
    * A code path is considered finished when a "RET" or "JMP _unknown_" is found and the register or offset can not be resolved.

And, if deep code analysis is enabled:

  * Search every possible function by searching typical prologs and put them in a queue.
  * Perform the same actions as in the previous steps with the entry points.

NOTE: Currently (2011-11-16) Pyew doesn't understand switchs.

# Disabling code analysis #

While code analysis is very interesting it may take a while to finish so, if you don't want to enable code analysis you may do the following:

  * Press Ctrl+C while the code analysis is being done.
  * Disable it in config.py by changing the value of the constant CODE\_ANALYSIS.

To analyze an executable file after disabling the automatic code analysis you may use the command "a".

# Enabling/Disabling deep code analysis #

Deep code analysis is more accurate but takes far longer and, sometimes, you don't want to have it enabled by default. To enable or disable this feature set the value of DEEP\_CODE\_ANALYSIS accordingly. This value is set to False by default.

# Information retrieved #

The following information is retrieved in the code analysis:

  * Functions: Every detected function.
  * Basic blocks: Every function's basic block.
  * Names: Every resolved function name and automatically generated function names too.
    * The function names may be "sub`_`_offset_" for a normal function or "ret`_`_offset_" for functions discovered with a "PUSH OFFSET+RET" combination. You may also find functions with names like "j\_library.dll!function".
  * Cross References: Cross references from functions and to functions.
  * Antidebug: Just as a helper, x86 instructions used as antidebugging or antiemulation.

To access to this information gathered by the x86analyzer module use the corresponding property from this list:

  * `[pyew.]`antidebug: A List of offset and name pairs with all the antidebugging tricks found.
  * `[pyew.]`names: A list of offset and name pairs with both resolved and automatically generated names.
  * `[pyew.]`functions: A list of offset and function objects.
  * `[pyew.]`functions\_address: A list of (function offset, (start\_offset, end\_offset)) of the discovered functions.
  * `[pyew.]`xrefs\_to: A list of (function\_offset, (function\_called\_from\_offset1, function\_called\_from\_offset2, ...)).
  * `[pyew.]`xrefs\_from: A list of (function\_offset, (function\_called\_to\_offset1, function\_called\_to\_offset2, ...)).
  * `[pyew.]`basic\_blocks: A list of every basic block found in the program.
  * `[pyew.]`function\_stats: A list of offset and statistics about every function. The statistics are the number of nodes, edges and ciclomatic complexity.
  * `[pyew.]`program\_stats: Same as function\_stats but for the whole program.

## Antidebug ##

What is considered as antidebugs? At the moment, the following x86 instructions:

  * INT `num`: Interruptions. Typically used as antiemulation (INT 4) and antidebugging tricks (INT 3).
  * UD2: Undefined instruction. Found in some packers/protectors as an antiemulation tricks.
  * RDTSC: Widely used in malware to check if the software is being traced. A typical way to detect binary instrumentation (PIN, DynamoRIO, etc...).
  * SIDT/SGDT: Store Interrupt/Global Descriptor Table. Trick used to detect some Virtual Machines (known as the red pill trick).
  * CPUID: Used to detect Virtual Machines and emulators.
  * NOP `args`: NOP with arguments are typical antiemulation tricks.
  * SYSENTER: Direct system calls. Commonly, used as antiemulation tricks.

## Functions ##

A function object exposes the following properties:

  * address: Physical offset of the function.
  * basic\_blocks: A list of basic block objects belonging to the function.
  * connections: A list of offsets to external functions and list of the function's internal connections (basic block's connections).
  * stats: Statistics about the current function. Namely, the number of basic blocks, edges and the ciclomatic complexity of the function.

# Notes #

Code analysis (this way) is only implemented in the Mercurial version (as of version 1.1.1). Deep code analysis is only implemented in the current (as of 2011) Mercurial version.