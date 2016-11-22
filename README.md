Pyew is a (command line) python tool to analyse malware. It does have support for hexadecimal viewing, disassembly (Intel 16, 32 and 64 bits), PE and ELF file formats (it performs code analysis and let you write scripts using an API to perform many types of analysis), follows direct call/jmp instructions in the interactive command line, displays function names and string data references; supports OLE2 format, PDF format and more. It also supports plugins to add more features to the tool.

Pyew have been successfully used in big malware analysis systems since almost 4 years, processing thousand of files daily.

See some [usage examples](UsageExample.md), example [batch](BatchExample.md) scripts or a [tool](GCluster.md) to compare and group programs (PE and ELF) using the API provided by Pyew.

NOTE: It's highly recommended to always use the Mercurial version (and the [branch 3.X](https://code.google.com/p/pyew/source/browse/?name=VERSION_3X)) instead of the versions available in the Downloads section.

ChangeLog:

Version 3.X (In development)

  * Dropped diStorm support.
  * Added support for [Capstone](http://www.capstone-engine.org/). Pyew now supports all the [architectures supported by Capstone](http://www.capstone-engine.org/arch.html).
Version 2.3 Stable (01-13-2014)

  * Many stability fixes to the x86 code analysis engine.
  * Refactorization of many parts of the code analysis engine.
  * Added support for command "ws" to patch files with null terminated strings.
  * Corrected version number and copyright notices.

Version 2.2 Stable (12-30-2012)

  * Loads of bug fixes.
  * Many little enhancements to the x86 code analysis engine, notoriously increasing the overall speed and finding more functions and basic blocks missed in previous versions.
  * Updated PEFile version to 1.2.10.
  * Support for 2 more disassembly engines: diStorm v3 and pymsasid (pure python disassembler).
  * Automatic calculation of the application call graph and function's flow graphs.
  * Support for analysing x86 boot sector files.

Version 2.1 Beta (11-27-2011)

  * Added Kenshoto's VTrace.
  * Initial support for integrated debugging.
  * Good support for ELF file format (both 32 and 64 bits).
  * Code analysis engine enhanced.
  * Fixed a lot of bugs.

Version 2.0

  * Code analysis system for x86 rewritten from scratch.
  * Support for databases. You can analyze binaries (PE or ELF) and save/open databases.
  * Added graph's based clusterization tool 'gcluster.py'.
  * Added new PDF utilities:
    * `pdfss`: Seek to one stream
    * `pdfobj`: Show object's list
    * `pdfso`: Seek to one object
  * Added new plugins:
    * `binvi`: Show an image representing the contents of the file. Usefull to see different sections in a binary.
    * `packer`: Check if the PE file is packed
    * `cgraph`: Show the callgraph of the whole program (needs PyGTK to show a GUI).
  * Many bug fixes.

Version 1.1.1

  * Support for ELF file formats (AMD64 and IA32) using the [Kenshoto's ELF library (VTrace)](http://www.kenshoto.com/vtrace/).
  * Code analysis by recursively traversing all possible code paths from entry points.
  * Added the following APIS:
    * `resolveName`: Resolves the internal name of the given address/offset.
    * `NextHead`: Return the next disassembly offset given an address/offset.
    * `GetMnem/GetMnems`: Returns the mnemonic or mnemonic list given an offset and the number of mnemonics to retrieve.

Pyew is very similar in some aspects to the following tools:

  * The Interactive Disassembler [(IDA)](http://www.hex-rays.com/products/ida/). Although Pyew does not compete with IDA (and the author of the tool doesn't want it at all), it can be considered as a "mini IDA" focused on batch malware analysis.
  * The almighty [radare](http://www.radare.org).
  * The open source [Biew](http://biew.sourceforge.net/) and the commercial [Hiew](http://www.hiew.ru/).