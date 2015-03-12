# Introduction #

## PEFILE: global name 'Decode32Bits' is not defined ##

You need to install diStorm64 version 2. You can download it [here](http://code.google.com/p/pyew/downloads/detail?name=distorm64-pkg1.7.30.zip&can=2&q=).

A compiled DLL for Windows is distributed with every Win32's package.

If this is not your problem and you get this error, report it to me plz!

## Cannot import capstone, Pyew will not have disassembly support. ##

The error message is the following:

```
$ pyew /something
Cannot import capstone, Pyew will not have disassembly support.
Please install it manually from http://www.capstone-engine.org/
```

It says it all! Just download Capstone from its repository and install both the library and the Python bindings.