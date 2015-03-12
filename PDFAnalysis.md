# PDF Support #

# Features #

## Encoded streams ##
Pyew has good support for viewing PDF streams. Currently, there is support for the following encoders:

  * ASCIIHexDecode
  * FlateDecode
  * ASCII85Decode
  * LZWDecode
  * RunLengthDecode

Those 5 encoders are the most widely used ones to, typically, obfuscate JavaScript code inside PDF exploits.

## Obfuscation ##

Some typical obfuscation tricks in the PDF format involve encoding strings as a mix of hexadecimal, octal and ASCII strings. In the current version (as of 2010-04-22) Pyew supports strings encoded as hexadecimal and/or ASCII strings but not encoded as octal strings. Support for it will be added in future releases.

## Encryption ##

Pyew doesn't support encryption at the moment and I'm not sure when (if ever) will add support for encryption. If you really need it, tell me and I will know that someone is interested in this feature ;)

## JavaScript ##

Currently (as of 2010-04-22) there is no support to deobfuscate JavaScript code (like http://www.jsbeautifier.org) nor support to execute/emulate/interpret it, however, I plan to add support for it using python-spidermonkey or [PyV8](http://code.google.com/p/pyv8/).

# Examples #

To list the streams that are encoded and see what filters the stream is using type "pdfilter":

```
[0x00000000]> pdfilter
Stream 2 uses ASCIIHexDecode
Stream 2 uses FlateDecode
```

To list every stream in the PDF document use "pdfstream":

```
[0x00000000]> pdfstream
HINT[0x00000200]: stream..0 0 612 792re W* n....endstream..endobj..6 0 obj..<<
HINT[0x000002aa]: stream..789ced5dcd76ec280e7e953e77d573ce2cca807feacca38c6791
```

To list every object in the PDF document use "pdfobj":

```
[0x00000000]> pdfobj
HINT[0x00000011]: 1 0 obj
HINT[0x0000008f]: 2 0 obj
HINT[0x000000fa]: 3 0 obj
HINT[0x000001be]: 4 0 obj
HINT[0x000001e7]: 5 0 obj
HINT[0x00000231]: 6 0 obj
HINT[0x00000268]: 7 0 obj
HINT[0x00001bb7]: 14 0 obj
HINT[0x00001be7]: 10 0 obj
HINT[0x00001c31]: 15 0 obj
```

To seek to the position where a stream is type "pdfss". To seek to the position where an object is type "pdfso":

```
[0x00000000]> pdfstream
HINT[0x00000200]: stream..0 0 612 792re W* n....endstream..endobj..6 0 obj..<<
HINT[0x000002aa]: stream..789ced5dcd76ec280e7e953e77d573ce2cca807feacca38c6791
[0x00000000]> pdfss 2
[0x000002aa]>
[0x000002aa]> pdfobj
HINT[0x00000011]: 1 0 obj
HINT[0x0000008f]: 2 0 obj
HINT[0x000000fa]: 3 0 obj
HINT[0x000001be]: 4 0 obj
HINT[0x000001e7]: 5 0 obj
HINT[0x00000231]: 6 0 obj
HINT[0x00000268]: 7 0 obj
HINT[0x00001bb7]: 14 0 obj
HINT[0x00001be7]: 10 0 obj
HINT[0x00001c31]: 15 0 obj
[0x000002aa]> pdfso 14
[0x00001bb7]>
```

To see every stream deobfuscated and decompressed type "pdfvi" to see them consecutively in the console:

```
[0x00001bb7]> pdfvi
Stream 1
--------------------------------------------------------------------------------
0 0 612 792re W* n

--------------------------------------------------------------------------------
Continue? <<ENTER>>
Applying Filter ASCIIHexDecode ...
Applying Filter FlateDecode ...
Encoded Stream 2
--------------------------------------------------------------------------------
app["\x65\x76\x61\x6c"]("\x66\x75\x6e\x63\x74\x69...")
```

...or type "pdfview" to see them in a GUI:

[![](http://joxeankoret.com/blog/wp-content/uploads/2010/02/pdf1.png)](http://joxeankoret.com/blog/2010/02/21/analyzing-pdf-exploits-with-pyew/#more-95)

# Links #

You may find an interesting post about the PDF plugin [here](http://joxeankoret.com/blog/2010/02/21/analyzing-pdf-exploits-with-pyew/#more-95).