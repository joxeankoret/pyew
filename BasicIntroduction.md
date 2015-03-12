# Introduction #

To start using Pyew, run it this way:

```
$ ./pyew.py filename
```

When you open a file with Pyew the first 512 bytes block (by default, specified by the configuration parameter pyew.bsize) is show in hexadecimal mode:

```
$ ./pyew.py a.html
0000   0D 0A 3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C    ..<!DOCTYPE html
0010   20 50 55 42 4C 49 43 20 22 2D 2F 2F 57 33 43 2F     PUBLIC "-//W3C/
0020   2F 44 54 44 20 58 48 54 4D 4C 20 31 2E 30 20 54    /DTD XHTML 1.0 T
0030   72 61 6E 73 69 74 69 6F 6E 61 6C 2F 2F 45 4E 22    ransitional//EN"
0040   20 22 68 74 74 70 3A 2F 2F 77 77 77 2E 77 33 2E     "http://www.w3.
0050   6F 72 67 2F 54 52 2F 78 68 74 6D 6C 31 2F 44 54    org/TR/xhtml1/DT
0060   44 2F 78 68 74 6D 6C 31 2D 74 72 61 6E 73 69 74    D/xhtml1-transit
0070   69 6F 6E 61 6C 2E 64 74 64 22 3E 0D 0A 3C 68 74    ional.dtd">..<ht
0080   6D 6C 20 78 6D 6C 6E 73 3D 22 68 74 74 70 3A 2F    ml xmlns="http:/
0090   2F 77 77 77 2E 77 33 2E 6F 72 67 2F 31 39 39 39    /www.w3.org/1999
00A0   2F 78 68 74 6D 6C 22 3E 0D 0A 3C 68 65 61 64 20    /xhtml">..<head
00B0   69 64 3D 22 63 74 6C 30 30 5F 48 65 61 64 31 22    id="ctl00_Head1"
00C0   3E 0D 0A 20 20 20 20 3C 74 69 74 6C 65 3E 0D 0A    >..    <title>..
00D0   09 43 72 65 61 74 65 50 72 6F 63 65 73 73 20 2D    .CreateProcess -
00E0   20 4D 53 44 4E 20 53 65 61 72 63 68 0D 0A 3C 2F     MSDN Search..</
00F0   74 69 74 6C 65 3E 0D 0A 20 20 20 20 3C 6C 69 6E    title>..    <lin
0100   6B 20 72 65 6C 3D 22 73 68 6F 72 74 63 75 74 20    k rel="shortcut
0110   69 63 6F 6E 22 20 68 72 65 66 3D 22 68 74 74 70    icon" href="http
0120   3A 2F 2F 69 34 2E 73 6F 63 69 61 6C 2E 6D 69 63    ://i4.social.mic
0130   72 6F 73 6F 66 74 2E 63 6F 6D 2F 53 65 61 72 63    rosoft.com/Searc
0140   68 2F 47 6C 6F 62 61 6C 52 65 73 6F 75 72 63 65    h/GlobalResource
0150   73 2F 69 6D 61 67 65 73 2F 4D 73 64 6E 2F 66 61    s/images/Msdn/fa
0160   76 69 63 6F 6E 2E 69 63 6F 3F 63 76 65 72 3D 32    vicon.ico?cver=2
0170   2E 36 2E 30 30 32 38 2E 30 31 22 20 74 79 70 65    .6.0028.01" type
0180   3D 22 69 6D 61 67 65 2F 78 2D 69 63 6F 6E 22 20    ="image/x-icon"
0190   2F 3E 20 0D 0A 20 20 20 20 3C 6C 69 6E 6B 20 74    /> ..    <link t
01A0   79 70 65 3D 22 74 65 78 74 2F 63 73 73 22 20 72    ype="text/css" r
01B0   65 6C 3D 22 53 74 79 6C 65 73 68 65 65 74 22 20    el="Stylesheet"
01C0   68 72 65 66 3D 22 68 74 74 70 3A 2F 2F 69 34 2E    href="http://i4.
01D0   73 6F 63 69 61 6C 2E 6D 69 63 72 6F 73 6F 66 74    social.microsoft
01E0   2E 63 6F 6D 2F 53 65 61 72 63 68 2F 47 6C 6F 62    .com/Search/Glob
01F0   61 6C 52 65 73 6F 75 72 63 65 73 2F 73 74 79 6C    alResources/styl
```

After this block of hexadecimal data you will see the Pyew's prompt:

```
[0x00000000]>
```

The prompt is the (hexadecimal) offset in the file. Now, to see help, type "?":

```
[0x00000000]> ?
PYEW! A Python tool like *iew 1.0

Commands:

?/help                            Show this help
x/dump/hexdump                    Show hexadecimal dump
s/seek                            Seek to a new offset
g/G                               Goto BOF (g) or EOF (G)
+/-                               Go forward/backward one block (specified by pyew.bsize)
c/d/dis/pd                        Show disassembly
r/repr                            Show string represantation
p                                 Print the buffer
/x expr                           Search hexadecimal string
/s expr                           Search strings
/i expr                           Search string ignoring case
/r expr                           Search regular expression
/u expr                           Search unicode expression
/U expr                           Search unicode expression ignoring case

Cryptographic functions: md5, sha1, sha224, sha256, sha384, sha512

Examples:
[0x0]> md5
md5: d37b6d42a04cbc04cb2988ed947a5b0d
[0x0]> md5(pyew.buf[0:7])
581fd4acfc2214aa246f0b47c8ae8a4e
[0x0]> md5(pyew.buf[15:35])
a73b2882dd918070c6e8dfd9081fb600

Current configuration options:

pyew.bsize           : 512
pyew.calls           : []
pyew.codeanalysis    : True
pyew.ep              : 0
pyew.f               : <open file 'a.html', mode 'rb' at 0x833e4e8>
pyew.filename        : a.html
pyew.hexcolumns      : 16
pyew.lastasmoffset   : 0
pyew.lines           : 40
pyew.maxfilesize     : 1073741824
pyew.maxsize         : 95699
pyew.mode            : rb
pyew.offset          : 0
pyew.physical        : True
pyew.previousoffset  : [0]
pyew.processor       : intel
pyew.type            : 32

Pyew Plugins:

url       Search URLs in the current document
chkurl    Check URLs of the current file
threat    Search in Threat Expert for the behavior's report
antivm    Search for common antivm tricks
sc        Search for shellcode
pdf       Get the information about the PDF
ole       Get the OLE2 directory

Any other expression will be evaled as a Python expression
```

Now, we will move to the offset 100 in decimal (note that you can use hexadecimal offsets) to see the hexadecimal dump of the block at this specific position by issuing the command "s 100" (which means: "seek to position 100") and "x" (hexadecimal dump):

```
[0x00000000]> s 100
[0x00000064]> x
0064   74 6D 6C 31 2D 74 72 61 6E 73 69 74 69 6F 6E 61    tml1-transitiona
0074   6C 2E 64 74 64 22 3E 0D 0A 3C 68 74 6D 6C 20 78    l.dtd">..<html x
0084   6D 6C 6E 73 3D 22 68 74 74 70 3A 2F 2F 77 77 77    mlns="http://www
0094   2E 77 33 2E 6F 72 67 2F 31 39 39 39 2F 78 68 74    .w3.org/1999/xht
00A4   6D 6C 22 3E 0D 0A 3C 68 65 61 64 20 69 64 3D 22    ml">..<head id="
00B4   63 74 6C 30 30 5F 48 65 61 64 31 22 3E 0D 0A 20    ctl00_Head1">..
00C4   20 20 20 3C 74 69 74 6C 65 3E 0D 0A 09 43 72 65       <title>...Cre
00D4   61 74 65 50 72 6F 63 65 73 73 20 2D 20 4D 53 44    ateProcess - MSD
00E4   4E 20 53 65 61 72 63 68 0D 0A 3C 2F 74 69 74 6C    N Search..</titl
00F4   65 3E 0D 0A 20 20 20 20 3C 6C 69 6E 6B 20 72 65    e>..    <link re
0104   6C 3D 22 73 68 6F 72 74 63 75 74 20 69 63 6F 6E    l="shortcut icon
0114   22 20 68 72 65 66 3D 22 68 74 74 70 3A 2F 2F 69    " href="http://i
0124   34 2E 73 6F 63 69 61 6C 2E 6D 69 63 72 6F 73 6F    4.social.microso
0134   66 74 2E 63 6F 6D 2F 53 65 61 72 63 68 2F 47 6C    ft.com/Search/Gl
0144   6F 62 61 6C 52 65 73 6F 75 72 63 65 73 2F 69 6D    obalResources/im
0154   61 67 65 73 2F 4D 73 64 6E 2F 66 61 76 69 63 6F    ages/Msdn/favico
0164   6E 2E 69 63 6F 3F 63 76 65 72 3D 32 2E 36 2E 30    n.ico?cver=2.6.0
0174   30 32 38 2E 30 31 22 20 74 79 70 65 3D 22 69 6D    028.01" type="im
0184   61 67 65 2F 78 2D 69 63 6F 6E 22 20 2F 3E 20 0D    age/x-icon" /> .
0194   0A 20 20 20 20 3C 6C 69 6E 6B 20 74 79 70 65 3D    .    <link type=
01A4   22 74 65 78 74 2F 63 73 73 22 20 72 65 6C 3D 22    "text/css" rel="
01B4   53 74 79 6C 65 73 68 65 65 74 22 20 68 72 65 66    Stylesheet" href
01C4   3D 22 68 74 74 70 3A 2F 2F 69 34 2E 73 6F 63 69    ="http://i4.soci
01D4   61 6C 2E 6D 69 63 72 6F 73 6F 66 74 2E 63 6F 6D    al.microsoft.com
01E4   2F 53 65 61 72 63 68 2F 47 6C 6F 62 61 6C 52 65    /Search/GlobalRe
01F4   73 6F 75 72 63 65 73 2F 73 74 79 6C 65 73 2F 4D    sources/styles/M
0204   61 73 74 65 72 50 61 67 65 2E 63 73 73 3F 63 76    asterPage.css?cv
0214   65 72 3D 32 2E 36 2E 30 30 32 38 2E 30 31 22 20    er=2.6.0028.01"
0224   2F 3E 0D 0A 20 20 20 20 3C 6C 69 6E 6B 20 74 79    />..    <link ty
0234   70 65 3D 22 74 65 78 74 2F 63 73 73 22 20 72 65    pe="text/css" re
0244   6C 3D 22 53 74 79 6C 65 73 68 65 65 74 22 20 68    l="Stylesheet" h
0254   72 65 66 3D 22 68 74 74 70 3A 2F 2F 69 31 2E 73    ref="http://i1.s
```

Uhm..., the block's size is too big, I will change it to see a smaller hexadecimal dump:

```
[0x00000064]> pyew.bsize = 64
[0x00000064]> x
0064   74 6D 6C 31 2D 74 72 61 6E 73 69 74 69 6F 6E 61    tml1-transitiona
0074   6C 2E 64 74 64 22 3E 0D 0A 3C 68 74 6D 6C 20 78    l.dtd">..<html x
0084   6D 6C 6E 73 3D 22 68 74 74 70 3A 2F 2F 77 77 77    mlns="http://www
0094   2E 77 33 2E 6F 72 67 2F 31 39 39 39 2F 78 68 74    .w3.org/1999/xht
```

Next usage example: How can I get a disassembly of this block? Just type the command "c" (or "d", "dis" or "pd"):

```
[0x00000064]> c
0x00000064 (02) 74 6d                JZ 0x000000d3      ; 1
0x00000066 (01) 6c                   INSB
0x00000067 (06) 312d 7472616e        XOR [0x6e617274], EBP
0x0000006d (02) 73 69                JAE 0x000000d8     ; 2
0x0000006f (02) 74 69                JZ 0x000000da      ; 3
0x00000071 (01) 6f                   OUTSD
0x00000072 (01) 6e                   OUTSB
0x00000073 (01) 61                   POPA
0x00000074 (01) 6c                   INSB
0x00000075 (01) 2e                   DB 0x2e
0x00000076 (01) 64                   DB 0x64
0x00000076 (03) 64 74 64             JZ 0x000000dd      ; 4
0x00000079 (02) 223e                 AND BH, [ESI]
0x0000007b (05) 0d 0a3c6874          OR EAX, 0x74683c0a
0x00000080 (01) 6d                   INSD
0x00000081 (01) 6c                   INSB
0x00000082 (03) 2078 6d              AND [EAX+0x6d], BH
0x00000085 (01) 6c                   INSB
0x00000086 (01) 6e                   OUTSB
0x00000087 (02) 73 3d                JAE 0x000000c6     ; 5
0x00000089 (03) 2268 74              AND CH, [EAX+0x74]
0x0000008c (02) 74 70                JZ 0x000000fe      ; 6
0x0000008e (02) 3a2f                 CMP CH, [EDI]
0x00000090 (01) 2f                   DAS
0x00000091 (02) 77 77                JA 0x0000010a      ; 7
0x00000093 (02) 77 2e                JA 0x000000c3      ; 8
```

As is obvious, this code doesn't make sense but, anyway, you may use this to discover shellcodes inside a file ;) Next step: How can I list all the URLs inside a file? Issue the command "url":

```
[0x00000064]> url
ASCII URLs

http://www.w3.org/1999/xhtml
http://XXXX.com/Search/GlobalResources/images/Msdn/favicon.ico?cver=2.6.0028.01
http://XXXX.com/Search/GlobalResources/styles/MasterPage.css?cver=2.6.0028.01
(...more...)

UNICODE URLs

http://www.omniture.com
```

OK. Now, I want to check the URLs for availability. To do this, issue the command "chkurl":

```
[0x00000064]> chkurl
Checking http://XXX.com/?linkid=8103551 ... OK
Checking http://XXX.com/Search/el ... OK
(...)
```