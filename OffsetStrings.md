# Introduction #

"Offseted strings" or just "offset strings" is the term used to define strings where each character is separated by some fixed number of characters between them.


# Details #

That's, let's imagine the following real example extracted from the TDSS rootkit's dropper:

```
[0x00000518:0x00401118]> c
0x00000518 (06) 008b 45b82b45        ADD [EBX+0x452bb845], CL
0x0000051e (04) c8 8b5d a8           ENTER 0x5d8b, 0xa8
0x00000522 (03) 8945 b8              MOV [EBP-0x48], EAX
0x00000525 (02) 03c6                 ADD EAX, ESI
0x00000527 (01) 50                   PUSH EAX
0x00000528 (03) 8d45 d8              LEA EAX, [EBP-0x28]
0x0000052b (01) 50                   PUSH EAX
0x0000052c (04) c645 d8 44           MOV BYTE [EBP-0x28], 0x44
0x00000530 (04) c645 d9 65           MOV BYTE [EBP-0x27], 0x65
0x00000534 (04) c645 da 6c           MOV BYTE [EBP-0x26], 0x6c
0x00000538 (04) c645 db 65           MOV BYTE [EBP-0x25], 0x65
0x0000053c (04) c645 dc 74           MOV BYTE [EBP-0x24], 0x74
0x00000540 (04) c645 dd 65           MOV BYTE [EBP-0x23], 0x65
0x00000544 (04) c645 de 46           MOV BYTE [EBP-0x22], 0x46
0x00000548 (04) c645 df 69           MOV BYTE [EBP-0x21], 0x69
0x0000054c (04) c645 e0 6c           MOV BYTE [EBP-0x20], 0x6c
0x00000550 (04) c645 e1 65           MOV BYTE [EBP-0x1f], 0x65
0x00000554 (04) c645 e2 41           MOV BYTE [EBP-0x1e], 0x41
0x00000558 (04) c645 e3 00           MOV BYTE [EBP-0x1d], 0x0
0x0000055c (05) e8 f1060000          CALL 0x00000c52    ; 1
```

The malware is creating one string at runtime to pass as parameter to the function at physical offset 0x00000c52. This strings is created by simply moving to the desired offset byte per byte the string. The offseted string search offers a way to detect those strings created this way. In this example, if we execute the command "/o" we get the following strings:

```
[0x00000518:0x00401118]> /o
HINT[0x00000523]: EPPDeleteFileA
HINT[0x000006a4]: PPDeleteFileW
(...)
```

So, this malware is creating the strings "DeleteFileA" and "DeleteFileW" at runtime using the MOV OFFSET, CHAR technique and Pyew found the strings. Another example extracted from the same malware but different sample:

```
[0x0000063c:0x1000123c]> c
0x0000063c (01) 50                   PUSH EAX
0x0000063d (04) c645 e3 72           MOV BYTE [EBP-0x1d], 0x72
0x00000641 (04) c645 e4 65           MOV BYTE [EBP-0x1c], 0x65
0x00000645 (04) c645 e5 70           MOV BYTE [EBP-0x1b], 0x70
0x00000649 (04) c645 e6 61           MOV BYTE [EBP-0x1a], 0x61
0x0000064d (04) c645 e7 72           MOV BYTE [EBP-0x19], 0x72
0x00000651 (04) c645 e8 65           MOV BYTE [EBP-0x18], 0x65
0x00000655 (04) c645 e9 4d           MOV BYTE [EBP-0x17], 0x4d
0x00000659 (04) c645 ea 64           MOV BYTE [EBP-0x16], 0x64
0x0000065d (04) c645 eb 6c           MOV BYTE [EBP-0x15], 0x6c
0x00000661 (04) c645 ec 57           MOV BYTE [EBP-0x14], 0x57
0x00000665 (04) c645 ed 72           MOV BYTE [EBP-0x13], 0x72
0x00000669 (04) c645 ee 69           MOV BYTE [EBP-0x12], 0x69
0x0000066d (04) c645 ef 74           MOV BYTE [EBP-0x11], 0x74
0x00000671 (04) c645 f0 65           MOV BYTE [EBP-0x10], 0x65
0x00000675 (04) c645 f1 00           MOV BYTE [EBP-0xf], 0x0
0x00000679 (05) e8 ea000000          CALL 0x00000768    ; 1
0x0000067e (03) 8b45 b0              MOV EAX, [EBP-0x50]
0x00000681 (02) 8bd8                 MOV EBX, EAX
0x00000683 (03) 0345 b8              ADD EAX, [EBP-0x48]
0x00000686 (01) 53                   PUSH EBX
0x00000687 (01) 56                   PUSH ESI
0x00000688 (03) 8945 b0              MOV [EBP-0x50], EAX
0x0000068b (05) e8 a6010000          CALL 0x00000836    ; 2
0x00000690 (03) 8b45 c0              MOV EAX, [EBP-0x40]
0x00000693 (03) 8b73 3c              MOV ESI, [EBX+0x3c]
0x00000696 (04) 8365 f4 00           AND DWORD [EBP-0xc], 0x0
0x0000069a (03) 8d0c18               LEA ECX, [EAX+EBX]
0x0000069d (02) 03f3                 ADD ESI, EBX
0x0000069f (02) 8bc3                 MOV EAX, EBX
0x000006a1 (03) 2b46 34              SUB EAX, [ESI+0x34]
0x000006a4 (03) 8339 00              CMP DWORD [ECX], 0x0
0x000006a7 (06) 0f86 26000000        JBE 0x000006d3     ; 3
0x000006a7 ---------------------------------------------------
0x000006ad (03) 8d51 04              LEA EDX, [ECX+0x4]
0x000006b0 (03) 8955 fc              MOV [EBP-0x4], EDX
0x000006b3 (03) 8b55 fc              MOV EDX, [EBP-0x4]
0x000006b6 (02) 8b12                 MOV EDX, [EDX]
0x000006b8 (04) 8345 fc 01           ADD DWORD [EBP-0x4], 0x1
0x000006bc (05) 836c65 fc fd         SUB DWORD [EBP-0x4], -0x3

[0x0000063c:0x1000123c]> /o
HINT[0x0000063c]: PrepareMdlWrite
HINT[0x000006f7]: CcPreparePinWrite
(...)
```

This malware is creating the strings "PrepareMdlWrite" and "CcPreparePinWrite" using this technique as we found using Pyew.

## Notes ##

The "offseted string" search, by default, search strings separated by a number of 4 characters. This option can be changed using the configuration parameter "pyew.deltaoffset". You may also change the minimun size of the string to be considered with the configuration parameter "pyew.minoffsetsize".