## Analyzing a PE file ##

Open the PE file you want to analyze:

```
$ ./pyew.py test.exe
PE Information

Sections:
   .text 0x1000 0x6f0 2048
   .data 0x2000 0x34 512
   .rdata 0x3000 0x80 512
   .bss 0x4000 0x60 0
   .idata 0x5000 0x29c 1024
   .stab 0x6000 0x6a20 27648
   .stabstr 0xd000 0x26970 158208

Entry Point at 0x620
Code Analysis ...

0000   4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00    MZ..............
0010   B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......
0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0030   00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00    ................
0040   0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68    ........!..L.!Th
0050   69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F    is program canno
0060   74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20    t be run in DOS
0070   6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00    mode....$.......
0080   50 45 00 00 4C 01 07 00 7A FF 98 4A 00 EA 02 00    PE..L...z..J....
0090   90 01 00 00 E0 00 07 01 0B 01 02 38 00 08 00 00    ...........8....
00A0   00 08 00 00 00 02 00 00 20 12 00 00 00 10 00 00    ........ .......
00B0   00 20 00 00 00 00 40 00 00 10 00 00 00 02 00 00    . ....@.........
00C0   04 00 00 00 01 00 00 00 04 00 00 00 00 00 00 00    ................
00D0   00 40 03 00 00 04 00 00 B5 B3 03 00 03 00 00 00    .@..............
00E0   00 00 20 00 00 10 00 00 00 00 10 00 00 10 00 00    .. .............
00F0   00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00    ................
0100   00 50 00 00 9C 02 00 00 00 00 00 00 00 00 00 00    .P..............
0110   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0120   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0130   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0140   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0150   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0160   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0170   00 00 00 00 00 00 00 00 2E 74 65 78 74 00 00 00    .........text...
0180   F0 06 00 00 00 10 00 00 00 08 00 00 00 04 00 00    ................
0190   00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60    ............ ..`
01A0   2E 64 61 74 61 00 00 00 34 00 00 00 00 20 00 00    .data...4.... ..
01B0   00 02 00 00 00 0C 00 00 00 00 00 00 00 00 00 00    ................
01C0   00 00 00 00 40 00 00 C0 2E 72 64 61 74 61 00 00    ....@....rdata..
01D0   80 00 00 00 00 30 00 00 00 02 00 00 00 0E 00 00    .....0..........
01E0   00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40    ............@..@
01F0   2E 62 73 73 00 00 00 00 60 00 00 00 00 40 00 00    .bss....`....@..
```

As you may see, very basic information is displayed when opening the file: file format, sections, entry point address and the first block (512 bytes) of hexadecimal data. Now, let's see the disassembly at the entry point so, <b>s</b>eek to the <b>e</b>ntry <b>p</b>oint:

```
[0x00000000]> s ep
```

And disassemble it with the command "c" (you may also use "d", "dis" or "pd"):

```
[0x00000620]> c
0x00000620 (01) 55                   PUSH EBP   ; Function sub_00000620
0x00000621 (02) 89e5                 MOV EBP, ESP
0x00000623 (03) 83ec 14              SUB ESP, 0x14
0x00000626 (02) 6a 01                PUSH 0x1
0x00000628 (06) ff15 c8504000        CALL msvcrt.dll!__set_app_type
0x0000062e (05) e8 ddfeffff          CALL 0x00000510    ; 1 sub_00000510
0x00000633 (06) 8db6 00000000        LEA ESI, [ESI+0x0]
0x00000639 (07) 8dbc27 00000000      LEA EDI, [EDI+0x0]
0x00000640 (01) 55                   PUSH EBP   ; Function sub_00000640
0x00000641 (02) 89e5                 MOV EBP, ESP
0x00000643 (03) 83ec 14              SUB ESP, 0x14
0x00000646 (02) 6a 02                PUSH 0x2
0x00000648 (06) ff15 c8504000        CALL msvcrt.dll!__set_app_type
0x0000064e (05) e8 bdfeffff          CALL 0x00000510    ; 2 sub_00000510
0x00000653 (06) 8db6 00000000        LEA ESI, [ESI+0x0]
0x00000659 (07) 8dbc27 00000000      LEA EDI, [EDI+0x0]
0x00000660 (01) 55                   PUSH EBP
0x00000661 (06) 8b0d dc504000        MOV ECX, [0x4050dc]
0x00000667 (02) 89e5                 MOV EBP, ESP
0x00000669 (01) 5d                   POP EBP
0x0000066a (02) ffe1                 JMP ECX
0x0000066c (04) 8d7426 00            LEA ESI, [ESI+0x0]
0x00000670 (01) 55                   PUSH EBP
0x00000671 (06) 8b0d d4504000        MOV ECX, [0x4050d4]
0x00000677 (02) 89e5                 MOV EBP, ESP
0x00000679 (01) 5d                   POP EBP
0x0000067a (02) ffe1                 JMP ECX
0x0000067c (01) 90                   NOP
0x0000067d (01) 90                   NOP
0x0000067e (01) 90                   NOP
0x0000067f (01) 90                   NOP
0x00000680 (01) 55                   PUSH EBP   ; Function sub_00000680
0x00000681 (02) 89e5                 MOV EBP, ESP
0x00000683 (03) 83ec 08              SUB ESP, 0x8
0x00000686 (05) a1 30204000          MOV EAX, [0x402030]
0x0000068b (02) 85c0                 TEST EAX, EAX
0x0000068d (02) 74 3b                JZ 0x000006ca      ; 3
0x0000068f (03) 83ec 0c              SUB ESP, 0xc
0x00000692 (05) 68 00304000          PUSH 0x403000
0x00000697 (05) e8 24040000          CALL 0x00000ac0    ; 4
```

OK, at the entry point we see 2 functions (sub\_00000620 and sub\_00000680) detected by Pyew and also we find a call to the MSVCRT.dll exported function set\_app\_type. It looks like a typical Visual C++ compiled executable file. After this call we have another one that's goes inside the PE binary, which is, by the way, also detected by Pyew. To see the code at the function's position, as in Hiew, just type the number assigned to the function (the number after the ";" character):

```
[0x00000620]> 1
0x00000510 (01) 55                   PUSH EBP   ; Function sub_00000510
0x00000511 (02) 89e5                 MOV EBP, ESP
0x00000513 (01) 53                   PUSH EBX
0x00000514 (03) 83ec 20              SUB ESP, 0x20
0x00000517 (05) 68 00104000          PUSH 0x401000
0x0000051c (05) e8 8f050000          CALL 0x00000ab0    ; 1
0x00000521 (03) 83c4 0c              ADD ESP, 0xc
0x00000524 (05) e8 77030000          CALL 0x000008a0    ; 2 sub_000008a0
0x00000529 (05) e8 92040000          CALL 0x000009c0    ; 3 sub_000009c0
0x0000052e (03) 83ec 0c              SUB ESP, 0xc
0x00000531 (03) 8d45 f8              LEA EAX, [EBP-0x8]
0x00000534 (07) c745 f8 00000000     MOV DWORD [EBP-0x8], 0x0
0x0000053b (01) 50                   PUSH EAX
0x0000053c (03) 8d45 f4              LEA EAX, [EBP-0xc]
0x0000053f (06) 8b1d 10204000        MOV EBX, [0x402010]
0x00000545 (01) 53                   PUSH EBX
0x00000546 (01) 50                   PUSH EAX
0x00000547 (05) 68 00404000          PUSH 0x404000
0x0000054c (05) 68 04404000          PUSH 0x404004
0x00000551 (05) e8 ca040000          CALL 0x00000a20    ; 4
0x00000556 (05) a1 10404000          MOV EAX, [0x404010]
0x0000055b (03) 83c4 20              ADD ESP, 0x20
0x0000055e (02) 85c0                 TEST EAX, EAX
0x00000560 (02) 74 4e                JZ 0x000005b0      ; 5
0x00000562 (06) 8b15 d0504000        MOV EDX, [0x4050d0]
0x00000568 (05) a3 20204000          MOV [0x402020], EAX
0x0000056d (02) 85d2                 TEST EDX, EDX
0x0000056f (06) 0f85 83000000        JNZ 0x000005f8     ; 6
0x00000575 (03) 83fa e0              CMP EDX, -0x20
0x00000578 (02) 74 1a                JZ 0x00000594      ; 7
0x0000057a (01) 50                   PUSH EAX
0x0000057b (01) 50                   PUSH EAX
0x0000057c (05) a1 10404000          MOV EAX, [0x404010]
0x00000581 (01) 50                   PUSH EAX
0x00000582 (03) 8b42 30              MOV EAX, [EDX+0x30]
0x00000585 (01) 50                   PUSH EAX
0x00000586 (05) e8 85040000          CALL 0x00000a10    ; 8
0x0000058b (03) 83c4 10              ADD ESP, 0x10
0x0000058e (06) 8b15 d0504000        MOV EDX, [0x4050d0]
0x00000594 (03) 83fa c0              CMP EDX, -0x40
```

OK, we're done analyzing this function. To go back to the prior point (the entry point in our case) we can type "b" to go <b>b</b>ack:

```
[0x00000510]> b
0x00000620 (01) 55                   PUSH EBP   ; Function sub_00000620
0x00000621 (02) 89e5                 MOV EBP, ESP
0x00000623 (03) 83ec 14              SUB ESP, 0x14
0x00000626 (02) 6a 01                PUSH 0x1
0x00000628 (06) ff15 c8504000        CALL msvcrt.dll!__set_app_type
0x0000062e (05) e8 ddfeffff          CALL 0x00000510    ; 1 sub_00000510
0x00000633 (06) 8db6 00000000        LEA ESI, [ESI+0x0]
0x00000639 (07) 8dbc27 00000000      LEA EDI, [EDI+0x0]
0x00000640 (01) 55                   PUSH EBP   ; Function sub_00000640
0x00000641 (02) 89e5                 MOV EBP, ESP
0x00000643 (03) 83ec 14              SUB ESP, 0x14
0x00000646 (02) 6a 02                PUSH 0x2
0x00000648 (06) ff15 c8504000        CALL msvcrt.dll!__set_app_type
0x0000064e (05) e8 bdfeffff          CALL 0x00000510    ; 2 sub_00000510
0x00000653 (06) 8db6 00000000        LEA ESI, [ESI+0x0]
0x00000659 (07) 8dbc27 00000000      LEA EDI, [EDI+0x0]
0x00000660 (01) 55                   PUSH EBP
0x00000661 (06) 8b0d dc504000        MOV ECX, [0x4050dc]
0x00000667 (02) 89e5                 MOV EBP, ESP
0x00000669 (01) 5d                   POP EBP
0x0000066a (02) ffe1                 JMP ECX
0x0000066c (04) 8d7426 00            LEA ESI, [ESI+0x0]
0x00000670 (01) 55                   PUSH EBP
0x00000671 (06) 8b0d d4504000        MOV ECX, [0x4050d4]
0x00000677 (02) 89e5                 MOV EBP, ESP
0x00000679 (01) 5d                   POP EBP
0x0000067a (02) ffe1                 JMP ECX
0x0000067c (01) 90                   NOP
0x0000067d (01) 90                   NOP
0x0000067e (01) 90                   NOP
0x0000067f (01) 90                   NOP
0x00000680 (01) 55                   PUSH EBP   ; Function sub_00000680
0x00000681 (02) 89e5                 MOV EBP, ESP
0x00000683 (03) 83ec 08              SUB ESP, 0x8
0x00000686 (05) a1 30204000          MOV EAX, [0x402030]
0x0000068b (02) 85c0                 TEST EAX, EAX
0x0000068d (02) 74 3b                JZ 0x000006ca      ; 3
0x0000068f (03) 83ec 0c              SUB ESP, 0xc
0x00000692 (05) 68 00304000          PUSH 0x403000
0x00000697 (05) e8 24040000          CALL 0x00000ac0    ; 4
```

To continue seeing more disassembly just press the enter key to see the next block's disasembly (BTW, if the last command was "x" to show the hexadecimal dump, by pressing enter you would see the next block's hexadecimal dump):

```
[0x00000620]>
0x0000069c (02) 89c2                 MOV EDX, EAX
0x0000069e (03) 83c4 0c              ADD ESP, 0xc
0x000006a1 (05) b8 00000000          MOV EAX, 0x0
0x000006a6 (02) 85d2                 TEST EDX, EDX
0x000006a8 (02) 74 0f                JZ 0x000006b9      ; 1
0x000006aa (01) 50                   PUSH EAX
0x000006ab (01) 50                   PUSH EAX
0x000006ac (05) 68 0d304000          PUSH 0x40300d
0x000006b1 (01) 52                   PUSH EDX
0x000006b2 (05) e8 19040000          CALL 0x00000ad0    ; 2
0x000006b7 (01) 5a                   POP EDX
0x000006b8 (01) 59                   POP ECX
0x000006b9 (02) 85c0                 TEST EAX, EAX
0x000006bb (02) 74 0d                JZ 0x000006ca      ; 3
0x000006bd (03) 83ec 0c              SUB ESP, 0xc
0x000006c0 (05) 68 30204000          PUSH 0x402030
0x000006c5 (02) ffd0                 CALL EAX
0x000006c7 (03) 83c4 10              ADD ESP, 0x10
0x000006ca (01) c9                   LEAVE
0x000006cb (01) c3                   RET
0x000006cc (04) 8d7426 00            LEA ESI, [ESI+0x0]
0x000006d0 (01) 55                   PUSH EBP   ; Function sub_000006d0
0x000006d1 (02) 89e5                 MOV EBP, ESP
0x000006d3 (01) 5d                   POP EBP
0x000006d4 (01) c3                   RET
0x000006d5 (04) 8d7426 00            LEA ESI, [ESI+0x0]
0x000006d9 (07) 8dbc27 00000000      LEA EDI, [EDI+0x0]
0x000006e0 (01) 55                   PUSH EBP   ; Function sub_000006e0
0x000006e1 (02) 89e5                 MOV EBP, ESP
0x000006e3 (03) 83ec 08              SUB ESP, 0x8
0x000006e6 (05) a1 04204000          MOV EAX, [0x402004]
0x000006eb (02) 8b00                 MOV EAX, [EAX]
0x000006ed (02) 85c0                 TEST EAX, EAX
0x000006ef (02) 74 15                JZ 0x00000706      ; 4
0x000006f1 (02) ffd0                 CALL EAX
0x000006f3 (05) a1 04204000          MOV EAX, [0x402004]
0x000006f8 (03) 83c0 04              ADD EAX, 0x4
0x000006fb (05) a3 04204000          MOV [0x402004], EAX
0x00000700 (02) 8b00                 MOV EAX, [EAX]
0x00000702 (02) 85c0                 TEST EAX, EAX
```

Press enter again to continue advancing one block (specified with the parameter pyew.bsize with a default value of 512 bytes).

```
[0x0000069c]>
0x00000704 (02) 75 eb                JNZ 0x000006f1     ; 1
0x00000706 (01) c9                   LEAVE
0x00000707 (01) c3                   RET
0x00000708 (01) 90                   NOP
0x00000709 (07) 8db426 00000000      LEA ESI, [ESI+0x0]
0x00000710 (01) 55                   PUSH EBP   ; Function sub_00000710
0x00000711 (02) 89e5                 MOV EBP, ESP
0x00000713 (01) 56                   PUSH ESI
0x00000714 (01) 53                   PUSH EBX
0x00000715 (06) 8b0d 00204000        MOV ECX, [0x402000]
0x0000071b (02) 85c9                 TEST ECX, ECX
0x0000071d (02) 74 07                JZ 0x00000726      ; 2
0x0000071f (03) 8d65 f8              LEA ESP, [EBP-0x8]
0x00000722 (01) 5b                   POP EBX
0x00000723 (01) 5e                   POP ESI
0x00000724 (01) 5d                   POP EBP
0x00000725 (01) c3                   RET
0x00000726 (06) 8b1d e0164000        MOV EBX, [0x4016e0]
0x0000072c (0a) c705 00204000 01000000 MOV DWORD [0x402000], 0x1
0x00000736 (05) e8 45ffffff          CALL 0x00000680    ; 3 sub_00000680
0x0000073b (03) 83fb ff              CMP EBX, -0x1
0x0000073e (02) 74 2f                JZ 0x0000076f      ; 4
0x00000740 (02) 85db                 TEST EBX, EBX
0x00000742 (02) 74 14                JZ 0x00000758      ; 5
0x00000744 (07) 8d349d e0164000      LEA ESI, [EBX*4+0x4016e0]
0x0000074b (01) 90                   NOP
0x0000074c (04) 8d7426 00            LEA ESI, [ESI+0x0]
0x00000750 (02) ff16                 CALL [ESI]
0x00000752 (03) 83ee 04              SUB ESI, 0x4
0x00000755 (01) 4b                   DEC EBX
0x00000756 (02) 75 f8                JNZ 0x00000750     ; 6
0x00000758 (03) 83ec 0c              SUB ESP, 0xc
0x0000075b (05) 68 e0124000          PUSH 0x4012e0
0x00000760 (05) e8 fbfeffff          CALL 0x00000660    ; 7
0x00000765 (03) 83c4 10              ADD ESP, 0x10
0x00000768 (03) 8d65 f8              LEA ESP, [EBP-0x8]
0x0000076b (01) 5b                   POP EBX
0x0000076c (01) 5e                   POP ESI
0x0000076d (01) 5d                   POP EBP
0x0000076e (01) c3                   RET

[0x00000704]> <<ENTER PRESSED AGAIN>>
0x0000076f (02) 31db                 XOR EBX, EBX
0x00000771 (02) eb 02                JMP 0x00000775     ; 1
0x00000773 (02) 89c3                 MOV EBX, EAX
0x00000775 (03) 8d43 01              LEA EAX, [EBX+0x1]
0x00000778 (07) 8b1485 e0164000      MOV EDX, [EAX*4+0x4016e0]
0x0000077f (02) 85d2                 TEST EDX, EDX
0x00000781 (02) 75 f0                JNZ 0x00000773     ; 2
0x00000783 (02) eb bb                JMP 0x00000740     ; 3
0x00000785 (01) 90                   NOP
0x00000786 (01) 90                   NOP
0x00000787 (01) 90                   NOP
0x00000788 (01) 90                   NOP
0x00000789 (01) 90                   NOP
0x0000078a (01) 90                   NOP
0x0000078b (01) 90                   NOP
0x0000078c (01) 90                   NOP
0x0000078d (01) 90                   NOP
0x0000078e (01) 90                   NOP
0x0000078f (01) 90                   NOP
0x00000790 (04) 8d4c24 04            LEA ECX, [ESP+0x4]
0x00000794 (03) 83e4 f0              AND ESP, -0x10
0x00000797 (03) ff71 fc              PUSH DWORD [ECX-0x4]
0x0000079a (01) 55                   PUSH EBP   ; Function sub_0000079a
0x0000079b (02) 89e5                 MOV EBP, ESP
0x0000079d (01) 51                   PUSH ECX
0x0000079e (03) 83ec 14              SUB ESP, 0x14
0x000007a1 (05) e8 6affffff          CALL 0x00000710    ; 4 sub_00000710
0x000007a6 (07) c745 f4 00000000     MOV DWORD [EBP-0xc], 0x0
0x000007ad (07) c745 f8 00000000     MOV DWORD [EBP-0x8], 0x0
0x000007b4 (03) 83ec 0c              SUB ESP, 0xc
0x000007b7 (05) 68 30304000          PUSH 0x403030
0x000007bc (05) e8 bf020000          CALL 0x00000a80    ; 5
0x000007c1 (03) 83c4 10              ADD ESP, 0x10
0x000007c4 (03) 83ec 08              SUB ESP, 0x8
0x000007c7 (05) 68 49304000          PUSH 0x403049
0x000007cc (05) 68 4b304000          PUSH 0x40304b
0x000007d1 (05) e8 ba020000          CALL 0x00000a90    ; 6
0x000007d6 (03) 83c4 10              ADD ESP, 0x10
0x000007d9 (03) 8945 f0              MOV [EBP-0x10], EAX
0x000007dc (04) 837d f0 00           CMP DWORD [EBP-0x10], 0x0
```

To list the functions detected by Pyew type "pyew.names":

```
[0x0000076f]> pyew.names
{1024: 'sub_00000400',
 1296: 'sub_00000510',
 1568: 'sub_00000620',
 1600: 'sub_00000640',
 1664: 'sub_00000680',
 1744: 'sub_000006d0',
 1760: 'sub_000006e0',
 1808: 'sub_00000710',
 1946: 'sub_0000079a',
 2208: 'sub_000008a0',
 2496: 'sub_000009c0',
 4214948: 'KERNEL32.dll!ExitProcess',
 4214952: 'KERNEL32.dll!GetModuleHandleA',
 4214956: 'KERNEL32.dll!GetProcAddress',
 4214960: 'KERNEL32.dll!SetUnhandledExceptionFilter',
 4214972: 'msvcrt.dll!__getmainargs',
 4214976: 'msvcrt.dll!__p__environ',
 4214980: 'msvcrt.dll!__p__fmode',
 4214984: 'msvcrt.dll!__set_app_type',
 4214988: 'msvcrt.dll!_cexit',
 4214992: 'msvcrt.dll!_iob',
 4214996: 'msvcrt.dll!_onexit',
 4215000: 'msvcrt.dll!_setmode',
 4215004: 'msvcrt.dll!atexit',
 4215008: 'msvcrt.dll!fclose',
 4215012: 'msvcrt.dll!fgetc',
 4215016: 'msvcrt.dll!fopen',
 4215020: 'msvcrt.dll!printf',
 4215024: 'msvcrt.dll!putchar',
 4215028: 'msvcrt.dll!puts',
 4215032: 'msvcrt.dll!signal',
 4215036: 'msvcrt.dll!system'}
```

This is a list of all the functions detected by Pyew in the format:
```
{offset:"function name"}
```

There are local functions (sub\_XXX), exported functions and imported functions. Now, I will return to the entry point to see an hexdump:

```
[0x00000000]> s ep
[0x00000620]> x
0620   55 89 E5 83 EC 14 6A 01 FF 15 C8 50 40 00 E8 DD    U.....j....P@...
0630   FE FF FF 8D B6 00 00 00 00 8D BC 27 00 00 00 00    ...........'....
0640   55 89 E5 83 EC 14 6A 02 FF 15 C8 50 40 00 E8 BD    U.....j....P@...
0650   FE FF FF 8D B6 00 00 00 00 8D BC 27 00 00 00 00    ...........'....
0660   55 8B 0D DC 50 40 00 89 E5 5D FF E1 8D 74 26 00    U...P@...]...t&.
0670   55 8B 0D D4 50 40 00 89 E5 5D FF E1 90 90 90 90    U...P@...]......
0680   55 89 E5 83 EC 08 A1 30 20 40 00 85 C0 74 3B 83    U......0 @...t;.
0690   EC 0C 68 00 30 40 00 E8 24 04 00 00 89 C2 83 C4    ..h.0@..$.......
06A0   0C B8 00 00 00 00 85 D2 74 0F 50 50 68 0D 30 40    ........t.PPh.0@
06B0   00 52 E8 19 04 00 00 5A 59 85 C0 74 0D 83 EC 0C    .R.....ZY..t....
06C0   68 30 20 40 00 FF D0 83 C4 10 C9 C3 8D 74 26 00    h0 @.........t&.
06D0   55 89 E5 5D C3 8D 74 26 00 8D BC 27 00 00 00 00    U..]..t&...'....
06E0   55 89 E5 83 EC 08 A1 04 20 40 00 8B 00 85 C0 74    U....... @.....t
06F0   15 FF D0 A1 04 20 40 00 83 C0 04 A3 04 20 40 00    ..... @...... @.
0700   8B 00 85 C0 75 EB C9 C3 90 8D B4 26 00 00 00 00    ....u......&....
0710   55 89 E5 56 53 8B 0D 00 20 40 00 85 C9 74 07 8D    U..VS... @...t..
0720   65 F8 5B 5E 5D C3 8B 1D E0 16 40 00 C7 05 00 20    e.[^].....@....
0730   40 00 01 00 00 00 E8 45 FF FF FF 83 FB FF 74 2F    @......E......t/
0740   85 DB 74 14 8D 34 9D E0 16 40 00 90 8D 74 26 00    ..t..4...@...t&.
0750   FF 16 83 EE 04 4B 75 F8 83 EC 0C 68 E0 12 40 00    .....Ku....h..@.
0760   E8 FB FE FF FF 83 C4 10 8D 65 F8 5B 5E 5D C3 31    .........e.[^].1
0770   DB EB 02 89 C3 8D 43 01 8B 14 85 E0 16 40 00 85    ......C......@..
0780   D2 75 F0 EB BB 90 90 90 90 90 90 90 90 90 90 90    .u..............
0790   8D 4C 24 04 83 E4 F0 FF 71 FC 55 89 E5 51 83 EC    .L$.....q.U..Q..
07A0   14 E8 6A FF FF FF C7 45 F4 00 00 00 00 C7 45 F8    ..j....E......E.
07B0   00 00 00 00 83 EC 0C 68 30 30 40 00 E8 BF 02 00    .......h00@.....
07C0   00 83 C4 10 83 EC 08 68 49 30 40 00 68 4B 30 40    .......hI0@.hK0@
07D0   00 E8 BA 02 00 00 83 C4 10 89 45 F0 83 7D F0 00    ..........E..}..
07E0   75 1A 83 EC 0C 68 59 30 40 00 E8 51 02 00 00 83    u....hY0@..Q....
07F0   C4 10 B8 01 00 00 00 89 45 E8 EB 69 83 EC 0C FF    ........E..i....
0800   75 F0 E8 59 02 00 00 83 C4 10 88 45 EF FF 45 F8    u..Y.......E..E.
0810   80 7D EF FF 74 34 0F BE 45 EF 83 EC 08 50 68 71    .}..t4..E....Phq
```

Now, let's see the first section's data of another PE binary:

```
[0x00000000]> print pyew.pe.sections[0]
[IMAGE_SECTION_HEADER]
Name:                          CODE
Misc:                          0x3000
Misc_PhysicalAddress:          0x3000
Misc_VirtualSize:              0x3000
VirtualAddress:                0x1000
SizeOfRawData:                 0x2200
PointerToRawData:              0x600
PointerToRelocations:          0x0
PointerToLinenumbers:          0x0
NumberOfRelocations:           0x0
NumberOfLinenumbers:           0x0
Characteristics:               0x60000020
```

You can access any PE field exposed by [PEFile](http://code.google.com/p/pefile) by using the syntax: print pyew.pe._desired property or method_.

And we're done with this basic example usage! To see a more interesting example continue with the next tutorial.