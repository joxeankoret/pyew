### Analyzing a malware: Mebroot/Sinowal ###

OK, enough theoretical uses, time to take a fast look to some malwares ;) Let's analyze a Mebroot downloader. Open it and start the analysis:

```
joxean$ ./pyew.py 57a1a763eda887dd32510d39941c60dd42c622a2fa6c3e0d0bf8848de7b602d6
PE Information

Sections:
   .text 0x1000 0x4c2e 19968
   .rdata 0x6000 0x35a 1024
   .data 0x7000 0xac 512
   .data 0x8000 0x2028 8704
   .reloc 0xb000 0x16e 512

Entry Point at 0xeea
Code Analysis ...

0000   4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00    MZ..............
0010   B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......
0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0030   00 00 00 00 00 00 00 00 00 00 00 00 C8 00 00 00    ................
0040   0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68    ........!..L.!Th
0050   69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F    is program canno
0060   74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20    t be run in DOS
0070   6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00    mode....$.......
0080   7F 4F D8 92 3B 2E B6 C1 3B 2E B6 C1 3B 2E B6 C1    .O..;...;...;...
0090   51 32 B4 C1 27 2E B6 C1 3B 2E B7 C1 5D 2E B6 C1    Q2..'...;...]...
00A0   62 0D A5 C1 30 2E B6 C1 11 26 B0 C1 3A 2E B6 C1    b...0....&..:...
00B0   3B 2E B6 C1 10 2E B6 C1 52 69 63 68 3B 2E B6 C1    ;.......Rich;...
00C0   00 00 00 00 00 00 00 00 50 45 00 00 4C 01 05 00    ........PE..L...
00D0   89 03 C1 47 00 00 00 00 00 00 00 00 E0 00 02 01    ...G............
00E0   0B 01 00 0D 00 4E 00 00 00 2A 00 00 00 00 00 00    .....N...*......
00F0   EA 1A 00 00 00 10 00 00 00 60 00 00 00 00 40 00    .........`....@.
0100   00 10 00 00 00 02 00 00 04 00 00 00 84 4A 38 07    .............J8.
0110   04 00 00 00 00 00 00 00 00 C0 00 00 00 04 00 00    ................
0120   E9 98 00 00 02 00 00 00 00 00 10 00 00 10 00 00    ................
0130   00 20 18 00 00 10 00 00 9F 07 C2 71 10 00 00 00    . .........q....
0140   00 00 00 00 00 00 00 00 98 60 00 00 B4 00 00 00    .........`......
0150   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0160   00 00 00 00 00 00 00 00 00 B0 00 00 20 01 00 00    ............ ...
0170   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0180   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0190   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
01A0   00 60 00 00 74 00 00 00 00 00 00 00 00 00 00 00    .`..t...........
01B0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
01C0   2E 74 65 78 74 00 00 00 2E 4C 00 00 00 10 00 00    .text....L......
01D0   00 4E 00 00 00 04 00 00 00 00 00 00 00 00 00 00    .N..............
01E0   00 00 00 00 20 00 00 68 2E 72 64 61 74 61 00 00    .... ..h.rdata..
01F0   5A 03 00 00 00 60 00 00 00 04 00 00 00 52 00 00    Z....`.......R..
```

It seems looking to the section's names and so on, that the file is OK (no strange section names, etc...). Now, I will seek to the entry point to see what is there:

```
[0x00000000]> s ep
[0x00000eea]> c
0x00000eea (01) 52                   PUSH EDX
0x00000eeb (01) f9                   STC
0x00000eec (01) f9                   STC
0x00000eed (01) f9                   STC
0x00000eee (01) f5                   CMC
0x00000eef (01) f5                   CMC
0x00000ef0 (05) ba 00000000          MOV EDX, 0x0
0x00000ef5 (06) 81c2 ee9ced75        ADD EDX, 0x75ed9cee
0x00000efb (01) 52                   PUSH EDX
0x00000efc (04) 0fbae2 06            BT EDX, 0x6
0x00000f00 (04) 0fbafa 07            BTC EDX, 0x7
0x00000f04 (03) c1c2 00              ROL EDX, 0x0
0x00000f07 (01) 5a                   POP EDX
0x00000f08 (06) 81c2 fa928469        ADD EDX, 0x698492fa
0x00000f0e (01) 5a                   POP EDX
0x00000f0f (02) 8d00                 LEA EAX, [EAX]
0x00000f11 (06) 0f85 6a050000        JNZ 0x00001481     ; 1 sub_00001481
0x00000f17 (06) d1a0 7f461850        SHL DWORD [EAX+0x5018467f], 0x1
0x00000f1d (05) e8 040c0000          CALL 0x00001b26    ; 2
0x00000f22 (03) 83c4 0c              ADD ESP, 0xc
0x00000f25 (02) 6a 1e                PUSH 0x1e
0x00000f27 (02) 6a 0d                PUSH 0xd
0x00000f29 (03) 8d4d 8c              LEA ECX, [EBP-0x74]
0x00000f2c (01) 51                   PUSH ECX
0x00000f2d (05) e8 f40b0000          CALL 0x00001b26    ; 3
0x00000f32 (03) 83c4 0c              ADD ESP, 0xc
0x00000f35 (03) 8d55 8c              LEA EDX, [EBP-0x74]
0x00000f38 (01) 52                   PUSH EDX
0x00000f39 (03) ff55 9c              CALL [EBP-0x64]
0x00000f3c (03) 8945 c8              MOV [EBP-0x38], EAX
0x00000f3f (04) 837d c8 00           CMP DWORD [EBP-0x38], 0x0
0x00000f43 (02) 75 05                JNZ 0x00000f4a     ; 4
0x00000f45 (05) e9 e0090000          JMP 0x0000192a     ; 5
0x00000f4a (03) 8d45 ec              LEA EAX, [EBP-0x14]
0x00000f4d (01) 50                   PUSH EAX
0x00000f4e (03) 8b4d c8              MOV ECX, [EBP-0x38]
0x00000f51 (01) 51                   PUSH ECX
0x00000f52 (06) ff95 70ffffff        CALL [EBP-0x90]
0x00000f58 (05) a3 60704000          MOV [0x407060], EAX
0x00000f5d (03) 8d55 dc              LEA EDX, [EBP-0x24]
```

Uhm..., it seems to be obfuscated and full of "Spaghetti code":

```
0x00000eeb (01) f9                   STC
0x00000eec (01) f9                   STC
0x00000eed (01) f9                   STC
0x00000eee (01) f5                   CMC
0x00000eef (01) f5                   CMC
```

It's suspicious. I will take the first conditional jump (JNZ 0x00001481) to see what is there:

```
[0x00000eea]> 1
0x00001481 (01) 55                   PUSH EBP   ; Function sub_00001481
0x00001482 (02) 8bec                 MOV EBP, ESP
0x00001484 (06) 81ec 94000000        SUB ESP, 0x94
0x0000148a (07) c745 d8 00000000     MOV DWORD [EBP-0x28], 0x0
0x00001491 (0a) c785 70ffffff 00000000 MOV DWORD [EBP-0x90], 0x0
0x0000149b (07) c745 9c 00000000     MOV DWORD [EBP-0x64], 0x0
0x000014a2 (07) c745 a0 00000000     MOV DWORD [EBP-0x60], 0x0
0x000014a9 (07) c745 cc 00000000     MOV DWORD [EBP-0x34], 0x0
0x000014b0 (07) c745 c8 00000000     MOV DWORD [EBP-0x38], 0x0
0x000014b7 (07) c745 a4 00000000     MOV DWORD [EBP-0x5c], 0x0
0x000014be (0a) c785 74ffffff 00000000 MOV DWORD [EBP-0x8c], 0x0
0x000014c8 (04) c645 dc 38           MOV BYTE [EBP-0x24], 0x38
0x000014cc (04) c645 dd 4b           MOV BYTE [EBP-0x23], 0x4b
0x000014d0 (01) 53                   PUSH EBX
0x000014d1 (01) 53                   PUSH EBX
0x000014d2 (06) 81db aeff28a8        SBB EBX, 0xa828ffae
0x000014d8 (06) 81eb 73dcbb85        SUB EBX, 0x85bbdc73
0x000014de (06) 81eb 138e5533        SUB EBX, 0x33558e13
0x000014e4 (06) 81cb 733e5097        OR EBX, 0x97503e73
0x000014ea (06) 81d3 24d45714        ADC EBX, 0x1457d424
0x000014f0 (01) 5b                   POP EBX
0x000014f1 (02) 33db                 XOR EBX, EBX
0x000014f3 (01) 5b                   POP EBX
0x000014f4 (06) 0f84 22fdffff        JZ 0x0000121c      ; 1
0x000014fa (01) fd                   STD
0x000014fb (01) f3                   DB 0xf3
0x000014fb (05) f3 007c26 e8         ADD [ESI-0x18], BH
0x00001500 (05) bf f4ffff52          MOV EDI, 0x52fffff4
0x00001505 (01) 57                   PUSH EDI
0x00001506 (06) 81df ef643831        SBB EDI, 0x313864ef
0x0000150c (01) 5f                   POP EDI
0x0000150d (05) ba 00000000          MOV EDX, 0x0
0x00001512 (06) 81c2 99ae350c        ADD EDX, 0xc35ae99
0x00001518 (01) 51                   PUSH ECX
0x00001519 (01) 59                   POP ECX
0x0000151a (06) 81c2 7f1a887c        ADD EDX, 0x7c881a7f
0x00001520 (01) 5a                   POP EDX
0x00001521 (02) 8d00                 LEA EAX, [EAX]
0x00001523 (06) 0f85 b4feffff        JNZ 0x000013dd     ; 2
0x00001529 (01) f1                   INT1
```

Definitely, it's strange. What we see at the moment:

  * Many non typically compiler generated code sequences:

```
0x000014d0 (01) 53                   PUSH EBX
0x000014d1 (01) 53                   PUSH EBX
0x000014d2 (06) 81db aeff28a8        SBB EBX, 0xa828ffae
0x000014d8 (06) 81eb 73dcbb85        SUB EBX, 0x85bbdc73
0x000014de (06) 81eb 138e5533        SUB EBX, 0x33558e13
0x000014e4 (06) 81cb 733e5097        OR EBX, 0x97503e73
0x000014ea (06) 81d3 24d45714        ADC EBX, 0x1457d424
0x000014f0 (01) 5b                   POP EBX
0x000014f1 (02) 33db                 XOR EBX, EBX
0x000014f3 (01) 5b                   POP EBX
```

  * Redundant REP prefixes:

```
0x000014fb (01) f3                   DB 0xf3
0x000014fb (05) f3 007c26 e8         ADD [ESI-0x18], BH
```

  * Antidebugging tricks:

```
0x00001529 (01) f1                   INT1
```

Let's continue analyzing it a bit more... I will advance 2 blocks (2 x 512 bytes) of disassembly (so just press the enter key 2 times):

```
[0x00001082]>
0x0000174e (07) c685 79ffffff 4b     MOV BYTE [EBP-0x87], 0x4b
0x00001755 (07) c685 7affffff 54     MOV BYTE [EBP-0x86], 0x54
0x0000175c (07) c685 7bffffff 56     MOV BYTE [EBP-0x85], 0x56
0x00001763 (07) c685 7cffffff 57     MOV BYTE [EBP-0x84], 0x57
0x0000176a (07) c685 7dffffff 43     MOV BYTE [EBP-0x83], 0x43
0x00001771 (07) c685 7effffff 4e     MOV BYTE [EBP-0x82], 0x4e
0x00001778 (07) c685 7fffffff 23     MOV BYTE [EBP-0x81], 0x23
0x0000177f (01) 57                   PUSH EDI
0x00001780 (01) f9                   STC
0x00001781 (01) f8                   CLC
0x00001782 (01) f9                   STC
0x00001783 (05) bf 00000000          MOV EDI, 0x0
0x00001788 (06) 81c7 4ac5522a        ADD EDI, 0x2a52c54a
0x0000178e (01) 51                   PUSH ECX
0x0000178f (02) 13c8                 ADC ECX, EAX
0x00001791 (02) 2bc9                 SUB ECX, ECX
0x00001793 (01) 59                   POP ECX
0x00001794 (06) 81c7 3009d877        ADD EDI, 0x77d80930
0x0000179a (01) 5f                   POP EDI
0x0000179b (06) 0f85 5c010000        JNZ 0x000018fd     ; 1
0x000017a1 (01) ae                   SCASB
0x000017a2 (02) 7e 86                JLE 0x0000172a     ; 2
0x000017a4 (01) 17                   POP SS
0x000017a5 (03) f6c6 45              TEST DH, 0x45
0x000017a8 (01) 96                   XCHG ESI, EAX
0x000017a9 (01) 4e                   DEC ESI
0x000017aa (04) c645 97 4e           MOV BYTE [EBP-0x69], 0x4e
0x000017ae (04) c645 98 00           MOV BYTE [EBP-0x68], 0x0
0x000017b2 (07) c745 fc 00000000     MOV DWORD [EBP-0x4], 0x0
0x000017b9 (07) c745 d0 00000000     MOV DWORD [EBP-0x30], 0x0
0x000017c0 (07) c745 f8 00000000     MOV DWORD [EBP-0x8], 0x0
0x000017c7 (07) c745 d4 00000000     MOV DWORD [EBP-0x2c], 0x0
0x000017ce (02) 6a 00                PUSH 0x0
0x000017d0 (06) ff15 2c604000        CALL KERNEL32.dll!DeleteAtom
0x000017d6 (02) 6a 00                PUSH 0x0
0x000017d8 (06) ff15 28604000        CALL KERNEL32.dll!DisconnectNamedPipe
0x000017de (01) 53                   PUSH EBX
0x000017df (01) 55                   PUSH EBP
0x000017e0 (02) 8beb                 MOV EBP, EBX
0x000017e2 (02) 13ee                 ADC EBP, ESI
```

More evidences: Calls to the quite non typical KERNEL32.dll!DeleteAtom and KERNEL32.dll!DisconnectNamedPipe functions. What is this? Antiemulation tricks for sure. Do we have collected enough evidences to say it's suspicious enough to perform a more in deep analysis? I think so.

Now, it's time to analyze the sample in a Sandbox or with a debugger like OllyDbg or to reverse engineer and document how it works in IDA Pro ;) Remember, like Biew and Hiew, it is only a tool to help malware researchers, not a tool to completely analyze a binary.