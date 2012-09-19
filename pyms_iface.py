#!/usr/bin/python
# -*- coding: utf-8 -*-

import pymsasid as pyms

from binascii import hexlify

class CDecodedIns:
    def __init__(self, mnem, operands, buf, offset):
        self.mnemonic = mnem.upper()
        self.operands = operands.upper().replace("0X", "0x")
        self.instructionHex = hexlify(buf)
        self.size = len(buf)
        self.offset = offset

def _Decode(offset, buf, dis_mode=32):
    ret = []
    prog = pyms.Pymsasid(hook=pyms.BufferHook, source=buf)
    prog.input.base_address = offset
    prog.dis_mode = dis_mode

    addr = 0
    while addr <= len(buf):
        try:
            x = prog.disassemble(addr)
            mnem = x.operator
            if len(x.operand) > 0:
                if len(x.operand) == 1 and str(mnem).startswith("j") or str(mnem).find("call") > -1:
                    try:
                        if str(x.operand[0]).startswith("-"):
                            value = int(str(x.operand[0])[1:], 16)
                            operands = hex(offset - value)
                        else:
                            value = int(str(x.operand[0]), 16)
                            operands = hex(offset + value)
                    except:
                        operands = str(x.operand[0])
                else:
                    operands = ", ".join(map(str, x.operand))
            else:
                operands = ""    
            size = x.size
        except KeyboardInterrupt:
            raise
        except:
            mnem = "ERROR"
            size = 1
            operands = ""

        _bytes = buf[addr:addr+size]
        ret.append(CDecodedIns(mnem, operands, _bytes, offset+addr))
        addr += size

    return ret

def Decode16Bits(offset, buf):
    return _Decode(offset, buf, 16)

def Decode32Bits(offset, buf):
    return _Decode(offset, buf, 32)

def Decode64Bits(offset, buf):
    return _Decode(offset, buf, 64)

def Decode(offset, buf, decoder):
    return decoder(offset, buf)

