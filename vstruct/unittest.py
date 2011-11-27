
import vstruct

from cStringIO import StringIO

from vstruct.primitives import *

def test(vs, hexstr):
    vshex = vs.vsEmit().encode('hex')
    if vshex != hexstr:
        raise Exception('FAIL')
    print 'PASS!'

v = vstruct.VStruct()
v.uint8 = v_uint8(1)
v.uint16 = v_uint16(2)
v.uint24 = v_uint24(3)
v.uint32 = v_uint32(4)
v.uint64 = v_uint64(5)
v.vbytes = v_bytes(vbytes='ABCD')

test(v,'01020003000004000000050000000000000041424344')
print v.tree()


v.uint8 = 99
v.uint16 = 100
v.uint24 = 101
v.uint32 = 102
v.uint64 = 103
v.vbytes = '\x00\x00\x00\x00'

test(v,'63640065000066000000670000000000000000000000')
print v.tree()


# =================================================================
v = vstruct.VStruct()
v._vs_field_align = True
v.uint8 = v_uint8(0x42, bigend=True)
v.uint16 = v_uint16(0x4243, bigend=True)
v.uint24 = v_uint24(0x424344, bigend=True)
v.uint32 = v_uint32(0x42434445, bigend=True)
v.uint64 = v_uint64(0x4243444546474849, bigend=True)

test(v, '420042430000424344000000424344454243444546474849')
print v.tree()


# ===============================================================

v = vstruct.VStruct()
v.strfield = v_str(size=30)
v.unifield = v_wstr(size=30)

v.strfield = 'wootwoot!'
v.unifield = 'bazbaz'

test(v, '776f6f74776f6f7421000000000000000000000000000000000000000000620061007a00620061007a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
print v.tree()

v.vsParse('B'*90)

# ===============================================================
def updatelen(vs):
    vs.vsGetField('strfield').vsSetLength(vs.lenfield)

v = vstruct.VStruct()
v.lenfield = v_uint8(0x30)
v.strfield = v_str(size=30)
v.vsAddParseCallback('lenfield', updatelen)

v.vsParse('\x01' + 'A' * 30)
test(v, '0141')
print v.tree()


# ==============================================================

class woot(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.lenfield = v_uint8()
        self.strfield = v_str(size=0x20)

    def pcb_lenfield(self):
        self.vsGetField('strfield').vsSetLength(self.lenfield)

v = woot()
v.vsParse('\x01' + 'A'*30)
test(v, '0141')
print v.tree()

# ==============================================================

v = woot()
sio = StringIO('\x01' + 'A' * 30)
v.vsParseFd(sio)
test(v, '0141')
print v.tree()


