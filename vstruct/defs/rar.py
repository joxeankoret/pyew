import vstruct
from vstruct.primitives import *

HEAD_TYPE_MARKER        = 0x72          #marker block
HEAD_TYPE_ARCHIVE       = 0x73          #archive header
HEAD_TYPE_FILE_HDR      = 0x74          #file header
HEAD_TYPE_OLD_COMMENT   = 0x75          #old style comment header
HEAD_TYPE_OLD_AUTH      = 0x76          #old style authenticity information
HEAD_TYPE_OLD_SUBBLOCK  = 0x77          #old style subblock
HEAD_TYPE_OLD_RECOVERY  = 0x78          #old style recovery record
HEAD_TYPE_OLD_AUTH2     = 0x79          #old style authenticity information
HEAD_TYPE_SUBBLOCK      = 0x7a          #subblock

class RarChunkUnkn(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.CHUNK_BYTES = v_bytes()

class RarBlock(vstruct.VStruct):

    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.HEAD_CRC       = v_uint16()
        self.HEAD_TYPE      = v_uint8()
        self.HEAD_FLAGS     = v_uint16()
        self.HEAD_SIZE      = v_uint16()
        self.ADD_SIZE       = v_uint32()
        self.BLOCK_DATA     = vstruct.VStruct()

    def pcb_HEAD_FLAGS(self):
        # a proto callback for the header
        if self.HEAD_FLAGS & 0x8000:
            self.ADD_SIZE = v_uint32()
        else:
            self.ADD_SIZE = vstruct.VStruct()

    def pcb_ADD_SIZE(self):
        hsize = 7
        totsize = self.HEAD_SIZE
        if not isinstance(self.ADD_SIZE, vstruct.VStruct):
            hsize += 4
            totsize += self.ADD_SIZE

        # We will *now* use TYPE to find out our chunk guts
        self.BLOCK_DATA = v_bytes(totsize - hsize)
        

if __name__ == '__main__':
    import sys

    offset = 0
    b = file(sys.argv[1], 'rb').read()

    while offset < len(b):
        r = RarBlock()
        offset = r.vsParse( b, offset=offset)
        print r.tree()
        
