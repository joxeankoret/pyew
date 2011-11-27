
import struct

class v_enum: pass

class v_base(object):
    def __init__(self):
        self._vs_meta = {}

    def vsGetMeta(self, name, defval=None):
        return self._vs_meta.get(name, defval)

    def vsSetMeta(self, name, value):
        self._vs_meta[name] = value

    # Sub-classes (primitive base, or VStruct must have these
    def vsParse(self, bytes): return NotImplemented
    def vsCalculate(self): pass
    def vsIsPrim(self): return NotImplemented
    def vsGetTypeName(self): return NotImplemented

class v_prim(v_base):

    def __init__(self):
        v_base.__init__(self)
        # Used by base len(),vsGetFormat, etc...
        self._vs_value = None
        self._vs_length = None
        self._vs_fmt = None

    def vsIsPrim(self):
        return True

    def vsGetTypeName(self):
        return self.__class__.__name__

    def vsParse(self, bytes, offset=0):
        """
        Parser for primitives which assumes we are
        calling parse directly.
        """
        return NotImplemented

    def vsParseFd(self, fd):
        # Most primitives should be able to simply use this...
        fbytes = fd.read(self._vs_length)
        if len(fbytes) != self._vs_length:
            raise Excetpion('Not enough data in fd!')

        self.vsParse(fbytes)

    def vsEmit(self):
        '''
        Return the actual bytes which represent this field
        '''
        return NotImplemented

    def vsGetValue(self):
        """
        Get the type specific value for this field.
        (Used by the structure dereference method to return
        a python native for the field by name)
        """
        return self._vs_value

    def vsSetValue(self, value):
        """
        Set the type specific value for this field.
        """
        self._vs_value = value

    def vsSetLength(self, size):
        '''
        Set the length of this primitive type.  This may be used to
        dynamically update the length of string fields, etc...
        '''
        return NotImplemented

    def __repr__(self):
        return repr(self.vsGetValue())

    def __len__(self):
        return self._vs_length

    def __str__(self):
        return str(self.vsGetValue())

num_fmts = {
    (True,1):'>B',
    (True,2):'>H',
    (True,4):'>I',
    (True,8):'>Q',
    (False,1):'<B',
    (False,2):'<H',
    (False,4):'<I',
    (False,8):'<Q',
}

class v_number(v_prim):

    _vs_length = 1

    def __init__(self, value=0, bigend=False):
        v_prim.__init__(self)
        self._vs_bigend = bigend
        self._vs_value = value
        self._vs_length = self.__class__._vs_length
        self._vs_fmt = num_fmts.get( (bigend, self._vs_length) )

    def vsGetValue(self):
        return self._vs_value

    def vsParse(self, fbytes, offset=0):
        '''
        Parse the given numeric type from the given bytes...
        '''
        sizeoff = offset + self._vs_length

        if self._vs_fmt != None:
            b = fbytes[ offset : sizeoff ]
            self._vs_value = struct.unpack(self._vs_fmt, b)[0]

        else:
            r = []
            for i in range(self._vs_length):
                r.append( ord( fbytes[ offset + i ] ) )

            if not self._vs_bigend:
                r.reverse()

            self._vs_value = 0
            for x in r:
                self._vs_value = (self._vs_value << 8) + x

        return sizeoff

    def vsEmit(self):
        '''
        Emit the bytes for this numeric type...
        '''
        if self._vs_fmt != None:
            return struct.pack(self._vs_fmt, self._vs_value)

        r = []
        for i in range(self._vs_length):
            r.append( chr( (self._vs_value >> (i*8)) & 0xff) )

        if self._vs_bigend:
            r.reverse()

        return ''.join(r)


    def vsSetValue(self, value):
        """
        Assure that the value is long() able for all numeric types.
        """
        self._vs_value = long(value)

    def __int__(self):
        return int(self._vs_value)

    def __long__(self):
        return long(self._vs_value)

    ##################################################################
    # Implement the number API

    def __add__(self, other): return long(self) + long(other)
    def __sub__(self, other): return long(self) - long(other)
    def __mul__(self, other): return long(self) * long(other)
    def __div__(self, other): return long(self) / long(other)
    def __floordiv__(self, other): return long(self) // long(other)
    def __mod__(self, other): return long(self) % long(other)
    def __divmod__(self, other): return divmod(long(self), long(other))
    def __pow__(self, other, modulo=None): return pow(long(self), long(other), modulo)
    def __lshift__(self, other): return long(self) << long(other)
    def __rshift__(self, other): return long(self) >> long(other)
    def __and__(self, other): return long(self) & long(other)
    def __xor__(self, other): return long(self) ^ long(other)
    def __or__(self, other): return long(self) | long(other)

    # Operator swapped variants
    def __radd__(self, other): return long(other) + long(self)
    def __rsub__(self, other): return long(other) - long(self)
    def __rmul__(self, other): return long(other) * long(self)
    def __rdiv__(self, other): return long(other) / long(self)
    def __rfloordiv__(self, other): return long(other) // long(self)
    def __rmod__(self, other): return long(other) % long(self)
    def __rdivmod__(self, other): return divmod(long(other), long(self))
    def __rpow__(self, other, modulo=None): return pow(long(other), long(self), modulo)
    def __rlshift__(self, other): return long(other) << long(self)
    def __rrshift__(self, other): return long(other) >> long(self)
    def __rand__(self, other): return long(other) & long(self)
    def __rxor__(self, other): return long(other) ^ long(self)
    def __ror__(self, other): return long(other) | long(self)

    # Inplace variants
    def __iadd__(self, other): self.vsSetValue(self+other); return self
    def __isub__(self, other): self.vsSetValue(self - other); return self
    def __imul__(self, other): self.vsSetValue(self*other); return self
    def __idiv__(self, other): self.vsSetValue(self/other); return self
    def __ifloordiv__(self, other): self.vsSetValue(self // other); return self
    def __imod__(self, other): self.vsSetValue(self % other); return self
    def __ipow__(self, other, modulo=None): self.vsSetValue(pow(self, other, modulo)); return self
    def __ilshift__(self, other): self.vsSetValue(self << other); return self
    def __irshift__(self, other): self.vsSetValue(self >> other); return self
    def __iand__(self, other): self.vsSetValue(self & other); return self
    def __ixor__(self, other): self.vsSetValue(self ^ other); return self
    def __ior__(self, other): self.vsSetValue(self | other); return self

    # operator helpers
    def __neg__(self): return -(long(self))
    def __pos__(self): return +(long(self))
    def __abs__(self): return abs(long(self))
    def __invert__(self): return ~(long(self))

    # index use helper
    def __index__(self): return long(self)

    def __coerce__(self, other):
        try:
            return long(self),long(other)
        except Exception, e:
            return NotImplemented

    # Print helpers
    def __hex__(self): return hex(long(self))
    def __oct__(self): return oct(long(self))

class v_uint8(v_number):
    _vs_builder = True
    _vs_length = 1

class v_uint16(v_number):
    _vs_builder = True
    _vs_length = 2

class v_uint24(v_number):
    _vs_builder = True
    _vs_length = 3

class v_uint32(v_number):
    _vs_builder = True
    _vs_length = 4

class v_uint64(v_number):
    _vs_builder = True
    _vs_length = 8

class v_int8(v_number):
    _vs_builder = True
    _vs_length = 1

class v_int16(v_number):
    _vs_builder = True
    _vs_length = 2

class v_int24(v_number):
    _vs_builder = True
    _vs_length = 3

class v_int32(v_number):
    _vs_builder = True
    _vs_length = 4

class v_int64(v_number):
    _vs_builder = True
    _vs_length = 8

pointersize = struct.calcsize("P")

class v_size_t(v_number):
    _vs_builder = True
    _vs_length = pointersize

    def __repr__(self):
        return "0x%.8x" % self._vs_value

class v_ptr(v_size_t):
    pass

class v_ptr32(v_ptr):
    _vs_builder = True
    _vs_length = 4

class v_ptr64(v_ptr):
    _vs_builder = True
    _vs_length = 8

class v_bytes(v_prim):

    '''
    v_bytes is used for fixed width byte fields.
    '''

    _vs_builder = True

    def __init__(self, size=0, vbytes=None):
        v_prim.__init__(self)
        if vbytes == None:
            vbytes = '\x00' * size
        self._vs_length = len(vbytes)
        self._vs_value = vbytes

    def vsSetValue(self, val):
        if len(val) != self._vs_length:
            raise Exception('v_bytes field set to wrong length!')
        self._vs_value = val

    def vsParse(self, fbytes, offset=0):
        offend = offset + self._vs_length
        self._vs_value = fbytes[offset : offend]
        return offend

    def vsEmit(self):
        return self._vs_value

    def vsSetLength(self, size):
        size = int(size)
        self._vs_length = size
        # Either chop or expand my string...
        b = self._vs_value[:size]
        self._vs_value = b.ljust(size, '\x00')

    def __repr__(self):
        return self._vs_value.encode('hex')

class v_str(v_prim):
    '''
    A string placeholder class which will automagically return
    up to a null terminator (and will keep it's size by null
    padding when assigned to)
    '''

    _vs_builder = True

    def __init__(self, size=4, val=''):
        v_prim.__init__(self)
        self._vs_length = size
        self._vs_value = val.ljust(size, '\x00')

    def vsParse(self, fbytes, offset=0):
        offend = offset + self._vs_length
        self._vs_value = fbytes[offset : offend]
        return offend

    def vsEmit(self):
        return self._vs_value

    def vsGetValue(self):
        s = self._vs_value.split("\x00")[0]
        return s

    def vsSetValue(self, val):
        self._vs_value = val.ljust(self._vs_length, '\x00')

    def vsSetLength(self, size):
        size = int(size)
        self._vs_length = size
        # Either chop or expand my string...
        b = self._vs_value[:size]
        self._vs_value = b.ljust(size, '\x00')

class v_wstr(v_str):
    '''
    Unicode variant of the above string class

    NOTE: the size paramater is in WCHARs!
    '''

    _vs_builder = True

    def __init__(self, size=4, encode='utf-16le', val=''):
        v_prim.__init__(self)
        b = val.ljust(size, '\x00').encode(encode)
        self._vs_length = len(b)
        self._vs_value = b
        self._vs_encode = encode

    def vsParse(self, fbytes, offset=0):
        offend = offset + self._vs_length
        self._vs_value = fbytes[offset : offend]
        return offend

    def vsEmit(self):
        return self._vs_value

    def vsGetValue(self):
        cstr = self._vs_value.decode(self._vs_encode)
        return cstr.split('\x00')[0]

    def vsSetValue(self, val):
        rbytes = val.encode(self._vs_encode)
        self._vs_value = rbytes.ljust(len(self), '\x00')

    def vsGetValue(self):
        s = self._vs_value.decode(self._vs_encode)
        s = s.split("\x00")[0]
        return s

class GUID(v_prim):

    _vs_builder = True

    def __init__(self, guidstr=None):
        """
        Construct a new GUID primitive.  You may specify a GUID string in the
        constructor to populate initial values.
        """
        v_prim.__init__(self)
        self._vs_length = 16
        self._vs_value = "\x00" * 16
        self._vs_fmt = "16s"
        self._guid_fields = (0,0,0,0,0,0,0,0,0,0,0)
        if guidstr != None:
            self._parseGuidStr(guidstr)

    def vsParse(self, fbytes, offset=0):
        offend = offset + self._vs_length
        self._guid_fields = struct.unpack("<IHH8B", bytes[offset:offend])
        return offend

    def vsEmit(self):
        return struck.pack("<IHH8B", *self._guid_fields)

    def _parseGuidStr(self, gstr):
        gstr = gstr.replace("{","")
        gstr = gstr.replace("}","")
        gstr = gstr.replace("-","")
        bytes = gstr.decode("hex")
        # Totally cheating... ;)
        self._guid_fields = struct.unpack(">IHH8B", bytes)

    def vsSetValue(self, guidstr):
        self._parseGuidStr(guidstr)

    def vsGetValue(self):
        return repr(self)

    def __repr__(self):
        base = "{%.8x-%.4x-%.4x-%.2x%.2x-%.2x%.2x%.2x%.2x%.2x%.2x}"
        return base  % self._guid_fields

