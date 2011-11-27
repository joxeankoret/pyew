
import struct

from inspect import isclass
from StringIO import StringIO

import vstruct.primitives as vs_prims

def isVstructType(x):
    return isinstance(x, vs_prims.v_base)

class VStruct(vs_prims.v_base):

    '''
    The VStruct class is the bases for all groups of primitive fields which define a "structure".
    Fields may be added with vsAddField() or simply added as attributes (provided you use a VStruct
    or one of the vstruct.primitives in the initial assignment.)

    Example:
        import vstruct
        from vstruct.primitives import *

        vs = vstruct.VStruct()
        vs.fieldone = v_uint32()
        vs.fieldtwo = v_str(size=30)

        bytes = vs.vsEmit()

    '''

    def __init__(self):
        # A tiny bit of evil...
        object.__setattr__(self, "_vs_values", {})
        vs_prims.v_base.__init__(self)
        self._vs_name = self.__class__.__name__
        self._vs_fields = []
        self._vs_field_align = False # To toggle visual studio style packing
        self._vs_padnum = 0
        self._vs_pcallbacks = {}

    def vsAddParseCallback(self, fieldname, callback):
        '''
        Register a callback which will be triggered when the field with the given name
        is set by the parser.  This can be used to simplify auto-parsing to change fields
        sizes or whatnot during parsing.

        (You may also name a method pcb_<FieldName> to get a callback for your struct.)

        Example:

            def updateLengthTarget(vs):
                dostuff()

            v.vsAddParseCallback('lenfield', updateLengthTarget)
        '''
        if self._vs_values.get(fieldname) == None:
            raise Exception('Invalid Field: %s' % fieldname)

        cblist = self._vs_pcallbacks.get(fieldname)
        if cblist == None:
            cblist = []
            self._vs_pcallbacks[fieldname] = cblist

        cblist.append(callback)

    def vsGetClassPath(self):
        '''
        Return the entire class name (including module path).
        '''
        return '%s.%s' % (self.__module__, self._vs_name)

    def vsParseFd(self, fd):
        '''
        Parse from the given file like object as input.
        '''
        for fname, fobj in self.vsGetFields():
            fobj.vsParseFd(fd)
            callback = getattr(self, 'pcb_%s' % fname, None)
            if callback != None:
                callback()
            cblist = self._vs_pcallbacks.get(fname)
            if cblist != None:
                for callback in cblist:
                    callback(self)

    def vsParse(self, sbytes, offset=0):
        """
        For all the primitives contained within, allow them
        an opportunity to parse the given data and return the
        total offset...

        Any method named pcb_<FieldName> will be called back when the specified
        field is set by the parser.
        
        """
        for fname, fobj in self.vsGetFields():
            offset = fobj.vsParse(sbytes, offset=offset)
            callback = getattr(self, 'pcb_%s' % fname, None)
            if callback != None:
                callback()
            cblist = self._vs_pcallbacks.get(fname)
            if cblist != None:
                for callback in cblist:
                    callback(self)
        return offset

    def vsEmit(self):
        """
        Get back the byte sequence associated with this structure.
        """
        # FIXME....
        ret = ''
        for fname, fobj in self.vsGetFields():
            ret += fobj.vsEmit()
        return ret
        
    def vsCalculate(self):
        '''
        Calculate fields which need correction before emitting bytes etc...

        (VStruct extenders may call this, then modify fields internally)
        '''
        for fname, fobj in self.vsGetFields():
            fobj.vsCalculate()

    def vsIsPrim(self):
        return False

    def vsGetFields(self):
        '''
        Get a list of (fieldname, fieldobj) tuples for all the kids
        in this VStruct (non-recursive)

        Example:
                for kidname, kidobj in x.vsGetFields():
                    print kidname
        '''
        ret = []
        for fname in self._vs_fields:
            fobj = self._vs_values.get(fname)
            ret.append((fname,fobj))
        return ret

    def vsGetField(self, name):
        x = self._vs_values.get(name)
        if x == None:
            raise Exception("Invalid field: %s" % name)
        return x

    def vsHasField(self, name):
        '''
        Test weather this structure contains a field with the
        given name....

        Example:
            if x.vsHasField('woot'):
                print 'STRUCT HAS WOOT FIELD!'
        '''
        return self._vs_values.get(name) != None

    def vsSetField(self, name, value):
        '''
        Mostly for internal use...
        '''
        if isVstructType(value):
            self._vs_values[name] = value
            return
        x = self._vs_values.get(name)
        return x.vsSetValue(value)

    # FIXME implement more arithmetic for structs...
    def __ixor__(self, other):
        for name,value in other._vs_values.items():
            self._vs_values[name] ^= value
        return self

    def vsClearFields(self):
        '''
        Clear all fields from the current vstruct object.  This may be useful
        in specialized parsers which populate their structure on vsParse()
        '''
        self.__init__()

    def vsAddField(self, name, value):
        if not isVstructType(value):
            raise Exception("Added fields MUST be vstruct types!")

        # Do optional field alignment...
        if self._vs_field_align:

            # If it's a primitive, all is well, if not, pad to size of
            # the first element of the VStruct/VArray...
            if value.vsIsPrim():
                align = len(value)
            else:
                fname = value._vs_fields[0]
                align = len(value._vs_values.get(fname))

            delta = len(self) % align
            if delta != 0:
                pname = "_pad%d" % self._vs_padnum
                self._vs_padnum += 1
                self._vs_fields.append(pname)
                self._vs_values[pname] = vs_prims.v_bytes(align-delta)

        self._vs_fields.append(name)
        self._vs_values[name] = value

    def vsGetPrims(self):
        """
        return an order'd list of the primitive fields in this
        structure definition.  This is recursive and will return
        the sub fields of all nested structures.
        """
        ret = []
        for name, field in self.vsGetFields():
            if field.vsIsPrim():
                ret.append(field)
            else:
                ret.extend(field.vsGetPrims())

        return ret

    def vsGetTypeName(self):
        return self._vs_name

    def vsGetOffset(self, name):
        """
        Return the offset of a member (by name):
        """
        offset = 0
        for fname in self._vs_fields:
            if name == fname:
                return offset
            x = self._vs_values.get(fname)
            offset += len(x)
        raise Exception("Invalid Field Specified!")

    def vsGetPrintInfo(self, offset=0, indent=0, top=True):
        ret = []
        if top:
            ret.append((offset, indent, self._vs_name, self))
        indent += 1
        for fname in self._vs_fields:
            x = self._vs_values.get(fname)
            off = offset + self.vsGetOffset(fname)
            if isinstance(x, VStruct):
                ret.append((off, indent, fname, x))
                ret.extend(x.vsGetPrintInfo(offset=off, indent=indent, top=False))
            else:
                ret.append((off, indent, fname, x))
        return ret

    def __len__(self):
        ret = 0
        for fname, fobj in self.vsGetFields():
            ret += len(fobj)
        return ret

    def __getattr__(self, name):
        # Gotta do this for pickle issues...
        vsvals = self.__dict__.get("_vs_values")
        if vsvals == None:
            vsvals = {}
            self.__dict__["_vs_values"] = vsvals
        r = vsvals.get(name)
        if r is None:
            raise AttributeError(name)
        if isinstance(r, vs_prims.v_prim):
            return r.vsGetValue()
        return r

    def __setattr__(self, name, value):
        # If we have this field, asign to it
        x = self._vs_values.get(name, None)
        if x != None:
            return self.vsSetField(name, value)

        # If it's a vstruct type, create a new field
        if isVstructType(value):
            return self.vsAddField(name, value)

        # Fail over to standard object attribute behavior
        return object.__setattr__(self, name, value)

    def __iter__(self):
        # Our iteration returns name,field pairs
        ret = []
        for name in self._vs_fields:
            ret.append((name, self._vs_values.get(name)))
        return iter(ret)

    def __repr__(self):
        return self._vs_name

    def tree(self, va=0, reprmax=None):
        ret = ""
        for off, indent, name, field in self.vsGetPrintInfo():
            rstr = field.vsGetTypeName()
            if isinstance(field, vs_prims.v_number):
                val = field.vsGetValue()
                rstr = '0x%.8x (%d)' % (val,val)
            elif isinstance(field, vs_prims.v_prim):
                rstr = repr(field)
            if reprmax != None and len(rstr) > reprmax:
                rstr = rstr[:reprmax] + '...'
            ret += "%.8x (%.2d)%s %s: %s\n" % (va+off, len(field), " "*(indent*2),name,rstr)
        return ret

class VArray(VStruct):

    def __init__(self, elems=()):
        VStruct.__init__(self)
        for e in elems:
            self.vsAddElement(e)

    def vsAddElement(self, elem):
        """
        Used to add elements to an array
        """
        idx = len(self._vs_fields)
        self.vsAddField("%d" % idx, elem)

    def __getitem__(self, index):
        return self.vsGetField("%d" % index)

    #FIXME slice asignment

def resolve(impmod, nameparts):
    """
    Resolve the given (potentially nested) object
    from within a module.
    """
    if not nameparts:
        return None

    m = impmod
    for nname in nameparts:
        m = getattr(m, nname, None)
        if m == None:
            break

    return m

def resolvepath(impmod, pathstr):
    '''
    Resolve an object/module from within the given module
    by path name (ie. 'foo.bar.baz')

    Example: x = resolvepath(vstruct.defs, 'win32.SEH_SCOPETABLE')
    '''
    nameparts = pathstr.split('.')
    return resolve(impmod, nameparts)

# NOTE: Gotta import this *after* VStruct/VSArray defined
import vstruct.defs as vs_defs

def getStructure(sname):
    """
    Return an instance of the specified structure.  The
    structure name may be a definition that was added with
    addStructure() or a python path (ie. win32.TEB) of a
    definition from within vstruct.defs.
    """
    x = resolve(vs_defs, sname.split("."))
    if x != None:
        return x()

    return None

def getModuleNames():
    return [x for x in dir(vs_defs) if not x.startswith("__")]

def getStructNames(modname):
    ret = []
    mod = resolve(vs_defs, modname)
    if mod == None:
        return ret

    for n in dir(mod):
        x = getattr(mod, n)
        if isclass(x) and issubclass(x, VStruct):
            ret.append(n)

    return ret

