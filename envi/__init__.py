
"""
The Envi framework allows architecutre abstraction through
the use of the ArchitectureModule, Opcode, Operand, and
Emulator objects.
"""

import types
import struct
import platform

# Instruciton flags (The first 8 bits are reserved for arch independant use)
IF_NOFALL = 0x01 # Set if this instruction does *not* fall through
IF_PRIV   = 0x02 # Set if this is a "privileged mode" instruction
IF_CALL   = 0x04 # Set if this instruction branches to a procedure
IF_BRANCH = 0x08 # Set if this instruction branches
IF_RET    = 0x10 # Set if this instruction terminates a procedure

# Branch flags (flags returned by the getBranches() method on an opcode)
BR_PROC  = 1<<0 # The branch target is a procedure (call <foo>)
BR_COND  = 1<<1 # The branch target is conditional (jz <foo>)
BR_DEREF = 1<<2 # the branch target is *dereferenced* into PC (call [0x41414141])
BR_TABLE = 1<<3 # The branch target is the base of a pointer array of jmp/call slots
BR_FALL  = 1<<4 # The branch is a "fall through" to the next instruction

import envi.bits as e_bits
import envi.memory as e_mem
import envi.registers as e_reg
import envi.memcanvas as e_canvas

class ArchitectureModule:
    """
    An architecture module implementes methods to deal
    with the creation of envi objects for the specified
    architecture.
    """
    def __init__(self, archname, maxinst=32):
        self._arch_name = archname
        self._arch_maxinst = maxinst
        self._arch_call_convs = {}

    def archGetBreakInstr(self):
        """
        Return a python string of the byte sequence which corresponds to
        a breakpoint (if present) for this architecture.
        """
        raise ArchNotImplemented("archGetBreakInstr")

    def archGetRegCtx(self):
        """
        Return an initialized register context object for the architecture.
        """
        raise ArchNotImplemented("archGetRegCtx")

    def makeOpcode(self, bytes, offset=0, va=0):
        """
        Create a new opcode from the specified bytes (beginning
        at the specified offset)
        """
        raise ArchNotImplemented("makeOpcode")

    def getEmulator(self):
        """
        Return a default instance of an emulator for the given arch.
        """
        raise ArchNotImplemented("getEmulator")

    def getPointerSize(self):
        """
        Get the size of a pointer in memory on this architecture.
        """
        raise ArchNotImplemented("getPointerSize")

    def pointerString(self, va):
        """
        Return a string representation for a pointer on this arch
        """
        raise ArchNotImplemented("pointerString")

    def addCallingConvention(self, name, obj):
        self._arch_call_convs[name] = obj

    def hasCallingConvention(self, name):
        if self._arch_call_convs.get(name) != None:
            return True
        return False

    def getCallingConvention(self, name):
        return self._arch_call_conv.get(name)

    def getCallingConventions(self):
        return self._arch_call_convs.items()

def stealArchMethods(obj, archname):
    '''
    Used by objects which are expected to inherit from an
    architecture module but don't know which one until runtime!
    '''
    arch = getArchModule(archname)
    for name in dir(arch):
        o = getattr(arch, name, None)
        if type(o) == types.MethodType:
            setattr(obj, name, o)

################################################################
#
# FIXME going away and becomming part of opcode.
#
    def getStackDelta(self, op):
        """
        If the given opcode instruction changes the value of the
        stack pointer, return the delta from that opcode...
        """
        raise ArchNotImplemented("getStackDelta")

class EnviException(Exception):
    def __str__(self):
        return repr(self)

class InvalidInstruction(EnviException):
    """
    Raised by opcode parsers when the specified
    bytes do not represent a valid opcode
    """
    def __init__(self, bytes=None):
        msg = None
        if bytes != None:
            msg = bytes.encode('hex')
        EnviException.__init__(self, msg)

class SegmentationViolation(EnviException):
    """
    Raised by an Emulator extension when you
    bad-touch memory. (Likely from memobj).
    """
    def __init__(self, va, msg=None):
        if msg == None:
            msg = "Bad Memory Access: %s" % hex(va)
        EnviException.__init__(self, msg)
        self.va = va

class ArchNotImplemented(EnviException):
    """
    Raised by various Envi components when the architecture
    does not implement that envi component.
    """
    pass

class EmuException(EnviException):
    """
    A parent for all emulation exceptions so catching
    them can be easy.
    """
    def __init__(self, emu, msg=None):
        EnviException.__init__(self, msg)
        self.va = emu.getProgramCounter()

    def __repr__(self):
        return "%s at %s" % (self.__class__.__name__, hex(self.va))

class UnsupportedInstruction(EmuException):
    """
    Raised by emulators when the given instruction
    is not implemented by the emulator.
    """
    def __init__(self, emu, op):
        EmuException.__init__(self, emu)
        self.op = op

    def __repr__(self):
        return "Unsupported Instruction: 0x%.8x %s" % (self.va, repr(self.op))

class DivideByZero(EmuException):
    """
    Raised by an Emulator when a divide/mod has
    a 0 divisor...
    """

class BreakpointHit(EmuException):
    """
    Raised by an emulator when you execute a breakpoint instruction
    """

class PDEUndefinedFlag(EmuException):
    """
    This exception is raised when a conditional operation is dependant on
    a flag state that is unknown.
    """

class PDEException(EmuException):
    """
    This exception is used in partially defined emulation to signal where
    execution flow becomes un-known due to undefined values.  This is considered
    un-recoverable.
    """

class UnknownCallingConvention(EmuException):
    """
    Raised when the getCallArgs() or setReturnValue() methods
    are given an unknown calling convention type.
    """

class MapOverlapException(EnviException):
    """
    Raised when adding a memory map to a MemoryObject which overlaps
    with another already existing map.
    """
    def __init__(self, map1, map2):
        self.map1 = map1
        self.map2 = map2
        margs = (map1[0], map1[1], map2[0], map2[1])
        EnviException.__init__(self, "Map At 0x%.8x (%d) overlaps map at 0x%.8x (%d)" % margs)

class Operand:

    """
    Thses are the expected methods needed by any implemented operand object
    attached to an envi Opcode.  This does *not* have a constructor of it's
    pwn on purpose to cut down on memory use and constructor CPU cost.
    """

    def getOperValue(self, op, emu=None):
        """
        Get the current value for the operand.  If needed, use
        the given emulator/workspace/trace to resolve things like
        memory and registers.

        NOTE: This API may be passed a None emu and should return what it can
              (or None if it can't be resolved)
        """
        print "%s needs to implement getOperValue!" % self.__class__.__name__
        return None

    def setOperValue(self, op, emu, val):
        """
        Set the current value for the operand.  If needed, use
        the given emulator/workspace/trace to assign things like
        memory and registers.
        """
        print("%s needs to implement setOperValue! (0x%.8x: %s) " % (self.__class__.__name__, op.va, repr(op)))

    def isDeref(self):
        """
        If the given operand will dereference memory, this method must return True.
        """
        return False

    def isImmed(self):
        '''
        If the given operand represents an immediate value, this must return True.
        '''
        return False

    def isReg(self):
        '''
        If the given operand represents a register value, this must return True.
        '''
        return False

    def getOperAddr(self, op, emu):
        """
        If the operand is a "dereference" operand, this method should use the
        specified op/emu to resolve the address of the dereference.

        NOTE: This API may be passed a None emu and should return what it can
              (or None if it can't be resolved)
        """
        print("%s needs to implement getOperAddr!" % self.__class__.__name__)
        return None
    
    def repr(self, op):
        """
        Used by the Opcode class to get a humon readable string for this operand.
        """
        return "unknown"

    def render(self, mcanv, op, idx):
        """
        Used by the opcode class when rendering to a memory canvas.
        """
        mcanv.addText(self.repr(op))

    def __ne__(self, op):
        return not op == self

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        #FIXME each one will need this...
        return True

class DerefOper(Operand):

    def isDeref(self):
        return True

class ImmedOper(Operand):

    def isImmed(self):
        return True

class RegisterOper(Operand):

    def isReg(self):
        return True

class Opcode:
    """
    A universal representation for an opcode
    """
    prefix_names = [] # flag->humon tuples

    def __init__(self, va, opcode, mnem, prefixes, size, operands, iflags=0):
        """
        constructor for the basic Envi Opcode object.  Arguments as follows:

        opcode   - An architecture specific numerical value for the opcode
        mnem     - A humon readable mnemonic for the opcode
        prefixes - a bitmask of architecture specific instruction prefixes
        size     - The size of the opcode in bytes
        operands - A list of Operand objects for this opcode
        iflags   - A list of Envi (architecture independant) instruction flags (see IF_FOO)
        va       - The virtual address the instruction lives at (used for PC relative immediates etc...)

        NOTE: If you want to create an architecture spcific opcode, I'd *highly* recommend you
              just copy/paste in the following simple initial code rather than calling the parent
              constructor.  The extra
        """
        self.opcode = opcode
        self.mnem = mnem
        self.prefixes = prefixes
        self.size = size
        self.opers = operands
        self.repr = None
        self.iflags = iflags
        self.va = va

    def __ne__(self, op):
        return not op == self

    def __eq__(self, op):
        if not isinstance(op, Opcode):
            return False
        if self.opcode != op.opcode:
            return False
        if self.mnem != op.mnem:
            return False
        if self.size != op.size:
            return False
        if self.iflags != op.iflags:
            return False
        if len(self.opers) != len(op.opers):
            return False
        for i in range(len(self.opers)):
            if self.opers[i] != op.opers[i]:
                return False
        return True

    def __hash__(self):
        return int(hash(self.mnem) ^ (self.size << 4))

    def __repr__(self):
        """
        Over-ride this if you want to make arch specific repr.
        """
        return self.mnem + " " + ",".join([o.repr(self) for o in self.opers])

    def __len__(self):
        return int(self.size)


    # NOTE: From here down is mostly things that architecture specific opcode
    #       extensions should override.
    def getBranches(self, emu=None):
        """
        Return a list of tuples.  Each tuple contains the target VA of the
        branch, and a possible set of flags showing what type of branch it is.

        See the BR_FOO types for all the supported envi branch flags....
        Example: for bva,bflags in op.getBranches():
        """
        return ()

    def render(self, mcanv):
        """
        Render this opcode to the memory canvas passed in.  This is used for both
        simple printing AND more complex representations.
        """
        mcanv.addText(repr(self))

    def getPrefixName(self):
        """
        Get the name of the prefixes associated with the specified
        architecture specific prefix bitmask.
        """
        ret = []
        for byte,name in self.prefix_names:
            if self.prefixes & byte:
                ret.append(name)
        return "".join(ret)

    def getOperValue(self, idx, emu=None):
        oper = self.opers[idx]
        return oper.getOperValue(self, emu=emu)

    def getOperands(self):
        return list(self.opers)

class Emulator(e_reg.RegisterContext, e_mem.IMemory):
    """
    The Emulator class is mostly "Abstract" in the java
    Interface sense.  The emulator should be able to
    be extended for the architecutures which are included
    in the envi framework.  You *must* mix in
    an instance of your architecture abstraction module.

    (NOTE: Most users will just use an arch mod and call getEmulator())

    The intention is for "light weight" emulation to be
    implemented mostly for user-space emulation of 
    protected mode execution.

    Additionally, the envi Emulator is capable of "partially defined
    emulation" which is triggered by any registers or memory reads having
    the value None (not 0).  In these cases, special exceptions may be used
    to manage execution flow and determine whatever is possible from the 
    PDE process that reversers typically do in their heads.
    """
    def __init__(self, segs=None, memobj=None):
        e_mem.IMemory.__init__(self)
        e_reg.RegisterContext.__init__(self)

        if segs == None:
            segs = [(0,0xffffffff),]

        self.segments = segs

        # Save off the memory object
        self.setMemoryObject(memobj)

        # Automagically setup an instruction mnemonic handler dict
        # by finding all methods starting with i_ and assume they
        # implement an instruction by mnemonic
        # FIXME THIS *MUST* GET FASTER FOR UTIL FUNCS!
        # POSSIBLY DECLARE IN ADVANCE?
        self.op_methods = {}
        for name in dir(self):
            if name.startswith("i_"):
                self.op_methods[name[2:]] = getattr(self, name)

    def getEmuSnap(self):
        """
        Return the data needed to "snapshot" this emulator.  For most
        archs, this method will be enough (it takes the memory object,
        and register values with it)
        """
        regs = self.getRegisterSnap()
        mem = self.memobj.getMemorySnap()
        return regs,mem

    def setEmuSnap(self, snap):
        regs,mem = snap
        self.setRegisterSnap(regs)
        self.memobj.setMemorySnap(mem)

    def getSegmentInfo(self, op):
        idx = self.getSegmentIndex(op)
        return self.segments[idx]

    def getSegmentIndex(self, op):
        """
        The *default* segmentation is none (most arch's will over-ride).
        This method may be implemented to return a segment index based on either
        emulator state or properties of the particular instruction in question.
        """
        return 0

    def setSegmentInfo(self, idx, base, size):
        self.segments[idx] = (base,size)

    def setMemoryObject(self, memobj):
        """
        Give the emulator a memory object to use for reads and writes.
        A memory object must implement the methods from the base MemoryObject.
        """
        self.memobj = memobj

    def getMemoryObject(self):
        return self.memobj

    def executeOpcode(self, opobj):
        """
        This is the core method for the 
        """
        raise ArchNotImplemented()

    def run(self, stepcount=None):
        """
        Run the emulator until "something" happens.
        (breakpoint, segv, syscall, etc...)
        """
        if stepcount != None:
            for i in xrange(stepcount):
                self.stepi()
        else:
            while True:
                self.stepi()

    def stepi(self):
        pc = self.getProgramCounter()
        bytes = self.readMemory(pc, 32)
        op = self.makeOpcode(bytes, va=pc)
        self.executeOpcode(op)

#############################################################
#
# NOTE: Although we are an IMemory object, our primitive
# reads/writes/maps go to another...
#
    def readMemory(self, va, size):
        """
        Read memory bytes in the emulated environment.
        For partially-defined emulation, this may return None when
        the state is unknown.
        """
        return self.memobj.readMemory(va, size)

    def writeMemory(self, va, bytes):
        """
        Write memory in the emulation Environment
        """
        return self.memobj.writeMemory(va, bytes)

    def getMemoryMaps(self):
        return self.memobj.getMemoryMaps()
#############################################################

    def getOperValue(self, op, idx):
        """
        Return the value for the operand at index idx for
        the given opcode reading memory and register states if necissary.

        In partially-defined emulation, this may return None
        """
        oper = op.opers[idx]
        return oper.getOperValue(op, self)

    def getOperAddr(self, op, idx):
        """
        Return the address that an operand which deref's memory
        would read from on getOperValue().
        """
        oper = op.opers[idx]
        return oper.getOperAddr(op, self)

    def setOperValue(self, op, idx, value):
        """
        Set the value of the target operand at index idx from
        opcode op.
        (obviously OM_IMMEDIATE *cannot* be set)
        """
        oper = op.opers[idx]
        return oper.setOperValue(op, self, value)

    def getCallArgs(self, count, cc):
        """
        Emulator implementors can implement this method to allow
        analysis modules a platform/architecture independant way
        to get stack/reg/whatever args.

        Usage: getCallArgs(3, "stdcall") -> (0, 32, 0xf00)
        """
        # use _arch_call_convs assuming we are an ArchitectureModule
        c = self._arch_call_convs.get(cc, None)
        if c == None:
            raise UnknownCallingConvention(cc)

        return c.getCallArgs(self, count)

    def setReturnValue(self, value, cc, argc=0):
        """
        Emulator implementors can implement this method to allow
        analysis modules a platform/architecture independant way
        to set a function return value. (this should also take
        care of any argument cleanup or other return time tasks
        for the calling convention)
        """
        c = self._arch_call_convs.get(cc, None)
        if c == None:
            raise UnknownCallingConvention(cc)

        return c.setReturnValue(self, value, argc)

class CallingConvention:
    """
    Implement calling conventions for your arch.
    """
    def setReturnValue(self, emu, value, ccinfo=None):
        pass

    def getCallArgs(self, emu, count):
        pass

    # If you want your arch to use symbolik emulation...
    def getSymbolikArgs(self, emu, argv):
        raise Exception('getSymbolikArgs() not in %s' % self.__class__.__name__)

    def setSymbolikReturn(self, emu, sym, argv):
        raise Exception('setSymbolikReturn() not in %s' % self.__class__.__name__)

# NOTE: This mapping is needed because of inconsistancies
# in how different compilers and versions of python embed
# the machine setting.
arch_xlate_32 = {
    'i386':'i386',
    'i486':'i386',
    'i586':'i386',
    'i686':'i386',
    'x86':'i386',
    'i86pc':'i386', # Solaris
    '':'i386', # Stupid windows...
    'AMD64':'i386', # ActiveState python can say AMD64 in 32 bit install?
}

arch_xlate_64 = {
    'x86_64':'amd64',
    'AMD64':'amd64',
    'amd64':'amd64',
    'i386':'amd64', # MAC ports builds are 64bit and say i386
    '':'amd64', # And again....
}

def getCurrentArch():
    """
    Return an envi normalized name for the current arch.
    """
    width = struct.calcsize("P")
    mach = platform.machine()   # 'i386','ppc', etc...

    if width == 4:
        ret = arch_xlate_32.get(mach)

    elif width == 8:
        ret = arch_xlate_64.get(mach)

    if ret == None:
        raise ArchNotImplemented(mach)

    return ret

def getArchModule(name=None):
    """
    return an Envi architecture module instance for the following
    architecture name.
    
    Current architectures include:

    i386 - Intel i386
    amd64 - The new 64bit AMD spec.
    """
    if name == None:
        name = getCurrentArch()

    # Some builds have x86 (py2.6) and some have other stuff...
    if name in ["i386","i486","i586","i686","x86"]:
        import envi.archs.i386 as e_i386
        return e_i386.i386Module()

    elif name == "amd64":
        import envi.archs.amd64 as e_amd64
        return e_amd64.Amd64Module()

    elif name == 'arm':
        import envi.archs.arm as e_arm
        return e_arm.ArmModule()

    else:
        raise ArchNotImplemented(name)

