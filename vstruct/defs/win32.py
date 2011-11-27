
# FIXME this is named wrong!

import vstruct
from vstruct.primitives import *

class CLIENT_ID(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.UniqueProcess = v_ptr32()
        self.UniqueThread = v_ptr32()

class EXCEPTION_RECORD(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.ExceptionCode = v_uint32()
        self.ExceptionFlags = v_uint32()
        self.ExceptionRecord = v_ptr32()
        self.ExceptionAddress = v_ptr32()
        self.NumberParameters = v_uint32()

class EXCEPTION_REGISTRATION(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.prev = v_ptr32()
        self.handler = v_ptr32()

class HEAP(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.Entry = HEAP_ENTRY()
        self.Signature = v_uint32()
        self.Flags = v_uint32()
        self.ForceFlags = v_uint32()
        self.VirtualMemoryThreshold = v_uint32()
        self.SegmentReserve = v_uint32()
        self.SegmentCommit = v_uint32()
        self.DeCommitFreeBlockThreshold = v_uint32()
        self.DeCommitTotalFreeThreshold = v_uint32()
        self.TotalFreeSize = v_uint32()
        self.MaximumAllocationSize = v_uint32()
        self.ProcessHeapsListIndex = v_uint16()
        self.HeaderValidateLength = v_uint16()
        self.HeaderValidateCopy = v_ptr32()
        self.NextAvailableTagIndex = v_uint16()
        self.MaximumTagIndex = v_uint16()
        self.TagEntries = v_ptr32()
        self.UCRSegments = v_ptr32()
        self.UnusedUnCommittedRanges = v_ptr32()
        self.AlignRound = v_uint32()
        self.AlignMask = v_uint32()
        self.VirtualAllocBlocks = ListEntry()
        self.Segments = vstruct.VArray([v_uint32() for i in range(64)])
        self.u = vstruct.VArray([v_uint8() for i in range(16)])
        self.u2 = vstruct.VArray([v_uint8() for i in range(2)])
        self.AllocatorBackTraceIndex = v_uint16()
        self.NonDedicatedListLength = v_uint32()
        self.LargeBlocksIndex = v_ptr32()
        self.PseudoTagEntries = v_ptr32()
        self.FreeLists = vstruct.VArray([ListEntry() for i in range(128)])
        self.LockVariable = v_uint32()
        self.CommitRoutine = v_ptr32()
        self.FrontEndHeap = v_ptr32()
        self.FrontEndHeapLockCount = v_uint16()
        self.FrontEndHeapType = v_uint8()
        self.LastSegmentIndex = v_uint8()

class HEAP_SEGMENT(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.Entry = HEAP_ENTRY()
        self.SegmentSignature = v_uint32()
        self.SegmentFlags = v_uint32()
        self.Heap = v_ptr32()
        self.LargestUncommitedRange = v_uint32()
        self.BaseAddress = v_ptr32()
        self.NumberOfPages = v_uint32()
        self.FirstEntry = v_ptr32()
        self.LastValidEntry = v_ptr32()
        self.NumberOfUnCommittedPages = v_uint32()
        self.NumberOfUnCommittedRanges = v_uint32()
        self.UncommittedRanges = v_ptr32()
        self.SegmentAllocatorBackTraceIndex = v_uint16()
        self.Reserved = v_uint16()
        self.LastEntryInSegment = v_ptr32()

class HEAP_ENTRY(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.Size = v_uint16()
        self.PrevSize = v_uint16()
        self.SegmentIndex = v_uint8()
        self.Flags = v_uint8()
        self.Unused = v_uint8()
        self.TagIndex = v_uint8()

class ListEntry(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.Flink = v_ptr32()
        self.Blink = v_ptr32()

class NT_TIB(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.ExceptionList = v_ptr32()
        self.StackBase = v_ptr32()
        self.StackLimit = v_ptr32()
        self.SubSystemTib = v_ptr32()
        self.FiberData = v_ptr32()
        #x.Version = v_ptr32() # This is a union field
        self.ArbitraryUserPtr = v_ptr32()
        self.Self = v_ptr32()

class PEB(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.InheritedAddressSpace = v_uint8()
        self.ReadImageFileExecOptions = v_uint8()
        self.BeingDebugged = v_uint8()
        self.SpareBool = v_uint8()
        self.Mutant = v_ptr32()
        self.ImageBaseAddress = v_ptr32()
        self.Ldr = v_ptr32()
        self.ProcessParameters = v_ptr32()
        self.SubSystemData = v_ptr32()
        self.ProcessHeap = v_ptr32()
        self.FastPebLock = v_ptr32()
        self.FastPebLockRoutine = v_ptr32()
        self.FastPebUnlockRoutine = v_ptr32()
        self.EnvironmentUpdateCount = v_uint32()
        self.KernelCallbackTable = v_ptr32()
        self.SystemReserved = v_uint32()
        self.AtlThunkSListPtr32 = v_ptr32()
        self.FreeList = v_ptr32()
        self.TlsExpansionCounter = v_uint32()
        self.TlsBitmap = v_ptr32()
        self.TlsBitmapBits = vstruct.VArray([v_uint32() for i in range(2)])
        self.ReadOnlySharedMemoryBase = v_ptr32()
        self.ReadOnlySharedMemoryHeap = v_ptr32()
        self.ReadOnlyStaticServerData = v_ptr32()
        self.AnsiCodePageData = v_ptr32()
        self.OemCodePageData = v_ptr32()
        self.UnicodeCaseTableData = v_ptr32()
        self.NumberOfProcessors = v_uint32()
        self.NtGlobalFlag = v_uint64()
        self.CriticalSectionTimeout = v_uint64()
        self.HeapSegmentReserve = v_uint32()
        self.HeapSegmentCommit = v_uint32()
        self.HeapDeCommitTotalFreeThreshold = v_uint32()
        self.HeapDeCommitFreeBlockThreshold = v_uint32()
        self.NumberOfHeaps = v_uint32()
        self.MaximumNumberOfHeaps = v_uint32()
        self.ProcessHeaps = v_ptr32()
        self.GdiSharedHandleTable = v_ptr32()
        self.ProcessStarterHelper = v_ptr32()
        self.GdiDCAttributeList = v_uint32()
        self.LoaderLock = v_ptr32()
        self.OSMajorVersion = v_uint32()
        self.OSMinorVersion = v_uint32()
        self.OSBuildNumber = v_uint16()
        self.OSCSDVersion = v_uint16()
        self.OSPlatformId = v_uint32()
        self.ImageSubsystem = v_uint32()
        self.ImageSubsystemMajorVersion = v_uint32()
        self.ImageSubsystemMinorVersion = v_uint32()
        self.ImageProcessAffinityMask = v_uint32()
        self.GdiHandleBuffer = vstruct.VArray([v_ptr32() for i in range(34)])
        self.PostProcessInitRoutine = v_ptr32()
        self.TlsExpansionBitmap = v_ptr32()
        self.TlsExpansionBitmapBits = vstruct.VArray([v_uint32() for i in range(32)])
        self.SessionId = v_uint32()
        self.AppCompatFlags = v_uint64()
        self.AppCompatFlagsUser = v_uint64()
        self.pShimData = v_ptr32()
        self.AppCompatInfo = v_ptr32()
        self.CSDVersion = v_ptr32()
        self.UNKNOWN = v_uint32()
        self.ActivationContextData = v_ptr32()
        self.ProcessAssemblyStorageMap = v_ptr32()
        self.SystemDefaultActivationContextData = v_ptr32()
        self.SystemAssemblyStorageMap = v_ptr32()
        self.MinimumStackCommit = v_uint32()

class SEH3_SCOPETABLE(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.EnclosingLevel = v_int32()
        self.FilterFunction = v_ptr32()
        self.HandlerFunction = v_ptr32()

class SEH4_SCOPETABLE(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.GSCookieOffset = v_int32()
        self.GSCookieXOROffset = v_int32()
        self.EHCookieOffset = v_int32()
        self.EHCookieXOROffset = v_int32()
        self.EnclosingLevel = v_int32()
        self.FilterFunction = v_ptr32()
        self.HandlerFunction = v_ptr32()

class TEB(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.TIB = NT_TIB()
        self.EnvironmentPointer = v_ptr32()
        self.ClientId = CLIENT_ID()
        self.ActiveRpcHandle = v_ptr32()
        self.ThreadLocalStorage = v_ptr32()
        self.ProcessEnvironmentBlock = v_ptr32()
        self.LastErrorValue = v_uint32()
        self.CountOfOwnedCriticalSections = v_uint32()
        self.CsrClientThread = v_ptr32()
        self.Win32ThreadInfo = v_ptr32()
        self.User32Reserved = vstruct.VArray([v_uint32() for i in range(26)])
        self.UserReserved = vstruct.VArray([v_uint32() for i in range(5)])
        self.WOW32Reserved = v_ptr32()
        self.CurrentLocale = v_uint32()
        self.FpSoftwareStatusRegister = v_uint32()

class CLSID(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.uuid = GUID()

class IID(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.uuid = GUID()

