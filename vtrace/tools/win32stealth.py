import vtrace
import vstruct

class StealthBreak(vtrace.Breakpoint):
    """
    A breakpoint to fake out CheckRemoteDebuggerPresent.
    """
    def notify(self, event, trace):
        sp = trace.getStackCounter()
        eip, handle, outbool = trace.readMemoryFormat(sp, "<LLL")
        trace.setRegisterByName("eax", 1)
        trace.writeMemoryFormat(outbool, "<L", 0)
        trace.setProgramCounter(eip)
        trace.setStackCounter(sp+12)
        trace.runAgain()

def writeBeingDebugged(trace, val):
    peb = trace.parseExpression("peb")
    ps = vstruct.getStructure("win32.PEB")
    off = ps.vsGetOffset("BeingDebugged")
    trace.writeMemoryFormat(peb+off, "<B", val)

def stealthify(trace):

    writeBeingDebugged(trace, 0)
    sym = trace.getSymByName("kernel32").getSymByName("CheckRemoteDebuggerPresent")
    if sym != None:
        addr = long(sym)
        bp = StealthBreak(addr)
        bpid = trace.addBreakpoint(bp)
        trace.setMeta("Win32Stealth", bpid)

def unstealthify(trace):
    writeBeingDebugged(trace, 1)
    bp = trace.getMeta("Win32Stealth")
    if bp != None:
        trace.setMeta("Win32Stealth", None)
        trace.removeBreakpoint(bp)

