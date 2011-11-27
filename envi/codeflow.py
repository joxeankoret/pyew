'''
A module to contain code flow analysis for envi opcode objects...
'''
import copy

import envi
import envi.memory as e_mem

class CodeFlowContext(object):

    '''
    A CodeFlowContext is used for code-flow (not linear) based disassembly
    for an envi MemoryObject (which is responsible for knowing the implementation
    of parseOpcode().  The CodeFlowContext will optionally notify several callback
    handlers for different events which occur during disassembly:

    self._cb_opcode(va, op, branches) - called for every newly parsed opcode
        NOTE: _cb_opcode must return the desired branches for continued flow

    self._cb_function(fva, metadict) - called once for every function

    self._cb_branchtable(tabva, destva) - called for switch tables

    '''
    def __init__(self, mem):

        self._funcs = {}
        self._entries = {}
        self._mem = mem
        self._opdone = {}

    def _cb_opcode(self, va, op, branches):
        '''
        Extend CodeFlowContext and implement this method to recieve
        a callback for every newly discovered opcode.
        '''
        return branches

    def _cb_function(self, fva, fmeta):
        '''
        Extend CodeFlowContext and implement this method to recieve
        a callback for every newly discovered function.  Additionally,
        metadata about the function may be stored in the fmeta dict.
        '''
        pass

    def _cb_branchtable(self, tabva, destva):
        pass

    def getCallsFrom(self, fva):
        return self._funcs.get(fva)

    def addFunctionDef(self, fva, calls_from):
        '''
        Add a priori knowledge of a function to the code flow
        stuff...
        '''

        if self._funcs.get(fva) != None:
            return

        self._funcs[fva] = calls_from

    def addCodeFlow(self, va, persist=False, exptable=True):
        '''
        Do code flow disassembly from the specified address.  Returnes a list
        of the procedural branch targets discovered during code flow...

        Set persist=True to store 'opdone' and never disassemble the same thing twice
        Set exptable=True to expand branch tables in this phase
        '''

        opdone = self._opdone
        if not persist:
            opdone = {}
        calls_from = {}
        optodo = [va, ]

        while len(optodo):

            va = optodo.pop()

            if opdone.get(va):
                continue

            opdone[va] = True

            try:
                op = self._mem.parseOpcode(va)
            except Exception, e:
                print 'parseOpcodeError at 0x%.8x: %s' % (va,e)
                # FIXME code block breakage...
                continue

            branches = op.getBranches()
            # The opcode callback may filter branches...
            branches = self._cb_opcode(va, op, branches)

            while len(branches):

                bva, bflags = branches.pop()

                # Don't worry about unresolved branches now...
                if bva == None:
                    continue

                # Handle a table branch by adding more branches...
                if bflags & envi.BR_TABLE:
                    if exptable:
                        ptrbase = bva
                        bdest = self._mem.readMemoryFormat(ptrbase, '<P')[0]
                        tabdone = {}
                        while self._mem.isValidPointer(bdest):

                            self._cb_branchtable(ptrbase, bdest)

                            if not tabdone.get(bdest):
                                tabdone[bdest] = True
                                branches.append((bdest, envi.BR_COND))

                            ptrbase += self._mem.psize
                            bdest = self._mem.readMemoryFormat(ptrbase, '<P')[0]

                    continue

                # FIXME handle conditionals here for block boundary detection!

                if bflags & envi.BR_DEREF:

                    if not self._mem.probeMemory(bva, 1, e_mem.MM_READ):
                        continue

                    bva = self._mem.readMemoryFormat(bva, '<P')[0]

                if not self._mem.probeMemory(bva, 1, e_mem.MM_EXEC):
                    continue

                if bflags & envi.BR_PROC:

                    # Record that the current code flow has a call from it
                    # to the branch target...
                    # FIXME intel hack, call 0, pop reg for geteip...
                    if bva != va + len(op):
                        calls_from[bva] = True

                else:
                    if not opdone.get(bva):
                        optodo.append(bva)

        return calls_from.keys()

    def _handleFunc(self, va, pth):

        path = []

        # Check if this is already a known function.
        if self._funcs.get(va) != None:
            return

        self._funcs[va] = True

        # Check if we have disassembled a loop
        if va in pth:
            return

        pth.append(va)

        calls_from = self.addCodeFlow(va)

        for callto in calls_from:
            self._handleFunc(callto, pth=pth)

        pth.pop()

        # Finally, notify the callback of a new function
        self._cb_function(va, {'CallsFrom':calls_from})

    def addEntryPoint(self, va):
        '''
        Analyze the given procedure entry point and flow downward
        to find all subsequent code blocks and procedure edges.
        '''
        self._entries[va] = True
        return self._handleFunc(va, [])

