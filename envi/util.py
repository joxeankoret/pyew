
class CopyOnWrite:
    """
    A memory object wrapper you can use to do copy-on-write memory
    use and be able to simply reset it.
    """

    def __init__(self, memobj):
        self.writes = []
        self.memobj = memobj

    def reset(self):
        """
        Throw away the current writes and be fresh...
        """
        self.writes = []

    def writeMemory(self, va, bytes):
        # FIXME for now, allow any writes, but soon, do more
        self.writes.append((va,va+len(bytes),bytes))

    def readMemory(self, va, size):
        for memva,nextva,bytes in self.writes:
            if memva <= va and va+size <= nextva:
                offset = va-memva
                return bytes[offset:offset+size]
        return self.memobj.readMemory(va, size)

