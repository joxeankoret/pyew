'''
A home for the page lookup construct.  Basically it is a
python object which implements a similar lookup mechanism
to the i386 page table lookups...
'''

# FIXME move functions in here too so there is procedural "speed" way
# and objecty pythonic way...

class PageLookup:
    '''
    An object capable of rapid lookups across a sparse address
    space which will also NOT eat *all* the RAMS like a straight
    dictionary full of millions of entries would.
    '''

    def __init__(self):
        self._page_dict = {}

    def getPageLookup(self, va):
        base = va >> 16
        offs = va & 0xffff
        page = self._page_dict.get(base)
        if page == None:
            return None
        return page[offs]

    def setPageLookup(self, va, size, obj):
        vamax = va+size
        while va < vamax:
            base = va >> 16
            offs = va & 0xffff
            page = self._page_dict.get(base)
            if page == None:
                page = [None] * 0xffff
                self._page_dict[base] = page
            page[offs] = obj
            va += 1

    # __getitem__
    # __getslice__
    # __setslice__

class MapLookup:

    '''
    A specialized lookup object for large densely populated ranges
    which are layed out in a sparse field space themselves...
    '''

    def __init__(self):
        self._maps_list = []

    def initMapLookup(self, va, size, obj=None):
        marray = [obj] * size
        # FIXME optimize by size!
        self._maps_list.append((va, va+size, marray))

    def setMapLookup(self, va, size, obj):
        for mva, mvamax, marray in self._maps_list:
            if va >= mva and va < mvamax:
                off = va - mva
                s = [obj] * size
                marray[off:off+size] = s
                return
        raise Exception('Address (0x%.8x) not in maps!' % va)

    def getMapLookup(self, va):
        for mva, mvamax, marray in self._maps_list:
            if va >= mva and va < mvamax:
                off = va - mva
                return marray[off]
        return None

    def __getslice__(self, start, end):
        print 'GET SLICE'

