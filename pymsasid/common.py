VENDOR_INTEL = 0
VENDOR_AMD   = 1

class DecodeException(Exception):
    def __init__(self, value):
        Exception.__init__(self, value)
        self.value = value
