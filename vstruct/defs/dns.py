
import vstruct
from vstruct.primitives import *

DNS_FLAG_RESPONSE       = 0x8000
DNS_FLAG_AUTHORITATIVE  = 0x0400

DNS_TYPE_A     = 1
DNS_TYPE_CNAME = 5

DNS_CLASS_IN   = 1

class DnsNamePart(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.length = v_uint8()
        self.namepart = v_str()

    def pcb_length(self):
        size = self.length
        if size == 0xc0: size = 1 # FIXME offsets for name...
        self.vsGetField('namepart').vsSetLength(size)

    def isNameTerm(self):
        if self.length == 0:
            return True
        if self.length == 0xc0:
            return True
        return False

class DnsName(vstruct.VArray):

    def __init__(self):
        vstruct.VStruct.__init__(self)

    def getFullName(self, dnspkt):
        r = []
        for fname,fobj in self.vsGetFields():
            if fobj.length == 0xc0:
                newn = DnsName()
                # FIXME redundant parsing...
                newn.vsParse(dnspkt, ord(fobj.namepart))
                r.append( newn.getFullName(dnspkt) )
            else:
                r.append(fobj.namepart)
        return '.'.join(r)

    def vsParse(self, bytes, offset=0):
        self.vsClearFields()
        while offset < len(bytes):
            np = DnsNamePart()
            offset = np.vsParse(bytes, offset=offset)
            self.vsAddElement(np)
            if np.isNameTerm():
                break
        return offset

class DnsQuery(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.qname  = DnsName()
        self.qtype  = v_uint16(bigend=True)
        self.qclass = v_uint16(bigend=True)

class DnsQueryArray(vstruct.VArray):

    def __init__(self, reccnt):
        vstruct.VArray.__init__(self)
        for i in xrange(reccnt):
            self.vsAddElement( DnsQuery() )

class DnsAnswer(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.qname      = DnsName()
        self.qtype      = v_uint16(bigend=True)
        self.qclass     = v_uint16(bigend=True)
        self.qttl       = v_uint32(bigend=True)
        self.dlength    = v_uint16(bigend=True)
        self.qdata      = v_bytes()

    def pcb_dlength(self):
        size = self.dlength
        self.vsGetField('qdata').vsSetLength(size)

class DnsAnswerArray(vstruct.VArray):

    def __init__(self, reccnt):
        vstruct.VArray.__init__(self)
        for i in xrange(reccnt):
            self.vsAddElement( DnsAnswer() )

class DnsPacket(vstruct.VStruct):

    def __init__(self):
        vstruct.VStruct.__init__(self)
        #self.length   = v_uint16(bigend=True)
        self.transid  = v_uint16(bigend=True)
        self.flags    = v_uint16(bigend=True)
        self.ques_cnt = v_uint16(bigend=True)
        self.answ_cnt = v_uint16(bigend=True)
        self.auth_cnt = v_uint16(bigend=True)
        self.addt_cnt = v_uint16(bigend=True)
        self.records  = vstruct.VStruct()
        self.records.queries = DnsQueryArray(0)
        self.records.answers = DnsAnswerArray(0)
        self.records.authns  = DnsAnswerArray(0)
        self.records.addtl   = DnsAnswerArray(0)

    def pcb_ques_cnt(self):
        self.records.queries = DnsQueryArray( self.ques_cnt )

    def pcb_answ_cnt(self):
        self.records.answers = DnsAnswerArray( self.answ_cnt )

    def pcb_auth_cnt(self):
        self.records.authns = DnsAnswerArray( self.auth_cnt )

    def pcb_addt_cnt(self):
        self.records.addtl = DnsAnswerArray( self.addt_cnt )

