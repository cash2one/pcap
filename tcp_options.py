from dpkt.tcp import *
import struct

class TcpOptions:
    def __init__(self, tcpOptionsBuf):
        if tcpOptionsBuf:
            self.tcpOptions = parse_opts(tcpOptionsBuf)
        else:
            self.tcpOptions = []
    def __len__(self):
        return len(self.tcpOptions)
    def __contains__(self, key):
        for o in self.tcpOptions:
            if key == o[0]:
                return True
        return False
    def iteritems(self):
        return iter(self.tcpOptions)
    def iterkeys(self):
        return (o[0] for o in self.tcpOptions)
    def items(self):
        return self.tcpOptions
    def keys(self):
        return [o[0] for o in self.tcpOptions]
    def __iter__(self):
        return (o[0] for o in self.tcpOptions)
    def __getitem__(self, key):
        for (k,v) in self.tcpOptions:
            if key == k:
                return v
        raise IndexError
    def get(self, key, default=None):
        for (k,v) in self.tcpOptions:
            if key == k:
                return v
        return default

    def getuint(self, key, default=0):
        val = self.get(key)
        if not val:
            return default
        l = len(val)
        if l==0:
            return 0
        elif l==1:
            return struct.unpack("!B", val)[0]
        elif l==2:
            return struct.unpack("!H", val)[0]
        elif l==4:
            return struct.unpack("!L", val)[0]
        elif l==8:
            return struct.unpack("!Q", val)[0]
        return default
    
    def hasWscale(self):
        return self.__contains__(TCP_OPT_WSCALE)
    @property 
    def wscale(self):
        return self.getuint(TCP_OPT_WSCALE, default=0)

    def hasMss(self):
        return self.__contains__(TCP_OPT_MSS)
    @property 
    def mss(self):
        return self.getuint(TCP_OPT_MSS, default=0)
    # returns (TS value, TS echo Reply)

    def hasTimestamp(self):
        return self.__contains__(TCP_OPT_TIMESTAMP)
    @property
    def timestamp(self):
        val = self.get(TCP_OPT_TIMESTAMP)
        if not val:
            return (0, 0)
        return struct.unpack("!LL", val)
    
    def sackPermitted(self):
        return self.__contains__(TCP_OPT_SACKOK)
    
    def hasSack(self):
        return self.__contains__(TCP_OPT_SACK)
    @property
    def sack(self):
        buf = self.get(TCP_OPT_SACK)
        if not buf:
            return
        numRanges = len(buf)/8
        format = "II"*numRanges
        t = struct.unpack("!"+format, buf)
        res = []
        for i in range(numRanges):
            res.append( (t[i*2], t[i*2+1]) )
        return res
    def __str__(self):
        s = "[%s]" % ",".join(map(str,self.keys()))
        if self.hasWscale():
            s+=",wscale"
        if self.sackPermitted():
            s+=",sackok"
        if self.hasSack():
            s+=",sack"
        if self.hasTimestamp():
            s += ",ts"
        if self.hasMss():
            s += ",mss"
        return s

def parseOptionsFromTcp(tcp):
    return TcpOptions(tcp.opts)
