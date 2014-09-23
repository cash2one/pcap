import dpkt
import m.common as common

class iEthernet(common.GeneratorBase):
    STATIC_VARIABLE_NAMES = ["timestamp", "ethernet"] 
    def __init__(self, fileHandler):
        self.fileHandler = fileHandler
        self.pcap = iter(dpkt.pcap.Reader(self.fileHandler))
    def __iter__(self):
        return self
    def close(self):
        self.fileHandler.close()
    def next(self):
        try:
            (ts, pcapData) = self.pcap.next()
            return (ts, dpkt.ethernet.Ethernet(pcapData))
        except StopIteration:
            raise StopIteration
    def getVariableNames(self):
        return iEthernet.STATIC_VARIABLE_NAMES

class iIP(iEthernet):
    STATIC_VARIABLE_NAMES = iEthernet.STATIC_VARIABLE_NAMES + ["ip"]
    def __init__(self, fileHandler):
        iEthernet.__init__(self, fileHandler)
    def next(self):
        while(True):
            try:
                (ts, ethernet) = iEthernet.next(self)
                if ethernet.type == dpkt.ethernet.ETH_TYPE_IP or  ethernet.type == dpkt.ethernet.ETH_TYPE_IP6:
                    ip = ethernet.data
                    return (ts, ethernet, ethernet.data)
            except:
                raise
        raise StopIteration
    def getVariableNames(self):
        return iIP.STATIC_VARIABLE_NAMES

class iTCP(iIP):
    STATIC_VARIABLE_NAMES = iIP.STATIC_VARIABLE_NAMES + ["tcp"]
    def __init__(self, fileHandler):
        iIP.__init__(self, fileHandler)
        self.streamMap = {}
        self.streamCnt = 0
    def next(self):
        while(True):
            try:
                (ts, ethernet, ip) = iIP.next(self)
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    if tcp.sport < tcp.dport:
                        key = (ip.dst, tcp.dport, ip.src, tcp.sport)
                        seqIndex = 2
                    else:
                        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                        seqIndex = 1
                    stream = self.streamMap.get(key, None)
                    if not stream:
                        stream = [self.streamCnt, 0, 0, seqIndex]
                        self.streamMap[key] = stream
                        self.streamCnt += 1
                    elif (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK):
                        # if stream exist but it is SYN packet - still update new stream counter
                        stream[0] = self.streamCnt
                        self.streamCnt += 1
                        stream[3] = seqIndex
                    
                    if tcp.flags & dpkt.tcp.TH_SYN:
                        # update initial sequence numbers
                        stream[seqIndex] = tcp.seq
                    
                    tcp.relativeSeq = tcp.seq - stream[seqIndex]
                    if tcp.relativeSeq < 0:
                        tcp.relativeSeq += 0xFFffFFff
                    tcp.relativeAck = tcp.ack - stream[3-seqIndex]
                    if tcp.relativeAck < 0:
                        tcp.relativeAck += 0xFFffFFff
                    tcp.stream = stream[0]
                    tcp.isRequest = (stream[3] == seqIndex)
                    return (ts, ethernet, ip, tcp)
            except:
                raise
        raise StopIteration
    def getVariableNames(self):
        return iTCP.STATIC_VARIABLE_NAMES
    
class oEthernet():
    def __init__(self, fileName, variableNames):
        self.myFileName = fileName
        self.myTimestampVarId = variableNames.index("timestamp")
        if self.myTimestampVarId < 0:
            raise common.CompilationError("timestamp variable for output pcap stream not available")
        self.myPacketVarId = variableNames.index("ethernet")
        if self.myPacketVarId < 0:
            raise common.CompilationError("ethernet variable for output pcap stream not available")
        self.fileHandle = open(fileName, "wb")
        self.pcapWriter = dpkt.pcap.Writer(self.fileHandle)
    def save(self, record):
        self.pcapWriter.writepkt(record[self.myPacketVarId], ts=record[self.myTimestampVarId])
    def close(self):
        self.pcapWriter.close()
                