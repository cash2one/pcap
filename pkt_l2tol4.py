from dpkt.tcp import *
from dpkt.ip import *
from dpkt.ip6 import *
from dpkt.ethernet import *
import tcp_options
import socket

class L2toL4:
    def __init__(self, buf=None):
        if buf is None:
            self.tcp = TCP()
            self.ip = IP()
            self.ip.data = self.tcp
            self.ethernet = Ethernet()
            self.ethernet.data = self.ip
            self.ethernet.type = ETH_TYPE_IP
            self.ip.p = IP_PROTO_TCP
        elif not buf:
            self.tcp = None
            self.ip = None
            self.ethernet = None
        else:
            self.ethernet = Ethernet(buf)
            if self.ethernet.type == ETH_TYPE_IP:
                self.ip = self.ethernet.data
                if self.ip.p == IP_PROTO_TCP:
                    self.tcp = self.ip.data
                else:
                    self.tcp = None
            else:
                self.ip = None
                self.tcp = None
        self._tcpOptions = None

    def __nonzero__(self):
        return self.ethernet is not None
    
    @property
    def source(self):
        if isinstance(self.ip, IP):
            return self.ip.source
        elif isinstance(self.ip, IP6):
            return socket.inet_ntop(socket.AF_INET6, self.ip.src)
    @property
    def dest(self):
        if isinstance(self.ip, IP):
            return self.ip.dest
        elif isinstance(self.ip, IP6):
            return socket.inet_ntop(socket.AF_INET6, self.ip.dst)

    def __str__(self):
        if self.ip:
            if isinstance(self.ip, IP):
                ip = "ip"
            elif isinstance(self.ip, IP6):
                ip = "ip6"
            if self.tcp is not None:
                if self.tcp.flags&TH_SYN:
                    flags = "S"
                elif self.tcp.flags&TH_FIN:
                    flags = "F"
                elif self.tcp.flags&TH_RST:
                    flags = "R"
                else:
                    flags = "-"
                if self.tcp.flags&TH_ACK:
                    flags += "A"
                else:
                    flags += "-"
                return "tcp/%s(flags=x%02x:%s) %s:%d->%s:%d" % (ip, self.tcp.flags, flags, self.source, self.tcp.sport, self.dest, self.tcp.dport)
            else:
                return "%s %s->%d" % (ip, self.source, self.dest)
        else:
            return "ethernet"
    @property
    def tcpoptions(self):
        if self.tcp is None:
            return None
        if self._tcpOptions is None:
            self._tcpOptions = tcp_options.TcpOptions(self.tcp.opts)
        return self._tcpOptions



