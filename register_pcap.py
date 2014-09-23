import miner_globals
import dpkt.ethernet
import dpkt.ip
import dpkt.tcp
from pkt_l2tol4 import L2toL4
from tcp_options import TcpOptions

ethernet = dpkt.ethernet.Ethernet()
ethernet.type = dpkt.ethernet.ETH_TYPE_IP
ip = dpkt.ip.IP()
ip.p = dpkt.ip.IP_PROTO_TCP
ethernet.data = ip
ip.data = dpkt.tcp.TCP()
ip.source = "1.1.1.1"
ip.dest = "1.1.1.1"

tcp = dpkt.tcp.TCP()
tcp.relativeSeq = 0
tcp.relativeAck = 0
tcp.stream = 0
tcp.isRequest = True

# define symbols for completion
miner_globals.addCompletionSymbol('timestamp', 0)
miner_globals.addCompletionSymbol('ethernet', ethernet)
miner_globals.addCompletionSymbol('ip', ip)
miner_globals.addCompletionSymbol('tcp', tcp)

# define targets
miner_globals.addExtensionToTargetMapping(".cap", "tcp")
miner_globals.addExtensionToTargetMapping(".pcap", "tcp")
miner_globals.addTargetToClassMapping("tcp", "pcap_streams.iTCP", "pcap_streams.oEthernet", "reads tcp packets from pcap file, record is (timestamp, ethernet, ip, tcp)")
miner_globals.addTargetToClassMapping("ip", "pcap_streams.iIP", None, "reads ip packets from pcap file, record is (timestamp, ethernet, ip)")
miner_globals.addTargetToClassMapping("ethernet", "pcap_streams.iEthernet", None, "reads ethernet packets from pcap file, record is (timestamp, ethernet)")

l2tol4 = L2toL4()
miner_globals.addParserClassMapping("l2tol4", "pkt_l2tol4.L2toL4", "L2 to L4 packet headers")
miner_globals.addCompletionSymbol('l2tol4', l2tol4)

tcpopts = TcpOptions("")
miner_globals.addParserClassMapping("tcpopts", "tcp_options.TcpOptions", "tcp options")
miner_globals.addCompletionSymbol('tcpopts', tcpopts)
miner_globals.addParserMapping("tcpopts", "tcp", "tcp_options.parseOptionsFromTcp")

