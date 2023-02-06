

javac Pktsniffer.java EtherFrame.java IPPacket.java ICMPSegment.java TCPSegment.java UDPDatagram.java

Syntax

java Pktsniffer [-r <filename>] [-c <integer>] [-host <IP add>] [-port <integer>] [-net <IP add>] [-ip] [-tcp] [-udp] [-icmp]



-r <filename>	: input pcap file to analyze
-c <integer>	: number of packets to analyze; if not set, all packets will be analyized
-host <IP add>	: will print only packets sent to/from this IP address
-port <integer>	: will print only packets with provided port number
-net <IP add>	: will print only packets sent over this network
-ip			: will print only packets with an IP packet*
-tcp			: will print only packets with a TCP segment*
-udp			: will print only packets with a UDP datagram*
-icmp			: will print only packets with a ICMP packet*


* - These flags are indenpendant of each other, i.e., if -ip and -udp are set, a packet that contains either
	one will print.

