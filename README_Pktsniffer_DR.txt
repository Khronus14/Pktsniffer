To compile, in working directory:

javac Pktsniffer.java EtherFrame.java IPDatagram.java ICMPSegment.java TCPSegment.java UDPSegment.java


To execute, in working directory:

java Pktsniffer [-r <filename>] [-c <integer>] [-host <IP add>] [-port <integer>] [-net <IP add>] [-ip] [-tcp] [-udp] [-icmp]


Syntax explination.

-r <filename>	: input pcap file to analyze
-c <integer>	: number of packets to analyze; if not set, all packets will be analyized
-host <IP add>	: will print packets sent to/from this IP address
-port <integer>	: will print packets with provided port number
-net <IP add>	: will print packets sent over this network
-ip			: will print packets with an IP packet
-tcp			: will print packets with a TCP segment
-udp			: will print packets with a UDP datagram
-icmp			: will print packets with a ICMP packet


