public class EtherFrame {
    private static final String etherTitle = String.format(Pktsniffer.title, "ETHER", "Ether");
    private static final String etherBreak = "ETHER:";
    private static final String pktSize = "ETHER:  Packet size = %d bytes\n";
    private static final String destMAC = "ETHER:  Destination = %02x:%02x:%02x:%02x:%02x:%02x\n";
    private static final String sourceMAC = "ETHER:  Source = %02x:%02x:%02x:%02x:%02x:%02x\n";
    private static final String etherType = "ETHER:  Ethertype = %02x%02x (%s)\n";

    public static StringBuilder parseEther(byte[] etherArray, int packetSize) {
        StringBuilder etherMSG = new StringBuilder(etherTitle);
        etherMSG.append(etherBreak + "\n");
        etherMSG.append(String.format(pktSize, packetSize));
        etherMSG.append(String.format(destMAC, etherArray[0], etherArray[1],
                etherArray[2], etherArray[3], etherArray[4], etherArray[5]));
        etherMSG.append(String.format(sourceMAC, etherArray[6], etherArray[7],
                etherArray[8], etherArray[9], etherArray[10], etherArray[11]));
        String protocol = String.format("%02x%02x", etherArray[12], etherArray[13]);
        switch (protocol) {
            case "0800" -> {
                protocol = "IPv4";
                Pktsniffer.nextHeader = "isIP";
            }
            case "86dd" -> {
                protocol = "IPv6";
                Pktsniffer.nextHeader = "isIP";
            }
            default -> {
                protocol = "Unknown";
            }
        }

        etherMSG.append(String.format(etherType, etherArray[12], etherArray[13], protocol));
        etherMSG.append(etherBreak + "\n");
        return etherMSG;
    }
}
