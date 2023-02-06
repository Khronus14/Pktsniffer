/**
 * Support class for Pktsniffer. Handles parsing ethernet frame header.
 * Parsing is based on IEEE 802.3
 *
 * Project 1 for CSCI 651
 *
 * @author David D. Robinson, ddr6248@rit.edu
 */

public class EtherFrame {
    private static final String etherTitle = String.format(Pktsniffer.title, "ETHER", "Ether");
    private static final String etherBreak = "ETHER:\n";
    private static final String pktSize = "ETHER:  Packet size = %d bytes\n";
    private static final String destMAC = "ETHER:  Destination = %02x:%02x:%02x:%02x:%02x:%02x\n";
    private static final String sourceMAC = "ETHER:  Source = %02x:%02x:%02x:%02x:%02x:%02x\n";
    private static final String etherType = "ETHER:  Ethertype = %02x%02x (%s)\n";

    /**
     * Function to parse ethernet frame header.
     * @param etherArray byte array containing ethernet header
     * @param etherMSG formatted string for output
     * @param packetSize size in bytes of current packet being analyzed
     */
    public static void parseEther(byte[] etherArray, StringBuilder etherMSG, int packetSize) {
        etherMSG.append(etherTitle).append(etherBreak);

        etherMSG.append(String.format(pktSize, packetSize));

        // bytes 0-5 for destination MAC address
        etherMSG.append(String.format(destMAC, etherArray[0], etherArray[1],
                etherArray[2], etherArray[3], etherArray[4], etherArray[5]));

        // bytes 6-11 for destination MAC address
        etherMSG.append(String.format(sourceMAC, etherArray[6], etherArray[7],
                etherArray[8], etherArray[9], etherArray[10], etherArray[11]));

        // bytes 12 and 13 for ethernet type
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
            default -> protocol = "Unknown";

        }
        etherMSG.append(String.format(etherType, etherArray[12], etherArray[13], protocol));

        etherMSG.append(etherBreak);
    }
}
