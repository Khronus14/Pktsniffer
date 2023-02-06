/**
 * Support class for Pktsniffer. Handles parsing UDP datagram header.
 * Parsing is based on RFC 768, dated 28 August 1980
 *
 * Project 1 for CSCI 651
 *
 * @author David D. Robinson, ddr6248@rit.edu
 */

public class UDPSegment {
    private static final String udpTitle = String.format(Pktsniffer.title, "UDP", "UDP");
    private static final String udpBreak = "UDP:\n";
    private static final String sourcePort = "UDP:  Source port = %d\n";
    private static final String destPort = "UDP:  Destination port = %d\n";
    private static final String length = "UDP:  Length = %d\n";
    private static final String checkSumUDP = "UDP:  Checksum = 0x%s\n";

    /**
     * Function to parse UDP datagram header.
     * @param udpArray byte array containing UDP datagram
     * @param udpMSG formatted string for output
     */
    public static void parseUDP(byte[] udpArray, StringBuilder udpMSG) {
        udpMSG.append(udpTitle).append(udpBreak);

        // add byte 0 and 1 for source port
        String sPortHex = String.format("%02x%02x", udpArray[0], udpArray[1]);
        int sPortInt = Integer.parseInt(sPortHex, 16);
        if (Pktsniffer.port == -1 || sPortInt == Pktsniffer.port) {
            Pktsniffer.correctPort = true;
        }
        udpMSG.append(String.format(sourcePort, sPortInt));

        // add byte 2 and 3 for destination port
        String dPortHex = String.format("%02x%02x", udpArray[2], udpArray[3]);
        int dPortInt = Integer.parseInt(dPortHex, 16);
        if (Pktsniffer.port == -1 || dPortInt == Pktsniffer.port) {
            Pktsniffer.correctPort = true;
        }
        udpMSG.append(String.format(destPort, dPortInt));

        // add byte 4 and 5 for length
        String lenHex = String.format("%02x%02x", udpArray[4], udpArray[5]);
        int lenInt = Integer.parseInt(lenHex, 16);
        udpMSG.append(String.format(length, lenInt));

        // byte 6 and 7 for check sum
        String checkSumHex = String.format("%02x%02x", udpArray[6], udpArray[7]);
        udpMSG.append(String.format(checkSumUDP, checkSumHex));

        udpMSG.append(udpBreak);
        Pktsniffer.nextHeader = "isEnd";
    }
}
