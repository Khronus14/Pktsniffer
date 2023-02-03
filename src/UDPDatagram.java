public class UDPDatagram {
    public final String udpTitle = String.format(Pktsniffer.title, "UDP", "UDP");
    public final String udpBreak = "UDP:";
    public String sourcePort = "UDP:  Source port = %d\n";
    public String destPort = "UDP:  Destination port = %d\n";
    public String length = "UDP:  Length = %d\n";
    public String checkSumUDP = "UDP:  Checksum = 0x%s\n";


    public StringBuilder parseUDP(byte[] udpArray) {
        StringBuilder udpMSG = new StringBuilder(udpTitle);
        udpMSG.append(udpBreak + "\n");

        // add byte 0 and 1 for source port
        String sPortHex = String.format("%02x%02x", udpArray[0], udpArray[1]);
        int sPortInt = Integer.parseInt(sPortHex, 16);
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
        if (Pktsniffer.port == -1 || lenInt == Pktsniffer.port) {
            Pktsniffer.correctPort = true;
        }
        udpMSG.append(String.format(length, lenInt));

        String checkSumHex = String.format("%02x%02x", udpArray[6], udpArray[7]);
        udpMSG.append(String.format(checkSumUDP, checkSumHex));

        udpMSG.append(udpBreak + "\n");
        Pktsniffer.nextHeader = "isEnd";
        return udpMSG;
    }
}
