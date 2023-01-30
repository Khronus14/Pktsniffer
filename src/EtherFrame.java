public class EtherFrame {
    public final String etherTitle = String.format(Pktsniffer.title, "ETHER", "Ether");
    public final String etherBreak = "ETHER:";
    public final String pktSize = "ETHER:  Packet size = %d bytes\n";
    public final String destMAC = "ETHER:  Destination = %02x:%02x:%02x:%02x:%02x:%02x\n";
    public final String sourceMAC = "ETHER:  Source = %02x:%02x:%02x:%02x:%02x:%02x\n";
    public final String etherType = "ETHER:  Ethertype = %02x%02x (%s)\n";

    public void parseEther(byte[] etherArray, int packetSize) {
        StringBuilder etherMSG = new StringBuilder(etherTitle);
        etherMSG.append(etherBreak + "\n");
        etherMSG.append(String.format(pktSize, packetSize));
        etherMSG.append(String.format(destMAC, etherArray[0], etherArray[1],
                etherArray[2], etherArray[3], etherArray[4], etherArray[5]));
        etherMSG.append(String.format(sourceMAC, etherArray[6], etherArray[7],
                etherArray[8], etherArray[9], etherArray[10], etherArray[11]));
        String eType = "";
        if (etherArray[12] == 8 && etherArray[13] == 0) {
            eType = "IP";
        } else {
            eType = "Unknown";
        }
        etherMSG.append(String.format(etherType, etherArray[12], etherArray[13], eType));
        etherMSG.append(etherBreak);
        System.out.println(etherMSG);
    }
}
