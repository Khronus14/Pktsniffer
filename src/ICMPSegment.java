public class ICMPSegment {
    public final String icmpTitle = String.format(Pktsniffer.title, "ICMP", "ICMP");
    public final String icmpBreak = "ICMP:";
    public String typeICMP = "TCP:  Type = %d\n";
    public String codeICMP = "TCP:  Code = %d\n";
    public String checkSumTCP = "ICMP:  Checksum = 0x%s\n";

    public StringBuilder parseICMP(byte[] icmpArray) {
        StringBuilder icmpMSG = new StringBuilder(icmpTitle);
        icmpMSG.append(icmpBreak + "\n");

        String typeStr = String.format("%x", icmpArray[0]);
        icmpMSG.append(String.format(typeICMP, typeStr));

        String codeStr = String.format("%x", icmpArray[1]);
        icmpMSG.append(String.format(codeICMP, codeStr));

        String checkSumHex = String.format("%02x%02x", icmpArray[2], icmpArray[3]);
        icmpMSG.append(String.format(checkSumTCP, checkSumHex));

        icmpMSG.append(icmpBreak + "\n");
        Pktsniffer.nextHeader = "isEnd";

        return icmpMSG;
    }
}
