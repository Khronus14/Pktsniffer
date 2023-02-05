public class ICMPSegment {
    private static final String icmpTitle = String.format(Pktsniffer.title, "ICMP", "ICMP");
    private static final String icmpBreak = "ICMP:";
    private static final String typeICMP = "TCP:  Type = %d\n";
    private static final String codeICMP = "TCP:  Code = %d\n";
    private static final String checkSumTCP = "ICMP:  Checksum = 0x%s\n";

    public static StringBuilder parseICMP(byte[] icmpArray) {
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
