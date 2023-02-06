public class ICMPSegment {
    private static final String icmpTitle = String.format(Pktsniffer.title, "ICMP", "ICMP");
    private static final String icmpBreak = "ICMP:";
    private static final String typeICMP = "ICMP:  Type = %s\n";
    private static final String codeICMP = "ICMP:  Code = %s\n";
    private static final String checkSumICMP = "ICMP:  Checksum = 0x%s\n";

    public static StringBuilder parseICMP(byte[] icmpArray) {
        StringBuilder icmpMSG = new StringBuilder(icmpTitle);
        icmpMSG.append(icmpBreak + "\n");

        String typeStr = String.format("%x", icmpArray[0]);
        switch (typeStr) {
            case "0" -> typeStr = "0 (Echo reply)";
            case "8" -> typeStr = "8 (Echo request)";
            default -> typeStr = String.format("%s (Not parsed)", typeStr);
        }
        icmpMSG.append(String.format(typeICMP, typeStr));

        String codeStr = String.format("%x", icmpArray[1]);
        icmpMSG.append(String.format(codeICMP, codeStr));

        String checkSumHex = String.format("%02x%02x", icmpArray[2], icmpArray[3]);
        icmpMSG.append(String.format(checkSumICMP, checkSumHex));

        icmpMSG.append(icmpBreak + "\n");
        Pktsniffer.nextHeader = "isEnd";

        return icmpMSG;
    }
}
