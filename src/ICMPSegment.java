/**
 * Support class for Pktsniffer. Handles parsing ICMP segment header.
 * Parsing is based on RFC 792, dated September 1981
 *
 * Project 1 for CSCI 651
 *
 * @author David D. Robinson, ddr6248@rit.edu
 */

public class ICMPSegment {
    private static final String icmpTitle = String.format(Pktsniffer.title, "ICMP", "ICMP");
    private static final String icmpBreak = "ICMP:\n";
    private static final String typeICMP = "ICMP:  Type = %s\n";
    private static final String codeICMP = "ICMP:  Code = %s\n";
    private static final String checkSumICMP = "ICMP:  Checksum = 0x%s\n";

    /**
     * Function to parse ICMP segment header.
     * @param icmpArray byte array containing ICMP segment
     * @param icmpMSG formatted string for output
     */
    public static void parseICMP(byte[] icmpArray, StringBuilder icmpMSG) {
        icmpMSG.append(icmpTitle).append(icmpBreak);

        // byte 0 for type of ICMP message
        String typeStr = String.format("%x", icmpArray[0]);
        switch (typeStr) {
            case "0" -> typeStr = "0 (Echo reply)";
            case "8" -> typeStr = "8 (Echo request)";
            default -> typeStr = String.format("%s (Not parsed)", typeStr);
        }
        icmpMSG.append(String.format(typeICMP, typeStr));

        // byte 1 for ICMP code
        String codeStr = String.format("%x", icmpArray[1]);
        icmpMSG.append(String.format(codeICMP, codeStr));

        // byte 2 and 3 for check sum
        String checkSumHex = String.format("%02x%02x", icmpArray[2], icmpArray[3]);
        icmpMSG.append(String.format(checkSumICMP, checkSumHex));

        icmpMSG.append(icmpBreak);
        Pktsniffer.nextHeader = "isEnd";
    }
}
