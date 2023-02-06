/**
 * Support class for Pktsniffer. Handles parsing TCP segment header.
 * Parsing is based on RFC 793, dated September 1981
 *
 * Project 1 for CSCI 651
 *
 * @author David D. Robinson, ddr6248@rit.edu
 */

import java.math.BigInteger;

public class TCPSegment {
    private static final String tcpTitle = String.format(Pktsniffer.title, "TCP", "TCP");
    private static final String tcpBreak = "TCP:\n";
    private static final String sourcePort = "TCP:  Source port = %d\n";
    private static final String destPort = "TCP:  Destination port = %d\n";
    private static final String seqNum = "TCP:  Sequence number = %d\n";
    private static final String ackNum = "TCP:  Acknowledgment number = %d\n";
    private static final String dataOffset = "TCP:  Data offset = %s bytes\n";
    private static final String tcpFlags = """
                             TCP:  Flags = 0x%s
                             TCP:    ..%s. .... = %s pointer
                             TCP:    ...%s .... = %s
                             TCP:    .... %s... = %s
                             TCP:    .... .%s.. = %s
                             TCP:    .... ..%s. = %s
                             TCP:    .... ...%s = %s
                             """;
    private static final String window = "TCP:  Window = %d\n";
    private static final String checkSumTCP = "TCP:  Checksum = 0x%s\n";
    private static final String urgentPointer = "TCP:  Urgent pointer = %s\n";
    private static final String tcpOptions = "TCP:  Options = %s\n";

    /**
     * Function to parse TCP segment header.
     * @param tcpArray byte array containing TCP header
     * @param tcpMSG formatted string for output
     */
    public static void parseTCP(byte[] tcpArray, StringBuilder tcpMSG) {
        tcpMSG.append(tcpTitle).append(tcpBreak);

        // add byte 0 and 1 for source port
        String sPortHex = String.format("%02x%02x", tcpArray[0], tcpArray[1]);
        int sPortInt = Integer.parseInt(sPortHex, 16);
        if (Pktsniffer.port == -1 || sPortInt == Pktsniffer.port) {
            Pktsniffer.correctPort = true;
        }
        tcpMSG.append(String.format(sourcePort, sPortInt));

        // add byte 2 and 3 for destination port
        String dPortHex = String.format("%02x%02x", tcpArray[2], tcpArray[3]);
        int dPortInt = Integer.parseInt(dPortHex, 16);
        if (Pktsniffer.port == -1 || dPortInt == Pktsniffer.port) {
            Pktsniffer.correctPort = true;
        }
        tcpMSG.append(String.format(destPort, dPortInt));

        // add byte 4-7 for sequence number
        String seqHex = String.format("%02x%02x%02x%02x", tcpArray[4], tcpArray[5],
                tcpArray[6], tcpArray[7]);
        BigInteger seqInt = new BigInteger(seqHex, 16);
        tcpMSG.append(String.format(seqNum, seqInt));

        // add byte 8-11 for acknowledgement number
        String ackHex = String.format("%02x%02x%02x%02x", tcpArray[8], tcpArray[9],
                tcpArray[10], tcpArray[11]);
        BigInteger ackInt = new BigInteger(ackHex, 16);
        tcpMSG.append(String.format(ackNum, ackInt));

        // separate byte 12 to parse first bit for data offset
        String dataOffStr = String.format("%02x", tcpArray[12]);
        String offsetLen = "Unknown";
        String tcpOptionStr = "Unknown";
        switch (dataOffStr.charAt(0)) {
            case '5' -> {
                offsetLen = "20";
                tcpOptionStr = "No options";
            }
            case '8' -> {
                offsetLen = "32";
                tcpOptionStr = "12 bytes long";
            }
            default -> offsetLen = String.format("%s (Not parsed)", offsetLen);
        }
        tcpMSG.append(String.format(dataOffset, offsetLen));

        // separate flags
        String flagTemp = String.format("%02x", tcpArray[13]); // prints 10, the byte value in hex
        int step1 = Integer.parseInt(flagTemp, 16); // prints 16
        String step2 = Integer.toBinaryString(step1); // prints 10000
        String step3 = String.format("%8s", step2).replace(' ', '0'); // prints 00010000
        String step4 = step3.substring(2, 8); // prints 010000
        int step5 = Integer.parseInt(step4, 2);
        String step6 = Integer.toHexString(step5); // prints 10

        // check/set flags
        String urgent, ack, push, reset, sync, fin;
        urgent = (step4.charAt(0) == '0') ? "No urgent" : "Urgent";
        ack = (step4.charAt(1) == '0') ? "Not acknowledged" : "Acknowledgement";
        push = (step4.charAt(2) == '0') ? "No push" : "Push";
        reset = (step4.charAt(3) == '0') ? "No reset" : "Reset";
        sync = (step4.charAt(4) == '0') ? "No Syn" : "Sync";
        fin = (step4.charAt(5) == '0') ? "No Fin" : "Final";

        tcpMSG.append(String.format(tcpFlags, step6, step4.charAt(0), urgent,
                step4.charAt(1), ack, step4.charAt(2), push,
                step4.charAt(3), reset, step4.charAt(4), sync,
                step4.charAt(5), fin));

        // byte 14 and 15 for window size
        String winHex = String.format("%02x%02x", tcpArray[14], tcpArray[15]);
        int winInt = Integer.parseInt(winHex, 16);
        tcpMSG.append(String.format(window, winInt));

        // byte 16 and 17 for check sum
        String checkSumHex = String.format("%02x%02x", tcpArray[16], tcpArray[17]);
        tcpMSG.append(String.format(checkSumTCP, checkSumHex));

        // byte 18 and 19 for pointer
        String pointer = "0";
        if (urgent.equals("Urgent")) {
            pointer = String.format("%02x%02x", tcpArray[18], tcpArray[19]);
        }
        tcpMSG.append(String.format(urgentPointer, pointer));

        tcpMSG.append(String.format(tcpOptions, tcpOptionStr));
        tcpMSG.append(tcpBreak);

        Pktsniffer.nextHeader = "isEnd";
    }
}
