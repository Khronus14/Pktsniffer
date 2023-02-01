import java.math.BigInteger;

public class TCPSegment {
    public final String tcpTitle = String.format(Pktsniffer.title, "TCP", "TCP");
    public final String tcpBreak = "TCP:";
    public String sourcePort = "TCP:  Source port = %d\n";
    public String destPort = "TCP:  Destination port = %d\n";
    public String seqNum = "TCP:  Sequence number = %d\n";
    public String ackNum = "TCP:  Acknowledgment number = %d\n";
    public String dataOffset = "TCP:  Data offset = %s bytes\n";
    public String tcpFlags = """
                             TCP:  Flags = 0x%s
                             TCP:    ..%s. .... = %s pointer
                             TCP:    ...%s .... = %s
                             TCP:    .... %s... = %s
                             TCP:    .... .%s.. = %s
                             TCP:    .... ..%s. = %s
                             TCP:    .... ...%s = %s
                             """;
    public String window = "TCP:  Window = %d\n";
    public String checkSumTCP = "TCP:  Checksum = 0x%s\n";
    public String urgentPointer = "TCP:  Urgent pointer = %s\n";
    public String tcpOptions = "TCP:  %s\n";
    public String tcpOptionStr = "Unknown";

    public void parseTCP(byte[] tcpArray) {
        StringBuilder tcpMSG = new StringBuilder(tcpTitle);
        tcpMSG.append(tcpBreak + "\n");

        // add byte 0 and 1 for source port
        String sPortHex = String.format("%02x%02x", tcpArray[0], tcpArray[1]);
        int sPortInt = Integer.parseInt(sPortHex, 16);
        tcpMSG.append(String.format(sourcePort, sPortInt));

        // add byte 2 and 3 for destination port
        String dPortHex = String.format("%02x%02x", tcpArray[2], tcpArray[3]);
        int dPortInt = Integer.parseInt(dPortHex, 16);
        tcpMSG.append(String.format(destPort, dPortInt));

        // add byte 4-7 for sequence number
        String seqHex = String.format("%x%x%x%x", tcpArray[4], tcpArray[5],
                tcpArray[6], tcpArray[7]);
        BigInteger seqInt = new BigInteger(seqHex, 16);
        tcpMSG.append(String.format(seqNum, seqInt));

        // add byte 4-7 for acknowledgement number
        String ackHex = String.format("%x%x%x%x", tcpArray[8], tcpArray[9],
                tcpArray[10], tcpArray[11]);
        BigInteger ackInt = new BigInteger(ackHex, 16);
        tcpMSG.append(String.format(ackNum, ackInt));

        // separate byte to parse first bit for data offset
        String dataOffStr = String.format("%02x", tcpArray[12]);
        String offsetLen = "Unknown";
        if (dataOffStr.charAt(0) == '5') {
            offsetLen = "20";
            tcpOptionStr = "No options";
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

        // add byte 14 and 15 for window size
        String winHex = String.format("%02x%02x", tcpArray[14], tcpArray[15]);
        int winInt = Integer.parseInt(winHex, 16);
        tcpMSG.append(String.format(window, winInt));

        String checkSumHex = String.format("%02x%02x", tcpArray[16], tcpArray[17]);
        tcpMSG.append(String.format(checkSumTCP, checkSumHex));

        String pointer = "0";
        if (urgent.equals("Urgent")) {
            pointer = String.format("%02x%02x", tcpArray[18], tcpArray[19]);
        }
        tcpMSG.append(String.format(urgentPointer, pointer));

        tcpMSG.append(String.format(tcpOptions, tcpOptionStr));

        tcpMSG.append(tcpBreak);

        // reset values
        tcpOptionStr = "Unknown";

        System.out.println(tcpMSG);
    }
}
