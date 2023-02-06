/**
 * Support class for Pktsniffer. Handles parsing IP packet header.
 * Parsing is based on RFC 791, dated September 1981
 *
 * Project 1 for CSCI 651
 *
 * @author David D. Robinson, ddr6248@rit.edu
 */

public class IPDatagram {
    private static final String ipTitle = String.format(Pktsniffer.title, "IP", "IP");
    private static final String ipBreak = "IP:\n";
    private static final String versionIP = "IP:  Version = %c\n";
    private static final String headerLength = "IP:  Header length = %s bytes\n";
    private static final String typeOfService = """
                            IP:  Type of service = 0x%s
                            IP:     xxx. .... = %d (precedence)
                            IP:     ...%s .... = %s delay
                            IP:     .... %s... = %s throughput
                            IP:     .... .%s.. = %s reliability
                            """;
    private static final String totalLength = "IP:  Total length = %d bytes\n";
    private static final String identification = "IP:  Identification = %d\n";
    private static final String ipFlags = """
                            IP:  Flags = 0x%s
                            IP:    .%s.. .... = %s fragment
                            IP:    ..%s. .... = %s fragment%s
                            """;
    private static final String fragmentOff = "IP:  Fragment offset = %d bytes\n";
    private static final String tTL = "IP:  Time to live = %d seconds/hops\n";
    private static final String protocol = "IP:  Protocol = %s\n";
    private static final String checkSumIP = "IP:  Header checksum = 0x%s\n";
    private static final String sourceAdd = "IP:  Source address = %d.%d.%d.%d\n";
    private static final String destAdd = "IP:  Destination address = %d.%d.%d.%d\n";
    private static final String ipOptions = "IP:  Options = %s\n";

    /**
     * Function to parse IP packet header.
     * @param ipArray byte array containing IP header
     * @param ipMSG formatted string for output
     */
    public static void parseIP(byte[] ipArray, StringBuilder ipMSG) {
        ipMSG.append(ipTitle).append(ipBreak);

        // separate first byte into two values
        String ver_lenByte = String.format("%02x", ipArray[0]);
        if (ver_lenByte.charAt(0) == '6') {
            System.out.println("""
                    IPv6 packet header detected.
                    Program does not parse IPv6 packet headers.
                    """);
            System.exit(0);
        }
        ipMSG.append(String.format(versionIP, ver_lenByte.charAt(0)));
        String headerLen = "Unknown";
        String optionStr = "Unknown";
        if (ver_lenByte.charAt(1) == '5') {
            headerLen = "20";
            optionStr = "No options";
        }
        ipMSG.append(String.format(headerLength, headerLen));

        // separate byte 1 for service flags
        String serviceTemp = String.format("%02x", ipArray[1]); // byte value in hex
        int step1a = Integer.parseInt(serviceTemp, 16); // convert to int
        String step2a = Integer.toBinaryString(step1a); // convert to binary
        String step3a = String.format("%8s", step2a).replace(' ', '0'); // add any leading zeros
        String step4a = step3a.substring(0, 6); // trim to digits needed

        // set service flags
        String delay, throughput, reliability;
        int precedence = Integer.parseInt(step4a.substring(0, 3),2);
        delay = (step4a.charAt(3) == '0') ? "normal" : "low";
        throughput = (step4a.charAt(4) == '0') ? "normal" : "high";
        reliability = (step4a.charAt(5) == '0') ? "normal" : "high";
        ipMSG.append(String.format(typeOfService, serviceTemp, precedence,
                step4a.charAt(3), delay, step4a.charAt(4), throughput,
                step4a.charAt(5), reliability));

        // add byte 2 and 3 for total length
        String lenHex = String.format("%02x%02x", ipArray[2], ipArray[3]);
        int lenInt = Integer.parseInt(lenHex, 16);
        ipMSG.append(String.format(totalLength, lenInt));

        // add byte 4 and 5 for identification
        String idHex = String.format("%02x%02x", ipArray[4], ipArray[5]);
        int idInt = Integer.parseInt(idHex, 16);
        ipMSG.append(String.format(identification, idInt));

        // separate byte 6 for fragment flags
        String byteTemp = String.format("%02x", ipArray[6]);
        int step1b = Integer.parseInt(byteTemp.substring(0, 1), 16);
        String step2b = Integer.toBinaryString(step1b);
        String step3b = String.format("%4s", step2b).replace(' ', '0');
        String step4b = step3b.substring(0, 3);
        int step5b = Integer.parseInt(step4b, 2);
        String step6b = Integer.toHexString(step5b);

        // check/set flags
        String dfS = step4b.charAt(1) == '0' ? "may" : "don't";
        String mfS = step4b.charAt(2) == '0' ? "last" : "more";
        String mfSplural = step4b.charAt(2) == '0' ? "" : "s";
        ipMSG.append(String.format(ipFlags, step6b, step4b.charAt(1), dfS, step4b.charAt(2), mfS, mfSplural));

        // add byte 6 and 7 for fragment offset
        String fragOffStr = String.format("%02x%02x", ipArray[6], ipArray[7]);
        int fragOffInt = Integer.parseInt(fragOffStr.substring(1, 4), 16);
        ipMSG.append(String.format(fragmentOff, fragOffInt));

        // byte 8 for time to live
        int ttlInt = Integer.parseInt(String.format("%x", ipArray[8]), 16);
        ipMSG.append(String.format(tTL, ttlInt));

        // byte 9 for type of protocol
        String protoHex = String.format("%x", ipArray[9]);
        String protoStr = "Unknown";
        switch (protoHex) {
            case "1" -> {
                protoStr = "1 (ICMP)";
                Pktsniffer.nextHeader = "isICMP";
            }
            case "6" -> {
                protoStr = "6 (TCP)";
                Pktsniffer.nextHeader = "isTCP";
            }
            case "11" -> {
                protoStr = "17 (UDP)";
                Pktsniffer.nextHeader = "isUDP";
            }
        }
        ipMSG.append(String.format(protocol, protoStr));

        // add byte 10 and 11 for check sum
        String checkSumHex = String.format("%02x%02x", ipArray[10], ipArray[11]);
        ipMSG.append(String.format(checkSumIP, checkSumHex));

        // bytes 12-15 for source address
        int[] sourceIP = parseIPAdd(ipArray, 12);
        ipMSG.append(String.format(sourceAdd,
                sourceIP[0], sourceIP[1], sourceIP[2], sourceIP[3]));

        // bytes 16-19 for destination address
        int[] destIP = parseIPAdd(ipArray, 16);
        ipMSG.append(String.format(destAdd,
                destIP[0], destIP[1], destIP[2], destIP[3]));

        // check each address if filtering by net or host
        if (Pktsniffer.hostAddress != null || Pktsniffer.netAddress != null) {
            checkIPAdd(sourceIP);
            checkIPAdd(destIP);
        }

        ipMSG.append(String.format(ipOptions, optionStr));
        ipMSG.append(ipBreak);
    }

    /**
     * Helper function parse packet IP addresses.
     * @param ipArray byte array containing IP address
     * @param ipIndex first byte of the address in the array
     * @return int array containing IP address from pcap file
     */
    private static int[] parseIPAdd(byte[] ipArray, int ipIndex) {
        int[] addArray = new int[4];
        int maxIndex = ipIndex + 4;
        for (int count = 0; ipIndex < maxIndex; count++, ipIndex++) {
            addArray[count] = Integer.parseInt(String.format("%x", ipArray[ipIndex]), 16);
        }
        return addArray;
    }

    /**
     * Helper function to check for filtered IP address.
     * @param ipAdd address to be checked against user input
     */
    private static void checkIPAdd(int[] ipAdd) {
        if (Pktsniffer.hostAddress != null) {
            if (ipAdd[0] == Pktsniffer.hostAddress[0] &&
                    ipAdd[1] == Pktsniffer.hostAddress[1] &&
                    ipAdd[2] == Pktsniffer.hostAddress[2] &&
                    ipAdd[3] == Pktsniffer.hostAddress[3]) {
                Pktsniffer.hostMatch = true;
            }
        }
        if (Pktsniffer.netAddress != null) {
            if (ipAdd[0] == Pktsniffer.netAddress[0] &&
                    ipAdd[1] == Pktsniffer.netAddress[1] &&
                    ipAdd[2] == Pktsniffer.netAddress[2]) {
                Pktsniffer.netMatch = true;
            }
        }
    }
}
