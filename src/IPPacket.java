public class IPPacket {
    private static final String ipTitle = String.format(Pktsniffer.title, "IP", "IP");
    private static final String ipBreak = "IP:";
    private static final String versionIP = "IP:  Version = %c\n";
    private static final String headerLength = "IP:  Header length = %s bytes\n";
    private static final String typeOfService = """
                            IP:  Type of service = 0x%s
                            IP:     xxx. .... = %s (precedence)
                            IP:     ...%s .... = %s
                            IP:     .... %s... = %s
                            IP:     .... .%s.. = %s
                            """;
    private static final String totalLength = "IP:  Total length = %d bytes\n";
    private static final String identification = "IP:  Identification = %d\n";
    private static final String ipFlags = """
                            IP:  Flags = 0x%s
                            IP:    .%s.. .... = do%s fragment
                            IP:    ..%s. .... = %s
                            """;
    private static final String fragmentOff = "IP:  Fragment offset = %d bytes\n";
    private static final String tTL = "IP:  Time to live = %d seconds/hops\n";
    private static final String protocol = "IP:  Protocol = %s\n";
    private static final String checkSumIP = "IP:  Header checksum = %s\n";
    private static final String sourceAdd = "IP:  Source address = %d.%d.%d.%d\n";
    private static final String destAdd = "IP:  Destination address = %d.%d.%d.%d\n";
    private static final String ipOptions = "IP:  %s\n";

    public static StringBuilder parseIP(byte[] ipArray) {
        StringBuilder iPMSG = new StringBuilder(ipTitle);
        iPMSG.append(ipBreak + "\n");

        // separate first byte into two values
        String ver_lenByte = String.format("%x", ipArray[0]);
        iPMSG.append(String.format(versionIP, ver_lenByte.charAt(0)));
        String headerLen = "Unknown";
        String optionStr = "Unknown";
        if (ver_lenByte.charAt(1) == '5') {
            headerLen = "20";
            optionStr = "No options";
        }
        iPMSG.append(String.format(headerLength, headerLen));

        // check/set flags
        //TODO can this block be simplified?
        String serviceTemp = String.format("%02x", ipArray[1]); // byte value in hex
        int step1a = Integer.parseInt(serviceTemp, 16); // convert to int
        String step2a = Integer.toBinaryString(step1a); // convert to binary
        String step3a = String.format("%8s", step2a).replace(' ', '0'); // add any leading zeros
        String step4a = step3a.substring(0, 6); // trim to digits needed
        int step5a = Integer.parseInt(step4a, 2); // convert to int
        String step6a = Integer.toHexString(step5a); // convert to hex

        String precedence, delay, throughput, reliability;
        precedence = (step4a.startsWith("000")) ? "0" : "Unknown";
        delay = (step4a.charAt(3) == '0') ? "normal delay" : "Unknown";
        throughput = (step4a.charAt(4) == '0') ? "normal throughput" : "Unknown";
        reliability = (step4a.charAt(5) == '0') ? "normal reliability" : "Unknown";
        iPMSG.append(String.format(typeOfService, step6a, precedence,
                step4a.charAt(3), delay, step4a.charAt(4), throughput,
                step4a.charAt(5), reliability));

        // add byte 2 and 3 for total length
        String lenHex = String.format("%x%x", ipArray[2], ipArray[3]);
        int lenInt = Integer.parseInt(lenHex, 16);
        iPMSG.append(String.format(totalLength, lenInt));

        // add byte 4 and 5 for identification
        String idHex = String.format("%x%x", ipArray[4], ipArray[5]);
        int idInt = Integer.parseInt(idHex, 16);
        iPMSG.append(String.format(identification, idInt));

        // separate flags DF/MF
        String byteTemp = String.format("%02x", ipArray[6]);
        int step1b = Integer.parseInt(byteTemp.substring(0, 1), 16);
        String step2b = Integer.toBinaryString(step1b);
        String step3b = String.format("%4s", step2b).replace(' ', '0');
        String step4b = step3b.substring(0, 3);
        int step5b = Integer.parseInt(step4b, 2);
        String step6b = Integer.toHexString(step5b);

        // check/set flags
        String dfS = step4b.charAt(1) == '1' ? " not" : "";
        String mfS = step4b.charAt(2) == '1' ? "more fragments" : "last fragment";
        iPMSG.append(String.format(ipFlags, step6b, step4b.charAt(1), dfS, step4b.charAt(2), mfS));

        String fragOffStr = String.format("%02x%02x", ipArray[6], ipArray[7]);
        int fragOffInt = Integer.parseInt(fragOffStr.substring(1, 4), 16);
        iPMSG.append(String.format(fragmentOff, fragOffInt));

        int ttlInt = Integer.parseInt(String.format("%x", ipArray[8]), 16);
        iPMSG.append(String.format(tTL, ttlInt));

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
        iPMSG.append(String.format(protocol, protoStr));

        String checkSumHex = String.format("%02x%02x", ipArray[10], ipArray[11]);
        iPMSG.append(String.format(checkSumIP, checkSumHex));

        int[] sourceIP = parseIPAdd(ipArray, 12);
        iPMSG.append(String.format(sourceAdd,
                sourceIP[0], sourceIP[1], sourceIP[2], sourceIP[3]));

        int[] destIP = parseIPAdd(ipArray, 16);
        iPMSG.append(String.format(destAdd,
                destIP[0], destIP[1], destIP[2], destIP[3]));

        if (Pktsniffer.hostAddress != null || Pktsniffer.netAddress != null) {
            checkIPAdd(sourceIP);
            checkIPAdd(destIP);
        }

        iPMSG.append(String.format(ipOptions, optionStr));
        iPMSG.append(ipBreak + "\n");
        return iPMSG;
    }

    private static int[] parseIPAdd(byte[] ipArray, int ipIndex) {
        int[] addArray = new int[4];
        int maxIndex = ipIndex + 4;
        for (int count = 0; ipIndex < maxIndex; count++, ipIndex++) {
            addArray[count] = Integer.parseInt(String.format("%x", ipArray[ipIndex]), 16);
        }
        return addArray;
    }

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
