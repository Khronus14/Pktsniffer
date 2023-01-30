public class IPStack {
    public final String iPTitle = String.format(Pktsniffer.title, "IP", "IP");
    public final String IPBreak = "IP:";
    public String versionIP = "IP:  Version = %c\n";
    public String headerLength = "IP:  Header length = %s bytes\n";
    public String typeOfService = "IP:  Type of service = ***NOT IMPLEMENTED\n";
    public String totalLength = "IP:  Total length = %d bytes\n";
    public String identification = "IP:  Identification = %d\n";
    public String flags = """
                             IP:  Flags = 0x%d
                             IP:    .%s.. .... = do%s fragment
                             IP:    ..%s. .... = %s
                             """;
    public String fragmentOff = "IP:  Fragment offset = %d\n";

    public void parseIP(byte[] ipArray) {
        StringBuilder iPMSG = new StringBuilder(iPTitle);
        iPMSG.append(IPBreak + "\n");

        // separate first byte into two values
        String ver_lenByte = String.format("%x", ipArray[0]);
        iPMSG.append(String.format(versionIP, ver_lenByte.charAt(0)));
        String headerLen = "Unknown";
        if (ver_lenByte.charAt(1) == '5') {
            headerLen = "20";
        }
        iPMSG.append(String.format(headerLength, headerLen));
        iPMSG.append(String.format(typeOfService, ipArray[1]));

        // add byte 2 and 3 for total length
        String lenHex = String.format("%x", ipArray[2]) + String.format("%x", ipArray[3]);
        int lenInt = Integer.parseInt(lenHex, 16);
        iPMSG.append(String.format(totalLength, lenInt));

        // add byte 4 and 5 for identification
        String idHex = String.format("%x", ipArray[4]) + String.format("%x", ipArray[5]);
        int idInt = Integer.parseInt(idHex, 16);
        iPMSG.append(String.format(identification, idInt));

        // separate flags DF/MF
        //TODO can this block be simplified?
        String byteTemp = String.format("%x", ipArray[6]); // prints 40, the byte value in hex
        int step1 = Integer.parseInt(byteTemp.substring(0, 1), 16); // prints 4
        String step2 = Integer.toBinaryString(step1); // prints 100
        String step3 = String.format("%4s", step2).replace(' ', '0'); // prints 0100
        String step4 = step3.substring(0, 3); // prints 010
        int step5 = Integer.parseInt(step4, 2); // prints 2

        // check/set flags
        String dfFlag = step4.substring(1, 2);
        String mfFlag = step4.substring(2, 3);
        String dfS, mfS;
        dfS = ((dfFlag.equals("1")) ? " not" : "");
        mfS = ((mfFlag.equals("1")) ? "more fragments" : "last fragment");

        iPMSG.append(String.format(flags, step5, dfFlag, dfS, mfFlag, mfS));
        iPMSG.append(String.format(fragmentOff, idInt));
        iPMSG.append(IPBreak);
        System.out.println(iPMSG);

        // test printing
//        System.out.println(ipArray[6]);
//        System.out.println(byteTemp);
//        System.out.println(step1);
//        System.out.println(step2);
//        System.out.println(step3);
//        System.out.println(step4);
//        System.out.println(step5);
    }
}
