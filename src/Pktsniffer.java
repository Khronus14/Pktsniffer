import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.InputMismatchException;

/**
 * @author David D. Robinson, ddr6248@rit.edu
 */

public class Pktsniffer {
    public static String filename;
    public int packetCount = -1;
    public int printedPkts = 0;
    public static String hostAddress;
    public static int port = -1;
    public static boolean correctPort = false;
    public boolean checkHeader = false;
    public boolean checkForIP = false;
    public boolean ipInPacket = false;
    public boolean checkForTCP = false;
    public boolean tcpInPacket = false;
    public boolean checkForUDP = false;
    public boolean udpInPacket = false;
    public boolean checkForICMP = false;
    public boolean icmpInPacket = false;
    public static String netAddress;
    public static final String title = "%s:  ----- %s Header -----\n";
    public EtherFrame etherFrame;
    public IPPacket ipPacket;
    public TCPSegment tcpSegment;
    public UDPDatagram udpDatagram;
    public ICMPSegment icmpSegment;
    public static String nextHeader;
    public static boolean endOfPacket = false;
    public int payload;

    public Pktsniffer() {
        this.etherFrame = new EtherFrame();
        this.ipPacket = new IPPacket();
        this.tcpSegment = new TCPSegment();
        this.udpDatagram = new UDPDatagram();
        this.icmpSegment = new ICMPSegment();
    }

    public static void main(String[] args) {
        Pktsniffer pktsniffer = new Pktsniffer();
        pktsniffer.parseCLA(args);
        pktsniffer.runSniffer();
    }

    private static void usageAndExit(boolean isError) {
        System.err.println("java Pktsniffer -r <file>");
        System.exit(isError ? 1 : 0);
    }

    public void parseCLA(String[] args) {
        //TODO add check to verify correct address formats 'X.X.X.X'
        if (args.length == 0) {
            usageAndExit(false);
        }
        try {
            int index = 0;
            while (index < args.length) {
                //TODO handle not every iteration advancing by 2
                //TODO implement host and net flags
                switch (args[index]) {
                    case "-r" -> filename = args[index + 1];
                    case "-c" -> this.packetCount = Integer.parseInt(args[index + 1]);
                    case "-host" -> hostAddress = args[index + 1];
                    case "-port" -> port = Integer.parseInt(args[index + 1]);
                    case "-ip", "-tcp", "-udp", "-icmp" -> this.setFilter(args[index]);
                    case "-net" -> netAddress = args[index + 1];
                }
                index += 2;
            }
        } catch (InputMismatchException | NumberFormatException exception) {
            System.err.println("""
                    Input mismatch; verify correct input for each flag.
                    -c and port flags MUST be followed by integers.
                    """);
            usageAndExit(true);
        }

        if (filename == null) {
            System.err.println("Missing filename.");
            usageAndExit(true);
        }
    }

    public void runSniffer() {
        this.readInPCAP();
    }

    public void readInPCAP() {
        File pcapFile = new File(filename);
        try (FileInputStream dataIn = new FileInputStream(pcapFile)) {

            boolean debug = false;
            if (debug) {
                // debug code that prints every byte in pcap file
                int input;
                int counter = 0;
                System.out.printf("Byte %03d:  ", counter);
                while (true) {
                    input = dataIn.read();
                    if (input == -1) {
                        break;
                    }
                    counter++; // track how many bytes are read
                    System.out.printf("%02x ", input);
                    if (Math.floorMod(counter, 8) == 0) {
                        System.out.printf("\nByte %03d:  ", counter);
                    }
                }
                System.out.printf("\nRead %d bytes.\n", counter);
            } else {
                // reading in pcap file header (24 bytes) and packet record (16 bytes)
                byte[] pcapHeader = new byte[24];
                dataIn.read(pcapHeader);
                if (pcapHeader[20] != 1) {
                    System.out.println("LinkType not recognized in file header.");
                    System.exit(0);
                }

                while (true) {
                    byte[] packetRecord = new byte[16];
                    int endOfFile = dataIn.read(packetRecord);
                    // stop reading file if end of file or if number of requested
                    // packets have been printed
                    if (endOfFile == -1 || this.printedPkts == this.packetCount) {
                        break;
                    }
                    String pktSizeStr = String.format("%02x%02x%02x%02x",
                            packetRecord[15], packetRecord[14], packetRecord[13], packetRecord[12]);
                    int pktSizeInt = Integer.parseInt(pktSizeStr, 16);
                    this.payload = pktSizeInt;

                    //int payload = pktSizeInt - this.totalHeadLen; // 42

                    StringBuilder packetMSG = new StringBuilder();
                    packetMSG.append(this.isEther(dataIn, pktSizeInt));

                    // loop to read each header and payload
                    while (!endOfPacket) {
                        switch (nextHeader) {
                            case "isIP" -> packetMSG.append(this.isIP(dataIn));
                            case "isTCP" -> packetMSG.append(this.isTCP(dataIn));
                            case "isUDP" -> packetMSG.append(this.isUDP(dataIn));
                            case "isICMP" -> packetMSG.append(this.isICMP(dataIn));
                            case "isEnd" -> this.isEnd(dataIn);
                            default -> usageAndExit(false);
                        }
                    }
                    this.printPacket(packetMSG);
                    Pktsniffer.endOfPacket = false;
                    this.payload = 0;
                }
            }
        } catch (FileNotFoundException fNFE) {
            System.err.println("File not found. Program ending.");
            System.exit(-1);
        } catch (IOException iOE) {
            System.err.println("I/O error. Program ending.");
            System.exit(-1);
        }
    }

    public StringBuilder isEther(FileInputStream dataIn, int packetSize) throws IOException {
        // read/parse ethernet frame
        byte[] etherArray = new byte[14];
        this.payload -= 14;
        dataIn.read(etherArray);
        return this.etherFrame.parseEther(etherArray, packetSize);
    }

    public StringBuilder isIP(FileInputStream dataIn) throws IOException {
        // read/parse IP stack
        this.ipInPacket = true;
        byte[] ipArray = new byte[20];
        this.payload -= 20;
        dataIn.read(ipArray);
        return this.ipPacket.parseIP(ipArray);
    }

    public StringBuilder isTCP(FileInputStream dataIn) throws IOException {
        // read/parse TCP segment
        this.tcpInPacket = true;
        byte[] tcpArray = new byte[20];
        this.payload -= 20;
        dataIn.read(tcpArray);
        return this.tcpSegment.parseTCP(tcpArray);
    }

    public StringBuilder isUDP(FileInputStream dataIn) throws IOException {
        // read/parse UDP segment
        this.udpInPacket = true;
        byte[] udpArray = new byte[8];
        this.payload -= 8;
        dataIn.read(udpArray);
        return this.udpDatagram.parseUDP(udpArray);
    }

    public StringBuilder isICMP(FileInputStream dataIn) throws IOException {
        // read/parse ICMP segment
        this.icmpInPacket = true;
        byte[] icmpArray = new byte[8];
        this.payload -= 8;
        dataIn.read(icmpArray);
        return this.icmpSegment.parseICMP(icmpArray);
    }

    public void isEnd(FileInputStream dataIn) throws IOException {
        // reads payload
        byte[] payloadArray = new byte[this.payload];
        dataIn.read(payloadArray);
        Pktsniffer.endOfPacket = true;
    }

    private void setFilter(String header) {
        if (!this.checkHeader) {
            this.checkHeader = true;
        }
        switch (header) {
            case "-ip" -> this.checkForIP = true;
            case "-tcp" -> this.checkForTCP = true;
            case "-udp" -> this.checkForUDP = true;
            case "-icmp" -> this.checkForICMP = true;
        }
    }

    public void printPacket(StringBuilder pktMessage) {
        // checks to print based on CLA
        // if we are not looking for a port, or we find one we are looking for...
        if (port == -1 || correctPort) {
            // if we are looking for a certain header...
            if (this.checkHeader) {
                // if at least one of the headers we are looking for is present
                if ((this.checkForIP && this.ipInPacket) ||
                        (this.checkForTCP && this.tcpInPacket) ||
                        (this.checkForUDP && this.udpInPacket) ||
                        (this.checkForICMP && this.icmpInPacket)) {

                    System.out.println(pktMessage);
                    this.printedPkts++;
                    correctPort = false;
                    this.ipInPacket = false;
                    this.tcpInPacket = false;
                    this.udpInPacket = false;
                    this.icmpInPacket = false;
                }
            } else {
                System.out.println(pktMessage);
                this.printedPkts++;
                correctPort = false;
            }
        }
        //System.out.println("\nFile analyzed: " + filename);
    }
}
