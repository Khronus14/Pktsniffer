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
    public int packetCount;
    public String hostAddress;
    public int port;
    public String ipAddress;
    public String tcpAddress;
    public String udpAddress;
    public String icmpAddress;
    public String netAddress;
    public static final String title = "%s:  ----- %s Header -----\n";
    public EtherFrame etherFrame;
    public IPStack ipStack;
    public TCPSegment tcpSegment;
    public UDPDatagram udpDatagram;
    public ICMPSegment icmpSegment;
    public static String nextHeader;
    public static boolean endOfPacket = false;

    public Pktsniffer() {
        this.etherFrame = new EtherFrame();
        this.ipStack = new IPStack();
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
                switch (args[index]) {
                    case "-r" -> filename = args[index + 1];
                    case "-c" -> this.packetCount = Integer.parseInt(args[index + 1]);
                    case "-host" -> this.hostAddress = args[index + 1];
                    case "-port" -> this.port = Integer.parseInt(args[index + 1]);
                    case "-ip" -> this.ipAddress = args[index + 1];
                    case "-tcp" -> this.tcpAddress = args[index + 1];
                    case "-udp" -> this.udpAddress = args[index + 1];
                    case "-icmp" -> this.icmpAddress = args[index + 1];
                    case "-net" -> this.netAddress = args[index + 1];
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
        this.outputResults();
    }

    public void readInPCAP() {
        File pcapFile = new File(filename);
        try (FileInputStream dataIn = new FileInputStream(pcapFile)) {

            boolean debug = false;
            if (debug) {
                // debug code that prints every byte in pcap file
                int input;
                int counter = 0;
                while (true) {
                    input = dataIn.read();
                    if (input == -1) {
                        break;
                    }
                    counter++; // track how many bytes are read
                    System.out.printf("%02x ", input);
                    if (Math.floorMod(counter, 8) == 0) {
                        System.out.println();
                    }
                }
                System.out.printf("\nRead %d bytes.\n", counter);
            } else {
                // reading in pcap file header (24 bytes) and packet record (16 bytes)
                byte[] pcapHeader = new byte[40];
                dataIn.read(pcapHeader);
                if (pcapHeader[20] != 1) {
                    System.out.println("LinkType not recognized in file header.");
                    System.exit(0);
                }
                //TODO review pcap file header for values to determine what
                // protocols are in packet (ether, TCP, IP, etc), then set flags
                // to only make the applicable parse calls

                String pktSizeStr = String.format("%02x%02x%02x%02x",
                        pcapHeader[35], pcapHeader[34], pcapHeader[33], pcapHeader[32]);
                int pktSizeInt = Integer.parseInt(pktSizeStr, 16);
                this.isEther(dataIn, pktSizeInt);

                while (!endOfPacket) {
                    switch (nextHeader) {
                        case "isIP" -> this.isIP(dataIn);
                        case "isTCP" -> this.isTCP(dataIn);
                        case "isUDP" -> this.isUDP(dataIn);
                        case "isICMP" -> this.isICMP(dataIn);
                        case "Unknown" -> usageAndExit(false);
                    }
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

    public void isEther(FileInputStream dataIn, int packetSize) throws IOException {
        // read/parse ethernet frame
        byte[] etherArray = new byte[14];
        dataIn.read(etherArray);
        this.etherFrame.parseEther(etherArray, packetSize);
    }

    public void isIP(FileInputStream dataIn) throws IOException {
        // read/parse IP stack
        byte[] ipArray = new byte[20];
        dataIn.read(ipArray);
        this.ipStack.parseIP(ipArray);
    }

    public void isTCP(FileInputStream dataIn) throws IOException {
        // read/parse TCP segment
        byte[] tcpArray = new byte[20];
        dataIn.read(tcpArray);
        this.tcpSegment.parseTCP(tcpArray);
        Pktsniffer.endOfPacket = true;
    }

    public void isUDP(FileInputStream dataIn) throws IOException {
        // read/parse UDP segment
        byte[] udpArray = new byte[8];
        dataIn.read(udpArray);
        this.udpDatagram.parseUDP(udpArray);
        Pktsniffer.endOfPacket = true;
    }

    public void isICMP(FileInputStream dataIn) throws IOException {
        // read/parse ICMP segment
        byte[] icmpArray = new byte[8];
        dataIn.read(icmpArray);
        this.icmpSegment.parseICMP(icmpArray);
        Pktsniffer.endOfPacket = true;
    }


    public void outputResults() {
        System.out.println("\nFile analyzed: " + filename);
    }
}
