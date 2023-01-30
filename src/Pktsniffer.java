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

    public Pktsniffer() {
        this.etherFrame = new EtherFrame();
        this.ipStack = new IPStack();
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
                    System.out.printf("%02x\n", input);
                    counter++; // track how many bytes are read
                }
                System.out.printf("Read %d bytes.\n", counter);
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

                // read/parse ethernet frame
                byte[] etherArray = new byte[14];
                dataIn.read(etherArray);
                // capture packet size for ether header
                int packetSize = pcapHeader[32];
                this.etherFrame.parseEther(etherArray, packetSize);

                // read/parse IP stack
                byte[] ipArray = new byte[20];
                dataIn.read(ipArray);
                this.ipStack.parseIP(ipArray);

                // read/parse TCP segment
                //TODO

                // read/parse UDP segment
                //TODO

                // read/parse ICMP segment
                //TODO
            }
        } catch (FileNotFoundException fNFE) {
            System.err.println("File not found. Program ending.");
            System.exit(-1);
        } catch (IOException iOE) {
            System.err.println("I/O error. Program ending.");
            System.exit(-1);
        }
    }

    public void outputResults() {
        System.out.println("\nFile analyzed: " + filename);
    }
}
