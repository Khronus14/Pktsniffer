import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.InputMismatchException;
import java.util.Scanner;

/**
 * @author David D. Robinson, ddr6248@rit.edu
 */

public class Pktsniffer {
    public String filename;
    public int packetCount;
    public String hostAddress;
    public int port;
    public String ipAddress;
    public String tcpAddress;
    public String udpAddress;
    public String icmpAddress;
    public String netAddress;
    public EtherHeader etherHeader;

    public Pktsniffer() {
        this.etherHeader = new EtherHeader();
    }

    public class EtherHeader {
        public final String destMAC = "";
        public final String sourceMAC = "";
        public final int pktSize = 0;
        public final int etherType = 0;

        public EtherHeader() {

        }

    }
    public static void main(String[] args) {
        Pktsniffer pktsniffer = new Pktsniffer();
        pktsniffer.parseCLA(args);
        pktsniffer.runSniffer();
    }

    private static void usageAndExit(boolean isError) {
        System.err.println("""
                java Pktsniffer -r <file>
                """);
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
                    case "-r" -> this.filename = args[index + 1];
                    case "-c" -> this.packetCount = Integer.parseInt(args[index + 1]);
                    case "host" -> this.hostAddress = args[index + 1];
                    case "port" -> this.port = Integer.parseInt(args[index + 1]);
                    case "ip" -> this.ipAddress = args[index + 1];
                    case "tcp" -> this.tcpAddress = args[index + 1];
                    case "udp" -> this.udpAddress = args[index + 1];
                    case "icmp" -> this.icmpAddress = args[index + 1];
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

        if (this.filename == null) {
            System.err.println("""
                    Missing filename.
                    """);
            usageAndExit(true);
        }
    }

    public void runSniffer() {
        this.readInPCAP();
        this.outputResults();
    }

    public void readInPCAP() {
        File pcapFile = new File(filename);
        try (FileInputStream scanner = new FileInputStream(pcapFile)) {
            int input;
            int counter = 0;
            while (true) {
                input = scanner.read();
                if (input == -1) {
                    break;
                }
                System.out.printf("'%x'\n", input);
                counter++; // track how many bytes are read
            }

            // alt method
//            byte[] byteArray = {0, 9, 3, -1, 5, 8, -2};
//            StringBuilder sb = new StringBuilder();
//            for (byte b : byteArray) {
//                sb.append(String.format("%02X ", b));
//            }
//            System.out.println(sb.toString());

            System.out.printf("Read %d bytes.\n", counter);
        } catch (FileNotFoundException fNFE) {
            System.err.println("File not found. Program ending.");
            System.exit(-1);
        } catch (IOException iOE) {
            System.err.println("I/O error. Program ending.");
            System.exit(-1);
        }
    }

    public void outputResults() {
        System.out.println(this.filename);
    }
}
