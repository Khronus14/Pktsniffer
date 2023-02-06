/**
 * Program analyzes a single .pcap file and displays packet header information.
 * Project 1 for CSCI 651
 *
 * @author David D. Robinson, ddr6248@rit.edu
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.InputMismatchException;

public class Pktsniffer {
    public static int[] hostAddress;
    public static boolean hostMatch = false;
    public static int port = -1;
    public static boolean correctPort = false;
    public static int[] netAddress;
    public static boolean netMatch = false;
    public static final String title = "%s:  ----- %s Header -----\n";
    public static String nextHeader;
    private static boolean endOfPacket = false;
    private static String filename;
    private int packetCount = -1;
    private int printedPkts = 0;
    private boolean checkHeader = false;
    private boolean checkForIP = false;
    private boolean ipInPacket = false;
    private boolean checkForTCP = false;
    private boolean tcpInPacket = false;
    private boolean checkForUDP = false;
    private boolean udpInPacket = false;
    private boolean checkForICMP = false;
    private boolean icmpInPacket = false;
    private static boolean debug = false;
    private static int payload;

    public static void main(String[] args) {
        Pktsniffer pktsniffer = new Pktsniffer();
        pktsniffer.parseCLA(args);
        pktsniffer.runSniffer();
    }

    /**
     * Handles command line arguments.
     * @param args command line arguments
     */
    public void parseCLA(String[] args) {
        if (args.length == 0) {
            usageAndExit(false);
        }
        try {
            int index = 0;
            while (index < args.length) {
                switch (args[index]) {
                    case "-r" -> filename = args[index + 1];
                    case "-c" -> this.packetCount = Integer.parseInt(args[index + 1]);
                    case "-host" -> this.parseAddress(args[index + 1], false);
                    case "-port" -> port = Integer.parseInt(args[index + 1]);
                    case "-net" -> this.parseAddress(args[index + 1], true);
                    case "-debug" -> debug = true;
                    case "-ip", "-tcp", "-udp", "-icmp" -> {
                        this.setFilter(args[index]);
                        index--;
                    }
                    default -> {
                        System.out.println("Argument not recognized:  " + args[index]);
                        System.out.println("Refer to documentation for proper usage.");
                        System.exit(0);
                    }
                }
                index += 2;
            }
        } catch (InputMismatchException | NumberFormatException exception) {
            System.err.println("""
                    Input mismatch; verify correct input for each flag.
                    -c and -port flags must be followed by integers.
                    """);
            usageAndExit(true);
        }

        if (filename == null) {
            System.err.println("Missing filename.");
            usageAndExit(true);
        }
    }

    /**
     * Parses input address into an array for filtering.
     * @param address IP address to filter by
     * @param isNet check value if filtering net or host
     */
    private void parseAddress(String address, boolean isNet) {
        String[] addArray = address.split("\\.");
        int[] toParse = new int[addArray.length];
        for (int i = 0; i < toParse.length; ++i) {
            toParse[i] = Integer.parseInt(addArray[i]);
        }

        if (isNet) {
            if (toParse.length < 3 || toParse.length > 4) {
                System.err.println("""
                        Incorrect IP address format for -net. Must be formatted:
                        [int].[int].[int] or [int].[int].[int].[int]""");
                System.exit(1);
            }
            netAddress = toParse;
        } else {
            if (toParse.length != 4) {
                System.err.println("""
                        Incorrect IP address format for -host. Must be formatted:
                        [int].[int].[int].[int]""");
                System.exit(1);
            }
            hostAddress = toParse;
        }
    }

    private static void usageAndExit(boolean isError) {
        System.err.println("java Pktsniffer [-r <filename>] [-c <integer>] " +
                "[-host <IP add>] [-port <integer>] [-net <IP add>] [-ip] " +
                "[-tcp] [-udp] [-icmp]");
        System.exit(isError ? 1 : 0);
    }

    /**
     * Starts program.
     */
    public void runSniffer() {
        File pcapFile = new File(filename);
        try (FileInputStream dataIn = new FileInputStream(pcapFile)) {
            if (debug) {
                runDebug(dataIn);
            } else {
                this.analyzePacket(dataIn);
            }
        } catch (FileNotFoundException fNFE) {
            System.err.println("File not found. Program ending.");
            System.exit(-1);
        } catch (IOException iOE) {
            System.err.println("I/O error. Program ending.");
            System.exit(-1);
        }
    }

    /**
     * Code that prints every byte in the packet in rows of 8
     * @param dataIn input file
     * @throws IOException
     */
    private static void runDebug(FileInputStream dataIn) throws IOException {
        int input;
        int counter = 0;
        System.out.printf("Byte %03d:  ", counter);
        while (true) {
            input = dataIn.read();
            // -1 is end of packet
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
    }

    /**
     * Function to read in file and calls functions to parse each header.
     * @param dataIn input file
     * @throws IOException
     */
    private void analyzePacket(FileInputStream dataIn) throws IOException{
        // read in pcap file header (24 bytes)
        byte[] pcapHeader = new byte[24];
        dataIn.read(pcapHeader);
        final int ethernetType = 1; // Link-Layer header type
        if (pcapHeader[20] != ethernetType) {
            System.out.println("LinkType not recognized in file header.");
            System.exit(0);
        }

        while (true) {
            // read packet record (16 bytes)
            byte[] packetRecord = new byte[16];
            int endOfFile = dataIn.read(packetRecord);
            // stop reading file if end of file or if number of requested
            // packets have been printed
            if (endOfFile == -1 || this.printedPkts == this.packetCount) {
                break;
            }

            // determine total packet length (headers + payload)
            String pktSizeStr = String.format("%02x%02x%02x%02x",
                    packetRecord[15], packetRecord[14], packetRecord[13], packetRecord[12]);
            int pktSizeInt = Integer.parseInt(pktSizeStr, 16);
            payload = pktSizeInt;

            // initialize new output message
            StringBuilder packetMSG = new StringBuilder();

            // assumption that every packet will start with an ethernet header
            nextHeader = "isEther";

            // loop to read each header and payload
            while (!endOfPacket) {
                switch (nextHeader) {
                    case "isEther" -> this.isEther(dataIn, packetMSG, pktSizeInt);
                    case "isIP" -> this.isIP(dataIn, packetMSG);
                    case "isTCP" -> this.isTCP(dataIn, packetMSG);
                    case "isUDP" -> this.isUDP(dataIn, packetMSG);
                    case "isICMP" -> this.isICMP(dataIn, packetMSG);
                    case "isEnd" -> this.isEnd(dataIn);
                    default -> usageAndExit(false);
                }
            }
            this.printPacket(packetMSG);
            Pktsniffer.endOfPacket = false;
            payload = 0;
        }
    }

    /**
     * Reads/parses the packet's ethernet header.
     * @param dataIn input file
     * @param pktMSG formatted output string
     * @param packetSize number of bytes in packet
     * @throws IOException
     */
    public void isEther(FileInputStream dataIn, StringBuilder pktMSG, int packetSize) throws IOException {
        // read/parse ethernet frame
        byte[] etherArray = new byte[14];
        payload -= etherArray.length;
        dataIn.read(etherArray);
        EtherFrame.parseEther(etherArray, pktMSG, packetSize);
    }

    /**
     * Reads/parses the packet's IP header.
     * @param dataIn input file
     * @param pktMSG formatted output string
     * @throws IOException
     */
    public void isIP(FileInputStream dataIn, StringBuilder pktMSG) throws IOException {
        // read/parse IP stack
        this.ipInPacket = true;
        byte[] ipArray = new byte[20];
        payload -= ipArray.length;
        dataIn.read(ipArray);
        IPPacket.parseIP(ipArray, pktMSG);
    }

    /**
     * Reads/parses the packet's TCP header.
     * @param dataIn input file
     * @param pktMSG formatted output string
     * @throws IOException
     */
    public void isTCP(FileInputStream dataIn, StringBuilder pktMSG) throws IOException {
        // read/parse TCP segment
        this.tcpInPacket = true;
        byte[] tcpArray = new byte[20];
        payload -= tcpArray.length;
        dataIn.read(tcpArray);
        TCPSegment.parseTCP(tcpArray, pktMSG);
    }

    /**
     * Reads/parses the packet's UDP header.
     * @param dataIn input file
     * @param pktMSG formatted output string
     * @throws IOException
     */
    public void isUDP(FileInputStream dataIn, StringBuilder pktMSG) throws IOException {
        // read/parse UDP segment
        this.udpInPacket = true;
        byte[] udpArray = new byte[8];
        payload -= udpArray.length;
        dataIn.read(udpArray);
        UDPDatagram.parseUDP(udpArray, pktMSG);
    }

    /**
     * Reads/parses the packet's ICMP header.
     * @param dataIn input file
     * @param pktMSG formatted output string
     * @throws IOException
     */
    public void isICMP(FileInputStream dataIn, StringBuilder pktMSG) throws IOException {
        // read/parse ICMP segment
        this.icmpInPacket = true;
        byte[] icmpArray = new byte[8];
        payload -= icmpArray.length;
        dataIn.read(icmpArray);
        ICMPSegment.parseICMP(icmpArray, pktMSG);
    }

    /**
     * Reads the packet's payload and sets end of packet flag.
     * @param dataIn input file
     * @throws IOException
     */
    public void isEnd(FileInputStream dataIn) throws IOException {
        // reads payload
        byte[] payloadArray = new byte[payload];
        dataIn.read(payloadArray);
        Pktsniffer.endOfPacket = true;
    }

    /**
     * Sets filter flag based on user input.
     * @param header type of header to filter by
     */
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

    /**
     * Check for filtering flags before printing.
     * @param pktMessage formatted string of analyzed packet
     */
    public void printPacket(StringBuilder pktMessage) {
        boolean portPrint = false;
        boolean hostPrint = false;
        boolean netPrint = false;
        boolean headerPrint = false;

        if (port == -1 || correctPort) {
            portPrint = true;
        }

        if (hostAddress == null || hostMatch) {
            hostPrint = true;
        }

        if (netAddress == null || netMatch) {
            netPrint = true;
        }

        if (this.checkHeader) {
            // if at least one of the headers we are looking for is present
            if ((this.checkForIP && this.ipInPacket) ||
                    (this.checkForTCP && this.tcpInPacket) ||
                    (this.checkForUDP && this.udpInPacket) ||
                    (this.checkForICMP && this.icmpInPacket)) {
                headerPrint = true;
            }
        } else {
            headerPrint = true;
        }

        if (portPrint && hostPrint && netPrint && headerPrint) {
            this.printedPkts++;
            //System.out.println("********** Packet number: " + this.printedPkts + " **********");
            System.out.println(pktMessage);
        }

        this.resetFlags();
        //System.out.println("\nFile analyzed: " + filename);
    }

    /**
     * Resets flags for next packet.
     */
    private void resetFlags() {
        correctPort = false;
        hostMatch = false;
        netMatch = false;
        this.ipInPacket = false;
        this.tcpInPacket = false;
        this.udpInPacket = false;
        this.icmpInPacket = false;
    }
}
