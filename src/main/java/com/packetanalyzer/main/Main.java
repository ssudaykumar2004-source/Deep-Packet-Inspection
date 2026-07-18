package com.packetanalyzer.main;

import com.packetanalyzer.model.ParsedPacket;
import com.packetanalyzer.model.RawPacket;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.reader.PcapReader;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Main entry point for the Packet Analyzer.
 * Reads a PCAP file and displays parsed packet information.
 */
public class Main {

    private static final DateTimeFormatter TIMESTAMP_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0 (Java)   ");
        System.out.println("====================================");
        System.out.println();

        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        String filename = args[0];
        int maxPackets = args.length >= 2 ? Integer.parseInt(args[1]) : -1;

        try (PcapReader reader = new PcapReader()) {
            if (!reader.open(filename)) {
                System.exit(1);
            }

            System.out.println("\n--- Reading packets ---");

            RawPacket rawPacket;
            int packetCount = 0;
            int parseErrors = 0;

            while ((rawPacket = reader.readNextPacket()) != null) {
                packetCount++;
                ParsedPacket parsed = PacketParser.parse(rawPacket);
                if (parsed != null) {
                    printPacketSummary(parsed, packetCount);
                } else {
                    System.err.println("Warning: Failed to parse packet #" + packetCount);
                    parseErrors++;
                }

                if (maxPackets > 0 && packetCount >= maxPackets) {
                    System.out.println("\n(Stopped after " + maxPackets + " packets)");
                    break;
                }
            }

            System.out.println("\n====================================");
            System.out.println("Summary:");
            System.out.println("  Total packets read:  " + packetCount);
            System.out.println("  Parse errors:        " + parseErrors);
            System.out.println("====================================");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void printPacketSummary(ParsedPacket pkt, int packetNum) {
        System.out.println("\n========== Packet #" + packetNum + " ==========");

        Instant instant = Instant.ofEpochSecond(pkt.getTimestampSec());
        String timestamp = TIMESTAMP_FMT.format(instant);
        System.out.printf("Time: %s.%06d%n", timestamp, pkt.getTimestampUsec());

        // Ethernet layer
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.getSrcMac());
        System.out.println("  Destination MAC: " + pkt.getDestMac());
        System.out.printf("  EtherType:       0x%04X", pkt.getEtherType());
        switch (pkt.getEtherType()) {
            case 0x0800 -> System.out.println(" (IPv4)");
            case 0x86DD -> System.out.println(" (IPv6)");
            case 0x0806 -> System.out.println(" (ARP)");
            default     -> System.out.println();
        }

        // IP layer
        if (pkt.isHasIp()) {
            System.out.println("\n[IPv" + pkt.getIpVersion() + "]");
            System.out.println("  Source IP:      " + pkt.getSrcIp());
            System.out.println("  Destination IP: " + pkt.getDestIp());
            System.out.println("  Protocol:       " + PacketParser.protocolToString(pkt.getProtocol()));
            System.out.println("  TTL:            " + (pkt.getTtl() & 0xFF));
        }

        // TCP layer
        if (pkt.isHasTcp()) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + pkt.getSrcPort());
            System.out.println("  Destination Port: " + pkt.getDestPort());
            System.out.println("  Sequence Number:  " + Integer.toUnsignedLong(pkt.getSeqNumber()));
            System.out.println("  Ack Number:       " + Integer.toUnsignedLong(pkt.getAckNumber()));
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.getTcpFlags()));
        }

        // UDP layer
        if (pkt.isHasUdp()) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + pkt.getSrcPort());
            System.out.println("  Destination Port: " + pkt.getDestPort());
        }

        // Payload
        if (pkt.getPayloadLength() > 0) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + pkt.getPayloadLength() + " bytes");

            byte[] payload = pkt.getPayloadData();
            int previewLen = Math.min(pkt.getPayloadLength(), 32);
            StringBuilder hexPreview = new StringBuilder("  Preview: ");
            for (int i = 0; i < previewLen; i++) {
                hexPreview.append(String.format("%02x ", payload[i] & 0xFF));
            }
            if (pkt.getPayloadLength() > 32) {
                hexPreview.append("...");
            }
            System.out.println(hexPreview);
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar packet-analyzer.jar <pcap_file> [max_packets]");
        System.out.println("\nArguments:");
        System.out.println("  pcap_file   - Path to a .pcap file captured by Wireshark");
        System.out.println("  max_packets - (Optional) Maximum number of packets to display");
        System.out.println("\nExample:");
        System.out.println("  java -jar packet-analyzer.jar capture.pcap");
        System.out.println("  java -jar packet-analyzer.jar capture.pcap 10");
    }
}
