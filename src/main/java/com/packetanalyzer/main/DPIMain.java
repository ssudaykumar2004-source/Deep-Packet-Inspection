package com.packetanalyzer.main;

import com.packetanalyzer.dpi.DPIEngine;

import java.io.IOException;

/**
 * Alternative main that runs the full DPI pipeline instead of just printing packets.
 *
 * Usage:
 *   java -cp packet-analyzer.jar com.packetanalyzer.main.DPIMain <pcap_file> [--block-app <AppName>] [--block-domain <domain>]
 *
 * Examples:
 *   java -cp packet-analyzer.jar com.packetanalyzer.main.DPIMain capture.pcap
 *   java -cp packet-analyzer.jar com.packetanalyzer.main.DPIMain capture.pcap --block-app Netflix --block-domain facebook.com
 */
public class DPIMain {

    public static void main(String[] args) throws IOException {
        System.out.println("====================================");
        System.out.println(" Packet Analyzer – DPI Mode (Java) ");
        System.out.println("====================================\n");

        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        String filename = args[0];

        try (DPIEngine engine = new DPIEngine()) {
            // Parse optional extra flags
            for (int i = 1; i < args.length - 1; i++) {
                switch (args[i]) {
                    case "--block-app" -> {
                        String appName = args[++i];
                        try {
                            var appType = com.packetanalyzer.dpi.AppType.valueOf(appName.toUpperCase());
                            engine.getRuleManager().blockApp(appType);
                        } catch (IllegalArgumentException e) {
                            System.err.println("Unknown app type: " + appName);
                        }
                    }
                    case "--block-domain" -> engine.getRuleManager().blockDomain(args[++i]);
                    case "--block-ip"     -> engine.getRuleManager().blockIP(args[++i]);
                    case "--block-port"   -> engine.getRuleManager().blockPort(Integer.parseInt(args[++i]));
                    default -> System.err.println("Unknown flag: " + args[i]);
                }
            }

            engine.run(filename);
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java -cp packet-analyzer.jar com.packetanalyzer.main.DPIMain <pcap_file> [options]");
        System.out.println("\nOptions:");
        System.out.println("  --block-app    <AppName>   Block an application (e.g. NETFLIX, FACEBOOK)");
        System.out.println("  --block-domain <domain>    Block a domain (supports *.example.com)");
        System.out.println("  --block-ip     <ip>        Block a source IP address");
        System.out.println("  --block-port   <port>      Block a destination port");
        System.out.println("\nExamples:");
        System.out.println("  java -cp packet-analyzer.jar com.packetanalyzer.main.DPIMain capture.pcap");
        System.out.println("  java -cp packet-analyzer.jar com.packetanalyzer.main.DPIMain capture.pcap --block-app NETFLIX");
    }
}
