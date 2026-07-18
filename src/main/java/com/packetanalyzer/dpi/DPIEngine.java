package com.packetanalyzer.dpi;

import com.packetanalyzer.model.ParsedPacket;
import com.packetanalyzer.model.RawPacket;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.reader.PcapReader;
import com.packetanalyzer.rules.RuleManager;
import com.packetanalyzer.sni.SNIExtractor;
import com.packetanalyzer.tracker.ConnectionTracker;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Deep Packet Inspection engine.
 * Reads a PCAP file, classifies flows via SNI/HTTP host detection,
 * applies blocking rules, and prints a statistical report.
 *
 * Mirrors the high-level functionality of dpi_engine.cpp / dpi_mt.cpp.
 */
public class DPIEngine implements AutoCloseable {

    private final PcapReader         reader          = new PcapReader();
    private final ConnectionTracker  tracker         = new ConnectionTracker(0);
    private final RuleManager        ruleManager     = new RuleManager();

    // Statistics
    private final AtomicLong totalPackets   = new AtomicLong();
    private final AtomicLong totalBytes     = new AtomicLong();
    private final AtomicLong tcpPackets     = new AtomicLong();
    private final AtomicLong udpPackets     = new AtomicLong();
    private final AtomicLong otherPackets   = new AtomicLong();
    private final AtomicLong forwardedPkts  = new AtomicLong();
    private final AtomicLong droppedPkts    = new AtomicLong();

    // -------------------------------------------------------------------------

    /** Open a PCAP file. Returns false on error. */
    public boolean open(String filename) {
        return reader.open(filename);
    }

    /** Convenience: open file, process all packets, print report, close. */
    public void run(String filename) throws IOException {
        if (!open(filename)) throw new IOException("Cannot open: " + filename);
        processAll();
        printReport();
    }

    /**
     * Process every packet in the currently-open file.
     */
    public void processAll() {
        RawPacket raw;
        while ((raw = reader.readNextPacket()) != null) {
            processPacket(raw);
        }
    }

    /**
     * Process a single raw packet through the DPI pipeline:
     * parse → build flow key → classify → check rules → update stats.
     */
    public Connection.Action processPacket(RawPacket raw) {
        totalPackets.incrementAndGet();

        ParsedPacket pkt = PacketParser.parse(raw);
        if (pkt == null) return Connection.Action.FORWARD;

        totalBytes.addAndGet(raw.getData().length);

        // Count by protocol
        int proto = pkt.getProtocol() & 0xFF;
        if      (proto == PacketParser.PROTO_TCP) tcpPackets.incrementAndGet();
        else if (proto == PacketParser.PROTO_UDP) udpPackets.incrementAndGet();
        else                                       otherPackets.incrementAndGet();

        if (!pkt.isHasIp()) { forwardedPkts.incrementAndGet(); return Connection.Action.FORWARD; }

        // Build five-tuple
        long srcIpLong  = ipStringToLong(pkt.getSrcIp());
        long dstIpLong  = ipStringToLong(pkt.getDestIp());
        FiveTuple tuple = new FiveTuple(srcIpLong, dstIpLong,
                pkt.getSrcPort(), pkt.getDestPort(), proto);

        Connection conn = tracker.getOrCreate(tuple);
        tracker.update(conn, raw.getData().length, true);

        // Classify if not yet done
        if (conn.getState() == Connection.State.NEW ||
            conn.getState() == Connection.State.ESTABLISHED) {

            classify(conn, pkt);
        }

        // Check rules
        Optional<RuleManager.BlockReason> reason = ruleManager.shouldBlock(
                srcIpLong, pkt.getDestPort(), conn.getAppType(), conn.getSni());

        if (reason.isPresent()) {
            tracker.block(conn);
            droppedPkts.incrementAndGet();
            System.out.printf("[DPI] BLOCKED pkt from %s:%d → %s (%s)%n",
                    pkt.getSrcIp(), pkt.getSrcPort(), pkt.getDestIp(),
                    reason.get().type() + "=" + reason.get().detail());
            return Connection.Action.DROP;
        }

        if (conn.getState() == Connection.State.BLOCKED) {
            droppedPkts.incrementAndGet();
            return Connection.Action.DROP;
        }

        forwardedPkts.incrementAndGet();
        return Connection.Action.FORWARD;
    }

    // -------------------------------------------------------------------------
    // Classification helpers
    // -------------------------------------------------------------------------

    private void classify(Connection conn, ParsedPacket pkt) {
        if (pkt.getPayloadLength() <= 0) return;
        byte[] payload  = pkt.getPayloadData();
        int    payLen   = pkt.getPayloadLength();

        // Port-based quick classification
        int dstPort = pkt.getDestPort();
        int srcPort = pkt.getSrcPort();

        if (dstPort == 53 || srcPort == 53) {
            // DNS
            Optional<String> query = SNIExtractor.extractDnsQuery(payload, payLen);
            String sni = query.orElse("");
            AppType app = sni.isEmpty() ? AppType.DNS : AppType.fromSni(sni);
            tracker.classify(conn, app, sni);
            return;
        }

        if (dstPort == 80 || srcPort == 80) {
            // Plain HTTP
            Optional<String> host = SNIExtractor.extractHttpHost(payload, payLen);
            String sni = host.orElse("");
            AppType app = sni.isEmpty() ? AppType.HTTP : AppType.fromSni(sni);
            tracker.classify(conn, app, sni);
            return;
        }

        if (dstPort == 443 || srcPort == 443) {
            // TLS / HTTPS
            Optional<String> sniOpt = SNIExtractor.extract(payload, payLen);
            if (sniOpt.isPresent()) {
                String sni = sniOpt.get();
                tracker.classify(conn, AppType.fromSni(sni), sni);
            } else {
                tracker.classify(conn, AppType.TLS, "");
            }
            return;
        }

        // Try TLS regardless of port
        if (SNIExtractor.isTLSClientHello(payload, payLen)) {
            Optional<String> sniOpt = SNIExtractor.extract(payload, payLen);
            if (sniOpt.isPresent()) {
                String sni = sniOpt.get();
                tracker.classify(conn, AppType.fromSni(sni), sni);
            } else {
                tracker.classify(conn, AppType.TLS, "");
            }
        }
    }

    // -------------------------------------------------------------------------
    // Rule management (delegates to RuleManager)
    // -------------------------------------------------------------------------

    public RuleManager getRuleManager() { return ruleManager; }

    // -------------------------------------------------------------------------
    // Reporting
    // -------------------------------------------------------------------------

    public void printReport() {
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║               DPI ENGINE STATISTICS REPORT                   ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Total Packets:      %10d                               ║%n", totalPackets.get());
        System.out.printf("║ Total Bytes:        %10d                               ║%n", totalBytes.get());
        System.out.printf("║ TCP Packets:        %10d                               ║%n", tcpPackets.get());
        System.out.printf("║ UDP Packets:        %10d                               ║%n", udpPackets.get());
        System.out.printf("║ Other Packets:      %10d                               ║%n", otherPackets.get());
        System.out.printf("║ Forwarded:          %10d                               ║%n", forwardedPkts.get());
        System.out.printf("║ Dropped (blocked):  %10d                               ║%n", droppedPkts.get());
        System.out.printf("║ Active Connections: %10d                               ║%n", tracker.getActiveCount());

        // App distribution
        Map<AppType, Long> appDist = new EnumMap<>(AppType.class);
        tracker.forEach(c -> appDist.merge(c.getAppType(), 1L, Long::sum));

        if (!appDist.isEmpty()) {
            System.out.println("╠══════════════════════════════════════════════════════════════╣");
            System.out.println("║                   APPLICATION BREAKDOWN                      ║");
            System.out.println("╠══════════════════════════════════════════════════════════════╣");

            long total = appDist.values().stream().mapToLong(Long::longValue).sum();
            appDist.entrySet().stream()
                .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
                .forEach(e -> {
                    double pct = total > 0 ? 100.0 * e.getValue() / total : 0;
                    System.out.printf("║ %-20s %10d (%5.1f%%)                      ║%n",
                            e.getKey().toDisplayString(), e.getValue(), pct);
                });
        }

        // Top domains
        Map<String, Long> domainCounts = new HashMap<>();
        tracker.forEach(c -> {
            if (c.getSni() != null && !c.getSni().isEmpty())
                domainCounts.merge(c.getSni(), 1L, Long::sum);
        });

        if (!domainCounts.isEmpty()) {
            System.out.println("╠══════════════════════════════════════════════════════════════╣");
            System.out.println("║                       TOP DOMAINS                             ║");
            System.out.println("╠══════════════════════════════════════════════════════════════╣");

            domainCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(20)
                .forEach(e -> {
                    String dom = e.getKey().length() > 40 ? e.getKey().substring(0, 37) + "..." : e.getKey();
                    System.out.printf("║ %-40s %10d               ║%n", dom, e.getValue());
                });
        }

        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    @Override
    public void close() {
        reader.close();
    }

    // -------------------------------------------------------------------------

    private static long ipStringToLong(String ip) {
        if (ip == null || ip.isEmpty()) return 0L;
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return 0L;
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (Long.parseLong(parts[i]) << (i * 8));
        }
        return result;
    }
}
