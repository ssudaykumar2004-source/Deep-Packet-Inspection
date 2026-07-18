package com.packetanalyzer.dpi;

import java.util.Objects;

/**
 * Uniquely identifies a network connection/flow (5-tuple).
 * Mirrors the C++ DPI::FiveTuple struct.
 */
public class FiveTuple {
    private final long   srcIp;      // stored as unsigned 32-bit
    private final long   dstIp;
    private final int    srcPort;    // 0-65535
    private final int    dstPort;
    private final int    protocol;   // TCP=6, UDP=17

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    public long getSrcIp()   { return srcIp; }
    public long getDstIp()   { return dstIp; }
    public int  getSrcPort() { return srcPort; }
    public int  getDstPort() { return dstPort; }
    public int  getProtocol(){ return protocol; }

    /** Return the reverse tuple (for bidirectional flow matching). */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple t = (FiveTuple) o;
        return srcIp == t.srcIp && dstIp == t.dstIp
            && srcPort == t.srcPort && dstPort == t.dstPort
            && protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        return ipToString(srcIp) + ":" + srcPort + " -> "
             + ipToString(dstIp) + ":" + dstPort
             + " (" + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") + ")";
    }

    private static String ipToString(long ip) {
        return ((ip      ) & 0xFF) + "."
             + ((ip >>  8) & 0xFF) + "."
             + ((ip >> 16) & 0xFF) + "."
             + ((ip >> 24) & 0xFF);
    }
}
