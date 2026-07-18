package com.packetanalyzer.parser;

import com.packetanalyzer.model.ParsedPacket;
import com.packetanalyzer.model.RawPacket;

import java.util.Arrays;

/**
 * Stateless packet parser that converts a RawPacket into a ParsedPacket.
 * Mirrors the C++ PacketParser class.
 */
public class PacketParser {

    // EtherType constants
    public static final int ETHER_TYPE_IPV4 = 0x0800;
    public static final int ETHER_TYPE_IPV6 = 0x86DD;
    public static final int ETHER_TYPE_ARP  = 0x0806;

    // IP Protocol constants
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;

    // TCP Flag bit masks
    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;

    /**
     * Parses a raw packet. Returns null on failure.
     */
    public static ParsedPacket parse(RawPacket raw) {
        if (raw == null || raw.getData() == null) return null;

        ParsedPacket parsed = new ParsedPacket();
        parsed.setTimestampSec(raw.getTsSec());
        parsed.setTimestampUsec(raw.getTsUsec());

        byte[] data = raw.getData();
        int offset = 0;

        // --- Ethernet (14 bytes) ---
        if (data.length < 14) return null;

        parsed.setDestMac(macToString(data, 0));
        parsed.setSrcMac(macToString(data, 6));
        int etherType = readUint16BE(data, 12);
        parsed.setEtherType(etherType);
        offset = 14;

        // --- IPv4 ---
        if (etherType == ETHER_TYPE_IPV4) {
            if (data.length < offset + 20) return null;

            int versionIhl = data[offset] & 0xFF;
            int version = (versionIhl >> 4) & 0x0F;
            int ihl = versionIhl & 0x0F;

            if (version != 4) return null;

            int ipHeaderLen = ihl * 4;
            if (ipHeaderLen < 20 || data.length < offset + ipHeaderLen) return null;

            parsed.setIpVersion(version);
            parsed.setTtl(data[offset + 8]);
            parsed.setProtocol(data[offset + 9]);
            parsed.setSrcIp(ipToString(data, offset + 12));
            parsed.setDestIp(ipToString(data, offset + 16));
            parsed.setHasIp(true);
            offset += ipHeaderLen;

            // --- TCP ---
            if ((parsed.getProtocol() & 0xFF) == PROTO_TCP) {
                if (data.length < offset + 20) return null;

                parsed.setSrcPort(readUint16BE(data, offset));
                parsed.setDestPort(readUint16BE(data, offset + 2));
                parsed.setSeqNumber(readInt32BE(data, offset + 4));
                parsed.setAckNumber(readInt32BE(data, offset + 8));

                int dataOffset = (data[offset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = dataOffset * 4;
                parsed.setTcpFlags(data[offset + 13]);

                if (tcpHeaderLen < 20 || data.length < offset + tcpHeaderLen) return null;

                parsed.setHasTcp(true);
                offset += tcpHeaderLen;

            // --- UDP ---
            } else if ((parsed.getProtocol() & 0xFF) == PROTO_UDP) {
                if (data.length < offset + 8) return null;

                parsed.setSrcPort(readUint16BE(data, offset));
                parsed.setDestPort(readUint16BE(data, offset + 2));
                parsed.setHasUdp(true);
                offset += 8;
            }
        }

        // --- Payload ---
        int payloadLength = data.length - offset;
        if (payloadLength > 0) {
            parsed.setPayloadLength(payloadLength);
            parsed.setPayloadData(Arrays.copyOfRange(data, offset, data.length));
        } else {
            parsed.setPayloadLength(0);
            parsed.setPayloadData(new byte[0]);
        }

        return parsed;
    }

    // -------------------------------------------------------------------------
    // String helpers
    // -------------------------------------------------------------------------

    public static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    public static String ipToString(byte[] data, int offset) {
        return (data[offset] & 0xFF) + "." +
               (data[offset + 1] & 0xFF) + "." +
               (data[offset + 2] & 0xFF) + "." +
               (data[offset + 3] & 0xFF);
    }

    public static String protocolToString(byte protocol) {
        return switch (protocol & 0xFF) {
            case PROTO_ICMP -> "ICMP";
            case PROTO_TCP  -> "TCP";
            case PROTO_UDP  -> "UDP";
            default         -> "Unknown(" + (protocol & 0xFF) + ")";
        };
    }

    public static String tcpFlagsToString(byte flags) {
        int f = flags & 0xFF;
        StringBuilder sb = new StringBuilder();
        if ((f & TCP_SYN) != 0) sb.append("SYN ");
        if ((f & TCP_ACK) != 0) sb.append("ACK ");
        if ((f & TCP_FIN) != 0) sb.append("FIN ");
        if ((f & TCP_RST) != 0) sb.append("RST ");
        if ((f & TCP_PSH) != 0) sb.append("PSH ");
        if ((f & TCP_URG) != 0) sb.append("URG ");
        String result = sb.toString().trim();
        return result.isEmpty() ? "none" : result;
    }

    // -------------------------------------------------------------------------
    // Byte-reading helpers (big-endian / network byte order)
    // -------------------------------------------------------------------------

    public static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    public static int readInt32BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24)
             | ((data[offset + 1] & 0xFF) << 16)
             | ((data[offset + 2] & 0xFF) << 8)
             |  (data[offset + 3] & 0xFF);
    }

    public static long readUint32BE(byte[] data, int offset) {
        return readInt32BE(data, offset) & 0xFFFFFFFFL;
    }
}
