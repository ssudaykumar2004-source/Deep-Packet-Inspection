package com.packetanalyzer.sni;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the Server Name Indication (SNI) from TLS Client Hello packets.
 * Mirrors C++ DPI::SNIExtractor.
 *
 * TLS Record Header (5 bytes):
 *   Byte 0:    Content Type (0x16 = Handshake)
 *   Bytes 1-2: TLS Version
 *   Bytes 3-4: Record Length
 *
 * Handshake Header (4 bytes):
 *   Byte 5:    Handshake Type (0x01 = ClientHello)
 *   Bytes 6-8: Handshake Length (24-bit big-endian)
 *
 * ClientHello body:
 *   2 bytes  client version
 *   32 bytes random
 *   1 byte   session-id length + session id
 *   2 bytes  cipher-suites length + cipher suites
 *   1 byte   compression methods length + compression methods
 *   2 bytes  extensions length + extensions
 *
 * SNI Extension (type 0x0000):
 *   2 bytes  extension type
 *   2 bytes  extension data length
 *   2 bytes  SNI list length
 *   1 byte   SNI entry type (0x00 = host_name)
 *   2 bytes  hostname length
 *   n bytes  hostname
 */
public class SNIExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI          = 0x0000;
    private static final int SNI_TYPE_HOSTNAME      = 0x00;

    public static boolean isTLSClientHello(byte[] payload, int length) {
        if (payload == null || length < 9) return false;
        if ((payload[0] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;

        int version = readUint16BE(payload, 1);
        if (version < 0x0300 || version > 0x0304) return false;

        int recordLen = readUint16BE(payload, 3);
        if (recordLen > length - 5) return false;

        return (payload[5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
    }

    public static Optional<String> extract(byte[] payload, int length) {
        if (!isTLSClientHello(payload, length)) return Optional.empty();

        try {
            int offset = 5;  // skip TLS record header

            // Handshake header: type (1) + length (3)
            offset += 4;                                 // skip type + 24-bit length

            // ClientHello body
            offset += 2;   // client version
            offset += 32;  // random

            // Session ID
            if (offset >= length) return Optional.empty();
            int sessionIdLen = payload[offset] & 0xFF;
            offset += 1 + sessionIdLen;

            // Cipher suites
            if (offset + 2 > length) return Optional.empty();
            int cipherSuitesLen = readUint16BE(payload, offset);
            offset += 2 + cipherSuitesLen;

            // Compression methods
            if (offset >= length) return Optional.empty();
            int compressionLen = payload[offset] & 0xFF;
            offset += 1 + compressionLen;

            // Extensions
            if (offset + 2 > length) return Optional.empty();
            int extensionsLen = readUint16BE(payload, offset);
            offset += 2;

            int extensionsEnd = Math.min(offset + extensionsLen, length);

            while (offset + 4 <= extensionsEnd) {
                int extType = readUint16BE(payload, offset);
                int extLen  = readUint16BE(payload, offset + 2);
                offset += 4;

                if (offset + extLen > extensionsEnd) break;

                if (extType == EXTENSION_SNI) {
                    if (extLen < 5) break;
                    // SNI list length (2) + type (1) + name length (2) + name
                    int sniListLen = readUint16BE(payload, offset);
                    if (sniListLen < 3) break;

                    int sniType   = payload[offset + 2] & 0xFF;
                    int sniLen    = readUint16BE(payload, offset + 3);

                    if (sniType != SNI_TYPE_HOSTNAME) break;
                    if (sniLen > extLen - 5 || offset + 5 + sniLen > length) break;

                    String hostname = new String(payload, offset + 5, sniLen, StandardCharsets.US_ASCII);
                    return Optional.of(hostname);
                }

                offset += extLen;
            }
        } catch (ArrayIndexOutOfBoundsException ignored) {}

        return Optional.empty();
    }

    // -------------------------------------------------------------------------

    /**
     * Tries to extract the HTTP Host header value from plain-text HTTP.
     */
    public static Optional<String> extractHttpHost(byte[] payload, int length) {
        if (payload == null || length < 4) return Optional.empty();

        String text;
        try {
            text = new String(payload, 0, length, StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            return Optional.empty();
        }

        // Must look like an HTTP request
        if (!text.startsWith("GET ") && !text.startsWith("POST") &&
            !text.startsWith("PUT ") && !text.startsWith("HEAD") &&
            !text.startsWith("DELE") && !text.startsWith("PATC") &&
            !text.startsWith("OPTI")) {
            return Optional.empty();
        }

        int hostIdx = text.toLowerCase().indexOf("host:");
        if (hostIdx < 0) return Optional.empty();

        int start = hostIdx + 5;
        while (start < text.length() && (text.charAt(start) == ' ' || text.charAt(start) == '\t'))
            start++;

        int end = start;
        while (end < text.length() && text.charAt(end) != '\r' && text.charAt(end) != '\n')
            end++;

        if (end <= start) return Optional.empty();

        String host = text.substring(start, end);
        // Strip port if present
        int colonIdx = host.lastIndexOf(':');
        if (colonIdx >= 0) host = host.substring(0, colonIdx);
        return Optional.of(host.trim());
    }

    /**
     * Extracts the queried domain from a DNS request payload (after UDP header).
     */
    public static Optional<String> extractDnsQuery(byte[] payload, int length) {
        if (payload == null || length < 12) return Optional.empty();

        // QR bit must be 0 (query)
        if ((payload[2] & 0x80) != 0) return Optional.empty();

        // QDCOUNT must be > 0
        int qdcount = readUint16BE(payload, 4);
        if (qdcount == 0) return Optional.empty();

        int offset = 12;
        StringBuilder domain = new StringBuilder();

        while (offset < length) {
            int labelLen = payload[offset] & 0xFF;
            if (labelLen == 0) break;
            if (labelLen > 63) break; // compression pointer

            offset++;
            if (offset + labelLen > length) break;

            if (domain.length() > 0) domain.append('.');
            domain.append(new String(payload, offset, labelLen, StandardCharsets.US_ASCII));
            offset += labelLen;
        }

        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }

    // -------------------------------------------------------------------------

    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}
