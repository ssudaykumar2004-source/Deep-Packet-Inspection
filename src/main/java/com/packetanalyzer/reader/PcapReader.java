package com.packetanalyzer.reader;

import com.packetanalyzer.model.PcapGlobalHeader;
import com.packetanalyzer.model.RawPacket;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads PCAP files and produces RawPacket objects.
 * Handles both little-endian (native) and big-endian PCAP formats.
 */
public class PcapReader implements Closeable {

    private static final long PCAP_MAGIC_NATIVE  = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;

    private FileInputStream fis;
    private DataInputStream dis;
    private PcapGlobalHeader globalHeader;
    private boolean needsByteSwap = false;
    private boolean isOpen = false;

    /**
     * Opens a PCAP file for reading.
     *
     * @param filename path to the .pcap file
     * @return true if opened successfully
     */
    public boolean open(String filename) {
        close();
        try {
            fis = new FileInputStream(filename);
            dis = new DataInputStream(new BufferedInputStream(fis));

            globalHeader = readGlobalHeader();
            if (globalHeader == null) return false;

            System.out.println("Opened PCAP file: " + filename);
            System.out.println("  Version: " + globalHeader.getVersionMajor() + "." + globalHeader.getVersionMinor());
            System.out.println("  Snaplen: " + globalHeader.getSnaplen() + " bytes");
            System.out.print("  Link type: " + globalHeader.getNetwork());
            if (globalHeader.getNetwork() == 1) System.out.println(" (Ethernet)");
            else System.out.println();

            isOpen = true;
            return true;

        } catch (IOException e) {
            System.err.println("Error: Could not open file: " + filename + " (" + e.getMessage() + ")");
            return false;
        }
    }

    /**
     * Reads the next packet from the file.
     *
     * @return a RawPacket, or null at end-of-file / error
     */
    public RawPacket readNextPacket() {
        if (!isOpen) return null;

        try {
            // Each packet is preceded by a 16-byte per-packet header
            byte[] hdrBytes = new byte[16];
            int read = dis.read(hdrBytes);
            if (read < 16) return null;  // EOF

            ByteBuffer hdrBuf = ByteBuffer.wrap(hdrBytes)
                    .order(needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

            long tsSec  = hdrBuf.getInt() & 0xFFFFFFFFL;
            long tsUsec = hdrBuf.getInt() & 0xFFFFFFFFL;
            long inclLen = hdrBuf.getInt() & 0xFFFFFFFFL;
            long origLen = hdrBuf.getInt() & 0xFFFFFFFFL;

            // Sanity check
            if (inclLen > globalHeader.getSnaplen() || inclLen > 65535) {
                System.err.println("Error: Invalid packet length: " + inclLen);
                return null;
            }

            byte[] data = new byte[(int) inclLen];
            int totalRead = 0;
            while (totalRead < (int) inclLen) {
                int r = dis.read(data, totalRead, (int) inclLen - totalRead);
                if (r < 0) {
                    System.err.println("Error: Could not read packet data (truncated file)");
                    return null;
                }
                totalRead += r;
            }

            RawPacket pkt = new RawPacket();
            pkt.setTsSec(tsSec);
            pkt.setTsUsec(tsUsec);
            pkt.setInclLen(inclLen);
            pkt.setOrigLen(origLen);
            pkt.setData(data);
            return pkt;

        } catch (EOFException eof) {
            return null;
        } catch (IOException e) {
            return null;
        }
    }

    @Override
    public void close() {
        isOpen = false;
        needsByteSwap = false;
        try {
            if (dis != null) { dis.close(); dis = null; }
            if (fis != null) { fis.close(); fis = null; }
        } catch (IOException ignored) {}
    }

    public PcapGlobalHeader getGlobalHeader() { return globalHeader; }
    public boolean isOpen() { return isOpen; }

    // -------------------------------------------------------------------------

    private PcapGlobalHeader readGlobalHeader() throws IOException {
        byte[] buf = new byte[24];
        if (dis.read(buf) < 24) {
            System.err.println("Error: Could not read PCAP global header");
            return null;
        }

        // Read magic number in little-endian first (most common)
        long magicLE = (buf[0] & 0xFFL)
                | ((buf[1] & 0xFFL) << 8)
                | ((buf[2] & 0xFFL) << 16)
                | ((buf[3] & 0xFFL) << 24);

        if (magicLE == PCAP_MAGIC_NATIVE) {
            needsByteSwap = false;
        } else if (magicLE == PCAP_MAGIC_SWAPPED) {
            needsByteSwap = true;
        } else {
            System.err.printf("Error: Invalid PCAP magic number: 0x%08X%n", magicLE);
            return null;
        }

        ByteBuffer bb = ByteBuffer.wrap(buf)
                .order(needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

        PcapGlobalHeader hdr = new PcapGlobalHeader();
        hdr.setMagicNumber(bb.getInt() & 0xFFFFFFFFL);
        hdr.setVersionMajor(bb.getShort() & 0xFFFF);
        hdr.setVersionMinor(bb.getShort() & 0xFFFF);
        hdr.setThiszone(bb.getInt());
        hdr.setSigfigs(bb.getInt() & 0xFFFFFFFFL);
        hdr.setSnaplen(bb.getInt() & 0xFFFFFFFFL);
        hdr.setNetwork(bb.getInt() & 0xFFFFFFFFL);
        return hdr;
    }
}
