package com.packetanalyzer.model;

/**
 * A single raw (unparsed) packet read from a PCAP file.
 */
public class RawPacket {
    private long tsSec;          // Timestamp seconds
    private long tsUsec;         // Timestamp microseconds
    private long inclLen;        // Number of bytes in the file
    private long origLen;        // Original length of the packet
    private byte[] data;         // Raw bytes

    public long getTsSec()    { return tsSec; }
    public void setTsSec(long v) { this.tsSec = v; }

    public long getTsUsec()   { return tsUsec; }
    public void setTsUsec(long v) { this.tsUsec = v; }

    public long getInclLen()  { return inclLen; }
    public void setInclLen(long v) { this.inclLen = v; }

    public long getOrigLen()  { return origLen; }
    public void setOrigLen(long v) { this.origLen = v; }

    public byte[] getData()   { return data; }
    public void setData(byte[] v) { this.data = v; }
}
