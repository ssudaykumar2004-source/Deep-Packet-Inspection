package com.packetanalyzer.model;

/**
 * Represents the 24-byte global header at the start of a PCAP file.
 */
public class PcapGlobalHeader {
    private long magicNumber;    // 0xa1b2c3d4 or byte-swapped variant
    private int versionMajor;
    private int versionMinor;
    private int thiszone;        // GMT offset (usually 0)
    private long sigfigs;        // Accuracy of timestamps (usually 0)
    private long snaplen;        // Max packet length
    private long network;        // Data link type (1 = Ethernet)

    public long getMagicNumber()  { return magicNumber; }
    public void setMagicNumber(long v) { this.magicNumber = v; }

    public int getVersionMajor()  { return versionMajor; }
    public void setVersionMajor(int v) { this.versionMajor = v; }

    public int getVersionMinor()  { return versionMinor; }
    public void setVersionMinor(int v) { this.versionMinor = v; }

    public int getThiszone()      { return thiszone; }
    public void setThiszone(int v) { this.thiszone = v; }

    public long getSigfigs()      { return sigfigs; }
    public void setSigfigs(long v) { this.sigfigs = v; }

    public long getSnaplen()      { return snaplen; }
    public void setSnaplen(long v) { this.snaplen = v; }

    public long getNetwork()      { return network; }
    public void setNetwork(long v) { this.network = v; }
}
