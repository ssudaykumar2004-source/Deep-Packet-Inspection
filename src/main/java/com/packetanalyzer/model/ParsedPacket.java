package com.packetanalyzer.model;

/**
 * Human-readable representation of a parsed network packet.
 */
public class ParsedPacket {
    // Timestamps
    private long timestampSec;
    private long timestampUsec;

    // Ethernet layer
    private String srcMac;
    private String destMac;
    private int etherType;       // 0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP

    // IP layer
    private boolean hasIp;
    private int ipVersion;
    private String srcIp;
    private String destIp;
    private byte protocol;       // 6=TCP, 17=UDP, 1=ICMP
    private byte ttl;

    // Transport layer
    private boolean hasTcp;
    private boolean hasUdp;
    private int srcPort;
    private int destPort;

    // TCP-specific
    private byte tcpFlags;
    private int seqNumber;
    private int ackNumber;

    // Payload
    private int payloadLength;
    private byte[] payloadData;

    // ---------- Getters & Setters ----------

    public long getTimestampSec()       { return timestampSec; }
    public void setTimestampSec(long v) { this.timestampSec = v; }

    public long getTimestampUsec()       { return timestampUsec; }
    public void setTimestampUsec(long v) { this.timestampUsec = v; }

    public String getSrcMac()            { return srcMac; }
    public void setSrcMac(String v)      { this.srcMac = v; }

    public String getDestMac()           { return destMac; }
    public void setDestMac(String v)     { this.destMac = v; }

    public int getEtherType()            { return etherType; }
    public void setEtherType(int v)      { this.etherType = v; }

    public boolean isHasIp()             { return hasIp; }
    public void setHasIp(boolean v)      { this.hasIp = v; }

    public int getIpVersion()            { return ipVersion; }
    public void setIpVersion(int v)      { this.ipVersion = v; }

    public String getSrcIp()             { return srcIp; }
    public void setSrcIp(String v)       { this.srcIp = v; }

    public String getDestIp()            { return destIp; }
    public void setDestIp(String v)      { this.destIp = v; }

    public byte getProtocol()            { return protocol; }
    public void setProtocol(byte v)      { this.protocol = v; }

    public byte getTtl()                 { return ttl; }
    public void setTtl(byte v)           { this.ttl = v; }

    public boolean isHasTcp()            { return hasTcp; }
    public void setHasTcp(boolean v)     { this.hasTcp = v; }

    public boolean isHasUdp()            { return hasUdp; }
    public void setHasUdp(boolean v)     { this.hasUdp = v; }

    public int getSrcPort()              { return srcPort; }
    public void setSrcPort(int v)        { this.srcPort = v; }

    public int getDestPort()             { return destPort; }
    public void setDestPort(int v)       { this.destPort = v; }

    public byte getTcpFlags()            { return tcpFlags; }
    public void setTcpFlags(byte v)      { this.tcpFlags = v; }

    public int getSeqNumber()            { return seqNumber; }
    public void setSeqNumber(int v)      { this.seqNumber = v; }

    public int getAckNumber()            { return ackNumber; }
    public void setAckNumber(int v)      { this.ackNumber = v; }

    public int getPayloadLength()        { return payloadLength; }
    public void setPayloadLength(int v)  { this.payloadLength = v; }

    public byte[] getPayloadData()       { return payloadData; }
    public void setPayloadData(byte[] v) { this.payloadData = v; }
}
