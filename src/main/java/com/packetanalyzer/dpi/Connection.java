package com.packetanalyzer.dpi;

import java.time.Instant;

/**
 * Represents an active network flow/connection.
 * Mirrors the C++ DPI::Connection struct.
 */
public class Connection {

    public enum State { NEW, ESTABLISHED, CLASSIFIED, BLOCKED, CLOSED }
    public enum Action { FORWARD, DROP, INSPECT, LOG_ONLY }

    // Flow identifier
    private FiveTuple tuple;

    // Classification
    private State   state      = State.NEW;
    private AppType appType    = AppType.UNKNOWN;
    private String  sni        = "";
    private Action  action     = Action.FORWARD;

    // Statistics
    private long packetsIn  = 0;
    private long packetsOut = 0;
    private long bytesIn    = 0;
    private long bytesOut   = 0;

    // Timing
    private Instant firstSeen = Instant.now();
    private Instant lastSeen  = Instant.now();

    // TCP state
    private boolean synSeen    = false;
    private boolean synAckSeen = false;
    private boolean finSeen    = false;

    // -------------------------------------------------------------------------

    public FiveTuple getTuple()           { return tuple; }
    public void setTuple(FiveTuple v)     { this.tuple = v; }

    public State getState()               { return state; }
    public void setState(State v)         { this.state = v; }

    public AppType getAppType()           { return appType; }
    public void setAppType(AppType v)     { this.appType = v; }

    public String getSni()                { return sni; }
    public void setSni(String v)          { this.sni = v; }

    public Action getAction()             { return action; }
    public void setAction(Action v)       { this.action = v; }

    public long getPacketsIn()            { return packetsIn; }
    public void setPacketsIn(long v)      { this.packetsIn = v; }

    public long getPacketsOut()           { return packetsOut; }
    public void setPacketsOut(long v)     { this.packetsOut = v; }

    public long getBytesIn()              { return bytesIn; }
    public void setBytesIn(long v)        { this.bytesIn = v; }

    public long getBytesOut()             { return bytesOut; }
    public void setBytesOut(long v)       { this.bytesOut = v; }

    public Instant getFirstSeen()         { return firstSeen; }
    public void setFirstSeen(Instant v)   { this.firstSeen = v; }

    public Instant getLastSeen()          { return lastSeen; }
    public void setLastSeen(Instant v)    { this.lastSeen = v; }

    public boolean isSynSeen()            { return synSeen; }
    public void setSynSeen(boolean v)     { this.synSeen = v; }

    public boolean isSynAckSeen()         { return synAckSeen; }
    public void setSynAckSeen(boolean v)  { this.synAckSeen = v; }

    public boolean isFinSeen()            { return finSeen; }
    public void setFinSeen(boolean v)     { this.finSeen = v; }
}
