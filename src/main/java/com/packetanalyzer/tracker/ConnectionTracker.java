package com.packetanalyzer.tracker;

import com.packetanalyzer.dpi.AppType;
import com.packetanalyzer.dpi.Connection;
import com.packetanalyzer.dpi.FiveTuple;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

/**
 * Tracks active connections (flows) for a single processing thread.
 * Mirrors the C++ DPI::ConnectionTracker class.
 */
public class ConnectionTracker {

    private final int   fpId;
    private final int   maxConnections;

    private final Map<FiveTuple, Connection> connections = new LinkedHashMap<>();

    private long totalSeen       = 0;
    private long classifiedCount = 0;
    private long blockedCount    = 0;

    public ConnectionTracker(int fpId) {
        this(fpId, 100_000);
    }

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId           = fpId;
        this.maxConnections = maxConnections;
    }

    // -------------------------------------------------------------------------
    // Connection lookup / creation
    // -------------------------------------------------------------------------

    public Connection getOrCreate(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        conn = new Connection();
        conn.setTuple(tuple);
        conn.setState(Connection.State.NEW);
        conn.setFirstSeen(Instant.now());
        conn.setLastSeen(conn.getFirstSeen());

        connections.put(tuple, conn);
        totalSeen++;
        return conn;
    }

    public Connection get(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;
        // Try reverse (bidirectional)
        return connections.get(tuple.reverse());
    }

    // -------------------------------------------------------------------------
    // Updates
    // -------------------------------------------------------------------------

    public void update(Connection conn, long packetSize, boolean isOutbound) {
        if (conn == null) return;
        conn.setLastSeen(Instant.now());
        if (isOutbound) {
            conn.setPacketsOut(conn.getPacketsOut() + 1);
            conn.setBytesOut(conn.getBytesOut() + packetSize);
        } else {
            conn.setPacketsIn(conn.getPacketsIn() + 1);
            conn.setBytesIn(conn.getBytesIn() + packetSize);
        }
    }

    public void classify(Connection conn, AppType app, String sni) {
        if (conn == null || conn.getState() == Connection.State.CLASSIFIED) return;
        conn.setAppType(app);
        conn.setSni(sni != null ? sni : "");
        conn.setState(Connection.State.CLASSIFIED);
        classifiedCount++;
    }

    public void block(Connection conn) {
        if (conn == null) return;
        conn.setState(Connection.State.BLOCKED);
        conn.setAction(Connection.Action.DROP);
        blockedCount++;
    }

    public void close(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) conn.setState(Connection.State.CLOSED);
    }

    // -------------------------------------------------------------------------
    // Housekeeping
    // -------------------------------------------------------------------------

    public int cleanupStale(Duration timeout) {
        Instant cutoff = Instant.now().minus(timeout);
        int removed = 0;
        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Connection c = it.next().getValue();
            if (c.getLastSeen().isBefore(cutoff) || c.getState() == Connection.State.CLOSED) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    public void clear() {
        connections.clear();
    }

    // -------------------------------------------------------------------------
    // Query
    // -------------------------------------------------------------------------

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() {
        return connections.size();
    }

    public void forEach(Consumer<Connection> callback) {
        connections.values().forEach(callback);
    }

    public TrackerStats getStats() {
        return new TrackerStats(connections.size(), totalSeen, classifiedCount, blockedCount);
    }

    // -------------------------------------------------------------------------

    private void evictOldest() {
        if (connections.isEmpty()) return;
        FiveTuple oldestKey = null;
        Instant oldestTime = Instant.MAX;
        for (Map.Entry<FiveTuple, Connection> e : connections.entrySet()) {
            if (e.getValue().getLastSeen().isBefore(oldestTime)) {
                oldestTime = e.getValue().getLastSeen();
                oldestKey  = e.getKey();
            }
        }
        if (oldestKey != null) connections.remove(oldestKey);
    }

    // -------------------------------------------------------------------------

    public record TrackerStats(
            long activeConnections,
            long totalConnectionsSeen,
            long classifiedConnections,
            long blockedConnections) {}
}
