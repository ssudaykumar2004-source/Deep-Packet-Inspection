package com.packetanalyzer.rules;

import com.packetanalyzer.dpi.AppType;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe rule manager for packet/connection filtering.
 * Supports blocking by IP, application type, domain, and port.
 * Mirrors the C++ DPI::RuleManager class.
 */
public class RuleManager {

    // -------------------------------------------------------------------------
    // Blocked-IP rules
    // -------------------------------------------------------------------------

    private final ReadWriteLock ipLock = new ReentrantReadWriteLock();
    private final Set<Long> blockedIPs = new HashSet<>();

    public void blockIP(long ip) {
        ipLock.writeLock().lock();
        try { blockedIPs.add(ip); }
        finally { ipLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked IP: " + ipToString(ip));
    }

    public void blockIP(String ipStr) { blockIP(parseIP(ipStr)); }

    public void unblockIP(long ip) {
        ipLock.writeLock().lock();
        try { blockedIPs.remove(ip); }
        finally { ipLock.writeLock().unlock(); }
    }

    public boolean isIPBlocked(long ip) {
        ipLock.readLock().lock();
        try { return blockedIPs.contains(ip); }
        finally { ipLock.readLock().unlock(); }
    }

    public List<String> getBlockedIPs() {
        ipLock.readLock().lock();
        try {
            List<String> list = new ArrayList<>();
            for (long ip : blockedIPs) list.add(ipToString(ip));
            return list;
        } finally { ipLock.readLock().unlock(); }
    }

    // -------------------------------------------------------------------------
    // Blocked-App rules
    // -------------------------------------------------------------------------

    private final ReadWriteLock appLock = new ReentrantReadWriteLock();
    private final Set<AppType> blockedApps = new HashSet<>();

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try { blockedApps.add(app); }
        finally { appLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked app: " + app.toDisplayString());
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try { blockedApps.remove(app); }
        finally { appLock.writeLock().unlock(); }
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try { return blockedApps.contains(app); }
        finally { appLock.readLock().unlock(); }
    }

    public List<AppType> getBlockedApps() {
        appLock.readLock().lock();
        try { return new ArrayList<>(blockedApps); }
        finally { appLock.readLock().unlock(); }
    }

    // -------------------------------------------------------------------------
    // Blocked-Domain rules (exact + wildcard *.example.com)
    // -------------------------------------------------------------------------

    private final ReadWriteLock domainLock = new ReentrantReadWriteLock();
    private final Set<String>   blockedDomains  = new HashSet<>();
    private final List<String>  domainPatterns  = new ArrayList<>();  // wildcard

    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) domainPatterns.add(domain);
            else blockedDomains.add(domain.toLowerCase());
        } finally { domainLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked domain: " + domain);
    }

    public void unblockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) domainPatterns.remove(domain);
            else blockedDomains.remove(domain.toLowerCase());
        } finally { domainLock.writeLock().unlock(); }
    }

    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        String lower = domain.toLowerCase();

        domainLock.readLock().lock();
        try {
            if (blockedDomains.contains(lower)) return true;
            for (String pattern : domainPatterns) {
                if (matchesWildcard(lower, pattern.toLowerCase())) return true;
            }
            return false;
        } finally { domainLock.readLock().unlock(); }
    }

    public List<String> getBlockedDomains() {
        domainLock.readLock().lock();
        try {
            List<String> list = new ArrayList<>(blockedDomains);
            list.addAll(domainPatterns);
            return list;
        } finally { domainLock.readLock().unlock(); }
    }

    // -------------------------------------------------------------------------
    // Blocked-Port rules
    // -------------------------------------------------------------------------

    private final ReadWriteLock portLock = new ReentrantReadWriteLock();
    private final Set<Integer>  blockedPorts = new HashSet<>();

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try { blockedPorts.add(port); }
        finally { portLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked port: " + port);
    }

    public void unblockPort(int port) {
        portLock.writeLock().lock();
        try { blockedPorts.remove(port); }
        finally { portLock.writeLock().unlock(); }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try { return blockedPorts.contains(port); }
        finally { portLock.readLock().unlock(); }
    }

    // -------------------------------------------------------------------------
    // Combined check
    // -------------------------------------------------------------------------

    public Optional<BlockReason> shouldBlock(long srcIp, int dstPort, AppType app, String domain) {
        if (isIPBlocked(srcIp))       return Optional.of(new BlockReason(BlockReason.Type.IP,     ipToString(srcIp)));
        if (isPortBlocked(dstPort))   return Optional.of(new BlockReason(BlockReason.Type.PORT,   String.valueOf(dstPort)));
        if (isAppBlocked(app))        return Optional.of(new BlockReason(BlockReason.Type.APP,    app.toDisplayString()));
        if (isDomainBlocked(domain))  return Optional.of(new BlockReason(BlockReason.Type.DOMAIN, domain));
        return Optional.empty();
    }

    // -------------------------------------------------------------------------
    // Persistence
    // -------------------------------------------------------------------------

    public boolean saveRules(String filename) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(filename))) {
            pw.println("[BLOCKED_IPS]");
            getBlockedIPs().forEach(pw::println);

            pw.println("\n[BLOCKED_APPS]");
            getBlockedApps().forEach(a -> pw.println(a.toDisplayString()));

            pw.println("\n[BLOCKED_DOMAINS]");
            getBlockedDomains().forEach(pw::println);

            pw.println("\n[BLOCKED_PORTS]");
            portLock.readLock().lock();
            try { blockedPorts.forEach(pw::println); }
            finally { portLock.readLock().unlock(); }

            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Failed to save rules: " + e.getMessage());
            return false;
        }
    }

    public boolean loadRules(String filename) {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line, section = "";
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.startsWith("[")) { section = line; continue; }
                switch (section) {
                    case "[BLOCKED_IPS]"     -> blockIP(line);
                    case "[BLOCKED_APPS]"    -> {
                        for (AppType a : AppType.values()) {
                            if (a.toDisplayString().equalsIgnoreCase(line)) { blockApp(a); break; }
                        }
                    }
                    case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                    case "[BLOCKED_PORTS]"   -> blockPort(Integer.parseInt(line));
                }
            }
            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Failed to load rules: " + e.getMessage());
            return false;
        }
    }

    public void clearAll() {
        ipLock.writeLock().lock();     try { blockedIPs.clear();      } finally { ipLock.writeLock().unlock(); }
        appLock.writeLock().lock();    try { blockedApps.clear();     } finally { appLock.writeLock().unlock(); }
        domainLock.writeLock().lock(); try { blockedDomains.clear(); domainPatterns.clear(); } finally { domainLock.writeLock().unlock(); }
        portLock.writeLock().lock();   try { blockedPorts.clear();    } finally { portLock.writeLock().unlock(); }
        System.out.println("[RuleManager] All rules cleared");
    }

    public RuleStats getStats() {
        ipLock.readLock().lock();
        int ips; try { ips = blockedIPs.size(); } finally { ipLock.readLock().unlock(); }

        appLock.readLock().lock();
        int apps; try { apps = blockedApps.size(); } finally { appLock.readLock().unlock(); }

        domainLock.readLock().lock();
        int domains; try { domains = blockedDomains.size() + domainPatterns.size(); } finally { domainLock.readLock().unlock(); }

        portLock.readLock().lock();
        int ports; try { ports = blockedPorts.size(); } finally { portLock.readLock().unlock(); }

        return new RuleStats(ips, apps, domains, ports);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Supports *.example.com wildcard pattern. */
    private static boolean matchesWildcard(String domain, String pattern) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // .example.com
            if (domain.endsWith(suffix)) return true;
            if (domain.equals(pattern.substring(2))) return true; // bare match
        }
        return false;
    }

    public static long parseIP(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid IP: " + ip);
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (Long.parseLong(parts[i]) << (i * 8));
        }
        return result;
    }

    public static String ipToString(long ip) {
        return ((ip      ) & 0xFF) + "."
             + ((ip >>  8) & 0xFF) + "."
             + ((ip >> 16) & 0xFF) + "."
             + ((ip >> 24) & 0xFF);
    }

    // -------------------------------------------------------------------------

    public record BlockReason(Type type, String detail) {
        public enum Type { IP, APP, DOMAIN, PORT }
    }

    public record RuleStats(int blockedIps, int blockedApps, int blockedDomains, int blockedPorts) {}
}
