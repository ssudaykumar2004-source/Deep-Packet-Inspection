package com.packetanalyzer.dpi;

/**
 * Application classification type.
 * Mirrors the C++ DPI::AppType enum.
 */
public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    // Detected via SNI
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE;

    public String toDisplayString() {
        return switch (this) {
            case TWITTER -> "Twitter/X";
            default -> name().charAt(0) + name().substring(1).toLowerCase();
        };
    }

    /** Map an SNI hostname to an AppType (mirrors C++ sniToAppType). */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;
        String s = sni.toLowerCase();

        if (s.contains("youtube") || s.contains("ytimg") || s.contains("youtu.be") || s.contains("yt3.ggpht"))
            return YOUTUBE;
        if (s.contains("instagram") || s.contains("cdninstagram"))
            return INSTAGRAM;
        if (s.contains("whatsapp") || s.contains("wa.me"))
            return WHATSAPP;
        if (s.contains("facebook") || s.contains("fbcdn") || s.contains("fb.com") || s.contains("meta.com"))
            return FACEBOOK;
        if (s.contains("google") || s.contains("gstatic") || s.contains("googleapis") || s.contains("gvt1"))
            return GOOGLE;
        if (s.contains("twitter") || s.contains("twimg") || s.contains("x.com") || s.contains("t.co"))
            return TWITTER;
        if (s.contains("netflix") || s.contains("nflxvideo") || s.contains("nflximg"))
            return NETFLIX;
        if (s.contains("amazon") || s.contains("amazonaws") || s.contains("cloudfront") || s.contains("aws"))
            return AMAZON;
        if (s.contains("microsoft") || s.contains("msn.com") || s.contains("office") ||
            s.contains("azure") || s.contains("live.com") || s.contains("outlook") || s.contains("bing"))
            return MICROSOFT;
        if (s.contains("apple") || s.contains("icloud") || s.contains("mzstatic") || s.contains("itunes"))
            return APPLE;
        if (s.contains("telegram") || s.contains("t.me"))
            return TELEGRAM;
        if (s.contains("tiktok") || s.contains("bytedance") || s.contains("musical.ly"))
            return TIKTOK;
        if (s.contains("spotify") || s.contains("scdn.co"))
            return SPOTIFY;
        if (s.contains("zoom"))
            return ZOOM;
        if (s.contains("discord") || s.contains("discordapp"))
            return DISCORD;
        if (s.contains("github") || s.contains("githubusercontent"))
            return GITHUB;
        if (s.contains("cloudflare") || s.contains("cf-"))
            return CLOUDFLARE;

        // SNI present but unrecognised → still TLS/HTTPS
        return HTTPS;
    }
}
