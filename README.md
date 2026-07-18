# Packet Analyzer – Java Port

A faithful Java conversion of the C++ Packet Analyzer project.  
Reads `.pcap` files and provides two modes: **basic packet display** and **Deep Packet Inspection (DPI)**.

---

## Project Structure

```
PacketAnalyzerJava/
├── build.sh                     # Linux/macOS build script
├── build.bat                    # Windows build script
├── README.md
└── src/main/java/com/packetanalyzer/
    ├── main/
    │   ├── Main.java            # Entry point – basic packet display
    │   └── DPIMain.java         # Entry point – DPI mode with rule-based blocking
    ├── model/
    │   ├── PcapGlobalHeader.java
    │   ├── RawPacket.java
    │   └── ParsedPacket.java
    ├── reader/
    │   └── PcapReader.java      # Binary PCAP file reader (handles byte-order)
    ├── parser/
    │   └── PacketParser.java    # Ethernet / IPv4 / TCP / UDP parser
    ├── dpi/
    │   ├── AppType.java         # Application classification enum (SNI-based)
    │   ├── Connection.java      # Per-flow connection state
    │   ├── FiveTuple.java       # Flow identifier (src-ip, dst-ip, ports, proto)
    │   └── DPIEngine.java       # Full DPI pipeline
    ├── tracker/
    │   └── ConnectionTracker.java  # Flow table with LRU eviction
    ├── sni/
    │   └── SNIExtractor.java    # TLS ClientHello SNI + HTTP Host + DNS query parsing
    └── rules/
        └── RuleManager.java     # Thread-safe rule manager (IP/app/domain/port blocking)
```

---

## Requirements

| Requirement | Version |
|-------------|---------|
| Java (JDK)  | **17 or higher** |

Check your version:
```bash
java -version
```

---

## Build Instructions

### Linux / macOS

```bash
cd PacketAnalyzerJava
chmod +x build.sh
./build.sh
```

### Windows

```bat
cd PacketAnalyzerJava
build.bat
```

Both scripts produce **`packet-analyzer.jar`** in the project root.

---

## How to Run

### Mode 1 — Basic Packet Display

Reads a PCAP file and prints layer-by-layer details for each packet  
(mirrors the original `main.cpp`).

```bash
# All packets
java -jar packet-analyzer.jar capture.pcap

# Limit to first 10 packets
java -jar packet-analyzer.jar capture.pcap 10
```

**Sample output:**
```
========== Packet #1 ==========
Time: 2024-03-15 10:22:31.000123

[Ethernet]
  Source MAC:      00:1a:2b:3c:4d:5e
  Destination MAC: ff:ff:ff:ff:ff:ff
  EtherType:       0x0800 (IPv4)

[IPv4]
  Source IP:      192.168.1.5
  Destination IP: 8.8.8.8
  Protocol:       UDP
  TTL:            64

[UDP]
  Source Port:      54321
  Destination Port: 53

[Payload]
  Length: 28 bytes
  Preview: 12 34 00 00 00 01 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 01 00 01 ...
```

---

### Mode 2 — DPI (Deep Packet Inspection)

Classifies flows via SNI / HTTP Host / DNS, applies optional blocking rules, and prints a statistics report.

```bash
# Basic DPI analysis (no blocking)
java -cp packet-analyzer.jar com.packetanalyzer.main.DPIMain capture.pcap

# Block Netflix traffic
java -cp packet-analyzer.jar com.packetanalyzer.main.DPIMain capture.pcap --block-app NETFLIX

# Block a specific domain
java -cp packet-analyzer.jar com.packetanalyzer.main.DPIMain capture.pcap --block-domain facebook.com

# Combine multiple rules
java -cp packet-analyzer.jar com.packetanalyzer.main.DPIMain capture.pcap \
  --block-app TIKTOK \
  --block-domain *.ads.google.com \
  --block-port 8080
```

**DPI flags:**

| Flag | Argument | Example |
|------|----------|---------|
| `--block-app`    | AppType name (uppercase) | `NETFLIX`, `FACEBOOK`, `YOUTUBE`, `DISCORD` … |
| `--block-domain` | Exact domain or `*.wildcard` | `facebook.com`, `*.doubleclick.net` |
| `--block-ip`     | IPv4 address | `192.168.1.100` |
| `--block-port`   | Port number | `8080` |

**Sample DPI report:**
```
╔══════════════════════════════════════════════════════════════╗
║               DPI ENGINE STATISTICS REPORT                   ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:           1024                               ║
║ TCP Packets:              876                               ║
║ UDP Packets:              148                               ║
║ Forwarded:               1010                               ║
║ Dropped (blocked):         14                               ║
║ Active Connections:         83                               ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                      ║
╠══════════════════════════════════════════════════════════════╣
║ Https                       42 ( 50.6%)                     ║
║ Google                      18 ( 21.7%)                     ║
║ Youtube                      9 ( 10.8%)                     ║
║ Http                         8 (  9.6%)                     ║
╚══════════════════════════════════════════════════════════════╝
```

---

## C++ → Java Mapping

| C++ File / Class        | Java Equivalent                              |
|------------------------|----------------------------------------------|
| `pcap_reader.{h,cpp}`  | `reader/PcapReader.java`                     |
| `packet_parser.{h,cpp}`| `parser/PacketParser.java`                   |
| `types.{h,cpp}`        | `dpi/AppType.java`, `dpi/FiveTuple.java`, `dpi/Connection.java` |
| `connection_tracker.*` | `tracker/ConnectionTracker.java`             |
| `sni_extractor.*`      | `sni/SNIExtractor.java`                      |
| `rule_manager.*`       | `rules/RuleManager.java`                     |
| `dpi_engine.*`         | `dpi/DPIEngine.java`                         |
| `main.cpp`             | `main/Main.java`                             |
| `main_dpi.cpp`         | `main/DPIMain.java`                          |

---

## Test PCAP files

The original project ships with two test files you can use immediately:

```bash
java -jar packet-analyzer.jar output.pcap
java -jar packet-analyzer.jar test_dpi.pcap
java -cp packet-analyzer.jar com.packetanalyzer.main.DPIMain test_dpi.pcap
```
