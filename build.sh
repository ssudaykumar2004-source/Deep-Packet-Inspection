#!/bin/bash
set -e

# ── Packet Analyzer Java Build Script ──────────────────────────────────────
# Compiles all source files and packages them into a runnable JAR.
#
# Requirements: Java 17+ (uses records and switch expressions)
# Usage:   ./build.sh
# Output:  packet-analyzer.jar

JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d. -f1)
if [ -z "$JAVA_VERSION" ] || [ "$JAVA_VERSION" -lt 17 ]; then
    echo "ERROR: Java 17 or higher is required. Found: $JAVA_VERSION"
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$PROJECT_DIR/src/main/java"
OUT_DIR="$PROJECT_DIR/out"
JAR_NAME="packet-analyzer.jar"
MANIFEST="$PROJECT_DIR/MANIFEST.MF"

echo "===================================="
echo "  Building Packet Analyzer (Java)"
echo "===================================="

# Clean
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# Gather all .java files
SOURCES=$(find "$SRC_DIR" -name "*.java")
SOURCE_COUNT=$(echo "$SOURCES" | wc -l)
echo "Compiling $SOURCE_COUNT source file(s)..."

javac -source 17 -target 17 -d "$OUT_DIR" $SOURCES
echo "Compilation successful."

# Write manifest
cat > "$MANIFEST" <<EOF
Manifest-Version: 1.0
Main-Class: com.packetanalyzer.main.Main

EOF

# Package JAR
jar cfm "$JAR_NAME" "$MANIFEST" -C "$OUT_DIR" .
echo "JAR created: $JAR_NAME"
echo ""
echo "Run with:"
echo "  java -jar $JAR_NAME <pcap_file> [max_packets]"
echo ""
echo "DPI mode:"
echo "  java -cp $JAR_NAME com.packetanalyzer.main.DPIMain <pcap_file> [options]"
echo "===================================="
