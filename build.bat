@echo off
:: Packet Analyzer Java – Windows Build Script
:: Requirements: Java 17+ on PATH
:: Usage: build.bat
:: Output: packet-analyzer.jar

setlocal EnableDelayedExpansion

set PROJECT_DIR=%~dp0
set SRC_DIR=%PROJECT_DIR%src\main\java
set OUT_DIR=%PROJECT_DIR%out
set JAR_NAME=packet-analyzer.jar
set MANIFEST=%PROJECT_DIR%MANIFEST.MF

echo ====================================
echo   Building Packet Analyzer (Java)
echo ====================================

:: Clean and recreate output directory
if exist "%OUT_DIR%" rmdir /s /q "%OUT_DIR%"
mkdir "%OUT_DIR%"

:: Gather all .java source files
set SOURCES_FILE=%TEMP%\java_sources.txt
if exist "%SOURCES_FILE%" del "%SOURCES_FILE%"

for /r "%SRC_DIR%" %%f in (*.java) do (
    echo %%f >> "%SOURCES_FILE%"
)

echo Compiling source files...
javac -source 17 -target 17 -d "%OUT_DIR%" @"%SOURCES_FILE%"
if errorlevel 1 (
    echo ERROR: Compilation failed.
    exit /b 1
)
echo Compilation successful.

:: Write manifest
(
    echo Manifest-Version: 1.0
    echo Main-Class: com.packetanalyzer.main.Main
    echo.
) > "%MANIFEST%"

:: Package JAR
jar cfm "%JAR_NAME%" "%MANIFEST%" -C "%OUT_DIR%" .
if errorlevel 1 (
    echo ERROR: JAR packaging failed.
    exit /b 1
)

echo JAR created: %JAR_NAME%
echo.
echo Run with:
echo   java -jar %JAR_NAME% ^<pcap_file^> [max_packets]
echo.
echo DPI mode:
echo   java -cp %JAR_NAME% com.packetanalyzer.main.DPIMain ^<pcap_file^> [options]
echo ====================================
endlocal
