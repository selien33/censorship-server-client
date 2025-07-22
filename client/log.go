package main

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "time"
    "os/exec"
    "sync"
)

var (
    detailedLogger *log.Logger
    logFile        *os.File
    logToTerminal  bool = true
    captureEnabled bool = false
    tcpdumpCmd     *exec.Cmd
    pcapFilename   string
    logEvents      []map[string]interface{}
    logMutex       sync.Mutex
)

// Initialize logging and packet capture
func InitLogging(protocol string, enableDetailed bool, terminal bool, enablePcap bool, targetAddr string) error {
    logToTerminal = terminal
    captureEnabled = enablePcap
    logEvents = make([]map[string]interface{}, 0)
    
    timestamp := time.Now().Unix()
    
    // Initialize detailed logging -> Will be stored in the logs/ folder
    if enableDetailed {
        filename := fmt.Sprintf("logs/%d-client-log-%s.json", timestamp, protocol)
        var err error
        logFile, err = os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
        if err != nil {
            return fmt.Errorf("failed to open log file: %v", err)
        }
        
        // Don't create detailedLogger yet -> will be writen at the end
        LogEvent("logging_initialized", map[string]interface{}{
            "protocol": protocol,
            "log_file": filename,
        })
    }
    
    // Initialize packet capture
    if enablePcap {
        if err := StartPacketCapture(protocol, timestamp, targetAddr); err != nil {
            fmt.Printf("Warning: Failed to start packet capture: %v\n", err)
            captureEnabled = false
        }
    }
    
    return nil
}

// Start packet capture using tcpdump
func StartPacketCapture(protocol string, timestamp int64, targetAddr string) error {
    pcapFilename = fmt.Sprintf("client-capture-%s-%d.pcap", protocol, timestamp)
    
    // Extract host from targetAddr
    host := targetAddr
    if idx := lastIndexByte(targetAddr, ':'); idx != -1 {
        host = targetAddr[:idx]
    }
    
    // Check if tcpdump is available
    if _, err := exec.LookPath("tcpdump"); err != nil {
        return fmt.Errorf("tcpdump not found in PATH: %v", err)
    }
    
    // Build tcpdump command - more portable approach
    args := []string{
        "-i", "any",           
        "-w", pcapFilename,
        "-s", "0",
        "-n",
        "host", host,
    }
    
    tcpdumpCmd = exec.Command("tcpdump", args...)
    
    // Start tcpdump in background
    if err := tcpdumpCmd.Start(); err != nil {
        return fmt.Errorf("failed to start tcpdump: %v (try running with sudo)", err)
    }
    
    // Wait for tcpdump to start (arbitrary)
    time.Sleep(100 * time.Millisecond)
    
    LogEvent("packet_capture_started", map[string]interface{}{
        "pcap_file": pcapFilename,
        "target":    targetAddr,
        "filter":    fmt.Sprintf("host %s", host),
        "pid":       tcpdumpCmd.Process.Pid,
    })
    
    if logToTerminal {
        fmt.Printf("✓ Packet capture started: %s (PID: %d)\n", pcapFilename, tcpdumpCmd.Process.Pid)
    }
    
    return nil
}

// Stop packet capture
func StopPacketCapture() {
    if tcpdumpCmd != nil && tcpdumpCmd.Process != nil {
        // Send SIGTERM to tcpdump to ensure proper pcap file closure
        if err := tcpdumpCmd.Process.Signal(os.Interrupt); err != nil {
            // If SIGTERM fails -> try SIGKILL
            tcpdumpCmd.Process.Kill()
        }
        
        // Wait for process to finish with timeout
        done := make(chan error, 1)
        go func() {
            done <- tcpdumpCmd.Wait()
        }()
        
        select {
        case err := <-done:
            if err != nil && logToTerminal {
                fmt.Printf("tcpdump finished with error: %v\n", err)
            }
        case <-time.After(2 * time.Second):
            // Force kill if it doesn't stop within 2 seconds
            tcpdumpCmd.Process.Kill()
            tcpdumpCmd.Wait()
        }
        
        // Check if pcap file was created
        if _, err := os.Stat(pcapFilename); err == nil {
            LogEvent("packet_capture_stopped", map[string]interface{}{
                "message":   "Packet capture completed",
                "pcap_file": pcapFilename,
                "file_created": true,
            })
            
            if logToTerminal {
                fmt.Printf("✓ Packet capture stopped - saved to: %s\n", pcapFilename)
            }
        } else {
            LogEvent("packet_capture_stopped", map[string]interface{}{
                "message":   "Packet capture completed but no file created",
                "pcap_file": pcapFilename,
                "file_created": false,
                "error": err.Error(),
            })
            
            if logToTerminal {
                fmt.Printf("⚠ Packet capture stopped but no file created: %v\n", err)
            }
        }
    }
}

// Generic event logger
func LogEvent(eventType string, data map[string]interface{}) {
    event := map[string]interface{}{
        "timestamp": time.Now(),
        "event":     eventType,
    }
    
    // Merge additional data
    for k, v := range data {
        event[k] = v
    }
    
    // Store event for JSON array format
    logMutex.Lock()
    logEvents = append(logEvents, event)
    logMutex.Unlock()
    
    // Log to terminal if enabled (filtered for readability)
    if logToTerminal && shouldLogToTerminal(eventType) {
        fmt.Printf("[%s] %s\n", eventType, formatEventForTerminal(data))
    }
}

// Test start log
func LogTestStart(protocol, target string) {
    LogEvent("test_start", map[string]interface{}{
        "protocol": protocol,
        "target":   target,
    })
    
    if logToTerminal {
        fmt.Printf("\n=== %s Test Started ===\n", protocol)
        fmt.Printf("Target: %s\n", target)
        fmt.Printf("========================\n\n")
    }
}

// Connection log
func LogConnection(protocol, target string, success bool, duration time.Duration, err error) {
    data := map[string]interface{}{
        "protocol": protocol,
        "target":   target,
        "success":  success,
        "duration": duration,
    }
    
    if err != nil {
        data["error"] = err.Error()
    }
    
    LogEvent("connection_attempt", data)
    
    if logToTerminal {
        if success {
            fmt.Printf("v Connected to %s (took %v)\n", target, duration)
        } else {
            fmt.Printf("x Connection failed: %v\n", err)
        }
    }
}

// Data transmission log
func LogDataTransmission(direction string, size int, success bool, duration time.Duration, err error) {
    data := map[string]interface{}{
        "direction": direction,
        "size":      size,
        "success":   success,
        "duration":  duration,
    }
    
    if err != nil {
        data["error"] = err.Error()
    }
    
    LogEvent("data_transmission", data)
    
    if logToTerminal {
        if success {
            fmt.Printf("v %s %d bytes (took %v)\n", 
                map[string]string{"send": "Sent", "receive": "Received"}[direction], 
                size, duration)
        } else {
            fmt.Printf("x Failed to %s data: %v\n", direction, err)
        }
    }
}

// Echo verification log
func LogEchoVerification(sent, received int, matches bool, differences int) {
    LogEvent("echo_verification", map[string]interface{}{
        "sent":        sent,
        "received":    received,
        "matches":     matches,
        "differences": differences,
    })
    
    if logToTerminal {
        if matches {
            fmt.Printf("v Echo verification successful: %d bytes matched\n", received)
        } else {
            fmt.Printf("x Echo verification failed: %d differences found\n", differences)
        }
    }
}

// Test completion log
func LogTestComplete(protocol string, success bool, duration time.Duration, sent, received int, err error) {
    data := map[string]interface{}{
        "protocol": protocol,
        "success":  success,
        "duration": duration,
        "sent":     sent,
        "received": received,
    }
    
    if err != nil {
        data["error"] = err.Error()
    }
    
    LogEvent("test_complete", data)
    
    if logToTerminal {
        fmt.Printf("\n=== %s Test Complete ===\n", protocol)
        fmt.Printf("Duration: %v\n", duration)
        fmt.Printf("Success: %t\n", success)
        fmt.Printf("Data sent: %d bytes\n", sent)
        fmt.Printf("Data received: %d bytes\n", received)
        if err != nil {
            fmt.Printf("Error: %v\n", err)
        }
        fmt.Printf("==========================\n\n")
    }
}

// Raw data log (for detailed analysis)
func LogRawData(direction, dataType string, data []byte, analysis string) {
    LogEvent("raw_data", map[string]interface{}{
        "direction": direction,
        "data_type": dataType,
        "size":      len(data),
        "raw_data":  data,
        "analysis":  analysis,
    })
}

// Configuration log
func LogConfiguration(protocol string, config map[string]interface{}) {
    LogEvent("configuration", map[string]interface{}{
        "protocol": protocol,
        "config":   config,
    })
    
    // TODO -> Think if really necessary not to log passworda to terminal ?!
    if logToTerminal {
        fmt.Printf("%s Configuration:\n", protocol)
        for key, value := range config {
            if key == "password" || key == "private_key" {
                fmt.Printf("  %s: [REDACTED]\n", key)
            } else {
                fmt.Printf("  %s: %v\n", key, value)
            }
        }
        fmt.Printf("\n")
    }
}

// Determine if event should be logged to terminal
func shouldLogToTerminal(eventType string) bool {
    importantEvents := []string{
        "test_start", "test_complete", "connection_attempt", 
        "data_transmission", "echo_verification", "packet_capture_started",
        "packet_capture_stopped", "configuration",
    }
    
    for _, important := range importantEvents {
        if eventType == important {
            return true
        }
    }
    return false
}

// Format event data for terminal display
func formatEventForTerminal(data map[string]interface{}) string {
    result := ""
    for k, v := range data {
        if k != "raw_data" && k != "config" { // Skip large data in terminal
            result += fmt.Sprintf("%s=%v ", k, v)
        }
    }
    return result
}

// Close logging and packet capture
func CloseLogging() {
    if captureEnabled {
        StopPacketCapture()
    }
    
    // Write all events as proper JSON array
    if logFile != nil {
        logMutex.Lock()
        jsonData, err := json.MarshalIndent(logEvents, "", "  ")
        logMutex.Unlock()
        
        if err != nil {
            fmt.Printf("Error marshaling log events: %v\n", err)
        } else {
            logFile.Write(jsonData)
        }
        
        logFile.Close()
    }
}

// Helper functions
func base64EncodeData(data []byte) string {
    if len(data) == 0 {
        return ""
    }
    // Encode to base64 but import the package at the top
    return "base64:" + fmt.Sprintf("%x", data) // Simple hex for now
}

func lastIndexByte(s string, c byte) int {
    for i := len(s) - 1; i >= 0; i-- {
        if s[i] == c {
            return i
        }
    }
    return -1
}