package main

import (
    "encoding/json"
    "fmt"
    "os"
    "strings"
    "time"
)

var (
    logFilePath   string
    logFile       *os.File
    logToTerminal bool = true
)

// Initialize logging system
func InitLogging(protocol string, enableDetailed bool, terminal bool) error {
    logToTerminal = terminal

    timestamp := time.Now().Unix()
    if enableDetailed {
        logFilePath = fmt.Sprintf("logs/%d-server-log-%s.json", timestamp, protocol)
        var err error
        logFile, err = os.OpenFile(logFilePath, os.O_CREATE|os.O_RDWR, 0666)
        if err != nil {
            return fmt.Errorf("failed to open log file: %v", err)
        }

        stat, _ := logFile.Stat()
        if stat.Size() == 0 {
            _, _ = logFile.WriteString("[\n]\n") // minimal valid JSON
        }

        LogEvent("logging_initialized", map[string]interface{}{
            "protocol": protocol,
            "log_file": logFilePath,
        })
    }

    return nil
}

// Generic event logger
func LogEvent(eventType string, data map[string]interface{}) {
    event := map[string]interface{}{
        "timestamp": time.Now().Format(time.RFC3339Nano),
        "event":     eventType,
    }

    for k, v := range data {
        event[k] = v
    }

    if logToTerminal {
        fmt.Printf("[%s] %s\n", eventType, formatEventForTerminal(data))
    }

    if logFile != nil {
        appendJSONLog(event)
    }
}

func appendJSONLog(event map[string]interface{}) {
    // Read current contents into memory
    bytes, err := os.ReadFile(logFilePath)
    if err != nil {
        fmt.Printf("log append error: %v\n", err)
        return
    }

    content := strings.TrimSpace(string(bytes))
    if len(content) < 2 || !strings.HasPrefix(content, "[") || !strings.HasSuffix(content, "]") {
        fmt.Println("Invalid log format")
        return
    }

    // Remove trailing "]"
    content = strings.TrimSuffix(content, "]")
    content = strings.TrimSpace(content)

    // Check if we need to add comma
    if len(content) > 1 {
        content += ",\n"
    }

    // Append new JSON log entry
    entryJSON, _ := json.Marshal(event)
    content += string(entryJSON) + "\n]"

    // Write back to file
    os.WriteFile(logFilePath, []byte(content), 0666)
}

// Format event data for terminal display
func formatEventForTerminal(data map[string]interface{}) string {
    result := ""
    for k, v := range data {
        if k != "raw_data" {
            result += fmt.Sprintf("%s=%v ", k, v)
        }
    }
    return result
}

// Connection established log
func LogConnection(protocol, connID, remoteAddr, localAddr string) {
    LogEvent(protocol+"_connection_established", map[string]interface{}{
        "connection_id": connID,
        "protocol":      protocol,
        "remote_addr":   remoteAddr,
        "local_addr":    localAddr,
    })

    if logToTerminal {
        fmt.Printf("New %s connection from %s (ID: %s)\n", protocol, remoteAddr, connID)
    }
}

// Data received log
func LogDataReceived(protocol, connID string, packetNum, size, totalBytes int, data []byte) {
    LogEvent(protocol+"_data_received", map[string]interface{}{
        "connection_id": connID,
        "protocol":      protocol,
        "packet_number": packetNum,
        "size":          size,
        "total_bytes":   totalBytes,
        "raw_data":      data,
    })

    if logToTerminal {
        fmt.Printf("%s received packet %d (%d bytes)\n", protocol, packetNum, size)
    }
}

// Data sent log
func LogDataSent(protocol, connID string, packetNum, size, totalBytes int, data []byte) {
    LogEvent(protocol+"_data_sent", map[string]interface{}{
        "connection_id": connID,
        "protocol":      protocol,
        "packet_number": packetNum,
        "size":          size,
        "total_bytes":   totalBytes,
        "raw_data":      data,
    })

    if logToTerminal {
        fmt.Printf("%s echoed packet %d (%d bytes)\n", protocol, packetNum, size)
    }
}

// Error log
func LogError(protocol, connID, errorType, errorMsg string, data map[string]interface{}) {
    logData := map[string]interface{}{
        "connection_id": connID,
        "protocol":      protocol,
        "error":         errorMsg,
    }

    for k, v := range data {
        logData[k] = v
    }

    LogEvent(protocol+"_"+errorType, logData)

    if logToTerminal {
        fmt.Printf("%s %s: %s\n", protocol, errorType, errorMsg)
    }
}

// Connection closed log
func LogConnectionClosed(protocol, connID string, totalPackets, totalBytes int) {
    LogEvent(protocol+"_connection_closed", map[string]interface{}{
        "connection_id": connID,
        "protocol":      protocol,
        "total_packets": totalPackets,
        "total_bytes":   totalBytes,
    })

    if logToTerminal {
        fmt.Printf("%s connection closed (ID: %s, packets: %d, bytes: %d)\n",
            protocol, connID, totalPackets, totalBytes)
    }
}

// Close logging system
func CloseLogging() {
    if logFile != nil {
        logFile.Close()
    }
}
