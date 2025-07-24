package main

import (
    "encoding/json"
    "fmt"
    "os"
    "time"
    "sync"
)

var (
    logFile        *os.File
    logToTerminal  bool = true
    logEvents      []map[string]interface{}
    logMutex       sync.Mutex
)

// Initialize logging
func InitLogging(protocol string, enableDetailed bool, terminal bool) error {
    logToTerminal = terminal
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
        
        LogEvent("logging_initialized", map[string]interface{}{
            "protocol": protocol,
            "log_file": filename,
        })
    }
    
    return nil
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
        "data_transmission", "echo_verification", "configuration",
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

// Close logging
func CloseLogging() {
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