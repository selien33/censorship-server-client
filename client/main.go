package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "strings"
    "time"
)

const (
    ProtocolObfs4       = "obfs4"
    ProtocolVLESS       = "vless"
    ProtocolVMESS       = "vmess"
    ProtocolXTLS        = "xtls"
    ProtocolShadowsocks = "shadowsocks"
    ProtocolQUIC        = "quic"
)

var validProtocols = []string{ProtocolObfs4, ProtocolVLESS, ProtocolVMESS, ProtocolXTLS, ProtocolShadowsocks, ProtocolQUIC}

func main() {
    protocol := flag.String("protocol", "", "Protocol to test")
    addr := flag.String("addr", "", "Server address (host:port)")
    config := flag.String("config", "", "Configuration file path")
    credentials := flag.String("credentials", "", "Server credentials file")
    testAll := flag.Bool("test-all", false, "Test all protocols")
    basePort := flag.Int("port", 8080, "Base port for test-all")
    host := flag.String("host", "localhost", "Host for test-all")
    list := flag.Bool("list", false, "List all supported protocols")
    generate := flag.String("generate", "", "Generate default config")
    verbose := flag.Bool("verbose", true, "Enable verbose output")
    flag.Parse()
    basePort
    fmt.Printf("=== Censorship Measurement Client ===\n")

    if *list {
        listProtocols()
        return
    }

    if *generate != "" {
        if *protocol == "" {
            log.Fatal("Protocol must be specified when generating config")
        }
        if err := generateConfig(*protocol, *generate); err != nil {
            log.Fatalf("Failed to generate config: %v", err)
        }
        fmt.Printf("Generated configuration for %s saved to %s\n", *protocol, *generate)
        return
    }

    // Load credentials if provided
    var serverCreds *ServerCredentials
    if *credentials != "" {
        var err error
        serverCreds, err = LoadServerCredentials(*credentials)
        if err != nil {
            log.Fatalf("Failed to load credentials: %v", err)
        }
        fmt.Printf("v Loaded server credentials from %s\n", *credentials)
        fmt.Printf("  Generated: %s\n", serverCreds.Timestamp.Format("2006-01-02 15:04:05"))
        fmt.Printf("  Server: %s:%d\n\n", serverCreds.Host, serverCreds.BasePort)
    }

    if *testAll {
        if err := testAllProtocols(*host, *basePort, serverCreds, *verbose); err != nil {
            log.Fatalf("Failed to test all protocols: %v", err)
        }
        return
    }

    if *protocol == "" || *addr == "" {
        log.Fatal("Protocol and address must be specified")
    }

    if !isValidProtocol(*protocol) {
        fmt.Fprintf(os.Stderr, "Invalid protocol: %s\n", *protocol)
        os.Exit(1)
    }

    if err := runSingleTest(*addr, *protocol, *config, serverCreds, *verbose); err != nil {
        log.Fatalf("Client error: %v", err)
    }
}

// Test all protocols
func testAllProtocols(host string, basePort int, creds *ServerCredentials, verbose bool) error {
    fmt.Printf("Testing all protocols against %s (base port: %d)\n", host, basePort)
    fmt.Printf("%s\n", strings.Repeat("=", 60))

    results := make(map[string]TestResult)
    
    for i, protocol := range validProtocols {
        port := basePort + i
        addr := fmt.Sprintf("%s:%d", host, port)
        
        fmt.Printf("Testing %s on %s...\n", protocol, addr)
        
        result := runSingleTestInternal(addr, protocol, "", creds, host, verbose)
        results[protocol] = result
        
        if result.Success {
            fmt.Printf("  v %s: Success (%v, %d bytes)\n", protocol, result.Duration, result.DataReceived)
        } else {
            fmt.Printf("  x %s: Failed - %s\n", protocol, result.Error)
        }
        
        time.Sleep(500 * time.Millisecond)
    }
    
    printTestSummary(results)
    return nil
}

// Run single test
func runSingleTest(addr, protocol, configFile string, creds *ServerCredentials, verbose bool) error {
    host := extractHost(addr)
    result := runSingleTestInternal(addr, protocol, configFile, creds, host, verbose)
    
    // TODO -> Put in log file
    fmt.Printf("\n=== Test Summary ===\n")
    fmt.Printf("Protocol: %s\n", protocol)
    fmt.Printf("Target: %s\n", addr)
    fmt.Printf("Success: %t\n", result.Success)
    fmt.Printf("Duration: %v\n", result.Duration)
    fmt.Printf("Data Sent: %d bytes\n", result.DataSent)
    fmt.Printf("Data Received: %d bytes\n", result.DataReceived)
    if result.Error != "" {
        fmt.Printf("Error: %s\n", result.Error)
    }
    fmt.Printf("===================\n")
    
    if !result.Success {
        return fmt.Errorf("test failed: %s", result.Error)
    }
    
    return nil
}

// Internal test runner
func runSingleTestInternal(addr, protocol, configFile string, creds *ServerCredentials, targetHost string, verbose bool) TestResult {
    startTime := time.Now()
    
    // Get configuration
    var config *TestConfig
    var err error
    
    if configFile != "" {
        config, err = LoadConfig(configFile)
        if err != nil {
            return TestResult{
                Protocol: protocol,
                Target:   addr,
                Success:  false,
                Error:    fmt.Sprintf("Failed to load config: %v", err),
                Duration: time.Since(startTime),
            }
        }
    } else if creds != nil {
        config, err = CreateConfigFromCredentials(protocol, creds, targetHost)
        if err != nil {
            fmt.Printf("Warning: Failed to use credentials (%v), using defaults\n", err)
            config = GetDefaultConfig(protocol)
        }
    } else {
        config = GetDefaultConfig(protocol)
    }
    
    if config == nil {
        return TestResult{
            Protocol: protocol,
            Target:   addr,
            Success:  false,
            Error:    "Failed to get configuration",
            Duration: time.Since(startTime),
        }
    }
    
    // Initialize logging
    if err := InitLogging(protocol, true, verbose); err != nil {
        return TestResult{
            Protocol: protocol,
            Target:   addr,
            Success:  false,
            Error:    fmt.Sprintf("Failed to initialize logging: %v", err),
            Duration: time.Since(startTime),
        }
    }
    defer CloseLogging()
    
    // Log configuration being used
    configMap := buildConfigMap(protocol, config)
    LogConfiguration(protocol, configMap)
    
    // Run the actual test
    return runProtocolTest(addr, protocol, config)
}

// Run protocol-specific test
func runProtocolTest(addr, protocol string, config *TestConfig) TestResult {
    switch protocol {
    case ProtocolObfs4:
        return RunObfs4Test(addr, config)
    case ProtocolVLESS:
        return RunV2RayTest(addr, ProtocolVLESS, config)
    case ProtocolVMESS:
        return RunV2RayTest(addr, ProtocolVMESS, config)
    case ProtocolXTLS:
        return RunV2RayTest(addr, ProtocolXTLS, config)
    case ProtocolShadowsocks:
        return RunV2RayTest(addr, ProtocolShadowsocks, config)
    case ProtocolQUIC:
        return RunQUICTest(addr, config)
    default:
        return TestResult{
            Protocol: protocol,
            Target:   addr,
            Success:  false,
            Error:    fmt.Sprintf("Unsupported protocol: %s", protocol),
        }
    }
}

// Test result structure
type TestResult struct {
    Protocol     string
    Target       string
    Success      bool
    Duration     time.Duration
    DataSent     int
    DataReceived int
    Error        string
}

// Print summary for all tests
func printTestSummary(results map[string]TestResult) {
    fmt.Printf("\n%s\n", strings.Repeat("=", 60))
    fmt.Printf("TEST SUMMARY\n")
    fmt.Printf("%s\n", strings.Repeat("=", 60))
    
    successful := 0
    failed := 0
    
    for _, protocol := range validProtocols {
        result, exists := results[protocol]
        if !exists {
            fmt.Printf("%-15s: NOT TESTED\n", protocol)
            continue
        }
        
        if result.Success {
            successful++
            fmt.Printf("%-15s: v SUCCESS (%v, %d/%d bytes)\n", 
                protocol, result.Duration, result.DataReceived, result.DataSent)
        } else {
            failed++
            fmt.Printf("%-15s: x FAILED - %s\n", protocol, result.Error)
        }
    }
    
    fmt.Printf("\nOverall Results: %d successful, %d failed\n", successful, failed)
}

// Helper functions
func listProtocols() {
    fmt.Printf("Supported Protocols:\n")
    fmt.Printf("  obfs4       - OBFS4 pluggable transport\n")
    fmt.Printf("  vless       - V2Ray VLESS protocol\n")
    fmt.Printf("  vmess       - V2Ray VMESS protocol\n")
    fmt.Printf("  xtls        - V2Ray XTLS protocol\n")
    fmt.Printf("  shadowsocks - V2Ray Shadowsocks protocol\n")
    fmt.Printf("  quic        - QUIC protocol\n")
    fmt.Printf("\nExample usage:\n")
    fmt.Printf("  Single test: ./client -protocol=quic -addr=127.0.0.1:8085\n")
    fmt.Printf("  Test all:    ./client -test-all -host=127.0.0.1 -port=8080\n")
    fmt.Printf("  Generate:    ./client -generate=quic-config.yaml -protocol=quic\n")
}

func generateConfig(protocol, filename string) error {
    config := GetDefaultConfig(protocol)
    if config == nil {
        return fmt.Errorf("unsupported protocol for config generation: %s", protocol)
    }
    
    return SaveConfig(config, filename)
}

func isValidProtocol(protocol string) bool {
    for _, p := range validProtocols {
        if p == protocol {
            return true
        }
    }
    return false
}

func extractHost(addr string) string {
    if idx := strings.LastIndex(addr, ":"); idx != -1 {
        return addr[:idx]
    }
    return addr
}

func buildConfigMap(protocol string, config *TestConfig) map[string]interface{} {
    configMap := map[string]interface{}{
        "timeout":        config.Timeout,
        "data_size":      config.DataSize,
    }
    
    switch protocol {
    case ProtocolObfs4:
        if config.Obfs4Config != nil {
            configMap["certificate"] = config.Obfs4Config.Certificate
            configMap["iat_mode"] = config.Obfs4Config.IATMode
        }
        
    case ProtocolVLESS, ProtocolVMESS, ProtocolXTLS, ProtocolShadowsocks:
        if config.V2RayConfig != nil {
            configMap["uuid"] = config.V2RayConfig.UUID
            configMap["network"] = config.V2RayConfig.Network
            configMap["security"] = config.V2RayConfig.Security
            if config.V2RayConfig.Password != "" {
                configMap["method"] = config.V2RayConfig.Method
            }
        }
        
    case ProtocolQUIC:
        if config.QUICConfig != nil {
            configMap["max_idle_timeout"] = config.QUICConfig.MaxIdleTimeout
            configMap["enable_datagrams"] = config.QUICConfig.EnableDatagrams
        }
    }
    
    return configMap
}