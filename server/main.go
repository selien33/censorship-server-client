package main

import (
    "flag"
    "fmt"
    "os"
    "os/signal"
    "strings"
    "sync"
    "syscall"
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

var (
    serverCredentials *ServerCredentials
    validProtocols    = []string{ProtocolObfs4, ProtocolVLESS, ProtocolVMESS, ProtocolXTLS, ProtocolShadowsocks, ProtocolQUIC}
)

type ServerConfig struct {
    Host      string
    BasePort  int
    Protocols []string
}

type ProtocolServer struct {
    Protocol string
    Port     int
    Status   string
    Error    error
}

func main() {
    host := flag.String("host", "127.0.0.1", "Host address to bind to")
    basePort := flag.Int("port", 8080, "Base port (protocols will use port+offset)")
    protocols := flag.String("protocols", "all", "Comma-separated list of protocols")
    showPorts := flag.Bool("ports", false, "Show port assignments and exit")
    genCreds := flag.Bool("credentials", true, "Generate credentials file")
    flag.Parse()

    fmt.Printf("=== Censorship Measurement Multi-Protocol Server ===\n")
    fmt.Printf("Host: %s, Base Port: %d\n\n", *host, *basePort)

    // Create logs directory if it doesn't exist
    if err := os.MkdirAll("logs", 0755); err != nil {
        fmt.Printf("Failed to create logs directory: %v\n", err)
        return
    }

    protocolList := parseProtocols(*protocols)
    
    if *showPorts {
        showPortAssignments(protocolList, *basePort)
        return
    }

    config := &ServerConfig{
        Host:      *host,
        BasePort:  *basePort,
        Protocols: protocolList,
    }

    // Generate credentials
    if *genCreds {
        var err error
        serverCredentials, err = GenerateCredentials(config.Host, config.BasePort, config.Protocols)
        if err != nil {
            fmt.Printf("Failed to generate credentials: %v\n", err)
            return
        }
        
        if err := SaveCredentials(serverCredentials); err != nil {
            fmt.Printf("Failed to save credentials: %v\n", err)
            return
        }
    }

    // Initialize logging
    if err := InitLogging("server", true, true); err != nil {
        fmt.Printf("Failed to initialize logging: %v\n", err)
        return
    }
    defer CloseLogging()

    // Start servers
    servers := startAllServers(config)
    printServerStatus(servers, *host, *basePort)
    waitForShutdown()
}

func parseProtocols(protocolStr string) []string {
    if protocolStr == "all" {
        return validProtocols
    }

    protocols := make([]string, 0)
    for _, p := range strings.Split(protocolStr, ",") {
        p = strings.TrimSpace(p)
        if isValidProtocol(p) {
            protocols = append(protocols, p)
        } else {
            fmt.Printf("Warning: Invalid protocol '%s' ignored\n", p)
        }
    }

    return protocols
}

func isValidProtocol(protocol string) bool {
    for _, p := range validProtocols {
        if p == protocol {
            return true
        }
    }
    return false
}

func showPortAssignments(protocols []string, basePort int) {
    fmt.Printf("Port Assignments:\n%s\n", strings.Repeat("=", 17))
    
    for i, protocol := range protocols {
        port := basePort + i
        fmt.Printf("%-15s: %d\n", protocol, port)
    }
    
    fmt.Printf("\nExample client usage:\n")
    for i, protocol := range protocols {
        port := basePort + i
        fmt.Printf("  ./client -protocol=%s -addr=localhost:%d\n", protocol, port)
    }
}

func startAllServers(config *ServerConfig) []*ProtocolServer {
    servers := make([]*ProtocolServer, 0)
    var wg sync.WaitGroup

    for i, protocol := range config.Protocols {
        port := config.BasePort + i
        addr := fmt.Sprintf("%s:%d", config.Host, port)
        
        server := &ProtocolServer{
            Protocol: protocol,
            Port:     port,
            Status:   "starting",
        }
        servers = append(servers, server)

        wg.Add(1)
        go func(s *ProtocolServer, proto, address string) {
            defer wg.Done()
            
            fmt.Printf("Starting %s server on %s...\n", proto, address)
            
            var err error
            switch proto {
            case ProtocolObfs4:
                err = StartObfs4Server(address, serverCredentials)
            case ProtocolVLESS, ProtocolVMESS, ProtocolXTLS, ProtocolShadowsocks:
                err = StartV2RayServer(address, proto, serverCredentials)
            case ProtocolQUIC:
                err = StartQUICServer(address, serverCredentials)
            default:
                err = fmt.Errorf("unsupported protocol: %s", proto)
            }
            
            if err != nil {
                s.Status = "failed"
                s.Error = err
                fmt.Printf("Failed to start %s server: %v\n", proto, err)
            } else {
                s.Status = "stopped"
                fmt.Printf("%s server stopped\n", proto)
            }
        }(server, protocol, addr)
        
        time.Sleep(100 * time.Millisecond)
    }

    time.Sleep(1 * time.Second)
    
    // Mark successfully started servers
    for _, server := range servers {
        if server.Status == "starting" {
            server.Status = "running"
        }
    }

    return servers
}

func printServerStatus(servers []*ProtocolServer, host string, basePort int) {
    fmt.Printf("\n%s\n", strings.Repeat("=", 60))
    fmt.Printf("SERVER STATUS\n")
    fmt.Printf("%s\n", strings.Repeat("=", 60))
    
    runningCount := 0
    for _, server := range servers {
        if server.Status == "running" {
            runningCount++
            fmt.Printf("✓ %-15s: %s:%d [%s]\n", server.Protocol, host, server.Port, server.Status)
            
            // Display client config
            if serverCredentials != nil {
                DisplayClientConfig(server.Protocol, serverCredentials)
            }
        } else {
            fmt.Printf("✗ %-15s: %s:%d [%s]", server.Protocol, host, server.Port, server.Status)
            if server.Error != nil {
                fmt.Printf(" - %v", server.Error)
            }
            fmt.Printf("\n")
        }
    }
    
    fmt.Printf("Running: %d/%d servers\n", runningCount, len(servers))
    fmt.Printf("%s\n", strings.Repeat("=", 60))
}

func waitForShutdown() {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    
    <-sigChan
    fmt.Printf("\nShutting down servers...\n")
    fmt.Printf("All servers stopped.\n")
}