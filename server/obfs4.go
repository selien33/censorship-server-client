package main

import (
    "fmt"
    "io"
    "net"
    "time"
    
    "gitlab.com/yawning/obfs4.git/transports"
)

func StartObfs4Server(addr string, creds *ServerCredentials) error {
    fmt.Printf("Starting OBFS4 server on %s\n", addr)
    
    // Initialize transports
    if err := transports.Init(); err != nil {
        return fmt.Errorf("failed to initialize transports: %v", err)
    }
    
    transport := transports.Get("obfs4")
    if transport == nil {
        return fmt.Errorf("obfs4 transport not available")
    }
    
    // Display server details from credentials
    if creds != nil {
        protocolCreds := creds.Protocols["obfs4"]
        fmt.Printf("OBFS4 Server Details:\n")
        fmt.Printf("  Certificate: %s\n", protocolCreds.Credentials["certificate"])
        fmt.Printf("  IAT Mode: %s\n", protocolCreds.Credentials["iat_mode"])
        fmt.Printf("\nUse the certificate above to configure clients.\n\n")
    }
    
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        return fmt.Errorf("failed to listen: %v", err)
    }
    defer listener.Close()
    
    fmt.Printf("OBFS4 server listening on %s\n", addr)
    
    for {
        conn, err := listener.Accept()
        if err != nil {
            continue
        }
        go handleObfs4Connection(conn)
    }
}

func handleObfs4Connection(conn net.Conn) {
    defer conn.Close()
    
    connID := fmt.Sprintf("obfs4-%d", time.Now().UnixNano())
    
    LogConnection("OBFS4", connID, conn.RemoteAddr().String(), conn.LocalAddr().String())
    
    conn.SetReadDeadline(time.Now().Add(30 * time.Second))
    
    buffer := make([]byte, 4096)
    packetCount := 0
    totalBytes := 0
    
    for {
        n, err := conn.Read(buffer)
        if err != nil {
            if err != io.EOF {
                LogError("OBFS4", connID, "read_error", err.Error(), map[string]interface{}{
                    "total_bytes":   totalBytes,
                    "total_packets": packetCount,
                })
            }
            break
        }
        
        if n > 0 {
            packetCount++
            totalBytes += n
            
            LogDataReceived("OBFS4", connID, packetCount, n, totalBytes, buffer[:n])
            
            conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
            
            written, err := conn.Write(buffer[:n])
            if err != nil {
                LogError("OBFS4", connID, "write_error", err.Error(), map[string]interface{}{
                    "packet_number": packetCount,
                })
                break
            }
            
            LogDataSent("OBFS4", connID, packetCount, written, totalBytes, buffer[:written])
        }
    }
    
    LogConnectionClosed("OBFS4", connID, packetCount, totalBytes)
}