package main

import (
    "fmt"
    "io"
    "net"
    "os"
    "path/filepath"
    "time"

    "gitlab.com/yawning/obfs4.git/transports"
    "gitlab.com/yawning/obfs4.git/transports/base"
    _ "gitlab.com/yawning/obfs4.git/transports/obfs4"
    pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

func StartObfs4Server(addr string, creds *ServerCredentials) error {
    fmt.Printf("Starting OBFS4 server on %s\n", addr)

    if err := transports.Init(); err != nil {
        return fmt.Errorf("failed to initialize transports: %v", err)
    }

    transport := transports.Get("obfs4")
    if transport == nil {
        return fmt.Errorf("obfs4 transport not available")
    }

    // Create state directory if it doesn't exist
    stateDir := "./obfs4_state"
    if err := os.MkdirAll(stateDir, 0700); err != nil {
        return fmt.Errorf("failed to create state directory: %v", err)
    }

    // Create or load server state
    stateFile := filepath.Join(stateDir, "obfs4_state.json")
    serverState, err := loadOrCreateObfs4State(stateFile)
    if err != nil {
        return fmt.Errorf("failed to load/create server state: %v", err)
    }

    // Create pt.Args from server state
    ptArgs := pt.Args{}
    ptArgs.Add("node-id", serverState.NodeID)
    ptArgs.Add("private-key", serverState.PrivateKey)
    ptArgs.Add("drbg-seed", serverState.DrbgSeed)
    ptArgs.Add("iat-mode", fmt.Sprintf("%d", serverState.IATMode))

    fmt.Printf("\n\n\n%s\n\n\n", serverState.PublicKey)

    
    


    factory, err := transport.ServerFactory(stateDir, &ptArgs)
    if err != nil {
        return fmt.Errorf("failed to create server factory: %v", err)
    }


    // Try to read the certificate from bridgeline.txt first
    bridgelineFile := filepath.Join(stateDir, "obfs4_bridgeline.txt")
    fmt.Printf("DEBUG: Looking for bridgeline file at: %s\n", bridgelineFile)
    
    if bridgeInfo, err := readObfs4BridgeLine(bridgelineFile); err == nil {
        obfs4Certificate := bridgeInfo.Certificate
        obfs4IATMode := bridgeInfo.IATMode
        fmt.Printf("DEBUG: Successfully read from bridgeline.txt\n")
        fmt.Printf("DEBUG: Certificate from bridgeline: '%s'\n", obfs4Certificate)
        fmt.Printf("DEBUG: Certificate length: %d characters\n", len(obfs4Certificate))

        fmt.Printf("OBFS4 Server Details:\n")
        fmt.Printf("  Certificate: %s\n",obfs4Certificate)
        fmt.Printf("  IAT Mode: %d\n", obfs4IATMode)
        fmt.Printf("\nUse the certificate above to configure clients.\n\n")

        if obfs4Cred, ok := creds.Protocols["obfs4"]; ok {
            obfs4Cred.Credentials["certificate"] = obfs4Certificate
            obfs4Cred.Credentials["iat_mode"] = fmt.Sprintf("%d", obfs4IATMode)
            creds.Protocols["obfs4"] = obfs4Cred
        } else {
            fmt.Println("WARNING: obfs4 entry not found in creds.Protocols")
        }
    

        //Save creds to .json
        if err := SaveCredentials(creds); err != nil {
            return fmt.Errorf("Failed to save credentials: %v\n", err)
        }
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
        go handleObfs4Connection(conn, factory)
    }
}

func handleObfs4Connection(conn net.Conn, factory base.ServerFactory) {
    defer conn.Close()

    connID := fmt.Sprintf("obfs4-%d", time.Now().UnixNano())
    LogConnection("OBFS4", connID, conn.RemoteAddr().String(), conn.LocalAddr().String())

    wrappedConn, err := factory.WrapConn(conn)
    if err != nil {
        LogError("OBFS4", connID, "wrap_error", err.Error(), nil)
        return
    }
    defer wrappedConn.Close()

    wrappedConn.SetReadDeadline(time.Now().Add(30 * time.Second))

    buffer := make([]byte, 4096)
    packetCount := 0
    totalBytes := 0

    for {
        n, err := wrappedConn.Read(buffer)
        if err != nil {
            if err != io.EOF {
                LogError("OBFS4", connID, "read_error", err.Error(), map[string]interface{}{
                    "total_bytes":   totalBytes,
                    "total_packets": packetCount,
                })
            }
            break
        }

        packetCount++
        totalBytes += n
        LogDataReceived("OBFS4", connID, packetCount, n, totalBytes, buffer[:n])

        wrappedConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
        written, err := wrappedConn.Write(buffer[:n])
        if err != nil {
            LogError("OBFS4", connID, "write_error", err.Error(), map[string]interface{}{
                "packet_number": packetCount,
            })
            break
        }

        LogDataSent("OBFS4", connID, packetCount, written, totalBytes, buffer[:written])
    }

    LogConnectionClosed("OBFS4", connID, packetCount, totalBytes)
}
