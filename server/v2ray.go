package main

import (
    "crypto/tls"
    "fmt"
    "io"
    "net"
    "net/http"
    "os"
    "strings"
    "time"
    
    "github.com/gorilla/websocket"
    "github.com/shadowsocks/go-shadowsocks2/core"
)

func StartV2RayServer(addr string, protocol string, creds *ServerCredentials) error {
    fmt.Printf("Starting V2Ray %s server on %s\n", protocol, addr)
    
    switch protocol {
    case "vless":
        return startVLESSServer(addr, creds)
    case "vmess":
        return startVMESSServer(addr, creds)
    case "shadowsocks":
        return startShadowsocksServer(addr, creds)
    case "xtls":
        return startXTLSServer(addr, creds)
    default:
        return fmt.Errorf("unsupported V2Ray protocol: %s", protocol)
    }
}

// ####################
// ### VLESS Server ###
// ####################
func startVLESSServer(addr string, creds *ServerCredentials) error {
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        return fmt.Errorf("failed to listen: %v", err)
    }
    defer listener.Close()
    
    fmt.Printf("VLESS server listening on %s\n", addr)
    
    for {
        conn, err := listener.Accept()
        if err != nil {
            continue
        }
        go handleV2RayConnection(conn, "VLESS")
    }
}

// ####################
// ### VMESS Server ###
// ####################
func startVMESSServer(addr string, creds *ServerCredentials) error {
    mux := http.NewServeMux()
    
    upgrader := websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool { return true },
    }
    
    mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
            return
        }
        handleVMESSWebSocket(conn)
    })
    
    // Handle direct TCP connections
    go func() {
        listener, err := net.Listen("tcp", addr)
        if err != nil {
            return
        }
        defer listener.Close()
        
        for {
            conn, err := listener.Accept()
            if err != nil {
                continue
            }
            go handleV2RayConnection(conn, "VMESS-TCP")
        }
    }()
    
    fmt.Printf("VMESS server listening on %s (HTTP/WebSocket)\n", addr)
    return http.ListenAndServe(addr, mux)
}

func handleVMESSWebSocket(wsConn *websocket.Conn) {
    defer wsConn.Close()
    
    connID := fmt.Sprintf("vmess-ws-%d", time.Now().UnixNano())
    LogConnection("VMESS-WS", connID, wsConn.RemoteAddr().String(), "")
    
    packetCount := 0
    totalBytes := 0
    
    for {
        _, data, err := wsConn.ReadMessage()
        if err != nil {
            if !websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
                LogError("VMESS-WS", connID, "websocket_error", err.Error(), nil)
            }
            break
        }
        
        packetCount++
        totalBytes += len(data)
        
        LogDataReceived("VMESS-WS", connID, packetCount, len(data), totalBytes, data)
        
        if err := wsConn.WriteMessage(websocket.BinaryMessage, data); err != nil {
            LogError("VMESS-WS", connID, "write_error", err.Error(), nil)
            break
        }
        
        LogDataSent("VMESS-WS", connID, packetCount, len(data), totalBytes, data)
    }
    
    LogConnectionClosed("VMESS-WS", connID, packetCount, totalBytes)
}

// ##########################
// ### Shadowsocks Server ###
// ##########################
func startShadowsocksServer(addr string, creds *ServerCredentials) error {
    protocolCreds := creds.Protocols["shadowsocks"]
    method := protocolCreds.Credentials["method"]
    password := protocolCreds.Credentials["password"]
    
    cipher, err := core.PickCipher(method, nil, password)
    if err != nil {
        return fmt.Errorf("failed to create cipher: %v", err)
    }
    
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        return fmt.Errorf("failed to listen: %v", err)
    }
    defer listener.Close()
    
    fmt.Printf("Shadowsocks server listening on %s (method: %s)\n", addr, method)
    
    for {
        conn, err := listener.Accept()
        if err != nil {
            continue
        }
        go handleShadowsocksConnection(conn, cipher)
    }
}

func handleShadowsocksConnection(conn net.Conn, cipher core.Cipher) {
    defer conn.Close()
    
    // Wrap connection with cipher
    ssConn := cipher.StreamConn(conn)
    handleV2RayConnection(ssConn, "Shadowsocks")
}

// ###################
// ### XTLS Server ###
// ###################
func startXTLSServer(addr string, creds *ServerCredentials) error {
    // Generate TLS certificate
    certPEM, keyPEM, err := GenerateTLSCert()
    if err != nil {
        return fmt.Errorf("failed to generate certificate: %v", err)
    }
    
    // Save certificate files
    certFile := "server.crt"
    keyFile := "server.key"
    
    if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
        return fmt.Errorf("failed to write cert file: %v", err)
    }
    if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
        return fmt.Errorf("failed to write key file: %v", err)
    }
    
    tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return fmt.Errorf("failed to load certificate: %v", err)
    }
    
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{tlsCert},
        NextProtos:   []string{"http/1.1"},
    }
    
    listener, err := tls.Listen("tcp", addr, tlsConfig)
    if err != nil {
        return fmt.Errorf("failed to listen: %v", err)
    }
    defer listener.Close()
    
    fmt.Printf("XTLS server listening on %s\n", addr)
    
    for {
        conn, err := listener.Accept()
        if err != nil {
            continue
        }
        go handleV2RayConnection(conn, "XTLS")
    }
}

// ########################################
// ### Generic V2Ray Connection Handler ###
// ########################################
func handleV2RayConnection(conn net.Conn, protocol string) {
    defer conn.Close()
    
    connID := fmt.Sprintf("%s-%d", strings.ToLower(protocol), time.Now().UnixNano())
    
    LogConnection(protocol, connID, conn.RemoteAddr().String(), conn.LocalAddr().String())
    
    conn.SetReadDeadline(time.Now().Add(30 * time.Second))
    
    buffer := make([]byte, 4096)
    packetCount := 0
    totalBytes := 0
    
    for {
        n, err := conn.Read(buffer)
        if err != nil {
            if err != io.EOF {
                LogError(protocol, connID, "read_error", err.Error(), map[string]interface{}{
                    "total_bytes":   totalBytes,
                    "total_packets": packetCount,
                })
            }
            break
        }
        
        if n > 0 {
            packetCount++
            totalBytes += n
            
            LogDataReceived(protocol, connID, packetCount, n, totalBytes, buffer[:n])
            
            conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
            
            if _, err := conn.Write(buffer[:n]); err != nil {
                LogError(protocol, connID, "write_error", err.Error(), map[string]interface{}{
                    "packet_number": packetCount,
                })
                break
            }
            
            LogDataSent(protocol, connID, packetCount, n, totalBytes, buffer[:n])
        }
    }
    
    LogConnectionClosed(protocol, connID, packetCount, totalBytes)
}