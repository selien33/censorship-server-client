package main

import (
    "context"
    "crypto/tls"
    "fmt"
    "io"
    "net"
    "time"

    "github.com/quic-go/quic-go"
    "github.com/quic-go/quic-go/logging"
    "github.com/quic-go/quic-go/qlog"
)

type discardCloser struct{}
func (d *discardCloser) Write(p []byte) (n int, err error) { return len(p), nil }
func (d *discardCloser) Close() error { return nil }

func StartQUICServer(addr string, creds *ServerCredentials) error {
    fmt.Printf("Starting QUIC server on %s\n", addr)
    
    // Generate TLS certificate
    certPEM, keyPEM, err := GenerateTLSCert()
    if err != nil {
        return fmt.Errorf("failed to generate TLS config: %v", err)
    }
    
    cert, err := tls.X509KeyPair(certPEM, keyPEM)
    if err != nil {
        return fmt.Errorf("failed to load certificate: %v", err)
    }
    
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        NextProtos:   []string{"quic-echo"},
    }
    
    // QUIC config
    quicConfig := &quic.Config{
        MaxIdleTimeout:                 30 * time.Second,
        MaxIncomingStreams:             100,
        MaxIncomingUniStreams:          100,
        KeepAlivePeriod:                15 * time.Second,
        EnableDatagrams:                true,
        InitialStreamReceiveWindow:     512 * 1024,
        MaxStreamReceiveWindow:         2 * 1024 * 1024,
        InitialConnectionReceiveWindow: 1024 * 1024,
        MaxConnectionReceiveWindow:     4 * 1024 * 1024,
        DisablePathMTUDiscovery:        false,
        Versions:                       []quic.VersionNumber{quic.Version1},
        Tracer: func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
            return qlog.NewConnectionTracer(&discardCloser{}, p, connID)
        },
    }
    
    listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
    if err != nil {
        return fmt.Errorf("failed to start QUIC listener: %v", err)
    }
    defer listener.Close()
    
    fmt.Printf("QUIC server listening on %s\n", addr)
    
    for {
        conn, err := listener.Accept(context.Background())
        if err != nil {
            continue
        }
        go handleQUICConnection(conn)
    }
}

func handleQUICConnection(conn quic.Connection) {
    defer conn.CloseWithError(0, "server closing")
    
    for {
        stream, err := conn.AcceptStream(context.Background())
        if err != nil {
            break
        }
        go handleQUICStream(stream, conn.RemoteAddr())
    }
}

func handleQUICStream(stream quic.Stream, remoteAddr net.Addr) {
    defer stream.Close()
    
    streamID := stream.StreamID()
    connID := fmt.Sprintf("quic-stream-%d", streamID)
    
    LogConnection("QUIC", connID, remoteAddr.String(), "")
    
    stream.SetReadDeadline(time.Now().Add(30 * time.Second))
    stream.SetWriteDeadline(time.Now().Add(30 * time.Second))
    
    buffer := make([]byte, 4096)
    totalBytes := 0
    packetCount := 0
    
    for {
        n, err := stream.Read(buffer)
        if err != nil {
            if err == io.EOF {
                LogEvent("quic_stream_eof", map[string]interface{}{
                    "connection_id":  connID,
                    "stream_id":      fmt.Sprintf("%d", streamID),
                    "total_bytes":    totalBytes,
                    "total_packets":  packetCount,
                })
            } else {
                LogError("QUIC", connID, "read_error", err.Error(), map[string]interface{}{
                    "stream_id": fmt.Sprintf("%d", streamID),
                })
            }
            break
        }
        
        if n > 0 {
            totalBytes += n
            packetCount++
            
            LogDataReceived("QUIC", connID, packetCount, n, totalBytes, buffer[:n])
            
            written, err := stream.Write(buffer[:n])
            if err != nil {
                LogError("QUIC", connID, "write_error", err.Error(), map[string]interface{}{
                    "stream_id": fmt.Sprintf("%d", streamID),
                })
                break
            }
            
            LogDataSent("QUIC", connID, packetCount, written, totalBytes, buffer[:written])
        }
    }
    
    LogConnectionClosed("QUIC", connID, packetCount, totalBytes)
}