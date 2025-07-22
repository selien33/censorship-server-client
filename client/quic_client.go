package main

import (
    "context"
    "crypto/tls"
    "fmt"
    "io"
    "time"

    "github.com/quic-go/quic-go"
)

func RunQUICTest(addr string, config *TestConfig) TestResult {
    startTime := time.Now()
    result := TestResult{
        Protocol: "quic",
        Target:   addr,
        Success:  false,
    }
    
    LogTestStart("QUIC", addr)
    
    // Create TLS config (insecure for testing)
    tlsConf := &tls.Config{
        InsecureSkipVerify: true,
        NextProtos:         []string{"quic-echo"},
    }
    
    // Create QUIC config
    quicConfig := buildQUICConfig(config.QUICConfig)
    
    // Connect
    connectionStart := time.Now()
    ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
    defer cancel()
    
    conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConfig)
    if err != nil {
        result.Error = fmt.Sprintf("Failed to connect: %v", err)
        result.Duration = time.Since(startTime)
        LogConnection("QUIC", addr, false, time.Since(connectionStart), err)
        return result
    }
    defer conn.CloseWithError(0, "client closing")
    
    connectionTime := time.Since(connectionStart)
    LogConnection("QUIC", addr, true, connectionTime, nil)
    
    // Open stream
    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        result.Error = fmt.Sprintf("Failed to open stream: %v", err)
        result.Duration = time.Since(startTime)
        return result
    }
    defer stream.Close()
    
    // Set deadlines
    stream.SetReadDeadline(time.Now().Add(config.Timeout))
    stream.SetWriteDeadline(time.Now().Add(config.Timeout))
    
    // Generate and send test data
    testData := GenerateTestData(config.DataSize, "QUIC-TEST-DATA-")
    LogRawData("outbound", "original", testData, "Original test data before QUIC stream processing")
    
    sendStart := time.Now()
    if _, err := stream.Write(testData); err != nil {
        result.Error = fmt.Sprintf("Failed to send data: %v", err)
        result.Duration = time.Since(startTime)
        LogDataTransmission("send", len(testData), false, time.Since(sendStart), err)
        return result
    }
    
    result.DataSent = len(testData)
    sendTime := time.Since(sendStart)
    LogDataTransmission("send", len(testData), true, sendTime, nil)
    LogRawData("outbound", "stream_processed", testData, "Data as sent over QUIC stream")
    
    // Receive response
    receiveStart := time.Now()
    responseData := make([]byte, len(testData))
    if _, err := io.ReadFull(stream, responseData); err != nil {
        result.Error = fmt.Sprintf("Failed to receive data: %v", err)
        result.Duration = time.Since(startTime)
        LogDataTransmission("receive", 0, false, time.Since(receiveStart), err)
        return result
    }
    
    result.DataReceived = len(responseData)
    receiveTime := time.Since(receiveStart)
    LogDataTransmission("receive", len(responseData), true, receiveTime, nil)
    LogRawData("inbound", "stream_received", responseData, "Data as received from QUIC stream")
    
    // Verify echo
    matches, differences := verifyEcho(testData, responseData)
    LogEchoVerification(len(testData), len(responseData), matches, differences)
    
    if !matches {
        result.Error = fmt.Sprintf("Echo data mismatch: %d differences", differences)
    } else {
        result.Success = true
    }
    
    result.Duration = time.Since(startTime)
    LogTestComplete("QUIC", result.Success, result.Duration, result.DataSent, result.DataReceived,
        func() error { if result.Error != "" { return fmt.Errorf(result.Error) }; return nil }())
    
    return result
}

func buildQUICConfig(config *QUICConfig) *quic.Config {
    if config == nil {
        return &quic.Config{
            MaxIdleTimeout:                 30 * time.Second,
            MaxIncomingStreams:             100,
            MaxIncomingUniStreams:          100,
            KeepAlivePeriod:               15 * time.Second,
            EnableDatagrams:               true,
            InitialStreamReceiveWindow:    512 * 1024,
            MaxStreamReceiveWindow:        2 * 1024 * 1024,
            InitialConnectionReceiveWindow: 1024 * 1024,
            MaxConnectionReceiveWindow:    4 * 1024 * 1024,
            DisablePathMTUDiscovery:      false,
            Versions:                     []quic.Version{quic.Version1},
        }
    }
    
    quicConfig := &quic.Config{
        MaxIdleTimeout:                 config.MaxIdleTimeout,
        MaxIncomingStreams:             config.MaxIncomingStreams,
        MaxIncomingUniStreams:          config.MaxIncomingUniStreams,
        KeepAlivePeriod:               config.KeepAlivePeriod,
        EnableDatagrams:               config.EnableDatagrams,
        InitialStreamReceiveWindow:    config.InitialStreamReceiveWindow,
        MaxStreamReceiveWindow:        config.MaxStreamReceiveWindow,
        InitialConnectionReceiveWindow: config.InitialConnectionReceiveWindow,
        MaxConnectionReceiveWindow:    config.MaxConnectionReceiveWindow,
        DisablePathMTUDiscovery:      config.DisablePathMTUDiscovery,
        Versions: make([]quic.Version, len(config.Versions)),
    }
    
    // Convert version numbers
    for i, v := range config.Versions {
        quicConfig.Versions[i] = quic.Version(v)
    }
    
    // Default to Version1 if no versions specified
    if len(quicConfig.Versions) == 0 {
        quicConfig.Versions = []quic.Version{quic.Version1}
    }
    
    return quicConfig
}