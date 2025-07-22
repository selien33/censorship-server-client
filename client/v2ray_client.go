package main

import (
    "crypto/tls"
    "fmt"
    "io"
    "net"
    "net/http"
    "strings"
    "time"
    
    "github.com/gorilla/websocket"
    "github.com/shadowsocks/go-shadowsocks2/core"
)

func RunV2RayTest(addr, protocol string, config *TestConfig) TestResult {
    startTime := time.Now()
    result := TestResult{
        Protocol: fmt.Sprintf("v2ray-%s", protocol),
        Target:   addr,
        Success:  false,
    }
    
    LogTestStart(strings.ToUpper(protocol), addr)
    
    // Validate V2Ray configuration
    if config.V2RayConfig == nil {
        result.Error = fmt.Sprintf("V2Ray %s configuration is required", protocol)
        result.Duration = time.Since(startTime)
        return result
    }
    
    // Create client based on protocol
    client, err := createV2RayClient(protocol, addr, config.V2RayConfig, config.Timeout)
    if err != nil {
        result.Error = fmt.Sprintf("Failed to create client: %v", err)
        result.Duration = time.Since(startTime)
        return result
    }
    defer client.Close()
    
    // Connect
    connectionStart := time.Now()
    if err := client.Connect(); err != nil {
        result.Error = fmt.Sprintf("Failed to connect: %v", err)
        result.Duration = time.Since(startTime)
        LogConnection(strings.ToUpper(protocol), addr, false, time.Since(connectionStart), err)
        return result
    }
    
    connectionTime := time.Since(connectionStart)
    LogConnection(strings.ToUpper(protocol), addr, true, connectionTime, nil)
    
    // Generate and send test data
    testData := GenerateTestData(config.DataSize, "V2RAY-TEST-DATA-")
    LogRawData("outbound", "original", testData, fmt.Sprintf("Original test data before V2Ray %s processing", protocol))
    
    sendStart := time.Now()
    if err := client.Send(testData); err != nil {
        result.Error = fmt.Sprintf("Failed to send data: %v", err)
        result.Duration = time.Since(startTime)
        LogDataTransmission("send", len(testData), false, time.Since(sendStart), err)
        return result
    }
    
    result.DataSent = len(testData)
    sendTime := time.Since(sendStart)
    LogDataTransmission("send", len(testData), true, sendTime, nil)
    LogRawData("outbound", "processed", testData, fmt.Sprintf("Data as processed by V2Ray %s", protocol))
    
    // Receive response
    receiveStart := time.Now()
    responseData, err := client.Receive(len(testData))
    if err != nil {
        result.Error = fmt.Sprintf("Failed to receive data: %v", err)
        result.Duration = time.Since(startTime)
        LogDataTransmission("receive", 0, false, time.Since(receiveStart), err)
        return result
    }
    
    result.DataReceived = len(responseData)
    receiveTime := time.Since(receiveStart)
    LogDataTransmission("receive", len(responseData), true, receiveTime, nil)
    LogRawData("inbound", "processed", responseData, fmt.Sprintf("Data as received via V2Ray %s", protocol))
    
    // Verify echo
    matches, differences := verifyEcho(testData, responseData)
    LogEchoVerification(len(testData), len(responseData), matches, differences)
    
    if !matches {
        result.Error = fmt.Sprintf("Echo data mismatch: %d differences", differences)
    } else {
        result.Success = true
    }
    
    result.Duration = time.Since(startTime)
    LogTestComplete(strings.ToUpper(protocol), result.Success, result.Duration, result.DataSent, result.DataReceived,
        func() error { if result.Error != "" { return fmt.Errorf(result.Error) }; return nil }())
    
    return result
}

// V2Ray client interface
type V2RayClient interface {
    Connect() error
    Send([]byte) error
    Receive(int) ([]byte, error)
    Close() error
}

// Create V2Ray client based on protocol
func createV2RayClient(protocol, addr string, config *V2RayConfig, timeout time.Duration) (V2RayClient, error) {
    switch protocol {
    case ProtocolVLESS:
        return newVLESSClient(addr, config, timeout), nil
    case ProtocolVMESS:
        if config.Network == "ws" {
            return newVMESSWebSocketClient(addr, config, timeout), nil
        }
        return newVMESSTCPClient(addr, config, timeout), nil
    case ProtocolShadowsocks:
        return newShadowsocksClient(addr, config, timeout)
    case ProtocolXTLS:
        return newXTLSClient(addr, config, timeout), nil
    default:
        return nil, fmt.Errorf("unsupported protocol: %s", protocol)
    }
}

// ####################
// ### VLESS Client ###
// ####################
type VLESSClient struct {
    addr    string
    config  *V2RayConfig
    timeout time.Duration
    conn    net.Conn
}

func newVLESSClient(addr string, config *V2RayConfig, timeout time.Duration) *VLESSClient {
    return &VLESSClient{addr: addr, config: config, timeout: timeout}
}

func (c *VLESSClient) Connect() error {
    conn, err := net.DialTimeout("tcp", c.addr, c.timeout)
    if err != nil {
        return err
    }
    c.conn = conn
    return nil
}

func (c *VLESSClient) Send(data []byte) error {
    _, err := c.conn.Write(data)
    return err
}

func (c *VLESSClient) Receive(expectedLen int) ([]byte, error) {
    data := make([]byte, expectedLen)
    _, err := io.ReadFull(c.conn, data)
    return data, err
}

func (c *VLESSClient) Close() error {
    if c.conn != nil {
        return c.conn.Close()
    }
    return nil
}

// ########################
// ### VMESS TCP Client ###
// ########################

type VMESSTCPClient struct {
    addr    string
    config  *V2RayConfig
    timeout time.Duration
    conn    net.Conn
}

func newVMESSTCPClient(addr string, config *V2RayConfig, timeout time.Duration) *VMESSTCPClient {
    return &VMESSTCPClient{addr: addr, config: config, timeout: timeout}
}

func (c *VMESSTCPClient) Connect() error {
    conn, err := net.DialTimeout("tcp", c.addr, c.timeout)
    if err != nil {
        return err
    }
    c.conn = conn
    return nil
}

func (c *VMESSTCPClient) Send(data []byte) error {
    _, err := c.conn.Write(data)
    return err
}

func (c *VMESSTCPClient) Receive(expectedLen int) ([]byte, error) {
    data := make([]byte, expectedLen)
    _, err := io.ReadFull(c.conn, data)
    return data, err
}

func (c *VMESSTCPClient) Close() error {
    if c.conn != nil {
        return c.conn.Close()
    }
    return nil
}

// ##############################
// ### VMESS WebSocket Client ###
// ##############################
type VMESSWebSocketClient struct {
    addr    string
    config  *V2RayConfig
    timeout time.Duration
    conn    *websocket.Conn
}

func newVMESSWebSocketClient(addr string, config *V2RayConfig, timeout time.Duration) *VMESSWebSocketClient {
    return &VMESSWebSocketClient{addr: addr, config: config, timeout: timeout}
}

func (c *VMESSWebSocketClient) Connect() error {
    url := fmt.Sprintf("ws://%s%s", c.addr, c.config.Path)
    
    headers := http.Header{}
    for k, v := range c.config.Headers {
        headers.Set(k, v)
    }
    
    dialer := &websocket.Dialer{
        HandshakeTimeout: c.timeout,
    }
    
    conn, _, err := dialer.Dial(url, headers)
    if err != nil {
        return err
    }
    
    c.conn = conn
    return nil
}

func (c *VMESSWebSocketClient) Send(data []byte) error {
    return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (c *VMESSWebSocketClient) Receive(expectedLen int) ([]byte, error) {
    _, data, err := c.conn.ReadMessage()
    return data, err
}

func (c *VMESSWebSocketClient) Close() error {
    if c.conn != nil {
        return c.conn.Close()
    }
    return nil
}

// ##########################
// ### Shadowsocks Client ###
// ##########################
type ShadowsocksClient struct {
    addr    string
    config  *V2RayConfig
    timeout time.Duration
    conn    net.Conn
    cipher  core.Cipher
}

func newShadowsocksClient(addr string, config *V2RayConfig, timeout time.Duration) (*ShadowsocksClient, error) {
    
    // Validate parameters
    if config.Method == "" || config.Password == "" {
        return nil, fmt.Errorf("missing shadowsocks parameters: method=%s, password=%s", config.Method, config.Password)
    }
    
    cipher, err := core.PickCipher(config.Method, nil, config.Password)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %v", err)
    }
    
    return &ShadowsocksClient{
        addr:    addr,
        config:  config,
        timeout: timeout,
        cipher:  cipher,
    }, nil
}

func (c *ShadowsocksClient) Connect() error {
    conn, err := net.DialTimeout("tcp", c.addr, c.timeout)
    if err != nil {
        return err
    }
    
    // Wrap connection with cipher
    c.conn = c.cipher.StreamConn(conn)
    return nil
}

func (c *ShadowsocksClient) Send(data []byte) error {
    _, err := c.conn.Write(data)
    return err
}

func (c *ShadowsocksClient) Receive(expectedLen int) ([]byte, error) {
    data := make([]byte, expectedLen)
    _, err := io.ReadFull(c.conn, data)
    return data, err
}

func (c *ShadowsocksClient) Close() error {
    if c.conn != nil {
        return c.conn.Close()
    }
    return nil
}

// ###################
// ### XTLS Client ###
// ###################
type XTLSClient struct {
    addr    string
    config  *V2RayConfig
    timeout time.Duration
    conn    net.Conn
}

func newXTLSClient(addr string, config *V2RayConfig, timeout time.Duration) *XTLSClient {
    return &XTLSClient{addr: addr, config: config, timeout: timeout}
}

func (c *XTLSClient) Connect() error {
    tlsConfig := &tls.Config{
        ServerName:         c.config.ServerName,
        NextProtos:         c.config.ALPN,
        InsecureSkipVerify: true, 
    }
    
    conn, err := tls.DialWithDialer(&net.Dialer{Timeout: c.timeout}, "tcp", c.addr, tlsConfig)
    if err != nil {
        return err
    }
    
    c.conn = conn
    return nil
}

func (c *XTLSClient) Send(data []byte) error {
    _, err := c.conn.Write(data)
    return err
}

func (c *XTLSClient) Receive(expectedLen int) ([]byte, error) {
    data := make([]byte, expectedLen)
    _, err := io.ReadFull(c.conn, data)
    return data, err
}

func (c *XTLSClient) Close() error {
    if c.conn != nil {
        return c.conn.Close()
    }
    return nil
}