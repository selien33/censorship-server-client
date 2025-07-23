package main

import (
    "bufio"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "math/big"
    mathRand "math/rand"
    "net"
    "os"
    "regexp"
    "strings"
    "time"
    
    "github.com/google/uuid"
    "gitlab.com/yawning/obfs4.git/common/ntor"
)

type ServerCredentials struct {
    Timestamp time.Time                      `json:"timestamp"`
    Host      string                         `json:"host"`
    BasePort  int                           `json:"base_port"`
    Protocols map[string]ProtocolCredential `json:"protocols"`
}

type ProtocolCredential struct {
    Protocol    string            `json:"protocol"`
    Port        int               `json:"port"`
    Credentials map[string]string `json:"credentials"`
}

// Obfs4ServerState represents the server's persistent state
type Obfs4ServerState struct {
    NodeID     string `json:"node-id"`
    PrivateKey string `json:"private-key"`
    PublicKey  string `json:"public-key"`
    DrbgSeed   string `json:"drbg-seed"`
    IATMode    int    `json:"iat-mode"`
}

// Obfs4BridgeInfo represents the parsed bridge line information
type Obfs4BridgeInfo struct {
    Certificate string
    IATMode     int
}

// Generate all server credentials
func GenerateCredentials(host string, basePort int, protocols []string) (*ServerCredentials, error) {
    creds := &ServerCredentials{
        Timestamp: time.Now(),
        Host:      host,
        BasePort:  basePort,
        Protocols: make(map[string]ProtocolCredential),
    }
    
    // Pre-generate common credentials
    shadowsocksPassword := generateSecurePassword(16)
    
    // Read certificate from bridgeline.txt -> done when server is started (in obfs4.go)
    var obfs4Certificate string
    var obfs4IATMode int

    // Dummy values for now
    obfs4Certificate = ""
    obfs4IATMode = -1
    
    
    for i, protocol := range protocols {
        port := basePort + i
        
        switch protocol {
        case "obfs4":
            creds.Protocols[protocol] = ProtocolCredential{
                Protocol: protocol,
                Port:     port,
                Credentials: map[string]string{
                    "certificate": obfs4Certificate,
                    "iat_mode":    fmt.Sprintf("%d", obfs4IATMode),
                },
            }
            
        case "vless":
            creds.Protocols[protocol] = ProtocolCredential{
                Protocol: protocol,
                Port:     port,
                Credentials: map[string]string{
                    "uuid":       generateUUID(),
                    "network":    "tcp",
                    "security":   "none",
                    "flow":       "xtls-rprx-vision",
                    "encryption": "none",
                },
            }
            
        case "vmess":
            creds.Protocols[protocol] = ProtocolCredential{
                Protocol: protocol,
                Port:     port,
                Credentials: map[string]string{
                    "uuid":       generateUUID(),
                    "network":    "ws",
                    "path":       "/ws",
                    "encryption": "auto",
                    "host":       "localhost",
                },
            }
            
        case "xtls":
            creds.Protocols[protocol] = ProtocolCredential{
                Protocol: protocol,
                Port:     port,
                Credentials: map[string]string{
                    "uuid":        generateUUID(),
                    "network":     "tcp",
                    "security":    "xtls",
                    "flow":        "xtls-rprx-vision",
                    "server_name": "localhost",
                    "alpn":        "http/1.1",
                },
            }
            
        case "shadowsocks":
            creds.Protocols[protocol] = ProtocolCredential{
                Protocol: protocol,
                Port:     port,
                Credentials: map[string]string{
                    "method":   "chacha20-ietf-poly1305",
                    "password": shadowsocksPassword,
                },
            }
            
        case "quic":
            creds.Protocols[protocol] = ProtocolCredential{
                Protocol: protocol,
                Port:     port,
                Credentials: map[string]string{
                    "max_idle_timeout":     "30s",
                    "max_incoming_streams": "100",
                    "enable_datagrams":     "true",
                    "versions":             "1",
                },
            }
        }
    }
    
    return creds, nil
}

// Read obfs4 certificate from bridgeline.txt file
func readObfs4BridgeLine(bridgelineFile string) (*Obfs4BridgeInfo, error) {
    fmt.Printf("DEBUG: Attempting to read file: %s\n", bridgelineFile)
    
    file, err := os.Open(bridgelineFile)
    if err != nil {
        return nil, fmt.Errorf("failed to open bridgeline file: %v", err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    
    // Regular expression to match the bridge line
    // Bridge obfs4 <IP ADDRESS>:<PORT> <FINGERPRINT> cert=<CERTIFICATE> iat-mode=<MODE>
    // Need to handle placeholders like <IP ADDRESS>:<PORT> and <FINGERPRINT> which contain spaces
    bridgeLineRegex := regexp.MustCompile(`Bridge\s+obfs4\s+(.+?)\s+(.+?)\s+cert=([A-Za-z0-9+/=]+)\s+iat-mode=(\d+)`)
    
    lineNum := 0
    for scanner.Scan() {
        lineNum++
        line := strings.TrimSpace(scanner.Text())
        fmt.Printf("DEBUG: Line %d: '%s'\n", lineNum, line)
        
        // Skip comments and empty lines
        if strings.HasPrefix(line, "#") || line == "" {
            fmt.Printf("DEBUG: Skipping line %d (comment or empty)\n", lineNum)
            continue
        }
        
        // Check if this is a bridge line
        fmt.Printf("DEBUG: Testing line %d against regex\n", lineNum)
        if matches := bridgeLineRegex.FindStringSubmatch(line); matches != nil {
            fmt.Printf("DEBUG: Regex matched! Found %d groups\n", len(matches))
            for i, match := range matches {
                fmt.Printf("DEBUG: Group %d: '%s'\n", i, match)
            }
            
            // matches[1] = IP:PORT, matches[2] = FINGERPRINT, matches[3] = CERTIFICATE, matches[4] = IAT-MODE
            certificate := matches[3]
            iatMode := 0
            if len(matches) > 4 {
                if _, err := fmt.Sscanf(matches[4], "%d", &iatMode); err != nil {
                    iatMode = 0
                }
            }
            
            fmt.Printf("DEBUG: Extracted certificate: '%s' (length: %d)\n", certificate, len(certificate))
            fmt.Printf("DEBUG: Extracted IAT mode: %d\n", iatMode)
            
            return &Obfs4BridgeInfo{
                Certificate: certificate,
                IATMode:     iatMode,
            }, nil
        } else {
            fmt.Printf("DEBUG: Line %d did not match bridge regex\n", lineNum)
        }
    }
    
    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("error reading bridgeline file: %v", err)
    }
    
    return nil, fmt.Errorf("no valid bridge line found in %s", bridgelineFile)
}

// Save credentials to files
func SaveCredentials(creds *ServerCredentials) error {
    // Debug: Check what we're about to save
    if obfs4Creds, exists := creds.Protocols["obfs4"]; exists {
        fmt.Printf("DEBUG: About to save obfs4 certificate: '%s'\n", obfs4Creds.Credentials["certificate"])
    }
    
    // Save JSON
    jsonFile := fmt.Sprintf("server-credentials.json")
    jsonData, err := json.MarshalIndent(creds, "", "  ")
    if err != nil {
        return err
    }
    if err := os.WriteFile(jsonFile, jsonData, 0644); err != nil {
        return err
    }
    
    // Save YAML
    yamlFile := fmt.Sprintf("server-credentials.yaml")
    yamlData := generateCredentialYAML(creds)
    if err := os.WriteFile(yamlFile, []byte(yamlData), 0644); err != nil {
        return err
    }
    
    fmt.Printf("\n%s\n", strings.Repeat("=", 70))
    fmt.Printf("CREDENTIALS GENERATED\n")
    fmt.Printf("%s\n", strings.Repeat("=", 70))
    fmt.Printf("JSON: %s\n", jsonFile)
    fmt.Printf("YAML: %s\n", yamlFile)
    fmt.Printf("%s\n\n", strings.Repeat("=", 70))
    
    return nil
}

// Generate YAML format
func generateCredentialYAML(creds *ServerCredentials) string {
    yaml := fmt.Sprintf("# Server Credentials Generated: %s\n# Host: %s, Base Port: %d\n\n",
        creds.Timestamp.Format("2006-01-02 15:04:05"), creds.Host, creds.BasePort)
    
    for protocol, cred := range creds.Protocols {
        yaml += fmt.Sprintf("%s:\n  port: %d\n", protocol, cred.Port)
        for key, value := range cred.Credentials {
            yaml += fmt.Sprintf("  %s: \"%s\"\n", key, value)
        }
        yaml += "\n"
    }
    
    return yaml
}

// Display client configuration for a protocol
func DisplayClientConfig(protocol string, creds *ServerCredentials) {
    if protocolCreds, exists := creds.Protocols[protocol]; exists {
        fmt.Printf("\n=== %s Client Configuration ===\n", strings.ToUpper(protocol))
        
        switch protocol {
        case "shadowsocks":
            fmt.Printf("v2ray_config:\n")
            fmt.Printf("  protocol: %s\n", protocol)
            fmt.Printf("  port: %d\n", protocolCreds.Port)
            fmt.Printf("  host: %s\n", creds.Host)
            fmt.Printf("  method: %s\n", protocolCreds.Credentials["method"])
            fmt.Printf("  password: %s\n", protocolCreds.Credentials["password"])
            
        case "vless", "vmess", "xtls":
            fmt.Printf("v2ray_config:\n")
            fmt.Printf("  protocol: %s\n", protocol)
            fmt.Printf("  uuid: %s\n", protocolCreds.Credentials["uuid"])
            fmt.Printf("  port: %d\n", protocolCreds.Port)
            fmt.Printf("  host: %s\n", creds.Host)
            for key, value := range protocolCreds.Credentials {
                if key != "uuid" {
                    fmt.Printf("  %s: %s\n", key, value)
                }
            }
            
        case "obfs4":
            fmt.Printf("obfs4_config:\n")
            fmt.Printf("  certificate: \"%s\"\n", protocolCreds.Credentials["certificate"])
            fmt.Printf("  iat_mode: %s\n", protocolCreds.Credentials["iat_mode"])
            
        case "quic":
            fmt.Printf("quic_config:\n")
            for key, value := range protocolCreds.Credentials {
                fmt.Printf("  %s: %s\n", key, value)
            }
            fmt.Printf("  target: %s:%d\n", creds.Host, protocolCreds.Port)
        }
        
        fmt.Printf("=====================================\n\n")
    }
}

// Generate TLS certificate
func GenerateTLSCert() ([]byte, []byte, error) {
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, nil, err
    }
    
    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization:  []string{"Test Server"},
            Country:       []string{"US"},
            Locality:      []string{"Test"},
        },
        NotBefore:    time.Now(),
        NotAfter:     time.Now().Add(365 * 24 * time.Hour),
        KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
        DNSNames:     []string{"localhost"},
    }
    
    certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
    if err != nil {
        return nil, nil, err
    }
    
    certPEM := []byte("-----BEGIN CERTIFICATE-----\n")
    certPEM = append(certPEM, base64.StdEncoding.EncodeToString(certDER)...)
    certPEM = append(certPEM, []byte("\n-----END CERTIFICATE-----\n")...)
    
    keyDER := x509.MarshalPKCS1PrivateKey(key)
    keyPEM := []byte("-----BEGIN RSA PRIVATE KEY-----\n")
    keyPEM = append(keyPEM, base64.StdEncoding.EncodeToString(keyDER)...)
    keyPEM = append(keyPEM, []byte("\n-----END RSA PRIVATE KEY-----\n")...)
    
    return certPEM, keyPEM, nil
}

// Helper functions

func generateUUID() string {
    return uuid.New().String()
}

func generateSecurePassword(length int) string {
    chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    password := make([]byte, length)
    for i := range password {
        password[i] = chars[mathRand.Intn(len(chars))]
    }
    return string(password)
}

func base64EncodeData(data []byte) string {
    if len(data) == 0 {
        return ""
    }
    return base64.StdEncoding.EncodeToString(data)
}

func loadOrCreateObfs4State(stateFile string) (*Obfs4ServerState, error) {
    // Try to load existing state
    if data, err := ioutil.ReadFile(stateFile); err == nil {
        var state Obfs4ServerState
        if err := json.Unmarshal(data, &state); err == nil {
            return &state, nil
        }
    }

    // Create new state
    keypair, err := ntor.NewKeypair(true)
    if err != nil {
        return nil, err
    }

    // Generate random node ID (20 bytes)
    nodeIDBytes := make([]byte, 20)
    if _, err := rand.Read(nodeIDBytes); err != nil {
        return nil, err
    }
    
    nodeID, err := ntor.NewNodeID(nodeIDBytes)
    if err != nil {
        return nil, err
    }

    // DRBG seed is 24 bytes for obfs4
    seed := make([]byte, 24)
    if _, err := rand.Read(seed); err != nil {
        return nil, err
    }

    state := &Obfs4ServerState{
        NodeID:     hex.EncodeToString(nodeID[:]),
        PrivateKey: hex.EncodeToString(keypair.Private().Bytes()[:]),
        PublicKey:  hex.EncodeToString(keypair.Public().Bytes()[:]),
        DrbgSeed:   hex.EncodeToString(seed),
        IATMode:    0,
    }

    // Save state
    data, err := json.MarshalIndent(state, "", "  ")
    if err != nil {
        return nil, err
    }

    fmt.Printf("\n\n\n %s \n\n\n\n", data)   

    if err := ioutil.WriteFile(stateFile, data, 0600); err != nil {
        return nil, err
    }

    return state, nil
}