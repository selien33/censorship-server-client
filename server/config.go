package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "math/big"
    mathRand "math/rand"
    "net"
    "os"
    "strings"
    "time"
    
    "github.com/google/uuid"
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
    obfs4NodeID, obfs4PublicKey, obfs4PrivateKey, _ := generateObfs4Keys()
    obfs4Certificate := generateObfs4Certificate(obfs4NodeID, obfs4PublicKey)
    
    for i, protocol := range protocols {
        port := basePort + i
        
        switch protocol {
        case "obfs4":
            creds.Protocols[protocol] = ProtocolCredential{
                Protocol: protocol,
                Port:     port,
                Credentials: map[string]string{
                    "node_id":     obfs4NodeID,
                    "public_key":  obfs4PublicKey,
                    "private_key": obfs4PrivateKey,
                    "certificate": obfs4Certificate,
                    "iat_mode":    "0",
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

// Save credentials to files
func SaveCredentials(creds *ServerCredentials) error {
   
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

func generateObfs4Keys() (string, string, string, error) {
    nodeID := make([]byte, 20)
    publicKey := make([]byte, 32)
    privateKey := make([]byte, 32)
    
    if _, err := rand.Read(nodeID); err != nil {
        return "", "", "", err
    }
    if _, err := rand.Read(publicKey); err != nil {
        return "", "", "", err
    }
    if _, err := rand.Read(privateKey); err != nil {
        return "", "", "", err
    }
    
    return base64.StdEncoding.EncodeToString(nodeID),
           base64.StdEncoding.EncodeToString(publicKey),
           base64.StdEncoding.EncodeToString(privateKey),
           nil
}

func generateObfs4Certificate(nodeID, publicKey string) string {
    certData := fmt.Sprintf("node-id=%s,public-key=%s", nodeID, publicKey)
    return base64.StdEncoding.EncodeToString([]byte(certData))
}

func base64EncodeData(data []byte) string {
    if len(data) == 0 {
        return ""
    }
    return base64.StdEncoding.EncodeToString(data)
}