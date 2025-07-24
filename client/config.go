package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "time"
    "gopkg.in/yaml.v2"
)

// TestConfig holds configuration for a test run
type TestConfig struct {
    Protocol    string            `yaml:"protocol" json:"protocol"`
    Timeout     time.Duration     `yaml:"timeout" json:"timeout"`
    DataSize    int               `yaml:"data_size" json:"data_size"`
    Iterations  int               `yaml:"iterations" json:"iterations"`
    Parameters  map[string]string `yaml:"parameters" json:"parameters"`
    Obfs4Config *Obfs4Config      `yaml:"obfs4_config,omitempty" json:"obfs4_config,omitempty"`
    V2RayConfig *V2RayConfig      `yaml:"v2ray_config,omitempty" json:"v2ray_config,omitempty"`
    QUICConfig  *QUICConfig       `yaml:"quic_config,omitempty" json:"quic_config,omitempty"`
    LogConfig   *LogConfig        `yaml:"log_config,omitempty" json:"log_config,omitempty"`
}

// Protocol configurations
type Obfs4Config struct {
    NodeID       string `yaml:"node_id" json:"node_id"`
    PublicKey    string `yaml:"public_key" json:"public_key"`
    PrivateKey   string `yaml:"private_key" json:"private_key"`
    IATMode      int    `yaml:"iat_mode" json:"iat_mode"`
    Certificate  string `yaml:"certificate" json:"certificate"`
    ServerCert   string `yaml:"server_cert" json:"server_cert"`
}

type V2RayConfig struct {
    Protocol     string            `yaml:"protocol" json:"protocol"`
    UUID         string            `yaml:"uuid" json:"uuid"`
    Port         int               `yaml:"port" json:"port"`
    Network      string            `yaml:"network" json:"network"`
    Security     string            `yaml:"security" json:"security"`
    Path         string            `yaml:"path,omitempty" json:"path,omitempty"`
    Host         string            `yaml:"host,omitempty" json:"host,omitempty"`
    ServerName   string            `yaml:"server_name,omitempty" json:"server_name,omitempty"`
    Encryption   string            `yaml:"encryption,omitempty" json:"encryption,omitempty"`
    Password     string            `yaml:"password,omitempty" json:"password,omitempty"`
    Method       string            `yaml:"method,omitempty" json:"method,omitempty"`
    Flow         string            `yaml:"flow,omitempty" json:"flow,omitempty"`
    Fingerprint  string            `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
    ALPN         []string          `yaml:"alpn,omitempty" json:"alpn,omitempty"`
    Headers      map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

type QUICConfig struct {
    MaxIdleTimeout      time.Duration `yaml:"max_idle_timeout" json:"max_idle_timeout"`
    MaxIncomingStreams  int64         `yaml:"max_incoming_streams" json:"max_incoming_streams"`
    MaxIncomingUniStreams int64       `yaml:"max_incoming_uni_streams" json:"max_incoming_uni_streams"`
    KeepAlivePeriod     time.Duration `yaml:"keep_alive_period" json:"keep_alive_period"`
    EnableDatagrams     bool          `yaml:"enable_datagrams" json:"enable_datagrams"`
    InitialStreamReceiveWindow uint64 `yaml:"initial_stream_receive_window" json:"initial_stream_receive_window"`
    MaxStreamReceiveWindow     uint64 `yaml:"max_stream_receive_window" json:"max_stream_receive_window"`
    InitialConnectionReceiveWindow uint64 `yaml:"initial_connection_receive_window" json:"initial_connection_receive_window"`
    MaxConnectionReceiveWindow     uint64 `yaml:"max_connection_receive_window" json:"max_connection_receive_window"`
    AllowConnectionMigration   bool   `yaml:"allow_connection_migration" json:"allow_connection_migration"`
    DisablePathMTUDiscovery    bool   `yaml:"disable_path_mtu_discovery" json:"disable_path_mtu_discovery"`
    Enable0RTT                 bool   `yaml:"enable_0rtt" json:"enable_0rtt"`
    Versions                   []uint32 `yaml:"versions" json:"versions"`
}

type LogConfig struct {
    EnableDetailedLogging bool   `yaml:"enable_detailed_logging" json:"enable_detailed_logging"`
    LogFile              string `yaml:"log_file" json:"log_file"`
    LogToTerminal        bool   `yaml:"log_to_terminal" json:"log_to_terminal"`
    LogRawData           bool   `yaml:"log_raw_data" json:"log_raw_data"`
    LogKeys              bool   `yaml:"log_keys" json:"log_keys"`
    LogLevel             string `yaml:"log_level" json:"log_level"`
}

// Server credentials from server-generated file
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

// Load server credentials from file
func LoadServerCredentials(filename string) (*ServerCredentials, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to read credentials file: %v", err)
    }
    
    var creds ServerCredentials
    if err := json.Unmarshal(data, &creds); err != nil {
        return nil, fmt.Errorf("failed to parse credentials file: %v", err)
    }
    
    return &creds, nil
}

// Load test configuration from file
func LoadConfig(filename string) (*TestConfig, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file: %v", err)
    }
    
    var config TestConfig
    
    // Try YAML first, then JSON
    if err := yaml.Unmarshal(data, &config); err != nil {
        if err := json.Unmarshal(data, &config); err != nil {
            return nil, fmt.Errorf("failed to parse config file: %v", err)
        }
    }
    
    return &config, nil
}

// Create config from server credentials
func CreateConfigFromCredentials(protocol string, creds *ServerCredentials, targetHost string) (*TestConfig, error) {
    protocolCred, exists := creds.Protocols[protocol]
    if !exists {
        return nil, fmt.Errorf("no credentials found for protocol %s", protocol)
    }
    
    switch protocol {
    case "obfs4":
        return createObfs4Config(protocolCred, targetHost)
    case "vless":
        return createVLESSConfig(protocolCred, targetHost)
    case "vmess":
        return createVMESSConfig(protocolCred, targetHost)
    case "xtls":
        return createXTLSConfig(protocolCred, targetHost)
    case "shadowsocks":
        return createShadowsocksConfig(protocolCred, targetHost)
    case "quic":
        return createQUICConfig(protocolCred, targetHost)
    default:
        return nil, fmt.Errorf("unsupported protocol: %s", protocol)
    }
}

// Get default configuration for protocol
func GetDefaultConfig(protocol string) *TestConfig {
    switch protocol {
    case "obfs4":
        return &TestConfig{
            Protocol:    "obfs4",
            Timeout:     10 * time.Second,
            DataSize:    1024,
            Iterations:  1,
            Parameters:  make(map[string]string),
            Obfs4Config: &Obfs4Config{IATMode: 0},
            LogConfig:   getDefaultLogConfig(),
        }
        
    case "vless":
        return &TestConfig{
            Protocol:    "v2ray-vless",
            Timeout:     15 * time.Second,
            DataSize:    1024,
            Iterations:  1,
            Parameters:  make(map[string]string),
            V2RayConfig: &V2RayConfig{
                Protocol:    "vless",
                Port:        8081,
                Host:        "localhost",
                Network:     "tcp",
                Security:    "none",
                Flow:        "xtls-rprx-vision",
                Encryption:  "none",
            },
            LogConfig: getDefaultLogConfig(),
        }
        
    case "vmess":
        return &TestConfig{
            Protocol:    "v2ray-vmess",
            Timeout:     15 * time.Second,
            DataSize:    1024,
            Iterations:  1,
            Parameters:  make(map[string]string),
            V2RayConfig: &V2RayConfig{
                Protocol:   "vmess",
                Port:       8082,
                Host:       "localhost",
                Network:    "ws",
                Path:       "/ws",
                Encryption: "auto",
                Headers:    map[string]string{"Host": "localhost"},
            },
            LogConfig: getDefaultLogConfig(),
        }
        
    case "xtls":
        return &TestConfig{
            Protocol:    "v2ray-xtls",
            Timeout:     20 * time.Second,
            DataSize:    1024,
            Iterations:  1,
            Parameters:  make(map[string]string),
            V2RayConfig: &V2RayConfig{
                Protocol:   "xtls",
                Port:       8083,
                Host:       "localhost",
                Network:    "tcp",
                Security:   "xtls",
                Flow:       "xtls-rprx-vision",
                ServerName: "localhost",
                ALPN:       []string{"http/1.1"},
            },
            LogConfig: getDefaultLogConfig(),
        }
        
    case "shadowsocks":
        return &TestConfig{
            Protocol:    "v2ray-shadowsocks",
            Timeout:     15 * time.Second,
            DataSize:    1024,
            Iterations:  1,
            Parameters:  make(map[string]string),
            V2RayConfig: &V2RayConfig{
                Protocol: "shadowsocks",
                Port:     8084,
                Host:     "localhost",
                Method:   "chacha20-ietf-poly1305",
                Password: "test-password-123",
                Network:  "tcp",
            },
            LogConfig: getDefaultLogConfig(),
        }
        
    case "quic":
        return &TestConfig{
            Protocol:   "quic",
            Timeout:    15 * time.Second,
            DataSize:   1024,
            Iterations: 1,
            Parameters: make(map[string]string),
            QUICConfig: &QUICConfig{
                MaxIdleTimeout:                30 * time.Second,
                MaxIncomingStreams:            100,
                MaxIncomingUniStreams:         100,
                KeepAlivePeriod:              15 * time.Second,
                EnableDatagrams:              true,
                InitialStreamReceiveWindow:   512 * 1024,
                MaxStreamReceiveWindow:       2 * 1024 * 1024,
                InitialConnectionReceiveWindow: 1024 * 1024,
                MaxConnectionReceiveWindow:   4 * 1024 * 1024,
                AllowConnectionMigration:     true,
                DisablePathMTUDiscovery:     false,
                Enable0RTT:                  false,
                Versions:                    []uint32{1},
            },
            LogConfig: getDefaultLogConfig(),
        }
        
    default:
        return nil
    }
}

// Helper functions to create configs from credentials
func createObfs4Config(cred ProtocolCredential, host string) (*TestConfig, error) {
    return &TestConfig{
        Protocol:    "obfs4",
        Timeout:     10 * time.Second,
        DataSize:    1024,
        Iterations:  1,
        Parameters:  make(map[string]string),
        Obfs4Config: &Obfs4Config{
            Certificate: cred.Credentials["certificate"],
            IATMode:     0,
        },
        LogConfig: getDefaultLogConfig(),
    }, nil
}

func createVLESSConfig(cred ProtocolCredential, host string) (*TestConfig, error) {
    return &TestConfig{
        Protocol:   "v2ray-vless",
        Timeout:    15 * time.Second,
        DataSize:   1024,
        Iterations: 1,
        Parameters: make(map[string]string),
        V2RayConfig: &V2RayConfig{
            Protocol:    "vless",
            UUID:        cred.Credentials["uuid"],
            Port:        cred.Port,
            Host:        host,
            Network:     cred.Credentials["network"],
            Security:    cred.Credentials["security"],
            Flow:        cred.Credentials["flow"],
            Encryption:  cred.Credentials["encryption"],
        },
        LogConfig: getDefaultLogConfig(),
    }, nil
}

func createVMESSConfig(cred ProtocolCredential, host string) (*TestConfig, error) {
    return &TestConfig{
        Protocol:   "v2ray-vmess",
        Timeout:    15 * time.Second,
        DataSize:   1024,
        Iterations: 1,
        Parameters: make(map[string]string),
        V2RayConfig: &V2RayConfig{
            Protocol:    "vmess",
            UUID:        cred.Credentials["uuid"],
            Port:        cred.Port,
            Host:        host,
            Network:     cred.Credentials["network"],
            Path:        cred.Credentials["path"],
            Encryption:  cred.Credentials["encryption"],
            Headers: map[string]string{
                "Host": cred.Credentials["host"],
            },
        },
        LogConfig: getDefaultLogConfig(),
    }, nil
}

func createXTLSConfig(cred ProtocolCredential, host string) (*TestConfig, error) {
    return &TestConfig{
        Protocol:   "v2ray-xtls",
        Timeout:    20 * time.Second,
        DataSize:   1024,
        Iterations: 1,
        Parameters: make(map[string]string),
        V2RayConfig: &V2RayConfig{
            Protocol:   "xtls",
            UUID:       cred.Credentials["uuid"],
            Port:       cred.Port,
            Host:       host,
            Network:    cred.Credentials["network"],
            Security:   cred.Credentials["security"],
            Flow:       cred.Credentials["flow"],
            ServerName: host,
            ALPN:       []string{cred.Credentials["alpn"]},
        },
        LogConfig: getDefaultLogConfig(),
    }, nil
}

func createShadowsocksConfig(cred ProtocolCredential, host string) (*TestConfig, error) {
    return &TestConfig{
        Protocol:   "v2ray-shadowsocks",
        Timeout:    15 * time.Second,
        DataSize:   1024,
        Iterations: 1,
        Parameters: make(map[string]string),
        V2RayConfig: &V2RayConfig{
            Protocol: "shadowsocks",
            Port:     cred.Port,
            Host:     host,
            Method:   cred.Credentials["method"],
            Password: cred.Credentials["password"],
            Network:  "tcp",
        },
        LogConfig: getDefaultLogConfig(),
    }, nil
}

func createQUICConfig(cred ProtocolCredential, host string) (*TestConfig, error) {
    return &TestConfig{
        Protocol:   "quic",
        Timeout:    15 * time.Second,
        DataSize:   1024,
        Iterations: 1,
        Parameters: make(map[string]string),
        QUICConfig: &QUICConfig{
            MaxIdleTimeout:                30 * time.Second,
            MaxIncomingStreams:            100,
            MaxIncomingUniStreams:         100,
            KeepAlivePeriod:              15 * time.Second,
            EnableDatagrams:              true,
            InitialStreamReceiveWindow:   512 * 1024,
            MaxStreamReceiveWindow:       2 * 1024 * 1024,
            InitialConnectionReceiveWindow: 1024 * 1024,
            MaxConnectionReceiveWindow:   4 * 1024 * 1024,
            AllowConnectionMigration:     true,
            DisablePathMTUDiscovery:     false,
            Enable0RTT:                  false,
            Versions:                    []uint32{1},
        },
        LogConfig: getDefaultLogConfig(),
    }, nil
}

// Save configuration to file
func SaveConfig(config *TestConfig, filename string) error {
    data, err := yaml.Marshal(config)
    if err != nil {
        return fmt.Errorf("failed to marshal config: %v", err)
    }
    
    return ioutil.WriteFile(filename, data, 0644)
}

// Get default log configuration
func getDefaultLogConfig() *LogConfig {
    return &LogConfig{
        EnableDetailedLogging: true,
        LogToTerminal:        true,
        LogRawData:           true,
        LogKeys:              true,
        LogLevel:             "DEBUG",
    }
}

// Generate test data with recognizable pattern
func GenerateTestData(size int, header string) []byte {
    data := make([]byte, size)
    copy(data, header)
    
    // Fill with pattern that can be easily identified
    for i := len(header); i < size; i++ {
        data[i] = byte(i % 256)
    }
    
    return data
}