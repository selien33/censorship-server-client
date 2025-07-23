package main

import (
    "fmt"
    "io"
    "time"

    "gitlab.com/yawning/obfs4.git/transports"
    "gitlab.com/yawning/obfs4.git/transports/base"
    _ "gitlab.com/yawning/obfs4.git/transports/obfs4"
    pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
    "golang.org/x/net/proxy"
)

func RunObfs4Test(addr string, config *TestConfig) TestResult {
    startTime := time.Now()
    result := TestResult{Protocol: "obfs4", Target: addr}

    LogTestStart("OBFS4", addr)

    if config.Obfs4Config == nil {
        result.Error = "OBFS4 config missing"
        result.Duration = time.Since(startTime)
        return result
    }

    if err := transports.Init(); err != nil {
        result.Error = fmt.Sprintf("transports.Init() failed: %v", err)
        result.Duration = time.Since(startTime)
        return result
    }

    transport := transports.Get("obfs4")
    if transport == nil {
        result.Error = "OBFS4 transport not available"
        result.Duration = time.Since(startTime)
        return result
    }

    factory, err := transport.ClientFactory("")
    if err != nil {
        result.Error = fmt.Sprintf("ClientFactory error: %v", err)
        result.Duration = time.Since(startTime)
        return result
    }

    clientFactory, ok := factory.(base.ClientFactory)
    if !ok {
        result.Error = "Failed to cast to ClientFactory"
        result.Duration = time.Since(startTime)
        return result
    }

    ptArgs := pt.Args{}
    ptArgs.Add("cert", config.Obfs4Config.Certificate)
    ptArgs.Add("iat-mode", fmt.Sprintf("%d", config.Obfs4Config.IATMode))

    // Parse args to get the transport-specific format !!!
    parsedArgs, err := clientFactory.ParseArgs(&ptArgs)
    if err != nil {
        result.Error = fmt.Sprintf("ParseArgs failed: %v", err)
        result.Duration = time.Since(startTime)
        return result
    }

    conn, err := clientFactory.Dial("tcp", addr, proxy.Direct.Dial, parsedArgs)
    if err != nil {
        result.Error = fmt.Sprintf("Dial failed: %v", err)
        result.Duration = time.Since(startTime)
        LogConnection("OBFS4", addr, false, time.Since(startTime), err)
        return result
    }
    defer conn.Close()

    LogConnection("OBFS4", addr, true, time.Since(startTime), nil)

    conn.SetReadDeadline(time.Now().Add(config.Timeout))
    conn.SetWriteDeadline(time.Now().Add(config.Timeout))

    testData := GenerateTestData(config.DataSize, "OBFS4-TEST-DATA-")
    LogRawData("outbound", "original", testData, "Original test data before OBFS4 processing")

    sendStart := time.Now()
    if _, err := conn.Write(testData); err != nil {
        result.Error = fmt.Sprintf("Failed to send data: %v", err)
        result.Duration = time.Since(startTime)
        LogDataTransmission("send", len(testData), false, time.Since(sendStart), err)
        return result
    }

    result.DataSent = len(testData)
    sendTime := time.Since(sendStart)
    LogDataTransmission("send", len(testData), true, sendTime, nil)
    LogRawData("outbound", "obfuscated", testData, "Data as sent over wire with OBFS4 obfuscation")

    receiveStart := time.Now()
    responseData := make([]byte, len(testData))
    if _, err := io.ReadFull(conn, responseData); err != nil {
        result.Error = fmt.Sprintf("Failed to read response: %v", err)
        result.Duration = time.Since(startTime)
        LogDataTransmission("receive", 0, false, time.Since(receiveStart), err)
        return result
    }

    result.DataReceived = len(responseData)
    receiveTime := time.Since(receiveStart)
    LogDataTransmission("receive", len(responseData), true, receiveTime, nil)
    LogRawData("inbound", "deobfuscated", responseData, "Deobfuscated response data after OBFS4 processing")

    matches, differences := verifyEcho(testData, responseData)
    LogEchoVerification(len(testData), len(responseData), matches, differences)

    if !matches {
        result.Error = fmt.Sprintf("Echo data mismatch: %d differences", differences)
    } else {
        result.Success = true
    }

    result.Duration = time.Since(startTime)
    LogTestComplete("OBFS4", result.Success, result.Duration, result.DataSent, result.DataReceived,
        func() error { if result.Error != "" { return fmt.Errorf(result.Error) }; return nil }())

    return result
}

func verifyEcho(sent, received []byte) (bool, int) {
    if len(sent) != len(received) {
        return false, abs(len(sent) - len(received))
    }

    differences := 0
    for i := range sent {
        if sent[i] != received[i] {
            differences++
        }
    }

    return differences == 0, differences
}

func abs(x int) int {
    if x < 0 {
        return -x
    }
    return x
}