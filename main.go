package main

import (
    "crypto/tls"
    "encoding/json"
    "log"
    "net"
    "net/http"
    "os"
    "syscall"
)

type ConnectionInfo struct {
    RemoteAddr    string `json:"remote_addr"`
    IncomingMSS   int    `json:"incoming_mss"`    // MSS value received from client
    TLSVersion    string `json:"tls_version"`
    CipherSuite   string `json:"cipher_suite"`
}

func getMSS(network string, address string) int {
    // Create a temporary connection to get MSS
    tcpAddr, err := net.ResolveTCPAddr(network, address)
    if err != nil {
        log.Printf("Error resolving address: %v", err)
        return 0
    }

    conn, err := net.DialTCP(network, nil, tcpAddr)
    if err != nil {
        log.Printf("Error dialing: %v", err)
        return 0
    }
    defer conn.Close()

    raw, err := conn.SyscallConn()
    if err != nil {
        log.Printf("Error getting syscall conn: %v", err)
        return 0
    }

    var mss int
    raw.Control(func(fd uintptr) {
        mss, err = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
        if err != nil {
            log.Printf("Error getting TCP_MAXSEG: %v", err)
            mss = 0
        }
    })

    log.Printf("MSS for %s: %d", address, mss)
    return mss
}

func connectionHandler(w http.ResponseWriter, r *http.Request) {
    // Get the remote host without port
    host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        log.Printf("Error splitting host port: %v", err)
        host = r.RemoteAddr
    }

    // Get MSS using a separate connection
    incomingMSS := getMSS("tcp", host+":443")

    // Get TLS version as string
    tlsVersionStr := "Unknown"
    if r.TLS != nil {
        switch r.TLS.Version {
        case tls.VersionTLS10:
            tlsVersionStr = "TLS 1.0"
        case tls.VersionTLS11:
            tlsVersionStr = "TLS 1.1"
        case tls.VersionTLS12:
            tlsVersionStr = "TLS 1.2"
        case tls.VersionTLS13:
            tlsVersionStr = "TLS 1.3"
        }
    }

    info := ConnectionInfo{
        RemoteAddr:    r.RemoteAddr,
        IncomingMSS:   incomingMSS,
        TLSVersion:    tlsVersionStr,
        CipherSuite:   tls.CipherSuiteName(r.TLS.CipherSuite),
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(info)
}

func main() {
    // Enable debug logging
    log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

    port := os.Getenv("PORT")
    if port == "" {
        port = "8443"
    }

    http.HandleFunc("/", connectionHandler)
    
    log.Printf("Starting HTTPS server on port %s", port)
    if err := http.ListenAndServeTLS("/certs/tls.crt", "/certs/tls.key", nil); err != nil {
        log.Fatal(err)
    }
}
