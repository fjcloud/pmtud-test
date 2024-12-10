package main

import (
    "crypto/tls"
    "encoding/json"
    "log"
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

func getTCPMaxSegSize(fd uintptr) (int, error) {
    return syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
}

func connectionHandler(w http.ResponseWriter, r *http.Request) {
    // Get the TCP connection info
    var incomingMSS int
    if tcpConn, ok := r.Context().Value(http.LocalAddrContextKey).(interface{ SyscallConn() (syscall.RawConn, error) }); ok {
        if sysConn, err := tcpConn.SyscallConn(); err == nil {
            sysConn.Control(func(fd uintptr) {
                incomingMSS, _ = getTCPMaxSegSize(fd)
            })
        }
    }

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
    port := os.Getenv("PORT")
    if port == "" {
        port = "8443"
    }

    http.HandleFunc("/", connectionHandler)
    
    certFile := "/certs/tls.crt"
    keyFile := "/certs/tls.key"

    log.Printf("Starting HTTPS server on port %s", port)
    if err := http.ListenAndServeTLS(":"+port, certFile, keyFile, nil); err != nil {
        log.Fatal(err)
    }
}
