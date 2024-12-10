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

func getMSS(conn *net.TCPConn) int {
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
    return mss
}

func connectionHandler(w http.ResponseWriter, r *http.Request) {
    var incomingMSS int

    // Try to get the underlying TCP connection
    hj, ok := w.(http.Hijacker)
    if ok {
        conn, _, err := hj.Hijack()
        if err == nil {
            if tcpConn, ok := conn.(*net.TCPConn); ok {
                incomingMSS = getMSS(tcpConn)
                // Don't close the connection here as we need it for the response
            }
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

    // Log for debugging
    log.Printf("Connection from %s, MSS: %d", r.RemoteAddr, incomingMSS)

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

    server := &http.Server{
        Addr: ":" + port,
        Handler: http.HandlerFunc(connectionHandler),
        TLSConfig: &tls.Config{
            MinVersion: tls.VersionTLS12,
        },
    }

    log.Printf("Starting HTTPS server on port %s", port)
    if err := server.ListenAndServeTLS("/certs/tls.crt", "/certs/tls.key"); err != nil {
        log.Fatal(err)
    }
}
