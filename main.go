package main

import (
    "crypto/tls"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "net/http"
    "os"
)

type ConnectionInfo struct {
    LocalAddress  string `json:"local_address"`
    RemoteAddress string `json:"remote_address"`
    MSS           int    `json:"mss"`
    TLSVersion    string `json:"tls_version"`
    CipherSuite   string `json:"cipher_suite"`
    Host          string `json:"host"`
    ClientIP      string `json:"client_ip"`
}

func getMSSInfo(conn *net.TCPConn) int {
    sysConn, err := conn.SyscallConn()
    if err != nil {
        return 0
    }

    var mss int
    sysConn.Control(func(fd uintptr) {
        mss, _ = GetTCPMaxSeg(fd)
    })
    
    return mss
}

func getTCPConnFromRequest(r *http.Request) (*net.TCPConn, error) {
    if r.TLS == nil {
        return nil, fmt.Errorf("not a TLS connection")
    }

    // Get the underlying connection
    conn := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
    if tcpConn, ok := conn.(*net.TCPAddr); ok {
        return net.DialTCP("tcp", nil, tcpConn)
    }
    
    return nil, fmt.Errorf("could not get TCP connection")
}

func connectionHandler(w http.ResponseWriter, r *http.Request) {
    tcpConn, err := getTCPConnFromRequest(r)
    if err != nil {
        log.Printf("Error getting TCP connection: %v", err)
        // Continue anyway to show available information
    }

    // Get MSS if we have a TCP connection
    var mss int
    if tcpConn != nil {
        mss = getMSSInfo(tcpConn)
        defer tcpConn.Close()
    }

    // Get TLS version string
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
        LocalAddress:  r.Host,
        RemoteAddress: r.RemoteAddr,
        MSS:          mss,
        TLSVersion:   tlsVersionStr,
        CipherSuite:  tls.CipherSuiteName(r.TLS.CipherSuite),
        Host:         r.Host,
        ClientIP:     r.RemoteAddr,
    }

    // Set headers for CORS and content type
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "GET")

    // Write JSON response
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
