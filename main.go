package main

import (
    "crypto/tls"
    "encoding/json"
    "log"
    "net"
    "net/http"
    "os"
)

type ConnectionInfo struct {
    LocalAddress  string `json:"local_address"`
    RemoteAddress string `json:"remote_address"`
    MSS           int    `json:"mss"`
    RequestedMSS  int    `json:"requested_mss,omitempty"`
    MTU          int    `json:"mtu"`
    TLSVersion    string `json:"tls_version"`
    CipherSuite   string `json:"cipher_suite"`
    Host          string `json:"host"`
    ClientIP      string `json:"client_ip"`
}

func getMSSandMTU(conn *net.TCPConn) (int, int) {
    sysConn, err := conn.SyscallConn()
    if err != nil {
        return 0, 0
    }

    var mss, mtu int
    sysConn.Control(func(fd uintptr) {
        // Get MSS
        mss, _ = GetTCPMaxSeg(fd)
        
        // Try to get interface MTU
        if iface, err := net.InterfaceByIndex(0); err == nil {
            mtu = iface.MTU
        }
        
        // Validate MSS
        if mss <= 0 || mss > 65535 {
            // Calculate default MSS based on MTU if available
            if mtu > 0 {
                mss = mtu - 40  // IPv6 header (40 bytes)
            } else {
                mss = 1460      // Default Ethernet MSS
            }
        }
    })
    
    return mss, mtu
}

func getRequestMSS(r *http.Request) int {
    // Try to get client's requested MSS from TCP options
    if tcpConn, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPConn); ok {
        sysConn, err := tcpConn.SyscallConn()
        if err != nil {
            return 0
        }
        var mss int
        sysConn.Control(func(fd uintptr) {
            mss, _ = GetTCPMaxSeg(fd)
        })
        return mss
    }
    return 0
}

func connectionHandler(w http.ResponseWriter, r *http.Request) {
    var mss, mtu int
    var requestedMSS int
    
    // Get connection details
    if tcpConn, err := net.Dial("tcp", r.Host); err == nil {
        mss, mtu = getMSSandMTU(tcpConn.(*net.TCPConn))
        tcpConn.Close()
    }
    
    // Try to get client's requested MSS
    requestedMSS = getRequestMSS(r)

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
        RequestedMSS: requestedMSS,
        MTU:          mtu,
        TLSVersion:   tlsVersionStr,
        CipherSuite:  tls.CipherSuiteName(r.TLS.CipherSuite),
        Host:         r.Host,
        ClientIP:     r.RemoteAddr,
    }

    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "GET")

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
