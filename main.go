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
    RemoteAddr  string `json:"remote_addr"`
    IncomingMSS int    `json:"incoming_mss"`
    TLSVersion string `json:"tls_version"`
    CipherSuite string `json:"cipher_suite"`
}

func getTCPConn(w http.ResponseWriter) (*net.TCPConn, error) {
    if v, ok := w.(interface {
        Hijack() (net.Conn, *bufio.ReadWriter, error)
    }); ok {
        conn, _, err := v.Hijack()
        if err != nil {
            return nil, err
        }
        if tcpConn, ok := conn.(*net.TCPConn); ok {
            return tcpConn, nil
        }
    }
    return nil, fmt.Errorf("not a TCP connection")
}

func getConnMSS(conn *net.TCPConn) int {
    raw, err := conn.SyscallConn()
    if err != nil {
        return 0
    }

    var mss int
    raw.Control(func(fd uintptr) {
        mss, err = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
    })
    return mss
}

func connectionHandler(w http.ResponseWriter, r *http.Request) {
    tlsConn := r.TLS
    var mss int
    
    if listener, ok := w.(http.Flusher); ok {
        listener.Flush()
        if conn := r.Context().Value(http.LocalAddrContextKey).(net.Conn); ok {
            if tcpConn, ok := conn.(*net.TCPConn); ok {
                mss = getConnMSS(tcpConn)
            }
        }
    }

    tlsVersionStr := "Unknown"
    if tlsConn != nil {
        switch tlsConn.Version {
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
        RemoteAddr:  r.RemoteAddr,
        IncomingMSS: mss,
        TLSVersion: tlsVersionStr,
        CipherSuite: tls.CipherSuiteName(tlsConn.CipherSuite),
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(info)
}

func main() {
    port := os.Getenv("PORT")
    if port == "" {
        port = "8443"
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/", connectionHandler)
    
    log.Printf("Starting HTTPS server on port %s", port)
    if err := http.ListenAndServeTLS(":"+port, "/certs/tls.crt", "/certs/tls.key", mux); err != nil {
        log.Fatal(err)
    }
}
