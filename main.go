package main

import (
    "crypto/tls"
    "fmt"
    "log"
    "net"
    "net/http"
    "os"
    "strings"
)

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

func getTLSConnection(conn net.Conn) (*net.TCPConn, error) {
    // Try to get TCP connection from TLS
    if tlsConn, ok := conn.(*tls.Conn); ok {
        if err := tlsConn.Handshake(); err != nil {
            return nil, fmt.Errorf("TLS handshake failed: %v", err)
        }
        if tcpConn, ok := tlsConn.NetConn().(*net.TCPConn); ok {
            return tcpConn, nil
        }
    }
    return nil, fmt.Errorf("not a TLS connection")
}

func connectionHandler(w http.ResponseWriter, r *http.Request) {
    hijacker, ok := w.(http.Hijacker)
    if !ok {
        http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
        return
    }
    
    conn, _, err := hijacker.Hijack()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer conn.Close()

    tcpConn, err := getTLSConnection(conn)
    if err != nil {
        fmt.Fprintf(w, "Error getting TCP connection: %v", err)
        return
    }

    mss := getMSSInfo(tcpConn)
    
    localAddr := tcpConn.LocalAddr().(*net.TCPAddr)
    remoteAddr := tcpConn.RemoteAddr().(*net.TCPAddr)

    response := fmt.Sprintf(`HTTP/1.1 200 OK
Content-Type: text/plain

Connection Information (TLS):
Local Address: %s
Remote Address: %s
MSS: %d bytes

Additional Network Information:
Host: %s
Client IP: %s
TLS Version: %s
Cipher Suite: %s
Headers: %v
`, 
        localAddr.String(),
        remoteAddr.String(),
        mss,
        r.Host,
        strings.Split(r.RemoteAddr, ":")[0],
        r.TLS.Version,
        tls.CipherSuiteName(r.TLS.CipherSuite),
        r.Header)

    conn.Write([]byte(response))
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
