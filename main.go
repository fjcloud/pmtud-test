package main

import (
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
        // Get TCP_MAXSEG using syscall
        mss, _ = getTCPMaxSegSize(fd)
    })
    
    return mss
}

func connectionHandler(w http.ResponseWriter, r *http.Request) {
    // Get the underlying TCP connection
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

    tcpConn, ok := conn.(*net.TCPConn)
    if !ok {
        fmt.Fprintf(w, "Not a TCP connection")
        return
    }

    // Get MSS information
    mss := getMSSInfo(tcpConn)
    
    // Get connection details
    localAddr := tcpConn.LocalAddr().(*net.TCPAddr)
    remoteAddr := tcpConn.RemoteAddr().(*net.TCPAddr)

    // Prepare response
    response := fmt.Sprintf(`HTTP/1.1 200 OK
Content-Type: text/plain

Connection Information:
Local Address: %s
Remote Address: %s
MSS: %d bytes

Additional Network Information:
Host: %s
Client IP: %s
Headers: %v
`, 
        localAddr.String(),
        remoteAddr.String(),
        mss,
        r.Host,
        strings.Split(r.RemoteAddr, ":")[0],
        r.Header)

    conn.Write([]byte(response))
}

func main() {
    // Get port from environment variable or use default
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    http.HandleFunc("/", connectionHandler)
    
    log.Printf("Starting server on port %s", port)
    if err := http.ListenAndServe(":"+port, nil); err != nil {
        log.Fatal(err)
    }
}
