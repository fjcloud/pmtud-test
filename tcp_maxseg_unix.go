package main

import (
    "syscall"
)

// GetTCPMaxSeg gets the TCP maximum segment size
func GetTCPMaxSeg(fd uintptr) (int, error) {
    return syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
}
