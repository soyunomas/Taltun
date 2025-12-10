package netutil

import (
    "encoding/binary"
    "net"
)

func IPToUint32(ip net.IP) uint32 {
    v4 := ip.To4()
    if v4 == nil {
        return 0
    }
    return binary.BigEndian.Uint32(v4)
}

func Uint32ToIP(nn uint32) net.IP {
    ip := make(net.IP, 4)
    binary.BigEndian.PutUint32(ip, nn)
    return ip
}

func ExtractDstIP(packet []byte) uint32 {
    if len(packet) < 20 {
        return 0
    }
    if (packet[0] >> 4) != 4 {
        return 0
    }
    return binary.BigEndian.Uint32(packet[16:20])
}
