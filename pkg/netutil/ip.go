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

func ExtractSrcIP(packet []byte) uint32 {
	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return 0
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return 0
	}
	return binary.BigEndian.Uint32(packet[12:16])
}

func ExtractDstIP(packet []byte) uint32 {
	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return 0
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return 0
	}
	return binary.BigEndian.Uint32(packet[16:20])
}
