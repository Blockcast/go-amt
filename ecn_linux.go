//go:build linux

package amt

import (
	"encoding/binary"
	"syscall"

	"golang.org/x/sys/unix"
)

// enableRecvTOS asks the kernel for the IPv4 TOS byte on every datagram.
// A refusal is the caller's to report as "unavailable"; it must not fail the open.
func enableRecvTOS(sock int) error {
	return unix.SetsockoptInt(sock, unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
}

// ParseECN returns the ECN field carried in oob (IPv4 IP_TOS or IPv6
// IPV6_TCLASS). ok is false when no such control message is present, which a
// caller must treat as "unavailable", never as Not-ECT.
func ParseECN(oob []byte) (ecn ECN, ok bool) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, false
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_TOS && len(m.Data) >= 1:
			return ECN(m.Data[0] & 0b11), true
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_TCLASS && len(m.Data) >= 4:
			return ECN(binary.NativeEndian.Uint32(m.Data) & 0b11), true
		}
	}
	return 0, false
}
