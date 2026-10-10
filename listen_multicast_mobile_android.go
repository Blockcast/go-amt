//go:build android

package amt

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"golang.org/x/sys/unix"
)

// clearMulticastAll keeps a mobile listener to the groups it joins. Android's
// kernel is Linux, which defaults IP_MULTICAST_ALL to 1, so a socket bound to
// the port, as Go's wildcard bind for a group address is, would also receive
// every group another socket on the device joined there. See
// ListenMulticastUDP4 in listen_multicast_linux.go, including the warning when
// the kernel lacks the option.
func clearMulticastAll(fd int, gaddr *net.UDPAddr) error {
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_ALL, 0); err != nil {
		if !errors.Is(err, unix.ENOPROTOOPT) {
			return fmt.Errorf("could not clear IP_MULTICAST_ALL: %w", err)
		}
		slog.Warn("amt: IP_MULTICAST_ALL unsupported, host-wide delivery stays on: this socket also receives groups other sockets joined on its port",
			"group", gaddr.IP, "port", gaddr.Port)
	}
	return nil
}
