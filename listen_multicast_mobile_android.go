//go:build android

package amt

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// clearMulticastAll keeps a mobile listener to the groups it joins. Android's
// kernel is Linux, which defaults IP_MULTICAST_ALL to 1, so a socket bound to
// the port, as Go's wildcard bind for a group address is, would also receive
// every group another socket on the device joined there. See
// ListenMulticastUDP4 in listen_multicast_linux.go.
func clearMulticastAll(fd int) error {
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_ALL, 0); err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
		return fmt.Errorf("could not clear IP_MULTICAST_ALL: %w", err)
	}
	return nil
}
