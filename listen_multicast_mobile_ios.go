//go:build ios

package amt

import "net"

// clearMulticastAll does nothing on iOS: Darwin delivers multicast only to
// sockets that joined the group.
func clearMulticastAll(int, *net.UDPAddr) error { return nil }
