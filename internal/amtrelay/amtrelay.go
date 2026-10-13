// Package amtrelay parses the AMT relay address that blockcast-shreds' ssm://
// feeds (?relay=) and txfeed-sub (-relay) hand to amt.ManagedConn, so both
// commands accept and refuse the same relays.
package amtrelay

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/blockcast/go-amt/messages"
)

// ErrPortZero reports a relay given as "IP:", whose empty port splits cleanly
// and so skips the default.
var ErrPortZero = errors.New("relay port 0")

// Parse resolves relay, IP[:PORT], to an IPv4 UDP address. The port defaults
// to messages.DefaultPort, 2268.
//
// A relay with no host is an error, not a native-only join: ":2268" resolves
// to a nil IP, and amt.ManagedConn reads a nil RelayAddr.IP as "no relay" and
// drops the AMT fallback in silence.
func Parse(relay string) (net.UDPAddr, error) {
	hostPort := relay
	if _, _, err := net.SplitHostPort(relay); err != nil {
		hostPort = net.JoinHostPort(relay, strconv.Itoa(messages.DefaultPort))
	}
	a, err := net.ResolveUDPAddr("udp4", hostPort)
	if err != nil {
		return net.UDPAddr{}, err
	}
	if len(a.IP) == 0 {
		return net.UDPAddr{}, fmt.Errorf("relay %q has no IP address", relay)
	}
	if a.Port == 0 {
		return net.UDPAddr{}, ErrPortZero
	}
	return *a, nil
}
