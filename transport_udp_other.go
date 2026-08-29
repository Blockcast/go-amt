//go:build !linux && !darwin

package amt

import "net"

// Other targets use the portable UDP API. Timestamp control messages and
// forced kernel buffer sizing are platform-specific and are unavailable here.
func openUDPConn(cfg TransportConfig) (net.PacketConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{})
}
