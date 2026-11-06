//go:build !(linux && !android) && !(darwin && !ios)

package amt

import (
	"fmt"

	"golang.org/x/net/ipv6"
)

// The signature must track managed_conn_native6.go's, for the reason
// managed_conn_non_native.go gives for its own.
func (mc *ManagedConn) dialNativeMulticast6(plan probePlan) (*ipv6.PacketConn, *pendingPacket, error) {
	return nil, nil, fmt.Errorf("native IPv6 multicast is not supported on this platform")
}
