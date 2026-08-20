//go:build !linux && !darwin

package amt

import (
	"fmt"

	"golang.org/x/net/ipv4"
)

func (mc *ManagedConn) dialNativeMulticast(plan probePlan) (*ipv4.PacketConn, error) {
	return nil, fmt.Errorf("native multicast is not supported on this platform")
}
