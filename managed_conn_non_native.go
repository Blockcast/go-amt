//go:build !linux && !darwin

package amt

import (
	"fmt"

	"golang.org/x/net/ipv4"
)

// The signature must track managed_conn_native.go's, including the pendingPacket
// return, even though this stub can never produce one: managed_conn.go is
// untagged, so its call site is compiled on every GOOS and binds all three
// results. Letting the two drift is a build break on any platform that selects
// this file, and no CI lane sees it — GOOS=ios satisfies darwin and GOOS=android
// satisfies linux, so the mobile-typecheck lane compiles the native file, not
// this one (Ally review on go-amt#58).
func (mc *ManagedConn) dialNativeMulticast(plan probePlan) (*ipv4.PacketConn, *pendingPacket, error) {
	return nil, nil, fmt.Errorf("native multicast is not supported on this platform")
}
