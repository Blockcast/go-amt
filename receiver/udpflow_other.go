//go:build !linux

package receiver

import (
	"fmt"
	"net"
)

func bindToInterface(_ int, name string) error {
	return fmt.Errorf("binding UDP feed to interface %q is only supported on Linux", name)
}

func setUDPFlowReceiveBuffer(conn *net.UDPConn, want int) (int, bool, error) {
	if err := conn.SetReadBuffer(want); err != nil {
		return 0, false, err
	}
	return want, false, nil
}
