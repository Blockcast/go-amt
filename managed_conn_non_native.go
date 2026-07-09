//go:build !linux && !darwin

package amt

import "fmt"

func (mc *ManagedConn) tryNativeMulticast() error {
	return fmt.Errorf("native multicast is not supported on this platform")
}
