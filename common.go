//go:build !cgo || purego || ios || android || js || wasm

package amt

import (
	m "github.com/blockcast/go-amt/messages"
)

// determineAMTmessageType extracts AMT message type from data.
// This is used by both the legacy Gateway code and the new RelayManager.
func determineAMTmessageType(data []byte) m.MessageType {
	if len(data) == 0 {
		return 0
	}
	return m.MessageType(data[0] & 0x0F)
}
