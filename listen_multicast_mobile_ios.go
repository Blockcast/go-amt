//go:build ios

package amt

// clearMulticastAll does nothing on iOS: Darwin delivers multicast only to
// sockets that joined the group.
func clearMulticastAll(int) error { return nil }
