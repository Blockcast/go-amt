//go:build !linux && !darwin

package amt

// The portable UDP implementation has no integer socket descriptor to tune.
func SetForcedReceiveBuffer(fd int, bytes int) error { return nil }

func SetForcedSendBuffer(fd int, bytes int) error { return nil }
