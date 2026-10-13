//go:build !linux

package main

import (
	"errors"
	"net"
	"net/netip"
)

// listenNative stands in for txfeed.ListenSSM, which needs Linux socket
// options. parse requires -relay off Linux, so nothing reaches it.
var listenNative = func(_, _ netip.Addr, _ int, _ netip.Addr, _ int) (*net.UDPConn, error) {
	return nil, errors.New("a native join needs Linux")
}
