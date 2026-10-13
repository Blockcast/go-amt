package txfeed

import (
	"fmt"
	"net"
	"net/netip"
)

// InterfaceWith returns the interface that holds ip.
func InterfaceWith(ip netip.Addr) (*net.Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifs {
		addrs, err := ifs[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if have, ok := netip.AddrFromSlice(n.IP); ok && have.Unmap() == ip.Unmap() {
					return &ifs[i], nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no interface holds %s", ip)
}
