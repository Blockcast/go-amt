//go:build linux && !android

package amt

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// netnsChildEnv marks the re-executed test binary running inside its own user
// and network namespace.
const netnsChildEnv = "GOAMT_NETNS_CHILD"

// TestListenMulticastUDP4SharedPortOverVeth pins BLO-47285. Five listeners
// share one port, each joined to its own group, as a receiver serving DS 74
// next to the four groups of an operator's live service does. Every packet sent
// to group 0 must reach listener 0 and no other.
//
// It runs over a veth pair, not lo: UDP early demux runs only on a packet
// without a route attached, and a looped-back packet keeps its route, so on lo
// the bug cannot show. With IP_MULTICAST_ALL cleared, early demux finds the one
// socket whose filter admits the group and marks it prefetched; since Linux
// 6.5 inet_steal_sock then re-selects among that socket's SO_REUSEPORT group by
// hash, and every socket bound to 0.0.0.0 on the port is in it. One hash-picked
// socket got every packet, usually not the one that joined the group. Binding
// each socket to its group splits the reuseport groups, so the re-selection can
// only pick a socket bound to the same group.
func TestListenMulticastUDP4SharedPortOverVeth(t *testing.T) {
	if os.Getenv(netnsChildEnv) == "" {
		runInNetns(t, "^TestListenMulticastUDP4SharedPortOverVeth$")
		return
	}
	peer := vethPair(t)

	const port, sent = 41024, 200
	var listeners []*ipv4.PacketConn
	for i := range 5 {
		g := &net.UDPAddr{IP: net.IPv4(239, 255, 47, byte(10+i)), Port: port}
		c, err := ListenMulticastUDP4("udp4", peer, netip.Addr{}, g, nil, false, 1, 0, 0, 0)
		if err != nil {
			t.Fatalf("listen %v: %v", g, err)
		}
		defer c.Close()
		listeners = append(listeners, c)
	}

	sendRawUDP4(t, "veth0", net.IPv4(239, 255, 47, 10), port, sent)

	for i, c := range listeners {
		got := drain(t, c)
		want := 0
		if i == 0 {
			want = sent
		}
		if got != want {
			t.Errorf("listener %d (group 239.255.47.%d) read %d packets, want %d", i, 10+i, got, want)
		}
	}

	// The pre-fix shape as a control, logged rather than asserted, since its
	// outcome is the kernel's: bound to 0.0.0.0, a 6.9+ kernel hands group 0
	// to one hash-picked socket with IP_MULTICAST_ALL=0, and clones it to all
	// five with IP_MULTICAST_ALL=1. Before 6.9 both deliver to socket 0 only
	// or to all five, respectively.
	var uts unix.Utsname
	_ = unix.Uname(&uts)
	for _, all := range []int{0, 1} {
		var fds []int
		for i := range 5 {
			fds = append(fds, anyAddrListener(t, peer, net.IPv4(239, 255, 47, byte(10+i)), port+1+all, all))
		}
		sendRawUDP4(t, "veth0", net.IPv4(239, 255, 47, 10), port+1+all, sent)
		time.Sleep(300 * time.Millisecond)
		var got []int
		for _, fd := range fds {
			n := 0
			for buf := make([]byte, 2048); ; n++ {
				if _, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT); err != nil {
					break
				}
			}
			got = append(got, n)
			unix.Close(fd)
		}
		t.Logf("control, kernel %s, bound 0.0.0.0, IP_MULTICAST_ALL=%d: per-socket packets %v (socket 0 joined the group)",
			unix.ByteSliceToString(uts.Release[:]), all, got)
	}
}

// anyAddrListener is ListenMulticastUDP4 before BLO-47285: SO_REUSEPORT,
// bound to 0.0.0.0, IP_MULTICAST_ALL as given, joined to group on ifi.
func anyAddrListener(t *testing.T, ifi *net.Interface, group net.IP, port, multicastAll int) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	mreq := &unix.IPMreqn{Ifindex: int32(ifi.Index)}
	copy(mreq.Multiaddr[:], group.To4())
	for _, err := range []error{
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1),
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1),
		unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_ALL, multicastAll),
		unix.Bind(fd, &unix.SockaddrInet4{Port: port}),
		unix.SetsockoptIPMreqn(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, mreq),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	return fd
}

// runInNetns re-executes the test binary for one test inside a new user and
// network namespace, where it may create a veth pair. It skips where the
// sandbox forbids unprivileged user namespaces.
func runInNetns(t *testing.T, run string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run="+run, "-test.v")
	cmd.Env = append(os.Environ(), netnsChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Skipf("cannot enter a user+network namespace: %v", err)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skipf("child skipped:\n%s", out)
	}
	if err != nil || !strings.Contains(string(out), "--- PASS") {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	t.Logf("child:\n%s", out)
}

// vethPair creates veth0/veth1, brings both up and gives veth1 10.47.0.2/24
// so the reverse-path check accepts a source on that subnet. It returns veth1,
// the receive side.
func vethPair(t *testing.T) *net.Interface {
	t.Helper()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Skipf("netlink: %v", err)
	}
	defer unix.Close(fd)

	attr := func(typ uint16, data []byte) []byte {
		b := make([]byte, 4, 4+len(data)+3)
		binary.NativeEndian.PutUint16(b[0:], uint16(4+len(data)))
		binary.NativeEndian.PutUint16(b[2:], typ)
		b = append(b, data...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	ifinfo := make([]byte, unix.SizeofIfInfomsg) // AF_UNSPEC, no index, no flags
	peer := append(append([]byte{}, ifinfo...), attr(unix.IFLA_IFNAME, []byte("veth1\x00"))...)
	linkinfo := append(attr(unix.IFLA_INFO_KIND, []byte("veth")),
		attr(unix.IFLA_INFO_DATA, attr(1 /* VETH_INFO_PEER */, peer))...)
	body := append(append(ifinfo, attr(unix.IFLA_IFNAME, []byte("veth0\x00"))...),
		attr(unix.IFLA_LINKINFO, linkinfo)...)

	msg := make([]byte, unix.SizeofNlMsghdr, unix.SizeofNlMsghdr+len(body))
	binary.NativeEndian.PutUint32(msg[0:], uint32(unix.SizeofNlMsghdr+len(body)))
	binary.NativeEndian.PutUint16(msg[4:], unix.RTM_NEWLINK)
	binary.NativeEndian.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	binary.NativeEndian.PutUint32(msg[8:], 1)
	msg = append(msg, body...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Skipf("netlink send: %v", err)
	}
	ack := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, ack, 0)
	if err != nil || n < unix.SizeofNlMsghdr+4 {
		t.Skipf("netlink ack: %v (%d bytes)", err, n)
	}
	if errno := int32(binary.NativeEndian.Uint32(ack[unix.SizeofNlMsghdr:])); errno != 0 {
		t.Skipf("create veth: %v", syscall.Errno(-errno))
	}

	ioc, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ioc)
	for _, name := range []string{"veth1", "veth0"} {
		ifr, err := unix.NewIfreq(name)
		if err != nil {
			t.Fatal(err)
		}
		if name == "veth1" {
			if err := ifr.SetInet4Addr(net.IPv4(10, 47, 0, 2).To4()); err != nil {
				t.Fatal(err)
			}
			if err := unix.IoctlIfreq(ioc, unix.SIOCSIFADDR, ifr); err != nil {
				t.Fatalf("address %s: %v", name, err)
			}
		}
		if err := unix.IoctlIfreq(ioc, unix.SIOCGIFFLAGS, ifr); err != nil {
			t.Fatal(err)
		}
		ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
		if err := unix.IoctlIfreq(ioc, unix.SIOCSIFFLAGS, ifr); err != nil {
			t.Fatalf("up %s: %v", name, err)
		}
	}
	ifi, err := net.InterfaceByName("veth1")
	if err != nil {
		t.Fatal(err)
	}
	return ifi
}

// sendRawUDP4 writes count UDP datagrams to group:port out of the named link
// with an AF_PACKET socket and a source of 10.47.0.9. A source address that
// is local to the namespace would be dropped on veth1 as martian, and raw
// sends need no route.
func sendRawUDP4(t *testing.T, link string, group net.IP, port, count int) {
	t.Helper()
	ifi, err := net.InterfaceByName(link)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_IP)))
	if err != nil {
		t.Skipf("AF_PACKET: %v", err)
	}
	defer unix.Close(fd)
	g := group.To4()
	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  ifi.Index,
		Halen:    6,
		Addr:     [8]byte{0x01, 0x00, 0x5e, g[1] & 0x7f, g[2], g[3]},
	}
	const payload = 8
	pkt := make([]byte, 20+8+payload)
	pkt[0], pkt[8], pkt[9] = 0x45, 1, unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	copy(pkt[12:16], net.IPv4(10, 47, 0, 9).To4())
	copy(pkt[16:20], g)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	binary.BigEndian.PutUint16(pkt[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(pkt[20:], 40000)
	binary.BigEndian.PutUint16(pkt[22:], uint16(port))
	binary.BigEndian.PutUint16(pkt[24:], 8+payload) // UDP checksum 0: none
	for range count {
		if err := unix.Sendto(fd, pkt, 0, sa); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// drain counts the datagrams c holds, waiting briefly for stragglers.
func drain(t *testing.T, c *ipv4.PacketConn) int {
	t.Helper()
	buf := make([]byte, 2048)
	n := 0
	for {
		if err := c.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := c.ReadFrom(buf); err != nil {
			return n
		}
		n++
	}
}
