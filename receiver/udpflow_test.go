package receiver

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestOpenUDPFlowSupportsOutboundAuthorizationAndReturnPayload(t *testing.T) {
	server, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	registration := []byte("opaque-broker-grant")
	payload := []byte("solana-shred-fixture")
	serverErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1024)
		if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			serverErr <- err
			return
		}
		n, client, err := server.ReadFromUDP(buffer)
		if err != nil {
			serverErr <- err
			return
		}
		if got := string(buffer[:n]); got != string(registration) {
			serverErr <- &unexpectedDatagramError{got: got, want: string(registration)}
			return
		}
		_, err = server.WriteToUDP(payload, client)
		serverErr <- err
	}()

	flow, err := OpenUDPFlow(context.Background(), UDPFlowConfig{
		BindAddress: netip.MustParseAddrPort("127.0.0.1:0"),
		Remote:      server.LocalAddr().(*net.UDPAddr).AddrPort(),
		RcvBufBytes: 32 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	if _, err := flow.Write(registration); err != nil {
		t.Fatal(err)
	}

	if err := flow.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1024)
	n, err := flow.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != string(payload) {
		t.Fatalf("received payload = %q, want %q", got, payload)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if got := flow.LocalAddr().(*net.UDPAddr).AddrPort().Addr(); !got.IsLoopback() {
		t.Fatalf("flow local address = %s, want loopback bind", got)
	}
}

func TestOpenUDPFlowValidatesBeforeOpeningSocket(t *testing.T) {
	valid := UDPFlowConfig{
		BindAddress: netip.MustParseAddrPort("0.0.0.0:0"),
		Remote:      netip.MustParseAddrPort("127.0.0.1:9000"),
		RcvBufBytes: 1,
	}
	tests := []struct {
		name    string
		change  func(*UDPFlowConfig)
		wantErr string
	}{
		{name: "invalid bind", change: func(c *UDPFlowConfig) { c.BindAddress = netip.AddrPort{} }, wantErr: "bind address"},
		{name: "multicast bind", change: func(c *UDPFlowConfig) { c.BindAddress = netip.MustParseAddrPort("239.1.1.1:0") }, wantErr: "bind address"},
		{name: "zero remote port", change: func(c *UDPFlowConfig) { c.Remote = netip.MustParseAddrPort("127.0.0.1:0") }, wantErr: "remote"},
		{name: "multicast remote", change: func(c *UDPFlowConfig) { c.Remote = netip.MustParseAddrPort("239.1.1.1:9000") }, wantErr: "remote"},
		{name: "invalid receive buffer", change: func(c *UDPFlowConfig) { c.RcvBufBytes = 0 }, wantErr: "receive buffer"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			flow, err := OpenUDPFlow(context.Background(), config)
			if flow != nil {
				flow.Close()
				t.Fatal("OpenUDPFlow() returned a socket for invalid configuration")
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("OpenUDPFlow() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestOpenUDPFlowRejectsUnknownInterface(t *testing.T) {
	flow, err := OpenUDPFlow(context.Background(), UDPFlowConfig{
		BindAddress: netip.MustParseAddrPort("0.0.0.0:0"),
		Remote:      netip.MustParseAddrPort("127.0.0.1:9000"),
		Interface:   "bcast-interface-that-does-not-exist",
		RcvBufBytes: 1,
	})
	if flow != nil {
		flow.Close()
		t.Fatal("OpenUDPFlow() returned a socket for an unknown interface")
	}
	if err == nil {
		t.Fatal("OpenUDPFlow() succeeded with an unknown interface")
	}
}

type unexpectedDatagramError struct {
	got  string
	want string
}

func (e *unexpectedDatagramError) Error() string {
	return "registration datagram = " + e.got + ", want " + e.want
}
