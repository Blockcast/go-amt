//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer collects log output written concurrently by Open and by the
// keepalive goroutine Open starts.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// captureLogs points the default logger at a buffer for the duration of a test.
func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	out := &syncBuffer{}
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(restore) })
	return out
}

// A handshake attempt, and its failure, must be visible in the log and must
// name the relay they concern.
//
// Regression: Gateway.Open had no log output whatsoever. On 2026-08-18 a
// production receiver pointed at an unreachable relay sat wedged inside Open
// for hours while the pod stayed 1/1 Running with 0 restarts and no error in
// any log — tcpdump was the only way to discover AMT was even being attempted.
// Bounding the handshake (#29) makes that hang terminate, but without these
// lines the resulting failure is still anonymous: nothing says which relay was
// tried, or that AMT was the thing that failed. See BLO-28641.
func TestGatewayOpenLogsTheRelayItIsAttempting(t *testing.T) {
	out := captureLogs(t)

	// A bound socket that accepts the discovery datagram and never replies, so
	// the failure is the missing advertisement rather than an ICMP error or a
	// routing quirk.
	silent, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind silent relay: %v", err)
	}
	defer silent.Close()

	relay := silent.LocalAddr().(*net.UDPAddr)
	gw := &Gateway{
		RelayAddr:  relay,
		GroupAddr:  net.ParseIP("232.0.0.1"),
		SourceAddr: net.ParseIP("192.0.2.1"),
		MTU:        1500,
		Timeout:    500 * time.Millisecond,
	}

	if err := gw.Open(); err == nil {
		t.Fatal("Open succeeded against a relay that never answered")
	}

	logged := out.String()
	for _, want := range []string{
		// The attempt is announced before Open blocks, so a wedged handshake is
		// distinguishable from never having reached AMT at all.
		"starting relay handshake",
		// The failure is reported by Open itself rather than only by its caller.
		"relay handshake failed",
		// Both lines name the relay, so an operator can tell which endpoint is
		// unreachable without reaching for tcpdump.
		relay.String(),
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("log output is missing %q; an operator cannot tell that AMT was attempted or why it failed.\ngot:\n%s", want, logged)
		}
	}
}

// A gateway with no relay configured must still log rather than panic on the
// nil address, since that path is reached exactly when configuration is wrong.
func TestGatewayOpenLogsWithoutARelayAddress(t *testing.T) {
	out := captureLogs(t)

	gw := &Gateway{
		GroupAddr: net.ParseIP("232.0.0.1"),
		MTU:       1500,
		Timeout:   250 * time.Millisecond,
	}

	if err := gw.Open(); err == nil {
		t.Fatal("Open succeeded with no relay address configured")
	}

	if logged := out.String(); !strings.Contains(logged, "relay handshake failed") {
		t.Errorf("a gateway with no relay address failed without saying so.\ngot:\n%s", logged)
	}
}
