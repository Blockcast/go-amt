//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"net"
	"testing"
	"time"
)

// BLO-44822: the Rust handle must not be freed while the keepalive goroutine
// can still call into it. conn.go runs abortOpen on a gateway whose Open has
// already succeeded when the MulticastConn was closed during Open, and by then
// the keepalive goroutine is running. Signalling it is not enough; the free has
// to wait for it to return.
//
// The race detector cannot see this window: the goroutine's last handle access
// and the free are ordered through the UDP socket (internal/poll's ioSync), so
// -race stays silent. The hook below asserts the ordering directly, at the
// instant of the free. Reverting stopKeepalive to a bare flag store fails it,
// because the goroutine is then still asleep in its 100ms interval.
func TestTeardownJoinsTheKeepaliveBeforeFreeingTheHandle(t *testing.T) {
	for _, tc := range []struct {
		name     string
		teardown func(*Gateway)
	}{
		{"abortOpen", func(g *Gateway) { g.abortOpen() }},
		{"Close", func(g *Gateway) { _ = g.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// QQIC 0x01: a 100ms keepalive, so the goroutine is mid-loop at
			// teardown rather than in a 10s first sleep.
			fr := newFakeRelay(t, withQueryIntervalCode(0x01))
			addr := fr.Addr()
			gw := &Gateway{
				RelayAddr:  &addr,
				GroupAddr:  net.ParseIP("232.0.0.1"),
				SourceAddr: net.ParseIP("192.0.2.1"),
				MTU:        1500,
				Timeout:    5 * time.Second,
			}
			if err := gw.Open(); err != nil {
				t.Fatalf("Open: %v", err)
			}
			// Wait for one keepalive pass so the goroutine is provably live.
			at := fr.discoveries.Load()
			deadline := time.Now().Add(2 * time.Second)
			for fr.discoveries.Load() == at && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if fr.discoveries.Load() == at {
				t.Fatal("keepalive never ran; the test would prove nothing")
			}

			done := gw.keepaliveDone
			freed := false
			beforeHandleFree = func(g *Gateway) {
				if g != gw {
					return
				}
				freed = true
				select {
				case <-done:
				default:
					t.Error("Rust handle freed while the keepalive goroutine is still running")
				}
			}
			t.Cleanup(func() { beforeHandleFree = nil })

			tc.teardown(gw)
			if !freed {
				t.Fatal("teardown never freed the handle")
			}
		})
	}
}
