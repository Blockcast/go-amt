//go:build ((!cgo || purego) && !android && !ios) || js || wasm

package amt

import (
	"errors"
	"net"
	"testing"
)

// TestWriteSegmentsStubWrapsTheSentinel pins the build-variant half of the
// WriteSegments contract, which the gso_linux_test.go refusal tests structurally
// cannot reach: they are tagged to conn.go's selection, so the stub variants are
// deselected wherever they run.
//
// The contract WriteSegments documents is that an error wrapping
// ErrSegmentsUnsupported means "nothing was written, use WriteBatch or WriteTo
// instead". Capability detection through that sentinel is the entire published
// interface, so a variant returning a bare error is not a cosmetic difference --
// a caller doing exactly what the doc says gets errors.Is false and surfaces a
// hard error rather than selecting the fallback.
//
// The build tag here is copied from conn_nocgo.go deliberately. It must track
// that file, not the lanes that happen to run today: the point is that whichever
// build selects the stub also selects this assertion.
func TestWriteSegmentsStubWrapsTheSentinel(t *testing.T) {
	mc := &MulticastConn{}
	dst := &net.UDPAddr{IP: net.IPv4(232, 254, 0, 10), Port: 1024}

	n, err := mc.WriteSegments(make([]byte, 400), 200, nil, dst)
	if err == nil {
		t.Fatal("stub WriteSegments returned no error, but this build has no send path")
	}
	if !errors.Is(err, ErrSegmentsUnsupported) {
		t.Fatalf("error %v does not wrap ErrSegmentsUnsupported, so a caller "+
			"selecting its fallback with errors.Is would surface a hard error "+
			"instead; conn_mobile.go and gso_other.go both wrap it", err)
	}
	if n != 0 {
		t.Fatalf("declined send reported %d bytes written, want 0", n)
	}
}
