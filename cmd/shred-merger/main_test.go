//go:build linux

package main

import (
	"bytes"
	"testing"
)

func TestDedupKeysOnFECSetAndLocalIndex(t *testing.T) {
	d := newDedup(64)
	for _, step := range []struct {
		name     string
		slot     uint64
		fec, idx uint32
		want     verdict
	}{
		{"first sighting", 100, 0, 5, emit},
		{"the same shred from the other listener", 100, 0, 5, duplicate},
		{"same local index, next FEC set: a different shred", 100, 32, 5, emit},
		{"same coordinates, next slot: a different shred", 101, 0, 5, emit},
		{"slot 0 is never emitted", 0, 0, 5, skip},
	} {
		if got := d.observe(step.slot, step.fec, step.idx); got != step.want {
			t.Errorf("%s: observe = %d, want %d", step.name, got, step.want)
		}
	}
}

func TestDedupDropsShredsOlderThanTheWindow(t *testing.T) {
	d := newDedup(64)
	d.observe(100, 0, 1)
	if got := d.observe(200, 0, 1); got != emit {
		t.Fatalf("slot 200 first sighting: observe = %d, want emit", got)
	}
	if _, kept := d.seen[100]; kept {
		t.Error("slot 100 is outside the 64-slot window but its history was not evicted")
	}
	// Its history is gone, so re-emitting it could repeat a shred the union
	// already carried.
	if got := d.observe(100, 0, 1); got != skip {
		t.Errorf("slot 100 after the window moved past it: observe = %d, want skip", got)
	}
	if got := d.observe(150, 0, 1); got != emit {
		t.Errorf("slot 150 is inside the window: observe = %d, want emit", got)
	}
}

func TestAsV3(t *testing.T) {
	// A version-4 frame: forwarder header, then a 32:32 chained data shred
	// (variant 0x96: chained Merkle data, proof 6).
	v4 := make([]byte, 28+1203)
	v4[0] = 4
	v4[1] = 7 // slot 7
	body := v4[28:]
	for i := range body {
		body[i] = byte(i)
	}
	body[64] = 0x96

	v3, ok := asV3(v4)
	if !ok {
		t.Fatal("asV3 refused a well-formed version-4 frame")
	}
	// The shard runs from after the signature (64) to before the 32-byte
	// root and six 20-byte proof entries.
	if v3[0] != 3 || v3[1] != 7 || !bytes.Equal(v3[28:], body[64:1203-32-6*20]) {
		t.Errorf("asV3(v4) = version %d, slot byte %d, %d-byte body; want 3, 7, %d", v3[0], v3[1], len(v3)-28, 1203-32-6*20-64)
	}

	passthrough := append([]byte{3}, v4[1:28]...)
	if got, ok := asV3(passthrough); !ok || &got[0] != &passthrough[0] {
		t.Error("a version-3 frame must pass through unchanged")
	}
	if _, ok := asV3(append([]byte{5}, v4[1:]...)); ok {
		t.Error("an unknown version must not reach the version-3 group")
	}
}
