package txfeed

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	raw := legacyTx.build()
	for _, f := range []Frame{
		{Vote: true, Slot: 439000406, BatchStart: 544, Index: 7, ShredTs: 1785000000000000, Tx: raw},
		{Slot: 1<<64 - 1, BatchStart: 1<<32 - 1, Index: 1<<16 - 1, ShredTs: 1<<64 - 1, Tx: raw[:1]},
	} {
		b := AppendFrame([]byte("prefix"), f)[len("prefix"):]
		if len(b) != frameHeaderSize+len(f.Tx) || b[0] != 1 {
			t.Fatalf("AppendFrame wrote %d bytes, version %d", len(b), b[0])
		}
		got, err := ParseFrame(b)
		if err != nil || got.Vote != f.Vote || got.Slot != f.Slot || got.BatchStart != f.BatchStart ||
			got.Index != f.Index || got.ShredTs != f.ShredTs || !bytes.Equal(got.Tx, f.Tx) {
			t.Errorf("ParseFrame(AppendFrame(%+v)) = %+v, %v", f, got, err)
		}
	}

	good := AppendFrame(nil, Frame{Tx: raw})
	for _, b := range [][]byte{good[:frameHeaderSize-1], append([]byte{2}, good[1:]...)} {
		if _, err := ParseFrame(b); err == nil {
			t.Errorf("ParseFrame(%x...) accepted a short frame or an unknown version", b[:min(4, len(b))])
		}
	}
}
