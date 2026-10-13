package txfeed

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	raw := legacyTx.build()
	for _, f := range []Frame{
		{Vote: true, Slot: 439000406, BatchStart: 544, Index: 7, ShredTs: 1785000000000000, Tx: raw},
		{Slot: 1<<64 - 1, BatchStart: 1<<32 - 1, Index: 1<<16 - 1, ShredTs: 1<<64 - 1, Tx: raw[:1]},
		{Vote: true, Slot: 439000406, BatchStart: 544, Index: 7, ShredTs: 1785000000000000, Chunk: 1, Chunks: 3, Tx: raw},
		{Slot: 1<<64 - 1, BatchStart: 1<<32 - 1, Index: 1<<16 - 1, ShredTs: 1<<64 - 1, Chunk: 254, Chunks: 255, Tx: raw[:0]},
	} {
		b := AppendFrame([]byte("prefix"), f)[len("prefix"):]
		size, version := frameHeaderSize, byte(1)
		if f.Chunks != 0 {
			size, version = chunkHeaderSize, 2
		}
		if len(b) != size+len(f.Tx) || b[0] != version {
			t.Fatalf("AppendFrame(%+v) wrote %d bytes, version %d; want %d, version %d", f, len(b), b[0], size+len(f.Tx), version)
		}
		got, err := ParseFrame(b)
		if err != nil || got.Vote != f.Vote || got.Slot != f.Slot || got.BatchStart != f.BatchStart ||
			got.Index != f.Index || got.ShredTs != f.ShredTs || got.Chunk != f.Chunk || got.Chunks != f.Chunks ||
			!bytes.Equal(got.Tx, f.Tx) {
			t.Errorf("ParseFrame(AppendFrame(%+v)) = %+v, %v", f, got, err)
		}
	}

	good := AppendFrame(nil, Frame{Tx: raw})
	chunk := AppendFrame(nil, Frame{Chunk: 1, Chunks: 2, Tx: raw})
	for name, b := range map[string][]byte{
		"short":            good[:frameHeaderSize-1],
		"version 0":        append([]byte{0}, good[1:]...),
		"version 3":        append([]byte{3}, good[1:]...),
		"short version 2":  chunk[:chunkHeaderSize-1],
		"chunk 2 of 2":     append(chunk[:24:24], 2, 2),
		"chunk 0 of 0":     append(chunk[:24:24], 0, 0),
		"version 1 as two": append([]byte{2}, good[1:frameHeaderSize]...), // a version-1 header is no version-2 one
	} {
		if f, err := ParseFrame(b); err == nil {
			t.Errorf("ParseFrame(%s) = %+v; want an error", name, f)
		}
	}
}

// fixtureFrames returns the 900 txframes of a receive-only SSM capture of
// shred-txfeed (69.25.95.57) on 2026-10-13 at 22:26Z, as the kernel
// reassembled them: 300 from the jupiter-v6 group 232.0.3.21:5003, then 600
// from the non-vote group 232.0.3.1:5003. Each is u16 LE length, then the
// frame.
func fixtureFrames(t testing.TB) [][]byte {
	t.Helper()
	f, err := os.Open("testdata/txframes-2026-10-13.bin.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	var frames [][]byte
	for len(b) >= 2 {
		n := 2 + int(binary.LittleEndian.Uint16(b))
		frames, b = append(frames, b[2:n]), b[n:]
	}
	if len(frames) != 900 || len(b) != 0 {
		t.Fatalf("fixture: %d frames and %d bytes left over; want 900 and 0", len(frames), len(b))
	}
	return frames
}

// TestDatagramsSplitsTheLiveFeed splits every captured transaction as
// shred-txfeed now does. One that fits leaves as the identical version-1
// frame; one that does not leaves as version-2 chunks, none over
// MaxDatagram, that reassemble into exactly the captured frame.
func TestDatagramsSplitsTheLiveFeed(t *testing.T) {
	t0 := time.Unix(1792000000, 0)
	var fragmented, split int
	for i, b := range fixtureFrames(t) {
		if len(b) > 1500-20-8 {
			fragmented++ // IPv4 fragmented it on a 1500-byte link
		}
		f, err := ParseFrame(b)
		if err != nil || f.Chunks != 0 {
			t.Fatalf("frame %d: %v, %d chunks; the capture is version 1", i, err, f.Chunks)
		}
		dgs := Datagrams(f)
		if len(b) <= MaxDatagram {
			if len(dgs) != 1 || !bytes.Equal(dgs[0], b) {
				t.Errorf("frame %d, %d bytes: %d datagrams; want it as the identical version-1 frame", i, len(b), len(dgs))
			}
			continue
		}
		split++
		r := NewReassembler(time.Second, 1)
		var whole Frame
		var ok bool
		for j, d := range dgs {
			if len(d) > MaxDatagram || d[0] != 2 || (j < len(dgs)-1 && len(d) != MaxDatagram) {
				t.Fatalf("frame %d, %d bytes: datagram %d of %d is %d bytes, version %d; want version 2, all but the last %d bytes",
					i, len(b), j, len(dgs), len(d), d[0], MaxDatagram)
			}
			c, err := ParseFrame(d)
			if err != nil {
				t.Fatalf("frame %d: chunk %d: %v", i, j, err)
			}
			if whole, ok = r.Add(c, t0); ok != (j == len(dgs)-1) {
				t.Fatalf("frame %d: chunk %d of %d: whole = %t", i, j, len(dgs), ok)
			}
		}
		if got := AppendFrame(nil, whole); !bytes.Equal(got, b) {
			t.Errorf("frame %d, %d bytes: reassembled into a different %d-byte frame", i, len(b), len(got))
		}
	}
	// 135 fragmented: 34 of the jupiter-v6 group's 300 and 101 of the
	// non-vote group's 600. MaxDatagram, below 1472, splits 9 more.
	if fragmented != 135 || split != 144 {
		t.Errorf("%d frames over 1472 bytes and %d split; want 135 and 144", fragmented, split)
	}
}

func TestDatagramsBoundary(t *testing.T) {
	for n, want := range map[int]int{
		0: 1, MaxDatagram - frameHeaderSize: 1, // fits: one version-1 frame of exactly MaxDatagram
		MaxDatagram - frameHeaderSize + 1: 2, 2 * maxChunk: 2, 2*maxChunk + 1: 3, MaxTxSize: 3,
	} {
		dgs := Datagrams(Frame{Tx: make([]byte, n)})
		if len(dgs) != want || len(dgs[0]) > MaxDatagram {
			t.Errorf("Datagrams(%d bytes): %d datagrams, the first %d bytes; want %d, none over %d", n, len(dgs), len(dgs[0]), want, MaxDatagram)
		}
	}
	// The chunk count is one byte: more than 255 chunks would wrap it.
	if dgs := Datagrams(Frame{Tx: make([]byte, 255*maxChunk+1)}); dgs != nil {
		t.Errorf("Datagrams over 255 chunks: %d datagrams, want none", len(dgs))
	}
}

// parseFrameV1 is ParseFrame as it was before version 2 (go-amt 4714f61), the
// decoder of every txfeed-sub already deployed.
func parseFrameV1(b []byte) (Frame, error) {
	if len(b) < frameHeaderSize {
		return Frame{}, fmt.Errorf("txframe: %d bytes, shorter than the header", len(b))
	}
	if b[0] != 1 {
		return Frame{}, fmt.Errorf("txframe: unsupported version %d", b[0])
	}
	return Frame{
		Vote:       b[1]&1 != 0,
		Slot:       binary.LittleEndian.Uint64(b[2:10]),
		BatchStart: binary.LittleEndian.Uint32(b[10:14]),
		Index:      binary.LittleEndian.Uint16(b[14:16]),
		ShredTs:    binary.LittleEndian.Uint64(b[16:24]),
		Tx:         b[frameHeaderSize:],
	}, nil
}

// TestV1DecoderRejectsChunks: a subscriber that knows only version 1 still
// decodes every transaction that fits, and rejects each chunk of the others
// by its version, as a malformed frame, instead of mistaking it for a
// transaction.
func TestV1DecoderRejectsChunks(t *testing.T) {
	var whole, chunks int
	for _, b := range fixtureFrames(t) {
		f, _ := ParseFrame(b)
		for _, d := range Datagrams(f) {
			g, err := parseFrameV1(d)
			switch {
			case len(Datagrams(f)) == 1 && (err != nil || !bytes.Equal(g.Tx, f.Tx)):
				t.Fatalf("the version-1 decoder lost a %d-byte transaction that fits: %v", len(f.Tx), err)
			case len(Datagrams(f)) > 1 && (err == nil || !strings.Contains(err.Error(), "unsupported version 2")):
				t.Fatalf("the version-1 decoder took a chunk: %+v, %v", g, err)
			case err == nil:
				whole++
			default:
				chunks++
			}
		}
	}
	if whole != 900-144 || chunks < 2*144 {
		t.Errorf("version-1 decoder: %d whole, %d chunks rejected; want %d and at least %d", whole, chunks, 900-144, 2*144)
	}
}

// chunksOf returns the parsed version-2 chunks of a transaction of n bytes.
func chunksOf(t *testing.T, index uint16, n int) []Frame {
	t.Helper()
	tx := make([]byte, n)
	for i := range tx {
		tx[i] = byte(i*7 + int(index))
	}
	var fs []Frame
	for _, d := range Datagrams(Frame{Slot: 439000406, BatchStart: 544, Index: index, ShredTs: 1785000000000000, Tx: tx}) {
		f, err := ParseFrame(d)
		if err != nil || f.Chunks == 0 {
			t.Fatalf("Datagrams(%d bytes): %+v, %v; want version-2 chunks", n, f, err)
		}
		fs = append(fs, f)
	}
	return fs
}

func TestReassemblerOrderDuplicatesAndLoss(t *testing.T) {
	t0 := time.Unix(1792000000, 0)
	r := NewReassembler(time.Second, 8)

	if f, ok := r.Add(Frame{Slot: 1, Tx: []byte{1}}, t0); !ok || f.Slot != 1 || r.Stats().Chunks != 0 {
		t.Fatal("a version-1 frame must pass through untouched")
	}

	a := chunksOf(t, 1, MaxTxSize) // 3 chunks
	if len(a) != 3 {
		t.Fatalf("%d chunks of a %d-byte transaction; want 3", len(a), MaxTxSize)
	}
	for _, c := range []Frame{a[2], a[0], a[0], a[2]} { // out of order, then each again from another group
		if _, ok := r.Add(c, t0); ok {
			t.Fatal("emitted before every chunk arrived")
		}
	}
	f, ok := r.Add(a[1], t0)
	if want := chunksOf(t, 1, MaxTxSize); !ok || f.Chunks != 0 || len(f.Tx) != MaxTxSize ||
		!bytes.Equal(f.Tx, bytes.Join([][]byte{want[0].Tx, want[1].Tx, want[2].Tx}, nil)) {
		t.Fatalf("Add(the last chunk) = %d bytes, %d chunks, %t; want the whole transaction as a version-1 frame", len(f.Tx), f.Chunks, ok)
	}
	if _, ok := r.Add(a[1], t0); ok { // the same chunk from another group, after reassembly
		t.Fatal("a transaction reassembled twice")
	}

	// Add copies what it keeps: a reader may reuse its buffer.
	c := chunksOf(t, 4, 2000)
	want := bytes.Join([][]byte{c[0].Tx, c[1].Tx}, nil)
	buf := bytes.Clone(c[0].Tx)
	r.Add(Frame{Slot: c[0].Slot, BatchStart: c[0].BatchStart, Index: 4, ShredTs: c[0].ShredTs, Chunks: 2, Tx: buf}, t0)
	clear(buf)
	if f, ok := r.Add(c[1], t0); !ok || !bytes.Equal(f.Tx, want) {
		t.Fatal("the reassembled transaction changed with the caller's buffer")
	}

	b := chunksOf(t, 2, 2000) // 2 chunks; the second never arrives
	if _, ok := r.Add(b[0], t0); ok {
		t.Fatal("emitted half a transaction")
	}
	if s := r.Stats(); s.Chunks != 9 || s.Txs != 2 || s.Dups != 3 || s.Timeouts != 0 || s.Inconsistent != 0 {
		t.Fatalf("stats %+v; want 9 chunks, 2 transactions, 3 dups", s)
	}
	// Past the timeout, the next chunk to arrive expires both: the
	// incomplete one as a timeout, the reassembled one quietly.
	if _, ok := r.Add(chunksOf(t, 3, 2000)[0], t0.Add(2*time.Second)); ok {
		t.Fatal("emitted half a transaction")
	}
	if s := r.Stats(); s.Timeouts != 1 || len(r.pending) != 1 {
		t.Fatalf("stats %+v, %d held; want 1 timeout and only the new transaction held", s, len(r.pending))
	}
}

func TestReassemblerDropsInconsistentChunks(t *testing.T) {
	t0 := time.Unix(1792000000, 0)
	a := chunksOf(t, 1, MaxTxSize)
	with := func(f Frame, edit func(*Frame)) Frame { edit(&f); return f }
	for name, seq := range map[string][]Frame{
		"chunk count":      {a[0], with(a[1], func(f *Frame) { f.Chunks = 2 }), a[1], a[2]},
		"larger count":     {a[0], with(a[1], func(f *Frame) { f.Chunk, f.Chunks = 3, 4 }), a[1], a[2]},
		"vote flag":        {a[0], with(a[1], func(f *Frame) { f.Vote = true }), a[1], a[2]},
		"shred_ts":         {a[0], with(a[1], func(f *Frame) { f.ShredTs++ }), a[1], a[2]},
		"repeat differs":   {a[0], with(a[0], func(f *Frame) { f.Tx = f.Tx[1:] }), a[1], a[2]},
		"over MaxTxSize":   {a[0], a[1], with(a[2], func(f *Frame) { f.Tx = make([]byte, maxChunk) })},
		"chunk past count": {with(a[0], func(f *Frame) { f.Chunk = 3 }), a[0], a[1], a[2]},
	} {
		r := NewReassembler(time.Second, 8)
		for _, c := range seq {
			if f, ok := r.Add(c, t0); ok {
				t.Errorf("%s: emitted %d bytes; want the transaction dropped", name, len(f.Tx))
			}
		}
		if s := r.Stats(); s.Inconsistent != 1 || s.Txs != 0 {
			t.Errorf("%s: stats %+v; want 1 inconsistent, 0 transactions", name, s)
		}
	}
}

func TestReassemblerCapsTransactionsHeld(t *testing.T) {
	t0 := time.Unix(1792000000, 0)
	r := NewReassembler(time.Second, 2)
	x, y, z := chunksOf(t, 1, 2000), chunksOf(t, 2, 2000), chunksOf(t, 3, 2000)
	r.Add(x[0], t0)
	r.Add(y[0], t0)
	if _, ok := r.Add(z[0], t0); ok || r.Stats().Overflow != 1 || len(r.pending) != 2 {
		t.Fatalf("a third transaction past a cap of 2: stats %+v, %d held; want it dropped", r.Stats(), len(r.pending))
	}
	if _, ok := r.Add(x[1], t0); !ok {
		t.Fatal("a transaction held under the cap must still complete")
	}
	// Once the timeout passes, the held ones expire and make room.
	r.Add(z[0], t0.Add(2*time.Second))
	if _, ok := r.Add(z[1], t0.Add(2*time.Second)); !ok || r.Stats().Overflow != 1 {
		t.Fatalf("after the timeout: stats %+v; want room for a new transaction", r.Stats())
	}
}
