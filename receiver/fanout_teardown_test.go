package receiver

import (
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

// wedgeFanoutInDeliver parks the fan-out worker inside deliver, holding the
// pre-swap table snapshot, and returns a func that releases it.
//
// This is the wedged socket the boundary wait exists to survive, held open
// deterministically instead of hoped for: the worker is stopped after the table
// load and before any counter is charged, which is exactly the window in which a
// departing target's final bill can come up short.
func wedgeFanoutInDeliver(t *testing.T, fanout *Fanout, packet []byte) (release func()) {
	t.Helper()

	inside := make(chan struct{})
	unblock := make(chan struct{})
	var once sync.Once
	fanout.sendBatch = func(_ *ipv4.PacketConn, messages []ipv4.Message, _ bool) (int, error) {
		once.Do(func() {
			close(inside)
			<-unblock
		})
		return len(messages), nil
	}

	if result := fanout.Enqueue("feed", packet); result != EnqueueAccepted {
		t.Fatalf("enqueue returned %v, want accepted", result)
	}
	select {
	case <-inside:
	case <-time.After(2 * time.Second):
		t.Fatal("worker never entered deliver")
	}
	return sync.OnceFunc(func() { close(unblock) })
}

// A reconcile that cannot certify a departing target's counters must withhold
// the sample, not return a short one labelled final.
//
// This is the boundary-wait fall-through. The wait is bounded so a wedged socket
// cannot deadlock the broker-grant client, but expiry does not license reading
// anyway: the parked packet still holds the pre-swap snapshot and will charge the
// departing target when it finally lands, so a sample read now is short by that
// packet. The caller closes the session on whatever it gets, and a final ledger
// record written short can never be repaired — so the only safe thing to return
// is nothing, plus ErrTeardownPending to say the departure set is incomplete.
func TestReconcileWithholdsADepartureItCannotCertify(t *testing.T) {
	fanout, err := NewUDPFanoutTargets([]Target{
		{ID: "grant-a", Address: "127.0.0.1:20001"},
		{ID: "grant-b", Address: "127.0.0.1:20002"},
	}, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fanout.Close()

	packet := []byte("shred")
	release := wedgeFanoutInDeliver(t, fanout, packet)
	defer release()

	// The worker is wedged holding the pre-swap snapshot, so this reconcile must
	// outlast its own boundary wait and give up.
	removed, err := fanout.ReconcileDestinations([]Target{{ID: "grant-a", Address: "127.0.0.1:20001"}})
	if !errors.Is(err, ErrTeardownPending) {
		t.Fatalf("reconcile returned err %v, want one wrapping ErrTeardownPending", err)
	}
	if len(removed) != 0 {
		t.Fatalf("reconcile returned %+v for a target still being delivered to; a sample read here is short by the in-flight packet and the caller closes the session on it", removed)
	}

	// Withheld, not lost: releasing the packet makes the counters final, and the
	// harvest must then report them INCLUDING that packet's charge.
	release()

	var harvested []DestinationStat
	var remaining int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		harvested, remaining = fanout.HarvestPendingTeardowns()
		if len(harvested) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(harvested) != 1 {
		t.Fatalf("harvest returned %d departures after the packet landed, want 1; a withheld teardown that never surfaces makes ErrTeardownPending a loss rather than a deferral", len(harvested))
	}
	if remaining != 0 {
		t.Errorf("harvest reports %d departures still uncertain, want 0", remaining)
	}
	if harvested[0].TargetID != "grant-b" {
		t.Fatalf("harvest reported %q, want grant-b", harvested[0].TargetID)
	}
	if harvested[0].Packets != 1 || harvested[0].Bytes != uint64(len(packet)) {
		t.Errorf("harvested departure billed %d packets / %d bytes, want 1 / %d; the packet in flight when the wait expired went unbilled",
			harvested[0].Packets, harvested[0].Bytes, len(packet))
	}

	// Idempotent: a settled departure must not be reported twice, or the tail
	// delta is billed twice.
	again, remaining := fanout.HarvestPendingTeardowns()
	if len(again) != 0 || remaining != 0 {
		t.Errorf("second harvest returned %+v (remaining %d), want nothing", again, remaining)
	}
}

// A departure withheld by one reconcile must be reported by the next one, so a
// caller on a grant-poll loop settles the ledger without having to know the
// off-cycle recovery path exists.
func TestNextReconcileReportsAWithheldDeparture(t *testing.T) {
	fanout, err := NewUDPFanoutTargets([]Target{
		{ID: "grant-a", Address: "127.0.0.1:20001"},
		{ID: "grant-b", Address: "127.0.0.1:20002"},
	}, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fanout.Close()

	packet := []byte("shred")
	release := wedgeFanoutInDeliver(t, fanout, packet)
	defer release()

	if _, err := fanout.ReconcileDestinations([]Target{{ID: "grant-a", Address: "127.0.0.1:20001"}}); !errors.Is(err, ErrTeardownPending) {
		t.Fatalf("first reconcile returned err %v, want one wrapping ErrTeardownPending", err)
	}
	release()

	// A later poll of an unchanged grant table removes nobody new, so whatever
	// it returns is the settled backlog.
	var removed []DestinationStat
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		removed, err = fanout.ReconcileDestinations([]Target{{ID: "grant-a", Address: "127.0.0.1:20001"}})
		if err == nil && len(removed) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if len(removed) != 1 || removed[0].TargetID != "grant-b" {
		t.Fatalf("second reconcile returned %+v, want the withheld grant-b departure", removed)
	}
	if removed[0].Packets != 1 || removed[0].Bytes != uint64(len(packet)) {
		t.Errorf("carried-over departure billed %d packets / %d bytes, want 1 / %d",
			removed[0].Packets, removed[0].Bytes, len(packet))
	}
}

// The quiesced path must not pay the deferral. A reconcile with no packet in
// flight has nothing to wait for, so it reports the departure inline with a nil
// error rather than parking it — otherwise every ordinary revocation would need
// a second call to settle.
func TestQuiescedReconcileReportsDeparturesInline(t *testing.T) {
	fanout, err := NewUDPFanoutTargets([]Target{
		{ID: "grant-a", Address: "127.0.0.1:20001"},
		{ID: "grant-b", Address: "127.0.0.1:20002"},
	}, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fanout.Close()

	removed, err := fanout.ReconcileDestinations([]Target{{ID: "grant-a", Address: "127.0.0.1:20001"}})
	if err != nil {
		t.Fatalf("reconcile on an idle fan-out: %v", err)
	}
	if len(removed) != 1 || removed[0].TargetID != "grant-b" {
		t.Fatalf("reconcile returned %+v, want grant-b inline", removed)
	}
	if _, remaining := fanout.HarvestPendingTeardowns(); remaining != 0 {
		t.Errorf("%d departures parked after an idle reconcile, want 0", remaining)
	}
}

// After Close the worker is stopped, so no bracket can still be open and a
// harvest must be able to settle every outstanding departure.
//
// This is the last chance to bill a departed target's tail: whatever is still
// unharvested when the Reporter runs CloseAll gets closed as SHUTDOWN, which is
// both the wrong close reason for a lapsed grant and a lost tail delta.
func TestHarvestAfterCloseSettlesEveryWithheldDeparture(t *testing.T) {
	fanout, err := NewUDPFanoutTargets([]Target{
		{ID: "grant-a", Address: "127.0.0.1:20001"},
		{ID: "grant-b", Address: "127.0.0.1:20002"},
	}, 16, nil)
	if err != nil {
		t.Fatal(err)
	}

	packet := []byte("shred")
	release := wedgeFanoutInDeliver(t, fanout, packet)

	if _, err := fanout.ReconcileDestinations([]Target{{ID: "grant-a", Address: "127.0.0.1:20001"}}); !errors.Is(err, ErrTeardownPending) {
		t.Fatalf("reconcile returned err %v, want one wrapping ErrTeardownPending", err)
	}

	release()
	if err := fanout.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Close waits for the worker, so this needs no retry loop: if the harvest is
	// not complete here it is not complete anywhere.
	removed, remaining := fanout.HarvestPendingTeardowns()
	if remaining != 0 {
		t.Errorf("%d departures still uncertain after Close, want 0 — the worker is stopped, so nothing can charge them", remaining)
	}
	if len(removed) != 1 || removed[0].TargetID != "grant-b" {
		t.Fatalf("harvest after Close returned %+v, want grant-b", removed)
	}
	if removed[0].Packets != 1 || removed[0].Bytes != uint64(len(packet)) {
		t.Errorf("departure billed %d packets / %d bytes after Close, want 1 / %d",
			removed[0].Packets, removed[0].Bytes, len(packet))
	}
}
