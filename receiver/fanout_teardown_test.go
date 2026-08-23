package receiver

import (
	"errors"
	"strings"
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

// A target ID whose departure has not settled must not be re-admitted, because
// one ID would then name two lifecycles that nothing downstream can separate.
//
// This is the re-grant race. pendingTeardown keys the old generation on
// TargetID alone, and a re-admitted ID gets fresh counters — carry is built from
// the live table, which no longer holds the departed entry. So if the swap were
// allowed, the next harvest would hand back the OLD generation's cumulative
// total under an ID that is once again live, and Reporter.CloseRemoved — which
// looks up only TargetID — would close the NEW session on that stale watermark:
// the new generation's traffic billed into the old session, the old total
// re-billed against the advanced watermark, and no session boundary left. A
// refused reconcile costs a retry; a fused one corrupts the ledger for good.
func TestReconcileRefusesToReAdmitAnUnsettledTargetID(t *testing.T) {
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

	// Force the deferral: the worker is wedged holding the pre-swap snapshot,
	// so grant-b's departure cannot be certified and stays parked.
	if _, err := fanout.ReconcileDestinations([]Target{
		{ID: "grant-a", Address: "127.0.0.1:20001"},
	}); !errors.Is(err, ErrTeardownPending) {
		t.Fatalf("removing reconcile returned err %v, want one wrapping ErrTeardownPending", err)
	}

	// Re-grant grant-b while its previous generation is still unsettled.
	removed, err := fanout.ReconcileDestinations([]Target{
		{ID: "grant-a", Address: "127.0.0.1:20001"},
		{ID: "grant-b", Address: "127.0.0.1:20002"},
	})
	if !errors.Is(err, ErrTeardownPending) {
		t.Fatalf("re-admitting an unsettled target ID returned err %v, want one wrapping ErrTeardownPending; "+
			"admitting it fuses the old generation's parked total with a new one counting from zero", err)
	}
	if !strings.Contains(err.Error(), "grant-b") {
		t.Errorf("refusal %q does not name grant-b; the caller cannot tell which grant to retry", err)
	}
	for _, stat := range removed {
		if stat.TargetID == "grant-b" {
			t.Fatalf("refused reconcile still reported grant-b as departed (%+v); "+
				"a caller passing that to CloseRemoved closes a session it was just told it could not re-open", stat)
		}
	}

	// The refusal must not have swapped the table: grant-b is still absent, and
	// grant-a keeps being served throughout.
	served := map[string]bool{}
	for _, entry := range fanout.table.Load().entries {
		served[entry.id] = true
	}
	if !served["grant-a"] {
		t.Error("grant-a stopped being served by a reconcile that was refused; a refusal must change nothing")
	}
	if served["grant-b"] {
		t.Error("grant-b was admitted despite the refusal, so its parked departure now shadows a live entry")
	}

	// Once the packet lands the departure settles, and the same re-grant is
	// accepted — the refusal is a deferral, not a permanent rejection. It
	// arrives carrying the OLD generation's final counters, so the caller can
	// close that session before the new one bills a byte.
	release()

	var accepted []DestinationStat
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		accepted, err = fanout.ReconcileDestinations([]Target{
			{ID: "grant-a", Address: "127.0.0.1:20001"},
			{ID: "grant-b", Address: "127.0.0.1:20002"},
		})
		if err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("re-grant still refused after the packet landed: %v; the refusal has to clear or a flapping grant is stuck forever", err)
	}
	if len(accepted) != 1 || accepted[0].TargetID != "grant-b" {
		t.Fatalf("accepted re-grant reported departures %+v, want exactly grant-b's settled old generation", accepted)
	}
	if accepted[0].Packets != 1 || accepted[0].Bytes != uint64(len(packet)) {
		t.Errorf("settled old generation billed %d packets / %d bytes, want 1 / %d; the tail delta must ride on the close that precedes the re-grant",
			accepted[0].Packets, accepted[0].Bytes, len(packet))
	}

	// The re-admitted generation starts from zero rather than inheriting the
	// old total, which is what makes the two sessions separately billable.
	for _, stat := range fanout.DestinationStats() {
		if stat.TargetID != "grant-b" {
			continue
		}
		if stat.Bytes != 0 || stat.Packets != 0 {
			t.Errorf("re-granted grant-b starts at %d packets / %d bytes, want 0 / 0; inherited totals re-bill the closed session's traffic",
				stat.Packets, stat.Bytes)
		}
	}
}

// A refused re-admission must not consume the departures it happened to find
// settled on its way in.
//
// The refusal is the error most likely to be written off as "nothing happened":
// no swap occurred and the caller is told to retry, so the idiomatic
// `if err != nil { continue }` reads as correct. It is only correct if the
// refusal really did change nothing. When the guard harvested before it
// checked, it did not — the harvest CONSUMES, moving a settled departure out of
// pendingTeardown and making the returned sample the last copy of it. Handed
// back with the refusal and dropped by the retry, that departure's session is
// never closed and its tail is never billed.
//
// The second-order failure is worse than the lost bytes. A consumed departure
// is gone from pendingTeardown, so its ID no longer collides — the very next
// retry re-admits it, and the new generation bills into the old session that
// nothing ever closed. The guard would be the thing that defeated the guard.
//
// So: a refusal returns no stats, and every parked departure it declined to
// harvest is still recoverable afterwards.
func TestRefusedReAdmissionDoesNotConsumeSettledDepartures(t *testing.T) {
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

	// Park grant-b unsettled: the worker holds the pre-swap snapshot, so its
	// counters cannot be certified and it stays in pendingTeardown.
	if _, err := fanout.ReconcileDestinations([]Target{
		{ID: "grant-a", Address: "127.0.0.1:20001"},
	}); !errors.Is(err, ErrTeardownPending) {
		t.Fatalf("removing reconcile returned err %v, want one wrapping ErrTeardownPending", err)
	}

	// Alongside it, a departure that has ALREADY settled and merely has not
	// been harvested yet — the ordinary state whenever one target's delivery
	// bracket closes before another's. seq 0 is even, so isFinal holds for any
	// reading: nothing can charge grant-c again.
	settled := &destCounters{}
	settled.packets.Store(3)
	settled.bytes.Store(96)
	fanout.reconcileMu.Lock()
	fanout.pendingTeardown = append(fanout.pendingTeardown, pendingDeparture{
		entry: destination{id: "grant-c", name: "127.0.0.1:20003", counters: settled},
		seq:   0,
	})
	fanout.reconcileMu.Unlock()

	// Ask for grant-b back while its previous generation is still unsettled.
	// This must be refused — and must not touch grant-c on the way out.
	removed, err := fanout.ReconcileDestinations([]Target{
		{ID: "grant-a", Address: "127.0.0.1:20001"},
		{ID: "grant-b", Address: "127.0.0.1:20002"},
	})
	if !errors.Is(err, ErrTeardownPending) {
		t.Fatalf("re-admitting an unsettled target ID returned err %v, want one wrapping ErrTeardownPending", err)
	}
	if len(removed) != 0 {
		t.Fatalf("refused reconcile returned %d departure(s) %+v, want none; a retry loop that discards the error "+
			"discards these too, and they are the only remaining record of those sessions", len(removed), removed)
	}

	// Discard the refusal exactly as `if err != nil { retry }` would, then prove
	// grant-c is still there to be closed. Before the fix it was consumed by the
	// refusal and this harvest came back empty.
	harvested, remaining := fanout.HarvestPendingTeardowns()
	var grantC *DestinationStat
	for i := range harvested {
		if harvested[i].TargetID == "grant-c" {
			grantC = &harvested[i]
		}
	}
	if grantC == nil {
		t.Fatalf("grant-c is gone after a refused reconcile (harvested %+v, %d remaining); the refusal consumed a "+
			"settled departure, so its session is never closed and its tail never billed", harvested, remaining)
	}
	if grantC.Packets != 3 || grantC.Bytes != 96 {
		t.Errorf("grant-c settled at %d packets / %d bytes, want 3 / 96", grantC.Packets, grantC.Bytes)
	}
	if remaining != 1 {
		t.Errorf("harvest left %d departures outstanding, want 1 (grant-b, still wedged)", remaining)
	}

	// And the refusal it was mixed in with still holds: grant-b was not
	// admitted, so nothing can bill into its unclosed old session.
	for _, entry := range fanout.table.Load().entries {
		if entry.id == "grant-b" {
			t.Fatal("grant-b was admitted by a refused reconcile; the new generation would bill into the old session")
		}
	}
}

// A reconcile the BROKER got wrong must not cost a departure either.
//
// The re-admission guard above is one of two rejections in ReconcileDestinations
// that can fire after the caller has been told nothing happened. The other is
// resolveTargets, which rejects a missing or duplicate target ID and an address
// that will not resolve to IPv4 — none of them exotic, all of them things a
// faulty or half-deployed broker emits on an ordinary reconcile.
//
// The trap is identical and the ordering fix is the same one: the harvest
// CONSUMES, so any rejection that runs after it hands back samples that are the
// last copy of those departures, and `if err != nil { retry }` drops them. The
// retry cannot recover them — they are no longer parked, so neither a later
// reconcile nor HarvestPendingTeardowns will ever produce them again. Their
// sessions stay open and their tails go unbilled.
//
// This is strictly worse than the re-admission case, which at least leaves the
// operator a wedged target to notice. A bad address is transient: the broker
// corrects itself, the next reconcile succeeds, and nothing anywhere records
// that a session was silently dropped on the failed one.
//
// So: every rejection shape returns no stats, and leaves every parked departure
// recoverable.
func TestRejectedTargetSetDoesNotConsumeSettledDepartures(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		targets []Target
		wantErr string
	}{
		{
			name: "duplicate target ID",
			targets: []Target{
				{ID: "grant-a", Address: "127.0.0.1:20001"},
				{ID: "grant-a", Address: "127.0.0.1:20009"},
			},
			wantErr: "appears more than once",
		},
		{
			name: "missing target ID",
			targets: []Target{
				{ID: "grant-a", Address: "127.0.0.1:20001"},
				{ID: "", Address: "127.0.0.1:20009"},
			},
			wantErr: "has no ID",
		},
		{
			name: "address that will not resolve",
			targets: []Target{
				{ID: "grant-a", Address: "127.0.0.1:20001"},
				{ID: "grant-d", Address: "not-a-host:::9"},
			},
			wantErr: "resolve UDP destination",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fanout, err := NewUDPFanoutTargets([]Target{
				{ID: "grant-a", Address: "127.0.0.1:20001"},
			}, 16, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer fanout.Close()

			// A departure that has already settled and merely has not been
			// harvested yet. seq 0 is even, so isFinal holds for any reading:
			// nothing can charge grant-c again, and the next reconcile to get
			// as far as the harvest will hand it back.
			settled := &destCounters{}
			settled.packets.Store(3)
			settled.bytes.Store(96)
			fanout.reconcileMu.Lock()
			fanout.pendingTeardown = append(fanout.pendingTeardown, pendingDeparture{
				entry: destination{id: "grant-c", name: "127.0.0.1:20003", counters: settled},
				seq:   0,
			})
			fanout.reconcileMu.Unlock()

			removed, err := fanout.ReconcileDestinations(testCase.targets)
			if err == nil {
				t.Fatalf("reconcile with a %s was accepted, want rejection", testCase.name)
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("reconcile returned err %v, want one containing %q", err, testCase.wantErr)
			}
			if len(removed) != 0 {
				t.Fatalf("rejected reconcile returned %d departure(s) %+v, want none; a retry loop that discards "+
					"the error discards these too, and they are the only remaining record of those sessions",
					len(removed), removed)
			}

			// Discard the rejection exactly as `if err != nil { retry }` would,
			// then prove grant-c survived it. Before the fix the harvest ran
			// ahead of resolveTargets and this came back empty.
			harvested, remaining := fanout.HarvestPendingTeardowns()
			var grantC *DestinationStat
			for i := range harvested {
				if harvested[i].TargetID == "grant-c" {
					grantC = &harvested[i]
				}
			}
			if grantC == nil {
				t.Fatalf("grant-c is gone after a reconcile rejected for a %s (harvested %+v, %d remaining); the "+
					"rejection consumed a settled departure, so its session is never closed and its tail never billed",
					testCase.name, harvested, remaining)
			}
			if grantC.Packets != 3 || grantC.Bytes != 96 {
				t.Errorf("grant-c settled at %d packets / %d bytes, want 3 / 96", grantC.Packets, grantC.Bytes)
			}
			if remaining != 0 {
				t.Errorf("harvest left %d departures outstanding, want 0", remaining)
			}

			// The rejection still holds: the bad set was not applied, so the
			// served table is untouched.
			entries := fanout.table.Load().entries
			if len(entries) != 1 || entries[0].id != "grant-a" {
				t.Errorf("rejected reconcile mutated the served table to %+v, want grant-a alone", entries)
			}
		})
	}
}
