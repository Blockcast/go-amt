package main

import (
	"strings"
	"testing"
	"time"

	"github.com/blockcast/go-amt/broker/gwclient"
	"github.com/blockcast/go-amt/erasure"
	"github.com/blockcast/go-amt/receiver"
	"github.com/prometheus/client_golang/prometheus"
)

// TestGenericModeHeartbeatIsUnsendable is the reproduction that motivates
// rejecting --mode generic alongside the heartbeat flags.
//
// It asserts the FAILURE the receiver would ship with, not the fix: generic
// mode builds no erasure trackers, so the pre-flight drain in listenAndScore
// populates nothing, every feed keeps the zero erasure.Window whose Schema is
// 0, and ValidateHeartbeat rejects the whole beat. Producer.Run only logs that
// rejection, so the gateway sends NOTHING while every flag reads as configured.
//
// If a later change gives generic mode a real, valid window, this test starts
// failing on the Build error -- which is the correct signal to revisit the
// startup rejection in heartbeatOptions rather than to delete this test.
func TestGenericModeHeartbeatIsUnsendable(t *testing.T) {
	feeds := []string{"feed-a", "feed-b"}
	metrics, err := receiver.NewReceiverMetrics(prometheus.NewRegistry(), feeds)
	if err != nil {
		t.Fatalf("new receiver metrics: %v", err)
	}

	// Exactly what listenAndScore does in generic mode: an empty tracker map,
	// then the pre-flight drain. The drain ranges over the map, so it is a
	// no-op and no window is ever published.
	trackers := make(map[string]*erasure.Tracker)
	publishWindows(trackers, metrics, time.Now())

	producer, err := gwclient.NewProducer(
		"00000000-0000-4000-8000-000000000000",
		"https://broker.invalid",
		metrics,
	)
	if err != nil {
		t.Fatalf("new producer: %v", err)
	}

	if _, err := producer.Build(); err == nil {
		t.Fatal("Build succeeded on a generic-mode receiver; expected the zero " +
			"erasure window (schema 0) to be rejected. If generic mode now emits a " +
			"valid window, revisit the startup rejection in heartbeatOptions.")
	} else if !strings.Contains(err.Error(), "schema") {
		t.Fatalf("Build failed for an unexpected reason, want a schema rejection: %v", err)
	}
}

// TestHeartbeatOptionsRejectsGenericMode is the guard for the failure above:
// the combination must be refused at startup, where the operator sees it, and
// never reach a producer that can only log its own rejection every 30s.
//
// The shred-mode cases are here so the rejection cannot be widened by accident
// into "the heartbeat never enables" -- a fix whose own regression test only
// asserted the error would pass just as happily with the feature broken.
func TestHeartbeatOptionsRejectsGenericMode(t *testing.T) {
	const (
		brokerURL = "https://broker.example"
		gwUUID    = "00000000-0000-4000-8000-000000000000"
	)
	generic := scoring{mode: "generic", sourceLabel: "synthetic", rightsBasis: "owned"}
	shred := scoring{mode: "shred"}

	t.Run("generic mode with heartbeat flags is rejected", func(t *testing.T) {
		_, err := heartbeatOptions(brokerURL, gwUUID, generic)
		if err == nil {
			t.Fatal("heartbeatOptions accepted --mode generic with the heartbeat " +
				"flags; the producer would send nothing while reading as configured")
		}
		// The message must name the flag the operator has to change. A bare
		// "invalid configuration" would leave them to rediscover the schema-0
		// chain this rejection exists to short-circuit.
		if !strings.Contains(err.Error(), "--mode shred") {
			t.Fatalf("rejection does not name the required mode: %v", err)
		}
	})

	t.Run("generic mode without heartbeat flags still starts", func(t *testing.T) {
		beat, err := heartbeatOptions("", "", generic)
		if err != nil {
			t.Fatalf("generic mode without heartbeat flags must remain valid: %v", err)
		}
		if beat.enabled() {
			t.Fatal("heartbeat enabled with no broker URL")
		}
	})

	t.Run("shred mode with heartbeat flags is accepted", func(t *testing.T) {
		beat, err := heartbeatOptions(brokerURL, gwUUID, shred)
		if err != nil {
			t.Fatalf("shred mode is the supported heartbeat configuration: %v", err)
		}
		if !beat.enabled() {
			t.Fatal("heartbeat not enabled for a valid shred-mode configuration")
		}
	})

	// The pre-existing both-or-neither rule must survive the new case, in both
	// modes: the mode check is additional to it, not a replacement.
	for _, mode := range []scoring{shred, generic} {
		t.Run("incomplete pair rejected in "+string(mode.mode)+" mode", func(t *testing.T) {
			if _, err := heartbeatOptions(brokerURL, "", mode); err == nil {
				t.Error("--broker-url without --gw-uuid was accepted")
			}
			if _, err := heartbeatOptions("", gwUUID, mode); err == nil {
				t.Error("--gw-uuid without --broker-url was accepted")
			}
		})
	}
}
