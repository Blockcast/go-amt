package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blockcast/go-amt/receiver/config"
	"github.com/blockcast/go-amt/shred"
)

// dataShred builds one shred-forwarder-framed data shred. Data shreds carry a
// local index of 0..31, so a set is complete at all 32 of them and erased below
// the 32-of-64 threshold.
func dataShred(slot uint64, fecSet uint32, indexWithinSet uint8) []byte {
	packet := make([]byte, shred.WireHeaderSize+16)
	packet[0] = 3 // erasure-shard body
	binary.LittleEndian.PutUint64(packet[1:9], slot)
	binary.LittleEndian.PutUint32(packet[9:13], fecSet)
	binary.LittleEndian.PutUint32(packet[13:17], uint32(indexWithinSet))
	packet[17] = 0 // data shred, no flags
	packet[18] = 0 // num_data is 0 on data shreds
	packet[19] = 0 // num_coding is 0 on data shreds
	binary.LittleEndian.PutUint64(packet[20:28], uint64(slot))
	return packet
}

// freeLocalAddr returns a loopback address that was bindable a moment ago. The
// socket is closed before returning so the code under test can bind it.
func freeLocalAddr(t *testing.T, network string) string {
	t.Helper()
	switch network {
	case "udp":
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		address := conn.LocalAddr().String()
		_ = conn.Close()
		return address
	default:
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		_ = listener.Close()
		return address
	}
}

// scrape fetches the Prometheus text exposition and returns the value of the
// first sample of name whose label set contains every fragment in match.
func scrape(t *testing.T, address, name string, match ...string) (float64, bool) {
	t.Helper()
	response, err := http.Get("http://" + address + "/metrics")
	if err != nil {
		return 0, false
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, name) {
			continue
		}
		labels, value, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		// Guard against name being a prefix of a longer metric name.
		if labels != name && !strings.HasPrefix(labels, name+"{") {
			continue
		}
		matched := true
		for _, fragment := range match {
			if !strings.Contains(labels, fragment) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			continue
		}
		return parsed, true
	}
	return 0, false
}

// silenceStdout points os.Stdout at the null device for the duration of a test.
// listenAndScore prints its receipt on the way out, which is not what these
// tests assert and would otherwise interleave with test output.
func silenceStdout(t *testing.T) {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = devnull
	t.Cleanup(func() {
		os.Stdout = original
		_ = devnull.Close()
	})
}

// waitReady blocks until the receiver's HTTP endpoint answers, which proves
// listenAndScore has bound its sockets.
//
// Without this the first datagram can race socket setup, and a CONNECTED UDP
// socket surfaces the resulting ICMP port-unreachable as ECONNREFUSED on a
// later write -- one spurious error that has nothing to do with the code under
// test. Senders below therefore also continue past write errors rather than
// treating one as end of stream.
func waitReady(t *testing.T, httpAddress string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := scrape(t, httpAddress, "bcast_shred_gw_report_schema", `feed="default"`); ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("receiver HTTP endpoint never became ready")
}

// TestListenAndScorePublishesRealErasureToMetrics is the guard for the whole
// disconnect this issue is about.
//
// receiver/metrics_test.go passes with the bug present because it publishes
// windows through its own construction path. erasure/tracker_test.go passes
// because it drives a Tracker directly. Both halves were complete and tested
// while nothing in the binary ever built a Tracker or published a window, so
// /metrics served the delivery SLA as a permanent zero -- a confidently clean
// feed -- under arbitrary real loss.
//
// So this drives real UDP datagrams into listenAndScore, the function the
// binary actually runs, and asserts the scraped HTTP exposition. Deleting the
// tracker construction, the Observe call, or the reporting loop fails it; no
// assertion here can be satisfied by a component test.
func TestListenAndScorePublishesRealErasureToMetrics(t *testing.T) {
	silenceStdout(t)

	const grace = 30 * time.Millisecond
	const reportInterval = 60 * time.Millisecond

	destination, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = destination.Close() }()

	feedAddress := freeLocalAddr(t, "udp")
	httpAddress := freeLocalAddr(t, "tcp")

	stop := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- listenAndScore(
			[]feed{{name: "default", address: feedAddress}},
			[]string{destination.LocalAddr().String()},
			httpAddress, 30*time.Second, true, grace, reportInterval, stop, "shred", "", "",
		)
	}()

	waitReady(t, httpAddress)

	sender, err := net.Dial("udp", feedAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()

	// Drain the fan-out destination so its socket buffer cannot fill and turn a
	// delivery assertion into a buffering artefact.
	delivered := make(chan []byte, 4096)
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, err := destination.Read(buffer)
			if err != nil {
				return
			}
			select {
			case delivered <- append([]byte(nil), buffer[:n]...):
			default:
			}
		}
	}()

	// Alternate erased and complete slots continuously. Traffic must keep
	// flowing: each drained window reports only what it saw, so a single burst
	// would leave whichever window the scrape lands in reporting zero for
	// reasons that have nothing to do with the wiring.
	//
	// Slots step by 7, not 1. Observed slot numbers on a real feed are not
	// contiguous -- in the bundled capture consecutive slots differ by 69 to
	// 364 -- and a contiguous-only test passes against a tracker that reclaims
	// slot state before it can be scored.
	senderStop := make(chan struct{})
	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		slot := uint64(1_000_000)
		for {
			select {
			case <-senderStop:
				return
			default:
			}
			for _, shredsInSlot := range []int{5, 32} {
				for index := range shredsInSlot {
					// A write error is not end of stream here; see waitReady.
					_, _ = sender.Write(dataShred(slot, 0, uint8(index)))
				}
				slot += 7
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	// Poll until a published window carries scored sets. The deadline covers
	// scheduling, not correctness: with traffic flowing the condition becomes
	// true on the first tick after the first slot's deadline and stays true.
	var total, erased, fraction, graceMS, schema float64
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		total, _ = scrape(t, httpAddress, "bcast_shred_gw_erasure_sets", `feed="default"`, `result="total"`)
		erased, _ = scrape(t, httpAddress, "bcast_shred_gw_erasure_sets", `feed="default"`, `result="erased"`)
		if total > 0 && erased > 0 && erased < total {
			fraction, _ = scrape(t, httpAddress, "bcast_shred_gw_erasure_fraction", `feed="default"`)
			graceMS, _ = scrape(t, httpAddress, "bcast_shred_gw_erasure_grace_milliseconds", `feed="default"`)
			schema, _ = scrape(t, httpAddress, "bcast_shred_gw_report_schema", `feed="default"`)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	meanRate, _ := scrape(t, httpAddress, "bcast_shred_gw_shreds_per_second", `feed="default"`, `measure="mean"`)
	peakRate, _ := scrape(t, httpAddress, "bcast_shred_gw_shreds_per_second", `feed="default"`, `measure="peak_100ms"`)
	var gapTotal float64
	for _, bucket := range []string{`bucket="<1"`, `bucket="1-2.4"`, `bucket="2.4-7"`, `bucket="7-32"`, `bucket=">=32"`} {
		value, _ := scrape(t, httpAddress, "bcast_shred_gw_gap_events", `feed="default"`, bucket)
		gapTotal += value
	}
	ingress, _ := scrape(t, httpAddress, "bcast_shred_gw_ingress_packets_total", `feed="default"`)
	egress, _ := scrape(t, httpAddress, "bcast_shred_gw_egress_packets_total", `feed="default"`)

	close(senderStop)
	<-senderDone
	close(stop)
	if err := <-finished; err != nil {
		t.Fatalf("listenAndScore: %v", err)
	}

	// The erasure SLA itself.
	if total == 0 {
		t.Fatal("erasure_sets{result=\"total\"} is 0: no window with scored sets was ever published to /metrics")
	}
	if erased == 0 {
		t.Fatal("erasure_sets{result=\"erased\"} is 0 while half of every slot pair carried 5 of 64 shreds")
	}
	// Complete sets must survive too. Without this, a tracker that scored
	// everything erased would satisfy the assertions above.
	if erased >= total {
		t.Fatalf("erased = %v of total = %v: the 32-shred slots must score complete", erased, total)
	}
	if fraction <= 0 || fraction >= 1 {
		t.Fatalf("erasure_fraction = %v, want strictly between 0 and 1", fraction)
	}
	if expected := erased / total; fraction != expected {
		t.Fatalf("erasure_fraction = %v, want %v (erased/total from the same window)", fraction, expected)
	}

	// The two series that are self-refuting when zero: v1 fixes schema at 1 and
	// the default grace at 400ms, so a zero here advertises a schema that does
	// not exist.
	if graceMS != float64(grace/time.Millisecond) {
		t.Fatalf("erasure_grace_milliseconds = %v, want %v", graceMS, grace/time.Millisecond)
	}
	if schema != 1 {
		t.Fatalf("report_schema = %v, want 1", schema)
	}

	// Rate and gap come from the same drained window, so they must be populated
	// wherever erasure is.
	if meanRate <= 0 {
		t.Fatalf("shreds_per_second{measure=\"mean\"} = %v, want > 0", meanRate)
	}
	if peakRate <= 0 {
		t.Fatalf("shreds_per_second{measure=\"peak_100ms\"} = %v, want > 0", peakRate)
	}
	if gapTotal <= 0 {
		t.Fatal("every gap_events bucket is 0 while shreds were arriving")
	}

	// Delivery is unaffected by the scoring work now sharing the path.
	if ingress <= 0 {
		t.Fatalf("ingress_packets_total = %v, want > 0", ingress)
	}
	if egress <= 0 {
		t.Fatalf("egress_packets_total = %v, want > 0", egress)
	}
	select {
	case packet := <-delivered:
		parsed, err := shred.Parse(packet, shred.FormatForwarder)
		if err != nil {
			t.Fatalf("forwarded packet is not a shred: %v", err)
		}
		if want := dataShred(parsed.Slot, parsed.FECSetIndex, parsed.IndexWithinSet); string(packet) != string(want) {
			t.Fatalf("forwarded packet = %x, want %x", packet, want)
		}
	default:
		t.Fatal("no packet reached the fan-out destination")
	}
}

// TestErasureGraceFlagIsAcceptedAndValidated covers the flag the receiver
// shipped without. Its default is taken from receiver/config so the demo path
// and the v1 broker path cannot advertise different scoring deadlines for the
// same binary.
func TestErasureGraceFlagIsAcceptedAndValidated(t *testing.T) {
	if config.DefaultErasureGrace != 400*time.Millisecond {
		t.Fatalf("DefaultErasureGrace = %v, want 400ms per the v1 scoring spec", config.DefaultErasureGrace)
	}

	for _, testCase := range []struct {
		name string
		args []string
		want string
	}{
		{name: "zero grace", args: []string{"--erasure-grace-ms", "0", "--http-addr", ""}, want: "--erasure-grace-ms must be positive"},
		{name: "negative grace", args: []string{"--erasure-grace-ms", "-1", "--http-addr", ""}, want: "--erasure-grace-ms must be positive"},
		{name: "zero report interval", args: []string{"--report-interval", "0s", "--http-addr", ""}, want: "--report-interval must be positive"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := run(testCase.args)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("run(%v) error = %v, want %q", testCase.args, err, testCase.want)
			}
		})
	}
}

// TestDefaultGraceReachesMetrics binds the documented 400ms default to the
// value an operator actually scrapes, rather than to the flag declaration.
func TestDefaultGraceReachesMetrics(t *testing.T) {
	silenceStdout(t)

	feedAddress := freeLocalAddr(t, "udp")
	httpAddress := freeLocalAddr(t, "tcp")
	stop := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- listenAndScore(
			[]feed{{name: "default", address: feedAddress}}, nil, httpAddress, 30*time.Second, true,
			config.DefaultErasureGrace, 40*time.Millisecond, stop, "shred", "", "",
		)
	}()

	var graceMS float64
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if value, ok := scrape(t, httpAddress, "bcast_shred_gw_erasure_grace_milliseconds", `feed="default"`); ok && value != 0 {
			graceMS = value
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	if err := <-finished; err != nil {
		t.Fatalf("listenAndScore: %v", err)
	}

	if graceMS != 400 {
		t.Fatalf("erasure_grace_milliseconds = %v, want 400; the published window does not carry the configured grace", graceMS)
	}
}
