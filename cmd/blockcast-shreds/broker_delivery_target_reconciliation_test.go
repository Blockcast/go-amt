package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/blockcast/go-amt/broker"
	"github.com/blockcast/go-amt/broker/gwclient"
	"github.com/blockcast/go-amt/receiver"
	"github.com/blockcast/go-amt/receiver/delivery"
	"github.com/blockcast/go-amt/shred"
)

const (
	grantA          = "11111111-1111-4111-8111-111111111111"
	grantB          = "22222222-2222-4222-8222-222222222222"
	testGatewayUUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

func TestBrokerDeliveryTargetReconciliation(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := newCertificate(t, nil, nil, true, "Blockcast test CA")
	serverCert, serverKey := newCertificate(t, caCert, caKey, false, "broker.test")
	clientCert, clientKey := newCertificate(t, caCert, caKey, false, "gateway.test")
	destination := listenUDP(t)
	defer destination.Close()

	var mu sync.RWMutex
	read := broker.DeliveryTargetsRead{FeedID: "feed-a", EvaluatedAt: "2026-08-27T00:00:00Z", Targets: []broker.DeliveryTarget{
		{TargetID: grantA, Addr: destination.LocalAddr().String()},
	}}
	failed := false
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		if failed {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(read)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate(t, serverCert, serverKey)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool(caCert),
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate(t, clientCert, clientKey)}, RootCAs: certPool(caCert), MinVersion: tls.VersionTLS12,
	}}}
	reader, err := gwclient.NewDeliveryTargetReader(server.URL, "feed-a", client)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := reader.Read(context.Background())
	if err != nil {
		t.Fatalf("initial mTLS broker read: %v", err)
	}
	if len(initial.Targets) != 1 || initial.Targets[0].TargetID != grantA {
		t.Fatalf("initial grants = %#v, want grant A", initial.Targets)
	}

	mu.Lock()
	read = initial
	mu.Unlock()
	fanout, err := receiver.NewUDPFanoutTargets(gwclient.ReceiverTargets(initial), 32, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fanout.Close()

	walPath := filepath.Join(dir, "delivery.wal")
	recordPath := filepath.Join(dir, "records.jsonl")
	wal, err := delivery.OpenWAL(walPath)
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()
	recordFile, err := delivery.OpenRecordFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	defer recordFile.Close()
	sink, err := delivery.NewWriterSink(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	tracker, err := delivery.NewTracker(wal)
	if err != nil {
		t.Fatal(err)
	}
	biller, err := delivery.NewReporter(tracker, sink)
	if err != nil {
		t.Fatal(err)
	}

	if err := biller.Tick(ledgerSamples(fanout)); err != nil {
		t.Fatal(err)
	}
	sendPacket(t, fanout, destination, []byte("first"))
	if err := biller.Tick(ledgerSamples(fanout)); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	failed = true
	mu.Unlock()
	if err := reconcileBrokerDeliveryTargets(context.Background(), reader, fanout, biller); err == nil {
		t.Fatal("failed broker read returned nil")
	}
	if stats := fanout.DestinationStats(); len(stats) != 1 || stats[0].TargetID != grantA {
		t.Fatalf("failed read changed target table: %#v", stats)
	}

	mu.Lock()
	failed = false
	read.Targets = []broker.DeliveryTarget{}
	mu.Unlock()
	if err := reconcileBrokerDeliveryTargets(context.Background(), reader, fanout, biller); err != nil {
		t.Fatal(err)
	}
	if len(fanout.DestinationStats()) != 0 {
		t.Fatal("empty snapshot left revoked targets in the fan-out")
	}

	mu.Lock()
	read.Targets = []broker.DeliveryTarget{{TargetID: grantB, Addr: destination.LocalAddr().String()}}
	mu.Unlock()
	if err := reconcileBrokerDeliveryTargets(context.Background(), reader, fanout, biller); err != nil {
		t.Fatal(err)
	}
	sendPacket(t, fanout, destination, []byte("tail"))
	records := readRecords(t, recordPath)
	var finals []delivery.Record
	for _, record := range records {
		if record.Final {
			finals = append(finals, record)
		}
	}
	if len(finals) != 1 {
		t.Fatalf("final records = %d, want exactly 1: %#v", len(finals), records)
	}
	final := finals[0]
	if final.SubscriberID != grantA || final.CloseReason != delivery.CloseTicketExpired {
		t.Fatalf("final record = %#v, want grant A TICKET_EXPIRED", final)
	}
	if final.PacketsOut != 0 || final.BytesOut != 0 {
		t.Fatalf("final revoked grant = packets %d bytes %d, want 0 and 0 after the prior tick", final.PacketsOut, final.BytesOut)
	}
}

func TestBrokerDeliveryTargetsStartEmptyAndReconcile(t *testing.T) {
	fanout, err := receiver.NewUDPFanoutTargetsAllowEmpty(nil, 32, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fanout.Close()

	if stats := fanout.DestinationStats(); len(stats) != 0 {
		t.Fatalf("initial target table = %#v, want empty", stats)
	}

	removed, err := fanout.ReconcileDestinations([]receiver.Target{{ID: grantA, Address: "127.0.0.1:20001"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("added target removed = %#v, want none", removed)
	}
	stats := fanout.DestinationStats()
	if len(stats) != 1 || stats[0].TargetID != grantA {
		t.Fatalf("reconciled target table = %#v, want grant A", stats)
	}
}

func TestListenAndScoreStartsEmptyThenServesGrantedTarget(t *testing.T) {
	silenceStdout(t)

	caCert, caKey := newCertificate(t, nil, nil, true, "Blockcast test CA")
	serverCert, serverKey := newCertificate(t, caCert, caKey, false, "broker.test")
	clientCert, clientKey := newCertificate(t, caCert, caKey, false, "gateway.test")
	certPath, keyPath, caPath := writeTLSFiles(t, clientCert, clientKey, caCert)

	destination := listenUDP(t)
	defer destination.Close()
	feedAddress := freeLocalAddr(t, "udp")
	httpAddress := freeLocalAddr(t, "tcp")

	var mu sync.RWMutex
	var reads int
	read := broker.DeliveryTargetsRead{FeedID: "default", EvaluatedAt: "2026-08-29T00:00:00Z", Targets: []broker.DeliveryTarget{}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		reads++
		_ = json.NewEncoder(w).Encode(read)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate(t, serverCert, serverKey)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool(caCert),
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	stop := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- listenAndScore(
			[]feed{{name: "default", address: feedAddress}}, nil,
			httpAddress, 30*time.Second, true,
			30*time.Millisecond, 40*time.Millisecond, shred.DefaultRetention, stop,
			scoring{mode: "shred"}, billing{}, heartbeatConfig{
				brokerURL: server.URL, gwUUID: testGatewayUUID,
				clientCert: certPath, clientKey: keyPath, caBundle: caPath,
			})
	}()
	readyDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(readyDeadline) {
		select {
		case err := <-finished:
			t.Fatalf("receiver exited before readiness: %v", err)
		default:
		}
		if _, ok := scrape(t, httpAddress, "bcast_shred_gw_report_schema", `feed="default"`); ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if time.Now().After(readyDeadline) {
		t.Fatal("receiver HTTP endpoint never became ready")
	}
	mu.RLock()
	startupReads := reads
	mu.RUnlock()

	sender, err := net.Dial("udp", feedAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	// The authoritative empty startup snapshot must not forward anything.
	if _, err := sender.Write([]byte("before-grant")); err != nil {
		t.Fatal(err)
	}
	if err := destination.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if _, _, err := destination.ReadFromUDP(buffer); err == nil {
		t.Fatal("empty initial target snapshot forwarded a packet")
	}

	mu.Lock()
	read.Targets = []broker.DeliveryTarget{{TargetID: grantA, Addr: destination.LocalAddr().String()}}
	mu.Unlock()

	// Drive the real loop until its next broker poll has installed the grant.
	time.Sleep(100 * time.Millisecond)
	mu.RLock()
	if reads <= startupReads {
		mu.RUnlock()
		t.Fatal("receiver did not poll broker after startup")
	}
	mu.RUnlock()
	if err := destination.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err := sender.Write([]byte("after-grant")); err != nil {
			t.Fatal(err)
		}
		n, _, err := destination.ReadFromUDP(buffer)
		if err == nil && string(buffer[:n]) == "after-grant" {
			break
		}
		if i == 99 {
			t.Fatalf("granted target never received a packet: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(stop)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func writeTLSFiles(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey, ca *x509.Certificate) (string, string, string) {
	t.Helper()
	certPath := filepath.Join(t.TempDir(), "client.crt")
	keyPath := filepath.Join(filepath.Dir(certPath), "client.key")
	caPath := filepath.Join(filepath.Dir(certPath), "ca.crt")
	for path, data := range map[string][]byte{
		certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		keyPath:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		caPath:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}),
	} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return certPath, keyPath, caPath
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func sendPacket(t *testing.T, fanout *receiver.Fanout, destination *net.UDPConn, packet []byte) {
	t.Helper()
	if fanout.Enqueue("feed-a", packet) != receiver.EnqueueAccepted {
		t.Fatal("fan-out rejected packet")
	}
	_ = destination.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 64)
	if _, _, err := destination.ReadFromUDP(buffer); err != nil {
		t.Fatalf("read fanned-out packet: %v", err)
	}
}

func certPool(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

func newCertificate(t *testing.T, parent *x509.Certificate, parentKey *rsa.PrivateKey, isCA bool, name string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	if !isCA {
		template.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	if isCA {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func tlsCertificate(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey) tls.Certificate {
	t.Helper()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}
