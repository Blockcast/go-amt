package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	config, err := Parse([]string{
		"--feed-ids", "primary, backup",
		"--bind-address", "192.0.2.10:0",
		"--interface", "eth1",
		"--rcvbuf-bytes", "8388608",
		"--dest-ip-ports", "127.0.0.1:8001,[::1]:8002",
		"--cert", "/etc/bcast/client.pem",
		"--key", "/etc/bcast/client-key.pem",
		"--broker-url", "https://broker.example.test/session",
		"--erasure-grace-ms", "650",
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if !reflect.DeepEqual(config.FeedIDs, []string{"primary", "backup"}) {
		t.Fatalf("FeedIDs = %v", config.FeedIDs)
	}
	if got := config.BindAddress.String(); got != "192.0.2.10:0" {
		t.Fatalf("BindAddress = %q", got)
	}
	if config.Interface != "eth1" || config.RcvBufBytes != 8388608 {
		t.Fatalf("interface/buffer = %q/%d", config.Interface, config.RcvBufBytes)
	}
	if got := []string{config.Destinations[0].String(), config.Destinations[1].String()}; !reflect.DeepEqual(got, []string{"127.0.0.1:8001", "[::1]:8002"}) {
		t.Fatalf("Destinations = %v", got)
	}
	if config.BrokerURL.String() != "https://broker.example.test/session" {
		t.Fatalf("BrokerURL = %q", config.BrokerURL)
	}
	if config.ErasureGrace != 650*time.Millisecond {
		t.Fatalf("ErasureGrace = %s", config.ErasureGrace)
	}
}

func TestParseDefaults(t *testing.T) {
	config, err := Parse(requiredArgs())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := config.BindAddress.String(); got != DefaultBindAddress {
		t.Fatalf("BindAddress = %q, want %q", got, DefaultBindAddress)
	}
	if config.RcvBufBytes != DefaultRcvBufBytes {
		t.Fatalf("RcvBufBytes = %d, want %d", config.RcvBufBytes, DefaultRcvBufBytes)
	}
	if config.ErasureGrace != DefaultErasureGrace {
		t.Fatalf("ErasureGrace = %s, want %s", config.ErasureGrace, DefaultErasureGrace)
	}
}

func TestParseRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "missing feed", args: replaceArg(requiredArgs(), "--feed-ids", ""), wantErr: "at least one feed ID is required"},
		{name: "duplicate feed", args: replaceArg(requiredArgs(), "--feed-ids", "primary,primary"), wantErr: "feed ID \"primary\" is configured more than once"},
		{name: "invalid bind", args: replaceArg(requiredArgs(), "--bind-address", "localhost:0"), wantErr: "parse --bind-address"},
		{name: "multicast bind", args: replaceArg(requiredArgs(), "--bind-address", "224.0.0.1:0"), wantErr: "--bind-address must not be multicast"},
		{name: "zero buffer", args: replaceArg(requiredArgs(), "--rcvbuf-bytes", "0"), wantErr: "--rcvbuf-bytes must be positive"},
		{name: "duplicate destination", args: replaceArg(requiredArgs(), "--dest-ip-ports", "127.0.0.1:8001,127.0.0.1:8001"), wantErr: "destination \"127.0.0.1:8001\" is configured more than once"},
		{name: "canonical duplicate destination", args: replaceArg(requiredArgs(), "--dest-ip-ports", "[::1]:8001,[0:0:0:0:0:0:0:1]:8001"), wantErr: "resolves to a duplicate address"},
		{name: "hostname destination", args: replaceArg(requiredArgs(), "--dest-ip-ports", "localhost:8001"), wantErr: "parse destination"},
		{name: "wildcard destination", args: replaceArg(requiredArgs(), "--dest-ip-ports", "0.0.0.0:8001"), wantErr: "must be a unicast IP"},
		{name: "mapped wildcard destination", args: replaceArg(requiredArgs(), "--dest-ip-ports", "[::ffff:0.0.0.0]:8001"), wantErr: "must be a unicast IP"},
		{name: "mapped multicast destination", args: replaceArg(requiredArgs(), "--dest-ip-ports", "[::ffff:224.0.0.1]:8001"), wantErr: "must be a unicast IP"},
		{name: "broadcast destination", args: replaceArg(requiredArgs(), "--dest-ip-ports", "255.255.255.255:8001"), wantErr: "must be a unicast IP"},
		{name: "zero destination port", args: replaceArg(requiredArgs(), "--dest-ip-ports", "127.0.0.1:0"), wantErr: "must be a unicast IP"},
		{name: "missing certificate", args: replaceArg(requiredArgs(), "--cert", ""), wantErr: "--cert is required"},
		{name: "missing key", args: replaceArg(requiredArgs(), "--key", ""), wantErr: "--key is required"},
		{name: "insecure broker", args: replaceArg(requiredArgs(), "--broker-url", "http://broker.example.test"), wantErr: "must be an HTTPS URL"},
		{name: "broker user info", args: replaceArg(requiredArgs(), "--broker-url", "https://user@broker.example.test"), wantErr: "without user information"},
		{name: "missing broker host", args: replaceArg(requiredArgs(), "--broker-url", "https://:443"), wantErr: "must be an HTTPS URL"},
		{name: "invalid broker port", args: replaceArg(requiredArgs(), "--broker-url", "https://broker.example.test:99999"), wantErr: "port must be between 1 and 65535"},
		{name: "zero grace", args: replaceArg(requiredArgs(), "--erasure-grace-ms", "0"), wantErr: "--erasure-grace-ms must be positive"},
		{name: "overflowing grace", args: replaceArg(requiredArgs(), "--erasure-grace-ms", "9223372036854775807"), wantErr: "exceeds the maximum supported duration"},
		{name: "positional argument", args: append(requiredArgs(), "extra"), wantErr: "unexpected positional arguments"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.args)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Parse() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func requiredArgs() []string {
	return []string{
		"--feed-ids", "primary",
		"--dest-ip-ports", "127.0.0.1:8001",
		"--cert", "/tmp/client.pem",
		"--key", "/tmp/client-key.pem",
		"--broker-url", "https://broker.example.test",
	}
}

func replaceArg(args []string, name, value string) []string {
	result := append([]string(nil), args...)
	for i := range result {
		if result[i] == name {
			result[i+1] = value
			return result
		}
	}
	return append(result, name, value)
}
