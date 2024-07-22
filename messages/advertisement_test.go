package messages_test

import (
	"github.com/blockcast/go-amt/messages"
	"net"
	"reflect"
	"testing"
)

func TestEncodeRelayAdvertisementMessageIPv4(t *testing.T) {
	message := messages.RelayAdvertisementMessage{
		Header:    messages.Header{Version: messages.Version, Type: messages.RelayAdvertisementType},
		Nonce:     [4]byte{0, 0, 0, 1},
		RelayAddr: net.IPv4(192, 168, 1, 1)[12:],
	}
	encoded, err := message.MarshalBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(encoded) != 8+net.IPv4len { // Header + Reserved + Nonce + IPv4 address length
		t.Errorf("unexpected encoded length: got %d, want %d", len(encoded), 8+net.IPv4len)
	}
}

func TestEncodeRelayAdvertisementMessageIPv6(t *testing.T) {
	message := messages.RelayAdvertisementMessage{
		Header:    messages.Header{Version: messages.Version, Type: messages.RelayAdvertisementType},
		Nonce:     [4]byte{0, 0, 0, 1},
		RelayAddr: net.ParseIP("2001:db8::1"),
	}
	encoded, err := message.MarshalBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(encoded) != 8+net.IPv6len { // Header + Reserved + Nonce + IPv6 address length
		t.Errorf("unexpected encoded length: got %d, want %d", len(encoded), 8+net.IPv6len)
	}
}

func TestDecodeRelayAdvertisementMessageIPv4(t *testing.T) {
	expected := messages.RelayAdvertisementMessage{
		Header:    messages.Header{Version: messages.Version, Type: messages.RelayAdvertisementType},
		Nonce:     [4]byte{0, 0, 0, 1},
		RelayAddr: net.IPv4(192, 168, 1, 1)[12:],
	}
	data := []byte{0x2, 0, 0, 0, 0, 0, 0, 1, 192, 168, 1, 1}
	var message messages.RelayAdvertisementMessage
	if err := message.UnmarshalBinary(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(message, expected) {
		t.Errorf("decoded message does not match expected: got %+v, want %+v", message, expected)
	}
}

func TestDecodeRelayAdvertisementMessageIPv6(t *testing.T) {
	expected := messages.RelayAdvertisementMessage{
		Header:    messages.Header{Version: messages.Version, Type: messages.RelayAdvertisementType},
		Nonce:     [4]byte{0, 0, 0, 1},
		RelayAddr: net.ParseIP("2001:db8::1"),
	}
	data := append([]byte{0x2, 0, 0, 0, 0, 0, 0, 1}, net.ParseIP("2001:db8::1").To16()...)
	var message messages.RelayAdvertisementMessage
	if err := message.UnmarshalBinary(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(message, expected) {
		t.Errorf("decoded message does not match expected: got %+v, want %+v", message, expected)
	}
}

func TestDecodeRelayAdvertisementMessageErrorHandling(t *testing.T) {
	data := []byte{0x20} // Insufficient data
	var message messages.RelayAdvertisementMessage
	if err := message.UnmarshalBinary(data); err == nil {
		t.Errorf("expected error for insufficient data, got nil")
	}
}
