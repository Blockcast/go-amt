//go:build (linux || darwin) && !ios && !android && cgo

package amt

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo LDFLAGS: -lamt_protocol -ldl -lm -lpthread

#include <stdlib.h>
#include <string.h>
#include "amt_protocol.h"
*/
import "C"
import (
	"fmt"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func init() {
	RegisterProtocol(ProtocolTypeCGO, func() (AMTProtocol, error) {
		return NewCGOProtocol()
	})
}

// CGOProtocol implements AMTProtocol using the Rust library via CGO.
// Only available on Linux/macOS desktop (not iOS/Android).
type CGOProtocol struct {
	handle C.amt_gateway_handle_t
	state  AMTState
	mu     sync.Mutex
}

// NewCGOProtocol creates a new CGO-based protocol instance
func NewCGOProtocol() (*CGOProtocol, error) {
	return &CGOProtocol{
		state: AMTStateIdle,
	}, nil
}

func (p *CGOProtocol) Initialize(relayAddr string, relayPort uint16) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.handle != nil {
		C.amt_gateway_free(p.handle)
		p.handle = nil
	}

	cAddr := C.CString(relayAddr)
	defer C.free(unsafe.Pointer(cAddr))

	var handle C.amt_gateway_handle_t
	result := C.amt_gateway_new(cAddr, C.uint16_t(relayPort), false, &handle)
	if result != C.AMT_RESULT_OK {
		return &ProtocolError{
			State:   AMTStateIdle,
			Message: fmt.Sprintf("failed to create gateway: error code %d", result),
		}
	}

	p.handle = handle
	p.state = AMTStateIdle
	return nil
}

func (p *CGOProtocol) CreateDiscoveryMessage() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.handle == nil {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "protocol not initialized",
		}
	}

	var outMsg C.amt_buffer_t
	result := C.amt_gateway_start_discovery(p.handle, &outMsg)
	if result != C.AMT_RESULT_OK {
		return nil, &ProtocolError{
			State:   p.state,
			Message: fmt.Sprintf("failed to start discovery: error code %d", result),
		}
	}
	defer C.amt_buffer_free(outMsg)

	p.state = AMTStateDiscovering
	return C.GoBytes(unsafe.Pointer(outMsg.data), C.int(outMsg.len)), nil
}

func (p *CGOProtocol) HandleAdvertisement(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.handle == nil {
		return &ProtocolError{
			State:   p.state,
			Message: "protocol not initialized",
		}
	}

	result := C.amt_gateway_handle_advertisement(
		p.handle,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
	)
	if result != C.AMT_RESULT_OK {
		return &ProtocolError{
			State:   p.state,
			Message: fmt.Sprintf("failed to handle advertisement: error code %d", result),
		}
	}

	return nil
}

func (p *CGOProtocol) CreateRequestMessage(preferNative bool) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.handle == nil {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "protocol not initialized",
		}
	}

	var outMsg C.amt_buffer_t
	result := C.amt_gateway_request_membership(p.handle, C.bool(preferNative), &outMsg)
	if result != C.AMT_RESULT_OK {
		return nil, &ProtocolError{
			State:   p.state,
			Message: fmt.Sprintf("failed to request membership: error code %d", result),
		}
	}
	defer C.amt_buffer_free(outMsg)

	p.state = AMTStateRequesting
	return C.GoBytes(unsafe.Pointer(outMsg.data), C.int(outMsg.len)), nil
}

func (p *CGOProtocol) HandleQuery(data []byte) ([]byte, time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.handle == nil {
		return nil, 0, &ProtocolError{
			State:   p.state,
			Message: "protocol not initialized",
		}
	}

	var outQueryData C.amt_buffer_t
	result := C.amt_gateway_handle_query(
		p.handle,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		&outQueryData,
	)
	if result != C.AMT_RESULT_OK {
		return nil, 0, &ProtocolError{
			State:   p.state,
			Message: fmt.Sprintf("failed to handle query: error code %d", result),
		}
	}
	defer C.amt_buffer_free(outQueryData)

	queryData := C.GoBytes(unsafe.Pointer(outQueryData.data), C.int(outQueryData.len))

	// Parse IGMP query to get interval time
	intervalTime := 10 * time.Second // default
	if len(queryData) > 0 && queryData[0]>>4 == 4 {
		pkt := gopacket.NewPacket(queryData, layers.LayerTypeIPv4, gopacket.NoCopy)
		igmp, ok := pkt.Layer(layers.LayerTypeIGMP).(*layers.IGMP)
		if ok && igmp.Type == layers.IGMPMembershipQuery && igmp.IntervalTime > 0 {
			intervalTime = igmp.IntervalTime
		}
	}

	p.state = AMTStateQuerying
	return queryData, intervalTime, nil
}

func (p *CGOProtocol) CreateIGMPJoinReport(source, group netip.Addr) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	source4 := source.As4()
	group4 := group.As4()

	cSource := C.CString(netip.AddrFrom4(source4).String())
	defer C.free(unsafe.Pointer(cSource))

	cGroup := C.CString(netip.AddrFrom4(group4).String())
	defer C.free(unsafe.Pointer(cGroup))

	var outReport C.amt_buffer_t
	result := C.amt_igmp_ssm_join(cSource, cGroup, &outReport)
	if result != C.AMT_RESULT_OK {
		return nil, &ProtocolError{
			State:   p.state,
			Message: fmt.Sprintf("failed to create IGMP report: error code %d", result),
		}
	}
	defer C.amt_buffer_free(outReport)

	return C.GoBytes(unsafe.Pointer(outReport.data), C.int(outReport.len)), nil
}

func (p *CGOProtocol) CreateIGMPJoinReportMulti(source netip.Addr, groups []netip.Addr) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(groups) == 0 {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "no groups specified",
		}
	}

	source4 := source.As4()
	cSource := C.CString(netip.AddrFrom4(source4).String())
	defer C.free(unsafe.Pointer(cSource))

	// Build array of group address C strings
	cGroups := make([]*C.char, len(groups))
	for i, g := range groups {
		g4 := g.As4()
		cGroups[i] = C.CString(netip.AddrFrom4(g4).String())
		defer C.free(unsafe.Pointer(cGroups[i]))
	}

	var outReport C.amt_buffer_t
	result := C.amt_igmp_ssm_join_multi(
		cSource,
		(**C.char)(unsafe.Pointer(&cGroups[0])),
		C.size_t(len(groups)),
		&outReport,
	)
	if result != C.AMT_RESULT_OK {
		return nil, &ProtocolError{
			State:   p.state,
			Message: fmt.Sprintf("failed to create multi-group IGMP report: error code %d", result),
		}
	}
	defer C.amt_buffer_free(outReport)

	return C.GoBytes(unsafe.Pointer(outReport.data), C.int(outReport.len)), nil
}

func (p *CGOProtocol) CreateIGMPLeaveReport(source, group netip.Addr) ([]byte, error) {
	return buildIGMPLeaveReport(source, group, p.State())
}

func (p *CGOProtocol) CreateMembershipUpdate(igmpReport []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.handle == nil {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "protocol not initialized",
		}
	}

	var outMsg C.amt_buffer_t
	result := C.amt_gateway_send_update(
		p.handle,
		(*C.uint8_t)(unsafe.Pointer(&igmpReport[0])),
		C.size_t(len(igmpReport)),
		&outMsg,
	)
	if result != C.AMT_RESULT_OK {
		return nil, &ProtocolError{
			State:   p.state,
			Message: fmt.Sprintf("failed to send update: error code %d", result),
		}
	}
	defer C.amt_buffer_free(outMsg)

	p.state = AMTStateActive
	return C.GoBytes(unsafe.Pointer(outMsg.data), C.int(outMsg.len)), nil
}

func (p *CGOProtocol) CreateTeardownMessage() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.handle == nil {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "protocol not initialized",
		}
	}

	var outMsg C.amt_buffer_t
	result := C.amt_gateway_send_teardown(p.handle, &outMsg)
	if result != C.AMT_RESULT_OK {
		return nil, &ProtocolError{
			State:   p.state,
			Message: fmt.Sprintf("failed to send teardown: error code %d", result),
		}
	}
	defer C.amt_buffer_free(outMsg)

	return C.GoBytes(unsafe.Pointer(outMsg.data), C.int(outMsg.len)), nil
}

func (p *CGOProtocol) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.handle != nil {
		C.amt_gateway_reset(p.handle)
	}
	p.state = AMTStateIdle
}

func (p *CGOProtocol) State() AMTState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

func (p *CGOProtocol) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.handle != nil {
		C.amt_gateway_free(p.handle)
		p.handle = nil
	}
	p.state = AMTStateClosed
}

// CGOVersion returns the Rust library version
func CGOVersion() string {
	return C.GoString(C.amt_version())
}
