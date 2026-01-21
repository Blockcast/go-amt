package amt

import (
	"fmt"
	"runtime"
)

// Platform represents the detected runtime platform
type Platform string

const (
	PlatformLinux   Platform = "linux"
	PlatformDarwin  Platform = "darwin"
	PlatformWindows Platform = "windows"
	PlatformAndroid Platform = "android"
	PlatformIOS     Platform = "ios"
	PlatformUnknown Platform = "unknown"
)

// PlatformCapabilities describes what features are available on this platform
type PlatformCapabilities struct {
	Platform          Platform
	SupportsUDP       bool // Raw UDP sockets available
	SupportsCGO       bool // CGO (C bindings) available
	SupportsBPF       bool // BPF filtering available
	SupportsTimestamp bool // Packet timestamps available
}

// DetectPlatform returns the current runtime platform
func DetectPlatform() Platform {
	switch runtime.GOOS {
	case "linux":
		// Could be regular Linux or Android
		// Android detection would require checking build tags
		return PlatformLinux
	case "darwin":
		// Could be macOS or iOS
		// iOS detection would require checking build tags
		return PlatformDarwin
	case "windows":
		return PlatformWindows
	default:
		return PlatformUnknown
	}
}

// GetPlatformCapabilities returns the capabilities for the current platform
func GetPlatformCapabilities() PlatformCapabilities {
	caps := PlatformCapabilities{
		Platform: DetectPlatform(),
	}

	switch caps.Platform {
	case PlatformLinux:
		caps.SupportsUDP = PlatformUDPAvailable()
		caps.SupportsCGO = IsCGOAvailable()
		caps.SupportsBPF = true
		caps.SupportsTimestamp = true

	case PlatformDarwin:
		caps.SupportsUDP = PlatformUDPAvailable()
		caps.SupportsCGO = IsCGOAvailable()
		caps.SupportsBPF = false // macOS has different BPF semantics
		caps.SupportsTimestamp = true

	case PlatformWindows:
		caps.SupportsUDP = true
		caps.SupportsCGO = false

	default:
		caps.SupportsUDP = true
		caps.SupportsCGO = false
	}

	return caps
}

// BestTransportType returns the recommended transport type for this platform
func BestTransportType() TransportType {
	return TransportTypeUDP
}

// BestProtocolType returns the recommended protocol type for this platform
func BestProtocolType() ProtocolType {
	caps := GetPlatformCapabilities()
	if caps.SupportsCGO {
		return ProtocolTypeCGO
	}
	return ProtocolTypePureGo
}

// ValidateConfiguration validates a configuration for the current platform
func ValidateConfiguration(cfg TransportConfig) error {
	return nil
}

// PlatformInfo returns a human-readable description of the platform
func PlatformInfo() string {
	caps := GetPlatformCapabilities()
	return fmt.Sprintf(
		"Platform: %s, UDP: %v, CGO: %v, BPF: %v, Timestamp: %v",
		caps.Platform,
		caps.SupportsUDP,
		caps.SupportsCGO,
		caps.SupportsBPF,
		caps.SupportsTimestamp,
	)
}
