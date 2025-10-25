// constants.js
// Shared constants for AMT Gateway Extension
// All modules should import from this file to avoid magic strings

// AMT Protocol Constants (RFC 7450)
export const AMT_DEFAULT_PORT = 2268;
export const AMT_ANYCAST_IPV4 = '192.52.193.1';
export const AMT_ANYCAST_IPV6 = '2001:3::1';

export const AMT_MSG_TYPE = {
  DISCOVERY: 1,
  ADVERTISEMENT: 2,
  REQUEST: 3,
  QUERY: 4,
  UPDATE: 5,
  DATA: 6,
  TEARDOWN: 7
};

// AMT Message Header Lengths
export const AMT_DATA_MSG_HDR_LEN = 2; // Type + Reserved byte

// Relay State Machine States
export const RELAY_STATE = {
  IDLE: 'IDLE',                    // No connection, no groups
  DISCOVERING: 'DISCOVERING',      // Sending Discovery messages
  CONNECTING: 'CONNECTING',        // Sent Request, awaiting Query
  ACTIVE: 'ACTIVE',                // Tunnel established, has groups
  IDLE_WAIT: 'IDLE_WAIT',         // No groups, grace period before teardown
  TEARDOWN: 'TEARDOWN',            // Sending teardown messages
  FAILED: 'FAILED'                 // Connection failed, needs recovery
};

// Message Types for Internal Communication
export const MSG_TYPE = {
  // Client subscription messages
  SUBSCRIBE: 'SUBSCRIBE',
  UNSUBSCRIBE: 'UNSUBSCRIBE',
  ACK: 'ACK',
  
  // WebRTC signaling
  WEBRTC_OFFER: 'webrtc-offer',
  WEBRTC_ANSWER: 'webrtc-answer',
  
  // Control messages
  DISCONNECT_RELAY: 'disconnect-relay',
  DISCONNECT_ALL: 'disconnect-all',
  
  // Notifications
  SHUTDOWN_INITIATED: 'shutdown-initiated',
  GROUP_LEFT: 'group-left',
  GROUP_LOST: 'group-lost',
  GROUP_UNAVAILABLE: 'group-unavailable',
  RELAY_STATE_CHANGED: 'relay-state-changed',
  HEALTH_CHANGED: 'health-changed'
};

// Configuration Defaults
export const DEFAULT_CONFIG = {
  // Timeouts
  IDLE_WAIT_TIMEOUT: 60000,         // 60 seconds grace before teardown
  SHUTDOWN_TIMEOUT: 3000,            // 3 seconds max for shutdown
  DISCOVERY_TIMEOUT: 1000,           // 1 second initial discovery timeout
  DISCOVERY_MAX_TIMEOUT: 120000,     // 120 seconds max discovery timeout
  REQUEST_TIMEOUT: 1000,             // 1 second initial request timeout
  REQUEST_MAX_TIMEOUT: 120000,       // 120 seconds max request timeout
  
  // IGMP/AMT Protocol
  QUERY_INTERVAL: 125000,            // 125 seconds (from IGMP Query)
  ROBUSTNESS_VARIABLE: 2,            // Default retries for IGMP messages
  
  // Health Monitoring
  HEALTH_CHECK_INTERVAL: 10000,      // 10 seconds between health checks
  PACKET_LOSS_THRESHOLD: 0.05,       // 5% packet loss = degraded
  MISSED_QUERIES_THRESHOLD: 2,       // 2 missed queries = degraded
  
  // Output Server Ports
  UDP_CONTROL_PORT: 5000,            // UDP subscription control port
  UDP_DATA_PORT: 0,                  // Ephemeral port for data
  TCP_HTTP_PORT: 5001,               // TCP/HTTP server port
  WEBTRANSPORT_PORT: 4433,           // WebTransport server port
  
  // Resource Management
  MAX_RELAYS: 10,                    // Maximum concurrent relay connections
  MAX_GROUPS_PER_RELAY: 100,         // Maximum groups per relay
  CLOSE_IDLE_RELAYS: true            // Delete IDLE relays from memory
};

// IGMPv3 Record Types (RFC 3376)
export const IGMP_RECORD_TYPE = {
  MODE_IS_INCLUDE: 1,                // Filter mode: include sources
  MODE_IS_EXCLUDE: 2,                // Filter mode: exclude sources
  CHANGE_TO_INCLUDE_MODE: 3,         // Change to include (leave)
  CHANGE_TO_EXCLUDE_MODE: 4,         // Change to exclude
  ALLOW_NEW_SOURCES: 5,              // Allow new sources
  BLOCK_OLD_SOURCES: 6               // Block old sources
};

// Health Status Values
export const HEALTH_STATUS = {
  GOOD: 'good',                      // All metrics healthy
  DEGRADED: 'degraded',              // Some packet loss or missed queries
  FAILED: 'failed'                   // Connection lost
};

// Shutdown Reasons (for logging and analytics)
export const SHUTDOWN_REASON = {
  USER_REQUEST: 'user-request',             // User clicked disconnect
  EXTENSION_SHUTDOWN: 'extension-shutdown', // Extension disabled/uninstalled
  RELAY_FAILED: 'relay-failed',             // Health check failure
  RELAY_SWITCHED: 'relay-switched',         // Switched to better relay
  IDLE_TIMEOUT: 'idle-timeout',             // IDLE_WAIT grace period expired
  FORCED_CLEANUP: 'forced-cleanup',         // Emergency cleanup
  BROWSER_CLOSING: 'browser-closing'        // Browser shutdown event
};

// Cleanup Reasons (for client notifications)
export const CLEANUP_REASON = {
  FORCED_CLEANUP: 'forced-cleanup',         // Emergency cleanup without protocol
  NORMAL_SHUTDOWN: 'normal-shutdown',       // Clean shutdown with Leave+Teardown
  CONNECTION_LOST: 'connection-lost',       // Network failure
  HEALTH_DEGRADED: 'health-degraded'       // Degraded health triggered cleanup
};

// Wildcard Constants
export const WILDCARD = {
  SOURCE: '*',                       // Any source (*,G)
  GROUP: '*',                        // Any group (promiscuous mode)
  PORT: '*'                          // Any port
};

// Default Values
export const DEFAULTS = {
  RELAY_NAME_PREFIX: 'relay',        // Prefix for auto-generated relay names
  RETRY_DELAY: 1000,                 // 1 second between retries
  MAX_RETRIES: 3,                    // Maximum retry attempts
  BUFFER_SIZE: 1500,                 // UDP buffer size (MTU)
  NONCE_SIZE: 4                      // AMT nonce size in bytes
};


