/**
 * AMT Protocol Library - C FFI
 *
 * Automatic Multicast Tunneling (RFC 7450) implementation.
 *
 * Usage:
 *   1. Create gateway: amt_gateway_new()
 *   2. Protocol operations: start_discovery, handle_advertisement, etc.
 *   3. Free resources: amt_gateway_free(), amt_buffer_free()
 *
 * Memory Management:
 *   - Gateway handles must be freed with amt_gateway_free()
 *   - AmtBuffer data must be freed with amt_buffer_free()
 *   - Strings from amt_driad_build_query must be freed with amt_string_free()
 */

#ifndef AMT_PROTOCOL_H
#define AMT_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Types
 * ============================================================================ */

/**
 * Opaque handle to AMT Gateway instance.
 * Created with amt_gateway_new(), freed with amt_gateway_free().
 */
typedef void* amt_gateway_handle_t;

/**
 * Result codes for FFI functions.
 */
typedef enum {
    /** Operation succeeded */
    AMT_RESULT_OK = 0,
    /** Invalid argument provided */
    AMT_RESULT_INVALID_ARGUMENT = 1,
    /** Invalid state for operation */
    AMT_RESULT_INVALID_STATE = 2,
    /** Invalid nonce in response */
    AMT_RESULT_INVALID_NONCE = 3,
    /** No response MAC available */
    AMT_RESULT_NO_RESPONSE_MAC = 4,
    /** Message decode error */
    AMT_RESULT_DECODE_ERROR = 5,
    /** Memory allocation error */
    AMT_RESULT_ALLOCATION_ERROR = 6,
    /** Null pointer provided */
    AMT_RESULT_NULL_POINTER = 7,
    /** Unknown error */
    AMT_RESULT_UNKNOWN = 99,
} amt_result_t;

/**
 * Gateway state values.
 */
typedef enum {
    AMT_STATE_IDLE = 0,
    AMT_STATE_DISCOVERING = 1,
    AMT_STATE_REQUESTING = 2,
    AMT_STATE_QUERYING = 3,
    AMT_STATE_ACTIVE = 4,
    AMT_STATE_CLOSED = 5,
} amt_gateway_state_t;

/**
 * Buffer returned from FFI functions.
 * Must be freed with amt_buffer_free().
 */
typedef struct {
    uint8_t* data;
    size_t len;
    size_t capacity;
} amt_buffer_t;

/* ============================================================================
 * Gateway Lifecycle
 * ============================================================================ */

/**
 * Create a new AMT Gateway.
 *
 * @param relay_address Null-terminated C string with relay IP address
 * @param relay_port Relay port (use 0 for default 2268)
 * @param enable_driad Enable DRIAD discovery
 * @param out_handle Pointer to receive gateway handle
 * @return AMT_RESULT_OK on success
 */
amt_result_t amt_gateway_new(
    const char* relay_address,
    uint16_t relay_port,
    bool enable_driad,
    amt_gateway_handle_t* out_handle
);

/**
 * Free an AMT Gateway.
 *
 * @param handle Gateway handle from amt_gateway_new()
 */
void amt_gateway_free(amt_gateway_handle_t handle);

/**
 * Free a buffer returned from FFI functions.
 *
 * @param buffer Buffer to free
 */
void amt_buffer_free(amt_buffer_t buffer);

/* ============================================================================
 * Gateway State
 * ============================================================================ */

/**
 * Get current gateway state.
 *
 * @param handle Gateway handle
 * @return Current state
 */
amt_gateway_state_t amt_gateway_state(amt_gateway_handle_t handle);

/**
 * Get current relay port.
 *
 * @param handle Gateway handle
 * @return Relay port
 */
uint16_t amt_gateway_relay_port(amt_gateway_handle_t handle);

/* ============================================================================
 * Protocol Operations
 * ============================================================================ */

/**
 * Start relay discovery.
 *
 * @param handle Gateway handle
 * @param out_message Pointer to receive encoded message buffer
 * @return AMT_RESULT_OK on success
 */
amt_result_t amt_gateway_start_discovery(
    amt_gateway_handle_t handle,
    amt_buffer_t* out_message
);

/**
 * Handle relay advertisement response.
 *
 * @param handle Gateway handle
 * @param data Advertisement message bytes
 * @param len Length of data
 * @return AMT_RESULT_OK on success
 */
amt_result_t amt_gateway_handle_advertisement(
    amt_gateway_handle_t handle,
    const uint8_t* data,
    size_t len
);

/**
 * Request membership.
 *
 * @param handle Gateway handle
 * @param p_flag Prefer native multicast flag
 * @param out_message Pointer to receive encoded message buffer
 * @return AMT_RESULT_OK on success
 */
amt_result_t amt_gateway_request_membership(
    amt_gateway_handle_t handle,
    bool p_flag,
    amt_buffer_t* out_message
);

/**
 * Handle membership query response.
 *
 * @param handle Gateway handle
 * @param data Query message bytes
 * @param len Length of data
 * @param out_query_data Pointer to receive IGMP/MLD query data
 * @return AMT_RESULT_OK on success
 */
amt_result_t amt_gateway_handle_query(
    amt_gateway_handle_t handle,
    const uint8_t* data,
    size_t len,
    amt_buffer_t* out_query_data
);

/**
 * Send membership update.
 *
 * @param handle Gateway handle
 * @param report_data IGMP/MLD report bytes
 * @param report_len Length of report data
 * @param out_message Pointer to receive encoded message buffer
 * @return AMT_RESULT_OK on success
 */
amt_result_t amt_gateway_send_update(
    amt_gateway_handle_t handle,
    const uint8_t* report_data,
    size_t report_len,
    amt_buffer_t* out_message
);

/**
 * Handle multicast data.
 *
 * @param handle Gateway handle
 * @param data Data message bytes
 * @param len Length of data
 * @param out_packet Pointer to receive IP packet
 * @return AMT_RESULT_OK on success
 */
amt_result_t amt_gateway_handle_data(
    amt_gateway_handle_t handle,
    const uint8_t* data,
    size_t len,
    amt_buffer_t* out_packet
);

/**
 * Send teardown message.
 *
 * @param handle Gateway handle
 * @param out_message Pointer to receive encoded message buffer
 * @return AMT_RESULT_OK on success
 */
amt_result_t amt_gateway_send_teardown(
    amt_gateway_handle_t handle,
    amt_buffer_t* out_message
);

/**
 * Reset gateway to idle state.
 *
 * @param handle Gateway handle
 */
void amt_gateway_reset(amt_gateway_handle_t handle);

/* ============================================================================
 * DRIAD Support
 * ============================================================================ */

/**
 * Build DRIAD query name for source address.
 *
 * @param source_address Null-terminated C string with source IP address
 * @param out_query Pointer to receive query name (null-terminated)
 * @return AMT_RESULT_OK on success
 *
 * @note Caller must free the returned string with amt_string_free()
 */
amt_result_t amt_driad_build_query(
    const char* source_address,
    char** out_query
);

/**
 * Free a string returned from FFI functions.
 *
 * @param s String to free
 */
void amt_string_free(char* s);

/* ============================================================================
 * IGMP Report Generation
 * ============================================================================ */

/**
 * Create an IGMPv3 SSM join report with IP encapsulation.
 *
 * Creates a complete IP-encapsulated IGMPv3 membership report for joining
 * a source-specific multicast group.
 *
 * @param source_address Null-terminated C string with multicast source IP (IPv4)
 * @param group_address Null-terminated C string with multicast group IP (IPv4)
 * @param out_report Pointer to receive encoded report buffer
 * @return AMT_RESULT_OK on success
 *
 * @note Caller must free the returned buffer with amt_buffer_free()
 */
amt_result_t amt_igmp_ssm_join(
    const char* source_address,
    const char* group_address,
    amt_buffer_t* out_report
);

/**
 * Create an IGMPv3 multi-group SSM join report with IP encapsulation.
 *
 * Creates a complete IP-encapsulated IGMPv3 membership report for joining
 * multiple source-specific multicast groups from the same source.
 *
 * @param source_address Null-terminated C string with multicast source IP (IPv4)
 * @param group_addresses Array of null-terminated C strings with group IPs
 * @param num_groups Number of groups in the array
 * @param out_report Pointer to receive encoded report buffer
 * @return AMT_RESULT_OK on success
 *
 * @note Caller must free the returned buffer with amt_buffer_free()
 */
amt_result_t amt_igmp_ssm_join_multi(
    const char* source_address,
    const char* const* group_addresses,
    size_t num_groups,
    amt_buffer_t* out_report
);

/* ============================================================================
 * Version Info
 * ============================================================================ */

/**
 * Get library version.
 *
 * @return Null-terminated C string with version (static, do not free)
 */
const char* amt_version(void);

#ifdef __cplusplus
}
#endif

#endif /* AMT_PROTOCOL_H */
