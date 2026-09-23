/**
 * Packet Parser for extracting (S,G) metadata from raw UDP packets
 * Used by Service Worker to forward packets with correct metadata to output servers
 */

/**
 * Parse AMT-encapsulated packet to extract (S,G) metadata
 * 
 * AMT Packet Structure:
 * - AMT Header (variable, typically 8-16 bytes)
 * - Encapsulated IP packet (multicast)
 *   - IP Header (20 bytes minimum)
 *     - Source IP (bytes 12-15)
 *     - Destination IP (bytes 16-19)
 *   - UDP Header (8 bytes)
 *     - Destination Port (bytes 2-3)
 * 
 * @param {Uint8Array} packet - Raw AMT packet
 * @returns {Object} { sourceIP, groupIP, port } or { sourceIP: null, groupIP: null, port: 0 } if parsing fails
 */
export function parsePacketMetadata(packet) {
  try {
    if (!packet || packet.length < 28) {
      // Too small to contain AMT + IP + UDP headers
      return { sourceIP: null, groupIP: null, port: 0 };
    }
    
    // AMT Header parsing
    // First byte contains type and version
    const amtType = packet[0] & 0x0F;
    
    // AMT Multicast Data message type is 6
    if (amtType !== 6) {
      // Not a data packet, might be control packet
      return { sourceIP: null, groupIP: null, port: 0 };
    }
    
    // AMT header size varies, but for Multicast Data it's typically 8 bytes
    // Format: Type(1) + Reserved(1) + IP header(var)
    let offset = 2; // Skip AMT type and reserved byte
    
    // The encapsulated packet starts after AMT header
    // Look for IP version marker (0x45 for IPv4)
    while (offset < packet.length - 28 && packet[offset] !== 0x45) {
      offset++;
    }
    
    if (offset >= packet.length - 28) {
      // Couldn't find IP header
      return { sourceIP: null, groupIP: null, port: 0 };
    }
    
    // Parse IP header (starts at offset)
    const ipHeaderStart = offset;
    
    // Check IP version (should be 4)
    const ipVersion = (packet[ipHeaderStart] >> 4) & 0x0F;
    if (ipVersion !== 4) {
      // Not IPv4
      return { sourceIP: null, groupIP: null, port: 0 };
    }
    
    // IP Header Length (IHL) in 32-bit words
    const ihl = packet[ipHeaderStart] & 0x0F;
    const ipHeaderLength = ihl * 4; // Convert to bytes
    
    // Extract Source IP (bytes 12-15 of IP header)
    const srcIP = [
      packet[ipHeaderStart + 12],
      packet[ipHeaderStart + 13],
      packet[ipHeaderStart + 14],
      packet[ipHeaderStart + 15]
    ].join('.');
    
    // Extract Destination IP (bytes 16-19 of IP header)
    const dstIP = [
      packet[ipHeaderStart + 16],
      packet[ipHeaderStart + 17],
      packet[ipHeaderStart + 18],
      packet[ipHeaderStart + 19]
    ].join('.');
    
    // UDP header starts after IP header
    const udpHeaderStart = ipHeaderStart + ipHeaderLength;
    
    if (udpHeaderStart + 8 > packet.length) {
      // Not enough data for UDP header
      return { sourceIP: srcIP, groupIP: dstIP, port: 0 };
    }
    
    // Extract UDP Destination Port (bytes 2-3 of UDP header, big-endian)
    const port = (packet[udpHeaderStart + 2] << 8) | packet[udpHeaderStart + 3];
    
    return {
      sourceIP: srcIP,
      groupIP: dstIP,
      port: port
    };
    
  } catch (error) {
    console.error('[PacketParser] Error parsing packet:', error);
    return { sourceIP: null, groupIP: null, port: 0 };
  }
}

/**
 * Check if an IP address is a multicast address
 * @param {string} ip - IP address string (e.g., "232.1.2.3")
 * @returns {boolean} true if multicast (224.0.0.0 to 239.255.255.255)
 */
export function isMulticastIP(ip) {
  if (!ip) return false;
  const firstOctet = parseInt(ip.split('.')[0]);
  return firstOctet >= 224 && firstOctet <= 239;
}

/**
 * Format (S,G) for logging
 * @param {string} sourceIP 
 * @param {string} groupIP 
 * @param {number} port 
 * @returns {string} Formatted string like "192.168.1.1@232.1.2.3:1234"
 */
export function formatSG(sourceIP, groupIP, port) {
  return `${sourceIP || '*'}@${groupIP || '*'}:${port || 0}`;
}

/**
 * Extract MPEG-TS payload from AMT-encapsulated packet
 * 
 * AMT Packet Structure:
 * - AMT Header (variable, typically 2-8 bytes)
 * - Encapsulated IP packet
 *   - IP Header (20+ bytes)
 *   - UDP Header (8 bytes)
 *   - MPEG-TS Payload (N * 188 bytes)
 * 
 * @param {Uint8Array} packet - Raw AMT packet
 * @returns {Uint8Array|null} Extracted TS payload, or null if invalid
 */
export function extractTSPayload(packet) {
  try {
    if (!packet || packet.length < 50) {
      // Too small to contain AMT + IP + UDP + TS (minimum)
      return null;
    }
    
    // Check AMT type (should be 6 for Multicast Data)
    const amtType = packet[0] & 0x0F;
    if (amtType !== 6) {
      // Not an AMT Multicast Data packet
      return null;
    }
    
    // Skip AMT header (typically 2 bytes: type + reserved)
    let offset = 2;
    
    // Find IP header (look for IPv4 marker 0x45)
    while (offset < packet.length - 28 && packet[offset] !== 0x45) {
      offset++;
    }
    
    if (offset >= packet.length - 28) {
      // Couldn't find IP header
      return null;
    }
    
    const ipHeaderStart = offset;
    
    // Get IP Header Length (IHL field in first byte, lower 4 bits)
    const ihl = packet[ipHeaderStart] & 0x0F;
    const ipHeaderLength = ihl * 4; // Convert to bytes
    
    // UDP header starts after IP header
    const udpHeaderStart = ipHeaderStart + ipHeaderLength;
    
    if (udpHeaderStart + 8 > packet.length) {
      // Not enough data for UDP header
      return null;
    }
    
    // UDP payload (TS data) starts after 8-byte UDP header
    const tsPayloadStart = udpHeaderStart + 8;
    
    if (tsPayloadStart >= packet.length) {
      // No payload
      return null;
    }
    
    // Extract TS payload
    const tsPayload = packet.subarray(tsPayloadStart);
    
    // Verify it looks like TS data (should start with 0x47 sync byte pattern)
    if (tsPayload.length > 0 && tsPayload[0] === 0x47) {
      // Verify multiple sync bytes at 188-byte intervals for confidence
      let syncCount = 0;
      for (let i = 0; i < Math.min(3, Math.floor(tsPayload.length / 188)); i++) {
        if (tsPayload[i * 188] === 0x47) {
          syncCount++;
        }
      }
      
      if (syncCount > 0) {
        return tsPayload;
      }
    }
    
    // If first check failed, maybe there's some padding before TS data
    // Search for first 0x47 within first 16 bytes
    for (let i = 0; i < Math.min(16, tsPayload.length); i++) {
      if (tsPayload[i] === 0x47 && tsPayload[i + 188] === 0x47) {
        // Found sync pattern, return from here
        return tsPayload.subarray(i);
      }
    }
    
    // Return payload anyway, let TS sync handle it
    return tsPayload;
    
  } catch (error) {
    console.error('[PacketParser] Error extracting TS payload:', error);
    return null;
  }
}


