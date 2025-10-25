// amt-url-parser.js
// Parse and validate AMT URLs (RFC-compliant format used by VLC)
// Format: amt://[source@]group:mediaport@relay:relayport

import { WILDCARD, AMT_DEFAULT_PORT } from './constants.js';

/**
 * Parse an AMT URL into its components
 * @param {string} amtUrl - AMT URL (e.g., "amt://83.97.94.146@232.1.2.3:1234@162.250.137.254:2268")
 * @returns {Object} Parsed components {source, group, mediaPort, relayIP, relayPort}
 * @throws {Error} If URL format is invalid
 */
export function parseAMTUrl(amtUrl) {
  if (!amtUrl || typeof amtUrl !== 'string') {
    throw new Error('Invalid AMT URL format: URL must be a non-empty string');
  }
  
  // Remove any whitespace
  amtUrl = amtUrl.trim();
  
  // Check protocol
  if (!amtUrl.startsWith('amt://')) {
    throw new Error('Invalid AMT URL format: must start with "amt://"');
  }
  
  // Remove protocol prefix
  const urlBody = amtUrl.substring(6); // Remove 'amt://'
  
  // Helper to parse address:port (handling IPv6 brackets)
  const parseAddressPort = (str) => {
    // Handle IPv6 with brackets: [2001:db8::1]:1234
    if (str.startsWith('[')) {
      const closeBracket = str.indexOf(']');
      if (closeBracket === -1) {
        throw new Error('IPv6 address missing closing bracket');
      }
      const addr = str.substring(1, closeBracket);
      const portPart = str.substring(closeBracket + 1);
      if (!portPart.startsWith(':')) {
        throw new Error('Missing port after IPv6 address');
      }
      const port = parseInt(portPart.substring(1), 10);
      return { addr, port };
    }
    
    // Handle IPv4 or hostname: 192.168.1.1:1234 or example.com:1234
    const lastColon = str.lastIndexOf(':');
    if (lastColon === -1) {
      throw new Error('Missing port separator ":"');
    }
    const addr = str.substring(0, lastColon);
    const port = parseInt(str.substring(lastColon + 1), 10);
    return { addr, port };
  };
  
  // Split by '@' to separate parts
  // Formats:
  // 1. source@group:mediaport@relay:relayport
  // 2. group:mediaport@relay:relayport (no source)
  // Handle brackets for IPv6
  const parts = urlBody.split('@').filter(p => p.length > 0);
  
  let source, groupAndPort, relayAndPort;
  
  // Count non-bracketed @ symbols to determine format
  const atCount = (urlBody.match(/@(?![^\[]*\])/g) || []).length;
  
  if (atCount === 2 || parts.length === 3) {
    // SSM: source@group:port@relay:port
    if (parts[0].startsWith('[')) {
      // IPv6 source
      source = parts[0].substring(1, parts[0].indexOf(']'));
      groupAndPort = urlBody.substring(parts[0].length + 1).split('@')[0];
      relayAndPort = urlBody.substring(parts[0].length + 1).split('@')[1];
    } else {
      [source, groupAndPort, relayAndPort] = parts;
    }
  } else if (atCount === 1 || parts.length === 2) {
    // ASM: group:port@relay:port (no source)
    source = WILDCARD.SOURCE;
    [groupAndPort, relayAndPort] = parts;
  } else {
    throw new Error('Invalid AMT URL format: incorrect number of @ separators');
  }
  
  // Parse group and media port
  const groupParsed = parseAddressPort(groupAndPort);
  const group = groupParsed.addr;
  const mediaPort = groupParsed.port;
  
  // Parse relay and relay port
  const relayParsed = parseAddressPort(relayAndPort);
  const relayIP = relayParsed.addr;
  const relayPort = relayParsed.port;
  
  // Validate port numbers
  if (mediaPort < 1 || mediaPort > 65535) {
    throw new Error(`Invalid media port: ${mediaPort} (must be 1-65535)`);
  }
  if (relayPort < 1 || relayPort > 65535) {
    throw new Error(`Invalid relay port: ${relayPort} (must be 1-65535)`);
  }
  
  // Validate IP addresses (basic validation)
  if (source !== WILDCARD.SOURCE && !isValidIPOrHostname(source)) {
    throw new Error(`Invalid source IP address: ${source}`);
  }
  if (!isValidIPOrHostname(group)) {
    throw new Error(`Invalid group address: ${group}`);
  }
  if (!isValidIPOrHostname(relayIP)) {
    throw new Error(`Invalid relay IP address: ${relayIP}`);
  }
  
  return {
    source,
    group,
    mediaPort,
    relayIP,
    relayPort
  };
}

/**
 * Validate if a string is a valid IP address or hostname
 * @param {string} addr - Address to validate
 * @returns {boolean} True if valid
 */
function isValidIPOrHostname(addr) {
  if (!addr || typeof addr !== 'string') {
    return false;
  }
  
  // Check for valid IPv4 (each octet must be 0-255)
  if (!addr.includes(':')) { // Not IPv6
    const ipv4Parts = addr.split('.');
    if (ipv4Parts.length === 4) {
      const allValid = ipv4Parts.every(part => {
        // Must not have leading zeros (except "0" itself)
        if (part.length > 1 && part[0] === '0') {
          return false;
        }
        const num = parseInt(part, 10);
        // Must be a valid number, in range, and string must match number
        return !isNaN(num) && num >= 0 && num <= 255 && part === String(num);
      });
      if (allValid) {
        return true;
      }
      // If we have 4 parts but validation failed, it's not a valid IPv4
      // Don't continue to check as hostname
      return false;
    }
  }
  
  // Check for valid IPv6 (simplified - just check structure)
  if (addr.includes(':')) {
    const parts = addr.split(':');
    // IPv6 should have 3-8 parts
    if (parts.length >= 3 && parts.length <= 8) {
      // Each part should be valid hex (0-4 digits) or empty (for ::)
      const allValid = parts.every(part => 
        part === '' || /^[0-9a-fA-F]{1,4}$/.test(part)
      );
      return allValid;
    }
    return false;
  }
  
  // Check for valid hostname (must have at least one dot for FQDN)
  // Single-label hostnames like "localhost" are allowed without dots
  const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/;
  if (hostnameRegex.test(addr)) {
    return true;
  }
  
  // Allow "localhost" as special case
  if (addr === 'localhost') {
    return true;
  }
  
  return false;
}

/**
 * Format AMT URL components into standard AMT URL string
 * @param {Object} components - {source, group, mediaPort, relayIP, relayPort}
 * @returns {string} Formatted AMT URL
 */
export function formatAMTUrl({ source, group, mediaPort, relayIP, relayPort }) {
  const groupPart = `${group}:${mediaPort}`;
  const relayPart = `${relayIP}:${relayPort}`;
  
  if (source && source !== WILDCARD.SOURCE) {
    // SSM: include source
    return `amt://${source}@${groupPart}@${relayPart}`;
  } else {
    // ASM: omit source
    return `amt://${groupPart}@${relayPart}`;
  }
}

/**
 * Validate an AMT URL without throwing exceptions
 * @param {string} amtUrl - AMT URL to validate
 * @returns {boolean} True if valid, false otherwise
 */
export function validateAMTUrl(amtUrl) {
  try {
    parseAMTUrl(amtUrl);
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Extract relay address from AMT URL
 * @param {string} amtUrl - AMT URL
 * @returns {Object} {ip, port} or null if invalid
 */
export function extractRelayAddress(amtUrl) {
  try {
    const parsed = parseAMTUrl(amtUrl);
    return {
      ip: parsed.relayIP,
      port: parsed.relayPort
    };
  } catch (error) {
    return null;
  }
}

/**
 * Extract group subscription from AMT URL
 * @param {string} amtUrl - AMT URL
 * @returns {Object} {source, group, port} or null if invalid
 */
export function extractGroupSubscription(amtUrl) {
  try {
    const parsed = parseAMTUrl(amtUrl);
    return {
      source: parsed.source,
      group: parsed.group,
      port: parsed.mediaPort
    };
  } catch (error) {
    return null;
  }
}

/**
 * Check if AMT URL specifies SSM (Source-Specific Multicast)
 * @param {string} amtUrl - AMT URL
 * @returns {boolean} True if SSM (has explicit source), false if ASM
 */
export function isSSM(amtUrl) {
  try {
    const parsed = parseAMTUrl(amtUrl);
    return parsed.source !== WILDCARD.SOURCE;
  } catch (error) {
    return false;
  }
}

/**
 * Generate a human-readable description of an AMT URL
 * @param {string} amtUrl - AMT URL
 * @returns {string} Human-readable description
 */
export function describeAMTUrl(amtUrl) {
  try {
    const parsed = parseAMTUrl(amtUrl);
    const sourceDesc = parsed.source === WILDCARD.SOURCE ? 'Any Source' : parsed.source;
    return `${sourceDesc} → ${parsed.group}:${parsed.mediaPort} via ${parsed.relayIP}:${parsed.relayPort}`;
  } catch (error) {
    return 'Invalid AMT URL';
  }
}

