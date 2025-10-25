/**
 * MPEG-TS Stream Synchronizer
 * Handles initial sync when joining mid-stream and ensures clean decoder state
 */

/**
 * Find the first TS sync byte (0x47) in packet data
 * MPEG-TS packets MUST start with 0x47 every 188 bytes
 * 
 * @param {Uint8Array} data - Raw packet data
 * @returns {number} Offset of first sync byte, or -1 if not found
 */
export function findTSSyncByte(data) {
  // Look for 0x47 pattern repeated at 188-byte intervals
  const TS_PACKET_SIZE = 188;
  const SYNC_BYTE = 0x47;
  const MIN_VERIFICATIONS = 3; // Require 3 consecutive sync bytes for confidence
  
  for (let i = 0; i < data.length - TS_PACKET_SIZE * MIN_VERIFICATIONS; i++) {
    if (data[i] === SYNC_BYTE) {
      // Verify this is real sync by checking multiple packets
      let isValid = true;
      for (let j = 1; j < MIN_VERIFICATIONS; j++) {
        const nextOffset = i + (TS_PACKET_SIZE * j);
        if (nextOffset >= data.length || data[nextOffset] !== SYNC_BYTE) {
          isValid = false;
          break;
        }
      }
      
      if (isValid) {
        // Found valid sync pattern with multiple verifications!
        return i;
      }
    }
  }
  
  return -1; // No sync found
}

/**
 * Check if TS packet contains a Random Access Indicator (RAI)
 * RAI = 1 means this packet starts a new access point (typically I-frame)
 * 
 * MPEG-TS Adaptation Field Format:
 * Byte 0: Sync byte (0x47)
 * Byte 1-2: Transport Error, PUSI, Priority, PID
 * Byte 3: Scrambling, Adaptation field control, Continuity counter
 * Byte 4: (if adaptation field) Adaptation field length
 * Byte 5: (if adaptation field) Flags including RAI
 * 
 * @param {Uint8Array} tsPacket - Single 188-byte TS packet
 * @returns {boolean} True if packet has RAI set (starts access point)
 */
export function hasRandomAccessIndicator(tsPacket) {
  if (tsPacket.length < 188 || tsPacket[0] !== 0x47) {
    return false;
  }
  
  // Check adaptation field control (bits 4-5 of byte 3)
  const adaptationFieldControl = (tsPacket[3] >> 4) & 0x03;
  
  // 0x02 = adaptation field only, 0x03 = adaptation field + payload
  if (adaptationFieldControl === 0x02 || adaptationFieldControl === 0x03) {
    const adaptationFieldLength = tsPacket[4];
    
    if (adaptationFieldLength > 0) {
      // Check RAI flag (bit 6 of byte 5)
      const flags = tsPacket[5];
      const randomAccessIndicator = (flags >> 6) & 0x01;
      return randomAccessIndicator === 1;
    }
  }
  
  return false;
}

/**
 * Check if TS packet has Payload Unit Start Indicator (PUSI)
 * PUSI = 1 means this packet starts a new PES packet (frame boundary)
 * 
 * @param {Uint8Array} tsPacket - Single 188-byte TS packet
 * @returns {boolean} True if PUSI is set
 */
export function hasPayloadUnitStartIndicator(tsPacket) {
  if (tsPacket.length < 188 || tsPacket[0] !== 0x47) {
    return false;
  }
  
  // PUSI is bit 6 of byte 1
  const pusi = (tsPacket[1] >> 6) & 0x01;
  return pusi === 1;
}

/**
 * Extract PID from TS packet
 * PID identifies the stream type (PAT=0, PMT varies, video/audio PIDs)
 * 
 * @param {Uint8Array} tsPacket - Single 188-byte TS packet
 * @returns {number} PID (0-8191)
 */
export function extractPID(tsPacket) {
  if (tsPacket.length < 188 || tsPacket[0] !== 0x47) {
    return -1;
  }
  
  // PID is in bytes 1-2 (13 bits)
  const pid = ((tsPacket[1] & 0x1F) << 8) | tsPacket[2];
  return pid;
}

/**
 * Split buffer into individual TS packets and analyze
 * 
 * @param {Uint8Array} data - Raw packet data (multiple TS packets)
 * @returns {Object} Analysis results
 */
export function analyzeTSStream(data) {
  const TS_PACKET_SIZE = 188;
  const packets = [];
  let syncOffset = findTSSyncByte(data);
  
  if (syncOffset === -1) {
    return {
      synced: false,
      error: 'No TS sync byte found',
      packets: []
    };
  }
  
  // Extract packets starting from sync point
  // IMPORTANT: Once we have strong sync (3-packet verification), trust it!
  // Don't re-sync during parsing - UDP boundaries can make bytes look out of sync
  let offset = syncOffset;
  while (offset + TS_PACKET_SIZE <= data.length) {
    const tsPacket = data.subarray(offset, offset + TS_PACKET_SIZE);
    
    // Note: We don't check tsPacket[0] === 0x47 here because:
    // 1. We already did strong 3-packet verification at syncOffset
    // 2. UDP packet boundaries can make mid-stream bytes != 0x47
    // 3. Trust the initial sync and just parse 188-byte chunks
    
    const pid = extractPID(tsPacket);
    const pusi = hasPayloadUnitStartIndicator(tsPacket);
    const rai = hasRandomAccessIndicator(tsPacket);
    
    packets.push({
      offset,
      pid,
      pusi,
      rai,
      isPAT: pid === 0,
      data: tsPacket
    });
    
    offset += TS_PACKET_SIZE;
  }
  
  // Check if we have PAT (required for stream structure)
  const hasPAT = packets.some(p => p.isPAT);
  
  // Check if we have any RAI packets (keyframes)
  const hasKeyframe = packets.some(p => p.rai);
  
  return {
    synced: true,
    syncOffset,
    totalPackets: packets.length,
    hasPAT,
    hasKeyframe,
    firstKeyframeIndex: packets.findIndex(p => p.rai),
    packets,
    // For discarding data before first keyframe
    bytesBeforeKeyframe: hasKeyframe 
      ? packets.find(p => p.rai).offset - syncOffset
      : -1
  };
}

/**
 * Sanitize TS stream by finding sync and discarding data before first keyframe
 * This ensures clean decoder start state
 * 
 * Fallback strategy if encoder doesn't set RAI flags:
 * 1. Try to find RAI (proper keyframe marker)
 * 2. Fall back to PUSI (Payload Unit Start Indicator)
 * 3. Last resort: use first packet with PAT
 * 
 * @param {Uint8Array} data - Raw packet data
 * @param {boolean} allowPUSIFallback - If true, allow starting from PUSI when no RAI found
 * @returns {Uint8Array} Sanitized data starting at best sync point (or null if no sync)
 */
export function sanitizeTSStream(data, allowPUSIFallback = false) {
  const analysis = analyzeTSStream(data);
  
  if (!analysis.synced) {
    console.warn('[TS Sync] Cannot sanitize: no sync found');
    return null;
  }
  
  // Preferred: Start from keyframe (RAI)
  if (analysis.hasKeyframe) {
    const firstKeyframePacket = analysis.packets[analysis.firstKeyframeIndex];
    const startOffset = firstKeyframePacket.offset;
    
    console.log(`[TS Sync] Found keyframe at packet ${analysis.firstKeyframeIndex}/${analysis.totalPackets}, discarding ${startOffset} bytes`);
    
    return data.subarray(startOffset);
  }
  
  // Fallback 1: Start from PUSI (at least starts at packet boundary)
  if (allowPUSIFallback) {
    // Log packet analysis to help debug
    const videoPackets = analysis.packets.filter(p => !p.isPAT && p.pid > 0 && p.pid < 0x1FFF);
    const pusiPackets = analysis.packets.filter(p => p.pusi);
    const raiPackets = analysis.packets.filter(p => p.rai);
    
    console.warn(`[TS Sync] Stream analysis: ${analysis.totalPackets} packets, ${videoPackets.length} video, ${pusiPackets.length} PUSI, ${raiPackets.length} RAI`);
    
    const firstPUSI = analysis.packets.find(p => p.pusi);
    if (firstPUSI) {
      const pusiIndex = analysis.packets.indexOf(firstPUSI);
      console.warn(`[TS Sync] No RAI found, falling back to PUSI at packet ${pusiIndex}/${analysis.totalPackets} (PID: ${firstPUSI.pid})`);
      return data.subarray(firstPUSI.offset);
    }
    
    // Fallback 2: Start from PAT (always safe to start from PAT)
    if (analysis.hasPAT) {
      const firstPAT = analysis.packets.find(p => p.isPAT);
      console.warn(`[TS Sync] No RAI/PUSI, falling back to PAT at packet ${analysis.packets.indexOf(firstPAT)}/${analysis.totalPackets}`);
      return data.subarray(firstPAT.offset);
    }
    
    // Fallback 3: Just start from first synced packet (last resort)
    console.warn(`[TS Sync] No RAI/PUSI/PAT markers, starting from first synced packet (THIS WILL LIKELY FAIL)`);
    return data.subarray(analysis.syncOffset);
  }
  
  // No keyframe and fallback not allowed
  console.warn('[TS Sync] No keyframe found in buffer, waiting for RAI packet...');
  return null;
}

/**
 * Check if buffer is TS-aligned (starts with sync byte, size is multiple of 188)
 * 
 * @param {Uint8Array} data - Packet data
 * @returns {boolean} True if properly aligned
 */
export function isTSAligned(data) {
  const TS_PACKET_SIZE = 188;
  return data.length > 0 && 
         data[0] === 0x47 && 
         data.length % TS_PACKET_SIZE === 0;
}

