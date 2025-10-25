/**
 * Preloaded AMT Stream Configuration
 * Source: https://menu.treedn.net/
 */

export const DEFAULT_RELAYS = [
  {
    id: 'gwu-1',
    address: '162.250.137.254',
    port: 2268,
    name: 'GWU-1'  // George Washington University AMT Relay (Verified working)
  },
  {
    id: 'gwu-2',
    address: '162.250.136.101',
    port: 2268,
    name: 'GWU-2'  // George Washington University AMT Relay
  }
];

export const PRELOADED_STREAMS = [
  {
    name: 'Infoshare: Precision Time Protocol (PTP) Issues',
    relay: 'gwu-1',  // amt://83.97.94.146@232.1.2.3:1234 --amt-relay 162.250.137.254
    source: '83.97.94.146',
    group: '232.1.2.3',
    port: 1234,
    category: 'Educational',
    url: 'https://menu.treedn.net/detail/330/'
  },
  {
    name: 'NSF Half hour-long Videos',
    relay: 'gwu-1',  // amt://162.250.138.201@232.162.250.143:5004 --amt-relay 162.250.137.254
    source: '162.250.138.201',
    group: '232.162.250.143',
    port: 5004,
    category: 'Educational',
    url: 'https://menu.treedn.net/detail/321/'
  },
  {
    name: 'NSF Hour-long Videos',
    relay: 'gwu-1',  // amt://162.250.138.201@232.162.250.144:5004 --amt-relay 162.250.137.254
    source: '162.250.138.201',
    group: '232.162.250.144',
    port: 5004,
    category: 'Educational',
    url: 'https://menu.treedn.net/detail/322/'
  },
  {
    name: 'Big Buck Bunny',
    relay: 'gwu-2',  // amt://162.250.138.201@232.162.250.138:1234 --amt-relay 162.250.136.101
    source: '162.250.138.201',
    group: '232.162.250.138',
    port: 1234,
    category: 'Video',
    verified: true,
    url: 'https://menu.treedn.net/detail/3/'
  },
  {
    name: 'Sintel Video Stream',
    relay: 'gwu-2',  // amt://162.250.138.201@232.162.250.140 --amt-relay 162.250.136.101
    source: '162.250.138.201',
    group: '232.162.250.140',
    port: 1234,
    category: 'Video',
    url: 'https://menu.treedn.net/detail/5/'
  },
  {
    name: 'Elephants Dream Video Stream',
    relay: 'gwu-2',  // amt://162.250.138.201@232.162.250.139 --amt-relay 162.250.136.101
    source: '162.250.138.201',
    group: '232.162.250.139',
    port: 1234,
    category: 'Video',
    url: 'https://menu.treedn.net/detail/2/'
  },
  {
    name: 'The Routing Table Podcast',
    relay: 'gwu-2',  // amt://162.250.138.201@232.162.250.141 --amt-relay 162.250.136.101
    source: '162.250.138.201',
    group: '232.162.250.141',
    port: 1234,
    category: 'Educational',
    url: 'https://menu.treedn.net/detail/1/'
  }
];

/**
 * Get relay by ID
 */
export function getRelayById(id) {
  return DEFAULT_RELAYS.find(r => r.id === id);
}

/**
 * Get streams by relay
 */
export function getStreamsByRelay(relayId) {
  return PRELOADED_STREAMS.filter(s => s.relay === relayId);
}

/**
 * Get all categories
 */
export function getCategories() {
  return [...new Set(PRELOADED_STREAMS.map(s => s.category))];
}

