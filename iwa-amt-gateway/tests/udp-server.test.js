// udp-server.test.js
// TEST FIRST: UDP output server with Direct Sockets
// Write tests BEFORE implementing the UDP server

const { test, expect } = require('@playwright/test');
const dgram = require('dgram');
const { installIWA, waitForServiceWorker, cleanup } = require('./test-helpers.cjs');

test.describe('UDP Output Server Tests', () => {
  let context;
  let page;
  let userDataDir;
  
  test.beforeEach(async () => {
    const result = await installIWA({ headless: false });
    context = result.context;
    page = result.page;
    userDataDir = result.userDataDir;
    
    await waitForServiceWorker(page);
  });
  
  test.afterEach(async () => {
    await cleanup(context, userDataDir);
  });
  
  test('UDP server starts on port 5000', async () => {
    // Check that UDP control socket is bound to port 5000
    const serverStatus = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => {
          resolve(event.data);
        };
        
        navigator.serviceWorker.controller.postMessage({
          type: 'GET_SERVER_STATUS'
        }, [channel.port2]);
        
        setTimeout(() => resolve({ error: 'Timeout' }), 5000);
      });
    });
    
    expect(serverStatus.udp).toBeDefined();
    expect(serverStatus.udp.enabled).toBe(true);
    expect(serverStatus.udp.controlPort).toBe(5000);
  });
  
  test('UDP server accepts subscription messages', async () => {
    // Create UDP client
    const client = dgram.createSocket('udp4');
    let receivedAck = false;
    let ackData = null;
    
    // Listen for ACK
    client.on('message', (msg) => {
      try {
        ackData = JSON.parse(msg.toString());
        if (ackData.type === 'ACK') {
          receivedAck = true;
        }
      } catch (err) {
        console.error('Failed to parse ACK:', err);
      }
    });
    
    // Bind to receive ACK
    await new Promise((resolve) => {
      client.bind(0, '127.0.0.1', resolve);
    });
    
    const clientPort = client.address().port;
    
    // Send SUBSCRIBE message
    const subscribe = JSON.stringify({
      type: 'SUBSCRIBE',
      source: '83.97.94.146',
      group: '232.1.2.3',
      port: 1234,
      clientPort: clientPort
    });
    
    client.send(subscribe, 5000, '127.0.0.1');
    
    // Wait for ACK
    await new Promise((resolve) => setTimeout(resolve, 1000));
    
    expect(receivedAck).toBe(true);
    expect(ackData).toBeDefined();
    expect(ackData.type).toBe('ACK');
    expect(ackData.subscribed).toBeDefined();
    expect(ackData.subscribed.source).toBe('83.97.94.146');
    expect(ackData.subscribed.group).toBe('232.1.2.3');
    
    client.close();
  });
  
  test('UDP server forwards packets to subscribed clients', async () => {
    // Create UDP client
    const client = dgram.createSocket('udp4');
    const receivedPackets = [];
    
    // Listen for data packets
    client.on('message', (msg) => {
      try {
        // Check if it's an ACK (JSON) or raw data
        const str = msg.toString();
        if (str.startsWith('{')) {
          // It's JSON (ACK), ignore
        } else {
          // It's raw data packet
          receivedPackets.push(msg);
        }
      } catch (err) {
        // Not JSON, it's raw data
        receivedPackets.push(msg);
      }
    });
    
    // Bind client
    await new Promise((resolve) => {
      client.bind(0, '127.0.0.1', resolve);
    });
    
    const clientPort = client.address().port;
    
    // Subscribe
    const subscribe = JSON.stringify({
      type: 'SUBSCRIBE',
      source: '*',
      group: '232.1.2.3',
      port: 1234,
      clientPort: clientPort
    });
    
    client.send(subscribe, 5000, '127.0.0.1');
    
    // Wait for subscription to be processed
    await new Promise((resolve) => setTimeout(resolve, 500));
    
    // Inject test packet from service worker
    const testPacket = new Uint8Array([0x47, 0x40, 0x11, 0x10]); // MPEG-TS sync byte + header
    await page.evaluate(async (packetData) => {
      return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => {
          resolve(event.data);
        };
        
        navigator.serviceWorker.controller.postMessage({
          type: 'INJECT_TEST_PACKET',
          data: {
            payload: Array.from(packetData),
            sourceIP: '83.97.94.146',
            groupIP: '232.1.2.3',
            groupPort: 1234
          }
        }, [channel.port2]);
      });
    }, Array.from(testPacket));
    
    // Wait for packet to be forwarded
    await new Promise((resolve) => setTimeout(resolve, 500));
    
    expect(receivedPackets.length).toBeGreaterThan(0);
    expect(receivedPackets[0][0]).toBe(0x47); // MPEG-TS sync byte
    
    client.close();
  });
  
  test('UDP server filters by source/group', async () => {
    // Create two clients with different subscriptions
    const client1 = dgram.createSocket('udp4');
    const client2 = dgram.createSocket('udp4');
    
    const packets1 = [];
    const packets2 = [];
    
    client1.on('message', (msg) => {
      if (msg[0] !== 123) { // Not JSON
        packets1.push(msg);
      }
    });
    
    client2.on('message', (msg) => {
      if (msg[0] !== 123) { // Not JSON
        packets2.push(msg);
      }
    });
    
    // Bind clients
    await Promise.all([
      new Promise((resolve) => client1.bind(0, '127.0.0.1', resolve)),
      new Promise((resolve) => client2.bind(0, '127.0.0.1', resolve))
    ]);
    
    // Subscribe client1 to group A
    const sub1 = JSON.stringify({
      type: 'SUBSCRIBE',
      source: '*',
      group: '232.1.2.3',
      port: 1234,
      clientPort: client1.address().port
    });
    
    // Subscribe client2 to group B
    const sub2 = JSON.stringify({
      type: 'SUBSCRIBE',
      source: '*',
      group: '232.1.2.4',
      port: 5678,
      clientPort: client2.address().port
    });
    
    client1.send(sub1, 5000, '127.0.0.1');
    client2.send(sub2, 5000, '127.0.0.1');
    
    await new Promise((resolve) => setTimeout(resolve, 500));
    
    // Inject packet for group A
    await page.evaluate(async () => {
      const testPacket = [0x47, 0x40, 0x11, 0x10];
      return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => resolve(event.data);
        
        navigator.serviceWorker.controller.postMessage({
          type: 'INJECT_TEST_PACKET',
          data: {
            payload: testPacket,
            sourceIP: '83.97.94.146',
            groupIP: '232.1.2.3',
            groupPort: 1234
          }
        }, [channel.port2]);
      });
    });
    
    await new Promise((resolve) => setTimeout(resolve, 500));
    
    // Client1 should receive packet, client2 should not
    expect(packets1.length).toBeGreaterThan(0);
    expect(packets2.length).toBe(0);
    
    client1.close();
    client2.close();
  });
  
  test('UDP server supports wildcard subscriptions', async () => {
    const client = dgram.createSocket('udp4');
    const receivedPackets = [];
    
    client.on('message', (msg) => {
      if (msg[0] !== 123) { // Not JSON
        receivedPackets.push(msg);
      }
    });
    
    await new Promise((resolve) => {
      client.bind(0, '127.0.0.1', resolve);
    });
    
    // Subscribe with wildcard source
    const subscribe = JSON.stringify({
      type: 'SUBSCRIBE',
      source: '*',
      group: '232.1.2.3',
      port: 1234,
      clientPort: client.address().port
    });
    
    client.send(subscribe, 5000, '127.0.0.1');
    
    await new Promise((resolve) => setTimeout(resolve, 500));
    
    // Inject packets from different sources
    await page.evaluate(async () => {
      const testPacket = [0x47, 0x40, 0x11, 0x10];
      
      // Source A
      await new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => resolve(event.data);
        
        navigator.serviceWorker.controller.postMessage({
          type: 'INJECT_TEST_PACKET',
          data: {
            payload: testPacket,
            sourceIP: '83.97.94.146',
            groupIP: '232.1.2.3',
            groupPort: 1234
          }
        }, [channel.port2]);
      });
      
      // Source B
      await new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => resolve(event.data);
        
        navigator.serviceWorker.controller.postMessage({
          type: 'INJECT_TEST_PACKET',
          data: {
            payload: testPacket,
            sourceIP: '162.250.138.201',
            groupIP: '232.1.2.3',
            groupPort: 1234
          }
        }, [channel.port2]);
      });
    });
    
    await new Promise((resolve) => setTimeout(resolve, 500));
    
    // Should receive packets from both sources
    expect(receivedPackets.length).toBeGreaterThanOrEqual(2);
    
    client.close();
  });
  
  test('UDP server handles unsubscribe', async () => {
    const client = dgram.createSocket('udp4');
    const receivedPackets = [];
    
    client.on('message', (msg) => {
      if (msg[0] !== 123) {
        receivedPackets.push(msg);
      }
    });
    
    await new Promise((resolve) => {
      client.bind(0, '127.0.0.1', resolve);
    });
    
    const clientPort = client.address().port;
    
    // Subscribe
    const subscribe = JSON.stringify({
      type: 'SUBSCRIBE',
      source: '*',
      group: '232.1.2.3',
      port: 1234,
      clientPort: clientPort
    });
    
    client.send(subscribe, 5000, '127.0.0.1');
    await new Promise((resolve) => setTimeout(resolve, 500));
    
    // Inject packet (should be received)
    await page.evaluate(async () => {
      const testPacket = [0x47, 0x40, 0x11, 0x10];
      return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => resolve(event.data);
        
        navigator.serviceWorker.controller.postMessage({
          type: 'INJECT_TEST_PACKET',
          data: {
            payload: testPacket,
            sourceIP: '83.97.94.146',
            groupIP: '232.1.2.3',
            groupPort: 1234
          }
        }, [channel.port2]);
      });
    });
    
    await new Promise((resolve) => setTimeout(resolve, 500));
    const packetsBeforeUnsub = receivedPackets.length;
    
    // Unsubscribe
    const unsubscribe = JSON.stringify({
      type: 'UNSUBSCRIBE',
      source: '*',
      group: '232.1.2.3'
    });
    
    client.send(unsubscribe, 5000, '127.0.0.1');
    await new Promise((resolve) => setTimeout(resolve, 500));
    
    // Inject another packet (should NOT be received)
    await page.evaluate(async () => {
      const testPacket = [0x47, 0x40, 0x11, 0x10];
      return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => resolve(event.data);
        
        navigator.serviceWorker.controller.postMessage({
          type: 'INJECT_TEST_PACKET',
          data: {
            payload: testPacket,
            sourceIP: '83.97.94.146',
            groupIP: '232.1.2.3',
            groupPort: 1234
          }
        }, [channel.port2]);
      });
    });
    
    await new Promise((resolve) => setTimeout(resolve, 500));
    
    // Should have received packet before unsubscribe but not after
    expect(packetsBeforeUnsub).toBeGreaterThan(0);
    expect(receivedPackets.length).toBe(packetsBeforeUnsub); // No new packets
    
    client.close();
  });
});

