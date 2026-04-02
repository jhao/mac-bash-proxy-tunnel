import fs from 'node:fs';
import net from 'node:net';
import { URL } from 'node:url';
import { parseArgs, required } from './args.js';
import { createSessionKey, rsaEncryptSessionKey, encryptPacket, decryptPacket } from './crypto.js';
import { encodeFrame, createFrameDecoder } from './framing.js';

const args = parseArgs(process.argv.slice(2));
const address = required(args, 'address');
const port = Number(required(args, 'port'));
const pubkeyPath = required(args, 'pubkey');
const localPort = Number(args['local-port'] || 8890);

const serverPublicKey = fs.readFileSync(pubkeyPath, 'utf8');

class TunnelClient {
  constructor() {
    this.socket = null;
    this.sessionKey = null;
    this.token = null;
    this.connected = false;
    this.connectPromise = null;
    this.reconnectTimer = null;
    this.streamCounter = 1;
    this.streams = new Map();
    this.pendingOpen = new Map();
    this.pendingPings = new Map();
  }

  async connect() {
    if (this.connectPromise) return this.connectPromise;
    this.connectPromise = this.#connectInternal().finally(() => {
      this.connectPromise = null;
    });
    return this.connectPromise;
  }

  async #connectInternal() {
    this.socket = net.connect(port, address);
    await onceEvent(this.socket, 'connect');

    this.sessionKey = createSessionKey();
    this.token = null;
    const encrypted = rsaEncryptSessionKey(this.sessionKey, serverPublicKey).toString('base64');
    this.socket.write(encodeFrame({ type: 'auth_init', encryptedSessionKey: encrypted }));

    const decoder = createFrameDecoder((frame) => {
      if (!this.token && frame.type === 'auth_ok') {
        this.requestToken();
        return;
      }

      if (!this.sessionKey || !frame.iv) return;
      const msg = decryptPacket(frame, this.sessionKey);
      this.onMessage(msg);
    });

    this.socket.on('data', decoder);
    this.socket.on('error', (err) => this.onDisconnect('error', err));
    this.socket.on('close', () => this.onDisconnect('close'));

    await this.waitForToken();
    this.connected = true;
    console.log('[client] handshake complete, token acquired');
  }

  waitForToken() {
    return new Promise((resolve) => {
      const timer = setInterval(() => {
        if (this.token) {
          clearInterval(timer);
          resolve();
        }
      }, 50);
    });
  }

  requestToken() {
    this.sendSecure({ type: 'token_request' }, false);
  }

  sendSecure(message, includeToken = true) {
    if (!this.socket || this.socket.destroyed) {
      throw new Error('Tunnel socket is not connected');
    }
    if (includeToken && !this.connected) {
      throw new Error('Tunnel socket is not connected');
    }
    const payload = includeToken ? { ...message, token: this.token } : message;
    const packet = encryptPacket(payload, this.sessionKey);
    this.socket.write(encodeFrame(packet));
  }

  onDisconnect(event, err) {
    if (!this.connected && !this.socket) return;
    if (event === 'error' && err) {
      console.error('[client] tunnel error:', err.message);
    } else {
      console.error('[client] tunnel closed');
    }
    this.connected = false;
    if (this.socket) {
      this.socket.removeAllListeners();
      this.socket.destroy();
    }
    this.socket = null;
    this.sessionKey = null;
    this.token = null;

    for (const [id, resolve] of this.pendingOpen.entries()) {
      this.pendingOpen.delete(id);
      resolve({ ok: false, error: 'Tunnel disconnected' });
    }
    for (const [id, resolve] of this.pendingPings.entries()) {
      this.pendingPings.delete(id);
      resolve(false);
    }
    for (const [id, stream] of this.streams.entries()) {
      this.streams.delete(id);
      stream.local.destroy(new Error('Tunnel disconnected'));
    }

    if (!this.reconnectTimer) {
      this.reconnectTimer = setTimeout(() => {
        this.reconnectTimer = null;
        this.reconnectLoop();
      }, 2000);
    }
  }

  async reconnectLoop() {
    while (!this.connected) {
      try {
        console.log('[client] attempting to reconnect tunnel...');
        await this.connect();
        console.log('[client] tunnel reconnected');
        return;
      } catch (err) {
        console.error('[client] reconnect failed:', err.message);
        await sleep(2000);
      }
    }
  }

  async ensureConnected() {
    if (this.connected) return;
    await this.connect();
  }

  onMessage(msg) {
    if (msg.type === 'token') {
      this.token = msg.token;
      return;
    }

    if (msg.type === 'token_invalid') {
      this.token = msg.token;
      if (msg.requestId && this.pendingPings.has(msg.requestId)) {
        // let ping timeout fallback handle it
      }
      return;
    }

    if (msg.type === 'health_pong') {
      const fn = this.pendingPings.get(msg.requestId);
      if (fn) {
        this.pendingPings.delete(msg.requestId);
        fn(true);
      }
      return;
    }

    if (msg.type === 'open_tcp_result') {
      const pending = this.pendingOpen.get(msg.streamId);
      if (pending) {
        this.pendingOpen.delete(msg.streamId);
        pending(msg);
      }
      return;
    }

    const stream = this.streams.get(msg.streamId);
    if (!stream) return;

    if (msg.type === 'tcp_data') {
      stream.noteResponse();
      stream.local.write(Buffer.from(msg.data, 'base64'));
      return;
    }

    if (msg.type === 'tcp_end') {
      stream.local.end();
      this.streams.delete(msg.streamId);
      return;
    }

    if (msg.type === 'tcp_error') {
      stream.local.destroy(new Error(msg.error));
      this.streams.delete(msg.streamId);
    }
  }

  async pingHealth() {
    if (!this.connected) return false;
    const requestId = `ping-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        this.pendingPings.delete(requestId);
        resolve(false);
      }, 5000);
      this.pendingPings.set(requestId, (ok) => {
        clearTimeout(timeout);
        resolve(ok);
      });
      this.sendSecure({ type: 'health_ping', requestId });
    });
  }

  async openTcp(host, targetPort, localSocket, initialData) {
    await this.ensureConnected();
    const streamId = this.streamCounter++;

    const result = await new Promise((resolve) => {
      this.pendingOpen.set(streamId, resolve);
      this.sendSecure({ type: 'open_tcp', streamId, host, port: targetPort });
    });

    if (!result.ok) {
      throw new Error(result.error || 'Failed to open remote stream');
    }

    const state = new StreamState(streamId, localSocket, this);
    this.streams.set(streamId, state);

    if (initialData?.length) {
      this.sendTcpData(streamId, initialData);
      state.noteSent();
    }

    localSocket.on('data', (chunk) => {
      this.sendTcpData(streamId, chunk);
      state.noteSent();
    });

    localSocket.on('end', () => {
      if (this.connected) this.sendSecure({ type: 'tcp_end', streamId });
      this.streams.delete(streamId);
    });

    localSocket.on('close', () => {
      if (this.connected) this.sendSecure({ type: 'tcp_end', streamId });
      this.streams.delete(streamId);
    });
  }

  sendTcpData(streamId, chunk) {
    this.sendSecure({ type: 'tcp_data', streamId, data: chunk.toString('base64') });
  }
}

class StreamState {
  constructor(streamId, local, tunnel) {
    this.streamId = streamId;
    this.local = local;
    this.tunnel = tunnel;
    this.waitingSince = 0;
    this.failedChecks = 0;
    this.timer = null;
  }

  noteSent() {
    if (!this.waitingSince) {
      this.waitingSince = Date.now();
      this.startWatchdog();
    }
  }

  noteResponse() {
    this.waitingSince = 0;
    this.failedChecks = 0;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  startWatchdog() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(async () => {
      const ok = await this.tunnel.pingHealth();
      if (!ok) {
        this.failedChecks += 1;
      }

      if (this.failedChecks >= 10) {
        this.local.destroy(new Error('Remote response timeout after health checks'));
        this.tunnel.streams.delete(this.streamId);
        if (this.tunnel.connected) {
          this.tunnel.sendSecure({ type: 'tcp_end', streamId: this.streamId });
        }
        return;
      }

      this.startWatchdog();
    }, 90_000);
  }
}

function onceEvent(target, event) {
  return new Promise((resolve, reject) => {
    target.once(event, resolve);
    target.once('error', reject);
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function extractSocks5Target(buffer) {
  const atyp = buffer[3];
  let offset = 4;
  let host;

  if (atyp === 0x01) {
    host = [...buffer.subarray(offset, offset + 4)].join('.');
    offset += 4;
  } else if (atyp === 0x03) {
    const len = buffer[offset];
    offset += 1;
    host = buffer.subarray(offset, offset + len).toString('utf8');
    offset += len;
  } else {
    throw new Error('IPv6 is not supported in SOCKS5 mode');
  }

  const targetPort = buffer.readUInt16BE(offset);
  return { host, targetPort };
}

function stripProxyRequest(raw) {
  const idx = raw.indexOf('\r\n\r\n');
  const headerRaw = raw.subarray(0, idx).toString('utf8');
  const lines = headerRaw.split('\r\n');
  const [method, uri, version] = lines[0].split(' ');
  const parsed = new URL(uri);
  const host = parsed.hostname;
  const targetPort = Number(parsed.port || (parsed.protocol === 'https:' ? 443 : 80));
  const path = `${parsed.pathname || '/'}${parsed.search || ''}`;

  const headers = lines
    .slice(1)
    .filter((line) => !/^proxy-connection:/i.test(line));

  const rewritten = Buffer.from(
    `${method} ${path} ${version}\r\n${headers.join('\r\n')}\r\n\r\n`,
    'utf8'
  );

  const body = raw.subarray(idx + 4);
  return { host, targetPort, data: Buffer.concat([rewritten, body]) };
}

async function main() {
  const tunnel = new TunnelClient();
  await tunnel.connect();

  const proxyServer = net.createServer((socket) => {
    socket.on('error', (err) => {
      console.error('[client] local socket error:', err.message);
    });

    socket.once('data', async (chunk) => {
      try {
        if (chunk[0] === 0x05) {
          socket.write(Buffer.from([0x05, 0x00]));
          const req = await new Promise((resolve) => socket.once('data', resolve));
          const { host, targetPort } = extractSocks5Target(req);
          await tunnel.openTcp(host, targetPort, socket);
          socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          return;
        }

        const headerEnd = chunk.indexOf('\r\n\r\n');
        if (headerEnd === -1) {
          socket.destroy(new Error('Invalid HTTP proxy request'));
          return;
        }

        const firstLine = chunk.subarray(0, chunk.indexOf('\r\n')).toString('utf8');
        if (firstLine.startsWith('CONNECT ')) {
          const authority = firstLine.split(' ')[1];
          const [host, p] = authority.split(':');
          const targetPort = Number(p || 443);
          await tunnel.openTcp(host, targetPort, socket);
          socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          return;
        }

        const { host, targetPort, data } = stripProxyRequest(chunk);
        await tunnel.openTcp(host, targetPort, socket, data);
      } catch (err) {
        socket.destroy(err);
      }
    });
  });

  proxyServer.listen(localPort, '127.0.0.1', () => {
    console.log(`[client] local proxy listening on 127.0.0.1:${localPort}`);
    console.log('[client] export https_proxy=http://127.0.0.1:8890 http_proxy=http://127.0.0.1:8890 all_proxy=socks5://127.0.0.1:8890');
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
