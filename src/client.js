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
    this.streamCounter = 1;
    this.streams = new Map();
    this.pendingOpen = new Map();
    this.pendingPings = new Map();
    this.closed = false;
  }

  async connect() {
    this.socket = net.connect(port, address);
    await onceEvent(this.socket, 'connect');

    this.sessionKey = createSessionKey();
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
    this.socket.on('error', (err) => console.error('[client] tunnel error:', err.message));
    this.socket.on('close', () => {
      this.closed = true;
      console.error('[client] tunnel closed');
    });

    await this.waitForToken();
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
    if (this.closed || !this.socket || this.socket.destroyed) return;
    const payload = includeToken ? { ...message, token: this.token } : message;
    const packet = encryptPacket(payload, this.sessionKey);
    this.socket.write(encodeFrame(packet));
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
    console.log(`[client] stream#${streamId} open ${host}:${targetPort}`);

    if (initialData?.length) {
      this.sendTcpData(streamId, initialData);
      state.noteSent();
    }

    localSocket.on('data', (chunk) => {
      this.sendTcpData(streamId, chunk);
      state.noteSent();
    });

    localSocket.on('end', () => {
      this.sendSecure({ type: 'tcp_end', streamId });
      this.streams.delete(streamId);
    });

    localSocket.on('close', () => {
      this.sendSecure({ type: 'tcp_end', streamId });
      this.streams.delete(streamId);
      state.dispose();
      console.log(`[client] stream#${streamId} closed`);
    });

    localSocket.on('error', (err) => {
      console.error(`[client] stream#${streamId} local socket error:`, err.message);
      this.sendSecure({ type: 'tcp_end', streamId });
      this.streams.delete(streamId);
      state.dispose();
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

  dispose() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  startWatchdog() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(async () => {
      if (!this.tunnel.streams.has(this.streamId)) return;
      const ok = await this.tunnel.pingHealth();
      if (!ok) {
        this.failedChecks += 1;
      }
      if (ok) this.failedChecks = 0;

      if (this.failedChecks >= 10) {
        this.local.destroy(new Error('Remote response timeout after health checks'));
        this.tunnel.streams.delete(this.streamId);
        this.tunnel.sendSecure({ type: 'tcp_end', streamId: this.streamId });
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
    const peer = `${socket.remoteAddress || 'unknown'}:${socket.remotePort || 0}`;
    console.log(`[client] inbound proxy connection from ${peer}`);
    socket.on('error', (err) => {
      console.error(`[client] inbound socket error (${peer}):`, err.message);
    });
    socket.on('close', () => {
      console.log(`[client] inbound proxy connection closed ${peer}`);
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

  proxyServer.on('error', (err) => {
    console.error('[client] local proxy server error:', err.message);
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
