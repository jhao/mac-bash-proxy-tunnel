import fs from 'node:fs';
import net from 'node:net';
import dgram from 'node:dgram';
import { parseArgs } from './args.js';
import { generateServerKeys, fingerprintPublicKey, rsaDecryptSessionKey, encryptPacket, decryptPacket } from './crypto.js';
import { encodeFrame, createFrameDecoder } from './framing.js';
import { TokenManager } from './token-manager.js';

const args = parseArgs(process.argv.slice(2));
const port = Number(args.port || 7000);

const { publicKey, privateKey } = generateServerKeys();
const fingerprint = fingerprintPublicKey(publicKey);

console.log('[service] startup complete');
console.log('[service] public key fingerprint:', fingerprint);
console.log('[service] public key PEM:\n' + publicKey);
console.log('[service] public key base64:', Buffer.from(publicKey, 'utf8').toString('base64'));

if (args['save-pubkey']) {
  fs.writeFileSync(String(args['save-pubkey']), publicKey, 'utf8');
  console.log(`[service] wrote public key to ${args['save-pubkey']}`);
}

const server = net.createServer((socket) => {
  const clientAddress = `${socket.remoteAddress || 'unknown'}:${socket.remotePort || 'unknown'}`;
  console.log(`[service] client connected: ${clientAddress}`);

  let sessionKey = null;
  const tokenManager = new TokenManager();
  const tcpStreams = new Map();
  const udpSockets = new Map();

  const decoder = createFrameDecoder((frame) => {
    if (!sessionKey) {
      if (frame.type !== 'auth_init') {
        console.error(`[service] invalid pre-auth frame from ${clientAddress}:`, frame.type);
        socket.end();
        return;
      }
      try {
        const encrypted = Buffer.from(frame.encryptedSessionKey, 'base64');
        sessionKey = rsaDecryptSessionKey(encrypted, privateKey);
        const msg = { type: 'auth_ok' };
        socket.write(encodeFrame(msg));
        console.log(`[service] auth success: ${clientAddress}`);
      } catch {
        console.error(`[service] auth failed: ${clientAddress}`);
        socket.end();
      }
      return;
    }

    let inner;
    try {
      inner = decryptPacket(frame, sessionKey);
    } catch {
      console.error(`[service] decrypt failed, closing client: ${clientAddress}`);
      socket.end();
      return;
    }

    handleMessage(inner);
  });

  function sendSecure(obj) {
    const packet = encryptPacket(obj, sessionKey);
    socket.write(encodeFrame(packet));
  }

  function validateTokenOrNotify(msg) {
    if (!tokenManager.validate(msg.token)) {
      const nextToken = tokenManager.invalidateAndRotate();
      sendSecure({ type: 'token_invalid', streamId: msg.streamId, requestId: msg.requestId, token: nextToken });
      return false;
    }
    return true;
  }

  function handleMessage(msg) {
    if (msg.type === 'token_request') {
      sendSecure({ type: 'token', token: tokenManager.token });
      return;
    }

    if (msg.type === 'health_ping') {
      sendSecure({ type: 'health_pong', requestId: msg.requestId, ts: Date.now() });
      return;
    }

    if (!validateTokenOrNotify(msg)) return;

    if (msg.type === 'open_tcp') {
      console.log(`[service] open_tcp stream=${msg.streamId} target=${msg.host}:${msg.port} client=${clientAddress}`);
      const remote = net.connect(msg.port, msg.host);
      tcpStreams.set(msg.streamId, remote);
      remote.once('connect', () => sendSecure({ type: 'open_tcp_result', streamId: msg.streamId, ok: true }));
      remote.on('data', (chunk) => {
        sendSecure({ type: 'tcp_data', streamId: msg.streamId, data: chunk.toString('base64') });
      });
      remote.on('end', () => sendSecure({ type: 'tcp_end', streamId: msg.streamId }));
      remote.on('error', (err) => {
        console.error(`[service] tcp stream error stream=${msg.streamId} client=${clientAddress}: ${err.message}`);
        sendSecure({ type: 'tcp_error', streamId: msg.streamId, error: err.message });
      });
      remote.on('close', () => tcpStreams.delete(msg.streamId));
      return;
    }

    if (msg.type === 'tcp_data') {
      const remote = tcpStreams.get(msg.streamId);
      if (remote) remote.write(Buffer.from(msg.data, 'base64'));
      return;
    }

    if (msg.type === 'tcp_end') {
      const remote = tcpStreams.get(msg.streamId);
      if (remote) remote.end();
      return;
    }

    if (msg.type === 'udp_request') {
      const key = msg.streamId;
      let udp = udpSockets.get(key);
      if (!udp) {
        udp = dgram.createSocket('udp4');
        udp.on('message', (data, rinfo) => {
          sendSecure({
            type: 'udp_response',
            streamId: msg.streamId,
            fromHost: rinfo.address,
            fromPort: rinfo.port,
            data: data.toString('base64')
          });
        });
        udp.on('error', (err) => {
          console.error(`[service] udp stream error stream=${msg.streamId} client=${clientAddress}: ${err.message}`);
          sendSecure({ type: 'udp_error', streamId: msg.streamId, error: err.message });
        });
        udpSockets.set(key, udp);
      }
      udp.send(Buffer.from(msg.data, 'base64'), msg.targetPort, msg.targetHost, (err) => {
        if (err) {
          console.error(`[service] udp send error stream=${msg.streamId} client=${clientAddress}: ${err.message}`);
          sendSecure({ type: 'udp_error', streamId: msg.streamId, error: err.message });
        }
      });
      return;
    }
  }

  socket.on('data', decoder);
  socket.on('error', (err) => {
    console.error(`[service] socket error client=${clientAddress}: ${err.message}`);
  });
  socket.on('close', () => {
    console.log(`[service] client disconnected: ${clientAddress}`);
    for (const s of tcpStreams.values()) s.destroy();
    for (const s of udpSockets.values()) s.close();
    tcpStreams.clear();
    udpSockets.clear();
  });
});

server.listen(port, '0.0.0.0', () => {
  console.log(`[service] listening on 0.0.0.0:${port}`);
});
