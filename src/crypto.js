import crypto from 'node:crypto';

export function generateServerKeys() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
  });
}

export function fingerprintPublicKey(publicKeyPem) {
  return crypto.createHash('sha256').update(publicKeyPem).digest('hex');
}

export function createSessionKey() {
  return crypto.randomBytes(32);
}

export function rsaEncryptSessionKey(sessionKey, publicKeyPem) {
  return crypto.publicEncrypt(
    {
      key: publicKeyPem,
      oaepHash: 'sha256',
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    },
    sessionKey
  );
}

export function rsaDecryptSessionKey(ciphertext, privateKeyPem) {
  return crypto.privateDecrypt(
    {
      key: privateKeyPem,
      oaepHash: 'sha256',
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    },
    ciphertext
  );
}

export function encryptPacket(obj, sessionKey) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    payload: ciphertext.toString('base64')
  };
}

export function decryptPacket(packet, sessionKey) {
  const iv = Buffer.from(packet.iv, 'base64');
  const tag = Buffer.from(packet.tag, 'base64');
  const payload = Buffer.from(packet.payload, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(payload), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}
