export function encodeFrame(obj) {
  const data = Buffer.from(JSON.stringify(obj), 'utf8');
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(data.length, 0);
  return Buffer.concat([header, data]);
}

export function createFrameDecoder(onFrame) {
  let buf = Buffer.alloc(0);
  return (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4) {
      const len = buf.readUInt32BE(0);
      if (buf.length < 4 + len) break;
      const body = buf.subarray(4, 4 + len);
      buf = buf.subarray(4 + len);
      onFrame(JSON.parse(body.toString('utf8')));
    }
  };
}
