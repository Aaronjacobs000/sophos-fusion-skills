// Pixel size of an image from its bytes, for the manifest icon checks. Reads PNG, JPEG, and SVG.

// Start-of-frame markers, which carry the size. C4 (DHT), C8 (JPG), and CC (DAC) are not frames.
const JPEG_FRAMES = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);

/** Width and height from a JPEG's first frame header, or null if the bytes do not reach one. */
function jpegSize(buf) {
  let i = 2;
  while (i + 4 <= buf.length) {
    if (buf[i] !== 0xff) return null;
    const marker = buf[i + 1];
    if (marker === 0xff) {
      i += 1; // fill byte
      continue;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) {
      i += 2; // markers with no length
      continue;
    }
    if (marker === 0xd9 || marker === 0xda) return null; // end of image, or scan data before any frame
    const length = buf.readUInt16BE(i + 2);
    if (length < 2) return null;
    if (JPEG_FRAMES.has(marker)) {
      if (i + 9 > buf.length) return null;
      const height = buf.readUInt16BE(i + 5);
      const width = buf.readUInt16BE(i + 7);
      return width && height ? { width, height } : null;
    }
    i += 2 + length;
  }
  return null;
}

/**
 * { type, width, height } for an image file's bytes. type is png, jpeg, or svg, or for other files
 * gif, webp, or unknown. width and height are null when the size can't be read.
 */
export function imageSize(buf) {
  if (buf.length >= 24 && buf.subarray(1, 4).toString('latin1') === 'PNG') return { type: 'png', width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    const size = jpegSize(buf);
    return { type: 'jpeg', width: size?.width ?? null, height: size?.height ?? null };
  }
  const head = buf.subarray(0, 12).toString('latin1');
  if (head.startsWith('GIF8')) return { type: 'gif', width: null, height: null };
  if (head.startsWith('RIFF') && head.slice(8) === 'WEBP') return { type: 'webp', width: null, height: null };
  const text = buf.toString('utf8');
  if (/<svg\b/.test(text)) {
    // XML allows either quote around an attribute
    const vb = /<svg\b[^>]*\bviewBox\s*=\s*(["'])\s*[-\d.]+[\s,]+[-\d.]+[\s,]+([\d.]+)[\s,]+([\d.]+)\s*\1/.exec(text);
    return { type: 'svg', width: vb ? Number(vb[2]) : null, height: vb ? Number(vb[3]) : null };
  }
  return { type: 'unknown', width: null, height: null };
}
