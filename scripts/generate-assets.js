const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function crc32(buf) {
  let table = [];
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c;
  }
  let crc = -1;
  for (let i = 0; i < buf.length; i++) {
    crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ -1) >>> 0;
}

function makeChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crcBuf]);
}

function encodeRGBAtoPNG(width, height, getPixel) {
  const rowLen = 1 + width * 4;
  const raw = Buffer.alloc(rowLen * height);
  for (let y = 0; y < height; y++) {
    const rowOffset = y * rowLen;
    raw[rowOffset] = 0;
    for (let x = 0; x < width; x++) {
      const [r, g, b, a] = getPixel(x, y);
      const pxOffset = rowOffset + 1 + x * 4;
      raw[pxOffset] = r;
      raw[pxOffset + 1] = g;
      raw[pxOffset + 2] = b;
      raw[pxOffset + 3] = a;
    }
  }

  const signature = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const idatData = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([
    signature,
    makeChunk('IHDR', ihdr),
    makeChunk('IDAT', idatData),
    makeChunk('IEND', Buffer.alloc(0))
  ]);
}

function makeIco(png32) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(1, 4);

  const dir = Buffer.alloc(16);
  dir[0] = 32;
  dir[1] = 32;
  dir[2] = 0;
  dir[3] = 0;
  dir.writeUInt16LE(1, 4);
  dir.writeUInt16LE(32, 6);
  dir.writeUInt32LE(png32.length, 8);
  dir.writeUInt32LE(22, 12);

  return Buffer.concat([header, dir, png32]);
}

const publicDir = path.join(__dirname, '..', 'cloud-dashboard', 'public');

// 1. Generate 32x32 Favicon PNG
const favicon32 = encodeRGBAtoPNG(32, 32, (x, y) => {
  const dx = x - 16;
  const dy = y - 16;
  const dist = Math.sqrt(dx * dx + dy * dy);
  // Shield shape logic
  const inShield = (y >= 6 && y <= 26 && Math.abs(x - 16) <= (y < 16 ? 10 : 10 - (y - 16) * 0.9));
  if (inShield) {
    if (Math.abs(dx) <= 2 && Math.abs(dy) <= 2) return [52, 211, 153, 255]; // emerald highlight
    return [16, 185, 129, 255]; // emerald-500
  }
  return [9, 10, 15, dist < 15 ? 255 : 0]; // background #090a0f
});

fs.writeFileSync(path.join(publicDir, 'favicon.ico'), makeIco(favicon32));
console.log('Created favicon.ico');

// 2. Generate 180x180 Apple Touch Icon
const appleIcon = encodeRGBAtoPNG(180, 180, (x, y) => {
  const rx = Math.abs(x - 90);
  const ry = y - 90;
  // Rounded squircle background
  const inBg = (x >= 8 && x <= 172 && y >= 8 && y <= 172);
  if (!inBg) return [0, 0, 0, 0];

  // Shield boundary
  const inShield = (y >= 35 && y <= 145 && rx <= (y < 90 ? 55 : 55 - (y - 90) * 0.95));
  const isBorder = inShield && (rx >= (y < 90 ? 47 : 47 - (y - 90) * 0.95) || y <= 42);

  if (isBorder) return [16, 185, 129, 255]; // Emerald-500
  if (inShield) {
    // Checkmark coordinates
    if (y >= 80 && y <= 105 && Math.abs((x - 70) - (y - 80)) <= 4) return [52, 211, 153, 255];
    if (y >= 65 && y <= 105 && Math.abs((x - 110) + (y - 65) - 40) <= 4) return [52, 211, 153, 255];
    return [16, 185, 129, 60]; // Translucent shield
  }

  // Dark background with radial gradient
  const dist = Math.sqrt(rx * rx + ry * ry);
  const glow = Math.max(0, 1 - dist / 90) * 40;
  return [9 + glow * 0.2, 10 + glow * 0.8, 15 + glow * 0.5, 255];
});

fs.writeFileSync(path.join(publicDir, 'apple-touch-icon.png'), appleIcon);
console.log('Created apple-touch-icon.png');

// 3. Generate 1200x630 OG Image
const ogImage = encodeRGBAtoPNG(1200, 630, (x, y) => {
  // Background gradient: deep dark slate #090a0f with emerald glow in center-left
  const glowDist = Math.sqrt((x - 300) ** 2 + (y - 315) ** 2);
  const glow = Math.max(0, 1 - glowDist / 500);

  // Grid line accents
  const isGrid = (x % 60 === 0 || y % 60 === 0) && glowDist < 550;

  // Central shield emblem at (x=240, y=315)
  const sx = Math.abs(x - 240);
  const sy = y - 315;
  const inShield = (sy >= -120 && sy <= 120 && sx <= (sy < 0 ? 110 : 110 - sy * 0.9));
  const isBorder = inShield && (sx >= (sy < 0 ? 98 : 98 - sy * 0.9) || sy <= -108);

  if (isBorder) return [16, 185, 129, 255];
  if (inShield) {
    // Checkmark
    if (sy >= -10 && sy <= 45 && Math.abs((x - 200) - (sy + 10)) <= 7) return [52, 211, 153, 255];
    if (sy >= -45 && sy <= 45 && Math.abs((x - 280) + (sy + 45) - 85) <= 7) return [52, 211, 153, 255];
    return [16, 185, 129, 80];
  }

  let r = 9 + glow * 20;
  let g = 10 + glow * 60;
  let b = 15 + glow * 40;

  if (isGrid) {
    r += 10;
    g += 20;
    b += 20;
  }

  return [Math.min(255, r), Math.min(255, g), Math.min(255, b), 255];
});

fs.writeFileSync(path.join(publicDir, 'og-image.png'), ogImage);
console.log('Created og-image.png');
