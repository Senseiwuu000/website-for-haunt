/**
 * Minimal ZIP / JAR reader.
 *
 * No dependencies. Central directory parsing, ZIP64 support, and raw
 * DEFLATE through the browser's own DecompressionStream. Entries are read
 * lazily from the File/Blob so a 200 MB archive never has to sit in memory
 * as one buffer unless you ask for it.
 */

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_EOCD64 = 0x06064b50;
const SIG_EOCD64_LOC = 0x07064b50;

const MAX_ENTRIES = 250000;

const decoder = new TextDecoder('utf-8');

function findSignatureBackwards(bytes, signature) {
  for (let i = bytes.length - 4; i >= 0; i--) {
    if (
      bytes[i] === (signature & 0xff) &&
      bytes[i + 1] === ((signature >>> 8) & 0xff) &&
      bytes[i + 2] === ((signature >>> 16) & 0xff) &&
      bytes[i + 3] === ((signature >>> 24) & 0xff)
    ) {
      return i;
    }
  }
  return -1;
}

async function readSlice(blob, start, end) {
  if (start < 0) start = 0;
  if (end > blob.size) end = blob.size;
  if (end <= start) return new Uint8Array(0);
  return new Uint8Array(await blob.slice(start, end).arrayBuffer());
}

/**
 * @param {Blob} blob
 * @returns {Promise<{entries: Array, comment: string, archiveSize: number}>}
 */
export async function readZip(blob) {
  const size = blob.size;
  if (size < 22) throw new Error('This file is too small to be a jar.');

  const tailLength = Math.min(size, 66000);
  const tail = await readSlice(blob, size - tailLength, size);
  const eocdInTail = findSignatureBackwards(tail, SIG_EOCD);
  if (eocdInTail < 0) {
    throw new Error('No ZIP central directory found. This is not a jar/zip, or the file is truncated.');
  }

  const eocdOffset = size - tailLength + eocdInTail;
  const eocdView = new DataView(tail.buffer, tail.byteOffset + eocdInTail, 22);
  let totalEntries = eocdView.getUint16(10, true);
  let cdSize = eocdView.getUint32(12, true);
  let cdOffset = eocdView.getUint32(16, true);
  const commentLength = eocdView.getUint16(20, true);
  const comment = commentLength > 0
    ? decoder.decode(tail.subarray(eocdInTail + 22, eocdInTail + 22 + commentLength))
    : '';

  // ZIP64: sizes or counts hit the 32-bit sentinel. Follow the locator.
  if (totalEntries === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    const locator = await readSlice(blob, eocdOffset - 20, eocdOffset);
    let resolved = false;
    if (locator.length === 20) {
      const lv = new DataView(locator.buffer, locator.byteOffset, 20);
      if (lv.getUint32(0, true) === SIG_EOCD64_LOC) {
        const zip64Offset = Number(lv.getBigUint64(8, true));
        const head = await readSlice(blob, zip64Offset, zip64Offset + 56);
        if (head.length === 56) {
          const hv = new DataView(head.buffer, head.byteOffset, head.length);
          if (hv.getUint32(0, true) === SIG_EOCD64) {
            totalEntries = Number(hv.getBigUint64(32, true));
            cdSize = Number(hv.getBigUint64(40, true));
            cdOffset = Number(hv.getBigUint64(48, true));
            resolved = true;
          }
        }
      }
    }
    if (!resolved) {
      throw new Error('This archive uses ZIP64 and its directory could not be read.');
    }
  }

  if (totalEntries > MAX_ENTRIES) {
    throw new Error(`Archive has ${totalEntries.toLocaleString()} entries, which is past the scanner's limit.`);
  }
  if (cdOffset + cdSize > size || cdSize <= 0) {
    throw new Error('The archive directory points past the end of the file. Truncated or deliberately malformed.');
  }

  const cdBytes = await readSlice(blob, cdOffset, cdOffset + cdSize);
  const cd = new DataView(cdBytes.buffer, cdBytes.byteOffset, cdBytes.byteLength);
  const entries = [];
  let p = 0;

  while (p + 46 <= cd.byteLength) {
    const signature = cd.getUint32(p, true);
    if (signature !== SIG_CENTRAL) break;

    const flags = cd.getUint16(p + 8, true);
    const method = cd.getUint16(p + 10, true);
    const crc = cd.getUint32(p + 16, true);
    let compressedSize = cd.getUint32(p + 20, true);
    let uncompressedSize = cd.getUint32(p + 24, true);
    const nameLength = cd.getUint16(p + 28, true);
    const extraLength = cd.getUint16(p + 30, true);
    const innerCommentLength = cd.getUint16(p + 32, true);
    let localOffset = cd.getUint32(p + 42, true);

    const nameStart = p + 46;
    const nameEnd = nameStart + nameLength;
    if (nameEnd > cd.byteLength) throw new Error('Corrupt archive: entry name runs past the directory.');
    const name = decoder.decode(cdBytes.subarray(nameStart, nameEnd));

    // ZIP64 extra field (0x0001) holds the real values, in the order the
    // corresponding 32-bit fields were saturated.
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff) {
      let e = nameEnd;
      const extraEnd = e + extraLength;
      while (e + 4 <= extraEnd) {
        const fieldId = cd.getUint16(e, true);
        const fieldSize = cd.getUint16(e + 2, true);
        const body = e + 4;
        if (fieldId === 1) {
          let cursor = body;
          const read64 = () => {
            if (cursor + 8 > body + fieldSize) return null;
            const value = Number(cd.getBigUint64(cursor, true));
            cursor += 8;
            return value;
          };
          if (uncompressedSize === 0xffffffff) {
            const v = read64();
            if (v !== null) uncompressedSize = v;
          }
          if (compressedSize === 0xffffffff) {
            const v = read64();
            if (v !== null) compressedSize = v;
          }
          if (localOffset === 0xffffffff) {
            const v = read64();
            if (v !== null) localOffset = v;
          }
          break;
        }
        e = body + fieldSize;
      }
    }

    entries.push({
      name,
      flags,
      method,
      crc,
      compressedSize,
      uncompressedSize,
      localOffset,
      isDir: name.endsWith('/'),
    });

    p = nameEnd + extraLength + innerCommentLength;
  }

  return { entries, comment, archiveSize: size };
}

/**
 * Raw entry bytes. Bound by maxBytes so one zip bomb cannot eat the tab.
 * @param {Blob} blob
 * @param {object} entry
 * @param {number} maxBytes
 */
export async function readEntry(blob, entry, maxBytes = 64 * 1024 * 1024) {
  if (entry.flags & 0x1) throw new Error('entry is encrypted');
  if (entry.isDir) return { bytes: new Uint8Array(0), truncated: false };

  const header = await readSlice(blob, entry.localOffset, entry.localOffset + 30);
  if (header.length < 30) throw new Error('local header is missing');
  const hv = new DataView(header.buffer, header.byteOffset, header.length);
  if (hv.getUint32(0, true) !== SIG_LOCAL) throw new Error('local header has the wrong signature');

  const nameLength = hv.getUint16(26, true);
  const extraLength = hv.getUint16(28, true);
  const dataStart = entry.localOffset + 30 + nameLength + extraLength;
  const dataEnd = Math.min(dataStart + entry.compressedSize, blob.size);
  if (dataStart >= blob.size) throw new Error('entry data is past the end of the file');

  if (entry.method === 0) {
    const raw = await readSlice(blob, dataStart, Math.min(dataEnd, dataStart + maxBytes));
    return { bytes: raw, truncated: dataEnd - dataStart > maxBytes };
  }

  if (entry.method !== 8) {
    throw new Error(`compression method ${entry.method} is not supported`);
  }

  const compressed = await readSlice(blob, dataStart, dataEnd);
  const inflated = await inflateRaw(compressed, maxBytes);
  return inflated;
}

/**
 * deflate-raw via the platform. Every current browser has it; if it does not,
 * say so plainly instead of pretending the scan happened.
 */
export async function inflateRaw(bytes, maxBytes) {
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('This browser cannot decompress zip entries inline. Use a current Chrome, Edge, Firefox or Safari.');
  }

  let stream;
  try {
    stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  } catch (error) {
    throw new Error('This browser does not support raw DEFLATE decompression.');
  }

  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;

  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (total + value.length > maxBytes) {
        const room = maxBytes - total;
        if (room > 0) chunks.push(value.subarray(0, room));
        total = maxBytes;
        truncated = true;
        await reader.cancel().catch(() => {});
        break;
      }
      chunks.push(value);
      total += value.length;
    }
  } finally {
    reader.releaseLock?.();
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return { bytes: out, truncated };
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return '—';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value >= 100 ? value.toFixed(0) : value.toFixed(value >= 10 ? 1 : 2)} ${units[unit]}`;
}
