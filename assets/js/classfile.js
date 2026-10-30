/**
 * Java class-file reader.
 *
 * Parses the constant pool, fields and methods so the scanner can look at
 * what a class actually references, and so the outline tab can show real
 * declarations. This is not a decompiler: bytecode is not reconstructed,
 * method bodies are not printed. It is the honest 80% that runs in a tab.
 */

const ACC = {
  public: 0x0001,
  private: 0x0002,
  protected: 0x0004,
  static: 0x0008,
  final: 0x0010,
  super: 0x0020,
  synchronized: 0x0020,
  volatile: 0x0040,
  bridge: 0x0040,
  transient: 0x0080,
  varargs: 0x0080,
  native: 0x0100,
  interface: 0x0200,
  abstract: 0x0400,
  strict: 0x0800,
  synthetic: 0x1000,
  annotation: 0x2000,
  enum: 0x4000,
  module: 0x8000,
};

const PRIMITIVES = {
  B: 'byte',
  C: 'char',
  D: 'double',
  F: 'float',
  I: 'int',
  J: 'long',
  S: 'short',
  Z: 'boolean',
  V: 'void',
};

// Java's modified UTF-8: NUL is two bytes, supplementary characters are
// CESU-8 surrogate pairs. TextDecoder refuses the NUL form, so decode by hand.
function decodeModifiedUtf8(bytes) {
  let out = '';
  let i = 0;
  const len = bytes.length;
  while (i < len) {
    const b = bytes[i];
    if (b === 0) {
      out += '\u0000';
      i += 1;
    } else if (b < 0x80) {
      out += String.fromCharCode(b);
      i += 1;
    } else if ((b & 0xe0) === 0xc0 && i + 1 < len) {
      out += String.fromCharCode(((b & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
      i += 2;
    } else if ((b & 0xf0) === 0xe0 && i + 2 < len) {
      out += String.fromCharCode(
        ((b & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f),
      );
      i += 3;
    } else if ((b & 0xf8) === 0xf0 && i + 3 < len) {
      const code = ((b & 0x07) << 18) | ((bytes[i + 1] & 0x3f) << 12) | ((bytes[i + 2] & 0x3f) << 6) | (bytes[i + 3] & 0x3f);
      const adjusted = code - 0x10000;
      out += String.fromCharCode(0xd800 + (adjusted >> 10), 0xdc00 + (adjusted & 0x3ff));
      i += 4;
    } else {
      out += '\ufffd';
      i += 1;
    }
  }
  return out;
}

function simpleType(typeName) {
  const cut = typeName.lastIndexOf('/');
  const base = cut >= 0 ? typeName.slice(cut + 1) : typeName;
  return base.replace(/\$/g, '.');
}

function dottedName(typeName) {
  return String(typeName || '?').replace(/\//g, '.').replace(/\$/g, '.');
}

function descriptorToType(descriptor, start = 0) {
  let pos = start;
  let dims = 0;
  while (descriptor[pos] === '[') {
    dims += 1;
    pos += 1;
  }
  let name;
  const ch = descriptor[pos];
  if (ch === 'L') {
    const end = descriptor.indexOf(';', pos);
    if (end < 0) return { name: '?', next: descriptor.length };
    name = simpleType(descriptor.slice(pos + 1, end));
    pos = end + 1;
  } else if (PRIMITIVES[ch]) {
    name = PRIMITIVES[ch];
    pos += 1;
  } else {
    name = '?';
    pos += 1;
  }
  return { name: name + '[]'.repeat(dims), next: pos };
}

export function methodSignature(descriptor) {
  if (!descriptor || descriptor[0] !== '(') return { params: [], returns: '?' };
  const params = [];
  let pos = 1;
  while (pos < descriptor.length && descriptor[pos] !== ')') {
    const parsed = descriptorToType(descriptor, pos);
    params.push(parsed.name);
    pos = parsed.next;
  }
  const ret = descriptorToType(descriptor, pos + 1);
  return { params, returns: ret.name };
}

export function fieldType(descriptor) {
  return descriptorToType(descriptor, 0).name;
}

function readModifiers(flags, kind) {
  const out = [];
  if (flags & ACC.public) out.push('public');
  if (flags & ACC.private) out.push('private');
  if (flags & ACC.protected) out.push('protected');
  if (kind === 'method') {
    if (flags & ACC.static) out.push('static');
    if (flags & ACC.final) out.push('final');
    if (flags & ACC.abstract) out.push('abstract');
    if (flags & ACC.native) out.push('native');
    if (flags & ACC.synchronized) out.push('synchronized');
  } else if (kind === 'field') {
    if (flags & ACC.static) out.push('static');
    if (flags & ACC.final) out.push('final');
    if (flags & ACC.volatile) out.push('volatile');
    if (flags & ACC.transient) out.push('transient');
  } else {
    if (flags & ACC.final) out.push('final');
    if (flags & ACC.abstract) out.push('abstract');
  }
  if (flags & ACC.synthetic) out.push('synthetic');
  return out;
}

/**
 * @param {Uint8Array} bytes
 * @returns {object|null} null when the file is not a class or is too broken to read.
 */
export function parseClass(bytes) {
  if (!bytes || bytes.length < 24) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0) !== 0xcafebabe) return null;

  try {
    const minor = view.getUint16(4);
    let major = view.getInt16(6);
    // Some obfuscators use a negative/absurd version to break tooling. Read it
    // unsigned but clamp the display.
    if (major < 0) major += 0x10000;

    const poolCount = view.getUint16(8);
    let pos = 10;
    const utf8 = new Array(poolCount).fill(null);
    const classNames = new Array(poolCount).fill(null);

    for (let i = 1; i < poolCount; i++) {
      const tag = view.getUint8(pos);
      pos += 1;
      switch (tag) {
        case 1: {
          const length = view.getUint16(pos);
          pos += 2;
          if (pos + length > bytes.length) throw new RangeError('utf8 constant overruns file');
          utf8[i] = decodeModifiedUtf8(bytes.subarray(pos, pos + length));
          pos += length;
          break;
        }
        case 3:
        case 4:
          pos += 4;
          break;
        case 5:
        case 6:
          pos += 8;
          i += 1; // long/double take two slots
          break;
        case 7:
          classNames[i] = view.getUint16(pos);
          pos += 2;
          break;
        case 8:
        case 16:
        case 19:
        case 20:
          pos += 2;
          break;
        case 15:
          pos += 3;
          break;
        case 9:
        case 10:
        case 11:
        case 12:
        case 17:
        case 18:
          pos += 4;
          break;
        default:
          return null;
      }
      if (pos > bytes.length) return null;
    }

    const className = (index) => {
      const nameIndex = classNames[index];
      return nameIndex ? utf8[nameIndex] || '' : '';
    };

    const accessFlags = view.getUint16(pos);
    pos += 2;
    const thisIndex = view.getUint16(pos);
    pos += 2;
    const superIndex = view.getUint16(pos);
    pos += 2;
    const interfaceCount = view.getUint16(pos);
    pos += 2;
    const interfaces = [];
    for (let i = 0; i < interfaceCount; i++) {
      interfaces.push(className(view.getUint16(pos)));
      pos += 2;
    }

    const fields = [];
    const fieldCount = view.getUint16(pos);
    pos += 2;
    for (let i = 0; i < fieldCount; i++) {
      const flags = view.getUint16(pos);
      const nameIndex = view.getUint16(pos + 2);
      const descIndex = view.getUint16(pos + 4);
      const attrCount = view.getUint16(pos + 6);
      pos += 8;
      for (let a = 0; a < attrCount; a++) {
        const length = view.getUint32(pos + 2);
        pos += 6 + length;
      }
      fields.push({
        flags,
        name: utf8[nameIndex] || '?',
        descriptor: utf8[descIndex] || '',
      });
    }

    const methods = [];
    const methodCount = view.getUint16(pos);
    pos += 2;
    for (let i = 0; i < methodCount; i++) {
      const flags = view.getUint16(pos);
      const nameIndex = view.getUint16(pos + 2);
      const descIndex = view.getUint16(pos + 4);
      const attrCount = view.getUint16(pos + 6);
      pos += 8;
      let codeLength = 0;
      for (let a = 0; a < attrCount; a++) {
        if (pos + 6 > bytes.length) throw new RangeError('attribute overruns file');
        const attrNameIndex = view.getUint16(pos);
        const length = view.getUint32(pos + 2);
        if (utf8[attrNameIndex] === 'Code') codeLength = length;
        pos += 6 + length;
      }
      methods.push({
        flags,
        name: utf8[nameIndex] || '?',
        descriptor: utf8[descIndex] || '',
        codeLength,
      });
    }

    let sourceFile = '';
    if (pos + 2 <= bytes.length) {
      const attrCount = view.getUint16(pos);
      pos += 2;
      for (let a = 0; a < attrCount; a++) {
        if (pos + 6 > bytes.length) break;
        const attrNameIndex = view.getUint16(pos);
        const length = view.getUint32(pos + 2);
        if (utf8[attrNameIndex] === 'SourceFile' && pos + 8 <= bytes.length) {
          const fileIndex = view.getUint16(pos + 6);
          sourceFile = utf8[fileIndex] || '';
        }
        pos += 6 + length;
      }
    }

    const thisName = className(thisIndex);
    const superName = className(superIndex);

    return {
      minor,
      major,
      javaVersion: major >= 45 ? major - 44 : null,
      accessFlags,
      className: thisName,
      superName,
      interfaces,
      fields,
      methods,
      sourceFile,
      strings: utf8.filter((value) => value !== null),
      constantPool: utf8,
      kind: (accessFlags & ACC.annotation)
        ? 'annotation'
        : (accessFlags & ACC.interface)
          ? 'interface'
          : (accessFlags & ACC.enum)
            ? 'enum'
            : 'class',
    };
  } catch {
    return null;
  }
}

/**
 * Human-readable class outline. No bytecode, no guessing — declarations only.
 */
export function renderOutline(parsed) {
  if (!parsed) return 'Could not parse this class. It may be deliberately malformed.';

  const modifiers = readModifiers(parsed.accessFlags, 'class');
  const head = `${modifiers.join(' ')} ${parsed.kind} ${dottedName(parsed.className)}`;
  const lines = [];
  lines.push(
    `${head}${parsed.superName && parsed.superName !== 'java/lang/Object' ? ` extends ${dottedName(parsed.superName)}` : ''}` +
    `${parsed.interfaces.length ? ` implements ${parsed.interfaces.map(dottedName).join(', ')}` : ''} {`,
  );

  if (parsed.sourceFile) lines.push(`  // source: ${parsed.sourceFile}`);
  lines.push(`  // class file ${parsed.major}.${parsed.minor}${parsed.javaVersion ? ` · Java ${parsed.javaVersion}` : ''}`);
  lines.push('');

  const visibleFields = parsed.fields.slice(0, 200);
  if (visibleFields.length) {
    for (const field of visibleFields) {
      const mods = readModifiers(field.flags, 'field');
      lines.push(`  ${mods.length ? `${mods.join(' ')} ` : ''}${fieldType(field.descriptor)} ${field.name};`);
    }
    if (parsed.fields.length > visibleFields.length) {
      lines.push(`  // … ${parsed.fields.length - visibleFields.length} more fields`);
    }
    lines.push('');
  }

  const visibleMethods = parsed.methods.slice(0, 200);
  if (visibleMethods.length) {
    for (const method of visibleMethods) {
      const mods = readModifiers(method.flags, 'method');
      const signature = methodSignature(method.descriptor);
      const body = method.flags & ACC.native ? ';' : ' { … }';
      lines.push(
        `  ${mods.length ? `${mods.join(' ')} ` : ''}${signature.returns} ${method.name}(${signature.params.join(', ')})${body}`,
      );
    }
    if (parsed.methods.length > visibleMethods.length) {
      lines.push(`  // … ${parsed.methods.length - visibleMethods.length} more methods`);
    }
  }

  if (!parsed.fields.length && !parsed.methods.length) lines.push('  // no fields or methods');
  lines.push('}');
  return lines.join('\n');
}

export function classSummary(parsed) {
  if (!parsed) return '';
  return `${parsed.kind} ${parsed.className} · ${parsed.methods.length} methods, ${parsed.fields.length} fields`;
}
