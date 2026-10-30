/**
 * Netmask jar scanner — static analysis, no server, no network.
 *
 * Reads a .jar/.zip, walks every entry, parses every class it can, and looks
 * for the things that actually show up in ratted clients: process spawning,
 * webhooks, runtime loaders, persistence, credential paths, screen capture,
 * native drops, double extensions, nested jars and obfuscation.
 *
 * The output is a heuristic report. "Nothing obvious" means no rule matched,
 * not that a file is safe. Nothing here proves intent.
 */

import { readZip, readEntry, formatBytes } from './zip.js';
import { parseClass, renderOutline } from './classfile.js';

export const MAX_FILE_BYTES = 200 * 1024 * 1024;
export const RULESET = '2026.10.3';

const MAX_CLASS_BYTES = 8 * 1024 * 1024;
const MAX_TEXT_BYTES = 1024 * 1024;
const MAX_NESTED_BYTES = 48 * 1024 * 1024;
const MAX_NESTED_TOTAL = 128 * 1024 * 1024;
const MAX_NESTED_COUNT = 12;
const MAX_LISTED_FILES = 30000;
const MAX_URLS = 300;

const CLASS_RULES = [
  {
    id: 'process-exec',
    sev: 'high',
    weight: 18,
    title: 'Process execution',
    detail: 'Code that starts other programs. Loaders, updaters and droppers all need this; so do legitimate launchers.',
    // RuntimeException / RuntimePermission are not process execution.
    re: /java\/lang\/ProcessBuilder|java\/lang\/ProcessImpl|java\/lang\/Process(?!Builder|Impl)|Runtime\.exec|Runtime\.getRuntime|java\/lang\/Runtime(?!Exception|Permission)/,
  },
  {
    id: 'shell-strings',
    sev: 'high',
    weight: 18,
    title: 'Shell and LOLBin commands',
    detail: 'Command strings used by droppers to fetch, unpack or hide a payload.',
    re: /powershell|cmd\.exe|mshta|certutil|bitsadmin|wmic|schtasks|reg\s+add|vssadmin|taskkill|msiexec|curl\s+-|wget\s+/i,
  },
  {
    id: 'discord-webhook',
    sev: 'high',
    weight: 22,
    title: 'Discord webhook / Telegram bot',
    detail: 'The usual exfiltration channel in a Minecraft-client RAT. Almost never appears in a client on purpose.',
    re: /discord(?:app)?\.com\/api\/webhooks|discord\.com\/api\/v\d+\/webhooks|api\.telegram\.org\/bot|hooks\.slack\.com\/services/i,
  },
  {
    id: 'dynamic-load',
    sev: 'high',
    weight: 16,
    title: 'Runtime class definition',
    detail: 'Defines or patches classes at runtime. A normal client has no reason to generate bytecode after it has been reviewed.',
    re: /defineClass|jdk\/internal\/loader|sun\/misc\/Unsafe|Unsafe\.defineAnonymousClass/,
  },
  {
    id: 'classloader',
    sev: 'med',
    weight: 6,
    title: 'Custom class loading',
    detail: 'Uses or inspects class loaders. Shared by plugin systems, hot-reload tooling and payload loaders alike.',
    re: /URLClassLoader|ClassLoader|MethodHandles\.Lookup/,
  },
  {
    id: 'network',
    sev: 'med',
    weight: 6,
    title: 'Network primitives',
    detail: 'HTTP or socket code. Normal in updaters and licence checks; also the first half of a dropper.',
    re: /HttpURLConnection|openConnection|java\/net\/Socket|okhttp3|HttpClient|URLConnection|openStream/,
  },
  {
    id: 'crypto',
    sev: 'med',
    weight: 5,
    title: 'Encoding / encryption',
    detail: 'Base64 or AES used on strings. Used for licence blobs and for hiding payload URLs.',
    re: /javax\/crypto|Cipher\.getInstance|Base64\.getDecoder|BASE64Decoder|DatatypeConverter|AES\/GCM|AES\/ECB/,
  },
  {
    id: 'persistence',
    sev: 'high',
    weight: 17,
    title: 'Persistence paths',
    detail: 'Writes a startup entry, launch agent or scheduled task. A game client has no reason to survive a reboot.',
    re: /CurrentVersion\\Run|AppData\\Roaming|LaunchAgents|crontab|systemd\/system|Start Menu\\Programs\\Startup/i,
  },
  {
    id: 'credential-paths',
    sev: 'high',
    weight: 20,
    title: 'Credential / session paths',
    detail: 'Browser profile, Discord leveldb or token strings — the things a session stealer reads.',
    re: /leveldb|Login Data|Local State|session-token|access_token|AppData\\Local\\Google|discord\\Local Storage/i,
  },
  {
    id: 'rat-features',
    sev: 'high',
    weight: 20,
    title: 'Remote access features',
    detail: 'Screen capture, clipboard reads, key input or webcam calls. A cheat client normally only draws overlays.',
    re: /createScreenCapture|java\/awt\/Robot|getAsyncKeyState|keylog|webcam|getClipboard|clipboard/i,
  },
  {
    id: 'evasion',
    sev: 'high',
    weight: 14,
    title: 'Analysis evasion',
    detail: 'Checks for virtual machines, sandboxes or debuggers before doing anything. There is no clean reason for this.',
    re: /VirtualBox|VMware|vboxservice|isDebuggerAttached|detectDebugger|Wireshark|Process Hacker|sbiedll|SbieSvc/i,
  },
  {
    id: 'native-strings',
    sev: 'high',
    weight: 14,
    title: 'Native library loading',
    detail: 'Loads a DLL/SO, often one it drops next to the jar first.',
    re: /System\.load|System\.loadLibrary|UnsatisfiedLinkError|[A-Za-z0-9_-]+\.(?:dll|dylib|so)\b/i,
  },
];

export const RULES_SUMMARY = [
  { label: 'Process spawning and shell commands', sev: 'high' },
  { label: 'Discord webhooks, Telegram bots, paste hosts', sev: 'high' },
  { label: 'Runtime class loading and reflection loaders', sev: 'high' },
  { label: 'Persistence: run keys, startup, launch agents', sev: 'high' },
  { label: 'Browser profiles, Discord leveldb, token paths', sev: 'high' },
  { label: 'Screen capture, keyboard, clipboard, webcam', sev: 'high' },
  { label: 'VM / sandbox / debugger checks', sev: 'high' },
  { label: 'Embedded DLL, SO, EXE, scripts and double extensions', sev: 'high' },
  { label: 'Network and download primitives', sev: 'med' },
  { label: 'Base64 / AES string obfuscation', sev: 'med' },
  { label: 'Nested jars and encrypted entries', sev: 'med' },
  { label: 'Class-name obfuscation and malformed classes', sev: 'low' },
];

const FILE_RULES = {
  executable: {
    id: 'embedded-exec',
    sev: 'high',
    weight: 18,
    title: 'Embedded executable',
    detail: 'An .exe, .scr, .msi or script is packed inside the archive. Sometimes that is the injector; sometimes it is the payload.',
  },
  native: {
    id: 'embedded-native',
    sev: 'high',
    weight: 12,
    title: 'Embedded native library',
    detail: 'A DLL/SO ships inside the jar. Normal for a GTA menu, unusual for a Minecraft client.',
  },
  doubleExtension: {
    id: 'double-extension',
    sev: 'high',
    weight: 20,
    title: 'Double extension',
    detail: 'Something like image.png.exe — a filename built to look harmless in Explorer.',
  },
  rtl: {
    id: 'rtl-name',
    sev: 'high',
    weight: 10,
    title: 'Bidirectional filename trick',
    detail: 'Unicode direction overrides reverse part of a filename so the extension shown is not the real one.',
  },
  encrypted: {
    id: 'encrypted-entries',
    sev: 'med',
    weight: 8,
    title: 'Encrypted archive entries',
    detail: 'The scanner cannot see inside these, and neither can you until someone opens them.',
  },
  nested: {
    id: 'nested-jar',
    sev: 'med',
    weight: 8,
    title: 'Nested jar',
    detail: 'A jar inside the jar. Used by installers and loaders — and by builds that want the reviewed jar to fetch a new payload.',
  },
  bomb: {
    id: 'compression-bomb',
    sev: 'high',
    weight: 12,
    title: 'Suspicious compression ratio',
    detail: 'One entry expands enormously compared to its compressed size. That is how a zip bomb looks.',
  },
};

const URL_HOST_RULES = [
  {
    id: 'payload-host',
    sev: 'med',
    weight: 10,
    title: 'Payload-friendly file host',
    detail: 'Pastebin, catbox, gofile and Discord attachment links are how second-stage jars usually arrive.',
    re: /(pastebin\.com|gofile\.io|catbox\.moe|transfer\.sh|anonfiles|0x0\.st|temp\.sh|file\.io|cdn\.discordapp\.com\/attachments|discord\.com\/attachments)/i,
  },
];

const TEXT_EXTENSIONS = new Set([
  'txt', 'json', 'yml', 'yaml', 'properties', 'xml', 'cfg', 'conf', 'ini', 'toml',
  'md', 'html', 'htm', 'css', 'js', 'ts', 'bat', 'cmd', 'sh', 'ps1', 'vbs', 'gradle', 'mf',
]);

const EXEC_EXTENSIONS = new Set(['exe', 'scr', 'msi', 'bat', 'cmd', 'com', 'pif', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'ps1']);
// Script files count as executables for name checks, but they are still text
// and their contents have to be scanned like any other resource.
const SCRIPT_TEXT_EXTENSIONS = new Set(['bat', 'cmd', 'ps1', 'sh', 'vbs', 'js']);
const NATIVE_EXTENSIONS = new Set(['dll', 'so', 'dylib']);
const IMAGE_EXTENSIONS = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'bmp', 'svg']);

const B64_RE = /^[A-Za-z0-9+/\r\n]{180,}={0,2}$/;
const URL_RE = /\bhttps?:\/\/[^\s"'`<>(){}|\\^[\]]{4,300}/gi;
const IP_RE = /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?![\d.])/g;

const PRIVATE_IP = /^(?:10\.|127\.|0\.0\.0\.0|255\.255\.255\.255|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)/;

export class ScanCancelled extends Error {
  constructor() {
    super('Scan cancelled');
    this.name = 'ScanCancelled';
  }
}

function extensionOf(name) {
  const base = name.slice(name.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : '';
}

function classify(name, isDir) {
  if (isDir) return 'dir';
  const ext = extensionOf(name);
  if (ext === 'class') return 'class';
  if (ext === 'jar' || ext === 'zip' || ext === 'war') return 'jar';
  if (ext === 'mf') return 'manifest';
  if (EXEC_EXTENSIONS.has(ext)) return 'exec';
  if (NATIVE_EXTENSIONS.has(ext)) return 'native';
  if (IMAGE_EXTENSIONS.has(ext)) return 'image';
  if (TEXT_EXTENSIONS.has(ext)) return 'text';
  return 'resource';
}

function snippetAt(text, index, length = 96) {
  const start = Math.max(0, index - 34);
  const raw = text.slice(start, start + length);
  const clean = raw
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return `${start > 0 ? '…' : ''}${clean}${start + length < text.length ? '…' : ''}`.slice(0, 150);
}

function sanitizeName(name) {
  return name.replace(/[\u0000-\u001f\u007f]/g, '?');
}

function parseManifest(text) {
  const map = Object.create(null);
  let lastKey = null;
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    if (line.startsWith(' ') && lastKey) {
      map[lastKey] += line.slice(1);
      continue;
    }
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const key = line.slice(0, colon).trim();
    map[key] = line.slice(colon + 1).trim();
    lastKey = key;
  }
  return map;
}

function now() {
  return typeof performance !== 'undefined' ? performance.now() : Date.now();
}

function hex(buffer) {
  return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(file) {
  const bytes = await file.arrayBuffer();
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return hex(digest);
}

function verdictFor(score) {
  if (score >= 55) {
    return {
      level: 'bad',
      title: "Don't run this",
      line: 'Several high-weight signals fired together. Treat it as malware until a decompile says otherwise — even a false positive needs a human look first.',
    };
  }
  if (score >= 22) {
    return {
      level: 'warn',
      title: 'Suspicious',
      line: 'Enough matched that this needs a human look before it touches a real machine. Not proof — a reason to slow down.',
    };
  }
  if (score > 0) {
    return {
      level: 'ok',
      title: 'Nothing obvious',
      line: 'Only low-weight notes. A clean report is a starting point, not a promise — rule-based scans miss things.',
    };
  }
  return {
    level: 'ok',
    title: 'Nothing obvious',
    line: 'No rule matched. That is not the same as safe: the scan reads structure and strings, not intent.',
  };
}

/**
 * Scan a jar.
 * @param {File|Blob} file
 * @param {{ onProgress?: Function, shouldCancel?: () => boolean }} options
 */
export async function scanJar(file, options = {}) {
  const { onProgress = () => {}, shouldCancel = () => false } = options;
  const started = now();

  if (!file || typeof file.size !== 'number') throw new Error('No file given.');
  if (file.size === 0) throw new Error('That file is empty.');
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error('This page cannot hash files here. Open it over HTTPS (or localhost) in a current browser.');
  }
  if (file.size > MAX_FILE_BYTES) {
    throw new Error(`That file is ${formatBytes(file.size)}. The scanner takes up to 200 MB.`);
  }

  const check = () => {
    if (shouldCancel()) throw new ScanCancelled();
  };

  onProgress({ stage: 'hashing the file', pct: 2, detail: 'SHA-256' });
  const digest = await sha256(file);
  check();

  onProgress({ stage: 'reading the archive', pct: 5, detail: 'central directory' });
  const top = await readZip(file);
  check();

  const findings = new Map();
  const urls = new Map();
  const files = [];
  const classes = [];
  const sources = [];
  const nestedCandidates = [];
  let listedTruncated = false;

  function addFinding(rule, filePath, snippet, extraCount = 1) {
    if (!rule) return;
    let entry = findings.get(rule.id);
    if (!entry) {
      entry = {
        id: rule.id,
        sev: rule.sev,
        weight: rule.weight,
        title: rule.title,
        detail: rule.detail,
        count: 0,
        evidence: [],
      };
      findings.set(rule.id, entry);
    }
    entry.count += extraCount;
    if (filePath && entry.evidence.length < 5) {
      entry.evidence.push({ file: sanitizeName(filePath), snippet: snippet || '' });
    }
  }

  function addUrl(raw, sourcePath) {
    if (urls.size >= MAX_URLS) return;
    let url = raw.replace(/[),.;]+$/, '');
    if (url.length < 8) return;
    let bad = false;
    const binary = /\.(?:jar|zip|exe|dll|scr|msi|ps1|bat|vbs|sh)$/i.test(url);
    if (binary) bad = true;
    if (/discord(?:app)?\.com\/api\/webhooks|discord\.com\/api\/v\d+\/webhooks|api\.telegram\.org\/bot|hooks\.slack\.com\/services/i.test(url)) bad = true;
    if (IP_RE.test(url)) bad = true;
    IP_RE.lastIndex = 0;
    for (const rule of URL_HOST_RULES) {
      if (rule.re.test(url)) {
        bad = true;
        addFinding(rule, sourcePath, url);
      }
    }
    const previous = urls.get(url);
    if (previous) {
      previous.count += 1;
      return;
    }
    urls.set(url, { url, count: 1, bad, file: sanitizeName(sourcePath) });
  }

  function scanStrings(text, filePath) {
    for (const rule of CLASS_RULES) {
      const match = rule.re.exec(text);
      if (match) addFinding(rule, filePath, snippetAt(text, match.index));
    }

    URL_RE.lastIndex = 0;
    let match;
    while ((match = URL_RE.exec(text)) !== null) addUrl(match[0], filePath);

    IP_RE.lastIndex = 0;
    while ((match = IP_RE.exec(text)) !== null) {
      const ip = match[0];
      if (PRIVATE_IP.test(ip)) continue;
      addFinding({ id: 'raw-ip', sev: 'med', weight: 10, title: 'Raw IP address', detail: 'A hard-coded IP instead of a domain. Common for throwaway command-and-control endpoints.' }, filePath, ip);
    }
    IP_RE.lastIndex = 0;

    const b64Match = B64_RE.exec(text);
    if (b64Match) {
      addFinding(
        { id: 'base64-blob', sev: 'med', weight: 8, title: 'Large encoded blob', detail: 'A long base64 string. Could be an image or a config — could be a second-stage payload.' },
        filePath,
        snippetAt(text, b64Match.index, 70),
      );
    }
  }

  function registerEntryNames(source) {
    for (const entry of source.entries) {
      if (entry.isDir) continue;
      const path = source.prefix + entry.name;

      if (files.length < MAX_LISTED_FILES) {
        const kind = classify(entry.name, false);
        const flags = [];
        if (kind === 'exec') flags.push('exec');
        if (kind === 'native') flags.push('native');
        if (kind === 'jar') flags.push('nested');
        if (entry.flags & 0x1) flags.push('encrypted');
        files.push({
          path: sanitizeName(path),
          kind,
          size: entry.uncompressedSize,
          flags,
          entry,
          source,
        });
      } else {
        listedTruncated = true;
      }

      if (classify(entry.name, false) === 'class') {
        classes.push({
          path,
          entry,
          source,
          className: entry.name.slice(0, -'.class'.length).replace(/\//g, '.'),
        });
      }

      if (entry.flags & 0x1) addFinding(FILE_RULES.encrypted, path, 'entry is encrypted');

      if (entry.compressedSize > 0 && entry.uncompressedSize > 8 * 1024 * 1024) {
        const ratio = entry.uncompressedSize / entry.compressedSize;
        if (ratio > 90) addFinding(FILE_RULES.bomb, path, `${formatBytes(entry.uncompressedSize)} from ${formatBytes(entry.compressedSize)}`);
      }
    }
  }

  function checkFileNameRules(entry, path) {
    const name = entry.name;
    const ext = extensionOf(name);

    if (EXEC_EXTENSIONS.has(ext)) addFinding(FILE_RULES.executable, path, name);
    else if (NATIVE_EXTENSIONS.has(ext)) addFinding(FILE_RULES.native, path, name);

    if (/\.(?:jar|zip|png|jpe?g|gif|txt|pdf|mp3|mp4|json|cfg|dat|log)\.(?:exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|wsf|ps1)$/i.test(name)) {
      addFinding(FILE_RULES.doubleExtension, path, name);
    }
    if (/[\u202a-\u202e\u2066-\u2069]/.test(name)) {
      addFinding(FILE_RULES.rtl, path, name);
    }
  }

  function sourceFromZip(zip, blob, prefix) {
    const source = { prefix, blob, entries: zip.entries };
    sources.push(source);
    return source;
  }

  const topSource = sourceFromZip(top, file, '');
  for (const entry of top.entries) {
    if (entry.isDir) continue;
    checkFileNameRules(entry, topSource.prefix + entry.name);
    if (classify(entry.name, false) === 'jar' && entry.uncompressedSize <= MAX_NESTED_BYTES && nestedCandidates.length < MAX_NESTED_COUNT) {
      nestedCandidates.push({ entry, path: entry.name });
    }
  }
  registerEntryNames(topSource);

  onProgress({ stage: 'opening nested jars', pct: 12, detail: `${nestedCandidates.length} candidate${nestedCandidates.length === 1 ? '' : 's'}` });
  check();

  let nestedBytes = 0;
  let nestedCount = 0;
  for (const candidate of nestedCandidates) {
    check();
    if (nestedBytes + candidate.entry.uncompressedSize > MAX_NESTED_TOTAL) {
      addFinding(
        { id: 'nested-skipped', sev: 'med', weight: 5, title: 'Nested jar skipped', detail: 'The nested archive is too large to open safely in a tab. Send this one to tickets.' },
        candidate.path,
        `${formatBytes(candidate.entry.uncompressedSize)} nested archive`,
      );
      continue;
    }
    try {
      const { bytes } = await readEntry(file, candidate.entry, MAX_NESTED_BYTES);
      nestedBytes += bytes.length;
      const inner = await readZip(new Blob([bytes]));
      const prefix = `${candidate.path}!/`;
      const innerSource = sourceFromZip(inner, new Blob([bytes]), prefix);
      nestedCount += 1;
      addFinding(FILE_RULES.nested, candidate.path, `${inner.entries.filter((entry) => !entry.isDir).length} entries inside`);

      for (const innerEntry of inner.entries) {
        if (innerEntry.isDir) continue;
        checkFileNameRules(innerEntry, prefix + innerEntry.name);
        const kind = classify(innerEntry.name, false);
        if (kind === 'jar') {
          addFinding(
            { id: 'nested-deep', sev: 'high', weight: 10, title: 'Jar inside a nested jar', detail: 'Two layers of archives is how a clean outer jar ships a payload the scanner was never meant to see.' },
            prefix + innerEntry.name,
            'depth 2 archive',
          );
        }
      }
      registerEntryNames(innerSource);
    } catch (error) {
      addFinding(
        { id: 'nested-unreadable', sev: 'med', weight: 4, title: 'Nested jar could not be opened', detail: 'Encrypted, corrupt, or using an unsupported compression method.' },
        candidate.path,
        error.message,
      );
    }
  }

  // Manifest and text resources.
  const textJobs = [];
  const manifests = [];
  for (const source of sources) {
    for (const entry of source.entries) {
      if (entry.isDir) continue;
      const kind = classify(entry.name, false);
      const ext = extensionOf(entry.name);
      if (kind === 'manifest') manifests.push({ entry, source, path: source.prefix + entry.name });
      else if (kind === 'text' || SCRIPT_TEXT_EXTENSIONS.has(ext)) {
        textJobs.push({ entry, source, path: source.prefix + entry.name });
      }
    }
  }

  let manifestFields = {};
  for (const manifest of manifests) {
    try {
      const { bytes } = await readEntry(manifest.source.blob, manifest.entry, MAX_TEXT_BYTES);
      const text = new TextDecoder('utf-8').decode(bytes);
      manifestFields = { ...parseManifest(text), ...manifestFields };
      const fields = parseManifest(text);
      if (fields['Premain-Class'] || fields['Agent-Class'] || fields['Launcher-Agent-Class']) {
        addFinding(
          {
            id: 'java-agent',
            sev: 'high',
            weight: 20,
            title: 'Java agent entry point',
            detail: 'Premain-Class / Agent-Class attaches into the JVM itself. Cheat clients rarely need this; stealers like it.',
          },
          manifest.path,
          fields['Premain-Class'] || fields['Agent-Class'] || fields['Launcher-Agent-Class'],
        );
      }
      if (fields['Class-Path'] && /https?:\/\//i.test(fields['Class-Path'])) {
        addFinding(
          {
            id: 'remote-classpath',
            sev: 'high',
            weight: 16,
            title: 'Remote class path',
            detail: 'The manifest tells the JVM to load classes from a URL at startup.',
          },
          manifest.path,
          fields['Class-Path'].slice(0, 120),
        );
      }
      scanStrings(text, manifest.path);
    } catch {
      // A manifest that cannot be read is not itself interesting.
    }
  }

  const signed = files.some((fileEntry) => /^META-INF\/[^/]+\.(?:SF|RSA|DSA|EC)$/i.test(fileEntry.path));
  addFinding(
    signed
      ? { id: 'signed-jar', sev: 'info', weight: 0, title: 'Jar is signed', detail: 'A signature only proves who signed it — a stolen key signs malware too. Check the certificate owner if it matters.' }
      : { id: 'unsigned-jar', sev: 'info', weight: 0, title: 'Jar is unsigned', detail: 'Normal for community builds. It means there is no signature to verify, so the hash is the only reference you have.' },
    manifests[0]?.path || '',
    '',
  );

  const totalUnits = classes.length + textJobs.length + 1;
  let done = 0;
  let lastYield = now();
  let lastProgress = 0;

  async function tick(detail) {
    done += 1;
    const time = now();
    const pct = 16 + Math.round((done / totalUnits) * 74);
    if (time - lastYield > 45 || pct - lastProgress >= 2) {
      lastYield = time;
      lastProgress = pct;
      onProgress({ stage: 'scanning contents', pct: Math.min(91, pct), detail });
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    check();
  }

  const obfuscatedNames = [];
  let totalClassEntries = 0;
  let nonAscii = 0;

  for (const item of classes) {
    totalClassEntries += 1;
    const base = item.path.slice(item.path.lastIndexOf('/') + 1, -'.class'.length);
    const outer = base.split('$')[0];
    if (outer.length <= 2 || /^[Il1|_]{2,}$/.test(outer) || (outer.length <= 6 && !/[aeiouyAEIOUY]/.test(outer))) {
      obfuscatedNames.push(base);
    }
    if (/[^\x20-\x7e]/.test(item.entry.name)) nonAscii += 1;

    try {
      const { bytes, truncated } = await readEntry(item.source.blob, item.entry, MAX_CLASS_BYTES);
      if (bytes.length === 0) {
        await tick(item.path);
        continue;
      }
      if (bytes.length < 4 || bytes[0] !== 0xca || bytes[1] !== 0xfe || bytes[2] !== 0xba || bytes[3] !== 0xbe) {
        addFinding(
          {
            id: 'class-mismatch',
            sev: 'high',
            weight: 18,
            title: 'Fake class file',
            detail: 'A file named .class that does not start with the Java class signature. Something else is stored under a class name.',
          },
          item.path,
          Array.from(bytes.subarray(0, 8), (byte) => byte.toString(16).padStart(2, '0')).join(' '),
        );
        await tick(item.path);
        continue;
      }
      if (truncated) {
        addFinding(
          { id: 'oversized-class', sev: 'med', weight: 4, title: 'Oversized class file', detail: 'The class is over 8 MB and was only partly read. Very large classes are usually packed payloads.' },
          item.path,
          formatBytes(item.entry.uncompressedSize),
        );
      }
      const parsed = parseClass(bytes);
      if (!parsed) {
        const lossy = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 512 * 1024));
        scanStrings(lossy, item.path);
        addFinding(
          {
            id: 'malformed-class',
            sev: 'low',
            weight: 4,
            title: 'Malformed class file',
            detail: 'The constant pool could not be parsed. Deliberately broken class files are a common anti-analysis trick.',
          },
          item.path,
          `class file ${bytes[6]}.${bytes[7]}`,
        );
        await tick(item.path);
        continue;
      }
      const text = parsed.strings.join('\n');
      scanStrings(text, item.path);

      for (const value of parsed.strings) {
        if (value.length >= 180 && B64_RE.test(value)) {
          addFinding(
            { id: 'base64-blob', sev: 'med', weight: 8, title: 'Large encoded blob', detail: 'A long base64 string inside a class. Could be an image or a config — could be a second-stage payload.' },
            item.path,
            value.slice(0, 90),
          );
          break;
        }
      }
    } catch (error) {
      addFinding(
        { id: 'unreadable-entries', sev: 'low', weight: 3, title: 'Entry could not be read', detail: 'Out of memory, encrypted, or compressed with an unsupported method. Not proof of anything on its own.' },
        item.path,
        error.message,
      );
    }
    await tick(item.path);
  }

  for (const job of textJobs) {
    try {
      const { bytes } = await readEntry(job.source.blob, job.entry, MAX_TEXT_BYTES);
      const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      scanStrings(text, job.path);
    } catch {
      // Text we cannot read is not worth a finding of its own.
    }
    await tick(job.path);
  }

  await tick('scoring');

  // Obfuscation heuristics, only meaningful past a handful of classes.
  if (totalClassEntries >= 15) {
    const ratio = obfuscatedNames.length / totalClassEntries;
    if (ratio > 0.8) {
      addFinding(
        {
          id: 'obfuscation',
          sev: 'high',
          weight: 14,
          title: 'Heavy class-name obfuscation',
          detail: `${Math.round(ratio * 100)}% of classes have throwaway names. Obfuscation protects the author from you reading the build.`,
        },
        '',
        `${obfuscatedNames.length}/${totalClassEntries} classes`,
      );
    } else if (ratio > 0.5) {
      addFinding(
        {
          id: 'obfuscation',
          sev: 'med',
          weight: 9,
          title: 'Obfuscated class names',
          detail: `${Math.round(ratio * 100)}% of classes use short or generated names, which makes a manual review slower.`,
        },
        '',
        `${obfuscatedNames.length}/${totalClassEntries} classes`,
      );
    }
  }
  if (nonAscii > 0) {
    addFinding(
      {
        id: 'nonascii-names',
        sev: 'med',
        weight: 6,
        title: 'Non-ASCII entry names',
        detail: 'Unicode names are used to get past filters and eyeballs. Sometimes they are just localisation files.',
      },
      '',
      `${nonAscii} entries`,
    );
  }

  const findingsList = Array.from(findings.values()).sort((a, b) => {
    const order = { high: 0, med: 1, low: 2, info: 3 };
    return (b.weight - a.weight) || (order[a.sev] - order[b.sev]) || (b.count - a.count);
  });

  let rawScore = 0;
  for (const finding of findingsList) {
    rawScore += finding.weight;
    if (finding.count > 1 && finding.weight > 0) rawScore += Math.min(6, finding.count - 1);
  }
  const score = Math.max(0, Math.min(100, Math.round(rawScore)));
  const verdict = verdictFor(score);

  const elapsed = Math.max(1, Math.round(now() - started));

  const report = {
    fileName: file.name || 'archive.jar',
    fileSize: file.size,
    sha256: digest,
    scannedAt: new Date().toISOString().slice(0, 10),
    elapsedMs: elapsed,
    score,
    verdict,
    entryCount: 0,
    classCount: totalClassEntries,
    nestedCount,
    findingCounts: {
      high: findingsList.filter((finding) => finding.sev === 'high').length,
      med: findingsList.filter((finding) => finding.sev === 'med').length,
      low: findingsList.filter((finding) => finding.sev === 'low').length,
    },
    findings: findingsList,
    urls: Array.from(urls.values()).sort((a, b) => Number(b.bad) - Number(a.bad) || a.url.localeCompare(b.url)),
    manifest: manifestFields,
    files,
    filesTruncated: listedTruncated,
    classes,
    sources,
    signed,
  };
  report.entryCount = sources.reduce((count, source) => count + source.entries.filter((entry) => !entry.isDir).length, 0);

  onProgress({ stage: 'done', pct: 100, detail: '' });
  return report;
}

export async function outlineFor(report, classItem) {
  try {
    const { bytes } = await readEntry(classItem.source.blob, classItem.entry, MAX_CLASS_BYTES);
    const parsed = parseClass(bytes);
    return renderOutline(parsed);
  } catch (error) {
    return `Could not read this class: ${error.message}`;
  }
}

export function toMarkdown(report) {
  const lines = [];
  lines.push(`# Netmask scan — ${report.fileName}`);
  lines.push('');
  lines.push(`- scanned: ${report.scannedAt}`);
  lines.push(`- ruleset: ${RULESET}`);
  lines.push(`- sha-256: \`${report.sha256}\``);
  lines.push(`- size: ${formatBytes(report.fileSize)}`);
  lines.push(`- verdict: **${report.verdict.title}** (risk ${report.score}/100)`);
  lines.push(`- entries: ${report.entryCount} · classes: ${report.classCount} · nested jars: ${report.nestedCount}`);
  lines.push('');
  lines.push('A heuristic pass, not a guarantee. Read the findings.');
  lines.push('');
  lines.push('## Findings');
  if (!report.findings.length) lines.push('');
  if (!report.findings.length) lines.push('No rule matched.');
  for (const finding of report.findings) {
    lines.push('');
    lines.push(`### [${finding.sev.toUpperCase()}] ${finding.title} — ${finding.count} hit${finding.count === 1 ? '' : 's'}`);
    lines.push('');
    lines.push(finding.detail);
    if (finding.evidence.length) {
      lines.push('');
      for (const item of finding.evidence) {
        lines.push(`- \`${item.file || 'archive'}\`${item.snippet ? ` — \`${item.snippet.replace(/`/g, "'")}\`` : ''}`);
      }
    }
  }
  if (report.urls.length) {
    lines.push('');
    lines.push('## URLs found');
    lines.push('');
    for (const url of report.urls.slice(0, 80)) {
      lines.push(`- ${url.bad ? '**flagged** ' : ''}${url.url}`);
    }
  }
  if (Object.keys(report.manifest).length) {
    lines.push('');
    lines.push('## Manifest');
    lines.push('');
    for (const [key, value] of Object.entries(report.manifest)) {
      lines.push(`- ${key}: \`${String(value).slice(0, 200)}\``);
    }
  }
  lines.push('');
  lines.push('---');
  lines.push('Scanned locally in a browser. Nothing was uploaded.');
  return lines.join('\n');
}
