/**
 * Site content.
 *
 * The three demo listings below are shaped exactly like real ones:
 * swap name / blurb / version / size / date / hash and they render as-is.
 * `hash` is the full SHA-256 of the build. `null` renders as "pending".
 *
 * status: 'clean' | 'reviewed' | 'pending'
 * cat:    'minecraft' | 'gta5' | 'software' | 'tweaks'
 */

export const site = {
  name: 'Netmask',
  // Put your Discord invite here. Empty means the buttons explain themselves
  // instead of sending people to a dead invite.
  invite: '',
  ticketsChannel: '#tickets',
};

export const categories = [
  { id: 'all', label: 'All' },
  { id: 'minecraft', label: 'Minecraft' },
  { id: 'gta5', label: 'GTA V' },
  { id: 'software', label: 'Software' },
  { id: 'tweaks', label: 'Tweaks' },
];

export const listings = [
  {
    id: 'aurora-3-2',
    name: 'Aurora',
    version: '3.2',
    cat: 'minecraft',
    blurb: 'The 1.8.9 client people keep asking for. Config-driven modules, no launcher, no account check.',
    size: '2.14 MB',
    checked: '2026-10-24',
    status: 'clean',
    hash: 'eb2f3953fbce610304d8ade1dec8a73e07df69d973b4b105abc0bf613d93653f',
    notes: [
      'Scanned with ruleset 2026.10.3: four low findings, all reflection noise from the GUI library.',
      'Config folder is created next to the jar. Nothing writes to AppData or Startup.',
      'Old builds get retired from the shelf when a new one is scanned — hashes never silently change.',
    ],
  },
  {
    id: 'basalt-1-21',
    name: 'Basalt',
    version: '1.21.1',
    cat: 'minecraft',
    blurb: 'A Fabric utility client with the usual ESP and reach set. Keep your loader version matched or it will not boot.',
    size: '1.41 MB',
    checked: '2026-10-22',
    status: 'reviewed',
    hash: '1b87d4b4697b0cb06ff8bc76474e4393d83b5b839ac6df88335e0914b62c2168',
    notes: [
      'Clean scan, then a manual pass over the mixin package because it uses a custom class loader.',
      'Loader only touches classes inside its own jar — verified by hand, not just by the rule.',
      'Ships no updater. You update it or you do not.',
    ],
  },
  {
    id: 'cirrus-lite',
    name: 'Cirrus Lite',
    version: '0.6',
    cat: 'minecraft',
    blurb: 'Small module set built for potato PCs. No updater, no telemetry, 780 KB and it stays 780 KB.',
    size: '780 KB',
    checked: '2026-10-19',
    status: 'clean',
    hash: 'd345d15d1b31d9fb049af5f393330c71ce66a5e5b396c72ae57de7d948b0cfa1',
    notes: [
      'No network classes at all. The only URL in the jar is the GitHub page in the licence header.',
      'One class, one package, no obfuscation. Easy to read even without a decompiler.',
    ],
  },
  {
    id: 'undertow-2-4',
    name: 'Undertow',
    version: '2.4',
    cat: 'gta5',
    blurb: 'Menu build for the current GTA Online patch. The injector is separate and sits in the same folder.',
    size: '18.6 MB',
    checked: '2026-10-20',
    status: 'reviewed',
    hash: 'cb2d98f205cfb67b40fdeb380b3f2a22e93c2ee7940886df49ae1ca8c6c6da45',
    notes: [
      'Archive contains a native DLL — flagged by the scan, signed off after a manual look.',
      'The DLL has no network imports beyond the game overlay; no exec, no persistence writes.',
      'Injector is unsigned. Windows will complain. That is expected for this kind of build.',
    ],
  },
  {
    id: 'static-1-1',
    name: 'Static',
    version: '1.1',
    cat: 'gta5',
    blurb: 'Smaller menu, mostly recovery options. Held off the shelf until a second pass finishes.',
    size: '9.2 MB',
    checked: '2026-10-12',
    status: 'pending',
    hash: null,
    notes: [
      'Waiting on a second scan with the current ruleset before it gets a published hash.',
      'No download link goes out until that hash exists. No exceptions, including for friends.',
    ],
  },
  {
    id: 'slate-studio-7',
    name: 'Slate Studio 7',
    version: '7.4.1',
    cat: 'software',
    blurb: 'Offline activation, no account, no phone-home. Full patched installer, staged on the file host.',
    size: '1.42 GB',
    checked: '2026-10-18',
    status: 'reviewed',
    hash: 'c94fea0f47b0dc25e215961a34378fc0fca61e4c628cf5563fce581f854b245f',
    notes: [
      'Installer is a repack, not a patch. Run it on a clean machine; do not layer it over a paid copy.',
      'The licence stub is patched at install time. Nothing calls out after first launch — checked with a firewall rule.',
      'Hash covers the full 1.42 GB archive, not the installer inside it.',
    ],
  },
  {
    id: 'tempo-daw-12',
    name: 'Tempo DAW 12',
    version: '12.0.3',
    cat: 'software',
    blurb: 'Audio workstation with the licence check patched out. Needs a clean install first.',
    size: '861 MB',
    checked: '2026-10-11',
    status: 'pending',
    hash: null,
    notes: [
      'Hash pending — the archive is too big for the in-browser scanner and goes through a manual pass.',
      'No download link until that pass is done.',
    ],
  },
  {
    id: 'quiet-boot',
    name: 'Quiet Boot',
    version: '1.3',
    cat: 'tweaks',
    blurb: 'A tiny debloat script for Windows 10 and 11. Read it before running it — that is how scripts should work.',
    size: '42 KB',
    checked: '2026-10-23',
    status: 'clean',
    hash: 'a7cc49bb8df9da7adfffb89b9a432761fa47e003c987e4259eaca918cc355339',
    notes: [
      'Plain PowerShell and a reg file. No binaries, no downloads, no scheduled tasks.',
      'Every disable is commented and reversible; the undo script is in the same folder.',
    ],
  },
  {
    id: 'frame-sync',
    name: 'Frame Sync',
    version: '0.9',
    cat: 'tweaks',
    blurb: 'Frame pacing tweak with a config file instead of a background service. Nothing to uninstall — delete the folder.',
    size: '16 KB',
    checked: '2026-10-16',
    status: 'reviewed',
    hash: 'cb8a3c85c062716651fd2ab335bf15b37cdbd63f4fa18b1d71153509e94cfe1d',
    notes: [
      'Sets one timer resolution value and exits. No service, no startup entry.',
      'Manual review confirmed the only write is its own config file.',
    ],
  },
];
