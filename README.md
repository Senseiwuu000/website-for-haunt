# Netmask

A dark, single-page site for a cracked-builds / cheat library, plus a working
JAR scanner that runs entirely in the browser. No framework, no build step, no
CDN, no analytics, no external fonts.

Sections: hero → catalog → JAR scanner → know ratters → FAQ → tickets.

## Run it

ES modules do not load from `file://`, so use any static server:

```bash
python3 -m http.server 3000
# open http://localhost:3000
```

`npx serve .`, Caddy, nginx, GitHub Pages, Cloudflare Pages or any static host
works too. The host must serve `.js` as `text/javascript` (all sane ones do),
and the clipboard button needs HTTPS or localhost.

## Replace these before publishing

1. **Discord invite.** `assets/js/data.js` → `site.invite`. While it is empty,
   every ticket button explains itself instead of sending people to a dead
   invite. Put the real invite in once the server is ready.
2. **Listings.** Also `assets/js/data.js`. The nine entries are demo content and
   are labelled as such on the page. Shape:

   ```js
   {
     id: 'unique-slug',
     name: 'Aurora',
     version: '3.2',
     cat: 'minecraft',        // minecraft | gta5 | software | tweaks
     blurb: 'One or two sentences.',
     size: '2.14 MB',
     checked: '2026-10-24',   // YYYY-MM-DD
     status: 'clean',         // clean | reviewed | pending
     hash: '64 hex chars',    // null renders as "hash pending"
     notes: ['shown in the details dialog'],
   }
   ```

   The filter chips and counts are generated from this array. The footer's
   "last swept" date is the newest `checked` value. Delete the `.demo-note`
   paragraph above the cards once real listings are in.
3. **Know-ratters rows.** In `index.html`, search for "sample rows". The three
   rows are clearly marked examples — publish a name only with a hash and a
   decompile attached, and keep the evidence column honest. The mobile layout
   stacks each row into a card automatically. Remove the `.sample-banner` once
   the rows are real.
4. **Logo.** Replace `assets/img/logo.svg` (header + footer, 32×32 viewBox) and
   `assets/img/favicon.svg` (browser tab). If you have a square PNG, point the
   two `<img class="logo-mark">` tags at it instead.
5. **Ruleset version.** `assets/js/scanner.js` → `RULESET`. It is used in scan
   reports and filled into the header/footer `[data-ruleset]` slots.
6. **Copy.** Hero, FAQ, tickets and footer text are plain HTML in `index.html`.
   Dates are ISO, so the catalog formats them consistently.

## The scanner is real

No upload endpoint exists. Open the network tab and scan something: the only
requests are the page's own files.

- `assets/js/zip.js` — ZIP/JAR reader written from scratch. Finds the end of
  central directory, follows the ZIP64 locator when needed, parses entries and
  local headers, and inflates with the browser's `DecompressionStream`
  (`deflate-raw`). Stored entries are handled too.
- `assets/js/classfile.js` — Java class-file parser: modified UTF-8 constant
  pool, access flags, fields, methods, interfaces, `SourceFile`. Renders the
  class outline (declarations only, no bytecode reconstruction).
- `assets/js/scanner.js` — the rules and the report. It checks:
  - manifest (`Premain-Class`, `Agent-Class`, remote `Class-Path`), signatures
  - embedded executables, DLL/SO files, double extensions, RTL filename tricks
  - nested jars (one level), encrypted entries, zip-bomb compression ratios
  - class-name obfuscation, malformed and fake `.class` entries
  - class strings and text/script resources: process execution, shell/LOLBins,
    Discord/Telegram webhooks, paste/file hosts, runtime class definition,
    class loaders, persistence paths, credential paths, screen/keyboard/clipboard
    features, VM/debugger checks, native loading, base64 blobs, raw IPs
  - every URL in the build, deduplicated and marked when it looks like payload
    hosting
- `assets/js/scanner-ui.js` — dropzone, progress, tabs, outline viewer, Markdown
  export. Calls into the scanner; contains no analysis logic.
- `assets/js/main.js` — catalog, filters, listing dialog, mobile nav, ticket links.

### Limits (stated on the page too)

- 200 MB per file. The hash and scan happen in the tab; a 200 MB file needs
  enough free browser memory.
- Class files up to 8 MB are read (larger ones are noted), text up to 1 MB,
  nested jars up to 48 MB each / 12 jars / 128 MB total. Nested *jars inside
  nested jars* are flagged, not opened.
- The entry list is capped at 30,000 rows in the UI; counts still cover the
  whole archive.
- Requires a current browser with `DecompressionStream` and Web Crypto. If it is
  missing, the scanner says so rather than pretending a scan happened.
- **This is not a decompiler.** The outline tab shows real parsed declarations.
  Full Vineflower / Recaf / Fernflower output needs a JVM, so the site routes it
  to `#tickets` (as the brief does). A static page cannot run those tools; if
  inline decompilation is wanted, it needs a backend, not a static host.
- Rules are heuristics. "Don't run this" means several strong signals fired;
  "Nothing obvious" only means nothing matched. Neither is proof of intent.
  Nothing in the archive is executed or loaded — it is parsed as data — but
  unknown jars still belong in a VM.

The scanner is readable on purpose: both the scanner panel and the FAQ link
`assets/js/scanner.js` directly.

## Tests

The analysis core is DOM-free, so it runs in Node:

```bash
mkdir -p .tmp
curl -fL -o .tmp/commons-lang3.jar \
  https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar
python3 scripts/make-fixtures.py
node scripts/scan-test.mjs
```

It verifies:

- a real 400+ class jar stays out of the "suspicious" range, parses every class,
  produces a real outline and a Markdown report;
- a synthetic suspicious jar trips agent manifest, remote class path, embedded
  EXE, double extension, webhook, persistence, credential paths, shell strings,
  nested jar, nested-in-nested and fake-class rules;
- non-zip/small input fails readably, and cancellation stops the run.

`scripts/make-fixtures.py` needs Python 3 and the downloaded commons-lang3 jar.
Tests were run on Node 24.

Browser QA was done headlessly at 1440, 768 and 390 px: no console errors, no
horizontal overflow, catalog filters/dialog/FAQ work, and a real 43-entry jar
scans end to end with findings, file table and class outline. That browser check
is a local script, not part of the site.

## Deploy

Upload the folder as-is; there is no build. Good fits: Cloudflare Pages,
GitHub Pages, Netlify, any nginx/Apache static root. Don't put the `.git`
directory or `scripts/` in a public web root if you don't want the fixtures
script served (harmless either way).

## Content notes

- The demo listings and all three ratter rows are fictional sample content. They
  must be replaced with real, substantiated entries before launch. The site's own
  rule is "no evidence, no row" — keep it.
- Cracked builds and cheats break terms of service and can get accounts banned.
  The footer says so; keep that warning.
- This page intentionally does not host or link any files. Listings carry hashes
  and point people to the server/tickets.

## File map

```
index.html
assets/
  css/styles.css        design tokens live at the top
  img/logo.svg          swap me
  img/favicon.svg       swap me
  js/
    data.js             site + listings (edit me)
    main.js             page UI
    scanner-ui.js       scanner UI
    scanner.js          rules + report (core)
    zip.js              ZIP reader
    classfile.js        class parser + outline
scripts/
  make-fixtures.py      test fixtures
  scan-test.mjs         Node tests
```
