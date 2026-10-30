/**
 * Node smoke tests for the analysis core. Run: node scripts/scan-test.mjs
 * Fixtures come from scripts/make-fixtures.py (needs .tmp/commons-lang3.jar).
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import { File } from 'node:buffer';

import { scanJar, outlineFor, toMarkdown, RULESET } from '../assets/js/scanner.js';
import { readZip } from '../assets/js/zip.js';

const tmp = path.join(process.cwd(), '.tmp');

async function openFixture(name) {
  const bytes = await fs.readFile(path.join(tmp, name));
  return new File([bytes], name, { type: 'application/java-archive' });
}

function findingIds(report) {
  return report.findings.map((finding) => finding.id);
}

let passed = 0;
function ok(label) {
  passed += 1;
  console.log(`  ok  ${label}`);
}

/* ---------------------------------------------------------------- clean jar */
{
  const file = await openFixture('commons-lang3.jar');
  const progress = [];
  const report = await scanJar(file, { onProgress: (event) => progress.push(event.pct) });

  console.log('\ncommons-lang3.jar');
  console.log(`  verdict: ${report.verdict.title} (${report.score}/100)`);
  console.log(`  entries: ${report.entryCount}, classes: ${report.classCount}, nested: ${report.nestedCount}`);
  console.log(`  findings: ${report.findings.map((f) => `${f.id}(${f.sev})`).join(', ') || 'none'}`);
  console.log(`  ${report.elapsedMs} ms`);

  const zip = await readZip(file);
  const expectedEntries = zip.entries.filter((entry) => !entry.isDir).length;

  assert.equal(report.fileName, 'commons-lang3.jar');
  assert.match(report.sha256, /^[0-9a-f]{64}$/);
  assert.equal(report.entryCount, expectedEntries);
  assert.ok(report.classCount > 300, `expected >300 classes, got ${report.classCount}`);
  assert.equal(report.nestedCount, 0);
  assert.equal(report.signed, false, 'this build is not signed');
  assert.ok(report.score < 22, `a utility library should not score as suspicious (${report.score})`);
  assert.equal(report.findingCounts.high, 0, `unexpected high findings: ${findingIds(report)}`);
  assert.ok(progress.at(-1) === 100);
  assert.ok(progress.some((pct) => pct > 20 && pct < 95), 'progress moves through the scan');

  const first = report.classes.find((item) => item.className === 'org.apache.commons.lang3.StringUtils');
  assert.ok(first, 'StringUtils class is listed');
  const outline = await outlineFor(report, first);
  assert.match(outline, /class org\.apache\.commons\.lang3\.StringUtils/);
  assert.match(outline, /public static boolean isEmpty\(CharSequence\)/);
  assert.match(outline, /source: StringUtils\.java/);
  console.log('  outline preview:');
  console.log(outline.split('\n').slice(0, 7).map((line) => `    ${line}`).join('\n'));

  const markdown = toMarkdown(report);
  assert.match(markdown, /# Netmask scan/);
  assert.match(markdown, new RegExp(`ruleset: ${RULESET}`));
  assert.match(markdown, /Scanned locally/);

  ok('clean jar scans, hashes, outlines and reports');
}

/* ----------------------------------------------------------- suspicious jar */
{
  const file = await openFixture('suspect.jar');
  const report = await scanJar(file);

  console.log('\nsuspect.jar');
  console.log(`  verdict: ${report.verdict.title} (${report.score}/100)`);
  console.log(`  entries: ${report.entryCount}, classes: ${report.classCount}, nested: ${report.nestedCount}`);
  for (const finding of report.findings) {
    console.log(`  [${finding.sev}] ${finding.id} x${finding.count} — ${finding.evidence[0]?.snippet?.slice(0, 70) || ''}`);
  }

  const ids = new Set(findingIds(report));
  assert.ok(report.score >= 55, `suspicious jar should score >=55, got ${report.score}`);
  assert.equal(report.verdict.title, "Don't run this");
  assert.equal(report.nestedCount, 1);
  assert.equal(report.signed, true, 'the .SF entry marks it as signed');
  assert.ok(report.classCount >= 32, `expected the nested class too, got ${report.classCount}`);
  for (const expected of [
    'java-agent',
    'remote-classpath',
    'embedded-exec',
    'double-extension',
    'discord-webhook',
    'persistence',
    'credential-paths',
    'shell-strings',
    'nested-jar',
    'nested-deep',
    'class-mismatch',
    'payload-host',
  ]) {
    assert.ok(ids.has(expected), `missing finding: ${expected} (got ${[...ids].join(', ')})`);
  }
  assert.ok(report.urls.some((url) => url.bad && url.url.includes('discord.com/api/webhooks')));
  assert.ok(report.manifest['Premain-Class'] === 'dev.aurora.Agent');
  assert.ok(report.files.some((entry) => entry.path === 'lib/loader.jar' && entry.kind === 'jar'));
  assert.ok(report.files.some((entry) => entry.path.startsWith('lib/loader.jar!/dev/aurora/Nested.class')));
  assert.ok(report.findings.some((finding) => finding.id === 'nested-jar' && finding.evidence[0].file === 'lib/loader.jar'));

  const nestedClass = report.classes.find((item) => item.path === 'lib/loader.jar!/dev/aurora/Nested.class');
  assert.ok(nestedClass, 'nested class listed');
  const outline = await outlineFor(report, nestedClass);
  assert.match(outline, /class org\.apache\.commons\.lang3\.math\.NumberUtils/);

  ok('suspicious jar trips the rules it should');
}

/* --------------------------------------------------------------- bad input */
{
  const junk = new File([new Uint8Array(4096).fill(0x41)], 'junk.jar');
  await assert.rejects(() => scanJar(junk), /not a jar|central directory/i);
  ok('non-zip input fails with a readable error');

  const tiny = new File([new Uint8Array(10)], 'tiny.jar');
  await assert.rejects(() => scanJar(tiny), /small/i);
  ok('tiny input fails with a readable error');

  await assert.rejects(() => readZip(new Blob([])), /small/i);

  let cancelled = false;
  const file = await openFixture('suspect.jar');
  await assert.rejects(
    () => scanJar(file, {
      shouldCancel: () => {
        cancelled = true;
        return true;
      },
    }),
    (error) => error.name === 'ScanCancelled',
  );
  assert.equal(cancelled, true);
  ok('cancellation stops the scan');
}

console.log(`\n${passed} checks passed.`);
