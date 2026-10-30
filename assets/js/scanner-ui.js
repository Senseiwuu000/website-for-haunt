/**
 * Scanner UI. Owns the dropzone, the progress bar, the tabs and the report
 * rendering. All analysis lives in scanner.js; this file only draws things.
 */

import {
  scanJar,
  outlineFor,
  toMarkdown,
  RULES_SUMMARY,
  MAX_FILE_BYTES,
  ScanCancelled,
} from './scanner.js';
import { formatBytes } from './zip.js';

const SEV_LABEL = { high: 'high', med: 'medium', low: 'low', info: 'note' };

function h(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function el(id) {
  return document.getElementById(id);
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.top = '-100px';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch {
      ok = false;
    }
    area.remove();
    return ok;
  }
}

export function initScanner({ toast = () => {} } = {}) {
  const drop = el('drop');
  const steps = el('scanSteps');
  const input = el('fileInput');
  const pick = el('pickFile');
  const progress = el('scanProgress');
  const progressStage = el('progressStage');
  const progressPct = el('progressPct');
  const progressBar = el('progressBar');
  const progressDetail = el('progressDetail');
  const cancelButton = el('cancelScan');
  const results = el('scanResults');
  const verdict = el('verdict');
  const verdictTitle = el('verdictTitle');
  const verdictLine = el('verdictLine');
  const scoreBar = el('scoreBar');
  const scoreNum = el('scoreNum');
  const mFile = el('mFile');
  const mHash = el('mHash');
  const mEntries = el('mEntries');
  const mClasses = el('mClasses');
  const mNested = el('mNested');
  const mTime = el('mTime');
  const findingsWrap = el('findings');
  const urlsBlock = el('urlsBlock');
  const urlList = el('urlList');
  const fileSearch = el('fileSearch');
  const fileCount = el('fileCount');
  const fileRows = el('fileRows');
  const classSearch = el('classSearch');
  const classList = el('classList');
  const outlineView = el('outlineView');
  const resetButton = el('resetScan');
  const copyReportButton = el('copyReport');
  const downloadReportButton = el('downloadReport');

  if (!drop || !input) return;

  const tabs = [
    { name: 'findings', tab: el('tabFindings'), panel: el('panelFindings') },
    { name: 'files', tab: el('tabFiles'), panel: el('panelFiles') },
    { name: 'outline', tab: el('tabOutline'), panel: el('panelOutline') },
  ];

  const counts = {
    findings: el('countFindings'),
    files: el('countFiles'),
    classes: el('countClasses'),
  };

  // The rules list on the left is generated from the same source of truth as
  // the scanner, so the "what it looks for" list cannot drift out of date.
  const ruleList = el('ruleList');
  if (ruleList) {
    for (const rule of RULES_SUMMARY) {
      const li = h('li');
      li.appendChild(h('span', `rule-sev ${rule.sev}`, ''));
      li.appendChild(h('span', '', rule.label));
      ruleList.appendChild(li);
    }
  }

  let report = null;
  let busy = false;
  let cancelRequested = false;
  let scanToken = 0;
  let selectedClassButton = null;
  let outlineRendered = false;

  function setProgress(stage, pct, detail) {
    progressStage.textContent = stage;
    const rounded = Math.max(0, Math.min(100, Math.round(pct)));
    progressPct.textContent = `${rounded}%`;
    progressBar.style.width = `${rounded}%`;
    progressDetail.textContent = detail || '\u00a0';
    progressDetail.title = detail || '';
  }

  function setBusy(next) {
    busy = next;
    drop.classList.toggle('is-busy', next);
    drop.setAttribute('aria-busy', next ? 'true' : 'false');
  }

  function resetView() {
    report = null;
    selectedClassButton = null;
    outlineRendered = false;
    results.hidden = true;
    progress.hidden = true;
    drop.hidden = false;
    if (steps) steps.hidden = false;
    fileSearch.value = '';
    classSearch.value = '';
    outlineView.textContent = 'Pick a class on the left.';
    urlList.textContent = '';
    urlsBlock.hidden = true;
    setProgress('reading archive', 0, '');
  }

  function renderVerdict(data) {
    verdict.className = `verdict is-${data.verdict.level}`;
    verdictTitle.textContent = data.verdict.title;
    verdictLine.textContent = data.verdict.line;
    scoreNum.textContent = String(data.score);
    scoreBar.style.width = `${data.score}%`;

    mFile.textContent = `${data.fileName} · ${formatBytes(data.fileSize)}`;
    mFile.title = mFile.textContent;
    mHash.textContent = data.sha256;
    mHash.title = data.sha256;
    mEntries.textContent = data.entryCount.toLocaleString();
    mClasses.textContent = data.classCount.toLocaleString();
    mNested.textContent = data.nestedCount.toLocaleString();
    mTime.textContent = data.elapsedMs < 1000 ? `${data.elapsedMs} ms` : `${(data.elapsedMs / 1000).toFixed(1)} s`;

    counts.findings.textContent = String(data.findings.length);
    counts.files.textContent = String(data.entryCount);
    counts.classes.textContent = String(data.classCount);
  }

  function renderFindings(data) {
    findingsWrap.textContent = '';

    if (!data.findings.length) {
      findingsWrap.appendChild(
        h('p', 'findings-empty', 'No rule matched. That is not a clean bill of health — if you do not know the author, send it for a decompile anyway.'),
      );
    }

    for (const finding of data.findings) {
      const card = h('article', 'finding');
      card.dataset.sev = finding.sev;

      const head = h('div', 'finding-head');
      head.appendChild(h('span', 'pill', SEV_LABEL[finding.sev] || finding.sev));
      head.appendChild(h('h4', '', finding.title));
      if (finding.count > 1) head.appendChild(h('span', 'finding-count', `${finding.count} hits`));
      card.appendChild(head);

      card.appendChild(h('p', 'finding-detail', finding.detail));

      if (finding.evidence.length) {
        const list = h('ul', 'evidence-list');
        for (const item of finding.evidence) {
          const li = h('li');
          const file = h('span', 'file', item.file || 'archive');
          file.title = item.file || '';
          li.appendChild(file);
          if (item.snippet) {
            const snippet = h('span', 'snip', item.snippet);
            snippet.title = item.snippet;
            li.appendChild(snippet);
          }
          list.appendChild(li);
        }
        card.appendChild(list);
      }

      findingsWrap.appendChild(card);
    }

    urlList.textContent = '';
    if (data.urls.length) {
      urlsBlock.hidden = false;
      const shown = data.urls.slice(0, 80);
      for (const item of shown) {
        const li = h('li', item.bad ? 'is-bad' : '', item.url);
        li.title = `${item.url}${item.file ? `\nfound in ${item.file}` : ''}`;
        urlList.appendChild(li);
      }
      if (data.urls.length > shown.length) {
        urlList.appendChild(h('li', '', `… ${data.urls.length - shown.length} more in the report`));
      }
    } else {
      urlsBlock.hidden = true;
    }
  }

  function renderFiles() {
    if (!report) return;
    const query = fileSearch.value.trim().toLowerCase();
    const all = report.files.filter((file) => {
      if (!query) return true;
      return file.path.toLowerCase().includes(query) || file.kind.includes(query) || file.flags.join(' ').includes(query);
    });

    fileRows.textContent = '';
    const limit = 800;
    const shown = all.slice(0, limit);
    const fragment = document.createDocumentFragment();

    for (const file of shown) {
      const row = document.createElement('tr');
      row.appendChild(h('td', '', file.path));
      row.appendChild(h('td', 'type', file.kind));
      row.appendChild(h('td', 'num', formatBytes(file.size)));

      const flagsCell = h('td');
      if (!file.flags.length) {
        flagsCell.textContent = '—';
      } else {
        for (const flag of file.flags) {
          const tone = flag === 'exec' || flag === 'native' || flag === 'encrypted'
            ? 'bad'
            : flag === 'nested'
              ? 'flag'
              : '';
          const label = flag === 'nested' ? 'jar' : flag;
          flagsCell.appendChild(h('span', `flag ${tone}`, label));
          flagsCell.appendChild(document.createTextNode(' '));
        }
      }
      row.appendChild(flagsCell);
      fragment.appendChild(row);
    }

    if (!all.length) {
      const row = document.createElement('tr');
      const cell = h('td', '', 'No entries match that filter.');
      cell.colSpan = 4;
      row.appendChild(cell);
      fragment.appendChild(row);
    }

    fileRows.appendChild(fragment);

    const truncation = all.length > limit ? ` · showing ${limit}` : '';
    const listed = report.filesTruncated ? ' · list capped' : '';
    fileCount.textContent = `${all.length}${truncation} of ${report.entryCount} entries${listed}`;
  }

  async function pickClass(item, button) {
    if (selectedClassButton) selectedClassButton.classList.remove('is-active');
    selectedClassButton = button;
    button.classList.add('is-active');
    outlineView.textContent = 'Reading class…';
    const outline = await outlineFor(report, item);
    outlineView.textContent = outline;
    outlineView.scrollTop = 0;
  }

  function renderClasses() {
    if (!report) return;
    const query = classSearch.value.trim().toLowerCase();
    const all = report.classes.filter((item) => {
      if (!query) return true;
      return item.className.toLowerCase().includes(query) || item.path.toLowerCase().includes(query);
    });

    classList.textContent = '';
    if (!report.classes.length) {
      classList.appendChild(h('li', '', 'No class files in this archive.'));
      outlineView.textContent = 'Nothing to outline.';
      return;
    }

    const limit = 300;
    for (const item of all.slice(0, limit)) {
      const li = document.createElement('li');
      const button = h('button', '', item.className);
      button.type = 'button';
      button.title = item.path;
      button.addEventListener('click', () => pickClass(item, button));
      li.appendChild(button);
      classList.appendChild(li);
    }

    if (!all.length) {
      classList.appendChild(h('li', '', 'No class matches that filter.'));
    } else if (all.length > limit) {
      classList.appendChild(h('li', '', `… ${all.length - limit} more — narrow the search`));
    }
  }

  function activateTab(name, { focus = false } = {}) {
    for (const entry of tabs) {
      const active = entry.name === name;
      entry.tab.classList.toggle('is-active', active);
      entry.tab.setAttribute('aria-selected', active ? 'true' : 'false');
      entry.panel.hidden = !active;
      if (active && focus) entry.tab.focus();
    }

    if (name === 'files') renderFiles();
    if (name === 'outline') {
      renderClasses();
      if (!outlineRendered && report && report.classes.length) {
        outlineRendered = true;
        const first = classList.querySelector('button');
        if (first) first.click();
      }
    }
  }

  for (const entry of tabs) {
    entry.tab.addEventListener('click', () => activateTab(entry.name));
    entry.tab.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
      event.preventDefault();
      const index = tabs.indexOf(entry);
      const next = event.key === 'ArrowRight'
        ? (index + 1) % tabs.length
        : (index - 1 + tabs.length) % tabs.length;
      activateTab(tabs[next].name, { focus: true });
    });
  }

  fileSearch.addEventListener('input', renderFiles);
  classSearch.addEventListener('input', renderClasses);

  async function startScan(file) {
    if (!file || busy) return;
    if (file.size > MAX_FILE_BYTES) {
      toast(`That file is ${formatBytes(file.size)} — the scanner takes up to 200 MB.`, { error: true });
      return;
    }

    setBusy(true);
    cancelRequested = false;
    scanToken += 1;
    const token = scanToken;
    report = null;
    results.hidden = true;
    drop.hidden = true;
    if (steps) steps.hidden = true;
    progress.hidden = false;
    setProgress('hashing the file', 1, file.name);

    try {
      const data = await scanJar(file, {
        shouldCancel: () => cancelRequested || token !== scanToken,
        onProgress: ({ stage, pct, detail }) => {
          if (token !== scanToken) return;
          setProgress(stage, pct, detail);
        },
      });
      report = data;
      renderVerdict(data);
      renderFindings(data);
      renderFiles();
      renderClasses();
      activateTab('findings');
      results.hidden = false;
      progress.hidden = true;
      results.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (error) {
      progress.hidden = true;
      drop.hidden = false;
      if (steps) steps.hidden = false;
      if (error instanceof ScanCancelled) {
        toast('Scan cancelled.');
      } else {
        toast(error.message || 'The scan failed. Is this really a jar?', { error: true });
      }
    } finally {
      setBusy(false);
    }
  }

  drop.addEventListener('click', (event) => {
    // The hidden input lives inside the dropzone: its synthetic click bubbles
    // back here, so ignore it or we reopen the picker recursively.
    if (event.target === input || event.target === pick) return;
    if (busy) return;
    input.click();
  });

  drop.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      if (!busy) input.click();
    }
  });

  pick.addEventListener('click', (event) => {
    event.stopPropagation();
    if (!busy) input.click();
  });

  input.addEventListener('change', () => {
    const file = input.files && input.files[0];
    if (file) startScan(file);
    input.value = '';
  });

  for (const type of ['dragenter', 'dragover']) {
    drop.addEventListener(type, (event) => {
      event.preventDefault();
      if (!busy) drop.classList.add('is-over');
    });
  }
  for (const type of ['dragleave', 'dragend']) {
    drop.addEventListener(type, () => drop.classList.remove('is-over'));
  }
  drop.addEventListener('drop', (event) => {
    event.preventDefault();
    drop.classList.remove('is-over');
    if (busy) return;
    const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
    if (file) startScan(file);
  });

  cancelButton.addEventListener('click', () => {
    cancelRequested = true;
    setProgress('cancelling', 0, 'stopping at the next entry');
  });

  resetButton.addEventListener('click', () => {
    cancelRequested = true;
    scanToken += 1;
    resetView();
    if (drop) drop.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });

  const hashCopy = document.querySelector('[data-copy="hash"]');
  if (hashCopy) {
    hashCopy.addEventListener('click', async () => {
      if (!report) return;
      const ok = await copyText(report.sha256);
      toast(ok ? 'SHA-256 copied.' : 'Could not reach the clipboard. Select the hash by hand.', { error: !ok });
    });
  }

  copyReportButton.addEventListener('click', async () => {
    if (!report) return;
    const ok = await copyText(toMarkdown(report));
    toast(ok ? 'Report copied as Markdown.' : 'Could not reach the clipboard.', { error: !ok });
  });

  downloadReportButton.addEventListener('click', () => {
    if (!report) return;
    const blob = new Blob([toMarkdown(report)], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    const base = report.fileName.replace(/\.[^.]+$/, '').replace(/[^\w.-]+/g, '-') || 'archive';
    anchor.href = url;
    anchor.download = `${base}-netmask-scan.md`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    toast('Report downloaded.');
  });

  drop.setAttribute('role', 'button');
  drop.setAttribute('tabindex', '0');
  drop.setAttribute('aria-label', 'Choose a jar file to scan');

  resetView();
}
