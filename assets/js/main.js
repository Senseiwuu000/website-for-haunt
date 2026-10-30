/**
 * Page behaviour: catalog, listing dialog, nav, FAQ bits that need JS.
 * The scanner mounts itself from scanner-ui.js.
 */

import { site, categories, listings } from './data.js';
import { initScanner, copyText } from './scanner-ui.js';
import { RULESET } from './scanner.js';

const toastNode = document.getElementById('toast');
let toastTimer = null;

function toast(message, { error = false } = {}) {
  if (!toastNode) return;
  toastNode.textContent = message;
  toastNode.classList.toggle('is-error', Boolean(error));
  toastNode.classList.add('is-show');
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toastNode.classList.remove('is-show'), 3200);
}

function h(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

const CATEGORY_LABELS = Object.fromEntries(categories.map((category) => [category.id, category.label]));
const STATUS_LABELS = {
  clean: 'scan clean',
  reviewed: 'reviewed by hand',
  pending: 'hash pending',
};

const dateShort = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short' });
const dateLong = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });

function toDate(iso) {
  return new Date(`${iso}T00:00:00Z`);
}

function shortDate(iso) {
  if (!iso) return '—';
  return dateShort.format(toDate(iso));
}

function longDate(iso) {
  if (!iso) return '—';
  return dateLong.format(toDate(iso));
}

function inviteButton(label, className = 'btn btn-accent') {
  const node = h('a', className, label);
  if (site.invite) {
    node.href = site.invite;
    node.target = '_blank';
    node.rel = 'noopener noreferrer';
  } else {
    node.href = '#tickets';
    node.addEventListener('click', (event) => {
      event.preventDefault();
      toast('Add your Discord invite in assets/js/data.js and this button will point at it.');
    });
  }
  return node;
}

/* -------------------------------------------------------------------------
   Catalog
   ------------------------------------------------------------------------- */

const cardsNode = document.getElementById('cards');
const filtersNode = document.getElementById('filters');
let activeCategory = 'all';

function cardFor(listing) {
  const card = h('article', 'card');

  const top = h('div', 'card-top');
  top.appendChild(h('span', 'cat-tag', CATEGORY_LABELS[listing.cat] || listing.cat));

  const status = h('span', 'card-status');
  status.appendChild(h('span', `dot ${listing.status === 'pending' ? 'warn' : 'ok'}`, ''));
  status.appendChild(h('span', '', STATUS_LABELS[listing.status] || listing.status));
  top.appendChild(status);
  card.appendChild(top);

  card.appendChild(h('h3', '', listing.name));
  card.appendChild(h('p', 'card-blurb', listing.blurb));

  const meta = h('dl', 'card-meta');
  const pairs = [
    ['version', listing.version],
    ['size', listing.size],
    ['checked', shortDate(listing.checked)],
  ];
  for (const [key, value] of pairs) {
    const group = h('div');
    group.appendChild(h('dt', '', key));
    const dd = h('dd', '', value);
    dd.title = key === 'checked' ? longDate(listing.checked) : value;
    group.appendChild(dd);
    meta.appendChild(group);
  }
  card.appendChild(meta);

  const foot = h('div', 'card-foot');
  const hash = h('span', 'card-hash', listing.hash ? `sha ${listing.hash.slice(0, 10)}…` : 'hash pending');
  hash.title = listing.hash || 'No published hash yet';
  foot.appendChild(hash);

  const open = h('button', 'card-open');
  open.type = 'button';
  open.appendChild(document.createTextNode('Details'));
  open.appendChild(h('span', 'arrow', '\u2192'));
  open.addEventListener('click', () => openListing(listing, open));
  foot.appendChild(open);

  card.appendChild(foot);
  return card;
}

function renderCards() {
  if (!cardsNode) return;
  cardsNode.textContent = '';
  const list = activeCategory === 'all'
    ? listings
    : listings.filter((listing) => listing.cat === activeCategory);

  const fragment = document.createDocumentFragment();
  for (const listing of list) fragment.appendChild(cardFor(listing));
  cardsNode.appendChild(fragment);
}

function renderFilters() {
  if (!filtersNode) return;
  filtersNode.textContent = '';

  for (const category of categories) {
    const count = category.id === 'all'
      ? listings.length
      : listings.filter((listing) => listing.cat === category.id).length;

    const chip = h('button', `chip${category.id === activeCategory ? ' is-active' : ''}`, category.label);
    chip.type = 'button';
    chip.appendChild(h('span', '', String(count)));
    chip.setAttribute('aria-pressed', category.id === activeCategory ? 'true' : 'false');
    chip.addEventListener('click', () => {
      activeCategory = category.id;
      renderFilters();
      renderCards();
    });
    filtersNode.appendChild(chip);
  }
}

/* -------------------------------------------------------------------------
   Listing dialog
   ------------------------------------------------------------------------- */

const modal = document.getElementById('modal');
const modalBody = document.getElementById('modalBody');
const modalPanel = modal ? modal.querySelector('.modal-panel') : null;
let lastFocused = null;

function openListing(listing, trigger) {
  if (!modal || !modalBody) return;
  lastFocused = trigger || document.activeElement;

  modalBody.textContent = '';

  modalBody.appendChild(h('span', 'cat-tag', CATEGORY_LABELS[listing.cat] || listing.cat));

  const title = h('h3', '', listing.name);
  title.id = 'modalTitle';
  title.appendChild(h('small', '', listing.version));
  modalBody.appendChild(title);

  modalBody.appendChild(h('p', 'modal-blurb', listing.blurb));

  if (listing.notes && listing.notes.length) {
    const notes = h('ul', 'modal-notes');
    for (const note of listing.notes) notes.appendChild(h('li', '', note));
    modalBody.appendChild(notes);
  }

  const meta = h('dl', 'modal-meta');
  const pairs = [
    ['size', listing.size],
    ['checked', longDate(listing.checked)],
    ['status', STATUS_LABELS[listing.status] || listing.status],
  ];
  for (const [key, value] of pairs) {
    const group = h('div');
    group.appendChild(h('dt', '', key));
    group.appendChild(h('dd', '', value));
    meta.appendChild(group);
  }
  modalBody.appendChild(meta);

  const hashBox = h('div', 'hash-box');
  hashBox.appendChild(h('span', '', 'sha-256'));
  hashBox.appendChild(h('code', '', listing.hash || 'pending — no download link goes out without one'));
  if (listing.hash) {
    const copy = h('button', 'copy', 'copy');
    copy.type = 'button';
    copy.addEventListener('click', async () => {
      const ok = await copyText(listing.hash);
      toast(ok ? 'SHA-256 copied.' : 'Could not reach the clipboard.', { error: !ok });
    });
    hashBox.appendChild(copy);
  }
  modalBody.appendChild(hashBox);

  const foot = h('div', 'modal-foot');
  foot.appendChild(inviteButton('Ask in #tickets'));
  const close = h('button', 'btn btn-quiet', 'Close');
  close.type = 'button';
  close.addEventListener('click', closeModal);
  foot.appendChild(close);
  modalBody.appendChild(foot);

  modalBody.appendChild(
    h(
      'p',
      'modal-note',
      `Download links live in the server, not on this page. Scanned with ruleset ${RULESET}. A clean scan is a starting point, not a promise.`,
    ),
  );

  modal.hidden = false;
  document.body.classList.add('is-locked');
  window.requestAnimationFrame(() => modalPanel?.focus());
}

function closeModal() {
  if (!modal || modal.hidden) return;
  modal.hidden = true;
  document.body.classList.remove('is-locked');
  if (lastFocused && typeof lastFocused.focus === 'function') lastFocused.focus();
  lastFocused = null;
}

if (modal) {
  modal.addEventListener('click', (event) => {
    if (event.target.closest('[data-close]')) closeModal();
  });
}

/* -------------------------------------------------------------------------
   Nav
   ------------------------------------------------------------------------- */

const nav = document.getElementById('nav');
const navToggle = document.getElementById('navToggle');

function closeNav() {
  if (!nav || !navToggle) return;
  nav.classList.remove('is-open');
  navToggle.setAttribute('aria-expanded', 'false');
}

if (nav && navToggle) {
  navToggle.addEventListener('click', () => {
    const open = nav.classList.toggle('is-open');
    navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  });

  nav.addEventListener('click', (event) => {
    if (event.target.closest('a')) closeNav();
  });

  document.addEventListener('click', (event) => {
    if (!nav.classList.contains('is-open')) return;
    if (nav.contains(event.target) || navToggle.contains(event.target)) return;
    closeNav();
  });
}

document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  closeNav();
  closeModal();
});

/* -------------------------------------------------------------------------
   Invite links, dates, scanner mount
   ------------------------------------------------------------------------- */

for (const node of document.querySelectorAll('[data-ruleset]')) {
  node.textContent = RULESET;
}

for (const node of document.querySelectorAll('[data-invite]')) {
  if (site.invite) {
    node.setAttribute('href', site.invite);
    node.setAttribute('target', '_blank');
    node.setAttribute('rel', 'noopener noreferrer');
  } else {
    node.addEventListener('click', (event) => {
      event.preventDefault();
      toast('Add your Discord invite in assets/js/data.js and this button will point at it.');
    });
  }
}

const yearNode = document.getElementById('year');
if (yearNode) yearNode.textContent = String(new Date().getFullYear());

const sweptNode = document.getElementById('lastSwept');
if (sweptNode) {
  const newest = listings.reduce((latest, listing) => (listing.checked > latest ? listing.checked : latest), '');
  if (newest) sweptNode.textContent = newest;
}

renderFilters();
renderCards();

initScanner({ toast });
