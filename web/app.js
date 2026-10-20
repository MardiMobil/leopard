'use strict';

/* leopard GUI. All data from lookups comes from third parties, so it is
 * only ever inserted with textContent, never as HTML. */

const TOKEN = document.querySelector('meta[name="api-token"]').content;
const $ = (sel) => document.querySelector(sel);

const TYPE_LABEL = { ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domain', hash: 'Hash',
  private: 'Private IP', unknown: 'Unknown' };
const VERDICT_LABEL = { malicious: 'MALICIOUS', suspicious: 'SUSPICIOUS', clean: 'CLEAN', info: 'INFO' };
const STATUS_LABEL = { skipped: 'SKIPPED', error: 'ERROR', not_found: 'NO DATA' };
const VERDICT_RANK = { '': 0, info: 0, clean: 1, suspicious: 2, malicious: 3 };
const STATE_TEXT = { ok: 'key OK', none: 'no key needed', optional: 'works without key',
  missing: 'no key, will be skipped' };
const SELECTION_KEY = 'mardimobil.sources';

let sources = [];
let reports = [];
let stopRequested = false;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

async function api(path, body) {
  const options = body === undefined
    ? { headers: { 'X-Token': TOKEN } }
    : { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Token': TOKEN },
        body: JSON.stringify(body) };
  const res = await fetch(path, options);
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try { message = (await res.json()).error || message; } catch (_) { /* not JSON */ }
    throw new Error(message);
  }
  return res;
}

let toastTimer;
function notify(message, isError = false) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.toggle('error', isError);
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, 3500);
}

/* ---------------------------------------------------------------- sources */

let userName = '';
function showName(name) {
  userName = name || 'OSINT';
  $('#userName').textContent = userName;
  document.title = `${userName} · OSINT Lookup`;
}

function savedSelection() {
  try { return JSON.parse(localStorage.getItem(SELECTION_KEY)); } catch (_) { return null; }
}

function saveSelection() {
  try { localStorage.setItem(SELECTION_KEY, JSON.stringify(selectedSources())); } catch (_) { /* private mode */ }
}

function selectedSources() {
  return [...document.querySelectorAll('#sources input:checked')].map((i) => i.value);
}

async function loadSources(extraChecked = []) {
  const data = await (await api('/api/sources')).json();
  sources = data.sources;
  $('#envPath').textContent = data.env_path;
  showName(data.user_name);

  const saved = savedSelection();
  const current = document.querySelector('#sources input') ? selectedSources() : null;
  const box = $('#sources');
  box.replaceChildren();
  for (const s of sources) {
    const label = el('label', `source ${s.state}`);
    label.title = `Supports ${s.kinds}`;
    const box_ = el('input');
    box_.type = 'checkbox';
    box_.value = s.id;
    const chosen = current || saved;
    box_.checked = extraChecked.includes(s.id) || (chosen ? chosen.includes(s.id) : s.state !== 'missing');
    box_.addEventListener('change', saveSelection);
    const text = el('span', 'source-text');
    text.append(el('strong', null, s.name), el('small', null, STATE_TEXT[s.state]));
    label.append(box_, text);
    box.append(label);
  }
}

/* ---------------------------------------------------------------- targets */

function parseTargets() {
  const seen = new Set();
  return $('#targets').value.split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#') && !seen.has(l) && seen.add(l));
}

function updateCount() {
  const n = parseTargets().length;
  $('#targetCount').textContent = `${n} target${n === 1 ? '' : 's'}`;
}

/* -------------------------------------------------------------------- run */

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function setRunning(running) {
  $('#run').disabled = running;
  $('#run').textContent = running ? 'Analyzing…' : 'Analyze';
  $('#stop').hidden = !running;
  $('#progress').hidden = !running;
}

function setProgress(text, done, total) {
  $('#progressText').textContent = `${text} (${done}/${total})`;
  $('#progressFill').style.width = `${total ? (done / total) * 100 : 0}%`;
}

async function run() {
  const targets = parseTargets();
  const ids = selectedSources();
  if (!targets.length) return notify('Enter at least one IP, domain or hash.', true);
  if (!ids.length) return notify('Select at least one source.', true);
  const delay = Math.min(120, Math.max(0, Number($('#delay').value) || 0));

  stopRequested = false;
  setRunning(true);
  for (let i = 0; i < targets.length && !stopRequested; i++) {
    if (i && delay) {
      setProgress(`Waiting ${delay}s between targets`, i, targets.length);
      await sleep(delay * 1000);
      if (stopRequested) break;
    }
    setProgress(`Checking ${targets[i]}`, i, targets.length);
    let report;
    try {
      report = await (await api('/api/lookup', { target: targets[i], sources: ids })).json();
    } catch (e) {
      report = { target: targets[i], value: targets[i], type: 'unknown',
        timestamp: new Date().toISOString(), results: [], error: `Request failed: ${e.message}` };
    }
    reports.push(report);
    $('#results').prepend(renderReport(report, reports.length - 1));
    renderSummary();
  }
  setRunning(false);
  if (stopRequested) notify('Stopped.');
}

/* ----------------------------------------------------------------- render */

function worstVerdict(report) {
  return (report.results || [])
    .filter((r) => r.status === 'ok')
    .map((r) => r.verdict)
    .reduce((a, b) => (a === null || VERDICT_RANK[b] > VERDICT_RANK[a] ? b : a), null);
}

function levelClass(score) {
  return score ? score.level.toLowerCase() : 'none';
}

function gauge(score) {
  const NS = 'http://www.w3.org/2000/svg';
  const R = 52;
  const C = 2 * Math.PI * R;
  const wrap = el('div', `gauge ${levelClass(score)}`);

  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 120 120');
  const ring = (cls) => {
    const c = document.createElementNS(NS, 'circle');
    c.setAttribute('cx', '60');
    c.setAttribute('cy', '60');
    c.setAttribute('r', String(R));
    c.setAttribute('class', cls);
    return c;
  };
  const bar = ring('ring-bar');
  bar.style.strokeDasharray = `0 ${C}`;
  if (!score || score.value === 0) bar.style.opacity = '0'; // a round cap would draw a dot at 0%
  svg.append(ring('ring-track'), bar);
  requestAnimationFrame(() => requestAnimationFrame(() => {
    bar.style.strokeDasharray = `${(C * (score ? score.value : 0)) / 100} ${C}`;
  }));

  const center = el('div', 'gauge-center');
  center.append(el('span', 'gauge-value', score ? `${score.value}%` : '--'),
    el('span', 'gauge-label', 'MALICIOUS SCORE'));

  const level = el('div', 'gauge-level', score ? `${score.level} RISK` : 'NO THREAT DATA');
  level.append(el('small', null, score
    ? `based on ${score.sources} source${score.sources === 1 ? '' : 's'}`
    : 'no scoring source answered'));

  wrap.append(svg, center, level);
  return wrap;
}

function sourceCard(r) {
  const card = el('section', `source-card ${r.status} ${r.status === 'ok' ? r.verdict : ''}`);
  const head = el('header');
  head.append(el('h4', null, r.name));
  if (r.status === 'ok') {
    if (r.score !== null && r.score !== undefined) head.append(el('span', 'src-score', `${r.score}/100`));
    head.append(el('span', `badge ${r.verdict}`, VERDICT_LABEL[r.verdict] || r.verdict));
  } else {
    head.append(el('span', `badge ${r.status}`, STATUS_LABEL[r.status] || r.status));
  }
  card.append(head);

  if (r.status !== 'ok') {
    card.append(el('p', 'message', r.message));
    return card;
  }
  const dl = el('dl');
  for (const [key, value] of Object.entries(r.fields || {})) {
    const dd = el('dd');
    if (Array.isArray(value)) {
      const ul = el('ul');
      value.forEach((item) => ul.append(el('li', null, item)));
      dd.append(ul);
    } else {
      dd.textContent = String(value);
    }
    dl.append(el('dt', null, key), dd);
  }
  card.append(dl);
  return card;
}

function renderReport(report, index) {
  const article = el('article', 'report');
  article.id = `report-${index}`;
  const head = el('header', 'report-head');
  head.append(el('h3', 'target', report.value),
    el('span', 'chip', TYPE_LABEL[report.type] || report.type),
    el('time', 'muted', new Date(report.timestamp).toLocaleString()));
  article.append(head);

  if (report.error) {
    article.classList.add('invalid');
    article.append(el('p', 'error-text', report.error));
    return article;
  }
  const body = el('div', 'report-body');
  const grid = el('div', 'source-grid');
  report.results.forEach((r) => grid.append(sourceCard(r)));
  body.append(gauge(report.score), grid);
  article.append(body);
  return article;
}

function scoreBar(score) {
  const wrap = el('div', `scorebar ${levelClass(score)}`);
  const track = el('span', 'track');
  const fill = el('span', 'fill');
  fill.style.width = `${score ? score.value : 0}%`;
  track.append(fill);
  wrap.append(el('b', null, score ? `${score.value}% ${score.level}` : '--'), track);
  return wrap;
}

function renderSummary() {
  $('#summary').hidden = reports.length === 0;
  $('#summaryCount').textContent = reports.length;
  const rows = [];
  for (let i = reports.length - 1; i >= 0; i--) {
    const rep = reports[i];
    const tr = el('tr');
    const target = el('button', 'link', rep.value);
    target.type = 'button';
    target.addEventListener('click', () =>
      document.getElementById(`report-${i}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
    const tdTarget = el('td');
    tdTarget.append(target);

    const tdScore = el('td');
    const tdVerdict = el('td');
    if (rep.error) {
      tdScore.append(el('span', 'badge error', 'INVALID'));
    } else {
      tdScore.append(scoreBar(rep.score));
      const worst = worstVerdict(rep);
      if (worst) tdVerdict.append(el('span', `badge ${worst}`, VERDICT_LABEL[worst]));
    }
    tr.append(tdTarget, el('td', 'muted', TYPE_LABEL[rep.type] || rep.type), tdScore, tdVerdict);
    rows.push(tr);
  }
  $('#summaryBody').replaceChildren(...rows);
}

/* ----------------------------------------------------------------- export */

async function exportReports(format) {
  if (!reports.length) return;
  try {
    const blob = await (await api('/api/export', { format, reports })).blob();
    const url = URL.createObjectURL(blob);
    const a = el('a');
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    a.href = url;
    a.download = `mardimobil-${stamp}.${format}`;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  } catch (e) {
    notify(`Export failed: ${e.message}`, true);
  }
}

/* ------------------------------------------------------------------- keys */

async function openKeys() {
  try {
    await loadSources();
  } catch (e) {
    return notify(e.message, true);
  }
  const fields = sources.filter((s) => s.key_env).map((s) => {
    const row = el('label', 'key-row');
    const info = el('div', 'key-info');
    info.append(el('strong', null, s.name), el('code', null, s.key_env),
      el('span', `key-state ${s.state}`, s.state === 'ok' ? `current: ${s.masked}`
        : s.state === 'optional' ? 'not set (optional)' : 'not set'));
    const input = el('input');
    input.type = 'password';
    input.name = s.id;
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.placeholder = s.state === 'ok' ? 'leave empty to keep the current key' : 'paste your key';
    row.append(info, input);
    return row;
  });
  $('#keyFields').replaceChildren(...fields);
  $('#nameInput').value = userName;
  $('#keysError').textContent = '';
  $('#keysDialog').showModal();
}

async function saveKeys(event) {
  event.preventDefault();
  const updates = {};
  for (const input of $('#keyFields').querySelectorAll('input')) {
    if (input.value.trim()) updates[input.name] = input.value.trim();
  }
  const name = $('#nameInput').value.trim();
  const nameChanged = name && name !== userName;
  if (!Object.keys(updates).length && !nameChanged) {
    $('#keysDialog').close();
    return;
  }
  try {
    const result = await (await api('/api/keys', { updates, name: nameChanged ? name : '' })).json();
    $('#keysDialog').close();
    await loadSources(result.saved);
    saveSelection();
    const parts = [];
    if (result.saved.length) parts.push(`${result.saved.length} key${result.saved.length === 1 ? '' : 's'}`);
    if (nameChanged) parts.push('display name');
    notify(`Saved ${parts.join(' and ')}.`);
  } catch (e) {
    $('#keysError').textContent = e.message;
  }
}

/* ------------------------------------------------------------------- init */

$('#targets').addEventListener('input', updateCount);
$('#targets').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); }
});
$('#fileInput').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const text = await file.text();
  const area = $('#targets');
  area.value = (area.value.trim() ? `${area.value.trim()}\n` : '') + text.trim();
  e.target.value = '';
  updateCount();
});
$('#run').addEventListener('click', run);
$('#stop').addEventListener('click', () => { stopRequested = true; });
$('#exportCsv').addEventListener('click', () => exportReports('csv'));
$('#exportJson').addEventListener('click', () => exportReports('json'));
$('#clear').addEventListener('click', () => {
  reports = [];
  $('#results').replaceChildren();
  renderSummary();
});
$('#openKeys').addEventListener('click', openKeys);
$('#keysForm').addEventListener('submit', saveKeys);
$('#cancelKeys').addEventListener('click', () => $('#keysDialog').close());

loadSources().catch((e) => notify(`Could not load sources: ${e.message}`, true));
updateCount();
