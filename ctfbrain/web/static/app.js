/* CTF-Brain UI. Vanilla JS, no build step, no CDN. */
'use strict';

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const state = {
  q: '', category: null, type: null, tags: [],
  results: [], total: 0, cursor: -1, stats: null, view: 'home',
  seq: 0, offset: 0, pageSize: 40, facets: null,
};

const el = {};
const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* The search API marks matches with « » (guillemets survive FTS5 snippetting
   without colliding with HTML). Escape first, then promote them to <mark>. */
const markSnippet = (s) => esc(s).replace(/«/g, '<mark>').replace(/»/g, '</mark>');

/* "SECCON CTF 2022 Quals" already carries its year; do not print it twice. */
const ctfLabel = (name, year) =>
  !name ? '' : (year && !String(name).includes(String(year)) ? `${name} ${year}` : name);

const catColor = (c) => (state.stats?.categories || []).find((x) => x.key === c)?.color || '#64748b';

/* ------------------------------------------------------------------ routing */
function pushState(replace = false) {
  const p = new URLSearchParams();
  if (state.q) p.set('q', state.q);
  if (state.category) p.set('cat', state.category);
  if (state.type) p.set('type', state.type);
  state.tags.forEach((t) => p.append('tag', t));
  const url = (state.view === 'doc' && state.slug)
    ? `/doc/${state.slug}`
    : (p.toString() ? `/search?${p}` : '/');
  history[replace ? 'replaceState' : 'pushState']({ ...state }, '', url);
}

function readLocation() {
  const path = location.pathname;
  if (path.startsWith('/doc/')) {
    state.view = 'doc';
    state.slug = decodeURIComponent(path.slice(5));
    return;
  }
  const p = new URLSearchParams(location.search);
  state.q = p.get('q') || '';
  state.category = p.get('cat');
  state.type = p.get('type');
  state.tags = p.getAll('tag');
  state.view = (state.q || state.category || state.type || state.tags.length) ? 'search' : 'home';
}

/* -------------------------------------------------------------------- data */
async function api(path) {
  const res = await fetch(path, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function loadStats() {
  if (!state.stats) state.stats = await api('/api/stats');
  return state.stats;
}

let debounce;
function scheduleSearch(delay = 130) {
  clearTimeout(debounce);
  debounce = setTimeout(() => { runSearch(); pushState(true); }, delay);
}

async function runSearch(append = false) {
  const seq = ++state.seq;
  if (!append) state.offset = 0;
  const p = new URLSearchParams({
    q: state.q, limit: String(state.pageSize), offset: String(state.offset),
  });
  if (state.category) p.set('category', state.category);
  if (state.type) p.set('type', state.type);
  state.tags.forEach((t) => p.append('tag', t));

  if (!state.q && !state.category && !state.type && !state.tags.length) {
    state.view = 'home'; state.facets = null; renderHome(); renderSidebar(); return;
  }
  state.view = 'search';
  if (!append) el.content.innerHTML = '<div class="loading">searching…</div>';
  try {
    const data = await api(`/api/search?${p}`);
    if (seq !== state.seq) return;            // a newer keystroke already won
    state.results = append ? [...state.results, ...data.results] : data.results;
    state.total = data.total;
    if (!append) state.cursor = -1;
    renderResults();
  } catch (err) {
    el.content.innerHTML = `<div class="empty"><h2>Search failed</h2><p>${esc(err.message)}</p></div>`;
    return;
  }
  // Facet counts scoped to the current query, so the sidebar shows where the
  // remaining results actually live rather than the size of the whole corpus.
  if (!append) {
    try {
      state.facets = state.q ? await api(`/api/facets?q=${encodeURIComponent(state.q)}`) : null;
    } catch { state.facets = null; }
    if (seq === state.seq) renderSidebar();
  }
}

/* ----------------------------------------------------------------- render */
function renderSidebar() {
  const s = state.stats;
  if (!s) return;
  const scopedCats = state.facets?.categories || null;
  const cats = s.categories
    .filter((c) => (scopedCats ? scopedCats[c.key] : c.count))
    .map((c) => `
    <button class="facet ${state.category === c.key ? 'active' : ''}" data-cat="${c.key}">
      <span class="swatch" style="background:${c.color}"></span>
      <span class="name">${esc(c.label)}</span>
      <span class="count">${scopedCats ? scopedCats[c.key] : c.count}</span>
    </button>`).join('');

  const typeCounts = state.facets?.types || s.by_type || {};
  const types = s.types.filter((t) => typeCounts[t]).map((t) => `
    <button class="facet ${state.type === t ? 'active' : ''}" data-type="${t}">
      <span class="name">${esc(t)}</span>
      <span class="count">${typeCounts[t] || 0}</span>
    </button>`).join('');

  const tags = (s.top_tags_list || []).slice(0, 60).map((t) => `
    <a class="tagchip ${state.tags.includes(t.tag) ? 'on' : ''}" data-tag="${esc(t.tag)}"
       href="#" title="${t.n} documents">${esc(t.tag)}</a>`).join('');

  el.sidebar.innerHTML = `
    <h3>Category</h3>${cats}
    <h3>Type</h3>${types}
    <h3>Popular tags</h3><div class="tagcloud">${tags}</div>`;
}

function renderHome() {
  const s = state.stats;
  const n = (x) => (x ?? 0).toLocaleString();
  const cards = s.categories.filter((c) => c.count).map((c) => `
    <a class="catcard" style="border-left-color:${c.color}" href="/search?cat=${c.key}" data-cat="${c.key}">
      <strong>${esc(c.label)}<em>${c.count}</em></strong>
      <span>${esc(c.description)}</span>
    </a>`).join('');

  const examples = ['gcd', 'padding oracle', 'tcache poisoning', 'ssti jinja2',
    'volatility3', 'ssl pinning bypass', 'type:playbook', 'reentrancy',
    'mt19937', 'format string', 'type:cheatsheet cat:pwn'];

  el.content.innerHTML = `
    <div class="hero">
      <h1>Your CTF brain.</h1>
      <p>Search ${n(s.documents)} documents across every category: writeups, techniques,
         cheatsheets and ready-to-run scripts. Type what you see, not what it is called.</p>
      <div class="statgrid">
        <div class="stat"><b>${n(s.documents)}</b><span>documents</span></div>
        <div class="stat"><b>${n(s.total_lines)}</b><span>lines</span></div>
        <div class="stat"><b>${n(s.code_blocks)}</b><span>code blocks</span></div>
        <div class="stat"><b>${n(s.unique_tags)}</b><span>tags</span></div>
        <div class="stat"><b>${n(s.ctfs)}</b><span>CTFs</span></div>
      </div>
      <h3 style="font-size:11px;text-transform:uppercase;letter-spacing:.09em;color:var(--fg-faint);margin:0 0 8px">Try</h3>
      <div class="quicklinks">
        ${examples.map((e) => `<a href="/search?q=${encodeURIComponent(e)}" data-q="${esc(e)}">${esc(e)}</a>`).join('')}
      </div>
    </div>
    <div class="catgrid">${cards}</div>`;
}

function renderResults() {
  if (!state.results.length) {
    el.content.innerHTML = `
      <div class="empty">
        <h2>Nothing found</h2>
        <p>No document matches <code>${esc(state.q)}</code>${state.category ? ` in ${esc(state.category)}` : ''}.</p>
        <p>Try a single keyword, a tool name, or drop the filters.</p>
      </div>`;
    return;
  }
  const chips = [];
  if (state.category) chips.push(`<span class="chip">cat: ${esc(state.category)}<button data-clear="category">×</button></span>`);
  if (state.type) chips.push(`<span class="chip">type: ${esc(state.type)}<button data-clear="type">×</button></span>`);
  state.tags.forEach((t) => chips.push(`<span class="chip">#${esc(t)}<button data-cleartag="${esc(t)}">×</button></span>`));

  const items = state.results.map((r, i) => {
    const sub = [r.subcategory, r.difficulty, ctfLabel(r.ctf_name, r.ctf_year)]
      .filter(Boolean).join(' · ');
    return `
      <li><a class="hit" href="/doc/${encodeURIComponent(r.slug)}" data-i="${i}" data-slug="${esc(r.slug)}">
        <div class="hit-top">
          <span class="catbar" style="background:${catColor(r.category)}"></span>
          <span class="hit-title">${esc(r.title)}</span>
          <span class="badge">${esc(r.type)}</span>
        </div>
        ${sub ? `<div class="hit-sub" style="font-size:11.5px;font-family:var(--mono);color:var(--fg-faint)">${esc(sub)}</div>` : ''}
        ${r.summary ? `<div class="hit-sub">${esc(r.summary)}</div>` : ''}
        ${r.snippet && r.snippet !== r.summary ? `<div class="hit-snippet">${markSnippet(r.snippet)}</div>` : ''}
        ${r.tags.length ? `<div class="hit-tags">${r.tags.slice(0, 12).map((t) => `<span>${esc(t)}</span>`).join('')}</div>` : ''}
      </a></li>`;
  }).join('');

  el.content.innerHTML = `
    <div class="resultmeta">
      <span>${state.total.toLocaleString()} result${state.total === 1 ? '' : 's'}</span>
      ${chips.join('')}
    </div>
    <ol class="results">${items}</ol>
    ${state.total > state.results.length
      ? `<div class="loadmore">
           <button id="more">load ${Math.min(state.pageSize, state.total - state.results.length)} more</button>
           <span>showing ${state.results.length} of ${state.total.toLocaleString()}, narrow with cat: / type: / tag:</span>
         </div>` : ''}`;

  $('#more')?.addEventListener('click', async (e) => {
    e.target.disabled = true;
    e.target.textContent = 'loading…';
    state.offset = state.results.length;
    await runSearch(true);
  });
}

async function renderDoc(slug) {
  el.content.innerHTML = '<div class="loading">loading…</div>';
  let doc;
  try {
    doc = await api(`/api/doc/${encodeURIComponent(slug)}`);
  } catch {
    el.content.innerHTML = `<div class="empty"><h2>Not found</h2><p><code>${esc(slug)}</code> is not in the index.</p></div>`;
    return;
  }
  state.slug = slug;
  document.title = `${doc.title} · CTF-Brain`;

  const meta = [];
  if (doc.difficulty) meta.push(`<span class="chip">${esc(doc.difficulty)}</span>`);
  if (doc.ctf_name) meta.push(`<span class="chip">${esc(ctfLabel(doc.ctf_name, doc.ctf_year))}</span>`);
  (doc.tools || []).forEach((t) => meta.push(`<span class="chip">${esc(t)}</span>`));
  (doc.cves || []).forEach((c) => meta.push(`<span class="chip">${esc(c)}</span>`));

  const tagLinks = (doc.tags || []).map((t) =>
    `<a class="tagchip" href="/search?tag=${encodeURIComponent(t)}" data-tag="${esc(t)}">${esc(t)}</a>`).join(' ');

  const toc = (doc.toc || []).length > 2
    ? `<nav class="toc"><h4>On this page</h4>${doc.toc.map((h) =>
        `<a class="lvl${h.level}" href="#${h.anchor}">${esc(h.text)}</a>`).join('')}</nav>`
    : '';

  const related = (doc.related || []).length
    ? `<div class="related"><h3>Related</h3><ul>${doc.related.map((r) =>
        `<li><a href="/doc/${encodeURIComponent(r.slug)}" data-slug="${esc(r.slug)}">
           ${esc(r.title)}<em>${esc(r.category)} / ${esc(r.type)}</em></a></li>`).join('')}</ul></div>`
    : '';

  el.content.innerHTML = `
    <div class="docwrap">
      <article>
        <div class="dochead">
          <div class="crumbs">
            <a href="/" data-home>home</a> /
            <a href="/search?cat=${doc.category}" data-cat="${doc.category}">${esc(doc.category)}</a> /
            ${esc(doc.type)}${doc.subcategory ? ' / ' + esc(doc.subcategory) : ''}
          </div>
          <h1>${esc(doc.title)}</h1>
          ${doc.summary ? `<div class="summary">${esc(doc.summary)}</div>` : ''}
          <div class="meta">${meta.join('')}</div>
          <div class="docactions">
            <button data-copy-all>copy all code</button>
            <a class="btn" href="/api/raw/${encodeURIComponent(slug)}" target="_blank" rel="noopener">raw markdown</a>
            ${doc.source_url ? `<a class="btn" href="${esc(doc.source_url)}" target="_blank" rel="noopener">source ↗</a>` : ''}
            ${doc.original_source ? `<a class="btn" href="${esc(doc.original_source)}" target="_blank" rel="noopener">original ↗</a>` : ''}
          </div>
          ${tagLinks ? `<div class="tagcloud" style="margin-top:11px">${tagLinks}</div>` : ''}
        </div>
        ${(doc.when_to_use || []).length
          ? `<div class="whenbox"><h4>Use this when</h4><ul>${doc.when_to_use.map((w) => `<li>${esc(w)}</li>`).join('')}</ul></div>`
          : ''}
        <div class="md">${doc.html}</div>
        ${related}
      </article>
      ${toc}
    </div>`;

  wireCopyButtons();
  wireScrollSpy();
  if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView();
  else window.scrollTo(0, 0);
}

/* ------------------------------------------------------------ interactions */
function wireCopyButtons() {
  $$('.codeblock .copy').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault(); e.stopPropagation();
      const code = btn.closest('.codeblock').querySelector('pre')?.innerText ?? '';
      try { await navigator.clipboard.writeText(code); } catch { return; }
      btn.textContent = 'copied'; btn.classList.add('done');
      setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('done'); }, 1400);
    });
  });
  $('[data-copy-all]')?.addEventListener('click', async (e) => {
    const all = $$('.codeblock pre').map((p) => p.innerText).join('\n\n# ---\n\n');
    try { await navigator.clipboard.writeText(all); } catch { return; }
    e.target.textContent = `copied ${$$('.codeblock').length} blocks`;
    setTimeout(() => { e.target.textContent = 'copy all code'; }, 1600);
  });
}

function wireScrollSpy() {
  const links = $$('nav.toc a');
  if (!links.length) return;
  const heads = links.map((a) => document.getElementById(a.getAttribute('href').slice(1))).filter(Boolean);
  const spy = () => {
    let active = 0;
    heads.forEach((h, i) => { if (h.getBoundingClientRect().top < 120) active = i; });
    links.forEach((a, i) => a.classList.toggle('here', i === active));
  };
  window.addEventListener('scroll', spy, { passive: true });
  spy();
}

function moveCursor(delta) {
  const hits = $$('.hit');
  if (!hits.length) return;
  hits[state.cursor]?.classList.remove('cursor');
  state.cursor = Math.max(0, Math.min(hits.length - 1, state.cursor + delta));
  const cur = hits[state.cursor];
  cur.classList.add('cursor');
  cur.scrollIntoView({ block: 'nearest' });
}

function navigate(url) {
  history.pushState({}, '', url);
  route();
}

async function route() {
  readLocation();
  await loadStats();
  el.q.value = state.q;
  renderSidebar();
  if (state.view === 'doc') await renderDoc(state.slug);
  else if (state.view === 'search') await runSearch();
  else { document.title = 'CTF-Brain'; renderHome(); }
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  try { localStorage.setItem('ctfbrain-theme', theme); } catch { /* private mode */ }
  const btn = $('#theme'); if (btn) btn.textContent = theme === 'dark' ? '◐' : '◑';
}

/* -------------------------------------------------------------------- boot */
document.addEventListener('DOMContentLoaded', async () => {
  el.q = $('#q'); el.content = $('#content'); el.sidebar = $('#sidebar');

  let theme = 'dark';
  try { theme = localStorage.getItem('ctfbrain-theme') || 'dark'; } catch { /* ignore */ }
  setTheme(theme);

  el.q.addEventListener('input', () => { state.q = el.q.value; scheduleSearch(); });
  el.q.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { clearTimeout(debounce); runSearch(); pushState(); }
    if (e.key === 'Escape') { el.q.blur(); }
    if (e.key === 'ArrowDown') { e.preventDefault(); el.q.blur(); moveCursor(1); }
  });

  // One delegated click handler for the whole app.
  document.addEventListener('click', (e) => {
    const a = e.target.closest('a');
    if (a && a.origin === location.origin && !a.target && !e.metaKey && !e.ctrlKey) {
      const tag = a.dataset.tag;
      if (tag) {
        e.preventDefault();
        state.tags = state.tags.includes(tag) ? state.tags.filter((t) => t !== tag) : [...state.tags, tag];
        state.view = 'search'; pushState(); runSearch(); return;
      }
      e.preventDefault(); navigate(a.getAttribute('href')); return;
    }
    const facetCat = e.target.closest('[data-cat]');
    if (facetCat && facetCat.tagName === 'BUTTON') {
      state.category = state.category === facetCat.dataset.cat ? null : facetCat.dataset.cat;
      pushState(); runSearch(); return;
    }
    const facetType = e.target.closest('[data-type]');
    if (facetType && facetType.tagName === 'BUTTON') {
      state.type = state.type === facetType.dataset.type ? null : facetType.dataset.type;
      pushState(); runSearch(); return;
    }
    const clear = e.target.closest('[data-clear]');
    if (clear) { state[clear.dataset.clear] = null; pushState(); runSearch(); return; }
    const clearTag = e.target.closest('[data-cleartag]');
    if (clearTag) {
      state.tags = state.tags.filter((t) => t !== clearTag.dataset.cleartag);
      pushState(); runSearch(); return;
    }
  });

  $('#theme').addEventListener('click', () =>
    setTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'));
  $('#help').addEventListener('click', () => $('#helpOverlay').classList.add('open'));
  $('#helpOverlay').addEventListener('click', (e) => {
    if (e.target.id === 'helpOverlay' || e.target.dataset.close) e.currentTarget.classList.remove('open');
  });
  $('#lucky').addEventListener('click', async () => {
    const r = await api('/api/random'); navigate(`/doc/${encodeURIComponent(r.slug)}`);
  });

  document.addEventListener('keydown', (e) => {
    const typing = ['INPUT', 'TEXTAREA'].includes(document.activeElement?.tagName);
    if (e.key === '/' && !typing) { e.preventDefault(); el.q.focus(); el.q.select(); return; }
    if (e.key === '?' && !typing) { $('#helpOverlay').classList.toggle('open'); return; }
    if (e.key === 'Escape') { $('#helpOverlay').classList.remove('open'); return; }
    if (typing) return;
    if (e.key === 'j') { e.preventDefault(); moveCursor(1); }
    if (e.key === 'k') { e.preventDefault(); moveCursor(-1); }
    if (e.key === 'Enter' && state.cursor >= 0) {
      const slug = $$('.hit')[state.cursor]?.dataset.slug;
      if (slug) navigate(`/doc/${encodeURIComponent(slug)}`);
    }
    if (e.key === 'h') navigate('/');
    if (e.key === 't') setTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    if (e.key === 'Backspace' && state.view === 'doc') { e.preventDefault(); history.back(); }
  });

  window.addEventListener('popstate', route);

  // Fold the tag list into stats so the sidebar renders in one round trip.
  await loadStats();
  try { state.stats.top_tags_list = (await api('/api/tags?limit=80')).tags; } catch { state.stats.top_tags_list = []; }
  await route();
});
