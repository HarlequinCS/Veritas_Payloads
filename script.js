/* ═══════════════════════════════════════════════════════════════
   Veritas Payloads — Cybersecurity Payload Dashboard
   Script (vanilla JS, no dependencies)
   ═══════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  /* ─── DATA ─── */
  const TOTAL_PAYLOADS = 65321;

  const CATEGORIES = [
    { name: 'Injection (LFI/RFI)', count: 25873 },
    { name: 'Injection (XSS)', count: 12462 },
    { name: 'Injection (Command Injection)', count: 9391 },
    { name: 'Injection (SQLi)', count: 5348 },
    { name: 'Security Misconfiguration', count: 5029 },
    { name: 'Software & Data Integrity Failures (Deserialization)', count: 3766 },
    { name: 'Identification & Authentication Failures', count: 899 },
    { name: 'Insecure Design', count: 473 },
    { name: 'Injection (Open Redirect)', count: 272 },
    { name: 'Cryptographic Failures', count: 166 },
    { name: 'Injection (NoSQLi)', count: 147 },
    { name: 'Broken Access Control (IDOR)', count: 138 },
    { name: 'Injection (SSRF)', count: 125 },
    { name: 'Injection (LDAP)', count: 123 },
    { name: 'Injection (Unrestricted File Upload)', count: 114 },
    { name: 'Injection (XXE)', count: 110 },
    { name: 'Injection (GraphQL)', count: 100 },
    { name: 'Injection (SSI)', count: 100 },
    { name: 'Injection (SSTI)', count: 86 },
    { name: 'Insecure Design (Race Condition)', count: 80 },
    { name: 'Injection (Prototype Pollution)', count: 73 },
  ];

  const SOURCES = [
    { name: 'PayloadsAllTheThings', by: 'Swissky & community', desc: 'Community-driven payload repository covering all major vulnerability categories including XSS, SQLi, LFI, SSRF, SSTI, CMD injection, Open Redirect, NoSQLi, LDAP, Prototype Pollution, and more.', url: 'https://github.com/swisskyrepo/PayloadsAllTheThings' },
    { name: 'SecLists', by: 'Daniel Miessler & Jason Haddix', desc: 'The ultimate collection of security testing wordlists. Extracted: XSS vectors (PortSwigger, OFJAAAH, PayloadBox), LFI paths, SQLi payloads, Commix, format strings, Java classes, and numeric amounts.', url: 'https://github.com/danielmiessler/SecLists' },
    { name: 'Nuclei Templates', by: 'ProjectDiscovery', desc: 'Community-contributed vulnerability templates. Extracted: WAF bypass, CORS misconfig, LFI fuzzing, SSRF proxying, XSS fuzz, SQL injection, CRLF injection, and environment disclosure patterns.', url: 'https://github.com/projectdiscovery/nuclei-templates' },
    { name: 'Exploit Database', by: 'Offensive Security', desc: 'The definitive archive of publicly disclosed exploits. Extracted 9,327 PoC payload strings from 13,605 webapp exploit scripts covering SQLi, XSS, LFI, CMD injection, auth bypass, and more.', url: 'https://gitlab.com/exploit-database/exploitdb' },
    { name: 'OWASP PayloadBox', by: 'PayloadBox', desc: 'XSS vulnerability payload list covering a wide range of injection contexts and filter bypass techniques.', url: 'https://github.com/payload-box/xss-payload-list' },
    { name: 'PortSwigger XSS Cheat Sheet', by: 'PortSwigger Research', desc: 'Cross-site scripting evasion and filter bypass reference. Contains hundreds of tested XSS vectors.', url: 'https://portswigger.net/web-security/cross-site-scripting/cheat-sheet' },
    { name: 'Commix', by: 'commixproject', desc: 'Automated command injection testing tool. Extracted 8,262 unique command injection test vectors.', url: 'https://github.com/commixproject/commix' },
    { name: 'sqlmap', by: 'sqlmapproject', desc: 'Automatic SQL injection and database takeover tool. Extracted risk-classified SQLi payloads.', url: 'https://github.com/sqlmapproject/sqlmap' },
    { name: 'LFISuite', by: 'D35m0nd142', desc: 'Local File Inclusion exploitation toolkit providing comprehensive LFI path lists for Linux and Windows targets.', url: 'https://github.com/D35m0nd142/LFISuite' },
    { name: 'fuzzdb', by: 'fuzzdb-project', desc: 'Attack pattern and fuzzing resource database with strings for protocol fuzzing and input validation testing.', url: 'https://github.com/fuzzdb-project/fuzzdb' },
    { name: 'Big List of Naughty Strings', by: 'minimaxir', desc: 'Edge case strings for input validation testing. Helps identify encoding, injection, and boundary-condition issues.', url: 'https://github.com/minimaxir/big-list-of-naughty-strings' },
    { name: 'Cloud & Container References', by: 'AWS, GCP, Azure, DigitalOcean, OpenStack, Kubernetes', desc: 'Cloud metadata endpoints (AWS IMDS, GCP, Azure, Alibaba, DigitalOcean, OpenStack) and container/K8s breakout paths for SSRF and LFI testing.', url: '#' },
  ];

  /* color palette cycled for categories/charts */
  const PALETTE = ['cyan', 'violet', 'green', 'amber', 'pink', 'red'];
  const COLOR_HEX = { cyan: '#22d3ee', violet: '#818cf8', green: '#34d399', amber: '#fbbf24', pink: '#f472b6', red: '#f87171' };

  /* ─── ICONS (inline SVG strings) ─── */
  const ICON = {
    overview: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>',
    library: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>',
    sources: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v6m0 6v6m11-7h-6m-6 0H1"/></svg>',
    walkthrough: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>',
    copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
    chevron: '<svg class="acc-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>',
    src: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="2"/><path d="M5 12H2m20 0h-3M12 5V2m0 20v-3"/></svg>',
    target: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
    ext: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>',
    layers: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>',
    grid: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>',
    users: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
    db: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
  };

  /* ─── HELPERS ─── */
  const $ = (sel, ctx) => (ctx || document).querySelector(sel);
  const $$ = (sel, ctx) => Array.from((ctx || document).querySelectorAll(sel));
  const fmt = n => n.toLocaleString();
  function escHtml(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
  function escAttr(s) { return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
  function colorFor(i) { return PALETTE[i % PALETTE.length]; }

  /* ─── DERIVED DATA ─── */
  function severityFor(cat) {
    if (/SQLi|Command|LFI|RFI|Deserialization|XXE|SSTI/.test(cat)) return { label: 'Critical', cls: 'badge-red' };
    if (/XSS|SSRF|Auth|Open Redirect|NoSQLi|Upload/.test(cat)) return { label: 'High', cls: 'badge-amber' };
    if (/Misconfig|IDOR|LDAP|Prototype|GraphQL|SSI/.test(cat)) return { label: 'Medium', cls: 'badge-violet' };
    return { label: 'Info', cls: 'badge-muted' };
  }

  function sourcesForCategory(cat) {
    if (cat.includes('SQLi')) return 'SecLists, sqlmap, Exploit Database';
    if (cat.includes('XSS')) return 'SecLists, PayloadsAllTheThings, OWASP PayloadBox, PortSwigger, Exploit Database';
    if (cat.includes('LFI') || cat.includes('RFI')) return 'SecLists, PayloadsAllTheThings, LFISuite, Exploit Database';
    if (cat.includes('Command')) return 'Commix, SecLists, Exploit Database';
    if (cat.includes('Open Redirect')) return 'PayloadsAllTheThings, Nuclei Templates';
    if (cat.includes('SSRF')) return 'Cloud References, Nuclei Templates, PayloadsAllTheThings';
    if (cat.includes('SSTI')) return 'SecLists, PayloadsAllTheThings';
    if (cat.includes('XXE')) return 'SecLists, PayloadsAllTheThings';
    if (cat.includes('NoSQLi')) return 'SecLists, PayloadsAllTheThings';
    if (cat.includes('Prototype')) return 'PayloadsAllTheThings';
    if (cat.includes('LDAP')) return 'SecLists, PayloadsAllTheThings';
    if (cat.includes('Misconfig')) return 'SecLists, Nuclei Templates, fuzzdb';
    if (cat.includes('Deserialization')) return 'SecLists (Java classes)';
    if (cat.includes('Auth')) return 'SecLists, Exploit Database';
    return 'PayloadsAllTheThings, SecLists, Exploit Database';
  }

  function descForCategory(cat) {
    if (cat.includes('LFI') || cat.includes('RFI')) return 'File path traversal and inclusion payloads targeting file inclusion vulnerabilities. Includes Linux/Windows absolute paths, traversal sequences, and container breakout paths.';
    if (cat.includes('XSS')) return 'Cross-site scripting vectors for reflected, stored, and DOM-based contexts. Includes polyglots, encoded variants, and filter bypasses.';
    if (cat.includes('Command')) return 'Operating system command injection payloads for Unix and Windows platforms. Includes blind and out-of-band detection techniques.';
    if (cat.includes('SQLi')) return 'SQL injection strings for MySQL, PostgreSQL, MSSQL, Oracle, and SQLite. Covers classic, blind, error-based, and time-based techniques.';
    if (cat.includes('Misconfig')) return 'Security misconfiguration detection strings including default paths, debug endpoints, and information disclosure probes.';
    if (cat.includes('Deserialization')) return 'Java fully-qualified class paths for deserialization attack surface detection on J2EE applications.';
    if (cat.includes('Auth')) return 'Authentication bypass payloads including SQL injection auth bypass, default credentials, and session manipulation strings.';
    if (cat.includes('Insecure Design')) return 'Business logic testing payloads including numeric amounts, edge case values, and mass assignment patterns.';
    if (cat.includes('Open Redirect')) return 'URL redirect injection payloads for detecting open redirect vulnerabilities. Includes whitelist bypass and protocol manipulation.';
    if (cat.includes('Cryptographic')) return 'Cryptographic weakness detection payloads including JWT attacks, weak keys, and TLS configuration probes.';
    if (cat.includes('IDOR')) return 'Insecure Direct Object Reference test values for enumerating and manipulating object identifiers.';
    return cat + ' vulnerability payloads for security testing and vulnerability assessment.';
  }

  function injectionPointFor(cat) {
    if (cat.includes('XXE')) return 'body_xml';
    if (cat.includes('SSRF')) return 'url_parameter';
    if (cat.includes('Upload')) return 'file_upload';
    if (cat.includes('Deserialization')) return 'request_body';
    return 'query_parameter';
  }

  const EXAMPLES = {
    'SQLi': "' OR '1'='1",
    'XSS': '<script>alert(1)</script>',
    'LFI': '../../../etc/passwd',
    'Command': '; id',
    'Open Redirect': '//evil.com',
    'SSRF': 'http://169.254.169.254/latest/meta-data/',
    'XXE': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
    'SSTI': '{{7*7}}',
    'NoSQLi': '{"$gt": ""}',
    'LDAP': '*)(uid=*',
    'Prototype': '{"__proto__": {"admin": true}}',
    'GraphQL': '{__schema{types{name}}}',
    'SSI': '<!--#exec cmd="id"-->',
    'IDOR': '/api/user/1001',
    'Deserialization': 'org.apache.commons.collections.functors.InvokerTransformer',
    'Misconfig': '/.git/config',
    'Upload': 'shell.php%00.jpg',
    'Auth': "admin' --",
  };
  function exampleFor(cat) {
    for (const k in EXAMPLES) if (cat.includes(k)) return EXAMPLES[k];
    return 'payload_string_example';
  }

  /* build enriched library items */
  const LIBRARY_ITEMS = CATEGORIES.map((cat, i) => {
    const sev = severityFor(cat.name);
    return {
      id: 'OWP-' + String(i + 1).padStart(3, '0'),
      category: cat.name,
      count: cat.count,
      share: cat.count / TOTAL_PAYLOADS,
      description: descForCategory(cat.name),
      source: sourcesForCategory(cat.name),
      contributor: SOURCES[0].by,
      injectionPoint: injectionPointFor(cat.name),
      statusCode: 200,
      severity: sev,
      example: exampleFor(cat.name),
      color: colorFor(i),
    };
  });

  function contributorCount() {
    const set = new Set();
    SOURCES.forEach(s => s.by.split(/[,&]/).forEach(n => { const t = n.trim(); if (t && !/community/i.test(t)) set.add(t); }));
    return set.size;
  }

  /* ─── TOAST ─── */
  let toastTimer;
  function showToast(msg) {
    const wrap = $('#toastWrap');
    if (!wrap) return;
    wrap.innerHTML = '<div class="toast">' + ICON.check + '<span>' + escHtml(msg) + '</span></div>';
    const t = wrap.firstChild;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      t.classList.add('out');
      setTimeout(() => { if (wrap.contains(t)) wrap.removeChild(t); }, 300);
    }, 1800);
  }

  /* ─── COPY ─── */
  function copyText(text) {
    const done = () => showToast('Copied to clipboard');
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
    } else {
      fallbackCopy(text, done);
    }
  }
  function fallbackCopy(text, cb) {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try { document.execCommand('copy'); cb(); } catch (e) { showToast('Copy failed'); }
    document.body.removeChild(ta);
  }
  function copyBtn(text) {
    return '<button class="copy-mini" data-copy="' + escAttr(text) + '" title="Copy" aria-label="Copy">' + ICON.copy + '</button>';
  }

  /* ─── RENDER: SIDEBAR NAV ─── */
  const VIEWS = [
    { id: 'overview', label: 'Overview', title: 'Overview', sub: 'Dataset summary & analytics', count: '' },
    { id: 'library', label: 'Payload Library', title: 'Payload Library', sub: 'Browse & filter payloads', count: fmt(CATEGORIES.length) },
    { id: 'sources', label: 'Sources', title: 'Sources & Contributors', sub: 'Trusted security repositories', count: fmt(SOURCES.length) },
    { id: 'walkthrough', label: 'Walkthrough', title: 'Walkthrough', sub: 'How to use the dataset', count: '' },
  ];

  function renderNav() {
    const nav = $('#sidebarNav');
    const label = nav.querySelector('.nav-section-label');
    nav.innerHTML = '';
    nav.appendChild(label);
    VIEWS.forEach(v => {
      const b = document.createElement('button');
      b.className = 'nav-item' + (v.id === 'overview' ? ' active' : '');
      b.dataset.view = v.id;
      b.innerHTML = ICON[v.id] + '<span>' + v.label + '</span>' + (v.count ? '<span class="nav-count">' + v.count + '</span>' : '');
      b.addEventListener('click', () => setView(v.id));
      nav.appendChild(b);
    });
  }

  /* ─── RENDER: STAT CARDS ─── */
  function renderStats() {
    const grid = $('#statsGrid');
    const cards = [
      { ico: 'db', cls: 'ico-cyan', value: TOTAL_PAYLOADS, desc: 'Total Payloads', trend: 'OWASP' },
      { ico: 'layers', cls: 'ico-violet', value: 36, desc: 'Vulnerability Categories', trend: 'Top 10' },
      { ico: 'users', cls: 'ico-green', value: contributorCount(), desc: 'Contributors', trend: 'Community' },
      { ico: 'grid', cls: 'ico-amber', value: SOURCES.length, desc: 'Sources & Repositories', trend: 'Curated' },
    ];
    grid.innerHTML = cards.map(c => (
      '<div class="stat-card">' +
        '<div class="stat-card-top">' +
          '<div class="stat-ico ' + c.cls + '">' + ICON[c.ico] + '</div>' +
          '<span class="stat-trend">' + c.trend + '</span>' +
        '</div>' +
        '<div class="stat-value" data-target="' + c.value + '">0</div>' +
        '<div class="stat-desc">' + c.desc + '</div>' +
      '</div>'
    )).join('');
  }

  /* ─── RENDER: BAR CHART ─── */
  function renderBarChart() {
    const el = $('#barChart');
    const top = CATEGORIES.slice(0, 6);
    const max = top[0].count;
    el.innerHTML = top.map(c => (
      '<div class="bar-item">' +
        '<div class="bar-top"><span class="bar-name">' + escHtml(c.name) + '</span><span class="bar-val">' + fmt(c.count) + '</span></div>' +
        '<div class="bar-track"><div class="bar-fill" data-w="' + (c.count / max * 100) + '"></div></div>' +
      '</div>'
    )).join('');
  }

  function animateBars() {
    $$('#barChart .bar-fill').forEach(f => { f.style.width = f.dataset.w + '%'; });
  }

  /* ─── RENDER: DONUT ─── */
  function renderDonut() {
    const donut = $('#donut');
    const legend = $('#donutLegend');
    const top = CATEGORIES.slice(0, 5);
    const topSum = top.reduce((a, c) => a + c.count, 0);
    const other = TOTAL_PAYLOADS - topSum;
    const segments = top.map((c, i) => ({ name: c.name, count: c.count, color: COLOR_HEX[colorFor(i)] }));
    segments.push({ name: 'Other categories', count: other, color: '#33405a' });

    let acc = 0;
    const stops = segments.map(s => {
      const start = acc / TOTAL_PAYLOADS * 100;
      acc += s.count;
      const end = acc / TOTAL_PAYLOADS * 100;
      return s.color + ' ' + start.toFixed(2) + '% ' + end.toFixed(2) + '%';
    }).join(', ');
    donut.style.background = 'conic-gradient(' + stops + ')';

    legend.innerHTML = segments.map(s => (
      '<div class="legend-item"><span class="legend-dot" style="background:' + s.color + '"></span>' +
      '<span>' + escHtml(shorten(s.name)) + '</span>' +
      '<span class="l-val">' + (s.count / TOTAL_PAYLOADS * 100).toFixed(1) + '%</span></div>'
    )).join('');
  }
  function shorten(n) { return n.replace('Injection ', '').replace('Software & Data Integrity Failures ', ''); }

  /* ─── RENDER: CATEGORY LIST ─── */
  function renderCatList() {
    const el = $('#catList');
    el.innerHTML = CATEGORIES.map((c, i) => (
      '<div class="cat-chip" data-cat="' + escAttr(c.name) + '">' +
        '<span class="c-dot" style="background:' + COLOR_HEX[colorFor(i)] + '"></span>' +
        '<span class="c-name">' + escHtml(c.name) + '</span>' +
        '<span class="c-count">' + fmt(c.count) + '</span>' +
      '</div>'
    )).join('');
    $$('#catList .cat-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const cat = chip.dataset.cat;
        $('#filterCategory').value = cat;
        setView('library');
        applyFilters();
      });
    });
  }

  /* ─── RENDER: SOURCES ─── */
  function renderSources() {
    const grid = $('#sourcesGrid');
    grid.innerHTML = SOURCES.map(s => (
      '<div class="source-card">' +
        '<div class="source-card-top">' +
          '<span class="source-logo">' + escHtml(s.name.charAt(0)) + '</span>' +
          '<div><h3>' + escHtml(s.name) + '</h3><div class="source-by">' + escHtml(s.by) + '</div></div>' +
        '</div>' +
        '<p>' + escHtml(s.desc) + '</p>' +
        (s.url !== '#' ? '<a href="' + escAttr(s.url) + '" class="source-link" target="_blank" rel="noopener">Visit Repository ' + ICON.ext + '</a>' : '') +
      '</div>'
    )).join('');
  }

  /* ─── RENDER: LIBRARY ─── */
  function renderLibrary(items) {
    const grid = $('#libraryGrid');
    const empty = $('#emptyState');
    const count = $('#resultCount');
    count.innerHTML = 'Showing <strong>' + items.length + '</strong> of <strong>' + LIBRARY_ITEMS.length + '</strong> categories';

    if (!items.length) {
      grid.innerHTML = '';
      empty.classList.add('show');
      return;
    }
    empty.classList.remove('show');

    grid.innerHTML = items.map(item => (
      '<div class="lib-card" data-id="' + item.id + '">' +
        '<div class="lib-card-header">' +
          '<span class="lib-card-id">' + item.id + '</span>' +
          '<span class="badge ' + item.severity.cls + '">' + item.severity.label + '</span>' +
        '</div>' +
        '<div class="lib-card-body">' +
          '<div class="lib-card-title">' + escHtml(item.category) + '</div>' +
          '<div class="lib-card-desc">' + escHtml(item.description) + '</div>' +
        '</div>' +
        '<div class="lib-card-example">' +
          '<div class="example-label">Example payload</div>' +
          '<div class="code-inline"><code>' + escHtml(item.example) + '</code>' + copyBtn(item.example) + '</div>' +
        '</div>' +
        '<div class="lib-card-footer">' +
          '<span class="meta badge badge-cyan">' + fmt(item.count) + '</span>' +
          '<span class="meta">' + ICON.target + item.injectionPoint + '</span>' +
          '<span class="spacer"></span>' +
          '<span class="view-link">Details &rarr;</span>' +
        '</div>' +
      '</div>'
    )).join('');

    $$('#libraryGrid .lib-card').forEach(card => {
      card.addEventListener('click', e => {
        if (e.target.closest('.copy-mini')) return; // let copy handle itself
        const item = LIBRARY_ITEMS.find(i => i.id === card.dataset.id);
        if (item) openModal(item);
      });
    });
  }

  /* ─── FILTER / SORT ─── */
  function applyFilters() {
    const term = ($('#searchInput').value || '').toLowerCase().trim();
    const catF = $('#filterCategory').value;
    const srcF = $('#filterSource').value;
    const sort = $('#sortBy').value;

    let list = LIBRARY_ITEMS.filter(it => {
      const matchSearch = !term ||
        it.category.toLowerCase().includes(term) ||
        it.source.toLowerCase().includes(term) ||
        it.description.toLowerCase().includes(term) ||
        it.severity.label.toLowerCase().includes(term);
      const matchCat = catF === 'all' || it.category === catF;
      const matchSrc = srcF === 'all' || it.source.includes(srcF);
      return matchSearch && matchCat && matchSrc;
    });

    list = list.slice().sort((a, b) => {
      switch (sort) {
        case 'count-asc': return a.count - b.count;
        case 'name-asc': return a.category.localeCompare(b.category);
        case 'name-desc': return b.category.localeCompare(a.category);
        default: return b.count - a.count;
      }
    });
    renderLibrary(list);
  }

  function populateFilters() {
    const catSel = $('#filterCategory');
    const srcSel = $('#filterSource');
    const srcs = new Set();
    LIBRARY_ITEMS.forEach(it => it.source.split(', ').forEach(s => srcs.add(s)));
    CATEGORIES.forEach(c => {
      const o = document.createElement('option');
      o.value = c.name; o.textContent = c.name;
      catSel.appendChild(o);
    });
    Array.from(srcs).sort().forEach(s => {
      const o = document.createElement('option');
      o.value = s; o.textContent = s;
      srcSel.appendChild(o);
    });
  }

  /* ─── MODAL ─── */
  function openModal(item) {
    $('#modalId').textContent = item.id + ' · ' + item.severity.label + ' severity';
    $('#modalTitle').textContent = item.category;
    $('#modalBody').innerHTML = (
      '<div class="detail-grid">' +
        '<div class="detail-row"><div class="detail-label">Total Payloads</div><div class="detail-value">' + fmt(item.count) + '</div></div>' +
        '<div class="detail-row"><div class="detail-label">Dataset Share</div><div class="detail-value">' + (item.share * 100).toFixed(2) + '%</div></div>' +
        '<div class="detail-row"><div class="detail-label">Injection Point</div><div class="detail-value">' + item.injectionPoint + '</div></div>' +
        '<div class="detail-row"><div class="detail-label">Expected Status</div><div class="detail-value">HTTP ' + item.statusCode + '</div></div>' +
        '<div class="detail-row full"><div class="detail-label">Description</div><div class="detail-value">' + escHtml(item.description) + '</div></div>' +
        '<div class="detail-row full"><div class="detail-label">Sources</div><div class="detail-value">' + escHtml(item.source) + '</div></div>' +
      '</div>' +
      '<div class="example-label">Example payload</div>' +
      '<div class="code-block-lg"><code>' + escHtml(item.example) + '</code>' + copyBtn(item.example) + '</div>'
    );
    $('#modalOverlay').classList.add('open');
    document.body.style.overflow = 'hidden';
  }
  function closeModal() {
    $('#modalOverlay').classList.remove('open');
    document.body.style.overflow = '';
  }

  /* ─── WALKTHROUGH ACCORDION ─── */
  const STEPS = [
    { t: 'Clone or Download', s: 'Get the dataset onto your machine', body:
      '<p>Start by cloning the repository or downloading the latest release from GitHub.</p>' + codeBlock('git clone https://github.com/HarlequinCS/Veritas_Payloads.git') },
    { t: 'Choose Your Format', s: 'Unified JSON or organized folders', body:
      '<p>The dataset is available as a single unified JSON file or split into category folders.</p>' + codeBlock(
'Veritas_Payloads/\n  owasp_top10_payloads.json   # Unified (65,321 entries)\n  organize_payloads.py        # Splitter tool\n  payloads/                   # Organized by category\n    injection_(xss)/query_parameter.json\n    injection_(sqli)/query_parameter.json') },
    { t: 'Understand the Schema', s: 'Consistent, integration-ready structure', body:
      '<p>Each payload entry follows a consistent structure for easy integration.</p>' + codeBlock(
'{\n  "payload_id": "OWP-0001",\n  "vulnerability_category": "Injection (SQLi)",\n  "injection_point": "query_parameter",\n  "payload_string": "\' OR \'1\'=\'1",\n  "validation": { "expected_status_code": 200, "success_regex": "error|sql" }\n}') },
    { t: 'Load in Your Scanner', s: 'Feed payloads into your DAST/fuzzer', body:
      '<p>Use the organized files to feed your DAST or fuzzing tool. Each file targets a specific category and injection point.</p>' + codeBlock(
'import json\n\nwith open("payloads/injection_(sqli)/query_parameter.json") as f:\n    payloads = json.load(f)\n\nfor p in payloads:\n    print(f"{p[\'payload_id\']}: {p[\'payload_string\']}")') },
    { t: 'Re-organize Anytime', s: 'Regenerate category folders', body:
      '<p>Run the included Python script to re-generate the organized folders after modifications.</p>' + codeBlock('python organize_payloads.py') },
    { t: 'Interpret Results', s: 'Validation hints per category', body:
      '<p>Each payload includes validation hints — expected status codes and success regex patterns — to verify if a vulnerability was triggered.</p>' +
      '<div class="tips-grid">' +
        tip('SQL Injection', 'Watch for: <code>syntax error</code>, <code>SQL</code>, unexpected 200 responses') +
        tip('XSS', 'Watch for: <code>&lt;script&gt;alert</code> in response, DOM changes') +
        tip('LFI/RFI', 'Watch for: <code>root:.*:0:0</code>, <code>boot.ini</code>, file contents') +
        tip('Open Redirect', 'Watch for: <code>Location:</code> header with 302 status') +
      '</div>' },
  ];
  function codeBlock(code) { return '<div class="code-block">' + escHtml(code) + copyBtn(code) + '</div>'; }
  function tip(title, span) { return '<div class="tip-card"><strong>' + title + '</strong><span>' + span + '</span></div>'; }

  function renderAccordion() {
    const acc = $('#accordion');
    acc.innerHTML = STEPS.map((st, i) => (
      '<div class="acc-item' + (i === 0 ? ' open' : '') + '">' +
        '<button class="acc-head">' +
          '<span class="acc-num">' + String(i + 1).padStart(2, '0') + '</span>' +
          '<span class="acc-titles"><h3>' + escHtml(st.t) + '</h3><p>' + escHtml(st.s) + '</p></span>' +
          ICON.chevron +
        '</button>' +
        '<div class="acc-body"><div class="acc-body-inner">' + st.body + '</div></div>' +
      '</div>'
    )).join('');

    $$('#accordion .acc-item').forEach(item => {
      const head = $('.acc-head', item);
      const body = $('.acc-body', item);
      const setHeight = () => { body.style.maxHeight = item.classList.contains('open') ? body.scrollHeight + 'px' : '0px'; };
      if (item.classList.contains('open')) requestAnimationFrame(setHeight);
      head.addEventListener('click', () => {
        item.classList.toggle('open');
        $$('#accordion .acc-item').forEach(o => { $('.acc-body', o).style.maxHeight = o.classList.contains('open') ? $('.acc-body', o).scrollHeight + 'px' : '0px'; });
      });
    });
  }

  /* ─── VIEW ROUTER ─── */
  function setView(id) {
    const view = VIEWS.find(v => v.id === id) || VIEWS[0];
    $$('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + view.id));
    $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === view.id));
    $('#pageTitle').textContent = view.title;
    $('#pageSubtitle').textContent = view.sub;
    if (history.replaceState) history.replaceState(null, '', '#' + view.id);
    window.scrollTo({ top: 0, behavior: 'smooth' });
    closeSidebar();
    if (view.id === 'overview') { setTimeout(animateBars, 80); animateCounters(); }
    if (view.id === 'walkthrough') requestAnimationFrame(refreshAccordion);
  }

  function refreshAccordion() {
    $$('#accordion .acc-item').forEach(o => {
      const body = $('.acc-body', o);
      body.style.maxHeight = o.classList.contains('open') ? body.scrollHeight + 'px' : '0px';
    });
  }

  /* ─── COUNTER ANIMATION ─── */
  function animateCounters() {
    $$('#statsGrid .stat-value').forEach(el => {
      const target = parseInt(el.dataset.target, 10);
      const dur = 1400, start = performance.now();
      function step(now) {
        const p = Math.min((now - start) / dur, 1);
        const eased = 1 - Math.pow(1 - p, 3);
        el.textContent = fmt(Math.floor(eased * target));
        if (p < 1) requestAnimationFrame(step); else el.textContent = fmt(target);
      }
      requestAnimationFrame(step);
    });
  }

  /* ─── MOBILE SIDEBAR ─── */
  function openSidebar() { $('#sidebar').classList.add('open'); $('#backdrop').classList.add('show'); }
  function closeSidebar() { $('#sidebar').classList.remove('open'); $('#backdrop').classList.remove('show'); }

  /* ─── GLOBAL EVENTS ─── */
  function bindEvents() {
    $('#searchInput').addEventListener('input', applyFilters);
    $('#filterCategory').addEventListener('change', applyFilters);
    $('#filterSource').addEventListener('change', applyFilters);
    $('#sortBy').addEventListener('change', applyFilters);
    $('#resetFilters').addEventListener('click', () => {
      $('#searchInput').value = '';
      $('#filterCategory').value = 'all';
      $('#filterSource').value = 'all';
      $('#sortBy').value = 'count-desc';
      applyFilters();
    });

    $('#modalClose').addEventListener('click', closeModal);
    $('#modalOverlay').addEventListener('click', e => { if (e.target.id === 'modalOverlay') closeModal(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

    $('#menuBtn').addEventListener('click', openSidebar);
    $('#backdrop').addEventListener('click', closeSidebar);

    $$('[data-goto]').forEach(b => b.addEventListener('click', () => setView(b.dataset.goto)));

    // delegated copy handler
    document.addEventListener('click', e => {
      const btn = e.target.closest('.copy-mini');
      if (!btn) return;
      e.stopPropagation();
      copyText(btn.getAttribute('data-copy'));
    });
  }

  /* ─── INIT ─── */
  function init() {
    renderNav();
    renderStats();
    renderBarChart();
    renderDonut();
    renderCatList();
    populateFilters();
    applyFilters();
    renderSources();
    renderAccordion();
    bindEvents();

    // initial view from hash
    const hash = (location.hash || '').replace('#', '');
    if (VIEWS.some(v => v.id === hash)) setView(hash);
    else { animateCounters(); setTimeout(animateBars, 200); }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
