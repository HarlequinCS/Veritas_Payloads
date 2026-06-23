/* ═══════════════════════════════════════════════════════════════
   Veritas Payloads — OWASP Top 10 Payload Dataset
   Script
   ═══════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  /* ─── DATA ─── */
  const CATEGORIES = [
    { name: 'Injection (LFI/RFI)', count: 25873, bar: 100 },
    { name: 'Injection (XSS)', count: 12462, bar: 49 },
    { name: 'Injection (Command Injection)', count: 9391, bar: 37 },
    { name: 'Injection (SQLi)', count: 5348, bar: 21 },
    { name: 'Security Misconfiguration', count: 5029, bar: 20 },
    { name: 'Software & Data Integrity Failures (Deserialization)', count: 3766, bar: 15 },
    { name: 'Identification & Authentication Failures', count: 899, bar: 4 },
    { name: 'Insecure Design', count: 473, bar: 2 },
    { name: 'Injection (Open Redirect)', count: 272, bar: 2 },
    { name: 'Cryptographic Failures', count: 166, bar: 1 },
    { name: 'Injection (NoSQLi)', count: 147, bar: 1 },
    { name: 'Broken Access Control (IDOR)', count: 138, bar: 1 },
    { name: 'Injection (SSRF)', count: 125, bar: 1 },
    { name: 'Injection (LDAP)', count: 123, bar: 1 },
    { name: 'Injection (Unrestricted File Upload)', count: 114, bar: 1 },
    { name: 'Injection (XXE)', count: 110, bar: 1 },
    { name: 'Injection (GraphQL)', count: 100, bar: 1 },
    { name: 'Injection (SSI)', count: 100, bar: 1 },
    { name: 'Injection (SSTI)', count: 86, bar: 1 },
    { name: 'Insecure Design (Race Condition)', count: 80, bar: 1 },
    { name: 'Injection (Prototype Pollution)', count: 73, bar: 1 },
  ];

  const SOURCES = [
    {
      name: 'PayloadsAllTheThings',
      by: 'Swissky & community',
      desc: 'Community-driven payload repository covering all major vulnerability categories including XSS, SQLi, LFI, SSRF, SSTI, CMD injection, Open Redirect, NoSQLi, LDAP, Prototype Pollution, and more.',
      url: 'https://github.com/swisskyrepo/PayloadsAllTheThings'
    },
    {
      name: 'SecLists',
      by: 'Daniel Miessler & Jason Haddix',
      desc: 'The ultimate collection of security testing wordlists. Extracted: XSS vectors (PortSwigger, OFJAAAH, PayloadBox), LFI paths, SQLi payloads, Commix, format strings, Java classes, and numeric amounts.',
      url: 'https://github.com/danielmiessler/SecLists'
    },
    {
      name: 'Nuclei Templates',
      by: 'ProjectDiscovery',
      desc: 'Community-contributed vulnerability templates. Extracted: WAF bypass, CORS misconfig, LFI fuzzing, SSRF proxying, XSS fuzz, SQL injection, CRLF injection, and environment disclosure patterns.',
      url: 'https://github.com/projectdiscovery/nuclei-templates'
    },
    {
      name: 'Exploit Database',
      by: 'Offensive Security',
      desc: 'The definitive archive of publicly disclosed exploits. Extracted 9,327 PoC payload strings from 13,605 webapp exploit scripts covering SQLi, XSS, LFI, CMD injection, auth bypass, and more.',
      url: 'https://gitlab.com/exploit-database/exploitdb'
    },
    {
      name: 'OWASP PayloadBox',
      by: 'PayloadBox',
      desc: 'XSS vulnerability payload list covering a wide range of injection contexts and filter bypass techniques.',
      url: 'https://github.com/payload-box/xss-payload-list'
    },
    {
      name: 'PortSwigger XSS Cheat Sheet',
      by: 'PortSwigger Research',
      desc: 'Cross-site scripting evasion and filter bypass reference. Contains hundreds of tested XSS vectors.',
      url: 'https://portswigger.net/web-security/cross-site-scripting/cheat-sheet'
    },
    {
      name: 'Commix',
      by: 'commixproject',
      desc: 'Automated command injection testing tool. Extracted 8,262 unique command injection test vectors.',
      url: 'https://github.com/commixproject/commix'
    },
    {
      name: 'sqlmap',
      by: 'sqlmapproject',
      desc: 'Automatic SQL injection and database takeover tool. Extracted risk-classified SQLi payloads.',
      url: 'https://github.com/sqlmapproject/sqlmap'
    },
    {
      name: 'LFISuite',
      by: 'D35m0nd142',
      desc: 'Local File Inclusion exploitation toolkit providing comprehensive LFI path lists for Linux and Windows targets.',
      url: 'https://github.com/D35m0nd142/LFISuite'
    },
    {
      name: 'fuzzdb',
      by: 'fuzzdb-project',
      desc: 'Attack pattern and fuzzing resource database with strings for protocol fuzzing and input validation testing.',
      url: 'https://github.com/fuzzdb-project/fuzzdb'
    },
    {
      name: 'Big List of Naughty Strings',
      by: 'minimaxir',
      desc: 'Edge case strings for input validation testing. Helps identify encoding, injection, and boundary-condition issues.',
      url: 'https://github.com/minimaxir/big-list-of-naughty-strings'
    },
    {
      name: 'Cloud & Container References',
      by: 'AWS, GCP, Azure, DigitalOcean, OpenStack, Kubernetes',
      desc: 'Cloud metadata endpoints (AWS IMDS, GCP, Azure, Alibaba, DigitalOcean, OpenStack) and container/K8s breakout paths for SSRF and LFI testing.',
      url: '#'
    }
  ];

  const LIBRARY_ITEMS = generateLibraryItems();

  function generateLibraryItems() {
    const items = [];
    CATEGORIES.forEach(cat => {
      const cleanName = cat.name.replace(/[()\/]/g, '_').toLowerCase().replace(/_+/g, '_').replace(/_$/, '');
      const sources = getSourcesForCategory(cat.name);
      const desc = getDescriptionForCategory(cat.name);
      items.push({
        id: cat.name.substring(0, 3).toUpperCase() + '-' + String(cat.count),
        category: cat.name,
        count: cat.count,
        description: desc,
        source: sources,
        usage: getUsageForCategory(cat.name)
      });
    });
    return items;
  }

  function getSourcesForCategory(cat) {
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

  function getDescriptionForCategory(cat) {
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
    return `${cat} vulnerability payloads for security testing and vulnerability assessment.`;
  }

  function getUsageForCategory(cat) {
    const ip = cat.includes('SQLi') || cat.includes('XSS') || cat.includes('LFI') ? 'query_parameter' :
               cat.includes('Command') ? 'query_parameter' :
               cat.includes('SSRF') ? 'query_parameter' :
               cat.includes('XXE') ? 'body_xml' : 'query_parameter';
    return { injectionPoint: ip, statusCode: 200, severity: 'high' };
  }

  /* ─── RENDER CATEGORIES ─── */
  function renderCategories() {
    const grid = document.getElementById('categoryGrid');
    if (!grid) return;
    grid.innerHTML = CATEGORIES.map(c => `
      <div class="cat-card">
        <span class="cat-name">${c.name}</span>
        <div class="cat-bar"><div class="cat-bar-fill" style="width: ${c.bar}%"></div></div>
        <span class="cat-count">${c.count.toLocaleString()}</span>
      </div>
    `).join('');
  }

  /* ─── RENDER SOURCES ─── */
  function renderSources() {
    const grid = document.getElementById('sourcesGrid');
    if (!grid) return;
    grid.innerHTML = SOURCES.map(s => `
      <div class="source-card">
        <h3>${s.name}</h3>
        <div class="source-by">${s.by}</div>
        <p>${s.desc}</p>
        ${s.url !== '#' ? `<a href="${s.url}" class="source-link" target="_blank">Visit Repository &rarr;</a>` : ''}
      </div>
    `).join('');
  }

  /* ─── RENDER LIBRARY ─── */
  function renderLibrary(items) {
    const grid = document.getElementById('libraryGrid');
    const empty = document.getElementById('libraryEmpty');
    if (!grid) return;
    if (!items || items.length === 0) {
      grid.innerHTML = '';
      if (empty) empty.classList.add('show');
      return;
    }
    if (empty) empty.classList.remove('show');
    grid.innerHTML = items.map(item => `
      <div class="lib-card" data-category="${item.category}" data-source="${item.source}">
        <div class="lib-card-header">
          <span class="lib-card-id">${item.id}</span>
          <span class="lib-card-cat">${item.count.toLocaleString()} payloads</span>
        </div>
        <div class="lib-card-body">
          <h4 style="font-size:.95rem;margin-bottom:6px">${item.category}</h4>
          <div class="lib-card-payload">${item.description}</div>
        </div>
        <div class="lib-card-footer">
          <span>&#9678; ${item.source}</span>
          <span>&#9654; ${item.usage.injectionPoint}</span>
          <span>&#9888; HTTP ${item.usage.statusCode}</span>
        </div>
      </div>
    `).join('');

    // Click listener for modal
    grid.querySelectorAll('.lib-card').forEach((card, idx) => {
      card.addEventListener('click', () => openModal(items[idx]));
    });
  }

  /* ─── MODAL ─── */
  function openModal(item) {
    const overlay = document.getElementById('modalOverlay');
    if (!overlay) return;
    const body = overlay.querySelector('.modal-body');
    const cat = item.category;
    overlay.classList.add('open');
    body.innerHTML = `
      <div class="detail-row">
        <div class="detail-label">Category</div>
        <div class="detail-value"><strong>${cat}</strong></div>
      </div>
      <div class="detail-row">
        <div class="detail-label">Total Payloads</div>
        <div class="detail-value">${item.count.toLocaleString()}</div>
      </div>
      <div class="detail-row">
        <div class="detail-label">Description</div>
        <div class="detail-value">${item.description}</div>
      </div>
      <div class="detail-row">
        <div class="detail-label">Sources</div>
        <div class="detail-value">${item.source}</div>
      </div>
      <div class="detail-row">
        <div class="detail-label">Target Injection Point</div>
        <div class="detail-value code">${item.usage.injectionPoint}</div>
      </div>
      <div class="detail-row">
        <div class="detail-label">Expected Status Code</div>
        <div class="detail-value">HTTP ${item.usage.statusCode}</div>
      </div>
      <div class="detail-row">
        <div class="detail-label">Example Payload</div>
        <div class="detail-value code">${getExamplePayload(cat)}</div>
      </div>
    `;
  }

  function getExamplePayload(cat) {
    const examples = {
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
      'CRLF': '%0d%0aSet-Cookie: malicious=true',
    };
    for (const [key, val] of Object.entries(examples)) {
      if (cat.includes(key)) return val;
    }
    return 'Example payload string for this category';
  }

  function closeModal() {
    const overlay = document.getElementById('modalOverlay');
    if (overlay) overlay.classList.remove('open');
  }

  /* ─── SEARCH & FILTER ─── */
  let currentFiltered = LIBRARY_ITEMS;

  function filterLibrary() {
    const searchTerm = (document.getElementById('searchInput').value || '').toLowerCase();
    const catFilter = document.getElementById('filterCategory').value;
    const srcFilter = document.getElementById('filterSource').value;

    currentFiltered = LIBRARY_ITEMS.filter(item => {
      const matchSearch = !searchTerm ||
        item.category.toLowerCase().includes(searchTerm) ||
        item.source.toLowerCase().includes(searchTerm) ||
        item.description.toLowerCase().includes(searchTerm);
      const matchCat = catFilter === 'all' || item.category === catFilter;
      const matchSrc = srcFilter === 'all' || item.source.includes(srcFilter);
      return matchSearch && matchCat && matchSrc;
    });
    renderLibrary(currentFiltered);
  }

  function populateFilters() {
    const catSelect = document.getElementById('filterCategory');
    const srcSelect = document.getElementById('filterSource');
    if (!catSelect || !srcSelect) return;

    const cats = new Set();
    const srcs = new Set();
    LIBRARY_ITEMS.forEach(item => {
      cats.add(item.category);
      item.source.split(', ').forEach(s => srcs.add(s));
    });

    cats.forEach(c => {
      const opt = document.createElement('option');
      opt.value = c; opt.textContent = c;
      catSelect.appendChild(opt);
    });
    srcs.forEach(s => {
      const opt = document.createElement('option');
      opt.value = s; opt.textContent = s;
      srcSelect.appendChild(opt);
    });
  }

  /* ─── HERO COUNTER ANIMATION ─── */
  function animateCounter() {
    const el = document.querySelector('.stat-num[data-target]');
    if (!el) return;
    const target = parseInt(el.getAttribute('data-target'), 10);
    const duration = 2000;
    const startTime = performance.now();

    function update(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.floor(eased * target).toLocaleString();
      if (progress < 1) requestAnimationFrame(update);
      else el.textContent = target.toLocaleString();
    }
    requestAnimationFrame(update);
  }

  /* ─── NAV SCROLL EFFECT ─── */
  function handleNavScroll() {
    const nav = document.getElementById('navbar');
    if (!nav) return;
    nav.classList.toggle('scrolled', window.scrollY > 64);
  }

  /* ─── NAV TOGGLE ─── */
  function setupNavToggle() {
    const btn = document.getElementById('navToggle');
    const links = document.getElementById('navLinks');
    if (!btn || !links) return;
    btn.addEventListener('click', () => links.classList.toggle('open'));
    links.querySelectorAll('a').forEach(a => a.addEventListener('click', () => links.classList.remove('open')));
  }

  /* ─── NAV ACTIVE LINK ─── */
  function updateActiveLink() {
    const links = document.querySelectorAll('.nav-links a');
    const sections = document.querySelectorAll('.section[id]');
    let current = '';
    sections.forEach(s => {
      const top = s.getBoundingClientRect().top;
      if (top <= 200) current = s.id;
    });
    links.forEach(a => {
      a.classList.toggle('active', a.getAttribute('href') === '#' + current);
    });
  }

  /* ─── MODAL CLOSE EVENTS ─── */
  function setupModal() {
    const overlay = document.getElementById('modalOverlay');
    if (!overlay) return;
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closeModal();
    });
    const closeBtn = overlay.querySelector('.modal-close');
    if (closeBtn) closeBtn.addEventListener('click', closeModal);
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeModal();
    });
  }

  /* ─── ADD MODAL TO DOM ─── */
  function addModal() {
    const div = document.createElement('div');
    div.className = 'modal-overlay';
    div.id = 'modalOverlay';
    div.innerHTML = `
      <div class="modal">
        <div class="modal-header">
          <h3>Payload Details</h3>
          <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body"></div>
      </div>
    `;
    document.body.appendChild(div);
  }

  /* ─── INIT ─── */
  function init() {
    addModal();
    renderCategories();
    renderSources();
    populateFilters();
    renderLibrary(LIBRARY_ITEMS);

    // Search/filter events
    document.getElementById('searchInput').addEventListener('input', filterLibrary);
    document.getElementById('filterCategory').addEventListener('change', filterLibrary);
    document.getElementById('filterSource').addEventListener('change', filterLibrary);

    // Nav
    setupNavToggle();
    window.addEventListener('scroll', () => { handleNavScroll(); updateActiveLink(); }, { passive: true });
    updateActiveLink();

    // Modal
    setupModal();

    // Counter animation on load
    setTimeout(animateCounter, 400);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
