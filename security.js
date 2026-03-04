/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║         ClassRoom Hub — SECURITY ENGINE v2.0                ║
 * ║  Firewall · Anti-Malware · Anti-XSS · Anti-Injection        ║
 * ║  Brute-Force Guard · Session Integrity · URL Scanner        ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

const Security = (() => {
  'use strict';

  // ─── SECURITY LOG ──────────────────────────────────────────────
  const LOG_KEY = 'ch_seclog';
  const MAX_LOG = 200;

  function getLog() {
    try { return JSON.parse(localStorage.getItem(LOG_KEY) || '[]'); } catch(e) { return []; }
  }
  function writeLog(entry) {
    try {
      const log = getLog();
      log.unshift({ ...entry, time: new Date().toISOString(), id: Math.random().toString(36).slice(2) });
      if (log.length > MAX_LOG) log.length = MAX_LOG;
      localStorage.setItem(LOG_KEY, JSON.stringify(log));
    } catch(e) {}
  }
  function logThreat(level, type, detail, blocked) {
    if (blocked === undefined) blocked = true;
    writeLog({ level, type, detail, blocked });
    console.warn('[SECURITY][' + level + '] ' + type + ': ' + detail);
  }

  // ─── BRUTE-FORCE PROTECTION ────────────────────────────────────
  const BF_KEY    = 'ch_bf';
  const MAX_TRIES = 5;
  const LOCK_MS   = 15 * 60 * 1000;

  function getBF() {
    try { return JSON.parse(localStorage.getItem(BF_KEY) || '{"tries":0,"lockedUntil":0}'); }
    catch(e) { return { tries: 0, lockedUntil: 0 }; }
  }
  function saveBF(data) { try { localStorage.setItem(BF_KEY, JSON.stringify(data)); } catch(e) {} }

  function checkBruteForce() {
    const bf = getBF();
    if (bf.lockedUntil && Date.now() < bf.lockedUntil) {
      const mins = Math.ceil((bf.lockedUntil - Date.now()) / 60000);
      return { locked: true, message: '🔒 Too many failed attempts. Try again in ' + mins + ' minute(s).' };
    }
    if (bf.lockedUntil && Date.now() >= bf.lockedUntil) saveBF({ tries: 0, lockedUntil: 0 });
    return { locked: false };
  }

  function recordLoginFail() {
    const bf = getBF();
    bf.tries = (bf.tries || 0) + 1;
    if (bf.tries >= MAX_TRIES) {
      bf.lockedUntil = Date.now() + LOCK_MS;
      logThreat('CRITICAL', 'BRUTE_FORCE', bf.tries + ' failed login attempts — locked 15min', true);
      saveBF(bf);
      return { locked: true, message: '🔒 ' + MAX_TRIES + ' failed attempts. Account locked for 15 minutes.' };
    }
    saveBF(bf);
    logThreat('WARN', 'FAILED_LOGIN', 'Failed attempt ' + bf.tries + '/' + MAX_TRIES, false);
    return { locked: false, remaining: MAX_TRIES - bf.tries };
  }

  function recordLoginSuccess() { saveBF({ tries: 0, lockedUntil: 0 }); }

  // ─── SESSION INTEGRITY ──────────────────────────────────────────
  const SESSION_KEY = 'ch_session';
  const SESSION_TTL = 8 * 60 * 60 * 1000;

  function getFingerprint() {
    const parts = [navigator.userAgent, navigator.language, screen.colorDepth,
                   screen.width + 'x' + screen.height, new Date().getTimezoneOffset()];
    let h = 0;
    const str = parts.join('|');
    for (let i = 0; i < str.length; i++) { h = ((h << 5) - h) + str.charCodeAt(i); h |= 0; }
    return h.toString(36);
  }

  function createSession(user) {
    const arr = new Uint32Array(4);
    crypto.getRandomValues(arr);
    const session = {
      user, token: Array.from(arr).join('-'),
      created: Date.now(), expires: Date.now() + SESSION_TTL,
      fingerprint: getFingerprint()
    };
    try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(session)); } catch(e) {}
    return session;
  }

  function validateSession() {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      if (!raw) return { valid: false, reason: 'No session' };
      const s = JSON.parse(raw);
      if (Date.now() > s.expires) {
        sessionStorage.removeItem(SESSION_KEY);
        logThreat('INFO', 'SESSION_EXPIRED', 'Session expired', true);
        return { valid: false, reason: 'expired' };
      }
      if (s.fingerprint !== getFingerprint()) {
        sessionStorage.removeItem(SESSION_KEY);
        logThreat('HIGH', 'SESSION_HIJACK', 'Fingerprint mismatch — session killed', true);
        return { valid: false, reason: 'fingerprint' };
      }
      return { valid: true, session: s };
    } catch(e) { return { valid: false, reason: 'corrupt' }; }
  }

  function destroySession() { sessionStorage.removeItem(SESSION_KEY); }

  // ─── XSS / INJECTION FIREWALL ──────────────────────────────────
  const XSS_PATTERNS = [
    { re: /<script[\s\S]*?>[\s\S]*?<\/script>/gi,  name: 'Script tag' },
    { re: /<script[^>]*>/gi,                        name: 'Script open tag' },
    { re: /javascript\s*:/gi,                       name: 'JS protocol' },
    { re: /vbscript\s*:/gi,                         name: 'VBScript protocol' },
    { re: /data\s*:\s*text\/html/gi,                name: 'Data URI HTML' },
    { re: /\bon\w+\s*=/gi,                          name: 'Inline event handler' },
    { re: /<(iframe|object|embed|form|link|meta|base|frame|frameset)[^>]*>/gi, name: 'Dangerous tag' },
    { re: /expression\s*\(/gi,                      name: 'CSS expression' },
    { re: /-moz-binding/gi,                         name: 'CSS binding' },
    { re: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC)\b)/gi, name: 'SQL keyword' },
    { re: /(--|\/\*|\*\/)/g,                        name: 'SQL comment' },
    { re: /\.\.[\/\\]/g,                            name: 'Path traversal' },
    { re: /\x00/g,                                  name: 'Null byte' },
  ];

  function sanitizeString(input) {
    if (typeof input !== 'string') return { value: String(input || ''), threats: [] };
    let value = input;
    const threats = [];
    for (const pat of XSS_PATTERNS) {
      pat.re.lastIndex = 0;
      if (pat.re.test(value)) {
        threats.push(pat.name);
        pat.re.lastIndex = 0;
        value = value.replace(pat.re, '');
      }
    }
    value = value.replace(/&(?!amp;|lt;|gt;|quot;|#\d+;)/g, '&amp;')
                 .replace(/</g, '&lt;').replace(/>/g, '&gt;').trim();
    if (value.length > 5000) { value = value.slice(0, 5000); threats.push('Truncated'); }
    return { value, threats };
  }

  function scanContent(obj) {
    const clean = {};
    const allThreats = [];
    for (const key of Object.keys(obj)) {
      const r = sanitizeString(obj[key]);
      clean[key] = r.value;
      r.threats.forEach(t => allThreats.push('[' + key + '] ' + t));
    }
    if (allThreats.length) logThreat('HIGH', 'XSS_ATTEMPT', allThreats.join(', '), true);
    return { clean, wasModified: allThreats.length > 0, threats: allThreats };
  }

  // ─── URL / MALWARE SCANNER ──────────────────────────────────────
  const BLOCKED_PROTOS = ['javascript:', 'vbscript:', 'data:', 'blob:', 'file:'];
  const MALICIOUS_PATS = [
    /[<>'"]/,
    /(\.\.)|(\/\/\/)/,
    /[^\x20-\x7E]/,
    /\.(exe|bat|cmd|sh|ps1|msi|dll|vbs|jar|apk)$/i,
  ];
  const SAFE_DOMAINS = [
    'khanacademy.org','wikipedia.org','bbc.co.uk','youtube.com','youtu.be',
    'github.com','google.com','drive.google.com','docs.google.com',
    'classroom.google.com','microsoft.com','office.com','onedrive.live.com',
    'dropbox.com','notion.so','grammarly.com','duolingo.com','coursera.org',
    'edx.org','udemy.com','britannica.com','quizlet.com','desmos.com','wolframalpha.com'
  ];

  function validateURL(url, context) {
    if (!url || url === '#') return { safe: true, url: '#' };
    const trimmed = url.trim();
    for (const p of BLOCKED_PROTOS) {
      if (trimmed.toLowerCase().startsWith(p)) {
        logThreat('CRITICAL', 'MALICIOUS_URL', 'Blocked ' + p + ' in ' + context, true);
        return { safe: false, reason: 'Protocol "' + p + '" is blocked' };
      }
    }
    for (const p of MALICIOUS_PATS) {
      if (p.test(trimmed)) {
        logThreat('HIGH', 'SUSPICIOUS_URL', 'Pattern matched in ' + context, true);
        return { safe: false, reason: 'URL contains suspicious characters' };
      }
    }
    if (!trimmed.startsWith('https://') && !trimmed.startsWith('http://'))
      return { safe: false, reason: 'URL must begin with https:// or http://' };
    try {
      const host = new URL(trimmed).hostname.replace(/^www\./, '');
      const known = SAFE_DOMAINS.some(d => host === d || host.endsWith('.' + d));
      if (!known) logThreat('WARN', 'UNKNOWN_DOMAIN', 'Unrecognised domain: ' + host, false);
    } catch(e) { return { safe: false, reason: 'Invalid URL' }; }
    return { safe: true, url: trimmed };
  }

  // ─── CSP ────────────────────────────────────────────────────────
  function enforceCSP() {
    if (document.querySelector('meta[http-equiv="Content-Security-Policy"]')) return;
    const m = document.createElement('meta');
    m.httpEquiv = 'Content-Security-Policy';
    m.content = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";
    document.head.prepend(m);
  }

  // ─── DOM GUARD ──────────────────────────────────────────────────
  function startDOMGuard() {
    if (typeof MutationObserver === 'undefined') return;
    const obs = new MutationObserver(function(mutations) {
      mutations.forEach(function(m) {
        m.addedNodes.forEach(function(node) {
          if (node.nodeType !== 1) return;
          const tag = (node.tagName || '').toLowerCase();
          if (['script','iframe','object','embed'].includes(tag)) {
            node.remove();
            logThreat('CRITICAL', 'DOM_INJECTION', 'Blocked injected <' + tag + '>', true);
            showSecurityAlert('🛡️ Security blocked an injected element!');
          }
          if (node.attributes) {
            Array.from(node.attributes).forEach(function(a) {
              if (a.name.startsWith('on')) {
                node.removeAttribute(a.name);
                logThreat('HIGH', 'EVENT_INJECT', 'Removed event attr: ' + a.name, true);
              }
            });
          }
        });
      });
    });
    obs.observe(document.body, { childList: true, subtree: true, attributes: true });
  }

  // ─── CLICKJACKING GUARD ─────────────────────────────────────────
  function checkClickjacking() {
    if (window.top !== window.self) {
      document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#1a1a2e;color:#ff6584;font-family:sans-serif;text-align:center;padding:20px"><div><div style="font-size:4rem">🛡️</div><h1 style="margin:12px 0">Clickjacking Blocked</h1><p style="color:#8892a4">This app cannot run inside another page.</p><a href="' + window.location.href + '" target="_blank" style="display:inline-block;margin-top:16px;padding:10px 24px;background:#6c63ff;color:white;border-radius:10px;text-decoration:none">Open Directly →</a></div></div>';
      logThreat('CRITICAL', 'CLICKJACKING', 'Iframe embed blocked', true);
    }
  }

  // ─── RATE LIMITER ───────────────────────────────────────────────
  const actionTs = {};
  function rateLimit(action, maxPerMin) {
    if (!maxPerMin) maxPerMin = 10;
    const now = Date.now();
    if (!actionTs[action]) actionTs[action] = [];
    actionTs[action] = actionTs[action].filter(function(t){ return now - t < 60000; });
    if (actionTs[action].length >= maxPerMin) {
      logThreat('WARN', 'RATE_LIMIT', 'Action "' + action + '" exceeded ' + maxPerMin + '/min', true);
      return false;
    }
    actionTs[action].push(now);
    return true;
  }

  // ─── STORAGE INTEGRITY ──────────────────────────────────────────
  function checkStorageIntegrity() {
    try {
      const raw = localStorage.getItem('classroomhub_data');
      if (!raw) return true;
      const data = JSON.parse(raw);
      ['notes','assignments','resources','announcements','students'].forEach(function(k){
        if (!Array.isArray(data[k])) throw new Error('Bad field: ' + k);
      });
      return true;
    } catch(e) {
      logThreat('HIGH', 'STORAGE_TAMPER', e.message, true);
      return false;
    }
  }

  // ─── SECURITY ALERT UI ──────────────────────────────────────────
  function showSecurityAlert(msg) {
    const old = document.getElementById('secAlert');
    if (old) old.remove();
    const el = document.createElement('div');
    el.id = 'secAlert';
    el.style.cssText = 'position:fixed;top:70px;left:50%;transform:translateX(-50%);background:#ff6584;color:white;padding:12px 20px;border-radius:12px;font-size:0.85rem;font-weight:600;z-index:9999;max-width:90vw;text-align:center;box-shadow:0 4px 20px rgba(255,101,132,0.5)';
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(function(){ el.remove(); }, 5000);
  }

  // ─── DASHBOARD DATA ─────────────────────────────────────────────
  function getDashboardData() {
    const log = getLog();
    const stats = {
      total:    log.length,
      critical: log.filter(function(e){ return e.level==='CRITICAL'; }).length,
      high:     log.filter(function(e){ return e.level==='HIGH'; }).length,
      warn:     log.filter(function(e){ return e.level==='WARN'; }).length,
      blocked:  log.filter(function(e){ return e.blocked; }).length,
    };
    const types = {};
    log.forEach(function(e){ types[e.type] = (types[e.type]||0)+1; });
    return { stats, types, log: log.slice(0, 50) };
  }

  function clearLog() { try { localStorage.removeItem(LOG_KEY); } catch(e) {} }

  // ─── INIT ────────────────────────────────────────────────────────
  function init() {
    checkClickjacking();
    enforceCSP();
    document.addEventListener('DOMContentLoaded', function() {
      startDOMGuard();
      checkStorageIntegrity();
    });
    document.addEventListener('keydown', function(e) {
      if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && ['I','J','C'].includes(e.key)))
        logThreat('INFO', 'DEVTOOLS', 'DevTools shortcut pressed', false);
    });
    logThreat('INFO', 'SECURITY_INIT', 'Security Engine v2.0 initialised', false);
  }

  init();

  return {
    checkBruteForce, recordLoginFail, recordLoginSuccess,
    createSession, validateSession, destroySession,
    sanitizeString, scanContent, validateURL,
    rateLimit, getDashboardData, clearLog, getLog, logThreat,
    showSecurityAlert, checkStorageIntegrity
  };
})();
