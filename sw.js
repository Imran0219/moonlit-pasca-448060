// ClassRoom Hub — Hardened Service Worker v2.0
const CACHE_NAME = 'classroomhub-v2-secure';
const ASSETS = ['./', './index.html', './manifest.json', './security.js', './icons/icon-192.svg', './icons/icon-512.svg'];
const ALLOWED_ORIGINS = [self.location.origin];
const DANGEROUS_CONTENT_TYPES = ['application/x-msdownload','application/x-executable','application/x-dosexec','application/octet-stream','application/x-sh','text/x-shellscript'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(ASSETS)).catch(err => console.warn('[SW]', err)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Block non-http(s)
  if (!['https:','http:'].includes(url.protocol)) {
    e.respondWith(new Response('Blocked by security policy', {status:403})); return;
  }
  // Block suspicious URL patterns
  const suspicious = [/\.\.(\/|%2f)/i, /javascript:/i, /data:text\/html/i, /<script/i, /%3cscript/i];
  if (suspicious.some(p => p.test(e.request.url))) {
    e.respondWith(new Response('Suspicious URL blocked', {status:403})); return;
  }
  // Block cross-origin to non-whitelisted
  const isCross = url.origin !== self.location.origin;
  if (isCross && !ALLOWED_ORIGINS.some(o => url.href.startsWith(o))) {
    e.respondWith(new Response('Cross-origin blocked', {status:403})); return;
  }
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request.clone()).then(res => {
        if (!res || res.status !== 200) return res;
        const ct = res.headers.get('content-type') || '';
        if (DANGEROUS_CONTENT_TYPES.some(t => ct.includes(t))) return new Response('Dangerous file blocked', {status:403});
        if (!isCross && res.type === 'basic') {
          const clone = res.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        }
        return res;
      }).catch(() => caches.match('./index.html') || new Response('Offline', {status:503}));
    })
  );
});

self.addEventListener('message', e => {
  if (e.data?.type === 'CLEAR_CACHE') caches.delete(CACHE_NAME).then(() => e.ports[0]?.postMessage({success:true}));
  if (e.data?.type === 'SECURITY_PING') e.ports[0]?.postMessage({active:true, cache:CACHE_NAME});
});
