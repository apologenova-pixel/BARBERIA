/**
 * ══════════════════════════════════════════════════════════════
 *  sw.js — Service Worker · Fabiola Gestión Pro
 *  Cache offline + instalación PWA · Tecno Jump
 * ══════════════════════════════════════════════════════════════
 *
 *  ESTRATEGIA: Cache-First para assets estáticos,
 *  Network-First para llamadas a Firebase (datos en tiempo real).
 *
 *  Cuando el dispositivo pierde internet:
 *   → La UI carga desde caché (funciona sin conexión)
 *   → Firebase Firestore usa su propia persistencia offline
 *   → Al reconectarse, sincroniza automáticamente
 */

const CACHE_NAME     = 'fabiola-v4.0';
const CACHE_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 días en ms

// Assets estáticos que se cachean al instalar el SW
const STATIC_ASSETS = [
  './',
  './index.html',
  './app.js',
  './styles.css',
  './config.js',
  './manifest.json',
  // CDNs — se cachean en el primer acceso (ver fetch handler)
];

// URLs que NUNCA se cachean (siempre van a la red)
const BYPASS_PATTERNS = [
  'firestore.googleapis.com',
  'firebase.googleapis.com',
  'identitytoolkit.googleapis.com',
  'securetoken.googleapis.com',
];

// ── Instalación — precaché de assets core ──────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(STATIC_ASSETS))
      .then(() => self.skipWaiting()) // activar inmediatamente
  );
});

// ── Activación — limpiar cachés antiguas ───────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => k !== CACHE_NAME)
          .map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// ── Fetch — estrategia híbrida ──────────────────────────────────
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // 1. Siempre network para Firebase
  if (BYPASS_PATTERNS.some(p => url.hostname.includes(p))) return;

  // 2. Solo GET se cachea
  if (request.method !== 'GET') return;

  // 3. CDNs externos: Cache-First con fallback a red
  if (url.origin !== self.location.origin) {
    event.respondWith(
      caches.match(request).then(cached => {
        if (cached) return cached;
        return fetch(request).then(response => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
          }
          return response;
        }).catch(() => cached || new Response('Recurso no disponible', { status: 503 }));
      })
    );
    return;
  }

  // 4. Assets locales: Network-First con fallback a caché
  event.respondWith(
    fetch(request)
      .then(response => {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
        }
        return response;
      })
      .catch(() => caches.match(request)
        .then(cached => cached || caches.match('./index.html'))
      )
  );
});

// ── Mensaje desde la app (forzar actualización) ────────────────
self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
});
