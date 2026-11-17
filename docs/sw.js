/* Offline support: app shell cached; published data network-first. */
const CACHE = "cortex-v0.6.0";
const SHELL = ["./", "index.html", "app.js", "engine.js", "samples.js", "manifest.webmanifest",
               "icons/apple-touch-icon.png", "icons/icon-192.png", "icons/icon-512.png"];
self.addEventListener("install", e => e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())));
self.addEventListener("activate", e => e.waitUntil(
  caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener("fetch", e => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin) return;              // Pyodide CDN: browser cache handles it
  if (url.pathname.endsWith("/data/status.json")) {         // network first, fall back to cache
    e.respondWith(fetch(e.request).then(r => { const c = r.clone(); caches.open(CACHE).then(x => x.put("data/status.json", c)); return r; })
      .catch(() => caches.match("data/status.json")));
    return;
  }
  e.respondWith(caches.match(e.request, { ignoreSearch: true }).then(r => r || fetch(e.request)));
});
