// 離線快取：所有檔案都來自同一個網站，不載入任何外部資源
// 更新網站時請把版本號 +1，使用者下次開啟就會取得新版
const CACHE = 'myvault-v1.0.0';
const FILES = [
  './',
  './index.html',
  './styles.css',
  './app.js',
  './core.js',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/apple-touch-icon.png',
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim()));
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== location.origin) return;
  e.respondWith(
    caches.match(req, { ignoreSearch: true }).then(hit => hit || fetch(req)));
});
