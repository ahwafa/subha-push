/* سُبحة: reminder server.
   The app sends its upcoming reminders here (times already worked out on the phone, prayer times included).
   One Durable Object keeps them and wakes itself with an alarm at each reminder's time, then sends a
   Web Push message (RFC 8291 encryption, RFC 8292 VAPID) to the phone. No other services or keys to set up:
   the VAPID key pair is made on first use and kept in the object's storage. */
import { DurableObject } from 'cloudflare:workers';

const CONTACT = 'https://ahwafa.github.io/Subha/';
const MAX_SUBS = 8;            // phones that may register; this server is for one person
const MAX_ITEMS = 400;         // reminders kept per phone (the app sends about two weeks)
const WAKE_EARLY = 5000;       // wake a few seconds before a reminder's minute
const DUE_WINDOW = 15000;      // and send everything that falls within the next few seconds
const PUSH_HOSTS = /(^|\.)(push\.apple\.com|googleapis\.com|push\.services\.mozilla\.com|notify\.windows\.com)$/;

/* ---------- small helpers ---------- */
const enc = new TextEncoder();
function b64u(bytes) {
  const b = new Uint8Array(bytes); let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64u(str) {
  str = String(str || '').replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
const randomId = n => b64u(crypto.getRandomValues(new Uint8Array(n)));
const str = (v, max) => (typeof v === 'string' ? v : '').slice(0, max);
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8' } });
}
function cors(res) {
  const h = new Headers(res.headers);
  h.set('Access-Control-Allow-Origin', '*');
  h.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  h.set('Access-Control-Allow-Headers', 'content-type');
  h.set('Access-Control-Max-Age', '86400');
  return new Response(res.body, { status: res.status, headers: h });
}

/* ---------- Web Push ---------- */
async function makeVapid() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return {
    publicKey: b64u(await crypto.subtle.exportKey('raw', kp.publicKey)),
    privateJwk: await crypto.subtle.exportKey('jwk', kp.privateKey)
  };
}
async function vapidAuth(endpoint, vapid) {
  const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64u(enc.encode(JSON.stringify({
    aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: CONTACT
  })));
  const key = await crypto.subtle.importKey('jwk', vapid.privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(head + '.' + claims));
  return 'vapid t=' + head + '.' + claims + '.' + b64u(sig) + ', k=' + vapid.publicKey;
}
async function hkdf(salt, ikm, info, bytes) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, bytes * 8));
}
/* aes128gcm content encoding, one record (RFC 8188 + RFC 8291) */
async function encrypt(sub, text) {
  const uaPublic = unb64u(sub.keys.p256dh);
  const authSecret = unb64u(sub.keys.auth);
  const local = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', local.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, local.privateKey, 256));
  const ikm = await hkdf(authSecret, shared, concat(enc.encode('WebPush: info\0'), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, concat(enc.encode(text), new Uint8Array([2]))));
  const header = new Uint8Array(21);
  header.set(salt, 0); new DataView(header.buffer).setUint32(16, 4096); header[20] = asPublic.length;
  return concat(header, asPublic, cipher);
}
/* returns the push service's HTTP status, or 0 when it could not be reached */
async function sendPush(sub, data, vapid, ttl = 1800) {
  try {
    const res = await fetch(sub.endpoint, {
      method: 'POST',
      headers: {
        'Authorization': await vapidAuth(sub.endpoint, vapid),
        'Content-Encoding': 'aes128gcm',
        'Content-Type': 'application/octet-stream',
        'TTL': String(ttl),
        'Urgency': 'high'
      },
      body: await encrypt(sub, JSON.stringify(data))
    });
    return res.status;
  } catch (e) {
    return 0;
  }
}

/* ---------- what the app may send ---------- */
function cleanSub(s, allowAny) {
  if (!s || typeof s !== 'object' || !s.keys) return null;
  let u; try { u = new URL(s.endpoint); } catch (e) { return null; }
  if (!allowAny && (u.protocol !== 'https:' || !PUSH_HOSTS.test(u.hostname))) return null;
  const p256dh = str(s.keys.p256dh, 200), auth = str(s.keys.auth, 100);
  if (unb64u(p256dh).length !== 65 || unb64u(auth).length !== 16) return null;
  return { endpoint: u.href, keys: { p256dh, auth } };
}
function cleanUrl(v) {
  v = str(v, 300);
  return (/^\.?\//.test(v) || v.startsWith(CONTACT)) ? v : './';
}
function cleanSchedule(list) {
  const now = Date.now(); const out = [];
  if (!Array.isArray(list)) return out;
  for (const x of list) {
    if (!x || typeof x !== 'object') continue;
    const at = Math.round(+x.at);
    if (!Number.isFinite(at) || at < now - 5 * 60000 || at > now + 45 * 86400000) continue;
    out.push({ at, title: str(x.title, 90) || 'سُبحة', body: str(x.body, 300), tag: str(x.tag, 80) || 'subha-' + at, url: cleanUrl(x.url) });
    if (out.length >= MAX_ITEMS) break;
  }
  return out.sort((a, b) => a.at - b.at);
}

/* ---------- the object that remembers and wakes up on time ---------- */
export class Hub extends DurableObject {
  async vapid() {
    let v = await this.ctx.storage.get('vapid');
    if (!v) { v = await makeVapid(); await this.ctx.storage.put('vapid', v); }
    return v;
  }
  async all() { return [...(await this.ctx.storage.list({ prefix: 'sub:' })).values()]; }
  async save(rec) { await this.ctx.storage.put('sub:' + rec.id, rec); }
  async drop(rec) { await this.ctx.storage.delete('sub:' + rec.id); }
  async find(body) {
    const rec = typeof body.id === 'string' ? await this.ctx.storage.get('sub:' + body.id.slice(0, 40)) : null;
    return rec && typeof body.token === 'string' && body.token === rec.token ? rec : null;
  }
  /* wake at the earliest reminder of any phone */
  async arm() {
    let next = Infinity;
    for (const rec of await this.all()) if (rec.schedule.length && rec.schedule[0].at < next) next = rec.schedule[0].at;
    if (next === Infinity) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(Math.max(Date.now() + 1000, next - WAKE_EARLY));
  }
  setSchedule(rec, list) {
    rec.schedule = cleanSchedule(list);
    rec.synced = Date.now();
    rec.horizon = rec.schedule.length ? rec.schedule[rec.schedule.length - 1].at : 0;
    rec.nudged = false;
  }
  async deliver(rec, data, ttl) {
    const status = await sendPush(rec.sub, data, await this.vapid(), ttl);
    if (status === 404 || status === 410) await this.drop(rec);   // the phone no longer has this subscription
    return status;
  }

  async fetch(request) {
    const path = new URL(request.url).pathname;
    try {
      if (path === '/api/key' && request.method === 'GET') return json({ key: (await this.vapid()).publicKey });
      if (request.method !== 'POST') return json({ error: 'method' }, 405);
      const body = await request.json().catch(() => null);
      if (!body || typeof body !== 'object') return json({ error: 'bad request' }, 400);

      if (path === '/api/subscribe') {
        const sub = cleanSub(body.subscription, !!this.env.ALLOW_ANY_ENDPOINT);
        if (!sub) return json({ error: 'subscription' }, 400);
        const recs = await this.all();
        let rec = await this.find(body) || recs.find(r => r.sub.endpoint === sub.endpoint);
        if (!rec) {
          if (recs.length >= MAX_SUBS) return json({ error: 'full' }, 429);
          rec = { id: randomId(12), created: Date.now() };
        }
        rec.token = randomId(24);
        rec.sub = sub;
        this.setSchedule(rec, body.schedule);
        await this.save(rec); await this.arm();
        return json({ id: rec.id, token: rec.token, count: rec.schedule.length });
      }

      const rec = await this.find(body);
      if (!rec) return json({ error: 'unknown' }, 404);
      if (path === '/api/schedule') {
        this.setSchedule(rec, body.schedule);
        await this.save(rec); await this.arm();
        return json({ ok: true, count: rec.schedule.length, next: rec.schedule.length ? rec.schedule[0].at : null });
      }
      if (path === '/api/test') {
        const status = await this.deliver(rec, { title: 'سُبحة', body: 'وصلت التجربة ✓ وبكذا تجيك التذكيرات في وقتها', tag: 'subha-test', url: './' }, 600);
        return json({ ok: status >= 200 && status < 300, status }, status === 404 || status === 410 ? 404 : 200);
      }
      if (path === '/api/unsubscribe') {
        await this.drop(rec); await this.arm();
        return json({ ok: true });
      }
      return json({ error: 'not found' }, 404);
    } catch (e) {
      return json({ error: String((e && e.message) || e) }, 500);
    }
  }

  async alarm() {
    const now = Date.now();
    const vapid = await this.vapid();
    for (const rec of await this.all()) {
      const due = rec.schedule.filter(x => x.at <= now + DUE_WINDOW);
      const keep = rec.schedule.filter(x => x.at > now + DUE_WINDOW);
      let gone = false, changed = due.length > 0;
      for (const item of due) {
        if (item.at < now - 2 * 3600000) continue;                 // hours late (server was asleep): skip quietly
        const status = await sendPush(rec.sub, { title: item.title, body: item.body, tag: item.tag, url: item.url }, vapid);
        if (status === 404 || status === 410) { gone = true; break; }
        if ((status === 0 || status === 429 || status >= 500) && (item.tries || 0) < 3) {
          keep.push(Object.assign({}, item, { at: now + 60000, tries: (item.tries || 0) + 1 }));   // try again in a minute
        }
      }
      if (gone) { await this.drop(rec); continue; }
      rec.schedule = keep.sort((a, b) => a.at - b.at);
      /* the app has not been opened for a long while and its reminders are running out: ask once to open it */
      if (!rec.nudged && rec.horizon - rec.synced > 5 * 86400000 && now >= rec.horizon - 36 * 3600000) {
        rec.nudged = true; changed = true;
        const status = await sendPush(rec.sub, { title: 'سُبحة', body: 'افتح التطبيق مرة عشان تتجدد تذكيراتك للأيام الجاية', tag: 'subha-refresh', url: './' }, vapid, 86400);
        if (status === 404 || status === 410) { await this.drop(rec); continue; }
      }
      if (changed) await this.save(rec);
    }
    await this.arm();
  }
}

/* ---------- the front door ---------- */
const HOME = `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>خادم تذكير سُبحة</title>
<style>
:root{--bg:#ECEFE8;--card:#F9FAF6;--ink:#15242A;--ink2:#55666A;--accent:#A9671A;--line:#CED6CF}
@media (prefers-color-scheme: dark){:root{--bg:#0C1618;--card:#132225;--ink:#F1E8D8;--ink2:#9EB0AD;--accent:#E8A847;--line:#233739}}
body{margin:0;background:var(--bg);color:var(--ink);font:17px/1.7 system-ui,-apple-system,"Geeza Pro",sans-serif;padding:24px 16px}
main{max-width:520px;margin:0 auto;background:var(--card);border:1px solid var(--line);border-radius:20px;padding:22px}
h1{font-size:22px;margin:0 0 6px}p{margin:8px 0;color:var(--ink2)}
.link{direction:ltr;text-align:left;background:var(--bg);border:1px solid var(--line);border-radius:12px;padding:12px;font:15px ui-monospace,Menlo,monospace;word-break:break-all;color:var(--ink);margin:14px 0}
button{width:100%;font:inherit;font-weight:700;border:0;border-radius:14px;padding:13px;background:var(--accent);color:#fff;cursor:pointer}
</style></head><body><main>
<h1>خادم تذكير سُبحة يعمل ✓</h1>
<p>انسخ هذا الرابط، وافتح سُبحة من أيقونتها، ثم الصقه في: الإعدادات ← إشعارات على الجوال.</p>
<div class="link" id="u"></div>
<button id="c">نسخ الرابط</button>
</main><script>
var u=location.origin,el=document.getElementById('u'),b=document.getElementById('c');el.textContent=u;
b.onclick=function(){var ok=function(){b.textContent='نُسخ ✓';};
if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(u).then(ok,sel);else sel();
function sel(){var r=document.createRange();r.selectNodeContents(el);var s=getSelection();s.removeAllRanges();s.addRange(r);try{document.execCommand('copy');ok();}catch(e){}}};
</script></body></html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return cors(new Response(null, { status: 204 }));
    if (url.pathname === '/' && request.method === 'GET') {
      return new Response(HOME, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
    }
    if (!url.pathname.startsWith('/api/')) return cors(json({ error: 'not found' }, 404));
    const hub = env.HUB.get(env.HUB.idFromName('main'));
    return cors(await hub.fetch(request));
  }
};
