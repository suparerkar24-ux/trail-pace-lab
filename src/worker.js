// Trail Planner: static site + feedback API (Cloudflare D1)
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key',
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
const sha = async (t) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t)))].map((x) => x.toString(16).padStart(2, '0')).join('');
const clip = (v, n) => (typeof v === 'string' ? v.slice(0, n) : null);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/admin/key') {
      // change admin code: header X-Admin-Key = current code, body {newKey}
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
      if (request.method !== 'POST') return json({ ok: false, error: 'method' }, 405);
      const row = await env.DB.prepare("SELECT v FROM config WHERE k = 'admin_sha256'").first();
      const cur = await sha(request.headers.get('X-Admin-Key') || '');
      if (!row || cur !== row.v) return json({ ok: false, error: 'auth' }, 401);
      let b; try { b = await request.json(); } catch { return json({ ok: false, error: 'json' }, 400); }
      const nk = typeof b.newKey === 'string' ? b.newKey.trim() : '';
      if (nk.length < 6 || nk.length > 64) return json({ ok: false, error: 'length' }, 400);
      await env.DB.prepare("UPDATE config SET v = ? WHERE k = 'admin_sha256'").bind(await sha(nk)).run();
      return json({ ok: true });
    }
    if (url.pathname === '/api/feedback') {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
      if (request.method === 'GET') {
        // admin read: needs X-Admin-Key whose SHA-256 matches config.admin_sha256
        const key = request.headers.get('X-Admin-Key') || '';
        const row = await env.DB.prepare("SELECT v FROM config WHERE k = 'admin_sha256'").first();
        const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key)))]
          .map((x) => x.toString(16).padStart(2, '0')).join('');
        if (!row || !key || hash !== row.v) return json({ ok: false, error: 'auth' }, 401);
        const limit = Math.min(500, Math.max(1, +url.searchParams.get('limit') || 200));
        const { results } = await env.DB.prepare(
          'SELECT id, created_at, rating, message, course, km, lang, source FROM feedback ORDER BY id DESC LIMIT ?'
        ).bind(limit).all();
        const sum = await env.DB.prepare(
          'SELECT COUNT(*) AS total, SUM(rating = 1) AS up, SUM(rating = -1) AS down, SUM(message IS NOT NULL AND message <> \'\') AS msgs FROM feedback'
        ).first();
        return json({ ok: true, summary: sum, items: results });
      }
      if (request.method !== 'POST') return json({ ok: false, error: 'method' }, 405);
      let b;
      try { b = await request.json(); } catch { return json({ ok: false, error: 'json' }, 400); }
      const rating = b.rating === 1 || b.rating === -1 ? b.rating : null;
      const message = clip(b.message, 2000);
      if (rating === null && !(message && message.trim())) return json({ ok: false, error: 'empty' }, 400);
      const km = Number.isFinite(+b.km) ? Math.round(+b.km * 10) / 10 : null;
      await env.DB.prepare(
        'INSERT INTO feedback (rating, message, course, km, lang, source, ua, contact) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(rating, message, clip(b.course, 120), km, clip(b.lang, 8), clip(b.source, 20),
             clip(request.headers.get('User-Agent') || '', 200), clip(b.contact, 120)).run();
      return json({ ok: true });
    }
    return env.ASSETS.fetch(request);
  },
};
