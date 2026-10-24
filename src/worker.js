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
    if (url.pathname === '/api/share') {
      // crew share: small ETA snapshot, read by anyone who has the id
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
      if (request.method === 'GET') {
        const id = url.searchParams.get('id') || '';
        if (!/^[a-z0-9]{8,16}$/.test(id)) return json({ ok: false }, 400);
        const r = await env.DB.prepare('SELECT data FROM shares WHERE id = ?').bind(id).first();
        return r ? new Response(r.data, { headers: { 'Content-Type': 'application/json', ...CORS } }) : json({ ok: false }, 404);
      }
      if (request.method !== 'POST') return json({ ok: false }, 405);
      const body = await request.text();
      if (body.length > 20000) return json({ ok: false, error: 'size' }, 413);
      try { JSON.parse(body); } catch { return json({ ok: false, error: 'json' }, 400); }
      const id = [...crypto.getRandomValues(new Uint8Array(8))].map((x) => 'abcdefghjkmnpqrstuvwxyz23456789'[x % 31]).join('') + Date.now().toString(36).slice(-2);
      await env.DB.prepare('INSERT INTO shares (id, data) VALUES (?, ?)').bind(id, body).run();
      return json({ ok: true, id });
    }
    if (url.pathname === '/api/gear') {
      // gear affiliate links: public read, admin write
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
      if (request.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT id, url FROM gear_links').all();
        const links = {}; for (const r of results) links[r.id] = r.url;
        return new Response(JSON.stringify({ ok: true, links }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=120', ...CORS } });
      }
      if (request.method !== 'POST') return json({ ok: false }, 405);
      const row = await env.DB.prepare("SELECT v FROM config WHERE k = 'admin_sha256'").first();
      if (!row || (await sha(request.headers.get('X-Admin-Key') || '')) !== row.v) return json({ ok: false, error: 'auth' }, 401);
      let b; try { b = await request.json(); } catch { return json({ ok: false, error: 'json' }, 400); }
      const links = b && typeof b.links === 'object' ? b.links : {};
      const stmts = [];
      for (const [id, u] of Object.entries(links)) {
        if (!/^[a-z0-9_-]{2,30}$/.test(id)) continue;
        const v = typeof u === 'string' ? u.trim() : '';
        if (!v) stmts.push(env.DB.prepare('DELETE FROM gear_links WHERE id = ?').bind(id));
        else if (/^https:\/\/[^\s]{4,500}$/.test(v)) stmts.push(env.DB.prepare("INSERT INTO gear_links (id, url, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(id) DO UPDATE SET url = excluded.url, updated_at = excluded.updated_at").bind(id, v));
      }
      if (stmts.length) await env.DB.batch(stmts);
      return json({ ok: true, saved: stmts.length });
    }
    if (url.pathname === '/api/hit') {
      // anonymous page view: random browser id only, no IP or personal data
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
      if (request.method !== 'POST') return json({ ok: false }, 405);
      let b = {}; try { b = await request.json(); } catch {}
      const vid = typeof b.vid === 'string' && /^[a-z0-9]{6,32}$/i.test(b.vid) ? b.vid : null;
      await env.DB.prepare('INSERT INTO hits (vid, src) VALUES (?, ?)').bind(vid, clip(b.src, 10)).run();
      return json({ ok: true });
    }
    if (url.pathname === '/api/stats') {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
      const row = await env.DB.prepare("SELECT v FROM config WHERE k = 'admin_sha256'").first();
      if (!row || (await sha(request.headers.get('X-Admin-Key') || '')) !== row.v) return json({ ok: false, error: 'auth' }, 401);
      const hours = Math.min(168, Math.max(6, +url.searchParams.get('hours') || 48));
      const { results } = await env.DB.prepare(
        "SELECT strftime('%Y-%m-%d %H', ts, '+7 hours') AS hr, COUNT(*) AS views, COUNT(DISTINCT vid) AS users FROM hits WHERE ts >= datetime('now', ?) GROUP BY hr ORDER BY hr"
      ).bind(`-${hours} hours`).all();
      const tot = await env.DB.prepare(
        "SELECT (SELECT COUNT(DISTINCT vid) FROM hits WHERE date(ts, '+7 hours') = date('now', '+7 hours')) AS today, (SELECT COUNT(DISTINCT vid) FROM hits WHERE ts >= datetime('now', '-7 days')) AS week, (SELECT COUNT(DISTINCT vid) FROM hits) AS all_users, (SELECT COUNT(*) FROM hits) AS all_views"
      ).first();
      return json({ ok: true, hours, series: results, totals: tot });
    }
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
