// Trail Planner: static site + feedback API (Cloudflare D1)
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
const clip = (v, n) => (typeof v === 'string' ? v.slice(0, n) : null);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/feedback') {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
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
