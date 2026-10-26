// End-to-end check against a running server:  npm start   (one terminal)   npm test   (another)
require('dotenv').config();
const B = process.env.BASE || `http://localhost:${process.env.PORT || 3000}`, jar = {}; let bad = 0;
async function call(who, method, url, body, form) {
  const h = { 'X-Requested-With': 'eco' }; if (jar[who]) h.Cookie = jar[who]; let b = form;
  if (body) { h['Content-Type'] = 'application/json'; b = JSON.stringify(body); }
  const r = await fetch(B + url, { method, headers: h, body: b }), sc = r.headers.getSetCookie && r.headers.getSetCookie()[0];
  if (sc) jar[who] = sc.split(';')[0]; const j = (r.headers.get('content-type') || '').includes('json');
  return { status: r.status, data: j ? await r.json() : null, raw: j ? null : r };
}
const check = (name, ok) => { console.log((ok ? 'PASS ' : 'FAIL ') + name); if (!ok) bad++; };
(async () => {
  const id = Date.now(), mk = (role, extra) => ({ name: role + ' Test', college: 'Test College', roll_no: 'R' + id, phone: '9876543210', email: `${role}${id}@example.com`, password: 'Passw0rdTest', role, ...extra });
  check('student registers', (await call('s', 'POST', '/api/auth/register', mk('student'))).status === 201);
  check('verifier blocked without invite', (await call('x', 'POST', '/api/auth/register', mk('verifier', { designation: 'Prof' }))).status === 403);
  check('verifier registers with invite', (await call('v', 'POST', '/api/auth/register', mk('verifier', { designation: 'Prof', invite: process.env.VERIFIER_INVITE }))).status === 201);
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
  const f = new FormData(); f.append('activity_id', '1'); f.append('event_date', new Date().toISOString().slice(0, 10)); f.append('location', 'Campus'); f.append('description', 'test');
  f.append('media', new Blob([png], { type: 'image/png' }), 'a.png');
  const up = await call('s', 'POST', '/api/proofs', null, f); check('student uploads a photo', up.status === 201);
  check('fake file is rejected', (await (async () => { const g = new FormData(); g.append('activity_id', '1'); g.append('event_date', new Date().toISOString().slice(0, 10)); g.append('location', 'x'); g.append('media', new Blob(['not an image'], { type: 'image/png' }), 'b.png'); return call('s', 'POST', '/api/proofs', null, g); })()).status === 400);
  const list = await call('v', 'GET', '/api/review/proofs?status=review');
  check('reviewer sees the proof', list.status === 200 && list.data.length >= 1);
  check('reviewer data has NO email/phone/roll', !/email|phone|roll|@example\.com|9876543210/i.test(JSON.stringify(list.data)));
  const m = await call('v', 'GET', `/api/proofs/${up.data.id}/media`); check('reviewer can load the photo', m.status === 200);
  check('student cannot use reviewer area', (await call('s', 'GET', '/api/review/proofs')).status === 403);
  check('approval works', (await call('v', 'POST', `/api/review/proofs/${up.data.id}/decision`, { approve: true })).status === 200);
  check('no cookie, no access', (await call('nobody', 'GET', '/api/me')).status === 401);
  console.log(bad ? `\n${bad} check(s) failed` : '\nAll checks passed'); process.exit(bad ? 1 : 0);
})().catch(e => { console.error('Could not reach the server. Is it running? ', e.message); process.exit(1); });
