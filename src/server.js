require('dotenv').config();
const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit'),
  multer = require('multer'), bcrypt = require('bcryptjs'), crypto = require('crypto'), path = require('path'), fs = require('fs');
const db = require('./db'), { enc, dec, blind } = require('./crypto');

const IDLE = (+process.env.IDLE_MINUTES || 15) * 60e3, ABSOLUTE = 12 * 3600e3, PROD = process.env.NODE_ENV === 'production';
const UP = path.join(__dirname, '..', 'storage', 'uploads'); fs.mkdirSync(UP, { recursive: true });
const DUMMY = bcrypt.hashSync('timing-equaliser', 12);
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const safeEq = (a, b) => { a = Buffer.from(a); b = Buffer.from(b); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const str = (v, max) => typeof v === 'string' && v.trim() && v.trim().length <= max ? v.trim() : null;
const audit = (uid, action, detail, ip) => db.prepare('INSERT INTO audit_log(at,user_id,action,detail,ip) VALUES(?,?,?,?,?)').run(Date.now(), uid || null, action, detail || '', ip || '');
const ah = fn => (q, s, n) => Promise.resolve(fn(q, s, n)).catch(n);
const cookies = q => Object.fromEntries((q.headers.cookie || '').split(';').map(x => x.trim().split('=')).filter(a => a[0]).map(a => [a[0], decodeURIComponent(a[1] || '')]));

const app = express();
app.disable('x-powered-by'); app.set('trust proxy', +process.env.TRUST_PROXY || 0);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
  fontSrc: ['https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:', 'blob:'], mediaSrc: ["'self'", 'blob:'], frameAncestors: ["'none'"] } } }));
app.use('/api', rateLimit({ windowMs: 15 * 60e3, limit: 600, standardHeaders: true, legacyHeaders: false }));
const authLimit = rateLimit({ windowMs: 15 * 60e3, limit: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again later.' } });
app.use(express.json({ limit: '20kb' }));
// CSRF defence: cookies are SameSite=Strict, and every write must also carry this header (browsers will not add it cross-site).
app.use('/api', (q, s, n) => ['GET', 'HEAD'].includes(q.method) || q.get('x-requested-with') === 'eco' ? n() : s.status(403).json({ error: 'Bad request' }));

// ---- Sessions: random token in an httpOnly cookie, only its hash is stored; idle + absolute expiry ----
function startSession(res, uid, ip) {
  const t = crypto.randomBytes(32).toString('hex'), n = Date.now();
  db.prepare('INSERT INTO sessions VALUES(?,?,?,?,?)').run(sha(t), uid, n, n, ip);
  res.cookie('sid', t, { httpOnly: true, sameSite: 'strict', secure: PROD, path: '/' });
}
function auth(q, s, next) {
  const t = cookies(q).sid; if (!t) return s.status(401).json({ error: 'Not signed in' });
  const r = db.prepare('SELECT s.token_hash,s.user_id,s.created_at,s.last_seen,u.role,u.name,u.college FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?').get(sha(t)), n = Date.now();
  if (!r || n - r.last_seen > IDLE || n - r.created_at > ABSOLUTE) {
    if (r) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(r.token_hash);
    s.clearCookie('sid'); return s.status(401).json({ error: 'Session expired. Please sign in again.', expired: true });
  }
  db.prepare('UPDATE sessions SET last_seen=? WHERE token_hash=?').run(n, r.token_hash);
  q.user = { id: r.user_id, role: r.role, name: r.name, college: r.college }; next();
}
const only = role => (q, s, n) => q.user.role === role ? n() : s.status(403).json({ error: 'Not allowed' });
setInterval(() => db.prepare('DELETE FROM sessions WHERE last_seen<? OR created_at<?').run(Date.now() - IDLE, Date.now() - ABSOLUTE), 3600e3).unref();

// ---- Accounts ----
app.post('/api/auth/register', authLimit, ah(async (q, s) => {
  const b = q.body || {}, role = b.role === 'verifier' ? 'verifier' : 'student';
  const name = str(b.name, 80), college = str(b.college, 120), roll = str(b.roll_no, 40), phone = str(b.phone, 20),
    email = (str(b.email, 120) || '').toLowerCase(), pw = typeof b.password === 'string' ? b.password : '';
  if (!name || !college || !roll || !phone || (role === 'verifier' && !str(b.designation, 80))) return s.status(400).json({ error: 'Please fill every field.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return s.status(400).json({ error: 'Enter a valid email address.' });
  if (!/^\+?[0-9 ()-]{7,20}$/.test(phone)) return s.status(400).json({ error: 'Enter a valid phone number.' });
  if (pw.length < 8 || pw.length > 72 || !/[A-Za-z]/.test(pw) || !/[0-9]/.test(pw)) return s.status(400).json({ error: 'Password needs 8 to 72 characters with letters and numbers.' });
  if (role === 'verifier' && !(process.env.VERIFIER_INVITE && safeEq(String(b.invite || ''), process.env.VERIFIER_INVITE))) { audit(null, 'verifier_invite_rejected', '', q.ip); return s.status(403).json({ error: 'A valid verifier invite code is required.' }); }
  const h = blind(email);
  if (db.prepare('SELECT 1 FROM users WHERE email_hash=?').get(h)) return s.status(409).json({ error: 'Could not register with these details. If you already have an account, sign in.' });
  const r = db.prepare('INSERT INTO users(role,name,college,designation,email_hash,email_enc,phone_enc,roll_enc,pw_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
    .run(role, name, college, role === 'verifier' ? str(b.designation, 80) : null, h, enc(email), enc(phone), enc(roll), await bcrypt.hash(pw, 12), Date.now());
  audit(r.lastInsertRowid, 'register', role, q.ip); startSession(s, r.lastInsertRowid, q.ip);
  s.status(201).json({ id: r.lastInsertRowid, name, college, role });
}));
app.post('/api/auth/login', authLimit, ah(async (q, s) => {
  const b = q.body || {}, u = db.prepare('SELECT * FROM users WHERE email_hash=?').get(blind(typeof b.email === 'string' ? b.email : '')), n = Date.now();
  if (u && u.locked_until > n) return s.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
  const ok = await bcrypt.compare(typeof b.password === 'string' ? b.password : '', u ? u.pw_hash : DUMMY);
  if (!u || !ok) {
    if (u) { const f = u.failed_count + 1; db.prepare('UPDATE users SET failed_count=?,locked_until=? WHERE id=?').run(f >= 5 ? 0 : f, f >= 5 ? n + 15 * 60e3 : 0, u.id); }
    audit(u && u.id, 'login_failed', '', q.ip); return s.status(401).json({ error: 'Email or password is incorrect.' });
  }
  db.prepare('UPDATE users SET failed_count=0,locked_until=0 WHERE id=?').run(u.id);
  audit(u.id, 'login', '', q.ip); startSession(s, u.id, q.ip);
  s.json({ id: u.id, name: u.name, college: u.college, role: u.role });
}));
app.post('/api/auth/logout', auth, (q, s) => { db.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash=?').run(q.user.id, sha(cookies(q).sid)); s.clearCookie('sid'); s.json({ ok: true }); });
app.get('/api/me', auth, (q, s) => { // a person can read only their own contact details
  const u = db.prepare('SELECT email_enc,phone_enc,roll_enc,designation FROM users WHERE id=?').get(q.user.id);
  s.json({ ...q.user, designation: u.designation, email: dec(u.email_enc), phone: dec(u.phone_enc), roll_no: dec(u.roll_enc) });
});
app.get('/api/activities', (q, s) => s.json(db.prepare('SELECT * FROM activities').all()));

// ---- Proof uploads (photo / video) ----
const upl = multer({ storage: multer.diskStorage({ destination: UP, filename: (q, f, cb) => cb(null, crypto.randomBytes(16).toString('hex')) }),
  limits: { fileSize: 25 * 1048576, files: 1 },
  fileFilter: (q, f, cb) => /^(image\/(jpeg|png|webp)|video\/(mp4|webm|quicktime))$/.test(f.mimetype) ? cb(null, true) : cb(new Error('Only JPG, PNG, WEBP, MP4, WEBM or MOV files are allowed.')) });
function sniff(p) { // trust the file's real header, not the name or declared type
  const b = Buffer.alloc(16), fd = fs.openSync(p, 'r'); fs.readSync(fd, b, 0, 16, 0); fs.closeSync(fd); const h = b.toString('hex');
  if (h.startsWith('ffd8ff') || h.startsWith('89504e47') || (b.toString('latin1', 0, 4) === 'RIFF' && b.toString('latin1', 8, 12) === 'WEBP')) return 'image';
  if (b.toString('latin1', 4, 8) === 'ftyp' || h.startsWith('1a45dfa3')) return 'video'; return null;
}
app.post('/api/proofs', auth, only('student'), upl.single('media'), (q, s) => {
  const f = q.file, bad = m => { if (f) fs.unlink(f.path, () => {}); return s.status(400).json({ error: m }); };
  if (!f) return bad('Attach a photo or video.');
  const kind = sniff(f.path); if (!kind || !f.mimetype.startsWith(kind + '/')) return bad('That file is not a valid photo or video.');
  const b = q.body, act = db.prepare('SELECT * FROM activities WHERE id=?').get(+b.activity_id); if (!act) return bad('Choose an activity.');
  const d = String(b.event_date || ''), max = new Date(Date.now() + 864e5).toISOString().slice(0, 10), min = new Date(Date.now() - 60 * 864e5).toISOString().slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d) || d > max || d < min) return bad('Date must be within the last 60 days and not in the future.');
  const loc = str(b.location, 120); if (!loc) return bad('Enter the location.');
  try {
    const r = db.prepare('INSERT INTO proofs(user_id,activity_id,event_date,location,description,media_file,media_type,media_mime,points,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
      .run(q.user.id, act.id, d, loc, typeof b.description === 'string' ? b.description.slice(0, 500) : '', f.filename, kind, f.mimetype, act.points, Date.now());
    s.status(201).json({ id: r.lastInsertRowid, status: 'review' });
  } catch (e) { fs.unlink(f.path, () => {}); if (String(e.code).startsWith('SQLITE_CONSTRAINT')) return s.status(409).json({ error: 'You already submitted this activity for that date.' }); throw e; }
});
app.get('/api/proofs/mine', auth, only('student'), (q, s) => s.json(db.prepare(
  'SELECT p.id,a.name AS activity,p.event_date,p.location,p.description,p.media_type,p.status,p.points,p.reject_reason,p.created_at FROM proofs p JOIN activities a ON a.id=p.activity_id WHERE p.user_id=? ORDER BY p.created_at DESC').all(q.user.id)));
app.get('/api/proofs/:id/media', auth, (q, s) => { // owner or a verifier only
  const p = db.prepare('SELECT user_id,media_file,media_mime FROM proofs WHERE id=?').get(+q.params.id);
  if (!p || (q.user.role !== 'verifier' && p.user_id !== q.user.id)) return s.status(404).json({ error: 'Not found' });
  s.sendFile(p.media_file, { root: UP, headers: { 'Content-Type': p.media_mime, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'private, no-store' } });
});

// ---- Reviewer area: reads only the PII-free view ----
app.get('/api/review/proofs', auth, only('verifier'), (q, s) => {
  const st = ['review', 'approved', 'rejected'].includes(q.query.status) ? q.query.status : null;
  const base = 'SELECT * FROM reviewer_proofs ';
  s.json(st ? db.prepare(base + 'WHERE status=? ORDER BY created_at DESC LIMIT 200').all(st) : db.prepare(base + 'ORDER BY created_at DESC LIMIT 200').all());
});
app.post('/api/review/proofs/:id/decision', auth, only('verifier'), (q, s) => {
  const ok = q.body && q.body.approve === true, reason = ok ? '' : String((q.body && q.body.reason) || '').slice(0, 300);
  const r = db.prepare("UPDATE proofs SET status=?,reject_reason=?,reviewed_by=?,reviewed_at=? WHERE id=? AND status='review'").run(ok ? 'approved' : 'rejected', reason, q.user.id, Date.now(), +q.params.id);
  if (!r.changes) return s.status(409).json({ error: 'This proof was already reviewed.' });
  audit(q.user.id, ok ? 'approve' : 'reject', 'proof ' + q.params.id, q.ip); s.json({ ok: true });
});
app.post('/api/review/proofs/:id/undo', auth, only('verifier'), (q, s) => {
  const r = db.prepare("UPDATE proofs SET status='review',reject_reason='',reviewed_by=NULL,reviewed_at=NULL WHERE id=? AND status!='review'").run(+q.params.id);
  if (!r.changes) return s.status(409).json({ error: 'Nothing to undo.' }); audit(q.user.id, 'undo', 'proof ' + q.params.id, q.ip); s.json({ ok: true });
});
app.get('/api/leaderboard', auth, (q, s) => s.json(db.prepare('SELECT * FROM leaderboard LIMIT 50').all()));


// ---- EcoPoints extension endpoints ----
// Challenges and rewards are separate from HIVE's core student records.
app.get('/api/challenges', auth, (q, s) => {
  const now = Date.now();
  s.json(db.prepare("SELECT id,title,description,starts_at,ends_at,points_bonus,status FROM eco_challenges WHERE status='active' AND starts_at<=? AND ends_at>=? ORDER BY ends_at").all(now, now));
});
app.post('/api/challenges/:id/join', auth, only('student'), (q, s) => {
  const now = Date.now(), id = Number(q.params.id);
  const c = db.prepare("SELECT id FROM eco_challenges WHERE id=? AND status='active' AND starts_at<=? AND ends_at>=?").get(id, now, now);
  if (!c) return s.status(404).json({ error: 'Challenge not available.' });
  try {
    db.prepare('INSERT INTO challenge_participants(challenge_id,user_id,joined_at) VALUES(?,?,?)').run(id,q.user.id,now);
    audit(q.user.id,'challenge_join',String(id),q.ip); return s.status(201).json({ok:true});
  } catch (e) { if (String(e.code).startsWith('SQLITE_CONSTRAINT')) return s.status(409).json({error:'Already joined this challenge.'}); throw e; }
});
app.get('/api/rewards', auth, (q, s) => s.json(db.prepare("SELECT id,title,description,points_cost,stock FROM eco_rewards WHERE status='active' AND stock>0 ORDER BY points_cost").all()));
app.get('/api/rewards/mine', auth, only('student'), (q, s) => s.json(db.prepare("SELECT r.id,r.points_spent,r.status,r.created_at,r.fulfilled_at,e.title AS reward FROM reward_redemptions r JOIN eco_rewards e ON e.id=r.reward_id WHERE r.user_id=? ORDER BY r.created_at DESC LIMIT 100").all(q.user.id)));
app.post('/api/rewards/:id/redeem', auth, only('student'), (q, s) => {
  const id = Number(q.params.id), now = Date.now();
  const reward = db.prepare("SELECT * FROM eco_rewards WHERE id=? AND status='active' AND stock>0").get(id);
  if (!reward) return s.status(404).json({error:'Reward unavailable.'});
  const earned = db.prepare("SELECT COALESCE(SUM(points),0) AS n FROM proofs WHERE user_id=? AND status='approved'").get(q.user.id).n;
  const spent = db.prepare("SELECT COALESCE(SUM(points_spent),0) AS n FROM reward_redemptions WHERE user_id=? AND status IN('pending','fulfilled')").get(q.user.id).n;
  if (earned-spent < reward.points_cost) return s.status(400).json({error:'Not enough available points.'});
  const redeem = db.transaction(() => {
    const current = db.prepare("SELECT stock,status FROM eco_rewards WHERE id=?").get(id);
    if (!current || current.status!=='active' || current.stock<1) throw new Error('OUT_OF_STOCK');
    db.prepare('UPDATE eco_rewards SET stock=stock-1 WHERE id=?').run(id);
    const r = db.prepare("INSERT INTO reward_redemptions(user_id,reward_id,points_spent,status,created_at) VALUES(?,?,?,'pending',?)").run(q.user.id,id,reward.points_cost,now);
    audit(q.user.id,'reward_redeem',String(r.lastInsertRowid),q.ip);
    return r.lastInsertRowid;
  });
  try { s.status(201).json({ok:true,redemption_id:redeem()}); }
  catch(e) { if (e.message==='OUT_OF_STOCK') return s.status(409).json({error:'Reward just ran out of stock.'}); throw e; }
});

app.use('/api', (q, s) => s.status(404).json({ error: 'Not found' }));
app.use(express.static(path.join(__dirname, '..', 'public'), { dotfiles: 'ignore' }));
app.use((e, q, s, n) => {
  if (e instanceof multer.MulterError) return s.status(400).json({ error: e.code === 'LIMIT_FILE_SIZE' ? 'File is too large (max 25 MB).' : 'Upload failed.' });
  if (e && String(e.message).startsWith('Only ')) return s.status(400).json({ error: e.message });
  console.error(e); s.status(500).json({ error: 'Server error' });
});
const port = +process.env.PORT || 3000;
app.listen(port, () => console.log(`Eco Points server running at http://localhost:${port}`));
