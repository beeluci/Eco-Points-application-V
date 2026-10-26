const c = require('crypto');
const KEY = Buffer.from(process.env.DATA_KEY || '', 'hex'), MAC = Buffer.from(process.env.MAC_KEY || '', 'hex');
if (KEY.length !== 32 || MAC.length !== 32) { console.error('Missing DATA_KEY / MAC_KEY. Run: npm run setup'); process.exit(1); }
exports.enc = t => { const iv = c.randomBytes(12), k = c.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([k.update(String(t), 'utf8'), k.final()]);
  return [iv, k.getAuthTag(), ct].map(b => b.toString('base64')).join('.'); };
exports.dec = s => { const [iv, tag, ct] = s.split('.').map(x => Buffer.from(x, 'base64'));
  const d = c.createDecipheriv('aes-256-gcm', KEY, iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8'); };
exports.blind = e => c.createHmac('sha256', MAC).update(String(e).trim().toLowerCase()).digest('hex');
