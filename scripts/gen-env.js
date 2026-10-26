// Creates .env with fresh random secrets. Refuses to overwrite an existing one.
const fs = require('fs'), c = require('crypto');
if (fs.existsSync('.env')) { console.log('.env already exists, leaving it alone.'); process.exit(0); }
const r = n => c.randomBytes(n);
fs.writeFileSync('.env', [
  'PORT=3000', 'NODE_ENV=development', 'IDLE_MINUTES=15',
  'DATA_KEY=' + r(32).toString('hex'),
  'MAC_KEY=' + r(32).toString('hex'),
  'VERIFIER_INVITE=' + r(9).toString('base64url'),
  'TRUST_PROXY=0', ''
].join('\n'), { mode: 0o600 });
console.log('.env created. BACK IT UP: if DATA_KEY or MAC_KEY is lost, stored emails/phones cannot be read.');
