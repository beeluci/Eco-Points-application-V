const Database = require('better-sqlite3'), fs = require('fs'), path = require('path');
const dir = path.join(__dirname, '..', 'storage'); fs.mkdirSync(dir, { recursive: true });
const db = new Database(path.join(dir, 'ecopoints.db'));
db.pragma('journal_mode = WAL'); db.pragma('foreign_keys = ON');
db.exec(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
if (!db.prepare('SELECT COUNT(*) n FROM activities').get().n) {
  const ins = db.prepare('INSERT INTO activities VALUES(@id,@category,@name,@description,@points)');
  db.transaction(a => a.forEach(x => ins.run(x)))(require('./activities.json'));
}
module.exports = db;
