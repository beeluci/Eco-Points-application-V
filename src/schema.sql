PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role TEXT NOT NULL CHECK(role IN('student','verifier')),
  name TEXT NOT NULL, college TEXT NOT NULL, designation TEXT,
  email_hash TEXT NOT NULL UNIQUE,   -- keyed hash, used only to find an account at login
  email_enc TEXT NOT NULL, phone_enc TEXT NOT NULL, roll_enc TEXT NOT NULL,  -- AES-256-GCM
  pw_hash TEXT NOT NULL,             -- bcrypt, never the password
  failed_count INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, ip TEXT);
CREATE TABLE IF NOT EXISTS activities(
  id INTEGER PRIMARY KEY, category TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL, points INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS proofs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id), activity_id INTEGER NOT NULL REFERENCES activities(id),
  event_date TEXT NOT NULL, location TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  media_file TEXT NOT NULL, media_type TEXT NOT NULL CHECK(media_type IN('image','video')), media_mime TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'review' CHECK(status IN('review','approved','rejected')),
  points INTEGER NOT NULL, reject_reason TEXT NOT NULL DEFAULT '',
  reviewed_by INTEGER REFERENCES users(id), reviewed_at INTEGER, created_at INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS one_proof_per_day ON proofs(user_id, activity_id, event_date) WHERE status!='rejected';
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, user_id INTEGER, action TEXT NOT NULL, detail TEXT, ip TEXT);
-- Reviewers only ever read this view: it has no email, phone or roll number columns.
DROP VIEW IF EXISTS reviewer_proofs;
CREATE VIEW reviewer_proofs AS
  SELECT p.id, u.name AS student_name, u.college, a.name AS activity, a.category, p.event_date, p.location,
         p.description, p.media_type, p.status, p.points, p.reject_reason, p.created_at
  FROM proofs p JOIN users u ON u.id=p.user_id JOIN activities a ON a.id=p.activity_id;
DROP VIEW IF EXISTS leaderboard;
CREATE VIEW leaderboard AS
  SELECT u.name, u.college, SUM(p.points) AS points, COUNT(*) AS activities
  FROM proofs p JOIN users u ON u.id=p.user_id WHERE p.status='approved' GROUP BY u.id ORDER BY points DESC;


-- HIVE/EcoPoints operational modules (separate from HIVE's core school records).
CREATE TABLE IF NOT EXISTS eco_challenges(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  starts_at INTEGER NOT NULL, ends_at INTEGER NOT NULL,
  points_bonus INTEGER NOT NULL DEFAULT 0 CHECK(points_bonus BETWEEN 0 AND 1000),
  status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN('draft','active','closed')),
  created_by INTEGER REFERENCES users(id), created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS challenge_participants(
  challenge_id INTEGER NOT NULL REFERENCES eco_challenges(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  joined_at INTEGER NOT NULL,
  PRIMARY KEY(challenge_id,user_id)
);
CREATE TABLE IF NOT EXISTS eco_rewards(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  points_cost INTEGER NOT NULL CHECK(points_cost > 0),
  stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN('active','paused','retired')),
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reward_redemptions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  reward_id INTEGER NOT NULL REFERENCES eco_rewards(id),
  points_spent INTEGER NOT NULL CHECK(points_spent > 0),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','fulfilled','cancelled')),
  created_at INTEGER NOT NULL, fulfilled_at INTEGER,
  fulfilled_by INTEGER REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS points_ledger(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  proof_id INTEGER REFERENCES proofs(id),
  redemption_id INTEGER REFERENCES reward_redemptions(id),
  delta INTEGER NOT NULL CHECK(delta != 0),
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  created_by INTEGER REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_proofs_user_created ON proofs(user_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_proofs_status_created ON proofs(status,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at DESC);
CREATE INDEX IF NOT EXISTS idx_redemptions_user ON reward_redemptions(user_id,created_at DESC);
