# Eco Points: secure backend

Node.js + SQLite API for the Eco Points app. One server gives you the database, login, photo/video storage and the reviewer area. Your website and a mobile app can both use the same API.

## Run it (3 commands)
Requires Node.js 18 or newer (https://nodejs.org).

    npm install
    npm run setup      # creates .env with fresh secret keys and a verifier invite code
    npm start          # http://localhost:3000

Check it works: open a second terminal and run `npm test`. It registers test users, uploads a photo, and confirms reviewers cannot see email or phone.

Your **verifier invite code** is the `VERIFIER_INVITE` line in `.env`. Give it only to real reviewers; without it nobody can register as one.

## What makes it secure
- **Passwords:** stored only as bcrypt hashes (cost 12). Min 8 chars with letters and numbers.
- **Personal data encrypted:** email, phone and roll number are stored with AES-256-GCM. Login finds accounts through a keyed hash of the email, never the plain address.
- **Reviewers cannot see personal details:** the reviewer endpoints read only the `reviewer_proofs` database view, which has no email, phone or roll number column (name and college only).
- **Sessions:** random token in an httpOnly, SameSite=Strict cookie (Secure in production). Only its hash is stored. Signed out after `IDLE_MINUTES` (default 15) of inactivity, and always after 12 hours. The client gets `expired: true` so your page can show the login screen.
- **Brute-force protection:** 20 auth attempts per 15 min per IP, and an account locks for 15 min after 5 wrong passwords.
- **Uploads:** JPG/PNG/WEBP/MP4/WEBM/MOV only, max 25 MB, file header checked (a renamed file is rejected), saved under random names outside the web folder, and served only to the owner or a verifier.
- **Points are decided by the server:** from the activity table, and only a verifier can approve. One proof per activity per day. Dates must be in the last 60 days.
- **Other:** helmet security headers, request size limit, CSRF header check, audit log of logins and review decisions (`audit_log` table), generic error messages.

## API (all JSON, send header `X-Requested-With: eco` on POST)
| Method and path | Who | Purpose |
|---|---|---|
| POST /api/auth/register | anyone | Create account (verifiers need `invite`) |
| POST /api/auth/login, /logout | | Sign in / out |
| GET /api/me | signed in | Your own profile |
| GET /api/activities | anyone | Activity list and points |
| POST /api/proofs | student | multipart: activity_id, event_date, location, description, media |
| GET /api/proofs/mine | student | Your submissions and their status |
| GET /api/proofs/:id/media | owner or verifier | The photo or video |
| GET /api/review/proofs?status= | verifier | Queue, without personal details |
| POST /api/review/proofs/:id/decision | verifier | `{approve:true}` or `{approve:false,reason}` |
| POST /api/review/proofs/:id/undo | verifier | Back to review |
| GET /api/leaderboard | signed in | Name, college, points |
| GET /api/challenges | signed in | Active EcoPoints challenges |
| POST /api/challenges/:id/join | student | Join an active challenge |
| GET /api/rewards | signed in | Available rewards |
| GET /api/rewards/mine | student | Own redemption history |
| POST /api/rewards/:id/redeem | student | Redeem a reward using approved points |

## Connecting your website
Put your site in `public/` (replace `index.html`); it is then served from the same address, which keeps cookies safe. Your page's code must call this API instead of `localStorage`, for example:

    await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'eco'},body:JSON.stringify({email,password})})

If any call returns `expired:true`, show the login page. For a mobile app, use the same endpoints (Capacitor or React Native work with this setup, but you will need HTTPS and a cookie or token approach suited to the app).

## HIVE integration and added operations
EcoPoints remains a separate module/database from HIVE's core school records. This version adds challenge participation, rewards, redemption history, and a points-ledger table for future auditable accounting. The existing public HTML file was intentionally not redesigned or modified. The new challenge/reward tables are ready for server-side management/seed data; this package does not yet include an admin UI for creating campaigns or managing reward inventory.

The current points balance is calculated from approved proof submissions minus pending/fulfilled redemptions. Reward redemption stock updates are transactional. For a public pilot, review concurrent redemption behaviour and add a single transaction that includes the balance check, redemption insert, stock decrement, and ledger entry before launch. The ledger schema is included but is not yet the source of truth for balances.

## Before real users
1. **Use HTTPS.** Host behind a provider that gives you a certificate, then set `NODE_ENV=production` (and `TRUST_PROXY=1` behind a proxy). Without HTTPS, passwords travel in the clear.
2. **Back up** the `storage/` folder (database and uploads) **and** `.env`. Losing the keys makes the encrypted data unreadable. Never commit `.env`.
3. SQLite suits a single server/prototype. For multi-instance deployment, move to managed PostgreSQL and use database-level access controls, encrypted backups, automated migrations, monitoring, and restore tests.
4. Have someone experienced review it before launch, especially if you hold students' personal data. Consider applicable data-protection rules and tell users how their data is used.
5. The app encrypts selected personal fields, but SQLite itself is not encrypted at rest by this code. Protect the disk/volume and backups; for hosted production, prefer managed PostgreSQL with encryption at rest and tightly scoped credentials.
6. Keep secrets outside source control, enforce HTTPS, configure trusted proxy settings correctly, and never share `.env` or production database files.
