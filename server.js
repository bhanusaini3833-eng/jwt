// Single-file JWT Auth API — Express + SQLite (better-sqlite3)
import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';

// ====== Config ======
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

// ====== DB (file-based, no server needed) ======
const db = new Database('db.sqlite3');
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);
const insertUser = db.prepare(
  INSERT `INTO users (email, name, password_hash) VALUES (@email, @name, @password_hash)`
);
const getUserByEmail = db.prepare(`SELECT * FROM users WHERE email = ?`);
const getUserById = db.prepare(`SELECT id, email, name, created_at FROM users WHERE id = ?`);

// ====== App ======
const app = express();
app.use(helmet());
app.use(express.json());
app.use(morgan('dev'));

// Health
app.get('/', (_req, res) => {
  res.json({ ok: true, service: 'jwt-auth-min', version: '1.0.0' });
});

// ====== Auth helpers ======
function makeToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}
function authRequired(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing Bearer token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ====== Routes ======

// POST /api/auth/signup  {email, name?, password}
app.post('/api/auth/signup', (req, res) => {
  const { email, name = null, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  // basic email + password sanity
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'invalid email' });
  if (String(password).length < 6)
    return res.status(400).json({ error: 'password must be >= 6 chars' });

  const existing = getUserByEmail.get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'email already registered' });

  const password_hash = bcrypt.hashSync(password, 10);
  try {
    const info = insertUser.run({
      email: email.toLowerCase(),
      name,
      password_hash
    });
    const userId = info.lastInsertRowid;
    const token = makeToken({ sub: String(userId) });
    const user = getUserById.get(userId);
    return res.status(201).json({ token, user });
  } catch (e) {
    return res.status(500).json({ error: 'failed to create user' });
  }
});

// POST /api/auth/login   {email, password}
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  const user = getUserByEmail.get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'invalid credentials' });

  const ok = bcrypt.compareSync(String(password), user.password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });

  const token = makeToken({ sub: String(user.id) });
  const safeUser = getUserById.get(user.id);
  return res.json({ token, user: safeUser });
});

// GET /api/auth/me  (Bearer token)
app.get('/api/auth/me', authRequired, (req, res) => {
  const uid = Number(req.user.sub);
  const user = getUserById.get(uid);
  if (!user) return res.status(404).json({ error: 'user not found' });
  return res.json({ user });
});

// (Optional) protected sample
app.get('/api/protected/ping', authRequired, (_req, res) => {
  res.json({ ok: true, msg: 'pong (protected)' });
});

// ====== Start ======
app.listen(PORT, () => {
  console.log("JWT Auth API running on http://localhost:${PORT}");
});