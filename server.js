require('dotenv').config();
const express = require('express'), helmet = require('helmet'), session = require('express-session');
const bcrypt = require('bcryptjs'), rateLimit = require('express-rate-limit'), multer = require('multer');
const Database = require('better-sqlite3'), path = require('path'), fs = require('fs'), crypto = require('crypto');

const PROD = process.env.NODE_ENV === 'production';
const SECRET = process.env.SESSION_SECRET;
if (!SECRET || SECRET.length < 32) { console.error('Set SESSION_SECRET (32+ chars).'); process.exit(1); }
const DATA = path.resolve(process.env.DATA_DIR || './data');
const UP = path.join(DATA, 'uploads');
fs.mkdirSync(UP, { recursive: true });

const db = new Database(path.join(DATA, 'kishora.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS admin(id INTEGER PRIMARY KEY CHECK(id=1), email TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT DEFAULT '', features TEXT DEFAULT '',
  category TEXT DEFAULT '', price TEXT DEFAULT '', image TEXT DEFAULT '', amazon_url TEXT DEFAULT '', flipkart_url TEXT DEFAULT '',
  published INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(sid TEXT PRIMARY KEY, data TEXT, exp INTEGER);`);

// One-time owner bootstrap from environment. No signup route exists.
if (!db.prepare('SELECT 1 FROM admin').get()) {
  const e = (process.env.OWNER_EMAIL || '').trim().toLowerCase(), p = process.env.OWNER_PASSWORD || '';
  if (e && p.length >= 12) {
    db.prepare('INSERT INTO admin(id,email,hash) VALUES(1,?,?)').run(e, bcrypt.hashSync(p, 12));
    console.log('Owner account created. Now remove OWNER_PASSWORD from your environment.');
  } else console.warn('No owner yet: set OWNER_EMAIL and OWNER_PASSWORD (12+ chars) and restart.');
}
const DUMMY = bcrypt.hashSync('x'.repeat(16), 12);

const MS = 1000 * 60 * 60 * 8;
class Store extends session.Store {
  get(sid, cb) { const r = db.prepare('SELECT data,exp FROM sessions WHERE sid=?').get(sid); cb(null, r && r.exp > Date.now() ? JSON.parse(r.data) : null); }
  set(sid, s, cb) { db.prepare('REPLACE INTO sessions VALUES(?,?,?)').run(sid, JSON.stringify(s), Date.now() + MS); cb && cb(); }
  destroy(sid, cb) { db.prepare('DELETE FROM sessions WHERE sid=?').run(sid); cb && cb(); }
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '20kb' }));
app.use(session({ name: 'kishora.sid', secret: SECRET, store: new Store(), resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: PROD, maxAge: MS } }));

// ---------- helpers ----------
const isAdmin = req => req.session && req.session.admin === true;
const requireAdmin = (req, res, next) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Not authorised' });
  if (req.method !== 'GET' && req.get('X-Requested-With') !== 'kishora') return res.status(403).json({ error: 'Bad request' });
  next();
};
const HOSTS = { amazon: /(^|\.)(amazon\.(in|com)|amzn\.(to|in)|a\.co)$/i, flipkart: /(^|\.)(flipkart\.com|fkrt\.(it|cc))$/i };
function cleanUrl(v, kind) {
  v = (v || '').trim(); if (!v) return '';
  let u; try { u = new URL(v); } catch { throw new Error(`${kind} URL is not valid`); }
  if (u.protocol !== 'https:' || !HOSTS[kind].test(u.hostname)) throw new Error(`${kind} URL must be an https ${kind} link`);
  return u.toString();
}
const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
function parse(b) {
  const name = str(b.name, 120); if (!name) throw new Error('Product name is required');
  return { name, description: str(b.description, 2000), features: str(b.features, 2000), category: str(b.category, 50),
    price: str(b.price, 30), amazon_url: cleanUrl(b.amazon_url, 'amazon'), flipkart_url: cleanUrl(b.flipkart_url, 'flipkart') };
}
function sniff(buf) {
  if (buf.length < 12) return null;
  if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return 'jpg';
  if (buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) return 'png';
  if (buf.slice(0, 4).toString() === 'RIFF' && buf.slice(8, 12).toString() === 'WEBP') return 'webp';
  return null;
}
function saveImage(file) {
  const ext = sniff(file.buffer); if (!ext) throw new Error('Image must be a real JPG, PNG or WebP file');
  const name = crypto.randomBytes(16).toString('hex') + '.' + ext;
  fs.writeFileSync(path.join(UP, name), file.buffer, { flag: 'wx' });
  return name;
}
const rmImage = n => { if (n && /^[a-f0-9]{32}\.(jpg|png|webp)$/.test(n)) fs.rm(path.join(UP, n), { force: true }, () => {}); };
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 1, fields: 12 } });
const pub = p => ({ id: p.id, name: p.name, description: p.description, features: p.features, category: p.category, price: p.price,
  image: p.image ? '/img/' + p.image : '', amazon_url: p.amazon_url, flipkart_url: p.flipkart_url });
const full = p => ({ ...pub(p), published: !!p.published, updated_at: p.updated_at });
const wrap = fn => (req, res) => { try { fn(req, res); } catch (e) { res.status(400).json({ error: e.message }); } };
const withUpload = (req, res, next) => upload.single('image')(req, res, e => e ? res.status(400).json({ error: e.code === 'LIMIT_FILE_SIZE' ? 'Image must be under 5 MB' : 'Upload failed' }) : next());

// ---------- public ----------
app.get('/api/products', (req, res) => res.json(db.prepare('SELECT * FROM products WHERE published=1 ORDER BY id DESC').all().map(pub)));
app.get('/img/:f', (req, res) => {           // drafts' images are only served to the owner
  const f = req.params.f; if (!/^[a-f0-9]{32}\.(jpg|png|webp)$/.test(f)) return res.sendStatus(404);
  const p = db.prepare('SELECT published FROM products WHERE image=?').get(f);
  if (!p || (!p.published && !isAdmin(req))) return res.sendStatus(404);
  res.set('Cache-Control', p.published ? 'public, max-age=86400' : 'private, no-store');
  res.sendFile(path.join(UP, f));
});

// ---------- auth ----------
const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again later.' } });
app.post('/api/admin/login', loginLimit, (req, res) => {
  const a = db.prepare('SELECT * FROM admin WHERE id=1').get();
  const email = str(req.body.email, 200).toLowerCase(), pw = str(req.body.password, 200);
  const ok = bcrypt.compareSync(pw, a ? a.hash : DUMMY) && a && a.email === email;
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
  req.session.regenerate(() => { req.session.admin = true; res.json({ ok: true }); });
});
app.post('/api/admin/logout', requireAdmin, (req, res) => req.session.destroy(() => { res.clearCookie('kishora.sid'); res.json({ ok: true }); }));
app.get('/api/admin/me', (req, res) => res.json({ admin: isAdmin(req) }));

// ---------- admin products ----------
app.get('/api/admin/products', requireAdmin, (req, res) => res.json(db.prepare('SELECT * FROM products ORDER BY id DESC').all().map(full)));

app.post('/api/admin/products', requireAdmin, withUpload, wrap((req, res) => {
  const d = parse(req.body), publish = req.body.status === 'publish';
  if (publish && !req.file) throw new Error('Upload an image before publishing');
  if (publish && !d.amazon_url && !d.flipkart_url) throw new Error('Add at least one affiliate URL before publishing');
  const img = req.file ? saveImage(req.file) : '';
  const r = db.prepare('INSERT INTO products(name,description,features,category,price,image,amazon_url,flipkart_url,published) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(d.name, d.description, d.features, d.category, d.price, img, d.amazon_url, d.flipkart_url, publish ? 1 : 0);
  res.json(full(db.prepare('SELECT * FROM products WHERE id=?').get(r.lastInsertRowid)));
}));

app.put('/api/admin/products/:id', requireAdmin, withUpload, wrap((req, res) => {
  const cur = db.prepare('SELECT * FROM products WHERE id=?').get(+req.params.id); if (!cur) return res.status(404).json({ error: 'Not found' });
  const d = parse(req.body), img = req.file ? saveImage(req.file) : cur.image;
  const publish = req.body.status ? req.body.status === 'publish' : !!cur.published;
  if (publish && !img) { if (req.file) rmImage(img); throw new Error('Upload an image before publishing'); }
  if (publish && !d.amazon_url && !d.flipkart_url) { if (req.file) rmImage(img); throw new Error('Add at least one affiliate URL before publishing'); }
  db.prepare('UPDATE products SET name=?,description=?,features=?,category=?,price=?,image=?,amazon_url=?,flipkart_url=?,published=?,updated_at=CURRENT_TIMESTAMP WHERE id=?')
    .run(d.name, d.description, d.features, d.category, d.price, img, d.amazon_url, d.flipkart_url, publish ? 1 : 0, cur.id);
  if (req.file) rmImage(cur.image);
  res.json(full(db.prepare('SELECT * FROM products WHERE id=?').get(cur.id)));
}));

app.post('/api/admin/products/:id/publish', requireAdmin, wrap((req, res) => {
  const cur = db.prepare('SELECT * FROM products WHERE id=?').get(+req.params.id); if (!cur) return res.status(404).json({ error: 'Not found' });
  const on = req.body.published === true;
  if (on && (!cur.image || (!cur.amazon_url && !cur.flipkart_url))) throw new Error('Needs an image and an affiliate URL to publish');
  db.prepare('UPDATE products SET published=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(on ? 1 : 0, cur.id);
  res.json({ ok: true, published: on });
}));

app.delete('/api/admin/products/:id', requireAdmin, (req, res) => {
  const cur = db.prepare('SELECT image FROM products WHERE id=?').get(+req.params.id); if (!cur) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM products WHERE id=?').run(+req.params.id); rmImage(cur.image); res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('/admin', (q, r) => r.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.listen(process.env.PORT || 3000, () => console.log('KISHORA running'));
