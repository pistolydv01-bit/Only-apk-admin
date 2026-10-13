require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '32kb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 60 }));
app.get('/health', (_req, res) => res.json({ ok: true }));

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  mobile: { type: String, required: true, trim: true, maxlength: 20 },
  email: { type: String, trim: true, lowercase: true, maxlength: 254, default: '' },
  username: { type: String, required: true, unique: true, lowercase: true, trim: true, minlength: 3, maxlength: 32 },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  status: { type: String, enum: ['pending', 'active', 'blocked'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);
const configSchema = new mongoose.Schema({ key: { type: String, unique: true }, value: String });
const Config = mongoose.model('Config', configSchema);

function publicUser(u) {
  return { id: String(u._id), name: u.name, mobile: u.mobile, email: u.email,
    username: u.username, role: u.role, status: u.status, createdAt: u.createdAt };
}
function sign(u) {
  return jwt.sign({ sub: String(u._id), role: u.role }, process.env.JWT_SECRET, { expiresIn: '12h' });
}
async function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : '';
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.sub);
    if (!user || user.status === 'blocked') return res.status(401).json({ error: 'Account unavailable' });
    req.user = user; next();
  } catch { return res.status(401).json({ error: 'Please log in again' }); }
}
function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, mobile, email = '', username, password } = req.body || {};
    if (!name?.trim() || !mobile?.trim() || !/^[a-zA-Z0-9_.-]{3,32}$/.test(username || '') || typeof password !== 'string' || password.length < 10 || password.length > 128)
      return res.status(400).json({ error: 'Enter valid name, mobile, username and a 10–128 character password' });
    const uname = username.toLowerCase();
    if (await User.exists({ username: uname })) return res.status(409).json({ error: 'Username already exists' });
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ name: name.trim(), mobile: mobile.trim(), email, username: uname, passwordHash, status: 'pending' });
    res.status(201).json({ message: 'Registration submitted; wait for admin approval', user: publicUser(user) });
  } catch (e) { res.status(500).json({ error: 'Registration failed' }); }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const user = await User.findOne({ username: String(username || '').toLowerCase() });
    if (!user || !(await bcrypt.compare(String(password || ''), user.passwordHash))) return res.status(401).json({ error: 'Invalid username or password' });
    if (user.status === 'blocked') return res.status(403).json({ error: 'Account blocked; contact admin' });
    if (user.role !== 'admin' && user.status !== 'active') return res.status(403).json({ error: 'Account pending approval' });
    res.json({ token: sign(user), user: publicUser(user) });
  } catch { res.status(500).json({ error: 'Login failed' }); }
});
app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));
app.get('/api/config', async (_req, res) => {
  const rows = await Config.find({ key: { $in: ['broadcast', 'maintenance'] } });
  const out = Object.fromEntries(rows.map(x => [x.key, x.value]));
  res.json({ broadcast: out.broadcast || '', maintenance: out.maintenance === 'true' });
});
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const users = await User.find({ role: 'user' }).sort({ createdAt: -1 }).limit(2000);
  res.json({ users: users.map(publicUser) });
});
app.patch('/api/admin/users/:id/status', auth, adminOnly, async (req, res) => {
  const { status } = req.body || {};
  if (!['pending', 'active', 'blocked'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  const user = await User.findOneAndUpdate({ _id: req.params.id, role: 'user' }, { status }, { new: true });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: publicUser(user) });
});
app.post('/api/admin/broadcast', auth, adminOnly, async (req, res) => {
  const message = String(req.body?.message || '').slice(0, 1000);
  await Config.findOneAndUpdate({ key: 'broadcast' }, { value: message }, { upsert: true, new: true });
  res.json({ ok: true, message: 'Broadcast saved' });
});

async function start() {
  if (!process.env.MONGODB_URI || !process.env.JWT_SECRET || !process.env.ADMIN_PASSWORD) throw new Error('Set MONGODB_URI, JWT_SECRET and ADMIN_PASSWORD');
  await mongoose.connect(process.env.MONGODB_URI);
  const username = String(process.env.ADMIN_USERNAME || 'admin').toLowerCase();
  let admin = await User.findOne({ username, role: 'admin' });
  if (!admin) {
    admin = await User.create({ name: 'Administrator', mobile: 'not-provided', username,
      passwordHash: await bcrypt.hash(process.env.ADMIN_PASSWORD, 12), role: 'admin', status: 'active' });
    console.log('Initial admin account created from environment settings.');
  }
  const port = Number(process.env.PORT || 3000);
  app.listen(port, '0.0.0.0', () => console.log(`API listening on ${port}`));
}
start().catch(err => { console.error(err.message); process.exit(1); });
