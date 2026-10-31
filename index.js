const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const JWT_SECRET = process.env.JWT_SECRET || 'redocs-secret-key';

// Health check - keeps server awake
app.get('/healthz', (req, res) => res.json({ status: 'ok' }));

// ── SIGN UP ──────────────────────────────────────────────
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'All fields required' });

  const hash = await bcrypt.hash(password, 10);

  const { data, error } = await supabase
    .from('users')
    .insert([{ name, email, password_hash: hash, subscribed: false, unlocked_docs: [] }])
    .select()
    .single();

  if (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'Email already exists' });
    return res.status(500).json({ error: error.message });
  }

  const token = jwt.sign({ id: data.id, email: data.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: data.id, name: data.name, email: data.email, subscribed: data.subscribed, unlocked_docs: data.unlocked_docs } });
});

// ── LOGIN ────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password required' });

  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();

  if (error || !data) return res.status(401).json({ error: 'Invalid email or password' });

  const valid = await bcrypt.compare(password, data.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ id: data.id, email: data.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: data.id, name: data.name, email: data.email, subscribed: data.subscribed, unlocked_docs: data.unlocked_docs } });
});

// ── GET PROFILE ──────────────────────────────────────────
app.get('/api/me', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, name, email, subscribed, unlocked_docs')
    .eq('id', req.user.id)
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ── UNLOCK DOC ───────────────────────────────────────────
app.post('/api/unlock', auth, async (req, res) => {
  const { docId } = req.body;
  const { data: user } = await supabase.from('users').select('unlocked_docs').eq('id', req.user.id).single();
  const docs = user.unlocked_docs || [];
  if (!docs.includes(docId)) docs.push(docId);

  await supabase.from('users').update({ unlocked_docs: docs }).eq('id', req.user.id);
  res.json({ unlocked_docs: docs });
});

// ── SET SUBSCRIBED ───────────────────────────────────────
app.post('/api/subscribe', auth, async (req, res) => {
  await supabase.from('users').update({ subscribed: true }).eq('id', req.user.id);
  res.json({ subscribed: true });
});

// ── AUTH MIDDLEWARE ──────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`RE Docs server running on port ${PORT}`));
