const express   = require('express');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ── Supabase Client ──
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ── REGISTER Route ──
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: 'Please fill in all fields.' });

  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .eq('username', username)
    .single();

  if (existing)
    return res.status(400).json({ message: 'Username already taken.' });

  const hashed = await bcrypt.hash(password, 10);
  const { error } = await supabase
    .from('users')
    .insert([{ username, password: hashed }]);

  if (error)
    return res.status(500).json({ message: 'Registration failed.' });

  res.json({ message: 'User registered successfully!' });
});

// ── LOGIN Route ──
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: 'Please fill in all fields.' });

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('username', username)
    .single();

  if (error || !user)
    return res.status(401).json({ message: 'Invalid username or password.' });

  const match = await bcrypt.compare(password, user.password);
  if (!match)
    return res.status(401).json({ message: 'Invalid username or password.' });

  const token = jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({ message: 'Login successful!', token });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));