require('dotenv').config();
const express = require('express');
const db = require('./database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const geoip = require('geoip-lite');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production';
const ADMIN_PATH = '/admin-dashboard-secure-2024';

// CSRF Protection
const csrfTokens = new Map();

function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

function validateCSRFToken(req, res, next) {
  const token = req.headers['x-csrf-token'] || req.body._csrf;
  
  if (!token) {
    return res.status(403).json({ error: 'CSRF token missing' });
  }

  const sessionToken = req.cookies.csrf_token;
  
  if (!sessionToken || token !== sessionToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  next();
}

app.use((req, res, next) => {
  if (!req.cookies.csrf_token) {
    const token = generateCSRFToken();
    res.cookie('csrf_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });
  }
  next();
});

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '.')));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts, please try again later.' }
});

app.use('/api', apiLimiter);

function authenticateToken(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.clearCookie('token');
    return res.status(403).json({ error: 'Invalid token.' });
  }
}

app.post('/api/login', authLimiter, validateCSRFToken, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input types.' });
  }

  if (username.length < 3 || username.length > 50) {
    return res.status(400).json({ error: 'Username must be between 3 and 50 characters.' });
  }

  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: 'Password must be between 8 and 128 characters.' });
  }

  const sanitizedUsername = username.trim();
  
  await db.read();
  const user = db.data.users.find(u => u.username === sanitizedUsername);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, is_permanent: user.is_permanent },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000
  });

  res.json({
    success: true,
    user: {
      id: user.id,
      username: user.username,
      is_permanent: !!user.is_permanent
    }
  });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.post('/api/visitor', validateCSRFToken, async (req, res) => {
  const { ip_address, user_agent } = req.body;
  
  if (!ip_address) {
    return res.status(400).json({ error: 'IP address is required.' });
  }

  if (typeof ip_address !== 'string') {
    return res.status(400).json({ error: 'Invalid input type.' });
  }

  if (ip_address.length < 7 || ip_address.length > 45) {
    return res.status(400).json({ error: 'Invalid IP address format.' });
  }

  const sanitizedIp = ip_address.trim();
  const sanitizedUserAgent = user_agent ? String(user_agent).trim().substring(0, 500) : 'Unknown';

  const geo = geoip.lookup(sanitizedIp);
  const country = geo?.country || null;
  const city = geo?.city || null;

  try {
    await db.read();
    db.data.visitors.push({
      id: Date.now(),
      ip_address: sanitizedIp,
      user_agent: sanitizedUserAgent,
      geo_country: country,
      geo_city: city,
      visited_at: new Date().toISOString()
    });
    await db.write();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to record visitor.' });
  }
});

app.post('/api/booking', validateCSRFToken, async (req, res) => {
  const { name, age, city, procedure, phone, country_code, ip_address } = req.body;

  if (!name || !age || !city || !procedure || !phone || !country_code || !ip_address) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  if (typeof name !== 'string' || typeof city !== 'string' || typeof procedure !== 'string' || typeof phone !== 'string' || typeof country_code !== 'string' || typeof ip_address !== 'string') {
    return res.status(400).json({ error: 'Invalid input types.' });
  }

  if (typeof age !== 'number' && isNaN(parseInt(age))) {
    return res.status(400).json({ error: 'Age must be a number.' });
  }

  const ageNum = parseInt(age);
  if (ageNum < 18 || ageNum > 100) {
    return res.status(400).json({ error: 'Age must be between 18 and 100.' });
  }

  if (name.length < 2 || name.length > 100) {
    return res.status(400).json({ error: 'Name must be between 2 and 100 characters.' });
  }

  if (city.length < 2 || city.length > 100) {
    return res.status(400).json({ error: 'City must be between 2 and 100 characters.' });
  }

  if (phone.length < 10 || phone.length > 20) {
    return res.status(400).json({ error: 'Phone number must be between 10 and 20 characters.' });
  }

  if (country_code.length < 1 || country_code.length > 5) {
    return res.status(400).json({ error: 'Country code must be between 1 and 5 characters.' });
  }

  if (!/^[0-9]+$/.test(phone)) {
    return res.status(400).json({ error: 'Phone number must contain only digits.' });
  }

  if (!/^[0-9]+$/.test(country_code)) {
    return res.status(400).json({ error: 'Country code must contain only digits.' });
  }

  const sanitizedName = name.trim();
  const sanitizedCity = city.trim();
  const sanitizedProcedure = procedure.trim();
  const sanitizedPhone = phone.trim();
  const sanitizedCountryCode = country_code.trim();
  const sanitizedIp = ip_address.trim();

  const geo = geoip.lookup(sanitizedIp);
  const country = geo?.country || null;
  const cityLocation = geo?.city || null;

  try {
    await db.read();
    db.data.bookings.push({
      id: Date.now(),
      name: sanitizedName,
      age: ageNum,
      city: sanitizedCity,
      procedure: sanitizedProcedure,
      phone: sanitizedPhone,
      country_code: sanitizedCountryCode,
      ip_address: sanitizedIp,
      geo_country: country,
      geo_city: cityLocation,
      booked_at: new Date().toISOString()
    });
    await db.write();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to save booking.' });
  }
});

app.get('/api/analytics/visitors', authenticateToken, async (req, res) => {
  const { start_date, end_date } = req.query;

  try {
    await db.read();
    let visitors = db.data.visitors;

    if (start_date && end_date) {
      visitors = visitors.filter(v => {
        const visitDate = new Date(v.visited_at).toISOString().split('T')[0];
        return visitDate >= start_date && visitDate <= end_date;
      });
    }

    const grouped = {};
    visitors.forEach(v => {
      const date = new Date(v.visited_at).toISOString().split('T')[0];
      if (!grouped[date]) {
        grouped[date] = { date, total_visitors: 0, unique_visitors: new Set() };
      }
      grouped[date].total_visitors++;
      grouped[date].unique_visitors.add(v.ip_address);
    });

    const data = Object.values(grouped).map(g => ({
      date: g.date,
      total_visitors: g.total_visitors,
      unique_visitors: g.unique_visitors.size
    })).sort((a, b) => a.date.localeCompare(b.date));

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch analytics.' });
  }
});

app.get('/api/bookings', authenticateToken, async (req, res) => {
  const { limit = 50, offset = 0 } = req.query;

  try {
    await db.read();
    const bookings = db.data.bookings
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
      .slice(parseInt(offset), parseInt(offset) + parseInt(limit));

    const total = db.data.bookings.length;

    res.json({ bookings, total });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch bookings.' });
  }
});

app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    await db.read();
    const users = db.data.users
      .map(u => ({
        id: u.id,
        username: u.username,
        is_permanent: u.is_permanent,
        created_at: u.created_at
      }))
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users.' });
  }
});

app.post('/api/users', authenticateToken, validateCSRFToken, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input types.' });
  }

  if (username.length < 3 || username.length > 50) {
    return res.status(400).json({ error: 'Username must be between 3 and 50 characters.' });
  }

  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: 'Password must be between 8 and 128 characters.' });
  }

  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores.' });
  }

  const sanitizedUsername = username.trim();

  try {
    await db.read();
    const existingUser = db.data.users.find(u => u.username === sanitizedUsername);

    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists.' });
    }

    const passwordHash = bcrypt.hashSync(password, 12);
    db.data.users.push({
      id: Date.now(),
      username: sanitizedUsername,
      password_hash: passwordHash,
      is_permanent: false,
      created_at: new Date().toISOString()
    });
    await db.write();

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create user.' });
  }
});

app.put('/api/users/:id', authenticateToken, validateCSRFToken, async (req, res) => {
  const { id } = req.params;
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: 'Password is required.' });
  }

  if (typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input type.' });
  }

  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: 'Password must be between 8 and 128 characters.' });
  }

  if (typeof id !== 'string' && isNaN(parseInt(id))) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }

  const userId = parseInt(id);

  try {
    await db.read();
    const userIndex = db.data.users.findIndex(u => u.id === userId);

    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = db.data.users[userIndex];

    if (user.is_permanent && user.username === 'm_uvex') {
      return res.status(403).json({ error: 'Cannot modify permanent user.' });
    }

    const passwordHash = bcrypt.hashSync(password, 12);
    db.data.users[userIndex].password_hash = passwordHash;
    await db.write();

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update user.' });
  }
});

app.delete('/api/users/:id', authenticateToken, validateCSRFToken, async (req, res) => {
  const { id } = req.params;

  if (typeof id !== 'string' && isNaN(parseInt(id))) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }

  const userId = parseInt(id);

  try {
    await db.read();
    const userIndex = db.data.users.findIndex(u => u.id === userId);

    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = db.data.users[userIndex];

    if (user.is_permanent && user.username === 'm_uvex') {
      return res.status(403).json({ error: 'Cannot delete permanent user.' });
    }

    db.data.users.splice(userIndex, 1);
    await db.write();

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete user.' });
  }
});

app.get(ADMIN_PATH, (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.sendFile(path.join(__dirname, 'dashboard-login.html'));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.sendFile(path.join(__dirname, 'dashboard.html'));
  } catch (error) {
    res.clearCookie('token');
    res.sendFile(path.join(__dirname, 'dashboard-login.html'));
  }
});

app.get('/api/auth/check', authenticateToken, (req, res) => {
  res.json({ authenticated: true, user: req.user });
});

app.get('*', (req, res) => {
  if (req.path.startsWith(ADMIN_PATH)) {
    return res.sendFile(path.join(__dirname, 'dashboard-login.html'));
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Invalid token.' });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({ error: 'Token expired.' });
  }
  
  res.status(500).json({ error: 'Internal server error.' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Dashboard accessible at: ${ADMIN_PATH}`);
});
