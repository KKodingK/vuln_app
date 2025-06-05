console.log('Starting app...');

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const path = require('path');

const app = express();
const db = new sqlite3.Database('vuln.db');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware to parse form data
app.use(express.urlencoded({ extended: true }));

// Session setup
app.use(session({
  secret: 'secret', // In production, use env variable & stronger secret
  resave: false,
  saveUninitialized: true,
}));

// Initialize DB and users table with roles
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user'
  )`);

  // Insert demo users (ignore if they exist)
  db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')`);
  db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES ('user1', 'pass1', 'user')`);
});

// Redirect root to login
app.get('/', (req, res) => res.redirect('/login'));

// Render login page
app.get('/login', (req, res) => res.render('login', { error: null }));

// Login route - vulnerable to SQL injection because of the direct parameterized query (simulate a safe example here)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  console.log('Login attempt:', username, password);

  // Using parameterized query to prevent injection, but if you want SQL injection vuln,
  // you can change to string concatenation (not recommended in practice).
  db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.render('login', { error: 'Database error' });
    }

    console.log('User found:', user);

    if (!user) return res.render('login', { error: 'Invalid username or password' });

    // Set user session
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.redirect('/dashboard');
  });
});

// Show all users - for debug (should be protected in real apps)
app.get('/users', (req, res) => {
  db.all('SELECT * FROM users', (err, rows) => {
    if (err) {
      console.error(err);
      return res.send('Database error');
    }
    res.json(rows);
  });
});

// Middleware for admin-only access
function requireAdmin(req, res, next) {
 // if (req.session.user && req.session.user.role === 'admin') {
    next();
 // } else {
  //  res.status(403).send('Access denied: Admins only');
 // }
}

// Admin panel - restricted access
app.get('/admin', requireAdmin, (req, res) => {
  res.send('Welcome to the admin panel');
});

// Dashboard accessible after login
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  // Broken Access Control example: showing admin access info incorrectly
  const isAdmin = req.session.user.role === 'admin';

  res.send(`
    <h1>Welcome ${req.session.user.username}</h1>
    <p>Admin panel access: ${isAdmin ? 'YES' : 'NO'}</p>
    <form method="GET" action="/xss">
      <input name="q" placeholder="Search anything">
      <button>Search</button>
    </form>
    <p><a href="/admin">Go to Admin Panel</a> (only admins should see this)</p>
  `);
});

// Reflected XSS vulnerability
app.get('/xss', (req, res) => {
  // Dangerous: directly embedding user input without sanitization
  res.send(`<p>You searched for: ${req.query.q}</p>`);
});

// Start server
app.listen(3000, () => {
  console.log('Vulnerable app running at http://localhost:3000');
});
