const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const svgCaptcha = require('svg-captcha');

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(session({ secret: 'secret-key', resave: false, saveUninitialized: true }));
app.use(express.static('public'));


const db = new sqlite3.Database('database.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS secrets (
    id TEXT,
    secret TEXT,
    pin TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT
  )`);
});

app.get('/captcha', (req, res) => {
  const captcha = svgCaptcha.create();
  req.session.captcha = captcha.text;
  res.type('svg');
  res.send(captcha.data);
});

app.get('/messages', (req, res) => {
  const { id, pin, vulnerability } = req.query;
  const vulnerabilityEnabled = vulnerability === 'on';

  if (vulnerabilityEnabled) {
    const query = `SELECT * FROM secrets WHERE id = '${id}' AND pin = '${pin}'`;
    db.all(query, [], (err, rows) => {
      if (err) {
        res.send('Error fetching data: ' + err.message);
      } else {
        res.render('messages', { messages: rows });
      }
    });
  } else {
    db.all('SELECT * FROM secrets WHERE id = ? AND pin = ?', [id, pin], (err, rows) => {
      if (err) {
        res.send('Error fetching data: ' + err.message);
      } else {
        res.render('messages', { messages: rows });
      }
    });
  }
});

app.post('/submit', (req, res) => {
  const { id, secret, pin } = req.body;
  const query = `INSERT INTO secrets (id, secret, pin) VALUES (?, ?, ?)`;

  db.run(query, [id, secret, pin], (err) => {
    if (err) {
      console.log('Database insertion error:', err);
      return res.redirect('/');
    }

    req.session.message = 'Podaci su uspješno spremljeni.';
    res.redirect('/');
  });
});


app.get('/', (req, res) => {
  const isLoggedIn = req.session.user ? true : false;
  const isBlocked = req.session.blockedUntil && new Date() < new Date(req.session.blockedUntil) ? true : false;
  const remainingTime = isBlocked ? Math.ceil((new Date(req.session.blockedUntil) - new Date()) / 1000) : 0;
  const username = req.session.user || null;
  const registerMessage = req.session.registerMessage || '';
  const loginMessage = req.session.loginMessage || '';
  const message = req.session.message || '';

  res.render('index', {
    isLoggedIn,
    username,
    isBlocked,
    remainingTime,
    registerMessage,
    loginMessage,
    message
  });

  req.session.registerMessage = null;
  req.session.loginMessage = null;
  req.session.message = null;
});

app.post('/register', (req, res) => {
  const { username, password, vulnerability } = req.body;
  const vulnerabilityEnabled = vulnerability === 'on';

  if (vulnerabilityEnabled) {
    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, password], (err) => {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed: users.username')) {
          req.session.registerMessage = 'Error: Korisničko ime već postoji.';
        } else {
          req.session.registerMessage = 'Error registering user: ' + err.message;
        }
        return res.redirect('/');
      } else {
        req.session.registerMessage = 'Korisnik je uspješno registiran (ranjivost uključena).';
        return res.redirect('/');
      }
    });
  } else {
    if (password.length < 10 || !/[A-Z]/.test(password) || !/\d/.test(password)) {
      req.session.registerMessage = 'Lozinka mora sadržavati najmanje 10 znakova, 1 veliko slovo i 1 broj.';
      return res.redirect('/');
    }
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        req.session.registerMessage = 'Error hashing password: ' + err.message;
        return res.redirect('/');
      } else {
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hash], (err) => {
          if (err) {
            if (err.message.includes('UNIQUE constraint failed: users.username')) {
              req.session.registerMessage = 'Error: Korisničko ime već postoji.';
            } else {
              req.session.registerMessage = 'Error registering user: ' + err.message;
            }
            return res.redirect('/');
          } else {
            req.session.registerMessage = 'Korisnik je uspješno registiran (ranjivost isključena).';
            return res.redirect('/');
          }
        });
      }
    });
  }
});


app.post('/login', (req, res) => {
  const { username, password, vulnerability } = req.body;
  const vulnerabilityEnabled = vulnerability === 'on';

  if (vulnerabilityEnabled) {
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
      if (err) {
        req.session.loginMessage = 'Error occurred while logging in.';
        return res.redirect('/');
      }
      if (!user) {
        req.session.loginMessage = 'Korisničko ime ne postoji.';
        return res.redirect('/');
      }
      if (password !== user.password) {
        req.session.loginMessage = 'Netočna lozinka';
        return res.redirect('/');
      }
      req.session.user = username;
      req.session.loginMessage = 'Prijava uspješna (ranjivost uključena).';
      return res.redirect('/');
    });
  } else {
    if (!req.body.captcha || req.body.captcha !== req.session.captcha) {
      req.session.loginMessage = 'CAPTCHA verifikacija neuspješna.';
      return res.redirect('/');
    }

    if (req.session.blockedUntil && new Date() < new Date(req.session.blockedUntil)) {
      req.session.loginMessage = `Previše neuspješnih pokušaja. Probajte ponovo za ${Math.ceil((new Date(req.session.blockedUntil) - new Date()) / 1000)} sekundi.`;
      return res.redirect('/');
    }

    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
      if (err || !user) {
        req.session.loginMessage = 'Podaci za prijavu su netočni.';
        req.session.failedAttempts = (req.session.failedAttempts || 0) + 1;
        if (req.session.failedAttempts >= 3) {
          req.session.blockedUntil = new Date(Date.now() + 30 * 1000);
          req.session.failedAttempts = 0;
        }
        return res.redirect('/');
      }

      bcrypt.compare(password, user.password, (err, result) => {
        if (result) {
          req.session.user = username;
          req.session.failedAttempts = 0;
          req.session.loginMessage = 'Prijava uspješna (ranjivost isključena).';
          return res.redirect('/');
        } else {
          req.session.loginMessage = 'Podaci za prijavu su netočni.';
          req.session.failedAttempts = (req.session.failedAttempts || 0) + 1;
          if (req.session.failedAttempts >= 3) {
            req.session.blockedUntil = new Date(Date.now() + 30 * 1000);
            req.session.failedAttempts = 0;
          }
          return res.redirect('/');
        }
      });
    });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect(req.get('Referrer') || '/');;
});

app.listen(port, () => {
  console.log(`App running at http://localhost:${port}`);
});
