import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import crypto from 'crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import cors from 'cors';

const {
  ISSUER,
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI = 'http://localhost:3000/callback',
  AUDIENCE,
  PORT = 3000,
  SESSION_SECRET = 'dev_secret'
} = process.env;

if (!ISSUER || !CLIENT_ID) {
  console.error('Set ISSUER and CLIENT_ID in .env');
  process.exit(1);
}

const app = express();

// Allow the SPA dev server
app.use(cors({ origin: 'http://localhost:5173', credentials: true }));

app.use(
  session({
    name: 'sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { sameSite: 'lax' }
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ----- OIDC discovery -----
let openidConfig;
async function getConfig() {
  if (openidConfig) return openidConfig;
  const url = `${ISSUER}/.well-known/openid-configuration`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`);
  openidConfig = await res.json();
  return openidConfig;
}

// ----- PKCE helpers -----
function b64url(input) {
  return input
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}
function genVerifier() {
  return b64url(crypto.randomBytes(32));
}
function genChallenge(verifier) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return b64url(hash);
}
function genState() {
  return b64url(crypto.randomBytes(16));
}

// 1) Start login
app.get('/login', async (req, res) => {
  const cfg = await getConfig();
  const state = genState();
  const verifier = genVerifier();
  const challenge = genChallenge(verifier);

  req.session.oauth = { state, verifier };

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: 'code',
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile email',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state
  });

  if (AUDIENCE) params.set('audience', AUDIENCE);

  const authUrl = `${cfg.authorization_endpoint}?${params.toString()}`;
  res.redirect(authUrl);
});

// 2) Callback → exchange code for tokens
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  const stash = req.session.oauth;
  if (!code || !state || !stash || state !== stash.state) {
    return res.status(400).send('Bad state or code');
  }

  const cfg = await getConfig();

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    code_verifier: stash.verifier,
    code,
    redirect_uri: REDIRECT_URI
  });

  // Some IdPs need client_secret for confidential apps
  if (CLIENT_SECRET) body.set('client_secret', CLIENT_SECRET);

  const tokRes = await fetch(cfg.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body
  });

  if (!tokRes.ok) {
    const text = await tokRes.text();
    return res.status(502).send(`Token exchange failed: ${text}`);
  }

  const tokens = await tokRes.json();
  req.session.tokens = tokens;

  // Verify ID Token if present
  try {
    if (tokens.id_token) {
      const JWKS = createRemoteJWKSet(new URL(cfg.jwks_uri));
      const { payload } = await jwtVerify(tokens.id_token, JWKS, {
        issuer: cfg.issuer,
        audience: CLIENT_ID
      });
      req.session.claims = payload;
    }
  } catch (e) {
    return res.status(400).send(`ID Token check failed: ${e.message}`);
  }

  res.redirect('/');
});

// Current user (from ID Token)
app.get('/me', (req, res) => {
  const claims = req.session.claims;
  if (!claims) return res.status(401).json({ error: 'not_authenticated' });
  res.json({ claims });
});

// UserInfo (optional)
app.get('/userinfo', async (req, res) => {
  const cfg = await getConfig();
  const tokens = req.session.tokens;
  if (!tokens?.access_token) {
    return res.status(401).json({ error: 'no_access_token' });
  }
  const uRes = await fetch(cfg.userinfo_endpoint, {
    headers: { Authorization: `Bearer ${tokens.access_token}` }
  });
  const data = await uRes.json();
  res.status(uRes.status).json(data);
});

// Logout (local)
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.status(204).end());
});

// Minimal home
app.get('/', (req, res) => {
  const loggedIn = Boolean(req.session.claims);
  res.type('html').send(`
    <h1>Auth Code + PKCE (Node)</h1>
    <p>Status: ${loggedIn ? 'signed in' : 'signed out'}</p>
    <p>
      <a href="/login">Login</a> |
      <a href="/me">/me</a> |
      <a href="/userinfo">/userinfo</a>
    </p>
    <form method="post" action="/logout"><button>Logout</button></form>
  `);
});

app.listen(PORT, () => {
  console.log(`Server on http://localhost:${PORT}`);
});
