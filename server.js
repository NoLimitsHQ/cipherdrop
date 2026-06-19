const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

loadDotEnv();

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'db.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const COLLECTIONS = ['users', 'sessions', 'friendRequests', 'messages', 'audit'];

function loadDotEnv() {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    if (!process.env[key]) process.env[key] = value;
  }
}
function now() { return new Date().toISOString(); }
function id(prefix='id') { return `${prefix}_${crypto.randomBytes(10).toString('hex')}`; }
function code6() { return String(Math.floor(100000 + Math.random() * 900000)); }
function password8() { return String(Math.floor(10000000 + Math.random() * 90000000)); }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(String(password), salt, 180000, 32, 'sha256').toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, expected] = String(stored || '').split(':');
  if (!salt || !expected) return false;
  const actual = crypto.pbkdf2Sync(String(password), salt, 180000, 32, 'sha256').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
}
function sanitizeUser(user) { if (!user) return null; const { passwordHash, ...safe } = user; return safe; }
function publicUser(user) { return user ? { id: user.id, displayName: user.displayName, authCode: user.authCode, avatar: user.avatar, status: user.status, createdAt: user.createdAt } : null; }
function emptyDb() { return { meta: { appName: 'CipherDrop', initializedAt: now(), storage: storage.kind }, users: [], sessions: [], friendRequests: [], messages: [], audit: [] }; }

function createStorage() {
  const firebaseConfigured = !!(process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY);
  if (firebaseConfigured) {
    try {
      const admin = require('firebase-admin');
      if (!admin.apps.length) {
        admin.initializeApp({
          credential: admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
          })
        });
      }
      const firestore = admin.firestore();
      return {
        kind: 'firebase',
        async load() {
          const db = { meta: { appName: 'CipherDrop', storage: 'firebase' }, users: [], sessions: [], friendRequests: [], messages: [], audit: [] };
          const metaDoc = await firestore.collection('meta').doc('app').get();
          if (metaDoc.exists) db.meta = { ...db.meta, ...metaDoc.data() };
          await Promise.all(COLLECTIONS.map(async (name) => {
            const snap = await firestore.collection(name).get();
            db[name] = snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
          }));
          return db;
        },
        async save(db) {
          db.meta = { ...(db.meta || {}), appName: 'CipherDrop', storage: 'firebase', updatedAt: now() };
          for (const name of COLLECTIONS) {
            const existing = await firestore.collection(name).get();
            const nextIds = new Set((db[name] || []).map(item => item.id));
            let batch = firestore.batch();
            let ops = 0;
            for (const doc of existing.docs) {
              if (!nextIds.has(doc.id)) { batch.delete(doc.ref); ops++; }
            }
            for (const item of (db[name] || [])) {
              const ref = firestore.collection(name).doc(item.id);
              batch.set(ref, item, { merge: false }); ops++;
              if (ops >= 450) { await batch.commit(); batch = firestore.batch(); ops = 0; }
            }
            if (ops) await batch.commit();
          }
          await firestore.collection('meta').doc('app').set(db.meta, { merge: true });
        }
      };
    } catch (e) {
      console.warn('Firebase env vars were found, but firebase-admin could not start. Falling back to local JSON.', e.message);
    }
  }
  return {
    kind: 'json',
    async load() {
      if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
      if (!fs.existsSync(DB_PATH)) fs.writeFileSync(DB_PATH, JSON.stringify(emptyDb(), null, 2));
      return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    },
    async save(db) {
      if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
      db.meta = { ...(db.meta || {}), appName: 'CipherDrop', storage: 'json', updatedAt: now() };
      fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
    }
  };
}
const storage = createStorage();

async function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; if (data.length > 1_000_000) { req.destroy(); reject(new Error('Body too large')); } });
    req.on('end', () => { if (!data) return resolve({}); try { resolve(JSON.parse(data)); } catch { reject(new Error('Invalid JSON')); } });
  });
}
function send(res, status, payload, headers={}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(payload));
}
function error(res, status, message) { send(res, status, { error: message }); }
function getToken(req) { const h = req.headers.authorization || ''; return h.startsWith('Bearer ') ? h.slice(7) : null; }
function requireUser(req, res, db) {
  const token = getToken(req);
  if (!token) { error(res, 401, 'Missing bearer token'); return null; }
  const session = db.sessions.find(s => s.token === token && (!s.expiresAt || new Date(s.expiresAt) > new Date()));
  if (!session) { error(res, 401, 'Session expired or invalid'); return null; }
  const user = db.users.find(u => u.id === session.userId);
  if (!user) { error(res, 401, 'User not found'); return null; }
  session.lastSeenAt = now();
  return user;
}
function areConnected(db, a, b) { return db.friendRequests.some(r => r.status === 'accepted' && ((r.fromUserId === a && r.toUserId === b) || (r.fromUserId === b && r.toUserId === a))); }
function requestBetween(db, a, b) { return db.friendRequests.find(r => (r.fromUserId === a && r.toUserId === b) || (r.fromUserId === b && r.toUserId === a)); }
function appState(db, user) {
  const myId = user.id;
  const contacts = db.friendRequests
    .filter(r => r.status === 'accepted' && (r.fromUserId === myId || r.toUserId === myId))
    .map(r => {
      const otherId = r.fromUserId === myId ? r.toUserId : r.fromUserId;
      return { requestId: r.id, since: r.updatedAt, user: publicUser(db.users.find(u => u.id === otherId)) };
    }).filter(c => c.user);
  const requests = db.friendRequests
    .filter(r => r.fromUserId === myId || r.toUserId === myId)
    .filter(r => r.status !== 'accepted')
    .map(r => ({ ...r, fromUser: publicUser(db.users.find(u => u.id === r.fromUserId)), toUser: publicUser(db.users.find(u => u.id === r.toUserId)) }))
    .sort((a,b) => b.createdAt.localeCompare(a.createdAt));
  const messages = db.messages
    .filter(m => m.fromUserId === myId || m.toUserId === myId)
    .map(m => ({
      ...m,
      body: m.status === 'destroyed' ? '' : m.body,
      fromUser: publicUser(db.users.find(u => u.id === m.fromUserId)),
      toUser: publicUser(db.users.find(u => u.id === m.toUserId))
    }))
    .sort((a,b) => b.createdAt.localeCompare(a.createdAt));
  return { user: sanitizeUser(user), contacts, requests, messages, storage: db.meta?.storage || storage.kind };
}
async function uniqueAuthCode(db) { let authCode; do { authCode = code6(); } while (db.users.some(u => u.authCode === authCode)); return authCode; }

async function api(req, res, pathname) {
  const db = await storage.load();
  try {
    if (req.method === 'POST' && pathname === '/api/login') {
      const body = await parseBody(req);
      const authCode = String(body.authCode || '').trim();
      const password = String(body.password || '').trim();
      if (!/^\d{6}$/.test(authCode) || !/^\d{8}$/.test(password)) return error(res, 400, 'Use a 6 digit auth code and 8 digit password.');
      const user = db.users.find(u => u.authCode === authCode);
      if (!user || !verifyPassword(password, user.passwordHash)) return error(res, 401, 'Invalid auth code or password.');
      const token = crypto.randomBytes(32).toString('hex');
      db.sessions.push({ id: id('sess'), token, userId: user.id, createdAt: now(), lastSeenAt: now(), expiresAt: new Date(Date.now()+1000*60*60*24*14).toISOString() });
      await storage.save(db);
      return send(res, 200, { token, state: appState(db, user) });
    }
    if (req.method === 'POST' && pathname === '/api/register') {
      const body = await parseBody(req);
      const displayName = String(body.displayName || '').trim().slice(0, 28);
      if (displayName.length < 2) return error(res, 400, 'Display name must be at least 2 characters.');
      const authCode = await uniqueAuthCode(db);
      const password = password8();
      const user = { id: id('u'), displayName, authCode, passwordHash: hashPassword(password), avatar: String(body.avatar || '🕶️').trim().slice(0, 4) || '🕶️', status: 'New anonymous inbox.', createdAt: now(), updatedAt: now() };
      db.users.push(user);
      const token = crypto.randomBytes(32).toString('hex');
      db.sessions.push({ id: id('sess'), token, userId: user.id, createdAt: now(), lastSeenAt: now(), expiresAt: new Date(Date.now()+1000*60*60*24*14).toISOString() });
      db.audit.push({ id: id('audit'), type: 'user.created', userId: user.id, createdAt: now() });
      await storage.save(db);
      return send(res, 201, { token, password, state: appState(db, user) });
    }

    const user = requireUser(req, res, db);
    if (!user) return;

    if (req.method === 'GET' && pathname === '/api/state') { await storage.save(db); return send(res, 200, appState(db, user)); }
    if (req.method === 'POST' && pathname === '/api/logout') {
      const token = getToken(req);
      db.sessions = db.sessions.filter(s => s.token !== token);
      await storage.save(db); return send(res, 200, { ok: true });
    }
    if (req.method === 'PATCH' && pathname === '/api/me') {
      const body = await parseBody(req);
      if (body.displayName !== undefined) {
        const name = String(body.displayName).trim().slice(0, 28);
        if (name.length < 2) return error(res, 400, 'Display name must be at least 2 characters.');
        user.displayName = name;
      }
      if (body.status !== undefined) user.status = String(body.status).trim().slice(0, 90);
      if (body.avatar !== undefined) user.avatar = String(body.avatar).trim().slice(0, 4) || '🕶️';
      user.updatedAt = now(); await storage.save(db); return send(res, 200, appState(db, user));
    }

    if (req.method === 'POST' && pathname === '/api/requests') {
      const body = await parseBody(req);
      const targetCode = String(body.authCode || '').trim();
      if (!/^\d{6}$/.test(targetCode)) return error(res, 400, 'Enter a valid 6 digit auth code.');
      const target = db.users.find(u => u.authCode === targetCode);
      if (!target) return error(res, 404, 'No user exists with that code.');
      if (target.id === user.id) return error(res, 400, 'You cannot add yourself.');
      const existing = requestBetween(db, user.id, target.id);
      if (existing) return error(res, 409, existing.status === 'accepted' ? 'You are already connected.' : 'A request already exists between these users.');
      db.friendRequests.push({ id: id('fr'), fromUserId: user.id, toUserId: target.id, status: 'pending', note: String(body.note || '').trim().slice(0, 120), createdAt: now(), updatedAt: now() });
      await storage.save(db); return send(res, 201, appState(db, user));
    }
    const reqMatch = pathname.match(/^\/api\/requests\/([^/]+)$/);
    if (reqMatch && req.method === 'PATCH') {
      const body = await parseBody(req); const fr = db.friendRequests.find(r => r.id === reqMatch[1]);
      if (!fr) return error(res, 404, 'Request not found.');
      const action = String(body.action || '');
      if (action === 'accept') { if (fr.toUserId !== user.id) return error(res, 403, 'Only the receiver can accept.'); fr.status = 'accepted'; fr.updatedAt = now(); await storage.save(db); return send(res, 200, appState(db, user)); }
      if (action === 'reject') { if (fr.toUserId !== user.id) return error(res, 403, 'Only the receiver can reject.'); fr.status = 'rejected'; fr.updatedAt = now(); await storage.save(db); return send(res, 200, appState(db, user)); }
      if (action === 'cancel') { if (fr.fromUserId !== user.id) return error(res, 403, 'Only the sender can cancel.'); db.friendRequests = db.friendRequests.filter(r => r.id !== fr.id); await storage.save(db); return send(res, 200, appState(db, user)); }
      return error(res, 400, 'Unsupported action.');
    }

    const contactsMatch = pathname.match(/^\/api\/contacts\/([^/]+)$/);
    if (contactsMatch && req.method === 'DELETE') {
      const otherId = contactsMatch[1];
      const before = db.friendRequests.length;
      db.friendRequests = db.friendRequests.filter(r => !(r.status === 'accepted' && ((r.fromUserId === user.id && r.toUserId === otherId) || (r.fromUserId === otherId && r.toUserId === user.id))));
      if (db.friendRequests.length === before) return error(res, 404, 'Contact not found.');
      await storage.save(db); return send(res, 200, appState(db, user));
    }

    if (req.method === 'POST' && pathname === '/api/messages') {
      const body = await parseBody(req);
      const toUserId = String(body.toUserId || '');
      const text = String(body.body || '').trim();
      if (text.length < 1 || text.length > 1000) return error(res, 400, 'Message must be 1-1000 characters.');
      if (!areConnected(db, user.id, toUserId)) return error(res, 403, 'Messages require an accepted connection.');
      db.messages.push({ id: id('m'), fromUserId: user.id, toUserId, body: text, status: 'unread', createdAt: now(), updatedAt: now(), readAt: null });
      await storage.save(db); return send(res, 201, appState(db, user));
    }
    const msgMatch = pathname.match(/^\/api\/messages\/([^/]+)$/);
    if (msgMatch && req.method === 'PATCH') {
      const body = await parseBody(req); const msg = db.messages.find(m => m.id === msgMatch[1]);
      if (!msg) return error(res, 404, 'Message not found.');
      if (body.action === 'open') {
        if (msg.toUserId !== user.id) return error(res, 403, 'Only the recipient can open this message.');
        if (msg.status !== 'unread') return error(res, 410, 'Message has already been destroyed.');
        const openedBody = msg.body;
        msg.status = 'destroyed'; msg.body = ''; msg.readAt = now(); msg.updatedAt = now();
        await storage.save(db); return send(res, 200, { opened: { ...msg, body: openedBody, fromUser: publicUser(db.users.find(u => u.id === msg.fromUserId)), toUser: publicUser(user) }, state: appState(db, user) });
      }
      if (body.body !== undefined) {
        if (msg.fromUserId !== user.id) return error(res, 403, 'Only the sender can edit.');
        if (msg.status !== 'unread') return error(res, 410, 'Destroyed messages cannot be edited.');
        const text = String(body.body || '').trim();
        if (text.length < 1 || text.length > 1000) return error(res, 400, 'Message must be 1-1000 characters.');
        msg.body = text; msg.updatedAt = now(); await storage.save(db); return send(res, 200, appState(db, user));
      }
      return error(res, 400, 'Unsupported message update.');
    }
    if (msgMatch && req.method === 'DELETE') {
      const msg = db.messages.find(m => m.id === msgMatch[1]);
      if (!msg) return error(res, 404, 'Message not found.');
      if (msg.fromUserId !== user.id && msg.toUserId !== user.id) return error(res, 403, 'Not your message.');
      db.messages = db.messages.filter(m => m.id !== msg.id); await storage.save(db); return send(res, 200, appState(db, user));
    }

    return error(res, 404, 'API route not found.');
  } catch (e) {
    return error(res, e.message === 'Invalid JSON' ? 400 : 500, e.message || 'Server error');
  }
}

function serveStatic(req, res, pathname) {
  let filePath = pathname === '/' ? path.join(PUBLIC_DIR, 'index.html') : path.join(PUBLIC_DIR, pathname);
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (e, html) => { res.writeHead(e ? 404 : 200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(e ? 'Not found' : html); });
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    const type = { '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'application/javascript; charset=utf-8', '.svg':'image/svg+xml' }[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': type }); res.end(data);
  });
}

http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname.startsWith('/api/')) return api(req, res, url.pathname).catch(e => error(res, 500, e.message || 'Server error'));
  return serveStatic(req, res, url.pathname);
}).listen(PORT, () => console.log(`CipherDrop running at http://localhost:${PORT} using ${storage.kind} storage`));
