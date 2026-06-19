const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

loadDotEnv();

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'db.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const COLLECTIONS = ['users', 'sessions', 'friendRequests', 'messages', 'emailVerifications', 'audit'];

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
function normalizeEmail(email) { return String(email || '').trim().toLowerCase(); }
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254; }
function verificationCode() { return String(Math.floor(100000 + Math.random() * 900000)); }
const EMAIL_TEST_BYPASS = '-*logintestpass999-*';
function isEmailTestBypass(value) { return String(value || '').trim() === EMAIL_TEST_BYPASS; }
function emptyDb() { return { meta: { appName: 'CipherDrop', initializedAt: now(), storage: storage.kind }, users: [], sessions: [], friendRequests: [], messages: [], emailVerifications: [], audit: [] }; }

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
          const db = { meta: { appName: 'CipherDrop', storage: 'firebase' }, users: [], sessions: [], friendRequests: [], messages: [], emailVerifications: [], audit: [] };
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

function smtpConfigured() {
  return !!(process.env.SMTP_HOST && process.env.SMTP_PORT && process.env.SMTP_USER && process.env.SMTP_PASS);
}
function brevoConfigured() {
  return !!process.env.BREVO_API_KEY;
}
function emailProviderConfigured() {
  return brevoConfigured() || smtpConfigured();
}
function parseEmailFrom(value) {
  const fallback = process.env.SMTP_USER || 'no-reply@cipherdrop.local';
  const raw = String(value || fallback).trim();
  const match = raw.match(/^(.*?)\s*<([^>]+)>$/);
  if (match) return { name: match[1].trim().replace(/^['"]|['"]$/g, '') || 'CipherDrop', email: match[2].trim() };
  return { name: process.env.EMAIL_FROM_NAME || 'CipherDrop', email: raw };
}
function verificationEmailContent(code) {
  const appUrl = process.env.APP_URL || `http://localhost:${PORT}`;
  const subject = 'Your CipherDrop verification code';
  const text = `Your CipherDrop verification code is ${code}. It expires in 15 minutes.\n\nOpen ${appUrl} and enter this code.\n\nIf you did not create a CipherDrop account, ignore this email.`;
  const html = `<!doctype html><html><body style="margin:0;background:#090b12;padding:28px;font-family:Arial,sans-serif;color:#f4f7fb"><table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td align="center"><table role="presentation" width="100%" style="max-width:560px;background:#111521;border:1px solid #2a3042;border-radius:22px;padding:26px"><tr><td><div style="font-size:22px;font-weight:800;margin-bottom:18px">✦ CipherDrop</div><h1 style="margin:0 0 12px;font-size:28px">Verify your email</h1><p style="color:#cbd3e7;line-height:1.6">Enter this code in CipherDrop. It expires in 15 minutes.</p><div style="font-size:34px;letter-spacing:8px;font-weight:800;background:#241f49;padding:18px;border-radius:16px;text-align:center;color:#ffffff">${code}</div><p style="color:#8c96ad;font-size:13px;line-height:1.5;margin-top:18px">If you did not create a CipherDrop account, ignore this email.</p></td></tr></table></td></tr></table></body></html>`;
  return { subject, text, html };
}
async function sendVerificationEmail(to, code) {
  const from = parseEmailFrom(process.env.EMAIL_FROM);
  const { subject, text, html } = verificationEmailContent(code);

  if (brevoConfigured()) {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'accept': 'application/json', 'api-key': process.env.BREVO_API_KEY, 'content-type': 'application/json' },
      body: JSON.stringify({ sender: from, to: [{ email: to }], subject, textContent: text, htmlContent: html })
    });
    const body = await response.text();
    if (!response.ok) throw new Error(`Brevo email failed (${response.status}): ${body.slice(0, 300)}`);
    return { sent: true, provider: 'brevo' };
  }

  if (smtpConfigured()) {
    const nodemailer = require('nodemailer');
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || '').toLowerCase() === 'true' || Number(process.env.SMTP_PORT) === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
    await transporter.sendMail({ from: `${from.name} <${from.email}>`, to, subject, text, html });
    return { sent: true, provider: 'smtp' };
  }

  if (process.env.NODE_ENV === 'production') throw new Error('Email provider is not configured. Add BREVO_API_KEY or SMTP variables.');
  console.log(`[DEV EMAIL] Verification code for ${to}: ${code}`);
  return { sent: false, provider: 'dev-log' };
}
function createEmailVerification(db, userId, email) {
  db.emailVerifications = db.emailVerifications || [];
  db.emailVerifications = db.emailVerifications.filter(v => !(v.userId === userId && !v.usedAt));
  const code = verificationCode();
  const record = { id: id('ev'), userId, email, codeHash: hashPassword(code), attempts: 0, createdAt: now(), expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(), usedAt: null };
  db.emailVerifications.push(record);
  return code;
}

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
      const rawEmail = String(body.email || '').trim();
      const bypassEmailVerification = isEmailTestBypass(rawEmail);
      const normalizedEmail = normalizeEmail(rawEmail);
      if (displayName.length < 2) return error(res, 400, 'Display name must be at least 2 characters.');
      if (!bypassEmailVerification && !validEmail(normalizedEmail)) return error(res, 400, 'Enter a valid email address.');
      if (!bypassEmailVerification && db.users.some(u => normalizeEmail(u.email) === normalizedEmail)) return error(res, 409, 'An account already exists with that email.');
      const authCode = await uniqueAuthCode(db);
      const password = password8();
      const userId = id('u');
      const email = bypassEmailVerification ? `test-${userId}@cipherdrop.local` : normalizedEmail;
      const user = { id: userId, displayName, email, emailVerified: bypassEmailVerification, emailVerifiedAt: bypassEmailVerification ? now() : null, authCode, passwordHash: hashPassword(password), avatar: String(body.avatar || '🕶️').trim().slice(0, 4) || '🕶️', status: 'New anonymous inbox.', createdAt: now(), updatedAt: now() };
      db.users.push(user);
      let code = null;
      if (!bypassEmailVerification) code = createEmailVerification(db, user.id, email);
      const token = crypto.randomBytes(32).toString('hex');
      db.sessions.push({ id: id('sess'), token, userId: user.id, createdAt: now(), lastSeenAt: now(), expiresAt: new Date(Date.now()+1000*60*60*24*14).toISOString() });
      db.audit.push({ id: id('audit'), type: 'user.created', userId: user.id, createdAt: now() });
      if (bypassEmailVerification) db.audit.push({ id: id('audit'), type: 'email.test_bypass', userId: user.id, createdAt: now() });
      if (!bypassEmailVerification) {
        try { await sendVerificationEmail(email, code); }
        catch (e) { return error(res, 502, `Could not send verification email: ${e.message}`); }
      }
      await storage.save(db);
      const payload = { token, password, state: appState(db, user), emailBypass: bypassEmailVerification };
      if (!bypassEmailVerification && !emailProviderConfigured() && process.env.NODE_ENV !== 'production') payload.devVerificationCode = code;
      return send(res, 201, payload);
    }

    const user = requireUser(req, res, db);
    if (!user) return;

    if (req.method === 'GET' && pathname === '/api/state') { await storage.save(db); return send(res, 200, appState(db, user)); }
    if (req.method === 'POST' && pathname === '/api/logout') {
      const token = getToken(req);
      db.sessions = db.sessions.filter(s => s.token !== token);
      await storage.save(db); return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && pathname === '/api/email/send-verification') {
      if (user.emailVerified) return send(res, 200, { ok: true, alreadyVerified: true, state: appState(db, user) });
      if (!validEmail(user.email)) return error(res, 400, 'This account has no valid email address.');
      const recent = (db.emailVerifications || []).find(v => v.userId === user.id && !v.usedAt && Date.now() - new Date(v.createdAt).getTime() < 60 * 1000);
      if (recent) return error(res, 429, 'Please wait at least 60 seconds before requesting another code.');
      const code = createEmailVerification(db, user.id, user.email);
      try { await sendVerificationEmail(user.email, code); }
      catch (e) { return error(res, 502, `Could not send verification email: ${e.message}`); }
      await storage.save(db);
      const payload = { ok: true, state: appState(db, user) };
      if (!emailProviderConfigured() && process.env.NODE_ENV !== 'production') payload.devVerificationCode = code;
      return send(res, 200, payload);
    }
    if (req.method === 'POST' && pathname === '/api/email/verify') {
      const body = await parseBody(req);
      const code = String(body.code || '').trim();
      if (!/^\d{6}$/.test(code)) return error(res, 400, 'Enter the 6 digit email verification code.');
      const records = (db.emailVerifications || []).filter(v => v.userId === user.id && !v.usedAt).sort((a,b) => b.createdAt.localeCompare(a.createdAt));
      const record = records[0];
      if (!record) return error(res, 404, 'No active verification code. Request a new one.');
      if (new Date(record.expiresAt) < new Date()) return error(res, 410, 'Verification code expired. Request a new one.');
      if (record.attempts >= 5) return error(res, 429, 'Too many attempts. Request a new code.');
      record.attempts += 1;
      if (!verifyPassword(code, record.codeHash)) { await storage.save(db); return error(res, 400, 'Invalid verification code.'); }
      record.usedAt = now();
      user.emailVerified = true;
      user.emailVerifiedAt = now();
      user.updatedAt = now();
      db.audit.push({ id: id('audit'), type: 'email.verified', userId: user.id, createdAt: now() });
      await storage.save(db);
      return send(res, 200, appState(db, user));
    }
    if (!user.emailVerified) return error(res, 403, 'Please verify your email before using CipherDrop.');
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
