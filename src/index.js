const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3007;
const BASE = '/ftdailyreport';
const RP_ID = process.env.RP_ID || 'app-ai.xvps.jp';
const RP_ORIGIN = process.env.RP_ORIGIN || 'https://app-ai.xvps.jp';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' }
}));

// Middleware
function requireAuth(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: 'ログインが必要です' });
  next();
}
function requireAdmin(req, res, next) {
  if (req.session?.user?.role !== 'admin') return res.status(403).json({ error: '管理者権限が必要です' });
  next();
}

// === Pages ===
app.get(`${BASE}/`, (req, res) => {
  if (!req.session?.user) return res.redirect(`${BASE}/login`);
  res.sendFile(path.join(__dirname, 'views', 'app.html'));
});
app.get(`${BASE}/login`, (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));

// === Auth ===
app.post(`${BASE}/api/auth/login`, (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'メールアドレスとパスワードを入力してください' });
  const user = db.authenticateUser(email, password);
  if (!user) return res.status(401).json({ error: 'メールアドレスまたはパスワードが正しくありません' });
  req.session.user = user;
  res.json({ success: true, user });
});
app.get(`${BASE}/api/auth/me`, (req, res) => {
  res.json(req.session?.user ? { logged_in: true, user: req.session.user } : { logged_in: false });
});
app.post(`${BASE}/api/auth/logout`, (req, res) => { req.session.destroy(); res.json({ success: true }); });

// === Passkey Registration ===
app.post(`${BASE}/api/passkey/register-options`, requireAuth, async (req, res) => {
  try {
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    const user = req.session.user;
    const existingKeys = db.getPasskeysByUser(user.id);
    const options = await generateRegistrationOptions({
      rpName: 'FT Daily Report', rpID: RP_ID,
      userID: new TextEncoder().encode(String(user.id)),
      userName: user.email, userDisplayName: user.display_name,
      excludeCredentials: existingKeys.map(k => ({ id: k.credential_id, type: 'public-key' })),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' }
    });
    req.session.passkeyChallenge = options.challenge;
    res.json(options);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post(`${BASE}/api/passkey/register-verify`, requireAuth, async (req, res) => {
  try {
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: req.session.passkeyChallenge,
      expectedOrigin: RP_ORIGIN, expectedRPID: RP_ID
    });
    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;
      db.savePasskey(req.session.user.id,
        Buffer.from(credential.id).toString('base64url'),
        Buffer.from(credential.publicKey).toString('base64'),
        credential.counter,
        req.body.response?.transports || []);
      res.json({ success: true });
    } else {
      res.status(400).json({ error: '検証に失敗しました' });
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// === Passkey Authentication ===
app.post(`${BASE}/api/passkey/auth-options`, async (req, res) => {
  try {
    const { generateAuthenticationOptions } = await import('@simplewebauthn/server');
    const options = await generateAuthenticationOptions({ rpID: RP_ID, userVerification: 'preferred' });
    req.session.passkeyChallenge = options.challenge;
    res.json(options);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post(`${BASE}/api/passkey/auth-verify`, async (req, res) => {
  try {
    const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');
    const credId = req.body.id;
    const passkey = db.getPasskeyByCredentialId(credId);
    if (!passkey) return res.status(400).json({ error: 'パスキーが見つかりません' });
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: req.session.passkeyChallenge,
      expectedOrigin: RP_ORIGIN, expectedRPID: RP_ID,
      credential: {
        id: passkey.credential_id,
        publicKey: Buffer.from(passkey.public_key, 'base64'),
        counter: passkey.counter
      }
    });
    if (verification.verified) {
      db.updatePasskeyCounter(credId, verification.authenticationInfo.newCounter);
      const user = db.getUser(passkey.user_id);
      if (!user || !user.active) return res.status(401).json({ error: 'アカウントが無効です' });
      req.session.user = { id: user.id, email: user.email, display_name: user.display_name, role: user.role };
      res.json({ success: true, user: req.session.user });
    } else {
      res.status(400).json({ error: '認証に失敗しました' });
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// === Job Numbers ===
app.get(`${BASE}/api/job-numbers`, requireAuth, (req, res) => {
  const q = req.query.q;
  res.json(q ? db.searchJobNumbers(q) : db.listJobNumbers(req.session.user.role === 'admin'));
});
app.post(`${BASE}/api/job-numbers`, requireAuth, requireAdmin, (req, res) => {
  try { db.createJobNumber(req.body.code, req.body.name); res.json({ success: true }); }
  catch (e) { res.status(400).json({ error: e.message.includes('UNIQUE') ? '工番コード重複' : e.message }); }
});
app.put(`${BASE}/api/job-numbers/:id`, requireAuth, requireAdmin, (req, res) => {
  db.updateJobNumber(req.params.id, req.body); res.json({ success: true });
});
app.delete(`${BASE}/api/job-numbers/:id`, requireAuth, requireAdmin, (req, res) => {
  db.deleteJobNumber(req.params.id); res.json({ success: true });
});

// === Reports ===
app.post(`${BASE}/api/reports`, requireAuth, (req, res) => {
  try {
    const id = db.createReport(req.session.user.id, req.body);
    res.json({ success: true, id });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get(`${BASE}/api/reports`, requireAuth, (req, res) => {
  const reports = db.listReportsByUser(req.session.user.id, parseInt(req.query.limit) || 50, parseInt(req.query.offset) || 0);
  res.json(reports);
});

app.get(`${BASE}/api/reports/:id`, requireAuth, (req, res) => {
  const r = db.getReport(req.params.id);
  if (!r) return res.status(404).json({ error: '日報が見つかりません' });
  if (r.user_id !== req.session.user.id && req.session.user.role !== 'admin') return res.status(403).json({ error: '権限がありません' });
  res.json(r);
});

app.put(`${BASE}/api/reports/:id`, requireAuth, (req, res) => {
  const r = db.getReport(req.params.id);
  if (!r) return res.status(404).json({ error: '日報が見つかりません' });
  if (r.user_id !== req.session.user.id && req.session.user.role !== 'admin') return res.status(403).json({ error: '権限がありません' });
  if (r.status === 'approved') return res.status(400).json({ error: '承認済みの日報は編集できません' });
  const updated = db.updateReport(req.params.id, req.session.user.id, req.body);
  res.json({ success: true, report: updated });
});

app.get(`${BASE}/api/reports/:id/history`, requireAuth, (req, res) => {
  res.json(db.getReportHistory(req.params.id));
});

// === Admin: Pending / Approve ===
app.get(`${BASE}/api/admin/pending`, requireAuth, requireAdmin, (req, res) => {
  res.json(db.listPendingReports());
});

app.post(`${BASE}/api/admin/approve`, requireAuth, requireAdmin, (req, res) => {
  const { report_ids } = req.body;
  if (!report_ids || !report_ids.length) return res.status(400).json({ error: '日報IDを指定してください' });
  const n = db.approveMultiple(report_ids, req.session.user.id);
  res.json({ success: true, approved: n });
});

// === Admin: CSV ===
app.get(`${BASE}/api/admin/csv`, requireAuth, requireAdmin, (req, res) => {
  const { start, end } = req.query;
  if (!start || !end) return res.status(400).json({ error: '期間を指定してください' });
  const rows = db.exportApprovedCSV(start, end);
  const header = '報告日,報告者名,工番,作業内容（工場）,作業内容（営業・工務）,勤怠1,勤怠2,図面番号,部品番号,詳細,承認日時,承認者\n';
  const csv = header + rows.map(r =>
    [r.report_date, r.reporter_name, r.job_code, r.work_factory, r.work_office,
     r.attendance1, r.attendance2, r.drawing_number, r.part_number, r.detail,
     r.approved_at, r.approver_name].map(v => `"${(v == null ? '' : String(v)).replace(/"/g, '""')}"`).join(',')
  ).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="daily_report_${start}_${end}.csv"`);
  res.send('\ufeff' + csv);
});

// === Admin: Users ===
app.get(`${BASE}/api/admin/users`, requireAuth, requireAdmin, (req, res) => res.json(db.listUsers()));
app.post(`${BASE}/api/admin/users`, requireAuth, requireAdmin, (req, res) => {
  try {
    const { email, password, display_name, role } = req.body;
    if (!email || !password || !display_name) return res.status(400).json({ error: '全項目を入力してください' });
    db.createUser(email, password, display_name, role || 'reporter');
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message.includes('UNIQUE') ? 'メールアドレス重複' : e.message }); }
});
app.put(`${BASE}/api/admin/users/:id`, requireAuth, requireAdmin, (req, res) => {
  db.updateUser(req.params.id, req.body); res.json({ success: true });
});

// Init
db.getDb();
app.listen(PORT, '0.0.0.0', () => console.log(`FT Daily Report on http://0.0.0.0:${PORT}${BASE}/`));
