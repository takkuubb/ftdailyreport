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

// === Admin: CSV (42-column format) ===
app.get(`${BASE}/api/admin/csv`, requireAuth, requireAdmin, (req, res) => {
  const { start, end } = req.query;
  if (!start || !end) return res.status(400).json({ error: '期間を指定してください' });
  const rows = db.exportApprovedCSV(start, end);

  // 42 columns header
  const header = [
    '伝票番号','入力方式','日付','従業員コード','従業員名',
    'スタンプ1','スタンプ2','スタンプ3','第2区分','金額端数',
    '承認','仮伝票','合計金額','システム予約','システム予約','システム予約','システム予約',
    '工事ｺｰﾄﾞ','工事ｺｰﾄﾞ枝番','工事名',
    '勤怠項目1','勤怠項目2','勤怠項目3','勤怠項目4','勤怠項目5',
    '勤怠項目6','勤怠項目7','勤怠項目8','勤怠項目9','勤怠項目10',
    '手当コード','手当名','手当金額','明細合計金額',
    '工種コード','工種名','部門コード','部門名',
    '作業種類コード','作業種類名','備考','原価締'
  ];

  function splitJobCode(code) {
    if (!code) return ['', ''];
    // e.g. "122-037-00" → main="122-037", branch="00"
    const lastDash = code.lastIndexOf('-');
    if (lastDash <= 0) return [code, ''];
    return [code.substring(0, lastDash), code.substring(lastDash + 1)];
  }

  function buildBiko(r) {
    const parts = [];
    if (r.drawing_number) parts.push(r.drawing_number);
    if (r.part_number) parts.push(r.part_number);
    if (r.detail) parts.push(r.detail);
    return parts.join('/');
  }

  // 工事ｺｰﾄﾞ枝番が空白のものは除外
  const filtered = rows.filter(r => {
    const [, branch] = splitJobCode(r.job_code);
    return branch !== '';
  });

  const csvRows = filtered.map(r => {
    const [jobMain, jobBranch] = splitJobCode(r.job_code);
    return [
      '',                        // 伝票番号
      '',                        // 入力方式
      r.report_date || '',       // 日付
      r.employee_code || '',     // 従業員コード
      r.reporter_name || '',     // 従業員名
      '','','',                  // スタンプ1-3
      '',                        // 第2区分
      '',                        // 金額端数
      '',                        // 承認
      '',                        // 仮伝票
      '',                        // 合計金額
      '','','','',               // システム予約 x4
      jobMain,                   // 工事ｺｰﾄﾞ
      jobBranch,                 // 工事ｺｰﾄﾞ枝番
      r.job_name || '',          // 工事名
      r.attendance1 || '',       // 勤怠項目1
      '',                        // 勤怠項目2
      '','','','','','','','',   // 勤怠項目3-10
      '',                        // 手当コード
      '',                        // 手当名
      '',                        // 手当金額
      '',                        // 明細合計金額
      r.employee_code || '',     // 工種コード (= 従業員コード)
      '',                        // 工種名
      r.department_code || '',   // 部門コード
      '',                        // 部門名
      '',                        // 作業種類コード
      '',                        // 作業種類名
      buildBiko(r),              // 備考
      ''                         // 原価締
    ];
  });

  const esc = v => `"${(v == null ? '' : String(v)).replace(/"/g, '""')}"`;
  const csv = [header.map(esc).join(','), ...csvRows.map(row => row.map(esc).join(','))].join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="daily_report_${start}_${end}.csv"`);
  res.send('\ufeff' + csv);
});

// === Admin: Users ===
app.get(`${BASE}/api/admin/users`, requireAuth, requireAdmin, (req, res) => res.json(db.listUsers()));
app.post(`${BASE}/api/admin/users`, requireAuth, requireAdmin, (req, res) => {
  try {
    const { email, password, display_name, role, employee_code, department_code, hourly_rate, team } = req.body;
    if (!email || !password || !display_name) return res.status(400).json({ error: '全項目を入力してください' });
    db.createUser(email, password, display_name, role || 'reporter', { employee_code, department_code, hourly_rate, team });
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message.includes('UNIQUE') ? 'メールアドレス重複' : e.message }); }
});
app.put(`${BASE}/api/admin/users/:id`, requireAuth, requireAdmin, (req, res) => {
  db.updateUser(req.params.id, req.body); res.json({ success: true });
});

// Init
db.getDb();
app.listen(PORT, '0.0.0.0', () => console.log(`FT Daily Report on http://0.0.0.0:${PORT}${BASE}/`));
