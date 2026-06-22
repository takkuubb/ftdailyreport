const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, '..', 'ftdailyreport.db');
let db;

function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    initSchema();
  }
  return db;
}

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'reporter' CHECK(role IN ('reporter','admin')),
      employee_code TEXT NOT NULL DEFAULT '',
      department_code TEXT NOT NULL DEFAULT '',
      hourly_rate INTEGER NOT NULL DEFAULT 0,
      team TEXT NOT NULL DEFAULT '',
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS passkeys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      credential_id TEXT UNIQUE NOT NULL,
      public_key TEXT NOT NULL,
      counter INTEGER NOT NULL DEFAULT 0,
      transports TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS job_numbers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL DEFAULT '',
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      report_date TEXT NOT NULL,
      job_number_id INTEGER REFERENCES job_numbers(id),
      work_factory TEXT DEFAULT '',
      work_office TEXT DEFAULT '',
      attendance1 REAL DEFAULT 0,
      attendance2 REAL DEFAULT 0,
      drawing_number TEXT DEFAULT '',
      part_number TEXT DEFAULT '',
      detail TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved')),
      approved_at TEXT,
      approved_by INTEGER REFERENCES users(id),
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS report_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      report_id INTEGER NOT NULL REFERENCES reports(id),
      changed_by INTEGER NOT NULL REFERENCES users(id),
      changed_at TEXT DEFAULT (datetime('now')),
      changes TEXT NOT NULL DEFAULT '{}'
    );

    CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id);
    CREATE INDEX IF NOT EXISTS idx_reports_date ON reports(report_date);
    CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
    CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id);
    CREATE INDEX IF NOT EXISTS idx_passkeys_cred ON passkeys(credential_id);
  `);

  // Migrate: add new columns if missing
  const cols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
  if (!cols.includes('employee_code')) {
    db.exec("ALTER TABLE users ADD COLUMN employee_code TEXT NOT NULL DEFAULT ''");
    db.exec("ALTER TABLE users ADD COLUMN department_code TEXT NOT NULL DEFAULT ''");
    db.exec("ALTER TABLE users ADD COLUMN hourly_rate INTEGER NOT NULL DEFAULT 0");
    db.exec("ALTER TABLE users ADD COLUMN team TEXT NOT NULL DEFAULT ''");
    console.log('Migrated: added employee_code, department_code, hourly_rate, team to users');
  }

  // Seed admin if no users
  const cnt = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  if (cnt === 0) {
    const hash = bcrypt.hashSync('ftdaily2026', 10);
    db.prepare('INSERT INTO users (email, password_hash, display_name, role) VALUES (?,?,?,?)').run('admin@ft.local', hash, '管理者', 'admin');
    console.log('Created default admin: admin@ft.local / ftdaily2026');
  }
}

// === User functions ===
function authenticateUser(email, password) {
  const user = getDb().prepare('SELECT * FROM users WHERE email = ? AND active = 1').get(email);
  if (!user) return null;
  if (!bcrypt.compareSync(password, user.password_hash)) return null;
  return { id: user.id, email: user.email, display_name: user.display_name, role: user.role,
           employee_code: user.employee_code, department_code: user.department_code,
           hourly_rate: user.hourly_rate, team: user.team };
}

function getUser(id) {
  return getDb().prepare('SELECT id, email, display_name, role, employee_code, department_code, hourly_rate, team, active, created_at FROM users WHERE id = ?').get(id);
}

function listUsers() {
  return getDb().prepare('SELECT id, email, display_name, role, employee_code, department_code, hourly_rate, team, active, created_at FROM users ORDER BY id').all();
}

function createUser(email, password, displayName, role, extra) {
  const hash = bcrypt.hashSync(password, 10);
  const e = extra || {};
  return getDb().prepare('INSERT INTO users (email, password_hash, display_name, role, employee_code, department_code, hourly_rate, team) VALUES (?,?,?,?,?,?,?,?)').run(
    email, hash, displayName, role || 'reporter',
    e.employee_code || '', e.department_code || '', e.hourly_rate || 0, e.team || '');
}

function updateUser(id, data) {
  const d = getDb();
  if (data.password) {
    d.prepare("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?").run(bcrypt.hashSync(data.password, 10), id);
  }
  if (data.display_name !== undefined) d.prepare("UPDATE users SET display_name = ?, updated_at = datetime('now') WHERE id = ?").run(data.display_name, id);
  if (data.role !== undefined) d.prepare("UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?").run(data.role, id);
  if (data.active !== undefined) d.prepare("UPDATE users SET active = ?, updated_at = datetime('now') WHERE id = ?").run(data.active ? 1 : 0, id);
  if (data.employee_code !== undefined) d.prepare("UPDATE users SET employee_code = ?, updated_at = datetime('now') WHERE id = ?").run(data.employee_code, id);
  if (data.department_code !== undefined) d.prepare("UPDATE users SET department_code = ?, updated_at = datetime('now') WHERE id = ?").run(data.department_code, id);
  if (data.hourly_rate !== undefined) d.prepare("UPDATE users SET hourly_rate = ?, updated_at = datetime('now') WHERE id = ?").run(parseInt(data.hourly_rate) || 0, id);
  if (data.team !== undefined) d.prepare("UPDATE users SET team = ?, updated_at = datetime('now') WHERE id = ?").run(data.team, id);
}

// === Passkey functions ===
function getPasskeysByUser(userId) {
  return getDb().prepare('SELECT * FROM passkeys WHERE user_id = ?').all(userId);
}

function savePasskey(userId, credentialId, publicKey, counter, transports) {
  return getDb().prepare('INSERT INTO passkeys (user_id, credential_id, public_key, counter, transports) VALUES (?,?,?,?,?)').run(userId, credentialId, publicKey, counter, JSON.stringify(transports || []));
}

function getPasskeyByCredentialId(credentialId) {
  return getDb().prepare('SELECT * FROM passkeys WHERE credential_id = ?').get(credentialId);
}

function updatePasskeyCounter(credentialId, counter) {
  getDb().prepare('UPDATE passkeys SET counter = ? WHERE credential_id = ?').run(counter, credentialId);
}

// === Job Number functions ===
function listJobNumbers(includeInactive) {
  const q = includeInactive ? 'SELECT * FROM job_numbers ORDER BY code' : 'SELECT * FROM job_numbers WHERE active = 1 ORDER BY code';
  return getDb().prepare(q).all();
}

function searchJobNumbers(query) {
  return getDb().prepare("SELECT * FROM job_numbers WHERE active = 1 AND (code LIKE ? OR name LIKE ?) ORDER BY code LIMIT 20").all(`%${query}%`, `%${query}%`);
}

function createJobNumber(code, name) {
  return getDb().prepare('INSERT INTO job_numbers (code, name) VALUES (?,?)').run(code, name || '');
}

function updateJobNumber(id, data) {
  const d = getDb();
  if (data.code !== undefined) d.prepare('UPDATE job_numbers SET code = ? WHERE id = ?').run(data.code, id);
  if (data.name !== undefined) d.prepare('UPDATE job_numbers SET name = ? WHERE id = ?').run(data.name, id);
  if (data.active !== undefined) d.prepare('UPDATE job_numbers SET active = ? WHERE id = ?').run(data.active ? 1 : 0, id);
}

function deleteJobNumber(id) {
  getDb().prepare('DELETE FROM job_numbers WHERE id = ?').run(id);
}

// === Report functions ===
function createReport(userId, data) {
  const d = getDb();
  const r = d.prepare(`INSERT INTO reports (user_id, report_date, job_number_id, work_factory, work_office,
    attendance1, attendance2, drawing_number, part_number, detail)
    VALUES (?,?,?,?,?,?,?,?,?,?)`).run(
    userId, data.report_date, data.job_number_id || null,
    data.work_factory || '', data.work_office || '',
    data.attendance1 || 0, data.attendance2 || 0,
    data.drawing_number || '', data.part_number || '', data.detail || ''
  );
  return r.lastInsertRowid;
}

function getReport(id) {
  return getDb().prepare(`SELECT r.*, u.display_name as reporter_name,
    u.employee_code, u.department_code, u.hourly_rate, u.team,
    j.code as job_code, j.name as job_name,
    a.display_name as approver_name
    FROM reports r
    LEFT JOIN users u ON r.user_id = u.id
    LEFT JOIN job_numbers j ON r.job_number_id = j.id
    LEFT JOIN users a ON r.approved_by = a.id
    WHERE r.id = ?`).get(id);
}

function updateReport(id, userId, data) {
  const d = getDb();
  const old = getReport(id);
  if (!old || old.status === 'approved') return null;

  const changes = {};
  const fields = ['report_date', 'job_number_id', 'work_factory', 'work_office', 'attendance1', 'attendance2', 'drawing_number', 'part_number', 'detail'];
  for (const f of fields) {
    if (data[f] !== undefined && String(data[f]) !== String(old[f])) {
      changes[f] = { before: old[f], after: data[f] };
    }
  }

  if (Object.keys(changes).length === 0) return old;

  d.prepare(`UPDATE reports SET report_date=?, job_number_id=?, work_factory=?, work_office=?,
    attendance1=?, attendance2=?, drawing_number=?, part_number=?, detail=?, updated_at=datetime('now')
    WHERE id=?`).run(
    data.report_date || old.report_date, data.job_number_id !== undefined ? data.job_number_id : old.job_number_id,
    data.work_factory !== undefined ? data.work_factory : old.work_factory,
    data.work_office !== undefined ? data.work_office : old.work_office,
    data.attendance1 !== undefined ? data.attendance1 : old.attendance1,
    data.attendance2 !== undefined ? data.attendance2 : old.attendance2,
    data.drawing_number !== undefined ? data.drawing_number : old.drawing_number,
    data.part_number !== undefined ? data.part_number : old.part_number,
    data.detail !== undefined ? data.detail : old.detail,
    id
  );

  d.prepare('INSERT INTO report_history (report_id, changed_by, changes) VALUES (?,?,?)').run(id, userId, JSON.stringify(changes));
  return getReport(id);
}

function listReportsByUser(userId, limit, offset) {
  return getDb().prepare(`SELECT r.*, j.code as job_code, j.name as job_name
    FROM reports r LEFT JOIN job_numbers j ON r.job_number_id = j.id
    WHERE r.user_id = ? ORDER BY r.report_date DESC, r.created_at DESC LIMIT ? OFFSET ?`).all(userId, limit || 50, offset || 0);
}

function listPendingReports() {
  return getDb().prepare(`SELECT r.*, u.display_name as reporter_name, j.code as job_code, j.name as job_name
    FROM reports r
    LEFT JOIN users u ON r.user_id = u.id
    LEFT JOIN job_numbers j ON r.job_number_id = j.id
    WHERE r.status = 'pending'
    ORDER BY r.report_date DESC, r.created_at DESC`).all();
}

function approveReport(reportId, adminUserId) {
  return getDb().prepare("UPDATE reports SET status = 'approved', approved_at = datetime('now'), approved_by = ? WHERE id = ? AND status = 'pending'").run(adminUserId, reportId);
}

function approveMultiple(reportIds, adminUserId) {
  const d = getDb();
  const stmt = d.prepare("UPDATE reports SET status = 'approved', approved_at = datetime('now'), approved_by = ? WHERE id = ? AND status = 'pending'");
  const tx = d.transaction((ids) => { let n = 0; for (const id of ids) { n += stmt.run(adminUserId, id).changes; } return n; });
  return tx(reportIds);
}

function getReportHistory(reportId) {
  return getDb().prepare(`SELECT rh.*, u.display_name as changer_name
    FROM report_history rh LEFT JOIN users u ON rh.changed_by = u.id
    WHERE rh.report_id = ? ORDER BY rh.changed_at DESC`).all(reportId);
}

// CSV export with full 42-column format
function exportApprovedCSV(startDate, endDate) {
  return getDb().prepare(`SELECT r.id, r.report_date,
    u.display_name as reporter_name, u.employee_code, u.department_code, u.hourly_rate, u.team,
    j.code as job_code, j.name as job_name,
    r.work_factory, r.work_office,
    r.attendance1, r.attendance2,
    r.drawing_number, r.part_number, r.detail,
    r.approved_at, a.display_name as approver_name
    FROM reports r
    LEFT JOIN users u ON r.user_id = u.id
    LEFT JOIN job_numbers j ON r.job_number_id = j.id
    LEFT JOIN users a ON r.approved_by = a.id
    WHERE r.status = 'approved' AND r.report_date >= ? AND r.report_date <= ?
    ORDER BY r.report_date, u.display_name`).all(startDate, endDate);
}

// Admin report: all reports with filters
function listAllReports(filters) {
  const d = getDb();
  const conds = [];
  const params = [];
  if (filters.start) { conds.push('r.report_date >= ?'); params.push(filters.start); }
  if (filters.end) { conds.push('r.report_date <= ?'); params.push(filters.end); }
  if (filters.user_id) { conds.push('r.user_id = ?'); params.push(filters.user_id); }
  if (filters.status) { conds.push('r.status = ?'); params.push(filters.status); }
  if (filters.job_code) { conds.push('j.code LIKE ?'); params.push('%' + filters.job_code + '%'); }
  if (filters.work_factory) { conds.push('r.work_factory = ?'); params.push(filters.work_factory); }
  if (filters.work_office) { conds.push('r.work_office = ?'); params.push(filters.work_office); }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const rows = d.prepare(`SELECT r.*, u.display_name as reporter_name, u.employee_code, u.department_code, u.team,
    j.code as job_code, j.name as job_name, a.display_name as approver_name
    FROM reports r
    LEFT JOIN users u ON r.user_id = u.id
    LEFT JOIN job_numbers j ON r.job_number_id = j.id
    LEFT JOIN users a ON r.approved_by = a.id
    ${where}
    ORDER BY r.report_date DESC, r.created_at DESC
    LIMIT 500`).all(...params);
  return rows;
}

function getReportStats(filters) {
  const d = getDb();
  const conds = [];
  const params = [];
  if (filters.start) { conds.push('r.report_date >= ?'); params.push(filters.start); }
  if (filters.end) { conds.push('r.report_date <= ?'); params.push(filters.end); }
  if (filters.user_id) { conds.push('r.user_id = ?'); params.push(filters.user_id); }
  if (filters.status) { conds.push('r.status = ?'); params.push(filters.status); }
  if (filters.job_code) { conds.push('j.code LIKE ?'); params.push('%' + filters.job_code + '%'); }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const row = d.prepare(`SELECT COUNT(*) as total,
    SUM(CASE WHEN r.status='approved' THEN 1 ELSE 0 END) as approved,
    SUM(CASE WHEN r.status='pending' THEN 1 ELSE 0 END) as pending,
    SUM(r.attendance1) as total_att1, SUM(r.attendance2) as total_att2,
    COUNT(DISTINCT r.user_id) as reporter_count,
    COUNT(DISTINCT r.report_date) as date_count
    FROM reports r
    LEFT JOIN job_numbers j ON r.job_number_id = j.id
    ${where}`).get(...params);
  return row;
}

module.exports = {
  getDb, authenticateUser, getUser, listUsers, createUser, updateUser,
  getPasskeysByUser, savePasskey, getPasskeyByCredentialId, updatePasskeyCounter,
  listJobNumbers, searchJobNumbers, createJobNumber, updateJobNumber, deleteJobNumber,
  createReport, getReport, updateReport, listReportsByUser, listPendingReports,
  approveReport, approveMultiple, getReportHistory, exportApprovedCSV,
  listAllReports, getReportStats
};
