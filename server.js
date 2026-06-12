require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { run, get, all, initDatabase } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret_change_me';
const DB_PATH = process.env.DB_PATH || './database.db';
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

if (JWT_SECRET === 'default_secret_change_me') {
  console.warn('⚠️  تحذير: JWT_SECRET غير معرّف في .env — استخدم قيمة عشوائية قوية!');
}

// إنشاء مجلد التحميلات
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// إعداد Multer للملفات مع فلترة الأنواع
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp|mp4|webm|mov|avi/i;
    if (allowed.test(path.extname(file.originalname))) cb(null, true);
    else cb(new Error('نوع الملف غير مسموح'));
  }
});

// Middleware
app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));

// تقديم الملفات الثابتة (HTML/CSS/JS)
app.use(express.static(__dirname));

// ───── Helpers ─────
function safeUnlink(relUrl) {
  try {
    if (!relUrl || !relUrl.startsWith('/uploads/')) return;
    const filename = path.basename(relUrl);
    const full = path.join(UPLOAD_DIR, filename);
    if (fs.existsSync(full)) fs.unlinkSync(full);
  } catch (e) { console.error('unlink err:', e.message); }
}

// ───── Auth Middleware ─────
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'يجب تسجيل الدخول' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'توكن غير صالح' });
    req.user = user;
    next();
  });
}

async function requireCoach(req, res, next) {
  try {
    const user = await get('SELECT role FROM users WHERE id = ?', [req.user.id]);
    if (!user || (user.role !== 'coach' && user.role !== 'admin')) {
      return res.status(403).json({ error: 'صلاحيات غير كافية' });
    }
    req.userRole = user.role;
    next();
  } catch (err) { res.status(500).json({ error: err.message }); }
}

async function requireAdmin(req, res, next) {
  try {
    const user = await get('SELECT role FROM users WHERE id = ?', [req.user.id]);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'صلاحيات المدير فقط' });
    }
    next();
  } catch (err) { res.status(500).json({ error: err.message }); }
}

// التحقق من صلاحية معينة للمدرب (admin يتجاوز دائماً)
function requirePermission(permKey) {
  return async (req, res, next) => {
    try {
      if (req.userRole === 'admin') return next();
      const coach = await get('SELECT id FROM coaches WHERE user_id = ?', [req.user.id]);
      if (!coach) return res.status(403).json({ error: 'مدرب غير مسجل' });
      const perms = await get('SELECT * FROM permissions WHERE coach_id = ?', [coach.id]);
      if (!perms || !perms[permKey]) {
        return res.status(403).json({ error: 'ليس لديك هذه الصلاحية' });
      }
      next();
    } catch (err) { res.status(500).json({ error: err.message }); }
  };
}

// بسيط: rate limit لتسجيل الدخول (في الذاكرة)
const loginAttempts = new Map();
function loginRateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const rec = loginAttempts.get(ip) || { count: 0, resetAt: now + 15 * 60 * 1000 };
  if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + 15 * 60 * 1000; }
  rec.count++;
  loginAttempts.set(ip, rec);
  if (rec.count > 10) {
    return res.status(429).json({ error: 'محاولات كثيرة، حاول بعد 15 دقيقة' });
  }
  next();
}

// ═══════════════════════════════════════════════════════════
// المصادقة
// ═══════════════════════════════════════════════════════════

app.post('/api/auth/login', loginRateLimit, async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) {
      return res.status(400).json({ error: 'رقم الجوال وكلمة المرور مطلوبان' });
    }
    const user = await get('SELECT * FROM users WHERE phone = ?', [phone]);
    if (!user) return res.status(401).json({ error: 'رقم الجوال أو كلمة المرور غير صحيحة' });
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'رقم الجوال أو كلمة المرور غير صحيحة' });

    const token = jwt.sign(
      { id: user.id, name: user.name, phone: user.phone, role: user.role },
      JWT_SECRET, { expiresIn: '7d' }
    );
    res.json({ token, user: { id: user.id, name: user.name, phone: user.phone, role: user.role } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, password } = req.body;
    if (!name || !phone || !password) return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    if (password.length < 6) return res.status(400).json({ error: 'كلمة المرور قصيرة (6 أحرف على الأقل)' });
    if (!/^[0-9+\-\s]{7,20}$/.test(phone)) return res.status(400).json({ error: 'رقم جوال غير صالح' });

    const existing = await get('SELECT id FROM users WHERE phone = ?', [phone]);
    if (existing) return res.status(400).json({ error: 'رقم الجوال مستخدم بالفعل' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await run(
      `INSERT INTO users (name, phone, password_hash, role) VALUES (?, ?, ?, 'user')`,
      [name.trim(), phone.trim(), hashedPassword]
    );
    res.status(201).json({ id: result.id, message: 'تم إنشاء الحساب بنجاح' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await get('SELECT id, name, phone, role FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
    let permissions = null;
    if (user.role === 'coach') {
      const coach = await get('SELECT id FROM coaches WHERE user_id = ?', [user.id]);
      if (coach) permissions = await get('SELECT * FROM permissions WHERE coach_id = ?', [coach.id]);
    }
    res.json({ ...user, permissions });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// إدارة المستخدمين (للمدير)
// ═══════════════════════════════════════════════════════════

app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const rows = await all('SELECT id, name, phone, role, created_at FROM users ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/coaches', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, phone, password, bio } = req.body;
    if (!name || !phone || !password) return res.status(400).json({ error: 'الاسم ورقم الجوال وكلمة المرور مطلوبة' });
    const existing = await get('SELECT id FROM users WHERE phone = ?', [phone]);
    if (existing) return res.status(400).json({ error: 'رقم الجوال مستخدم بالفعل' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const userResult = await run(
      `INSERT INTO users (name, phone, password_hash, role) VALUES (?, ?, ?, 'coach')`,
      [name, phone, hashedPassword]
    );
    const coachResult = await run(
      `INSERT INTO coaches (user_id, bio) VALUES (?, ?)`,
      [userResult.id, bio || '']
    );
    await run(
      `INSERT INTO permissions (coach_id, can_add_media, can_delete_media, can_edit_media, can_pin_media, can_manage_stars, can_manage_votes)
       VALUES (?, 1, 1, 1, 1, 1, 1)`,
      [coachResult.id]
    );
    res.status(201).json({ id: userResult.id, message: 'تم إنشاء المدرب بنجاح' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/coaches/:id/permissions', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { can_add_media, can_delete_media, can_edit_media, can_pin_media, can_manage_stars, can_manage_votes } = req.body;
    await run(
      `UPDATE permissions SET can_add_media=?, can_delete_media=?, can_edit_media=?,
         can_pin_media=?, can_manage_stars=?, can_manage_votes=? WHERE coach_id=?`,
      [can_add_media?1:0, can_delete_media?1:0, can_edit_media?1:0,
       can_pin_media?1:0, can_manage_stars?1:0, can_manage_votes?1:0, req.params.id]
    );
    res.json({ message: 'تم تحديث الصلاحيات' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    if (Number(req.params.id) === Number(req.user.id)) {
      return res.status(400).json({ error: 'لا يمكنك حذف حسابك الخاص' });
    }
    await run('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.json({ message: 'تم حذف المستخدم' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// التسجيلات
// ═══════════════════════════════════════════════════════════

app.post('/api/registrations', async (req, res) => {
  try {
    const { full_name, phone, dob } = req.body;
    if (!full_name || !phone || !dob) return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    const result = await run(
      `INSERT INTO registrations (full_name, phone, dob) VALUES (?, ?, ?)`,
      [full_name.trim(), phone.trim(), dob]
    );
    res.status(201).json({ id: result.id, message: 'تم إرسال الطلب بنجاح' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/registrations/pending', authenticateToken, requireCoach, async (req, res) => {
  try {
    const rows = await all('SELECT * FROM registrations WHERE status = ? ORDER BY created_at DESC', ['pending']);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/registrations', authenticateToken, requireCoach, async (req, res) => {
  try {
    const rows = await all('SELECT * FROM registrations ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/registrations/:id/approve', authenticateToken, requireCoach, async (req, res) => {
  try {
    const reg = await get('SELECT * FROM registrations WHERE id = ?', [req.params.id]);
    if (!reg) return res.status(404).json({ error: 'الطلب غير موجود' });
    if (reg.status === 'approved') return res.status(400).json({ error: 'الطلب مقبول مسبقاً' });

    await run('UPDATE registrations SET status = ? WHERE id = ?', ['approved', req.params.id]);
    const exists = await get('SELECT id FROM approved_players WHERE registration_id = ?', [reg.id]);
    if (!exists) {
      await run(
        `INSERT INTO approved_players (registration_id, full_name, phone, dob) VALUES (?, ?, ?, ?)`,
        [reg.id, reg.full_name, reg.phone, reg.dob]
      );
    }
    res.json({ message: 'تم قبول الطلب بنجاح' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/registrations/:id/reject', authenticateToken, requireCoach, async (req, res) => {
  try {
    await run('UPDATE registrations SET status = ? WHERE id = ?', ['rejected', req.params.id]);
    res.json({ message: 'تم رفض الطلب' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// المقبولين
// ═══════════════════════════════════════════════════════════

app.get('/api/approved-players', async (req, res) => {
  try {
    const rows = await all('SELECT * FROM approved_players ORDER BY approved_at DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/approved-players/:id', authenticateToken, requireCoach, async (req, res) => {
  try {
    await run('DELETE FROM approved_players WHERE id = ?', [req.params.id]);
    res.json({ message: 'تم حذف اللاعب' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// التصويت
// ═══════════════════════════════════════════════════════════

app.get('/api/nominees', async (req, res) => {
  try {
    const rows = await all(`
      SELECT n.*, COUNT(v.id) as votes_count
      FROM nominees n
      LEFT JOIN votes v ON n.id = v.nominee_id
      GROUP BY n.id
      ORDER BY votes_count DESC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/nominees', authenticateToken, requireCoach, requirePermission('can_manage_votes'), upload.single('photo'), async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'الاسم مطلوب' });
    const photoUrl = req.file ? `/uploads/${req.file.filename}` : null;
    const result = await run(
      `INSERT INTO nominees (name, photo_url) VALUES (?, ?)`,
      [name, photoUrl]
    );
    res.status(201).json({ id: result.id, message: 'تم إضافة المرشح' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/nominees/:id', authenticateToken, requireCoach, requirePermission('can_manage_votes'), async (req, res) => {
  try {
    const nominee = await get('SELECT photo_url FROM nominees WHERE id = ?', [req.params.id]);
    await run('DELETE FROM votes WHERE nominee_id = ?', [req.params.id]);
    await run('DELETE FROM nominees WHERE id = ?', [req.params.id]);
    if (nominee) safeUnlink(nominee.photo_url);
    res.json({ message: 'تم حذف المرشح' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/votes', authenticateToken, async (req, res) => {
  try {
    const { nominee_id } = req.body;
    if (!nominee_id) return res.status(400).json({ error: 'المرشح مطلوب' });
    const user_id = req.user.id;
    const existing = await get('SELECT id FROM votes WHERE user_id = ?', [user_id]);
    if (existing) return res.status(400).json({ error: 'لقد قمت بالتصويت مسبقاً', voted: true });
    await run('INSERT INTO votes (user_id, nominee_id) VALUES (?, ?)', [user_id, nominee_id]);
    res.json({ message: 'تم التصويت بنجاح' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/votes/my-vote', authenticateToken, async (req, res) => {
  try {
    await run('DELETE FROM votes WHERE user_id = ?', [req.user.id]);
    res.json({ message: 'تم إلغاء التصويت' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/votes/my-vote', authenticateToken, async (req, res) => {
  try {
    const vote = await get('SELECT * FROM votes WHERE user_id = ?', [req.user.id]);
    res.json({ voted: !!vote, vote });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// نجوم الأسبوع
// ═══════════════════════════════════════════════════════════

app.get('/api/weekly-stars', async (req, res) => {
  try {
    const rows = await all(`
      SELECT * FROM weekly_stars
      WHERE week_start = (SELECT MAX(week_start) FROM weekly_stars)
      ORDER BY category
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/weekly-stars', authenticateToken, requireCoach, requirePermission('can_manage_stars'), upload.single('photo'), async (req, res) => {
  try {
    const { category, player_name, week_start } = req.body;
    if (!category || !player_name || !week_start) return res.status(400).json({ error: 'الحقول ناقصة' });
    const photoUrl = req.file ? `/uploads/${req.file.filename}` : req.body.photo_url;
    await run('DELETE FROM weekly_stars WHERE category = ? AND week_start = ?', [category, week_start]);
    const result = await run(
      `INSERT INTO weekly_stars (category, player_name, photo_url, week_start, created_by) VALUES (?, ?, ?, ?, ?)`,
      [category, player_name, photoUrl, week_start, req.user.id]
    );
    res.json({ id: result.id, message: 'تم تحديث نجم الأسبوع' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// الوسائط
// ═══════════════════════════════════════════════════════════

app.get('/api/media/photos', async (req, res) => {
  try {
    const rows = await all('SELECT * FROM media_photos ORDER BY is_pinned DESC, created_at DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/media/photos', authenticateToken, requireCoach, requirePermission('can_add_media'), upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'الصورة مطلوبة' });
    const { title, is_pinned } = req.body;
    const url = `/uploads/${req.file.filename}`;
    const result = await run(
      `INSERT INTO media_photos (title, url, is_pinned, created_by) VALUES (?, ?, ?, ?)`,
      [title || 'صورة', url, is_pinned ? 1 : 0, req.user.id]
    );
    res.status(201).json({ id: result.id, url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/media/photos/:id', authenticateToken, requireCoach, requirePermission('can_delete_media'), async (req, res) => {
  try {
    const row = await get('SELECT url FROM media_photos WHERE id = ?', [req.params.id]);
    await run('DELETE FROM media_photos WHERE id = ?', [req.params.id]);
    if (row) safeUnlink(row.url);
    res.json({ message: 'تم حذف الصورة' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/media/videos', async (req, res) => {
  try {
    const rows = await all('SELECT * FROM media_videos ORDER BY is_pinned DESC, created_at DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/media/videos', authenticateToken, requireCoach, requirePermission('can_add_media'), upload.single('video'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'الفيديو مطلوب' });
    const { title, is_pinned } = req.body;
    const url = `/uploads/${req.file.filename}`;
    const result = await run(
      `INSERT INTO media_videos (title, url, is_pinned, created_by) VALUES (?, ?, ?, ?)`,
      [title || 'فيديو', url, is_pinned ? 1 : 0, req.user.id]
    );
    res.status(201).json({ id: result.id, url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/media/videos/:id', authenticateToken, requireCoach, requirePermission('can_delete_media'), async (req, res) => {
  try {
    const row = await get('SELECT url FROM media_videos WHERE id = ?', [req.params.id]);
    await run('DELETE FROM media_videos WHERE id = ?', [req.params.id]);
    if (row) safeUnlink(row.url);
    res.json({ message: 'تم حذف الفيديو' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/media/:type/:id/pin', authenticateToken, requireCoach, requirePermission('can_pin_media'), async (req, res) => {
  try {
    const { type, id } = req.params;
    const { is_pinned } = req.body;
    if (type !== 'photos' && type !== 'videos') return res.status(400).json({ error: 'نوع غير صالح' });
    const table = type === 'photos' ? 'media_photos' : 'media_videos';
    await run(`UPDATE ${table} SET is_pinned = ? WHERE id = ?`, [is_pinned ? 1 : 0, id]);
    res.json({ message: is_pinned ? 'تم التثبيت' : 'تم إلغاء التثبيت' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// النتائج
// ═══════════════════════════════════════════════════════════

app.get('/api/results', async (req, res) => {
  try {
    const rows = await all('SELECT * FROM results ORDER BY match_date DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/results', authenticateToken, requireCoach, async (req, res) => {
  try {
    const { match_date, match_name, score, note } = req.body;
    if (!match_date || !match_name || !score) return res.status(400).json({ error: 'الحقول ناقصة' });
    const result = await run(
      `INSERT INTO results (match_date, match_name, score, note) VALUES (?, ?, ?, ?)`,
      [match_date, match_name, score, note || '']
    );
    res.status(201).json({ id: result.id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/results/:id', authenticateToken, requireCoach, async (req, res) => {
  try {
    await run('DELETE FROM results WHERE id = ?', [req.params.id]);
    res.json({ message: 'تم حذف النتيجة' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// Multer error handler
// ═══════════════════════════════════════════════════════════
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.message });
  }
  if (err) return res.status(400).json({ error: err.message });
  next();
});

// Fallback: للصفحات غير الـAPI أرجع index.html (لدعم التنقل المباشر)
app.get(/^\/(?!api|uploads).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'), (err) => {
    if (err) res.status(404).send('Not Found');
  });
});

// ═══════════════════════════════════════════════════════════
// تشغيل الخادم
// ═══════════════════════════════════════════════════════════
async function startServer() {
  await initDatabase();
  app.listen(PORT, () => {
    console.log(`🚀 الخادم يعمل على http://localhost:${PORT}`);
    console.log(`📁 مجلد التحميلات: ${path.resolve(UPLOAD_DIR)}`);
    console.log(`🗄️  قاعدة البيانات: ${path.resolve(DB_PATH)}`);
  });
}

startServer();
