const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = process.env.DB_PATH || './database.db';

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('❌ خطأ في فتح قاعدة البيانات:', err.message);
  } else {
    console.log('✅ تم الاتصال بقاعدة البيانات SQLite');
  }
});

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ id: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

async function initDatabase() {
  try {
    // جدول المستخدمين
    await run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user' CHECK(role IN ('user', 'coach', 'admin')),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // جدول المدربين
    await run(`
      CREATE TABLE IF NOT EXISTS coaches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        bio TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // جدول الصلاحيات
    await run(`
      CREATE TABLE IF NOT EXISTS permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        coach_id INTEGER UNIQUE NOT NULL,
        can_add_media INTEGER DEFAULT 1,
        can_delete_media INTEGER DEFAULT 1,
        can_edit_media INTEGER DEFAULT 1,
        can_pin_media INTEGER DEFAULT 1,
        can_manage_stars INTEGER DEFAULT 1,
        can_manage_votes INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (coach_id) REFERENCES coaches(id) ON DELETE CASCADE
      )
    `);

    // جدول طلبات الانضمام (بدون فئة)
    await run(`
      CREATE TABLE IF NOT EXISTS registrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        dob TEXT NOT NULL,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // جدول المقبولين (بدون فئة)
    await run(`
      CREATE TABLE IF NOT EXISTS approved_players (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        registration_id INTEGER UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        dob TEXT NOT NULL,
        approved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (registration_id) REFERENCES registrations(id) ON DELETE CASCADE
      )
    `);

    // جدول المرشحين للتصويت
    await run(`
      CREATE TABLE IF NOT EXISTS nominees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        photo_url TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // جدول الأصوات
    await run(`
      CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        nominee_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (nominee_id) REFERENCES nominees(id) ON DELETE CASCADE,
        UNIQUE(user_id, nominee_id)
      )
    `);

    // جدول نجوم الأسبوع (بدون فئة - يستخدم category للعرض فقط)
    await run(`
      CREATE TABLE IF NOT EXISTS weekly_stars (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL CHECK(category IN ('A', 'B')),
        player_name TEXT NOT NULL,
        photo_url TEXT,
        week_start DATE NOT NULL,
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // جدول الوسائط
    await run(`
      CREATE TABLE IF NOT EXISTS media_photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        url TEXT NOT NULL,
        is_pinned INTEGER DEFAULT 0,
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // جدول الفيديوهات
    await run(`
      CREATE TABLE IF NOT EXISTS media_videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        url TEXT NOT NULL,
        thumbnail TEXT,
        is_pinned INTEGER DEFAULT 0,
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // جدول النتائج
    await run(`
      CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_date TEXT NOT NULL,
        match_name TEXT NOT NULL,
        score TEXT NOT NULL,
        note TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // إنشاء المستخدم المدير الافتراضي
    const adminExists = await get('SELECT id FROM users WHERE role = ?', ['admin']);
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('adm-123321', 10);
      await run(`
        INSERT INTO users (name, phone, password_hash, role)
        VALUES (?, ?, ?, ?)
      `, ['مدير النظام', '0500000000', hashedPassword, 'admin']);
      console.log('✅ تم إنشاء حساب المدير الافتراضي: 0500000000 / adm-123321');
    }

    // إنشاء مدرب افتراضي
    const coachExists = await get('SELECT id FROM users WHERE phone = ?', ['0511111111']);
    if (!coachExists) {
      const hashedPassword = await bcrypt.hash('coach123', 10);
      const result = await run(`
        INSERT INTO users (name, phone, password_hash, role)
        VALUES (?, ?, ?, ?)
      `, ['مدرب رئيسي', '0511111111', hashedPassword, 'coach']);

      const coachResult = await run(`
        INSERT INTO coaches (user_id, bio)
        VALUES (?, ?)
      `, [result.id, 'مدرب أكاديمية أشبال الجديدة']);

      await run(`
        INSERT INTO permissions (coach_id, can_add_media, can_delete_media, can_edit_media, can_pin_media, can_manage_stars, can_manage_votes)
        VALUES (?, 1, 1, 1, 1, 1, 1)
      `, [coachResult.id]);

      console.log('✅ تم إنشاء حساب المدرب الافتراضي: 0511111111 / coach123');
    }

    console.log('✅ تم تهيئة قاعدة البيانات بنجاح');
  } catch (err) {
    console.error('❌ خطأ في تهيئة قاعدة البيانات:', err.message);
  }
}

module.exports = { db, run, get, all, initDatabase };
