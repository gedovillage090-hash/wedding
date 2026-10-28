'use strict';
const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20mb' }));
app.use(cookieParser());

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_KEY || '';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
const secret = process.env.JWT_SECRET || 'local-dev-secret-change-before-production';

function auth(req, res, next) {
  const token = req.cookies.nasim_token;
  if (!token) return res.status(401).json({ error: 'يلزم تسجيل الدخول' });
  try {
    req.user = jwt.verify(token, secret);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'جلسة الدخول انتهت' });
  }
}

// دالة جلب البيانات مع ضمان إرجاع مصفوفة صريحة
async function fetchSafeTable(res, tableName) {
  try {
    const { data, error } = await supabase.from(tableName).select('*').order('id', { ascending: false });
    if (error || !Array.isArray(data)) return res.json([]);
    return res.json(data);
  } catch (err) {
    return res.json([]);
  }
}

// مسارات تسجيل الدخول
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (String(username || '').trim() === 'admin' && String(password || '').trim() === 'admin123') {
    const token = jwt.sign({ id: 1, username: 'admin', full_name: 'المدير العام', role: 'admin' }, secret, { expiresIn: '10h' });
    res.cookie('nasim_token', token, { httpOnly: true, sameSite: 'strict' });
    return res.json({ id: 1, username: 'admin', name: 'المدير العام', role: 'admin', permissions: ['all'] });
  }
  return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('nasim_token');
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ id: 1, username: 'admin', name: 'المدير العام', role: 'admin', permissions: ['all'] });
});

// المسارات المعروفة للنظام
const tables = [
  'bookings', 'booking_archive', 'halls', 'packages', 'buffet_packages', 
  'buffet_items', 'buffet_addons', 'addons', 'contractors', 'expenses', 
  'inquiries', 'notifications', 'safe_transactions', 'inventory', 'work_orders', 
  'offers', 'users', 'customers'
];

tables.forEach(tableName => {
  app.get(`/api/${tableName}`, auth, (req, res) => fetchSafeTable(res, tableName));
});

// مسار التقارير والمبيعات والحسابات
app.get('/api/contractor_report', auth, (req, res) => res.json([]));
app.get('/api/sales_performance', auth, (req, res) => res.json([]));
app.get('/api/accounting', auth, (req, res) => res.json([]));

// معالج احتياطي لكل طلبات الـ API
app.all('/api/*', auth, (req, res) => {
  res.json([]);
});

app.get('/api/health', (req, res) => res.json({ ok: true, database: 'supabase', timestamp: new Date().toISOString() }));

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const port = Number(process.env.PORT || 3000);
app.listen(port, '0.0.0.0', () => console.log(`السيرفر يعمل على المنفذ ${port}`));