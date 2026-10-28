'use strict';
const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const QRCode = require('qrcode');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20mb' }));
app.use(cookieParser());

const SUPABASE_URL = process.env.SUPABASE_URL || '';
// Must be the server-side service_role key; never expose it to public/app.js or browser variables.
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const secret = process.env.JWT_SECRET || '';
const supabase = SUPABASE_URL && SUPABASE_KEY ? createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
}) : null;
const dbReady = () => Boolean(supabase);
const hasSecret = () => secret.length >= 32;

const TABLES = {
  'booking-archive': 'bookings', booking_archive: 'bookings',
  'buffetPackages': 'buffet_packages', buffetPackages: 'buffet_packages', buffetItems: 'buffet_items',
  'operational-addons': 'operational_addons', 'operationalAddons': 'operational_addons',
  'cash-journal': 'cash_journal', 'cash-journal/expense': null,
  'booking-files': 'booking_files', 'booking-status-history': 'booking_status_history',
  'expense-receipts': 'expense_receipts', 'inventory/items': 'inventory_items',
  'contractor-report': null, 'sales-performance': null, 'report-data': null,
  'accounting': null, 'accounting/summary': null, 'settings/hall-package-terms': null,
  'inquiries/archive': 'inquiries', 'inquiries/summary': null,
  'collection': null, 'cashier/booking-lookup': null, 'customer-lookup': null,
  'occupancy-calendar': null, 'availability': null, 'booking-status-report': 'booking_status_history',
  'discount-limit': null, 'rejection-reasons': null, 'data-deletion/counts': null, 'data-deletion/reports': null,
  'reports': null, 'reports/employee-sales': null, 'inventory/report': null,
  bookings: 'bookings', halls: 'halls', packages: 'hall_packages', hall_packages: 'hall_packages',
  buffetPackages: 'buffet_packages', buffet_packages: 'buffet_packages', buffetItems: 'buffet_items', buffet_items: 'buffet_items',
  addons: 'addons', 'operational-addons': 'operational_addons', operational_addons: 'operational_addons',
  contractors: 'contractors', customers: 'customers', inquiries: 'inquiries', followups: 'followups', users: 'users',
  notifications: 'audit_logs', offers: 'hall_offers', hall_offers: 'hall_offers', 'cash-journal': 'cash_journal', cash_journal: 'cash_journal',
  payments: 'payments', 'contractor-payouts': 'contractor_payouts', contractor_payouts: 'contractor_payouts',
  'work-orders': 'work_orders', work_orders: 'work_orders', 'booking-change-requests': 'booking_change_requests',
  'additional-discount-requests': 'additional_discount_requests', 'discount-requests': 'discount_requests',
  'official-holidays': 'official_holidays', 'independent-events': 'independent_events', 'inventory/items': 'inventory_items',
  inventory: 'inventory_items', 'expense-receipts': 'expense_receipts', 'booking-status-report': 'booking_status_history',
  'booking-archive': 'bookings', 'accounting/accounts': 'accounting_accounts', 'accounting/journals': 'journal_entries',
  'booking-activity':'booking_activity', 'booking-addons':'booking_addons', 'booking-adjustments':'booking_adjustments',
  'booking-bride-rooms':'booking_bride_rooms', 'booking-buffets':'booking_buffets', 'booking-files':'booking_files',
  'booking-operational-addons':'booking_operational_addons', 'booking-contractors':'booking_contractors',
  'booking-work-contractors':'booking_work_contractors', 'booking-status-history':'booking_status_history',
  'inventory-alerts':'inventory_alerts', 'inventory-movements':'inventory_movements', 'inventory/items':'inventory_items',
  'journal-entries':'journal_entries', 'journal-lines':'journal_lines', 'accounting-periods':'accounting_periods',
  'cash-journal':'cash_journal', 'independent-events':'independent_events', 'invitation-cards':'invitation_cards',
  'invitation-checkins':'invitation_checkins', 'official-holidays':'official_holidays', 'expense-receipts':'expense_receipts',
  'discount-requests':'discount_requests', 'additional-discount-requests':'additional_discount_requests',
  'contractor-payouts':'contractor_payouts', 'hall-offers':'hall_offers', 'buffet-package-items':'buffet_package_items'
};
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
function parsePermissions(value) {
  if (Array.isArray(value)) return value;
  try { const parsed = JSON.parse(value || '[]'); return Array.isArray(parsed) ? parsed : []; } catch { return []; }
}
function publicUser(row) {
  return { id: row.id, username: row.username, name: row.full_name, full_name: row.full_name,
    role: row.role, permissions: row.role === 'admin' ? ['all'] : parsePermissions(row.permissions),
    discount_normal: Number(row.discount_normal || 0), discount_special: Number(row.discount_special || 0) };
}
function requireDb(req, res, next) {
  if (!dbReady()) return res.status(503).json({ error: 'إعدادات Supabase ناقصة. اضبط SUPABASE_URL وSUPABASE_SERVICE_ROLE_KEY وJWT_SECRET في إعدادات الاستضافة.' });
  next();
}
function auth(req, res, next) {
  const token = req.cookies.nasim_token;
  if (!token) return res.status(401).json({ error: 'يلزم تسجيل الدخول' });
  try { req.user = jwt.verify(token, secret); next(); }
  catch { return res.status(401).json({ error: 'جلسة الدخول انتهت، سجّل الدخول مرة أخرى' }); }
}
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'هذه العملية متاحة للمدير فقط' });
  next();
}
function tableFor(alias) { return TABLES[alias] || null; }
function sortRows(query, table) {
  // Most application tables have an id; avoid requiring it for join-only endpoints.
  if (table) return query.order('id', { ascending: false });
  return query;
}
async function getRows(table, opts = {}) {
  if (!dbReady()) throw new Error('Supabase is not configured');
  let q = supabase.from(table).select('*');
  if (opts.id) q = q.eq('id', opts.id);
  if (opts.limit) q = q.limit(opts.limit);
  if (opts.order !== false) q = q.order('id', { ascending: false });
  const { data, error } = await q;
  if (error) throw error;
  return data || [];
}
function handleDbError(res, error) {
  console.error('Database request failed:', error?.message || error);
  return res.status(400).json({ error: 'تعذر تنفيذ العملية على قاعدة البيانات. راجع أسماء الأعمدة وصلاحيات الاتصال.' });
}

app.get('/api/health', async (req, res) => { let database='not_configured'; if(dbReady()){try{const {error}=await supabase.from('app_settings').select('key').limit(1);database=error?'error':'connected';}catch{database='error';}} res.status(database==='error'?503:200).json({ok:database==='connected',database,databaseConfigured:dbReady(),timestamp:new Date().toISOString()}); });
app.post('/api/login', requireDb, async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    if (!username || !password) return res.status(400).json({ error: 'اكتب اسم المستخدم وكلمة المرور' });
    const { data, error } = await supabase.from('users').select('*').eq('username', username).maybeSingle();
    if (error) throw error;
    if (!data || !data.active || !await bcrypt.compare(password, data.password_hash))
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    if (!hasSecret()) return res.status(503).json({ error: 'اضبط JWT_SECRET بقيمة عشوائية طويلة (32 حرفًا على الأقل) في إعدادات الاستضافة' });
    const user = publicUser(data);
    const token = jwt.sign(user, secret, { expiresIn: '10h', issuer: 'nasim-wedding' });
    res.cookie('nasim_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 10 * 60 * 60 * 1000, path: '/' });
    return res.json(user);
  } catch (error) { return handleDbError(res, error); }
});
app.post('/api/logout', (req, res) => { res.clearCookie('nasim_token', { path: '/' }); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json(req.user));
app.post('/api/change-own-password', requireDb, auth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body || {};
    if (String(new_password || '').length < 10) return res.status(400).json({ error: 'كلمة المرور الجديدة يجب أن تكون 10 أحرف على الأقل' });
    const { data, error } = await supabase.from('users').select('id,password_hash').eq('id', req.user.id).maybeSingle();
    if (error) throw error;
    if (!data || !await bcrypt.compare(String(current_password || ''), data.password_hash)) return res.status(400).json({ error: 'كلمة المرور الحالية غير صحيحة' });
    const hash = await bcrypt.hash(String(new_password), 12);
    const upd = await supabase.from('users').update({ password_hash: hash }).eq('id', req.user.id);
    if (upd.error) throw upd.error;
    res.json({ ok: true });
  } catch (error) { return handleDbError(res, error); }
});

// Dashboard and frequently used reports return real database data, not fabricated empty arrays.
app.get('/api/summary', auth, requireDb, async (req, res) => {
  try {
    const counts = await Promise.all(['halls','hall_packages','bookings','payments'].map(async t => [t, (await supabase.from(t).select('id', { count: 'exact', head: true })).count || 0]));
    const revenueResult = await supabase.from('payments').select('amount');
    if (revenueResult.error) throw revenueResult.error;
    const countsMap = Object.fromEntries(counts);
    res.json({ halls: countsMap.halls, packages: countsMap.hall_packages, bookings: countsMap.bookings,
      revenue: (revenueResult.data || []).reduce((s, r) => s + Number(r.amount || 0), 0) });
  } catch (error) { handleDbError(res, error); }
});
app.get('/api/inquiries/summary', auth, (req, res) => res.json({ totals: {}, employees: [] }));
app.get('/api/followups', auth, requireDb, async (req, res) => {
  try {
    const rows = await getRows('followups');
    res.json({ followups: rows, upcoming_count: rows.filter(x => x.scheduled_at && new Date(x.scheduled_at) >= new Date() && new Date(x.scheduled_at) <= new Date(Date.now()+86400000)).length });
  } catch (error) { handleDbError(res, error); }
});
app.get('/api/contractor-report', auth, requireDb, async (req, res) => {
  try {
    const [contractors, rows, payouts] = await Promise.all([getRows('contractors'), getRows('booking_contractors'), getRows('contractor_payouts')]);
    const mapped = rows.map(r => ({ ...r, contractor_name: contractors.find(c => c.id === r.contractor_id)?.full_name || '', job_title: contractors.find(c => c.id === r.contractor_id)?.job_title || '', owed: Number(r.cost_amount || 0), paid: payouts.filter(p => p.contractor_id === r.contractor_id && p.booking_id === r.booking_id).reduce((s,p)=>s+Number(p.amount||0),0) }));
    res.json({ rows: mapped, contractors: contractors.map(c => ({...c, owed: mapped.filter(r=>r.contractor_id===c.id).reduce((s,r)=>s+r.owed,0), paid: mapped.filter(r=>r.contractor_id===c.id).reduce((s,r)=>s+r.paid,0)})) });
  } catch (error) { handleDbError(res, error); }
});
// Accounting endpoints return the exact response shapes expected by the UI.
async function accountingSnapshot() {
  const [accounts, entries, lines] = await Promise.all([
    getRows('accounting_accounts'), getRows('journal_entries'), getRows('journal_lines')
  ]);
  const entryById = new Map(entries.map(e => [Number(e.id), e]));
  const accountById = new Map(accounts.map(a => [Number(a.id), a]));
  return { accounts, entries, lines, entryById, accountById };
}
function dateInRange(value, from, to) {
  const day = String(value || '').slice(0, 10);
  return (!from || day >= from) && (!to || day <= to);
}
function postedEntries(entries) {
  return entries.filter(e => String(e.status || 'posted') !== 'reversed');
}
function netSide(debit, credit) {
  const net = Number(debit || 0) - Number(credit || 0);
  return { debit: Math.max(0, net), credit: Math.max(0, -net) };
}
app.get('/api/accounting/summary', auth, requireDb, async (req, res) => {
  try {
    const { accounts, entries, lines } = await accountingSnapshot();
    res.json({ accounts, entries, journals: entries, lines, totals: {
      entries: entries.length,
      debit: lines.reduce((sum, x) => sum + Number(x.debit || 0), 0),
      credit: lines.reduce((sum, x) => sum + Number(x.credit || 0), 0)
    }});
  } catch (error) { handleDbError(res, error); }
});
app.get('/api/accounting/journals', auth, requireDb, async (req, res) => {
  try {
    const { entries, lines } = await accountingSnapshot();
    res.json(entries.map(e => {
      const own = lines.filter(l => Number(l.entry_id) === Number(e.id));
      return { ...e, debit: own.reduce((n,l) => n + Number(l.debit || 0), 0), credit: own.reduce((n,l) => n + Number(l.credit || 0), 0) };
    }));
  } catch (error) { handleDbError(res, error); }
});
app.get('/api/accounting/trial-balance', auth, requireDb, async (req, res) => {
  try {
    const { accounts, entries, lines } = await accountingSnapshot();
    const from = String(req.query.from || ''); const to = String(req.query.to || '');
    const eligible = postedEntries(entries);
    const activeEntries = new Map(eligible.map(e => [Number(e.id), e]));
    const result = accounts.map(a => {
      const related = lines.filter(l => Number(l.account_id) === Number(a.id)).map(l => ({ line: l, entry: activeEntries.get(Number(l.entry_id)) })).filter(x => x.entry);
      const opening = related.filter(x => from && String(x.entry.entry_date || '').slice(0,10) < from);
      const movement = related.filter(x => dateInRange(x.entry.entry_date, from, to) && (!from || String(x.entry.entry_date || '').slice(0,10) >= from));
      const openingSide = netSide(opening.reduce((n,x)=>n+Number(x.line.debit||0),0), opening.reduce((n,x)=>n+Number(x.line.credit||0),0));
      const debit = movement.reduce((n,x)=>n+Number(x.line.debit||0),0);
      const credit = movement.reduce((n,x)=>n+Number(x.line.credit||0),0);
      const closing = netSide(openingSide.debit + debit, openingSide.credit + credit);
      // Opening/closing sides are displayed as net balances; movement columns are period totals.
      return { id:a.id, code:a.code, name:a.name, account_type:a.account_type,
        opening_debit:openingSide.debit, opening_credit:openingSide.credit,
        debit, credit, closing_debit:closing.debit, closing_credit:closing.credit };
    });
    res.json(result);
  } catch (error) { handleDbError(res, error); }
});
app.get('/api/accounting/ledger', auth, requireDb, async (req, res) => {
  try {
    const { accounts, entries, lines } = await accountingSnapshot();
    const from=String(req.query.from||''); const to=String(req.query.to||'');
    const entryMap=new Map(entries.map(e=>[Number(e.id),e])); const accountMap=new Map(accounts.map(a=>[Number(a.id),a]));
    const result=lines.map(l=>{const e=entryMap.get(Number(l.entry_id))||{};const a=accountMap.get(Number(l.account_id))||{};return {entry_date:e.entry_date||'',entry_no:e.entry_no||'',code:a.code||'',account_name:a.name||'',account_type:a.account_type||'',entry_description:e.description||'',line_description:l.description||'',debit:Number(l.debit||0),credit:Number(l.credit||0),status:e.status||'posted'};})
      .filter(r=>dateInRange(r.entry_date,from,to)&&(!from||String(r.entry_date).slice(0,10)>=from)&&String(r.status)!=='reversed')
      .sort((a,b)=>String(a.entry_date).localeCompare(String(b.entry_date))||String(a.entry_no).localeCompare(String(b.entry_no)));
    res.json(result);
  } catch (error) { handleDbError(res, error); }
});
app.get('/api/accounting/income-statement', auth, requireDb, async (req, res) => {
  try {
    const { accounts, entries, lines } = await accountingSnapshot();
    const from=String(req.query.from||''); const to=String(req.query.to||'');
    const entryMap=new Map(postedEntries(entries).map(e=>[Number(e.id),e])); const accountMap=new Map(accounts.map(a=>[Number(a.id),a]));
    const totals=new Map();
    for(const line of lines){const entry=entryMap.get(Number(line.entry_id));const account=accountMap.get(Number(line.account_id));if(!entry||!account||!['revenue','expense'].includes(account.account_type)||!dateInRange(entry.entry_date,from,to)|| (from&&String(entry.entry_date).slice(0,10)<from))continue;
      const current=totals.get(account.id)||{code:account.code,name:account.name,account_type:account.account_type,amount:0};
      current.amount += account.account_type==='revenue' ? Number(line.credit||0)-Number(line.debit||0) : Number(line.debit||0)-Number(line.credit||0);
      totals.set(account.id,current);
    }
    const rows=[...totals.values()].map(x=>({...x,amount:Math.round(x.amount*100)/100})).sort((a,b)=>String(a.code).localeCompare(String(b.code)));
    const revenue=rows.filter(x=>x.account_type==='revenue').reduce((n,x)=>n+x.amount,0);
    const expenses=rows.filter(x=>x.account_type==='expense').reduce((n,x)=>n+x.amount,0);
    res.json({rows,revenue,expenses,net_profit:revenue-expenses});
  } catch (error) { handleDbError(res, error); }
});
app.post('/api/accounting/journals', auth, requireDb, async (req,res)=>{
  let createdId=null;
  try {
    if(req.user?.role!=='admin'&&!req.user?.permissions?.includes('accounting')&&!req.user?.permissions?.includes('edit_accounting'))return res.status(403).json({error:'ليس لديك صلاحية إنشاء قيد محاسبي'});
    const entry_date=String(req.body?.entry_date||''); const description=String(req.body?.description||'').trim();
    const input=Array.isArray(req.body?.lines)?req.body.lines:[];
    if(!/^\d{4}-\d{2}-\d{2}$/.test(entry_date)||!description||input.length<2)return res.status(400).json({error:'أدخل تاريخ القيد والبيان وسطرين على الأقل'});
    const lines=input.map(x=>({account_id:Number(x.account_id),description:String(x.description||''),debit:Number(x.debit||0),credit:Number(x.credit||0)}));
    if(lines.some(x=>!Number.isInteger(x.account_id)||x.account_id<1||!Number.isFinite(x.debit)||!Number.isFinite(x.credit)||x.debit<0||x.credit<0||(x.debit>0&&x.credit>0)||(x.debit===0&&x.credit===0)))return res.status(400).json({error:'راجع الحسابات وقيم المدين والدائن في كل سطر'});
    const debit=lines.reduce((n,x)=>n+x.debit,0),credit=lines.reduce((n,x)=>n+x.credit,0);
    if(Math.abs(debit-credit)>0.009)return res.status(400).json({error:'القيد غير متوازن: يجب تساوي إجمالي المدين والدائن'});
    const {data:entry,error}=await supabase.from('journal_entries').insert({entry_no:receiptNo('JE'),entry_date,description,source_type:'manual',status:'posted',created_by:req.user.id}).select('*').single();
    if(error)throw error; createdId=entry.id;
    const inserted=await supabase.from('journal_lines').insert(lines.map(x=>({...x,entry_id:entry.id})));
    if(inserted.error)throw inserted.error;
    res.status(201).json({...entry,debit,credit});
  } catch(error){if(createdId!==null){try{await supabase.from('journal_lines').delete().eq('entry_id',createdId);await supabase.from('journal_entries').delete().eq('id',createdId)}catch{}}handleDbError(res,error);}
});

// High-level reports and report-data used by the current UI.
app.get('/api/reports', auth, requireDb, async (req,res)=>{
  try {
    const [bookings,payments,journal]=await Promise.all([getRows('bookings'),getRows('payments'),getRows('cash_journal')]);
    const active=bookings.filter(b=>String(b.status||'').toLowerCase()!=='cancelled');
    const paid=payments.reduce((n,p)=>n+(String(p.payment_type||'')==='security_refund'?-1:1)*Number(p.amount||0),0);
    res.json({bookings:active.length,eventRevenue:active.reduce((n,b)=>n+Number(b.event_total||0),0),paid,
      journalIncome:journal.filter(x=>x.entry_type==='income').reduce((n,x)=>n+Number(x.amount||0),0),
      journalExpense:journal.filter(x=>x.entry_type==='expense').reduce((n,x)=>n+Number(x.amount||0),0)});
  } catch(error){handleDbError(res,error)}
});
app.get('/api/report-data', auth, requireDb, async (req,res)=>{
  try {
    const type=String(req.query.type||'bookings'); const from=String(req.query.from||''); const to=String(req.query.to||''); const status=String(req.query.status||''); const q=String(req.query.q||'').trim().toLowerCase();
    const includesQ=row=>!q||Object.values(row).some(v=>v!==null&&v!==undefined&&String(v).toLowerCase().includes(q));
    const dateOk=v=>dateInRange(v,from,to)&&(!from||String(v||'').slice(0,10)>=from);
    if(type==='bookings'){
      const [bookings,customers,halls,packages,users,payments]=await Promise.all([getRows('bookings'),getRows('customers'),getRows('halls'),getRows('hall_packages'),getRows('users'),getRows('payments')]);
      const result=bookings.map(b=>{const c=customers.find(x=>Number(x.id)===Number(b.customer_id))||{};const h=halls.find(x=>Number(x.id)===Number(b.hall_id))||{};const p=packages.find(x=>Number(x.id)===Number(b.hall_package_id))||{};const u=users.find(x=>Number(x.id)===Number(b.created_by))||{};const paid=payments.filter(x=>Number(x.booking_id)===Number(b.id)).reduce((n,x)=>n+(x.payment_type==='security_refund'?-1:1)*Number(x.amount||0),0);const stage=b.booking_stage||'preliminary';const stageLabel=({preliminary:'حجز مبدئي',awaiting_manager:'بانتظار موافقة المدير العام',confirmed:'مؤكد'})[stage]||stage;return {...b,customer_name:c.full_name||c.name||'',bride_name:c.bride_name||'',phone:c.phone||'',hall_name:h.name||'',package_name:p.name||'',employee:u.full_name||u.username||'—',booking_stage_label:stageLabel,payment_status:paid>=Number(b.event_total||0)+Number(b.deposit||0)-Number(b.special_discount||0)?'paid':'pending',amount_due:Math.max(0,Number(b.event_total||0)+Number(b.deposit||0)-Number(b.special_discount||0)-paid)};})
        .filter(b=>dateOk(b.event_date)&&(!status||status===b.booking_stage)&&includesQ(b));
      return res.json(result);
    }
    if(type==='inquiries'){
      const [inquiries,users]=await Promise.all([getRows('inquiries'),getRows('users')]);
      const result=inquiries.map(x=>({...x,employee:users.find(u=>Number(u.id)===Number(x.assigned_to))?.full_name||users.find(u=>Number(u.id)===Number(x.created_by))?.full_name||'—'})).filter(x=>dateOk(x.event_date||x.created_at)&&(!status||status===x.status)&&includesQ(x));
      return res.json(result);
    }
    if(type==='halls'){
      const [halls,bookings]=await Promise.all([getRows('halls'),getRows('bookings')]);
      return res.json(halls.map(h=>{const own=bookings.filter(b=>Number(b.hall_id)===Number(h.id)&&dateOk(b.event_date)&&String(b.status||'')!=='cancelled');return {hall_name:h.name,status:h.active?'نشطة':'متوقفة',bookings_count:own.length,event_revenue:own.reduce((n,b)=>n+Number(b.event_total||0),0)}}).filter(includesQ));
    }
    if(type==='packages'){
      const [packages,halls,bookings]=await Promise.all([getRows('hall_packages'),getRows('halls'),getRows('bookings')]);
      return res.json(packages.map(p=>{const h=halls.find(x=>Number(x.id)===Number(p.hall_id))||{};const own=bookings.filter(b=>Number(b.hall_package_id)===Number(p.id)&&dateOk(b.event_date)&&String(b.status||'')!=='cancelled');return {hall_name:h.name||'',package_name:p.name,period:p.period,guest_count:p.guest_count,price:p.price,start_time:p.start_time,end_time:p.end_time,bookings_count:own.length,event_revenue:own.reduce((n,b)=>n+Number(b.event_total||0),0)}}).filter(includesQ));
    }
    if(type==='buffet'){
      const [packages,bookingBuffets,bookings]=await Promise.all([getRows('buffet_packages'),getRows('booking_buffets',{order:false}),getRows('bookings')]);
      const result=packages.map(p=>{const own=bookingBuffets.filter(x=>Number(x.buffet_package_id)===Number(p.id)&&bookings.some(b=>Number(b.id)===Number(x.booking_id)&&dateOk(b.event_date)&&String(b.status||'')!=='cancelled'));const usedBookings=new Set(own.map(x=>Number(x.booking_id)));return {package_name:p.name,price_per_person:p.price_per_person,bookings_count:usedBookings.size,guests_count:own.reduce((n,x)=>n+Number(x.guest_count||0),0),sales_total:own.reduce((n,x)=>n+Number(x.line_total||0),0)}}).filter(includesQ);
      return res.json(result);
    }
    if(type==='finance'){
      const all=await getRows('cash_journal');
      return res.json(all.filter(x=>dateOk(x.created_at)&&(!status||status===x.entry_type)&&includesQ(x)).map(x=>({...x,method:x.method||'—'})));
    }
    return res.status(400).json({error:'نوع التقرير غير معروف'});
  } catch(error){handleDbError(res,error)}
});
app.get('/api/reports/employee-sales', auth, requireDb, async (req,res)=>{
  try {
    const [users,salesRaw,activityRaw,bookings,customers]=await Promise.all([getRows('users'),getRows('booking_addon_sales'),getRows('booking_activity'),getRows('bookings'),getRows('customers')]);
    const usersById=new Map(users.map(u=>[Number(u.id),u]));const bookingsById=new Map(bookings.map(b=>[Number(b.id),b]));const customersById=new Map(customers.map(c=>[Number(c.id),c]));
    const userFilter=String(req.query.user_id||'');const from=String(req.query.from||'');const to=String(req.query.to||'');const bookingNo=String(req.query.booking_no||'').trim().toLowerCase();
    const matchingBooking=id=>{const b=bookingsById.get(Number(id))||{};return !bookingNo||String(b.booking_no||'').toLowerCase().includes(bookingNo)};
    const timeOk=v=>dateInRange(v,from,to)&&(!from||String(v||'').slice(0,10)>=from);
    const sales=salesRaw.filter(x=>(!userFilter||Number(x.user_id)===Number(userFilter))&&timeOk(x.created_at)&&matchingBooking(x.booking_id)).map(x=>{const b=bookingsById.get(Number(x.booking_id))||{};const c=customersById.get(Number(b.customer_id))||{};const u=usersById.get(Number(x.user_id))||{};return {...x,employee:u.full_name||u.username||'النظام',booking_no:b.booking_no||'',customer_name:c.full_name||c.name||'',phone:c.phone||''}});
    const activities=activityRaw.filter(x=>(!userFilter||Number(x.user_id)===Number(userFilter))&&timeOk(x.created_at)&&matchingBooking(x.booking_id)).map(x=>{const b=bookingsById.get(Number(x.booking_id))||{};const c=customersById.get(Number(b.customer_id))||{};const u=usersById.get(Number(x.user_id))||{};return {...x,employee:u.full_name||u.username||'النظام',booking_no:b.booking_no||'',customer_name:c.full_name||c.name||'',phone:c.phone||''}});
    const ids=new Set([...sales.map(x=>Number(x.booking_id)),...activities.map(x=>Number(x.booking_id))]);const affectedUsers=new Set([...sales.map(x=>Number(x.user_id||0)),...activities.map(x=>Number(x.user_id||0))].filter(Boolean));
    const summary={sales_total:sales.reduce((n,x)=>n+Number(x.sales_delta||0),0),positive_sales:sales.reduce((n,x)=>n+Math.max(0,Number(x.sales_delta||0)),0),employees:affectedUsers.size,bookings:ids.size};
    const groups=new Map();const ensure=id=>{const key=Number(id||0);if(!groups.has(key)){const u=usersById.get(key)||{};groups.set(key,{user_id:key,employee:u.full_name||u.username||'النظام',bookings_created:0,booking_count:0,addons_added:0,sales_total:0,removed_value:0,net_changes:0,bookings:[],_bookingIds:new Set(),_createdIds:new Set()})}return groups.get(key)};
    for(const x of activities){const g=ensure(x.user_id);if(x.booking_no&&!g.bookings.includes(x.booking_no))g.bookings.push(x.booking_no);if(x.booking_id)g._bookingIds.add(Number(x.booking_id));if(x.action==='create_booking'&&x.booking_id)g._createdIds.add(Number(x.booking_id));}
    for(const x of sales){const g=ensure(x.user_id);if(x.booking_no&&!g.bookings.includes(x.booking_no))g.bookings.push(x.booking_no);if(x.booking_id)g._bookingIds.add(Number(x.booking_id));const delta=Number(x.sales_delta||0);g.net_changes+=delta;g.sales_total+=delta;if(x.change_type==='add')g.addons_added+=1;if(x.change_type==='remove')g.removed_value+=Math.abs(Math.min(0,delta));}
    const employeeSummary=[...groups.values()].map(g=>({...g,booking_count:g._bookingIds.size,bookings_created:g._createdIds.size,bookings:g.bookings.sort(),_bookingIds:undefined,_createdIds:undefined})).sort((a,b)=>b.sales_total-a.sales_total||a.employee.localeCompare(b.employee));
    res.json({users:users.filter(u=>u.active!==false&&u.active!==0).map(u=>({id:u.id,full_name:u.full_name,username:u.username})),summary,employeeSummary,sales,activities});
  } catch(error){handleDbError(res,error)}
});

// Booking archive data must be an object containing a rows array (not a raw history table).
app.get('/api/booking-status-report', auth, requireDb, async (req,res)=>{
  try {
    const [bookings,customers,halls,packages,payments,statusHistory,discountRequests]=await Promise.all([getRows('bookings'),getRows('customers'),getRows('halls'),getRows('hall_packages'),getRows('payments'),getRows('booking_status_history'),getRows('additional_discount_requests')]);
    const userRows=await getRows('users');
    const rows=bookings.map(b=>{const c=customers.find(x=>Number(x.id)===Number(b.customer_id))||{};const h=halls.find(x=>Number(x.id)===Number(b.hall_id))||{};const p=packages.find(x=>Number(x.id)===Number(b.hall_package_id))||{};const paidRows=payments.filter(x=>Number(x.booking_id)===Number(b.id));const paid=paidRows.reduce((n,x)=>n+(x.payment_type==='security_refund'?-1:1)*Number(x.amount||0),0);const securityReceived=paidRows.filter(x=>['security_deposit','deposit','booking_deposit'].includes(String(x.payment_type||''))).reduce((n,x)=>n+Number(x.amount||0),0);const securityRefunded=paidRows.filter(x=>x.payment_type==='security_refund').reduce((n,x)=>n+Number(x.amount||0),0);const discount=discountRequests.filter(x=>Number(x.booking_id)===Number(b.id)).sort((a,z)=>String(z.created_at).localeCompare(String(a.created_at)))[0];const stage=b.booking_stage||'preliminary';return {...b,customer_name:c.full_name||c.name||'',bride_name:c.bride_name||'',phone:c.phone||'',phone2:c.phone2||'',id_number:c.id_number||'',hall_name:h.name||'',package_name:p.name||'',paid_amount:paid,final_total:Number(b.event_total||0)+Number(b.deposit||0)-Number(b.special_discount||0),security_received:securityReceived,security_refunded:securityRefunded,booking_stage_label:({preliminary:'حجز مبدئي',awaiting_manager:'بانتظار موافقة المدير العام',confirmed:'مؤكد'})[stage]||stage,additional_discount_status:discount?.status||'',additional_discount_review_note:discount?.review_note||'',additional_discount_reason:discount?.reason||'',latest_status_change:statusHistory.filter(x=>Number(x.booking_id)===Number(b.id)).sort((a,z)=>String(z.created_at).localeCompare(String(a.created_at)))[0]||null,created_by_name:userRows.find(u=>Number(u.id)===Number(b.created_by))?.full_name||''};});
    res.json({rows});
  } catch(error){handleDbError(res,error)}
});

// Invitation card lifecycle endpoints.
async function invitationBookingView(booking) {
  if(!booking)return null;
  const [customer,hall,pkg,cards,checkins]=await Promise.all([
    one('customers',booking.customer_id),one('halls',booking.hall_id),one('hall_packages',booking.hall_package_id),
    rows('invitation_cards',{booking_id:Number(booking.id)}),rows('invitation_checkins',{booking_id:Number(booking.id)})
  ]);
  return {...booking,customer_name:customer?.full_name||customer?.name||'',bride_name:customer?.bride_name||'',phone:customer?.phone||'',hall_name:hall?.name||'',package_name:pkg?.name||'',event_type_ar:({wedding:'حفل الزفاف',engagement:'حفل الخطوبة',birthday:'عيد ميلاد',other:'المناسبة'})[booking.event_type]||'حفل الزفاف',invitation_count:cards.filter(c=>c.status==='active').length,checked_in:checkins.reduce((n,c)=>n+Number(c.guest_count||0),0)};
}
async function invitationCardViews(cards) {
  return Promise.all(cards.map(async c=>{let qr_data_url='';try{qr_data_url=await QRCode.toDataURL('NASIM:'+c.token,{width:220,margin:1,errorCorrectionLevel:'M'});}catch{}return {...c,qr_data_url};}));
}
app.get('/api/invitations/bookings', auth, requireDb, async (req,res)=>{
  try {
    const [bookings,customers,halls,packages,cards,checkins]=await Promise.all([getRows('bookings'),getRows('customers'),getRows('halls'),getRows('hall_packages'),getRows('invitation_cards'),getRows('invitation_checkins')]);
    const q=String(req.query.q||'').trim().toLowerCase();
    const result=bookings.filter(b=>String(b.booking_stage||'')==='confirmed'&&!['cancelled','completed'].includes(String(b.status||'').toLowerCase())).map(b=>{const c=customers.find(x=>Number(x.id)===Number(b.customer_id))||{};const h=halls.find(x=>Number(x.id)===Number(b.hall_id))||{};const p=packages.find(x=>Number(x.id)===Number(b.hall_package_id))||{};const cardRows=cards.filter(x=>Number(x.booking_id)===Number(b.id)&&x.status==='active');return {...b,customer_name:c.full_name||c.name||'',bride_name:c.bride_name||'',phone:c.phone||'',hall_name:h.name||'',package_name:p.name||'',event_type_ar:({wedding:'حفل الزفاف',engagement:'حفل الخطوبة',birthday:'عيد ميلاد',other:'المناسبة'})[b.event_type]||'حفل الزفاف',invitation_count:cardRows.length,checked_in:checkins.filter(x=>Number(x.booking_id)===Number(b.id)).reduce((n,x)=>n+Number(x.guest_count||0),0)}}).filter(b=>!q||[b.booking_no,b.customer_name,b.bride_name,b.hall_name,b.phone].some(v=>String(v||'').toLowerCase().includes(q)));
    res.json(result);
  } catch(error){handleDbError(res,error)}
});
app.get('/api/invitations/booking/:id', auth, requireDb, async (req,res)=>{
  try {const b=await one('bookings',req.params.id);if(!b)return res.status(404).json({error:'الحجز غير موجود'});const view=await invitationBookingView(b);const cards=await rows('invitation_cards',{booking_id:Number(b.id)});res.json({booking:view,cards:await invitationCardViews(cards)});}catch(error){handleDbError(res,error)}
});
app.post('/api/invitations/booking/:id/create', auth, requireDb, async (req,res)=>{
  try {
    const b=await one('bookings',req.params.id);if(!b)return res.status(404).json({error:'الحجز غير موجود'});
    if(String(b.booking_stage||'')!=='confirmed'||['cancelled','completed'].includes(String(b.status||'').toLowerCase()))return res.status(409).json({error:'لا يمكن إصدار دعوة إلا لحجز مؤكد وغير ملغي'});
    const guest_limit=Number(req.body?.guest_limit);if(!Number.isInteger(guest_limit)||guest_limit<1||guest_limit>100)return res.status(400).json({error:'عدد الأفراد يجب أن يكون من 1 إلى 100'});
    const existing=await rows('invitation_cards',{booking_id:Number(b.id)});const active=existing.find(x=>x.status==='active');
    if(active&&Number(active.guests_checked_in||0)>0)return res.status(409).json({error:'تم تسجيل دخول بهذه الدعوة؛ لا يمكن استبدالها بعد الاستخدام'});
    if(active){const upd=await supabase.from('invitation_cards').update({status:'revoked',updated_at:new Date().toISOString()}).eq('id',active.id);if(upd.error)throw upd.error;}
    const eventDay=String(b.event_date||'').slice(0,10);if(!/^\d{4}-\d{2}-\d{2}$/.test(eventDay))return res.status(400).json({error:'تاريخ المناسبة غير صالح'});
    const expires_at=new Date(`${eventDay}T23:59:59`).toISOString();const token=crypto.randomBytes(24).toString('hex');
    const {data,error}=await supabase.from('invitation_cards').insert({booking_id:b.id,token,template_id:String(req.body?.template_id||'custom1'),guest_limit,guests_checked_in:0,expires_at,status:'active',created_by:req.user.id,updated_at:new Date().toISOString()}).select('*').single();if(error)throw error;
    const booking=await invitationBookingView(b);const cards=await invitationCardViews([data]);res.status(201).json({ok:true,message:'تم إنشاء بطاقة الدعوة بنجاح',booking,cards,expiry:expires_at});
  } catch(error){handleDbError(res,error)}
});
app.post('/api/invitations/:id/revoke', auth, requireDb, async (req,res)=>{
  try {const card=await one('invitation_cards',req.params.id);if(!card)return res.status(404).json({error:'بطاقة الدعوة غير موجودة'});if(card.status!=='active')return res.status(409).json({error:'بطاقة الدعوة ملغاة بالفعل'});if(Number(card.guests_checked_in||0)>0)return res.status(409).json({error:'لا يمكن إلغاء الدعوة بعد تسجيل دخول أي فرد بها'});const {data,error}=await supabase.from('invitation_cards').update({status:'revoked',updated_at:new Date().toISOString()}).eq('id',card.id).select('*').single();if(error)throw error;res.json({ok:true,card:data});}catch(error){handleDbError(res,error)}
});
app.post('/api/invitations/scan', auth, requireDb, async (req,res)=>{
  try {
    const token=String(req.body?.token||'').trim().replace(/^NASIM:/i,'');const guestCount=Number(req.body?.guest_count||1);
    if(!token)return res.status(400).json({error:'أدخل رمز الدعوة أولًا'});if(!Number.isInteger(guestCount)||guestCount<1||guestCount>100)return res.status(400).json({error:'عدد الأفراد غير صحيح'});
    const {data:card,error}=await supabase.from('invitation_cards').select('*').eq('token',token).maybeSingle();if(error)throw error;if(!card)return res.status(404).json({error:'رمز الدعوة غير صحيح'});if(card.status!=='active')return res.status(409).json({error:'هذه الدعوة ملغاة'});if(new Date(card.expires_at).getTime()<Date.now())return res.status(410).json({error:'انتهت صلاحية الدعوة'});
    const b=await one('bookings',card.booking_id);if(!b||['cancelled','completed'].includes(String(b.status||'').toLowerCase()))return res.status(409).json({error:'الحجز ملغي أو غير متاح للدخول'});
    const remaining=Number(card.guest_limit||0)-Number(card.guests_checked_in||0);if(guestCount>remaining)return res.status(409).json({error:`عدد الأفراد يتجاوز المتبقي في الدعوة (${Math.max(0,remaining)})`});
    const newCount=Number(card.guests_checked_in||0)+guestCount;const upd=await supabase.from('invitation_cards').update({guests_checked_in:newCount,updated_at:new Date().toISOString()}).eq('id',card.id).eq('status','active').select('*').maybeSingle();if(upd.error)throw upd.error;if(!upd.data)return res.status(409).json({error:'تم تحديث الدعوة بالتزامن؛ أعد المحاولة'});
    const check=await supabase.from('invitation_checkins').insert({invitation_id:card.id,booking_id:b.id,guest_count:guestCount,result:'allowed',employee_id:req.user.id,notes:String(req.body?.notes||'')}).select('*').single();if(check.error){await supabase.from('invitation_cards').update({guests_checked_in:Number(card.guests_checked_in||0),updated_at:new Date().toISOString()}).eq('id',card.id);throw check.error;}
    const view=await invitationBookingView(b);res.json({ok:true,message:'تم السماح بالدخول وتسجيل الأفراد',booking_no:b.booking_no,customer_name:view.customer_name,bride_name:view.bride_name,hall_name:view.hall_name,event_date:b.event_date,guests_checked_in:newCount,guest_limit:Number(card.guest_limit),remaining:Number(card.guest_limit)-newCount,expires_at:card.expires_at});
  } catch(error){handleDbError(res,error)}
});

// Transactional workflow endpoints used by the UI. Every write returns an error on failure.
function receiptNo(prefix='NS') { return `${prefix}-${new Date().toISOString().replace(/[-:TZ.]/g,'').slice(0,14)}-${Math.floor(Math.random()*900+100)}`; }
app.get('/api/cashier/booking-lookup', auth, requireDb, async (req,res)=>{
  try { const digits=String(req.query.phone||'').replace(/\D/g,''); if(digits.length<3)return res.json([]); const customers=await getRows('customers'); const matches=customers.filter(c=>String(c.phone||'').replace(/\D/g,'').includes(digits)); const bookings=await getRows('bookings'); const out=[]; for(const b of bookings.filter(x=>matches.some(c=>c.id===x.customer_id))){const c=matches.find(y=>y.id===b.customer_id)||{};const h=await one('halls',b.hall_id)||{};const pays=await rows('payments',{booking_id:b.id});out.push({...b,customer_name:c.name||c.full_name||'',phone:c.phone||'',hall_name:h.name||'',paid_amount:pays.reduce((n,p)=>n+Number(p.amount||0),0),adjustments_total:0,change_notes:''})} res.json(out); }
  catch(e){handleDbError(res,e)}
});
app.get('/api/collection', auth, requireDb, async (req,res)=>{
  try {
    const [payments,bookings,customers,halls,packages,discountRequests] = await Promise.all([
      getRows('payments'),getRows('bookings'),getRows('customers'),getRows('halls'),getRows('hall_packages'),getRows('additional_discount_requests')
    ]);
    const customersById = new Map(customers.map(x=>[Number(x.id),x]));
    const hallsById = new Map(halls.map(x=>[Number(x.id),x]));
    const packagesById = new Map(packages.map(x=>[Number(x.id),x]));
    const out = bookings.map(b=>{
      const customer = customersById.get(Number(b.customer_id)) || {};
      const hall = hallsById.get(Number(b.hall_id)) || {};
      const pkg = packagesById.get(Number(b.hall_package_id)) || {};
      const ownPayments = payments.filter(p=>Number(p.booking_id)===Number(b.id));
      const paid = ownPayments.reduce((sum,p)=>sum+(String(p.payment_type||'')==='security_refund'?-1:1)*Number(p.amount||0),0);
      const securityPaid = ownPayments.filter(p=>['security_deposit','deposit'].includes(String(p.payment_type||''))).reduce((sum,p)=>sum+Number(p.amount||0),0);
      const securityRefunded = ownPayments.filter(p=>String(p.payment_type||'')==='security_refund').reduce((sum,p)=>sum+Number(p.amount||0),0);
      const lastDiscount = discountRequests.filter(x=>Number(x.booking_id)===Number(b.id)).sort((x,y)=>String(y.created_at||'').localeCompare(String(x.created_at||'')))[0];
      const finalTotal = Number(b.event_total||0)+Number(b.deposit||0)-Number(b.special_discount||0);
      return {...b, customer_name:customer.full_name||customer.name||'', phone:customer.phone||'', phone2:customer.phone2||'', hall_name:hall.name||'', package_name:pkg.name||'', paid, paid_total:paid, security_paid:securityPaid, security_refunded:securityRefunded, final_total:finalTotal, amount_due:Math.max(0,finalTotal-paid), special_discount_request_id:lastDiscount?.id||null, latest_discount_status:lastDiscount?.status||''};
    });
    res.json(out);
  } catch(e) { handleDbError(res,e); }
});
app.get('/api/collection/payments/:id', auth, requireDb, async (req,res)=>{try{res.json(await rows('payments',{booking_id:Number(req.params.id)}))}catch(e){handleDbError(res,e)}});
app.get('/api/collection/:id/history', auth, requireDb, async (req,res)=>{
  try {
    const bookingId = Number(req.params.id);
    const booking = await one('bookings',bookingId);
    if(!booking) return res.status(404).json({error:'الحجز غير موجود'});
    const [payments,customers,halls,packages,users,discountRequests] = await Promise.all([
      rows('payments',{booking_id:bookingId}),getRows('customers'),getRows('halls'),getRows('hall_packages'),getRows('users'),getRows('additional_discount_requests')
    ]);
    const customer = customers.find(x=>Number(x.id)===Number(booking.customer_id)) || {};
    const hall = halls.find(x=>Number(x.id)===Number(booking.hall_id)) || {};
    const pkg = packages.find(x=>Number(x.id)===Number(booking.hall_package_id)) || {};
    const userById = new Map(users.map(x=>[Number(x.id),x]));
    const decoratedPayments = payments.map(p=>({...p,receiver:userById.get(Number(p.received_by))?.full_name||userById.get(Number(p.received_by))?.username||'—'}));
    const recordedTypes = {};
    for(const p of decoratedPayments) recordedTypes[p.payment_type]=(Number(recordedTypes[p.payment_type])||0)+1;
    const paidTotal = decoratedPayments.reduce((sum,p)=>sum+(String(p.payment_type||'')==='security_refund'?-1:1)*Number(p.amount||0),0);
    const request = discountRequests.filter(x=>Number(x.booking_id)===bookingId).sort((x,y)=>String(y.created_at||'').localeCompare(String(x.created_at||'')))[0];
    const bookingView = {...booking,customer_name:customer.full_name||customer.name||'',phone:customer.phone||'',hall_name:hall.name||'',package_name:pkg.name||'',final_total:Number(booking.event_total||0)+Number(booking.deposit||0)-Number(booking.special_discount||0),special_discount_request_id:request?.id||null};
    res.json({booking:bookingView,payments:decoratedPayments,recorded_types:recordedTypes,paid_total:paidTotal});
  } catch(e) { handleDbError(res,e); }
});
app.get('/api/collection/receipt/:id', auth, requireDb, async (req,res)=>{
  try {
    const p=await one('payments',req.params.id);
    if(!p)return res.status(404).json({error:'الإيصال غير موجود'});
    const b=await one('bookings',p.booking_id)||{};
    const [c,h,pkg,allPayments,users]=await Promise.all([
      one('customers',b.customer_id),one('halls',b.hall_id),one('hall_packages',b.hall_package_id),rows('payments',{booking_id:Number(p.booking_id)}),getRows('users')
    ]);
    const receiver=users.find(u=>Number(u.id)===Number(p.received_by));
    const paidTotal=allPayments.reduce((sum,x)=>sum+(String(x.payment_type||'')==='security_refund'?-1:1)*Number(x.amount||0),0);
    const securityHeld=allPayments.filter(x=>['security_deposit','deposit'].includes(String(x.payment_type||''))).reduce((sum,x)=>sum+Number(x.amount||0),0);
    const securityRefunded=allPayments.filter(x=>String(x.payment_type||'')==='security_refund').reduce((sum,x)=>sum+Number(x.amount||0),0);
    res.json({...p,booking_no:b.booking_no||'',event_date:b.event_date||'',start_time:b.start_time||'',end_time:b.end_time||'',customer_name:c?.full_name||c?.name||'',phone:c?.phone||'',hall_name:h?.name||'',package_name:pkg?.name||'',event_total:Number(b.event_total||0),deposit:Number(b.deposit||0),special_discount:Number(b.special_discount||0),final_total:Number(b.event_total||0)+Number(b.deposit||0)-Number(b.special_discount||0),paid_total:paidTotal,security_held:securityHeld,security_refunded:securityRefunded,receiver:receiver?.full_name||receiver?.username||p.received_by||'—',received_by:receiver?.full_name||receiver?.username||'—'});
  } catch(e) { handleDbError(res,e); }
});
app.get('/api/collection/receipt-by-no/:receiptNo', auth, requireDb, async (req,res)=>{
  try {
    const all=await getRows('payments');
    const p=all.find(x=>String(x.receipt_no)===String(req.params.receiptNo));
    if(!p)return res.status(404).json({error:'الإيصال غير موجود'});
    const b=await one('bookings',p.booking_id)||{};
    const [c,h,allPayments]=await Promise.all([one('customers',b.customer_id),one('halls',b.hall_id),rows('payments',{booking_id:Number(b.id)})]);
    const held=allPayments.filter(x=>['security_deposit','deposit'].includes(String(x.payment_type||''))).reduce((sum,x)=>sum+Number(x.amount||0),0);
    const refunded=allPayments.filter(x=>String(x.payment_type||'')==='security_refund').reduce((sum,x)=>sum+Number(x.amount||0),0);
    res.json({...p,booking_id:b.id,booking_no:b.booking_no||'',event_date:b.event_date||'',customer_name:c?.full_name||c?.name||'',phone:c?.phone||'',hall_name:h?.name||'',security_held:held,security_refunded:refunded,deposit:Number(b.deposit||0)});
  } catch(e) { handleDbError(res,e); }
});
app.delete('/api/collection/payments/:id', auth, requireDb, async (req,res)=>{
  try {
    if(req.user.role!=='admin'&&!req.user.permissions?.includes('delete_collections')&&!req.user.permissions?.includes('delete_all_data')) return res.status(403).json({error:'ليس لديك صلاحية مسح الدفعات'});
    const payment=await one('payments',req.params.id);
    if(!payment)return res.status(404).json({error:'الدفعة غير موجودة'});
    if(String(payment.payment_type||'')==='security_refund')return res.status(409).json({error:'لا يمكن مسح قيد رد التأمين من شاشة التحصيل'});
    const j=await supabase.from('cash_journal').delete().eq('payment_id',Number(payment.id));
    if(j.error)throw j.error;
    const d=await supabase.from('payments').delete().eq('id',Number(payment.id));
    if(d.error)throw d.error;
    res.json({ok:true,message:'تم مسح الدفعة وقيد الخزنة المرتبط بها'});
  } catch(e) { handleDbError(res,e); }
});
app.post('/api/collection/receipt/:id/reprint', auth, requireDb, async (req,res)=>{
  try {
    const payment=await one('payments',req.params.id);
    if(!payment)return res.status(404).json({error:'الإيصال غير موجود'});
    const printed=Number(payment.receipt_reprints||0);
    if(printed>=2)return res.status(409).json({error:'تم استنفاد مرات إعادة الطباعة المسموح بها لهذا الإيصال'});
    const {data,error}=await supabase.from('payments').update({receipt_reprints:printed+1}).eq('id',Number(payment.id)).eq('receipt_reprints',printed).select('*').maybeSingle();
    if(error)throw error;
    if(!data)return res.status(409).json({error:'تم تحديث عدد الطباعة بالتزامن؛ أعد تحميل سجل الدفعات'});
    res.json({ok:true,print_count:Number(data.receipt_reprints||0),reprints_left:Math.max(0,2-Number(data.receipt_reprints||0))});
  } catch(e) { handleDbError(res,e); }
});

app.post('/api/collection/:id/payment', auth, requireDb, async (req,res)=>{
  try {const booking=await one('bookings',req.params.id);if(!booking)return res.status(404).json({error:'الحجز غير موجود'});const amount=Number(req.body?.amount);if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({error:'مبلغ التحصيل غير صحيح'});const receipt_no=receiptNo('RC');const payload={booking_id:booking.id,amount,payment_type:String(req.body?.payment_type||'payment'),paid_at:new Date().toISOString(),received_by:req.user.id,notes:String(req.body?.notes||''),receipt_no,method:String(req.body?.method||'cash'),reference:req.body?.reference||null};const {data,error}=await supabase.from('payments').insert(payload).select('*').single();if(error)throw error;const isRefund=payload.payment_type==='security_refund';const journal={entry_no:receiptNo('CJ'),entry_type:isRefund?'expense':'income',category:isRefund?'رد تأمين':payload.payment_type,amount,method:payload.method,description:payload.notes||(isRefund?`رد تأمين للحجز ${booking.booking_no}`:`تحصيل للحجز ${booking.booking_no}`),booking_id:booking.id,payment_id:data.id,created_by:req.user.id,payee:''};const j=await supabase.from('cash_journal').insert(journal);if(j.error){await supabase.from('payments').delete().eq('id',data.id);throw j.error;}res.status(201).json({ok:true,payment_id:data.id,receipt_no,amount});}
  catch(e){handleDbError(res,e)}
});
app.post('/api/cash-journal/expense', auth, requireDb, async (req,res)=>{
  try {
    const amount=Number(req.body?.amount);if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({error:'مبلغ المصروف غير صحيح'});
    const entry_no=receiptNo('EX');
    const payload={entry_no,entry_type:'expense',category:String(req.body?.category||'مصروف'),amount,method:String(req.body?.method||'cash'),description:String(req.body?.description||''),created_by:req.user.id,payee:String(req.body?.payee||'')};
    const {data,error}=await supabase.from('cash_journal').insert(payload).select('*').single();if(error)throw error;
    const receipt=await supabase.from('expense_receipts').insert({journal_id:data.id,receipt_no:entry_no,payee:payload.payee,invoice_image:req.body?.invoice_image||null,print_count:0}).select('*').single();
    if(receipt.error){await supabase.from('cash_journal').delete().eq('id',data.id);throw receipt.error;}
    res.status(201).json({...data,receipt_no:receipt.data.receipt_no,receipt_id:receipt.data.id,print_count:receipt.data.print_count});
  }catch(e){handleDbError(res,e)}
});
app.post('/api/booking-change-requests/:id/decision', auth, requireDb, requireAdmin, async (req,res)=>{
 try {const status=String(req.body?.decision||'');if(!['approved','rejected'].includes(status))return res.status(400).json({error:'قرار غير صحيح'});const row=await one('booking_change_requests',req.params.id);if(!row)return res.status(404).json({error:'الطلب غير موجود'});if(row.status!=='pending')return res.status(409).json({error:'تم اتخاذ قرار على هذا الطلب مسبقًا'});const {data,error}=await supabase.from('booking_change_requests').update({status,reviewed_by:req.user.id,review_note:String(req.body?.note||''),reviewed_at:new Date().toISOString(),amount:Number(req.body?.amount||row.amount||0)}).eq('id',row.id).select('*').single();if(error)throw error;if(status==='approved'){const changes={};if(row.change_type==='change_date'&&row.new_event_date)changes.event_date=row.new_event_date;if(row.new_start_time)changes.start_time=row.new_start_time;if(row.new_end_time)changes.end_time=row.new_end_time;if(row.change_type==='cancel')changes.status='cancelled';if(Object.keys(changes).length){const u=await supabase.from('bookings').update(changes).eq('id',row.booking_id);if(u.error)throw u.error;}}res.json({ok:true,message:status==='approved'?'تمت الموافقة وتطبيق التعديل المتاح':'تم رفض الطلب',request:data});}
 catch(e){handleDbError(res,e)}
});
app.post('/api/discount-requests/:id/decision', auth, requireDb, requireAdmin, async (req,res)=>{try{const status=String(req.body?.decision||'');if(!['approved','rejected'].includes(status))return res.status(400).json({error:'قرار غير صحيح'});const {data,error}=await supabase.from('discount_requests').update({status,reviewed_by:req.user.id,review_note:String(req.body?.note||''),reviewed_at:new Date().toISOString()}).eq('id',Number(req.params.id)).eq('status','pending').select('*').maybeSingle();if(error)throw error;if(!data)return res.status(404).json({error:'الطلب غير موجود أو تمت مراجعته'});res.json({ok:true,message:'تم حفظ القرار',request:data})}catch(e){handleDbError(res,e)}});
app.post('/api/additional-discount-requests/:id/decision', auth, requireDb, requireAdmin, async (req,res)=>{try{const status=String(req.body?.decision||'');if(!['approved','rejected'].includes(status))return res.status(400).json({error:'قرار غير صحيح'});const {data,error}=await supabase.from('additional_discount_requests').update({status,reviewed_by:req.user.id,review_note:String(req.body?.note||''),reviewed_at:new Date().toISOString()}).eq('id',Number(req.params.id)).eq('status','pending').select('*').maybeSingle();if(error)throw error;if(!data)return res.status(404).json({error:'الطلب غير موجود أو تمت مراجعته'});res.json({ok:true,message:'تم حفظ القرار',request:data})}catch(e){handleDbError(res,e)}});
app.post('/api/followups/:id/result', auth, requireDb, async (req,res)=>{try{const patch={result:String(req.body?.result||''),completed_by:req.user.id,completed_at:new Date().toISOString()};if(req.body?.next_followup_at)patch.next_followup_at=String(req.body.next_followup_at);const {data,error}=await supabase.from('followups').update(patch).eq('id',Number(req.params.id)).select('*').maybeSingle();if(error)throw error;if(!data)return res.status(404).json({error:'موعد المتابعة غير موجود'});res.json(data)}catch(e){handleDbError(res,e)}});
app.post('/api/inventory/items/:id/movement', auth, requireDb, async (req,res)=>{try{const item=await one('inventory_items',req.params.id);if(!item)return res.status(404).json({error:'الصنف غير موجود'});const qty=Number(req.body?.quantity);if(!Number.isFinite(qty)||qty===0)return res.status(400).json({error:'الكمية غير صحيحة'});const movement={item_id:item.id,movement_type:qty>0?'in':'out',quantity:Math.abs(qty),balance_after:Number(item.stock||0)+qty,notes:String(req.body?.reason||''),created_by:req.user.id};const ins=await supabase.from('inventory_movements').insert(movement).select('*').single();if(ins.error)throw ins.error;const upd=await supabase.from('inventory_items').update({stock:Number(item.stock||0)+qty}).eq('id',item.id);if(upd.error)throw upd.error;res.status(201).json({ok:true,item_id:item.id,stock:Number(item.stock||0)+qty,movement:ins.data})}catch(e){handleDbError(res,e)}});
app.post('/api/inventory/alerts/:id/resolve', auth, requireDb, async (req,res)=>{try{const {data,error}=await supabase.from('inventory_alerts').update({status:'resolved'}).eq('id',Number(req.params.id)).select('*').maybeSingle();if(error)throw error;if(!data)return res.status(404).json({error:'التنبيه غير موجود'});res.json(data)}catch(e){handleDbError(res,e)}});

// Specialized read endpoints used by the existing front end.
async function rows(table, filters = {}) {
  let q = supabase.from(table).select('*');
  for (const [k, v] of Object.entries(filters)) if (v !== undefined && v !== null && v !== '') q = q.eq(k, v);
  const { data, error } = await q;
  if (error) throw error;
  return data || [];
}
async function one(table, id) {
  const { data, error } = await supabase.from(table).select('*').eq('id', Number(id)).maybeSingle();
  if (error) throw error;
  return data;
}
app.get('/api/booking-archive', auth, requireDb, async (req,res) => {
  try { const all=await getRows('bookings'); res.json(all.filter(x=>['completed','postponed','cancelled'].includes(String(x.status||'').toLowerCase()))); }
  catch(e){ handleDbError(res,e); }
});
app.get('/api/availability', auth, requireDb, async (req,res) => {
  try {
    const date = String(req.query.date || '');
    const period = String(req.query.period || '').toLowerCase();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({error:'التاريخ غير صحيح'});

    // The calendar UI expects { date, halls: [{ ..., bookings: [] }] }.
    // Returning a flat bookings array made every date look available and
    // caused the detail panel to say there were no halls.
    const [hallRows, bookingRows, customerRows] = await Promise.all([
      rows('halls'), rows('bookings'), rows('customers')
    ]);
    const customerById = new Map(customerRows.map(c => [Number(c.id), c]));
    const isInactive = v => v === false || v === 0 || v === '0' || String(v).toLowerCase() === 'false';
    const activeHalls = hallRows.filter(h => !isInactive(h.active));
    const visibleHalls = activeHalls.length ? activeHalls : hallRows;
    const validBookings = bookingRows.filter(b => {
      const bookingDate = String(b.event_date || '').slice(0, 10);
      const status = String(b.status || '').toLowerCase();
      if (bookingDate !== date || ['cancelled','canceled','postponed'].includes(status)) return false;
      if (period === 'day' && String(b.event_period || '').toLowerCase() !== 'day' && String(b.package_period || '').toLowerCase() !== 'day') return false;
      return true;
    }).map(b => {
      const customer = customerById.get(Number(b.customer_id)) || {};
      return {
        ...b,
        customer_name: b.customer_name || customer.full_name || customer.name || '',
        phone: b.phone || customer.phone || ''
      };
    });

    const halls = visibleHalls.map(h => ({
      ...h,
      bookings: validBookings
        .filter(b => Number(b.hall_id) === Number(h.id))
        .sort((a,b) => String(a.start_time || '').localeCompare(String(b.start_time || '')))
    }));
    res.json({ date, halls });
  } catch(e) { handleDbError(res,e); }
});
app.get('/api/occupancy-calendar', auth, requireDb, async (req,res) => {
  try {
    const from=String(req.query.from||'');
    const to=String(req.query.to||from);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(from) || !/^\d{4}-\d{2}-\d{2}$/.test(to) || from > to) {
      return res.status(400).json({error:'الفترة المحددة لتقويم الغرف غير صحيحة'});
    }
    const [roomRows, assignments, bookings, customers] = await Promise.all([
      rows('bride_rooms'), rows('booking_bride_rooms'), rows('bookings'), rows('customers')
    ]);
    const rooms = roomRows
      .filter(r => r.active !== false && Number(r.active) !== 0)
      .sort((a,b) => Number(a.id)-Number(b.id))
      .map(r => ({id:Number(r.id), name:String(r.name||('غرفة العروسة '+r.id))}));
    const visibleRooms = rooms.length ? rooms : [1,2,3,4,5].map(id => ({id, name:'غرفة العروسة '+id}));
    const bookingById = new Map(bookings.map(b => [Number(b.id), b]));
    const customerById = new Map(customers.map(c => [Number(c.id), c]));
    const roomBookings = assignments.filter(a => {
      const start = String(a.start_at||'').slice(0,10);
      const end = String(a.end_at||'').slice(0,10);
      return start && end && start <= to && end >= from;
    }).flatMap(a => {
      const booking = bookingById.get(Number(a.booking_id));
      if (!booking || ['cancelled','postponed'].includes(String(booking.status||'').toLowerCase())) return [];
      const customer = customerById.get(Number(booking.customer_id)) || {};
      return [{
        ...a,
        room_id: Number(a.room_id),
        booking_id: Number(a.booking_id),
        booking_no: booking.booking_no || '',
        customer_name: customer.full_name || customer.name || '',
        start_at: a.start_at || `${booking.event_date||''} ${booking.start_time||'10:00'}`,
        end_at: a.end_at || `${booking.event_date||''} ${booking.end_time||'23:00'}`
      }];
    });
    res.json({from,to,rooms:visibleRooms,roomBookings});
  } catch(e) { handleDbError(res,e); }
});
app.get('/api/customer-lookup', auth, requireDb, async (req,res) => {
  try { const phone=String(req.query.phone||'').replace(/\D/g,''); if(phone.length<3)return res.json([]); const cs=await rows('customers'); const ids=new Set(cs.filter(c=>String(c.phone||'').replace(/\D/g,'').includes(phone)).map(c=>c.id)); const bs=await rows('bookings'); const out=[]; for(const b of bs.filter(x=>ids.has(x.customer_id))){ const c=cs.find(x=>x.id===b.customer_id)||{}; const h=await one('halls',b.hall_id)||{}; const p=await one('payments',b.id)||{}; out.push({...b,customer_name:c.name||c.full_name||'',phone:c.phone||'',hall_name:h.name||'',paid_amount:Number(p.amount||0)}); } res.json(out); }
  catch(e){ handleDbError(res,e); }
});
app.get('/api/bookings/:id/details', auth, requireDb, async (req,res,next) => {
  if(!/^\d+$/.test(req.params.id)) return next();
  try { const b=await one('bookings',req.params.id); if(!b)return res.status(404).json({error:'الحجز غير موجود'}); const [customer,hall,pkg,payments,files,rooms,buffets,addons]=await Promise.all([one('customers',b.customer_id),one('halls',b.hall_id),one('hall_packages',b.hall_package_id),rows('payments',{booking_id:b.id}),rows('booking_files',{booking_id:b.id}),rows('booking_bride_rooms',{booking_id:b.id}),rows('booking_buffets',{booking_id:b.id}),rows('booking_operational_addons',{booking_id:b.id})]); res.json({...b,customer_name:customer?.name||customer?.full_name||'',phone:customer?.phone||'',hall_name:hall?.name||'',package_name:pkg?.name||'',payments,files,rooms,buffets,addons,paid_amount:payments.reduce((n,x)=>n+Number(x.amount||0),0)}); }
  catch(e){handleDbError(res,e)}
});
app.get('/api/bookings/:id/files', auth, requireDb, async (req,res,next)=>{try{res.json(await rows('booking_files',{booking_id:Number(req.params.id)}))}catch(e){handleDbError(res,e)}});
app.get('/api/bookings/:id/rooms', auth, requireDb, async (req,res,next)=>{try{res.json(await rows('booking_bride_rooms',{booking_id:Number(req.params.id)}))}catch(e){handleDbError(res,e)}});
app.get('/api/bookings/:id/additional-discount-requests', auth, requireDb, async (req,res)=>{try{res.json(await rows('additional_discount_requests',{booking_id:Number(req.params.id)}))}catch(e){handleDbError(res,e)}});
app.get('/api/booking-status-history/:id', auth, requireDb, async (req,res)=>{try{res.json(await rows('booking_status_history',{booking_id:Number(req.params.id)}))}catch(e){handleDbError(res,e)}});
app.get('/api/inquiries/archive', auth, requireDb, async (req,res)=>{try{const all=await getRows('inquiries');res.json(all.filter(x=>['archived','closed','converted'].includes(String(x.status||'').toLowerCase())))}catch(e){handleDbError(res,e)}});
app.get('/api/settings/hall-package-terms', auth, requireDb, async (req,res)=>{try{const {data,error}=await supabase.from('app_settings').select('*').eq('key','hall_package_terms').maybeSingle();if(error)throw error;res.json({terms:data?.value||''})}catch(e){handleDbError(res,e)}});
app.put('/api/settings/hall-package-terms', auth, requireDb, requireAdmin, async (req,res)=>{try{const value=String(req.body?.terms||'');const {data,error}=await supabase.from('app_settings').upsert({key:'hall_package_terms',value},{onConflict:'key'}).select('*').single();if(error)throw error;res.json(data)}catch(e){handleDbError(res,e)}});
app.get('/api/notifications', auth, requireDb, async (req,res)=>{try{const logs=await getRows('audit_logs',{limit:100});res.json(logs.map(x=>({...x,title:x.action||'عملية بالنظام',details:x.details||x.description||'',employee:x.username||'النظام'})))}catch(e){handleDbError(res,e)}});
app.get('/api/summary', auth, requireDb, async (req,res)=>{try{const counts=await Promise.all(['halls','hall_packages','bookings','payments'].map(async t=>[t,(await supabase.from(t).select('id',{count:'exact',head:true})).count||0]));const {data,error}=await supabase.from('payments').select('amount');if(error)throw error;const m=Object.fromEntries(counts);res.json({halls:m.halls,packages:m.hall_packages,bookings:m.bookings,revenue:(data||[]).reduce((s,x)=>s+Number(x.amount||0),0)})}catch(e){handleDbError(res,e)}});
app.get('/api/contractor-report', auth, requireDb, async (req,res)=>{try{const [cs,links,pays]=await Promise.all([getRows('contractors'),getRows('booking_contractors'),getRows('contractor_payouts')]);const mapped=links.map(x=>({...x,contractor_name:cs.find(c=>c.id===x.contractor_id)?.name||cs.find(c=>c.id===x.contractor_id)?.full_name||'',owed:Number(x.cost_amount||0),paid:pays.filter(p=>p.contractor_id===x.contractor_id&&p.booking_id===x.booking_id).reduce((s,p)=>s+Number(p.amount||0),0)}));res.json({rows:mapped,contractors:cs})}catch(e){handleDbError(res,e)}});
app.get('/api/followups', auth, requireDb, async (req,res)=>{try{const [f,is]=await Promise.all([getRows('followups'),getRows('inquiries')]);const now=Date.now();const rows=f.map(x=>{const i=is.find(y=>y.id===x.inquiry_id)||{};return {...x,customer_name:i.customer_name||i.name||'',phone:i.phone||'',inquiry_status:i.status||'',employee:''}});res.json({followups:rows,upcoming_count:rows.filter(x=>x.scheduled_at&&new Date(x.scheduled_at).getTime()>=now&&new Date(x.scheduled_at).getTime()<=now+86400000).length})}catch(e){handleDbError(res,e)}});

app.get('/api/bookings/:id/activity', auth, requireDb, async (req,res)=>{try{const b=await one('bookings',req.params.id);if(!b)return res.status(404).json({error:'الحجز غير موجود'});const [activity,sales,customer]=await Promise.all([rows('booking_activity',{booking_id:b.id}),rows('booking_addon_sales',{booking_id:b.id}),one('customers',b.customer_id)]);const userRows=await getRows('users');const label=x=>userRows.find(u=>u.id===x.user_id)?.full_name||'النظام';res.json({booking:{...b,customer_name:customer?.full_name||'',phone:customer?.phone||''},activity:activity.map(x=>({...x,employee:label(x)})),sales:sales.map(x=>({...x,employee:label(x)}))})}catch(e){handleDbError(res,e)}});
app.put('/api/bookings/:id/details', auth, requireDb, async (req,res)=>{try{const old=await one('bookings',req.params.id);if(!old)return res.status(404).json({error:'الحجز غير موجود'});if(old.status==='cancelled'||old.status==='completed')return res.status(409).json({error:'لا يمكن تعديل حجز ملغي أو مكتمل'});const d=req.body||{};const customer=await one('customers',old.customer_id);if(customer){const cp={full_name:String(d.customer_name??customer.full_name),phone:String(d.phone??customer.phone),id_number:String((d.id_number??customer.id_number)||''),nationality:String((d.nationality??customer.nationality)||'egyptian'),bride_name:String((d.bride_name??customer.bride_name)||''),phone2:String((d.phone2??customer.phone2)||''),contractor_name:String((d.contractor_name??customer.contractor_name)||''),address:String((d.address??customer.address)||''),notes:String((d.notes??customer.notes)||'')};const u=await supabase.from('customers').update(cp).eq('id',customer.id);if(u.error)throw u.error;}const patch={};for(const k of ['event_date','start_time','end_time','guest_count','notes','nationality','event_type','booking_stage'])if(d[k]!==undefined)patch[k]=d[k];if(d.hall_id!==undefined)patch.hall_id=Number(d.hall_id);if(d.hall_package_id!==undefined)patch.hall_package_id=Number(d.hall_package_id);if(d.discount_percent!==undefined){const p=await one('hall_packages',patch.hall_package_id||old.hall_package_id);const hallTotal=Number(p?.price||old.package_price||0);patch.discount=Math.round(hallTotal*Math.max(0,Math.min(100,Number(d.discount_percent)||0)))/100;}const {data,error}=await supabase.from('bookings').update(patch).eq('id',old.id).select('*').single();if(error)throw error;const activity=await supabase.from('booking_activity').insert({booking_id:old.id,user_id:req.user.id,action:'edit_booking',details:JSON.stringify({old:{event_date:old.event_date,guest_count:old.guest_count,notes:old.notes},new:patch})});if(activity.error)console.warn('Could not record booking activity:',activity.error.message);res.json({...data,customer_name:d.customer_name||customer?.full_name,phone:d.phone||customer?.phone})}catch(e){handleDbError(res,e)}});
app.put('/api/bookings/:id/rooms', auth, requireDb, async (req,res)=>{try{const booking=await one('bookings',req.params.id);if(!booking)return res.status(404).json({error:'الحجز غير موجود'});const ids=[...new Set((Array.isArray(req.body?.bride_room_ids)?req.body.bride_room_ids:[]).map(Number).filter(x=>Number.isInteger(x)&&x>0))];const del=await supabase.from('booking_bride_rooms').delete().eq('booking_id',booking.id);if(del.error)throw del.error;if(ids.length){const ins=await supabase.from('booking_bride_rooms').insert(ids.map(room_id=>({booking_id:booking.id,room_id})));if(ins.error)throw ins.error;}res.json({ok:true,bride_room_ids:ids})}catch(e){handleDbError(res,e)}});
app.put('/api/bookings/:id/workflow-status', auth, requireDb, async (req,res)=>{try{if(req.user.role!=='admin')return res.status(403).json({error:'تغيير حالة الحجز متاح للمدير فقط'});const stage=String(req.body?.booking_stage||'');if(!['preliminary','awaiting_manager','confirmed'].includes(stage))return res.status(400).json({error:'حالة الحجز غير صحيحة'});const old=await one('bookings',req.params.id);if(!old)return res.status(404).json({error:'الحجز غير موجود'});const {data,error}=await supabase.from('bookings').update({booking_stage:stage}).eq('id',old.id).select('*').single();if(error)throw error;await supabase.from('booking_activity').insert({booking_id:old.id,user_id:req.user.id,action:'booking_stage_changed',details:JSON.stringify({old_stage:old.booking_stage,new_stage:stage})});res.json(data)}catch(e){handleDbError(res,e)}});
app.post('/api/bookings/:id/postpone', auth, requireDb, async (req,res)=>{try{const old=await one('bookings',req.params.id);if(!old)return res.status(404).json({error:'الحجز غير موجود'});const d=req.body||{};const date=String(d.event_date||d.new_event_date||'');if(!/^\d{4}-\d{2}-\d{2}$/.test(date)||date<new Date().toISOString().slice(0,10))return res.status(400).json({error:'التاريخ الجديد غير صحيح'});if(!String(d.reason||'').trim())return res.status(400).json({error:'سبب التأجيل مطلوب'});if(req.user.role!=='admin'){const ins=await supabase.from('booking_change_requests').insert({booking_id:old.id,requested_by:req.user.id,change_type:'change_date',old_event_date:old.event_date,new_event_date:date,new_start_time:d.start_time||old.start_time,new_end_time:d.end_time||old.end_time,reason:String(d.reason),status:'pending'});if(ins.error)throw ins.error;return res.json({ok:true,message:'تم إرسال طلب التأجيل للمدير للمراجعة'})}const patch={event_date:date,postponed_from_date:old.event_date,status:'postponed'};if(d.start_time)patch.start_time=d.start_time;if(d.end_time)patch.end_time=d.end_time;const {data,error}=await supabase.from('bookings').update(patch).eq('id',old.id).select('*').single();if(error)throw error;await supabase.from('booking_status_history').insert({booking_id:old.id,old_status:old.status,new_status:'postponed',old_event_date:old.event_date,new_event_date:date,reason:String(d.reason),changed_by:req.user.id});await supabase.from('booking_activity').insert({booking_id:old.id,user_id:req.user.id,action:'postpone_booking',details:JSON.stringify({old_event_date:old.event_date,new_event_date:date,reason:d.reason})});res.json({ok:true,booking:data})}catch(e){handleDbError(res,e)}});
app.post('/api/bookings/:id/collect-initial', auth, requireDb, async (req,res)=>{try{const b=await one('bookings',req.params.id);if(!b)return res.status(404).json({error:'الحجز غير موجود'});const existing=await rows('payments',{booking_id:b.id});if(existing.some(p=>p.payment_type==='deposit'||p.payment_type==='initial'))return res.status(409).json({error:'تم تسجيل التحصيل الابتدائي لهذا الحجز بالفعل'});const amount=Number(b.deposit||5000);const receipt_no=receiptNo('RC');const {data,error}=await supabase.from('payments').insert({booking_id:b.id,amount,payment_type:'deposit',paid_at:new Date().toISOString(),received_by:req.user.id,notes:'تحصيل التأمين الابتدائي',receipt_no,method:'cash'}).select('*').single();if(error)throw error;const j=await supabase.from('cash_journal').insert({entry_no:receiptNo('CJ'),entry_type:'income',category:'deposit',amount,method:'cash',description:`تأمين الحجز ${b.booking_no}`,booking_id:b.id,payment_id:data.id,created_by:req.user.id,payee:''});if(j.error){await supabase.from('payments').delete().eq('id',data.id);throw j.error}res.json({ok:true,booking:b,payment_id:data.id,receipt_no})}catch(e){handleDbError(res,e)}});

// Booking creation: validate and persist the booking plus its related selections.
app.post('/api/bookings', auth, requireDb, async (req,res)=>{
  let createdBookingId=null;
  try {
    const d=req.body||{}; const required=['customer_name','phone','hall_id','hall_package_id','event_date','start_time','end_time','guest_count'];
    for(const k of required) if(d[k]===undefined||d[k]===null||String(d[k]).trim()==='') return res.status(400).json({error:`البيان مطلوب: ${k}`});
    const guests=Number(d.guest_count), hallId=Number(d.hall_id), packageId=Number(d.hall_package_id);
    if(!Number.isInteger(guests)||guests<1)return res.status(400).json({error:'عدد الأفراد يجب أن يكون رقمًا صحيحًا أكبر من صفر'});
    if(String(d.event_date)<new Date().toISOString().slice(0,10))return res.status(400).json({error:'تاريخ المناسبة لا يمكن أن يكون في الماضي'});
    const [hall,pkg]=await Promise.all([one('halls',hallId),one('hall_packages',packageId)]);
    if(!hall||!pkg||Number(pkg.hall_id)!==hallId)return res.status(400).json({error:'القاعة أو باكدج القاعة غير صحيح'});
    const phone=String(d.phone).trim();let customer=null;const {data:found,error:findErr}=await supabase.from('customers').select('*').eq('phone',phone).limit(1).maybeSingle();if(findErr)throw findErr;customer=found;
    const customerPayload={full_name:String(d.customer_name).trim(),phone,id_number:String(d.id_number||''),nationality:String(d.nationality||'egyptian'),notes:String(d.notes||''),bride_name:String(d.bride_name||''),phone2:String(d.phone2||''),contractor_name:String(d.contractor_name||d.customer_name).trim(),address:String(d.address||'')};
    if(customer){const u=await supabase.from('customers').update(customerPayload).eq('id',customer.id).select('*').single();if(u.error)throw u.error;customer=u.data;}else{const c=await supabase.from('customers').insert(customerPayload).select('*').single();if(c.error)throw c.error;customer=c.data;}
    const packageRows=await getRows('hall_packages');const basePkg=packageRows.filter(x=>Number(x.hall_id)===hallId&&String(x.period)===String(d.event_period||pkg.period)&&Number(x.active??1)!==0).sort((a,b)=>Number(a.guest_count)-Number(b.guest_count)||Number(a.price)-Number(b.price))[0]||pkg;
    const extraRate=String(d.event_period||pkg.period)==='day'?75:60;const hallTotal=Number(basePkg.price||pkg.price||0)+Math.max(0,guests-Number(basePkg.guest_count||pkg.guest_count||0))*extraRate;
    let buffetTotal=0,addonsTotal=0,operationalTotal=0;const buffetRows=[],addonRows=[],operationalRows=[];
    for(const selected of Array.isArray(d.buffet_package_ids)?d.buffet_package_ids:[]){const id=Number(typeof selected==='object'?selected.id:selected),count=Number(typeof selected==='object'?selected.guest_count:guests);const item=await one('buffet_packages',id);if(!item)throw new Error(`باكدج بوفيه غير موجود: ${id}`);const total=Number(item.price_per_person||0)*Math.max(1,count);buffetTotal+=total;buffetRows.push({buffet_package_id:id,guest_count:Math.max(1,count),unit_price:Number(item.price_per_person||0),line_total:total});}
    for(const selected of Array.isArray(d.addons)?d.addons:[]){const id=Number(selected.id),count=Number(selected.guest_count||guests),item=await one('addons',id);if(!item)throw new Error(`إضافة بوفيه غير موجودة: ${id}`);const unit=Number(item.price||0),total=unit*Math.max(1,count);addonsTotal+=total;addonRows.push({addon_id:id,quantity_per_person:Number(selected.quantity_per_person||1),guest_count:Math.max(1,count),unit_price:unit,line_total:total});}
    for(const selected of Array.isArray(d.operational_addons)?d.operational_addons:[]){const id=Number(selected.id),qty=Number(selected.quantity||1),item=await one('operational_addons',id);if(!item)throw new Error(`إضافة تشغيل غير موجودة: ${id}`);const unit=Number(item.price||0),total=unit*Math.max(1,qty);operationalTotal+=total;operationalRows.push({addon_id:id,name_snapshot:item.name,unit_price:unit,quantity:Math.max(1,qty),line_total:total,created_by:req.user.id});}
    const discountPct=Math.max(0,Math.min(100,Number(d.discount_percent||0)));const discount=Math.round(Math.max(0,hallTotal)*discountPct)/100;const buffetDiscount=0;const softDrink=d.soft_drink_upgrade?guests*15:0;const subtotal=Math.max(0,hallTotal-discount)+buffetTotal+addonsTotal+operationalTotal+softDrink;const service=Math.round(subtotal*0.15*100)/100;const extraBrideFee=d.extra_brides_fee?Math.round((subtotal+service)*0.25*100)/100:0;const deposit=String(d.nationality)==='non_egyptian'?10000:5000;const eventTotal=subtotal+service+extraBrideFee;const bookingNo=`NS-${new Date().toISOString().slice(0,10).replaceAll('-','')}-${Math.random().toString(36).slice(2,7).toUpperCase()}`;
    const payload={booking_no:bookingNo,customer_id:customer.id,hall_id:hallId,hall_package_id:packageId,event_date:String(d.event_date),start_time:String(d.start_time),end_time:String(d.end_time),guest_count:guests,nationality:String(d.nationality||'egyptian'),deposit,package_price:hallTotal,buffet_total:buffetTotal,addons_total:addonsTotal,discount,special_discount:0,service_rate:15,service_total:service,event_total:eventTotal,amount_due:eventTotal+deposit,status:'confirmed',notes:String(d.notes||''),created_by:req.user.id,booking_stage:String(d.booking_stage||'preliminary'),event_type:String(d.event_type||'wedding'),buffet_discount:buffetDiscount,offer_id:d.selected_offer_id?Number(d.selected_offer_id):null,offer_discount:0,free_meals:0,extra_guest_total:Math.max(0,guests-Number(basePkg.guest_count||0))*extraRate};
    const ins=await supabase.from('bookings').insert(payload).select('*').single();if(ins.error)throw ins.error;createdBookingId=ins.data.id;
    if(buffetRows.length){const x=await supabase.from('booking_buffets').insert(buffetRows.map(r=>({...r,booking_id:createdBookingId})));if(x.error)throw x.error;}
    if(addonRows.length){const x=await supabase.from('booking_addons').insert(addonRows.map(r=>({...r,booking_id:createdBookingId})));if(x.error)throw x.error;}
    if(operationalRows.length){const x=await supabase.from('booking_operational_addons').insert(operationalRows.map(r=>({...r,booking_id:createdBookingId})));if(x.error)throw x.error;}
    const roomIds=(Array.isArray(d.bride_room_ids)?d.bride_room_ids:[]).map(Number).filter(Number.isFinite);if(roomIds.length){const x=await supabase.from('booking_bride_rooms').insert(roomIds.map(room_id=>({booking_id:createdBookingId,room_id})));if(x.error)throw x.error;}
    const activity=await supabase.from('booking_activity').insert({booking_id:createdBookingId,user_id:req.user.id,action:'create_booking',details:JSON.stringify({booking_no:bookingNo,customer_name:customer.full_name,event_date:payload.event_date})});if(activity.error)console.warn('Booking activity could not be written:',activity.error.message);
    if(discountPct>Number(req.user.discount_normal||0)&&req.user.role!=='admin'){const reqIns=await supabase.from('discount_requests').insert({booking_id:createdBookingId,requested_by:req.user.id,percent:discountPct,reason:String(d.discount_reason||'طلب خصم أثناء إنشاء الحجز'),status:'pending'});if(reqIns.error)throw reqIns.error;}
    res.status(201).json({...ins.data,customer_name:customer.full_name,phone:customer.phone});
  } catch(e){if(createdBookingId){try{await supabase.from('bookings').delete().eq('id',createdBookingId)}catch{}}handleDbError(res,e)}
});
app.post('/api/bookings/:id/change-requests', auth, requireDb, async (req,res)=>{try{const b=await one('bookings',req.params.id);if(!b)return res.status(404).json({error:'الحجز غير موجود'});const d=req.body||{};const payload={booking_id:b.id,requested_by:req.user.id,change_type:String(d.change_type||d.type||'change_date'),old_event_date:b.event_date,new_event_date:d.new_event_date||d.event_date||null,new_start_time:d.new_start_time||d.start_time||null,new_end_time:d.new_end_time||d.end_time||null,item_action:d.item_action||null,item_details:d.item_details||null,reason:String(d.reason||''),amount:Number(d.amount||0),status:'pending'};if(!payload.reason)return res.status(400).json({error:'سبب الطلب مطلوب'});const {data,error}=await supabase.from('booking_change_requests').insert(payload).select('*').single();if(error)throw error;res.status(201).json({ok:true,message:'تم إرسال الطلب للمدير للمراجعة',request:data})}catch(e){handleDbError(res,e)}});
app.post('/api/bookings/:id/cancel', auth, requireDb, async (req,res)=>{try{const b=await one('bookings',req.params.id);if(!b)return res.status(404).json({error:'الحجز غير موجود'});if(req.user.role!=='admin'){return res.status(403).json({error:'إلغاء الحجز يتطلب موافقة المدير'});}const {data,error}=await supabase.from('bookings').update({status:'cancelled',cancel_reason:String(req.body?.reason||'')}).eq('id',b.id).select('*').single();if(error)throw error;await supabase.from('booking_status_history').insert({booking_id:b.id,old_status:b.status,new_status:'cancelled',old_event_date:b.event_date,new_event_date:b.event_date,reason:String(req.body?.reason||''),changed_by:req.user.id});res.json(data)}catch(e){handleDbError(res,e)}});

// Specialized endpoints for cashbox and expense receipts. The UI needs joined journal, booking, user and receipt fields.
app.get('/api/cash-journal', auth, requireDb, async (req,res)=>{
  try {
    const [journal,payments,receipts,bookings,customers,users,contractors]=await Promise.all([
      getRows('cash_journal'),getRows('payments'),getRows('expense_receipts'),getRows('bookings'),getRows('customers'),getRows('users'),getRows('contractors')
    ]);
    const usersById=new Map(users.map(x=>[Number(x.id),x]));
    const bookingsById=new Map(bookings.map(x=>[Number(x.id),x]));
    const paymentsById=new Map(payments.map(x=>[Number(x.id),x]));
    const receiptsByJournalId=new Map(receipts.map(x=>[Number(x.journal_id),x]));
    const contractorsById=new Map(contractors.map(x=>[Number(x.id),x]));
    const rowsOut=journal.map(j=>{
      const b=bookingsById.get(Number(j.booking_id))||{};
      const c=customers.find(x=>Number(x.id)===Number(b.customer_id))||{};
      const pay=paymentsById.get(Number(j.payment_id))||{};
      const receipt=receiptsByJournalId.get(Number(j.id))||{};
      const contractor=contractorsById.get(Number(j.contractor_id))||{};
      const user=usersById.get(Number(j.created_by))||{};
      return {...j,booking_no:b.booking_no||'',event_date:b.event_date||'',customer_name:c.full_name||c.name||'',phone:c.phone||'',employee:user.full_name||user.username||'النظام',payment_receipt_no:pay.receipt_no||'',receipt_no:receipt.receipt_no||pay.receipt_no||'',receipt_id:receipt.id||null,print_count:Number(receipt.print_count||0),invoice_image:receipt.invoice_image||null,contractor_name:contractor.full_name||contractor.name||''};
    }).filter(x=>String(req.query.scope||'')!=='expenses'||x.entry_type==='expense');
    res.json(rowsOut);
  } catch(e) { handleDbError(res,e); }
});
app.get('/api/expense-receipts', auth, requireDb, async (req,res)=>{
  try {
    const [receipts,journal,users]=await Promise.all([getRows('expense_receipts'),getRows('cash_journal'),getRows('users')]);
    const out=receipts.map(r=>{const j=journal.find(x=>Number(x.id)===Number(r.journal_id))||{};const u=users.find(x=>Number(x.id)===Number(j.created_by))||{};return {...r,entry_no:j.entry_no||'',entry_type:j.entry_type||'expense',category:j.category||'',amount:Number(j.amount||0),method:j.method||'',description:j.description||'',payee:r.payee||j.payee||'',created_at:j.created_at||r.created_at,employee:u.full_name||u.username||'النظام'};});
    res.json(out);
  } catch(e) { handleDbError(res,e); }
});
app.get('/api/expense-receipts/:id', auth, requireDb, async (req,res)=>{
  try {
    const receipt=await one('expense_receipts',req.params.id);
    if(!receipt)return res.status(404).json({error:'إيصال المصروف غير موجود'});
    const journal=await one('cash_journal',receipt.journal_id);
    if(!journal)return res.status(404).json({error:'قيد المصروف المرتبط بالإيصال غير موجود'});
    res.json({...receipt,receipt_id:receipt.id,entry_no:journal.entry_no,entry_type:journal.entry_type,category:journal.category,amount:journal.amount,method:journal.method,description:journal.description,payee:receipt.payee||journal.payee||'',created_at:journal.created_at,created_by:journal.created_by});
  } catch(e) { handleDbError(res,e); }
});
app.post('/api/expense-receipts/:id/print', auth, requireDb, async (req,res)=>{
  try {
    const receipt=await one('expense_receipts',req.params.id);
    if(!receipt)return res.status(404).json({error:'إيصال المصروف غير موجود'});
    const count=Number(receipt.print_count||0);
    if(count>=3)return res.status(409).json({error:'تم استنفاد مرات طباعة إيصال المصروف المسموح بها (3 مرات)'});
    const {data,error}=await supabase.from('expense_receipts').update({print_count:count+1}).eq('id',Number(receipt.id)).eq('print_count',count).select('*').maybeSingle();
    if(error)throw error;
    if(!data)return res.status(409).json({error:'تم تحديث عدد الطباعة بالتزامن؛ حدّث الصفحة'});
    res.json({ok:true,print_count:Number(data.print_count||0),reprints_left:Math.max(0,3-Number(data.print_count||0))});
  } catch(e) { handleDbError(res,e); }
});

// Work-order APIs are explicit because the work-order screen expects a joined payload, not a raw work_orders table.
const WORK_ORDER_TYPES={hall:{code:'HALL',title:'أمر تجهيز القاعة'},kitchen:{code:'KITCHEN',title:'أمر تشغيل المطبخ'},store:{code:'STORE',title:'أمر تجهيز المخزن'},contractor:{code:'CONTRACTOR',title:'أمر تشغيل المتعهد'}};
const drinkPattern=/(مياه|مياة|ماء|زجاجة|كانز|كنز|سوفت|درينك|عصير|كولا|بيبسي|سفن|7\s*up|water|juice|soft.?drink|can)/i;
async function workOrderContext(booking){
  const [customer,hall,pkg,bookingBuffets,bufferPackages,bufferItems,packageItems,bookingAddons,addons,operationalAddons,inventory,contractors,assignments]=await Promise.all([
    one('customers',booking.customer_id),one('halls',booking.hall_id),one('hall_packages',booking.hall_package_id),rows('booking_buffets',{booking_id:Number(booking.id)}),getRows('buffet_packages'),getRows('buffet_items'),getRows('buffet_package_items'),rows('booking_addons',{booking_id:Number(booking.id)}),getRows('addons'),rows('booking_operational_addons',{booking_id:Number(booking.id)}),getRows('inventory_items'),getRows('contractors'),rows('booking_work_contractors',{booking_id:Number(booking.id)})
  ]);
  return {booking,customer:customer||{},hall:hall||{},pkg:pkg||{},bookingBuffets,bufferPackages,bufferItems,packageItems,bookingAddons,addons,operationalAddons,inventory,contractors,assignments};
}
function workOrderSpecs(context,type,contractorAssignment=null){
  const {booking,customer,hall,pkg,bookingBuffets,bufferPackages,bufferItems,packageItems,bookingAddons,addons,operationalAddons,inventory}=context;
  const specs=[];
  if(type==='hall'){
    specs.push({item_name:hall.name||'القاعة',quantity:1,unit:'قاعة',details:''});
    specs.push({item_name:'عدد الأفراد',quantity:Number(booking.guest_count||0),unit:'فرد',details:''});
    if(pkg.name)specs.push({item_name:'باكدج القاعة — '+pkg.name,quantity:1,unit:'باكدج',details:''});
    for(const item of operationalAddons)specs.push({item_name:String(item.name_snapshot||'إضافة تشغيل'),quantity:Number(item.quantity||1),unit:'وحدة',details:''});
  } else if(type==='kitchen'){
    for(const selected of bookingBuffets){const buffet=bufferPackages.find(x=>Number(x.id)===Number(selected.buffet_package_id));if(buffet)specs.push({item_name:String(buffet.name),quantity:Number(selected.guest_count||booking.guest_count||0),unit:'فرد',details:'باكدج البوفيه'});}
    for(const selected of bookingAddons){const addon=addons.find(x=>Number(x.id)===Number(selected.addon_id));const name=String(addon?.name||'إضافة بوفيه');if(drinkPattern.test(name))continue;specs.push({item_name:name,quantity:Number(selected.guest_count||booking.guest_count||0)*Number(selected.quantity_per_person||1),unit:'قطعة',details:''});}
    if(Number(booking.free_meals||0)>0)specs.push({item_name:String(booking.free_meals_description||booking.free_meal_name||'وجبات هدية'),quantity:Number(booking.free_meals),unit:'وجبة',details:'ضمن العرض'});
  } else if(type==='store'){
    const totals=new Map();
    const addInventory=(inv,qty,detail)=>{if(!inv||!(inv.active===true||Number(inv.active)===1)||!Number.isFinite(qty)||qty<=0)return;const k=Number(inv.id);const old=totals.get(k)||{item_name:String(inv.name||'صنف مخزن'),quantity:0,unit:String(inv.unit||'وحدة'),details:detail||''};old.quantity+=qty;if(detail&&!old.details.includes(detail))old.details=[old.details,detail].filter(Boolean).join('، ');totals.set(k,old)};
    for(const selected of bookingBuffets){
      const buffet=bufferPackages.find(x=>Number(x.id)===Number(selected.buffet_package_id));
      const selectedItems=packageItems.filter(x=>Number(x.package_id)===Number(selected.buffet_package_id));
      for(const rel of selectedItems){
        const linked=inventory.filter(i=>Number(i.buffet_item_id)===Number(rel.item_id)&&String(i.source_type||'menu')!=='addon');
        const qty=Number(selected.guest_count||booking.guest_count||0)*Number(rel.quantity||0);
        for(const inv of linked)addInventory(inv,qty*Number(inv.units_per_buffet_unit||1),buffet?.name||'باكدج البوفيه');
      }
    }
    for(const selected of bookingAddons){
      const linked=inventory.filter(i=>Number(i.addon_id)===Number(selected.addon_id)&&String(i.source_type||'')==='addon');
      const addon=addons.find(x=>Number(x.id)===Number(selected.addon_id));
      const qty=Number(selected.guest_count||booking.guest_count||0)*Number(selected.quantity_per_person||1);
      for(const inv of linked)addInventory(inv,qty*Number(inv.units_per_buffet_unit||1),addon?.name||'إضافة');
    }
    specs.push(...[...totals.values()].sort((a,b)=>a.item_name.localeCompare(b.item_name,'ar')));
  } else if(type==='contractor'&&contractorAssignment){
    const contractor=(context.contractors||[]).find(c=>Number(c.id)===Number(contractorAssignment.contractor_id))||{};
    const details=String(contractorAssignment.service_details||'').trim();
    specs.push({item_name:details||contractor.job_title||'الخدمة المطلوبة',quantity:1,unit:'خدمة',details:''});
  }
  return specs;
}
async function saveWorkOrder(booking,type,specs,userId,contractorId=null,notes=''){
  const meta=WORK_ORDER_TYPES[type];
  if(!meta)throw new Error('نوع أمر التشغيل غير صحيح');
  const allExisting=await rows('work_orders',{booking_id:Number(booking.id),order_type:type});
  const existing=allExisting.find(x=>contractorId===null?x.contractor_id===null||x.contractor_id===undefined:Number(x.contractor_id)===Number(contractorId));
  const now=new Date().toISOString();
  let order;
  if(existing){
    const version=Number(existing.version||1)+1;
    const upd=await supabase.from('work_orders').update({title:meta.title,status:'new',version,updated_at:now,notes:String(notes||'')}).eq('id',Number(existing.id)).select('*').single();
    if(upd.error)throw upd.error;order=upd.data;
    const del=await supabase.from('work_order_lines').delete().eq('work_order_id',Number(order.id));if(del.error)throw del.error;
    const hist=await supabase.from('work_order_history').insert({work_order_id:order.id,version,action:'updated',details:JSON.stringify({serial_no:order.serial_no,title:meta.title,lines_count:specs.length}),user_id:userId});if(hist.error)throw hist.error;
  } else {
    const current=await getRows('work_orders');const nextNo=Math.max(0,...current.map(x=>Number(x.id)||0))+1;const serial_no=`WO-${meta.code}-${String(nextNo).padStart(7,'0')}`;
    const ins=await supabase.from('work_orders').insert({serial_no,booking_id:Number(booking.id),order_type:type,contractor_id:contractorId,title:meta.title,status:'new',version:1,created_by:userId,updated_at:now,notes:String(notes||'')}).select('*').single();
    if(ins.error)throw ins.error;order=ins.data;
    const hist=await supabase.from('work_order_history').insert({work_order_id:order.id,version:1,action:'created',details:JSON.stringify({serial_no,title:meta.title,lines_count:specs.length}),user_id:userId});if(hist.error)throw hist.error;
  }
  const cleanSpecs=specs.filter(x=>String(x.item_name||'').trim()).map(x=>({work_order_id:Number(order.id),item_name:String(x.item_name),quantity:Number.isFinite(Number(x.quantity))?Number(x.quantity):1,unit:String(x.unit||''),details:String(x.details||'')}));
  if(cleanSpecs.length){const insLines=await supabase.from('work_order_lines').insert(cleanSpecs);if(insLines.error)throw insLines.error;}
  return order;
}
async function decorateWorkOrder(order,context){
  const booking=context.bookingsById.get(Number(order.booking_id))||{};
  const customer=context.customersById.get(Number(booking.customer_id))||{};
  const hall=context.hallsById.get(Number(booking.hall_id))||{};
  const pkg=context.packagesById.get(Number(booking.hall_package_id))||{};
  const contractor=context.contractorsById.get(Number(order.contractor_id))||{};
  return {...order,booking_no:booking.booking_no||'',customer_name:customer.full_name||customer.name||'',customer_phone:customer.phone||'',phone:customer.phone||'',hall_name:hall.name||'',package_name:pkg.name||'',event_date:booking.event_date||'',start_time:booking.start_time||'',end_time:booking.end_time||'',guest_count:Number(booking.guest_count||0),contractor_name:contractor.full_name||contractor.contractor_name||'',contractor_job:contractor.job_title||'',lines:context.lines.filter(x=>Number(x.work_order_id)===Number(order.id))};
}
app.get('/api/work-orders', auth, requireDb, async (req,res)=>{
  try{
    const [bookings,customers,halls,packages,orders,lines,contractors]=await Promise.all([getRows('bookings'),getRows('customers'),getRows('halls'),getRows('hall_packages'),getRows('work_orders'),getRows('work_order_lines'),getRows('contractors')]);
    const customersById=new Map(customers.map(x=>[Number(x.id),x]));
    const hallsById=new Map(halls.map(x=>[Number(x.id),x]));
    const packagesById=new Map(packages.map(x=>[Number(x.id),x]));
    const bookingsById=new Map(bookings.map(x=>[Number(x.id),x]));
    const contractorsById=new Map(contractors.map(x=>[Number(x.id),x]));
    const bookingViews=bookings.map(b=>{const c=customersById.get(Number(b.customer_id))||{};const h=hallsById.get(Number(b.hall_id))||{};const p=packagesById.get(Number(b.hall_package_id))||{};return {...b,customer_name:c.full_name||c.name||'',customer_phone:c.phone||'',phone:c.phone||'',hall_name:h.name||'',package_name:p.name||''};});
    if(req.query.booking_phone!==undefined){
      const q=String(req.query.booking_phone||'').replace(/\D/g,'');
      if(q.length<3)return res.json({bookings:[]});
      const matchingIds=new Set(customers.filter(c=>{const p=String(c.phone||'').replace(/\D/g,'');return p.includes(q)||q.includes(p)||p.slice(-10)===q.slice(-10)}).map(c=>Number(c.id)));
      return res.json({bookings:bookingViews.filter(b=>matchingIds.has(Number(b.customer_id))&&!['cancelled','completed'].includes(String(b.status||'').toLowerCase()))});
    }
    const phone=String(req.query.q||'').replace(/\D/g,'');
    let filteredOrders=orders.map(order=>({...order,lines:lines.filter(l=>Number(l.work_order_id)===Number(order.id))}));
    const filterType=String(req.query.type||''),filterStatus=String(req.query.status||''),from=String(req.query.from||''),to=String(req.query.to||'');
    const q=String(req.query.q||'').trim().toLowerCase();
    const rowsOut=[];
    for(const order of filteredOrders){
      const booking=bookingsById.get(Number(order.booking_id))||{};const customer=customersById.get(Number(booking.customer_id))||{};const hall=hallsById.get(Number(booking.hall_id))||{};const contractor=contractorsById.get(Number(order.contractor_id))||{};
      const date=String(booking.event_date||'').slice(0,10);
      if(filterType&&order.order_type!==filterType)continue;if(filterStatus&&order.status!==filterStatus)continue;if(from&&date<from)continue;if(to&&date>to)continue;
      const search=[order.serial_no,order.title,booking.booking_no,customer.full_name,customer.name,customer.phone,hall.name,contractor.full_name,contractor.job_title].join(' ').toLowerCase();if(q&&!search.includes(q)&&!(phone.length>=3&&String(customer.phone||'').replace(/\D/g,'').includes(phone)))continue;
      rowsOut.push(order);
    }
    const context={bookingsById,customersById,hallsById,packagesById,contractorsById,lines};
    const decorated=[];for(const order of rowsOut)decorated.push(await decorateWorkOrder(order,context));
    const eligibleBookings=bookingViews.filter(b=>String(b.booking_stage||'')==='confirmed'&&!['cancelled','completed'].includes(String(b.status||'').toLowerCase()));
    const eligibleContractors=contractors.filter(c=>c.active===undefined||c.active===null||c.active===true||Number(c.active)===1).map(c=>({...c,hall_name:hallsById.get(Number(c.hall_id))?.name||''}));
    res.json({rows:decorated,bookings:eligibleBookings,contractors:eligibleContractors});
  }catch(e){handleDbError(res,e)}
});
app.post('/api/work-orders/generate/:id', auth, requireDb, async (req,res)=>{
  try{
    const booking=await one('bookings',req.params.id);if(!booking)return res.status(404).json({error:'الحجز غير موجود'});
    if(String(booking.booking_stage||'')!=='confirmed')return res.status(409).json({error:'لا يمكن إصدار أوامر الشغل قبل تأكيد الحجز من الإدارة.'});
    if(['cancelled','completed'].includes(String(booking.status||'').toLowerCase()))return res.status(409).json({error:'لا يمكن إصدار أوامر شغل لحجز ملغي أو مكتمل.'});
    const context=await workOrderContext(booking);
    const core=[['hall','أمر تجهيز القاعة'],['kitchen','أمر تشغيل المطبخ'],['store','أمر تجهيز المخزن']];
    const saved=[];for(const [type] of core){const specs=workOrderSpecs(context,type);saved.push(await saveWorkOrder(booking,type,specs,req.user.id,null,String(booking.notes||'')));}
    res.json({ok:true,message:'تم إصدار/تحديث أوامر القاعة والمطبخ والمخزن بنجاح',orders:saved});
  }catch(e){handleDbError(res,e)}
});
app.post('/api/work-orders/assign-contractor/:id', auth, requireDb, async (req,res)=>{
  try{
    const booking=await one('bookings',req.params.id);if(!booking)return res.status(404).json({error:'الحجز غير موجود'});
    if(String(booking.booking_stage||'')!=='confirmed'||['cancelled','completed'].includes(String(booking.status||'').toLowerCase()))return res.status(409).json({error:'إسناد المتعهد متاح للحجز المؤكد والفعال فقط.'});
    const contractorId=Number(req.body?.contractor_id),cost=Number(req.body?.cost_amount||0),details=String(req.body?.service_details||'').trim();
    if(!Number.isInteger(contractorId)||contractorId<=0)return res.status(400).json({error:'اختر متعهدًا صحيحًا.'});
    if(!Number.isFinite(cost)||cost<0)return res.status(400).json({error:'التكلفة الداخلية غير صحيحة.'});
    if(!details)return res.status(400).json({error:'اكتب تفاصيل الخدمة المطلوبة للمتعهد.'});
    const contractor=await one('contractors',contractorId);if(!contractor||!(contractor.active===true||Number(contractor.active)===1))return res.status(404).json({error:'المتعهد غير موجود أو غير نشط.'});
    const {data:hall}=await supabase.from('halls').select('name').eq('id',Number(booking.hall_id)).maybeSingle();
    const existingLinks=await rows('booking_work_contractors',{booking_id:Number(booking.id),contractor_id:contractorId});
    let assignment;
    if(existingLinks.length){const upd=await supabase.from('booking_work_contractors').update({cost_amount:cost,service_details:details,created_by:req.user.id,active:1}).eq('id',Number(existingLinks[0].id)).select('*').single();if(upd.error)throw upd.error;assignment=upd.data;}
    else {const ins=await supabase.from('booking_work_contractors').insert({booking_id:Number(booking.id),contractor_id:contractorId,cost_amount:cost,service_details:details,created_by:req.user.id,active:1}).select('*').single();if(ins.error)throw ins.error;assignment=ins.data;}
    const oldLink=await rows('booking_contractors',{booking_id:Number(booking.id),contractor_id:contractorId});
    const linkPayload={booking_id:Number(booking.id),contractor_id:contractorId,contractor_name:String(contractor.full_name||contractor.name||''),job_title:String(contractor.job_title||''),hall_name:String(hall?.name||''),cost_amount:cost};
    if(oldLink.length){const upd=await supabase.from('booking_contractors').update(linkPayload).eq('id',Number(oldLink[0].id));if(upd.error)throw upd.error;}
    else {const ins=await supabase.from('booking_contractors').insert(linkPayload);if(ins.error)throw ins.error;}
    const context=await workOrderContext(booking);const spec=workOrderSpecs(context,'contractor',assignment);const order=await saveWorkOrder(booking,'contractor',spec,req.user.id,contractorId,details);
    res.json({ok:true,message:'تم إسناد المتعهد وإنشاء/تحديث أمر التشغيل الخاص به',assignment,order});
  }catch(e){handleDbError(res,e)}
});
app.put('/api/work-orders/:id/status', auth, requireDb, async (req,res)=>{
  try{
    const allowedStatus=['new','printed','delivered','in_progress','completed','cancelled'];const status=String(req.body?.status||'');if(!allowedStatus.includes(status))return res.status(400).json({error:'حالة أمر التشغيل غير صحيحة'});
    const order=await one('work_orders',req.params.id);if(!order)return res.status(404).json({error:'أمر التشغيل غير موجود'});
    const {data,error}=await supabase.from('work_orders').update({status,updated_at:new Date().toISOString()}).eq('id',Number(order.id)).select('*').single();if(error)throw error;
    if(status!==order.status){const hist=await supabase.from('work_order_history').insert({work_order_id:Number(order.id),version:Number(order.version||1),action:'status_changed',details:JSON.stringify({old_status:order.status,new_status:status}),user_id:req.user.id});if(hist.error)throw hist.error;}
    res.json(data);
  }catch(e){handleDbError(res,e)}
});
app.get('/api/work-orders/:id/history', auth, requireDb, async (req,res)=>{
  try{
    const id=Number(req.params.id);const order=await one('work_orders',id);if(!order)return res.status(404).json({error:'أمر التشغيل غير موجود'});
    const [history,users]=await Promise.all([rows('work_order_history',{work_order_id:id}),getRows('users')]);const userById=new Map(users.map(x=>[Number(x.id),x]));
    res.json(history.map(x=>({...x,employee:userById.get(Number(x.user_id))?.full_name||userById.get(Number(x.user_id))?.username||'النظام'})).sort((a,b)=>String(b.created_at||'').localeCompare(String(a.created_at||''))));
  }catch(e){handleDbError(res,e)}
});
app.post('/api/contractor-payouts', auth, requireDb, async (req,res)=>{
  try{
    const contractorId=Number(req.body?.contractor_id),bookingId=Number(req.body?.booking_id)||null,amount=Number(req.body?.amount);
    if(!Number.isInteger(contractorId)||contractorId<=0)return res.status(400).json({error:'اختر متعهدًا صحيحًا'});if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({error:'مبلغ الصرف غير صحيح'});
    const contractor=await one('contractors',contractorId);if(!contractor)return res.status(404).json({error:'المتعهد غير موجود'});
    const method=String(req.body?.method||'cash'),reference=String(req.body?.reference||''),notes=String(req.body?.notes||''),receipt_no=receiptNo('CP'),entry_no=receiptNo('EX');
    const {data:journal,error:jerr}=await supabase.from('cash_journal').insert({entry_no,entry_type:'expense',category:'مستحقات متعهد',amount,method,description:notes||`صرف مستحقات المتعهد ${contractor.full_name||contractor.name||''}`,booking_id:bookingId,contractor_id:contractorId,created_by:req.user.id,payee:String(contractor.full_name||contractor.name||'')}).select('*').single();if(jerr)throw jerr;
    const {data,error}=await supabase.from('contractor_payouts').insert({receipt_no,contractor_id:contractorId,amount,method,reference,notes,paid_by:req.user.id,journal_id:journal.id,created_at:new Date().toISOString(),booking_id:bookingId}).select('*').single();
    if(error){await supabase.from('cash_journal').delete().eq('id',journal.id);throw error;}
    res.status(201).json({...data,entry_no:journal.entry_no,payee:journal.payee});
  }catch(e){handleDbError(res,e)}
});

// Table CRUD for standard catalog and records. Unknown table names are never queried.
app.get('/api/:resource', auth, requireDb, async (req, res, next) => {
  const table = tableFor(req.params.resource);
  if (!table) return next();
  try {
    let rows = await getRows(table);
    if (req.query.active === 'true') rows = rows.filter(r => r.active === true || r.active === 1);
    if (req.params.resource === 'notifications') rows = rows.map(r => ({ ...r, title: r.action || 'عملية بالنظام', details: r.details || r.description || '', employee: r.username || 'النظام', created_at: r.created_at || new Date().toISOString() }));
    if (table === 'users') rows = rows.map(({password_hash, ...r}) => ({...r, ...publicUser(r)}));
    res.json(rows);
  } catch (error) { handleDbError(res, error); }
});
app.get('/api/:resource/:id', auth, requireDb, async (req, res, next) => {
  const table = tableFor(req.params.resource); if (!table || !/^\d+$/.test(req.params.id)) return next();
  try { const rows = await getRows(table, { id: Number(req.params.id) }); if (!rows.length) return res.status(404).json({ error: 'السجل غير موجود' }); if(table==='users'){const {password_hash,...safe}=rows[0]; return res.json({...safe,...publicUser(safe)});} res.json(rows[0]); }
  catch (error) { handleDbError(res, error); }
});
app.post('/api/:resource', auth, requireDb, async (req, res, next) => {
  const table = tableFor(req.params.resource); if (!table) return next();
  if (table === 'users' && req.user.role !== 'admin') return res.status(403).json({ error: 'إدارة المستخدمين للمدير فقط' });
  try {
    const body = { ...(req.body || {}) };
    delete body.id;
    if (table === 'users') {
      if (!body.password || String(body.password).length < 10) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 10 أحرف على الأقل' });
      body.password_hash = await bcrypt.hash(String(body.password), 12); delete body.password;
      body.permissions = JSON.stringify(parsePermissions(body.permissions)); body.active = body.active === false ? false : true;
    }
    const { data, error } = await supabase.from(table).insert(body).select('*').single();
    if (error) throw error;
    if(table==='users'){const {password_hash,...safe}=data; return res.status(201).json({...safe,...publicUser(safe)});}
    res.status(201).json(data);
  } catch (error) { handleDbError(res, error); }
});
app.put('/api/:resource/:id', auth, requireDb, async (req, res, next) => {
  const table = tableFor(req.params.resource); if (!table || !/^\d+$/.test(req.params.id)) return next();
  if (table === 'users' && req.user.role !== 'admin' && Number(req.params.id) !== Number(req.user.id)) return res.status(403).json({ error: 'غير مصرح بتعديل هذا المستخدم' });
  try {
    const body = { ...(req.body || {}) }; delete body.id; delete body.password_hash;
    if (table === 'users') {
      if (body.password) { if (String(body.password).length < 10) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 10 أحرف على الأقل' }); body.password_hash = await bcrypt.hash(String(body.password), 12); }
      delete body.password; if (body.permissions !== undefined) body.permissions = JSON.stringify(parsePermissions(body.permissions));
    }
    const { data, error } = await supabase.from(table).update(body).eq('id', Number(req.params.id)).select('*').maybeSingle();
    if (error) throw error; if (!data) return res.status(404).json({ error: 'السجل غير موجود' }); if(table==='users'){const {password_hash,...safe}=data; return res.json({...safe,...publicUser(safe)});} res.json(data);
  } catch (error) { handleDbError(res, error); }
});
app.delete('/api/:resource/:id', auth, requireDb, async (req, res, next) => {
  const table = tableFor(req.params.resource); if (!table || !/^\d+$/.test(req.params.id)) return next();
  if (table === 'users' && req.user.role !== 'admin') return res.status(403).json({ error: 'إدارة المستخدمين للمدير فقط' });
  try { const { error } = await supabase.from(table).delete().eq('id', Number(req.params.id)); if (error) throw error; res.json({ ok: true }); }
  catch (error) { handleDbError(res, error); }
});

// Never silently claim unsupported APIs succeeded: return a clear diagnostic instead of fake [] results.
app.all('/api/*', auth, (req, res) => res.status(501).json({ error: `المسار ${req.method} ${req.path} لم يتم تنفيذه بعد في نسخة Supabase؛ لم يتم تغيير البيانات.` }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
const port = Number(process.env.PORT || 3000);
app.listen(port, '0.0.0.0', () => console.log(`Nasim server listening on ${port}; Supabase configured: ${dbReady()}`));
