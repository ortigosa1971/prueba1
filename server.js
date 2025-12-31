// server.js — sesión única + APIs Weather.com (WU) + lluvia YTD por meses
// Node >=18 (fetch nativo). Listo para Railway.
//Prueba david

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const util = require('util');
const cors = require('cors');

const app = express();
app.set('trust proxy', 1);

/* ============ CORS ============ */
const ALLOWED = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(s => s.trim().replace(/\/+$/, ''))
  .filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (ALLOWED.length === 0) return cb(null, true);
    const ok = ALLOWED.includes(origin.replace(/\/+$/, ''));
    cb(ok ? null : new Error('Not allowed by CORS'), ok);
  },
  credentials: true
}));
app.options('*', cors());
app.use((req,res,next)=>{ res.header('Vary','Origin'); next(); });

/* ============ Carpetas ============ */
const DB_DIR = path.join(__dirname, 'db');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const PUBLIC_DIR = path.join(__dirname, 'public');
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });

/* ============ Sesión (SQLite) ============ */
const store = new SQLiteStore({ db: 'sessions.sqlite', dir: DB_DIR });
app.use(session({
  store,
  secret: process.env.SESSION_SECRET || 'change_this_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: process.env.SAMESITE || 'none',
    secure: process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8
  }
}));
const storeGet = util.promisify(store.get).bind(store);
const storeDestroy = util.promisify(store.destroy).bind(store);

/* ============ Body + estáticos ============ */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

/* ============ DB usuarios ============ */
const db = new Database(path.join(DB_DIR, 'usuarios.db'));
db.pragma('journal_mode = wal');
db.prepare(`
  CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY,
    password TEXT,
    session_id TEXT
  )
`).run();
if (process.env.SEED_ADMIN === '1') {
  db.prepare("INSERT OR IGNORE INTO users (username,password,session_id) VALUES ('admin','1234',NULL)").run();
}

/* ============ Healthcheck ============ */
app.get('/health', (_,res)=>res.status(200).send('OK'));
app.get('/salud',  (_,res)=>res.status(200).send('OK'));

/* ============ Raíz / Login ============ */
app.get('/', (req, res) => {
  const f = path.join(PUBLIC_DIR, 'login.html');
  if (fs.existsSync(f)) return res.sendFile(f);
  res.type('html').send('<h1>Login</h1>');
});

function autenticar(username, password) {
  const row = db.prepare('SELECT username,password,session_id FROM users WHERE username=?').get(username);
  if (!row) return null;
  if (row.password && password && row.password !== password) return null;
  return row;
}

app.post('/login', async (req, res) => {
  try {
    const { usuario, username, password } = req.body;
    const userField = (usuario || username || '').trim();
    if (!userField) return res.redirect('/login.html?error=credenciales');

    const user = autenticar(userField, password);
    if (!user) return res.redirect('/login.html?error=credenciales');

    if (user.session_id) {
      await storeDestroy(user.session_id).catch(()=>{});
      db.prepare('UPDATE users SET session_id=NULL WHERE username=?').run(user.username);
    }
    await new Promise((resolve,reject)=> req.session.regenerate(err=>err?reject(err):resolve()));
    const claim = db.prepare('UPDATE users SET session_id=? WHERE username=? AND session_id IS NULL')
                    .run(req.sessionID, user.username);
    if (claim.changes === 0) return res.redirect('/login.html?error=sesion_activa');

    req.session.usuario = user.username;
    res.redirect('/inicio');
  } catch (e) {
    console.error(e);
    res.redirect('/login.html?error=interno');
  }
});

/* ============ Middleware sesión única ============ */
async function requiereSesionUnica(req, res, next) {
  try {
    if (!req.session?.usuario) return res.redirect('/login.html');
    const row = db.prepare('SELECT session_id FROM users WHERE username=?').get(req.session.usuario);
    if (!row) return res.redirect('/login.html');
    if (!row.session_id) { req.session.destroy(()=>res.redirect('/login.html?error=sesion_invalida')); return; }
    if (row.session_id !== req.sessionID) { req.session.destroy(()=>res.redirect('/login.html?error=conectado_en_otra_maquina')); return; }
    const sess = await storeGet(row.session_id);
    if (!sess) {
      db.prepare('UPDATE users SET session_id=NULL WHERE username=?').run(req.session.usuario);
      req.session.destroy(()=>res.redirect('/login.html?error=sesion_expirada'));
      return;
    }
    next();
  } catch (e) { console.error(e); res.redirect('/login.html?error=interno'); }
}

/* ============ Rutas protegidas básicas ============ */
app.get('/inicio', requiereSesionUnica, (req, res) => {
  const f = path.join(PUBLIC_DIR, 'inicio.html');
  if (fs.existsSync(f)) return res.sendFile(f);
  res.type('html').send(`<h1>Inicio</h1><p>Usuario: ${req.session.usuario}</p>`);
});

app.post('/logout', (req, res) => {
  const usuario = req.session?.usuario;
  const sid = req.sessionID;
  req.session.destroy(async () => {
    if (usuario) {
      const row = db.prepare('SELECT session_id FROM users WHERE username=?').get(usuario);
      if (row?.session_id === sid) db.prepare('UPDATE users SET session_id=NULL WHERE username=?').run(usuario);
    }
    res.redirect('/login.html?msg=logout');
  });
});

/* ============ Verificar sesión (front lo usa) ============ */
app.get('/verificar-sesion', (req, res) => {
  res.json({ activo: !!req.session?.usuario });
});

/* ============ Historial URL (front lo usa) ============ */
const HISTORIAL_FALLBACK = 'https://prueba2-production-50d4.up.railway.app/';
app.get('/historial-url', (req, res) => {
  res.json({ url: process.env.HISTORIAL_URL || HISTORIAL_FALLBACK });
});

/* ============ Proxies Weather.com PWS ============ */
const UA = process.env.USER_AGENT ||
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome Safari';

app.get('/api/weather/current', requiereSesionUnica, async (req, res) => {
  try {
    const apiKey = process.env.WEATHER_API_KEY || process.env.WU_API_KEY;
    const stationId = req.query.stationId || process.env.WU_STATION_ID;
    const units = req.query.units || 'm';
    if (!apiKey || !stationId) return res.status(400).json({ error:'config_missing', detalle:'Faltan WEATHER_API_KEY/WU_API_KEY o WU_STATION_ID' });

    const url = new URL('https://api.weather.com/v2/pws/observations/current');
    url.searchParams.set('stationId', stationId);
    url.searchParams.set('format', 'json');
    url.searchParams.set('units', units);
    url.searchParams.set('apiKey', apiKey);
    url.searchParams.set('numericPrecision', 'decimal');

    const r = await fetch(url, { headers: { 'User-Agent': UA, 'Accept':'application/json,text/plain,*/*', 'Accept-Language':'es-ES,es;q=0.9' }});
    const ct = (r.headers.get('content-type') || '').toLowerCase();
    const body = await r.text();
    if (!r.ok) { console.error('Upstream /current', r.status, ct, body.slice(0,300)); return res.status(r.status).json({ error:'weather.com denied', status:r.status }); }
    if (!ct.includes('application/json')) return res.status(502).json({ error:'Invalid response from weather.com' });
    res.set('Cache-Control','public, max-age=60').type('application/json').send(body);
  } catch (e) { console.error(e); res.status(500).json({ error:'Weather proxy failed' }); }
});

app.get('/api/weather/history', requiereSesionUnica, async (req, res) => {
  try {
    const apiKey = process.env.WEATHER_API_KEY || process.env.WU_API_KEY;
    const stationId = req.query.stationId || process.env.WU_STATION_ID;
    const { startDate, endDate } = req.query;
    const units = req.query.units || 'm';
    if (!apiKey || !stationId) return res.status(400).json({ error:'config_missing', detalle:'Faltan WEATHER_API_KEY/WU_API_KEY o WU_STATION_ID' });
    if (!startDate || !endDate) return res.status(400).json({ error:'params_missing', detalle:'startDate y endDate son obligatorios (YYYYMMDD)' });

    const url = new URL('https://api.weather.com/v2/pws/history/daily');
    url.searchParams.set('stationId', stationId);
    url.searchParams.set('format', 'json');
    url.searchParams.set('units', units);
    url.searchParams.set('startDate', startDate);
    url.searchParams.set('endDate', endDate);
    url.searchParams.set('apiKey', apiKey);
    url.searchParams.set('numericPrecision', 'decimal');

    const r = await fetch(url, { headers: { 'User-Agent': UA, 'Accept':'application/json,text/plain,*/*', 'Accept-Language':'es-ES,es;q=0.9' }});
    const ct = (r.headers.get('content-type') || '').toLowerCase();
    const body = await r.text();
    if (!r.ok) { console.error('Upstream /history', r.status, ct, body.slice(0,300)); return res.status(r.status).json({ error:'weather.com denied', status:r.status }); }
    if (!ct.includes('application/json')) return res.status(502).json({ error:'Invalid response from weather.com' });
    res.set('Cache-Control','public, max-age=300').type('application/json').send(body);
  } catch (e) { console.error(e); res.status(500).json({ error:'Weather history proxy failed' }); }
});

/* ============ Lluvia acumulada (YTD) por meses (evita 502) ============ */
app.get('/api/lluvia/total/year', requiereSesionUnica, async (req, res) => {
  try {
    const apiKey    = process.env.WU_API_KEY;
    const stationId = process.env.WU_STATION_ID;
    if (!apiKey || !stationId) {
      return res.status(400).json({ error:'config_missing', detalle:'Define WU_API_KEY y WU_STATION_ID' });
    }

    const now  = new Date();
    const YEAR = now.getFullYear();
    const pad  = (n) => String(n).padStart(2,'0');

    const toNum = (v) => (v === 'T' ? 0 : (Number.isFinite(Number(v)) ? Number(v) : null));
    const in2mm = (inch) => inch * 25.4;

    const dayMm = (d) => {
      let v = toNum(d?.metric?.precipTotal); if (v != null) return v;
      v = toNum(d?.imperial?.precipTotal);   if (v != null) return in2mm(v);
      v = toNum(d?.precipTotal);             if (v != null) return v;
      v = toNum(d?.metric?.precip);          if (v != null) return v;
      v = toNum(d?.precip);                  if (v != null) return v;
      v = toNum(d?.imperial?.precip);        if (v != null) return in2mm(v);
      return 0;
    };

    async function fetchRange(startDate, endDate) {
      const u =
        `https://api.weather.com/v2/pws/history/daily?stationId=${encodeURIComponent(stationId)}` +
        `&format=json&units=m&startDate=${startDate}&endDate=${endDate}` +
        `&numericPrecision=decimal&apiKey=${encodeURIComponent(apiKey)}`;

      const r = await fetch(u, {
        headers: {
          'User-Agent': process.env.USER_AGENT || 'Mozilla/5.0',
          'Accept': 'application/json,text/plain,*/*',
          'Accept-Language': 'es-ES,es;q=0.9'
        }
      });

      const ct = (r.headers.get('content-type') || '').toLowerCase();
      const text = await r.text();

      if (!r.ok || !ct.includes('application/json')) {
        console.warn('[WU chunk] status=', r.status, 'ct=', ct, 'range=', startDate, endDate, 'body=', text.slice(0,200));
        return { observations: [] };
      }
      try { return JSON.parse(text); } catch { return { observations: [] }; }
    }

    // Recorremos enero → hoy, mes a mes, acumulando por día (evitar duplicados)
    const perDay = new Map(); // YYYY-MM-DD -> mm
    for (let m = 0; m < 12; m++) {
      const monthStart = new Date(YEAR, m, 1);
      if (monthStart > now) break;

      const monthEnd = new Date(YEAR, m + 1, 0);
      const end = monthEnd > now ? now : monthEnd;

      const startDate = `${YEAR}${pad(m + 1)}01`;
      const endDate   = `${YEAR}${pad(end.getMonth() + 1)}${pad(end.getDate())}`;

      const data = await fetchRange(startDate, endDate);
      const obs = Array.isArray(data?.observations) ? data.observations : [];

      for (const d of obs) {
        const iso = (d?.obsTimeLocal || d?.obsTimeUtc || '').slice(0, 10); // YYYY-MM-DD
        if (!iso) continue;
        const mm = dayMm(d);
        perDay.set(iso, Math.max(perDay.get(iso) || 0, mm));
      }
    }

    const lista = Array.from(perDay.entries()).sort((a, b) => a[0].localeCompare(b[0]));
    const total = lista.reduce((acc, [, mm]) => acc + (Number.isFinite(mm) ? mm : 0), 0);

    if (req.query.debug === '1') {
      return res.json({
        year: YEAR,
        desde: `${YEAR}-09-01`,
        hasta: `${YEAR}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`,
        dias_contados: lista.length,
        total_mm: Number(total.toFixed(2)) + 200,
        muestra: lista.slice(-10).map(([fecha, mm]) => ({ fecha, mm })),
      });
    }

    return res.json({
      year: YEAR,
      desde: `${YEAR}-09-01`,
      hasta: `${YEAR}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`,
      dias_contados: lista.length,
      total_mm: Number(total.toFixed(2)) + 200,
      origen: 'WU history/daily (mensual)'
    });

  } catch (e) {
    console.error('Error /api/lluvia/total/year:', e);
    return res.status(500).json({ error:'calc_failed', detalle:String(e.message || e) });
  }
});


/* ============ Arranque ============ */
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () =>
  console.log(`🚀 http://0.0.0.0:${PORT} — listo (rutas: /verificar-sesion, /api/weather/*, /api/lluvia/total/year)`)
);
