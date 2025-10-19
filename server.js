// server.js — sesión única con reemplazo y claim atómico
// Listo para Railway: /health, /salud, login e inicio
// Lluvia YTD robusta (WU), convierte imperial->mm si es necesario

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

/* ====== CORS ====== */
const ALLOWED = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(s => s.trim().replace(/\/+$/, ''))
  .filter(Boolean);

const corsMiddleware = cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (ALLOWED.length === 0) return cb(null, true);
    const ok = ALLOWED.includes(origin.replace(/\/+$/, ''));
    cb(ok ? null : new Error('Not allowed by CORS'), ok);
  },
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  optionsSuccessStatus: 204
});
app.use(corsMiddleware);
app.options('*', corsMiddleware);
app.use((req,res,next)=>{ res.header('Vary','Origin'); next(); });

/* ====== Carpetas ====== */
const DB_DIR = path.join(__dirname, 'db');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const PUBLIC_DIR = path.join(__dirname, 'public');
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });

/* ====== Sesiones ====== */
const store = new SQLiteStore({ db: 'sessions.sqlite', dir: DB_DIR });
app.use(session({
  store,
  secret: process.env.SESSION_SECRET || 'cambia-esta-clave',
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

/* ====== Body y estáticos ====== */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

/* ====== DB usuarios ====== */
const db = new Database(path.join(DB_DIR, 'usuarios.db'));
db.pragma('journal_mode = wal');
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    session_id TEXT
  )
`).run();

if (process.env.SEED_ADMIN === '1') {
  db.prepare("INSERT OR IGNORE INTO users (username, password, session_id) VALUES ('admin','1234',NULL)").run();
}

/* ====== Healthcheck ====== */
app.get('/health', (req, res) => res.status(200).send('OK'));
app.get('/salud',  (req, res) => res.status(200).send('OK'));

/* ====== Raíz ====== */
app.get('/', (req, res) => {
  const loginFile = path.join(PUBLIC_DIR, 'login.html');
  if (fs.existsSync(loginFile)) return res.sendFile(loginFile);
  res.redirect('/login.html');
});

/* ====== Auth helpers ====== */
function autenticar(username, password) {
  const row = db.prepare('SELECT username,password,session_id FROM users WHERE username = ?').get(username);
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
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(user.username);
    }

    await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
    const claim = db.prepare('UPDATE users SET session_id = ? WHERE username = ? AND session_id IS NULL')
                    .run(req.sessionID, user.username);
    if (claim.changes === 0) return res.redirect('/login.html?error=sesion_activa');

    req.session.usuario = user.username;
    return res.redirect('/inicio');
  } catch (e) {
    console.error(e);
    res.redirect('/login.html?error=interno');
  }
});

async function requiereSesionUnica(req, res, next) {
  try {
    if (!req.session?.usuario) return res.redirect('/login.html');
    const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(req.session.usuario);
    if (!row) return res.redirect('/login.html');

    if (!row.session_id) {
      req.session.destroy(()=> res.redirect('/login.html?error=sesion_invalida'));
      return;
    }
    if (row.session_id !== req.sessionID) {
      req.session.destroy(()=> res.redirect('/login.html?error=conectado_en_otra_maquina'));
      return;
    }
    const sess = await storeGet(row.session_id);
    if (!sess) {
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(req.session.usuario);
      req.session.destroy(()=> res.redirect('/login.html?error=sesion_expirada'));
      return;
    }
    next();
  } catch(e) {
    console.error(e);
    res.redirect('/login.html?error=interno');
  }
}

/* ====== Rutas protegidas ====== */
app.get('/inicio', requiereSesionUnica, (req, res) => {
  const f = path.join(PUBLIC_DIR, 'inicio.html');
  if (fs.existsSync(f)) return res.sendFile(f);
  res.type('html').send('<h1>Inicio</h1>');
});

app.get('/api/datos', requiereSesionUnica, (req, res) => {
  res.json({ ok: true, usuario: req.session.usuario, sid: req.sessionID });
});

/* ====== Historial URL ====== */
const HISTORIAL_FALLBACK = 'https://prueba2-production-50d4.up.railway.app/';
app.get('/historial-url', (req, res) => {
  res.json({ url: process.env.HISTORIAL_URL || HISTORIAL_FALLBACK });
});

app.get('/historial', requiereSesionUnica, (req, res) => {
  const url = process.env.HISTORIAL_URL || HISTORIAL_FALLBACK;
  try {
    const u = new URL(url);
    if (!/^https?:$/.test(u.protocol)) throw new Error('Bad protocol');
    return res.redirect(u.toString());
  } catch {
    return res.status(500).send('Configuración de HISTORIAL_URL inválida');
  }
});

/* ====== Logout ====== */
app.post('/logout', (req, res) => {
  const usuario = req.session?.usuario;
  const sid = req.sessionID;
  req.session.destroy(async () => {
    if (usuario) {
      const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(usuario);
      if (row?.session_id === sid) {
        db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(usuario);
      }
    }
    res.redirect('/login.html?msg=logout');
  });
});

/* ====== LLUVIA YTD (WU) ====== */
app.get('/api/lluvia/total/year', requiereSesionUnica, async (req, res) => {
  try {
    const apiKey = process.env.WU_API_KEY;
    const stationId = process.env.WU_STATION_ID;
    if (!apiKey || !stationId) {
      return res.status(400).json({ error: 'config_missing', detalle: 'Define WU_API_KEY y WU_STATION_ID en el .env' });
    }

    const ahora = new Date();
    const year = ahora.getFullYear();
    const pad = n => String(n).padStart(2, '0');
    const startDate = `${year}0101`;
    const endDate   = `${year}${pad(ahora.getMonth()+1)}${pad(ahora.getDate())}`;

    const url = `https://api.weather.com/v2/pws/history/daily` +
      `?stationId=${encodeURIComponent(stationId)}` +
      `&format=json&units=m` +
      `&startDate=${startDate}&endDate=${endDate}` +
      `&numericPrecision=decimal` +
      `&apiKey=${encodeURIComponent(apiKey)}`;

    const r = await fetch(url, {
      headers: {
        'User-Agent': process.env.USER_AGENT || 'Mozilla/5.0',
        'Accept': 'application/json,text/plain,*/*',
        'Accept-Language': 'es-ES,es;q=0.9'
      }
    });

    const ct = (r.headers.get('content-type') || '').toLowerCase();
    const bodyText = await r.text();

    if (!r.ok || !ct.includes('application/json')) {
      console.error('[WU] status=', r.status, 'ct=', ct, 'body=', bodyText.slice(0,300));
      return res.status(502).json({
        error: 'upstream_error',
        detalle: `WU ${r.status} - CT=${ct}`,
        muestra: bodyText.slice(0,300)
      });
    }

    let data;
    try { data = JSON.parse(bodyText); }
    catch(e) { return res.status(502).json({ error: 'json_parse_error', detalle: String(e) }); }

    const arr = Array.isArray(data?.observations) ? data.observations : [];
    if (arr.length === 0) {
      return res.json({
        total_mm: 0,
        year,
        desde: `${year}-01-01`,
        hasta: `${year}-${pad(ahora.getMonth()+1)}-${pad(ahora.getDate())}`,
        dias_contados: 0,
        origen: 'WU history/daily',
        aviso: 'observations vacío (rango/estación sin datos o permisos)'
      });
    }

    const toNum = v => (v === 'T' ? 0 : (Number.isFinite(Number(v)) ? Number(v) : null));
    const inchesToMm = inch => inch * 25.4;

    const dayMm = d => {
      let v = toNum(d?.metric?.precipTotal);
      if (v != null) return v;
      v = toNum(d?.imperial?.precipTotal);
      if (v != null) return inchesToMm(v);
      v = toNum(d?.precipTotal);
      if (v != null) return v;
      v = toNum(d?.metric?.precip);
      if (v != null) return v;
      v = toNum(d?.precip);
      if (v != null) return v;
      v = toNum(d?.imperial?.precip);
      if (v != null) return inchesToMm(v);
      return 0;
    };

    const porDia = arr.map(d => ({
      fecha: d?.obsTimeLocal || d?.obsTimeUtc || d?.day || null,
      mm: dayMm(d),
      m_total: d?.metric?.precipTotal ?? null,
      i_total: d?.imperial?.precipTotal ?? null
    }));

    const totalYear = porDia.reduce((acc, x) => acc + (Number.isFinite(x.mm) ? x.mm : 0), 0);

    if (req.query.debug === '1') {
      return res.json({
        total_mm: Number(totalYear.toFixed(2)),
        year,
        desde: `${year}-01-01`,
        hasta: `${year}-${pad(ahora.getMonth()+1)}-${pad(ahora.getDate())}`,
        dias_contados: porDia.length,
        origen: 'WU history/daily',
        muestra: porDia.slice(-10)
      });
    }

    res.json({
      total_mm: Number(totalYear.toFixed(2)),
      year,
      desde: `${year}-01-01`,
      hasta: `${year}-${pad(ahora.getMonth()+1)}-${pad(ahora.getDate())}`,
      dias_contados: porDia.length,
      origen: 'WU history/daily'
    });

  } catch (e) {
    console.error('Error /api/lluvia/total/year:', e);
    res.status(500).json({ error: 'calc_failed', detalle: String(e.message || e) });
  }
});

/* ====== Arranque ====== */
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () =>
  console.log(`🚀 http://0.0.0.0:${PORT} — reemplazo automático de sesión activado`)
);
