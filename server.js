// server.js — sesión única con reemplazo y claim atómico
// Incluye rutas de lluvia corregidas (WU: imperial -> mm)

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");
const util = require("util");
const cors = require("cors");
const fetch = require("node-fetch");

const app = express();
app.set("trust proxy", 1);

// ====== CORS ======
const ALLOWED = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim().replace(/\/+$/, ""))
  .filter(Boolean);

const corsMiddleware = cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (ALLOWED.length === 0) return cb(null, true);
    const clean = origin.replace(/\/+$/, "");
    const ok = ALLOWED.includes(clean);
    cb(ok ? null : new Error("Not allowed by CORS"), ok);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  preflightContinue: false,
  optionsSuccessStatus: 204,
});

app.use(corsMiddleware);
app.options("*", corsMiddleware);
app.use((req, res, next) => {
  res.header("Vary", "Origin");
  next();
});

// ====== Carpetas ======
const DB_DIR = path.join(__dirname, "db");
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const PUBLIC_DIR = path.join(__dirname, "public");
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });

// ====== Sesiones (SQLite) ======
const store = new SQLiteStore({ db: "sessions.sqlite", dir: DB_DIR });
app.use(
  session({
    store,
    secret: process.env.SESSION_SECRET || "cambia-esta-clave",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: process.env.SAMESITE || "none",
      secure:
        process.env.COOKIE_SECURE === "true" ||
        process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 8,
    },
  })
);

const storeGet = util.promisify(store.get).bind(store);
const storeDestroy = util.promisify(store.destroy).bind(store);

// ====== Body y estáticos ======
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// ====== DB usuarios ======
const db = new Database(path.join(DB_DIR, "usuarios.db"));
db.pragma("journal_mode = wal");
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    session_id TEXT
  )
`).run();

if (process.env.SEED_ADMIN === "1") {
  db.prepare(
    "INSERT OR IGNORE INTO users (username, password, session_id) VALUES ('admin','1234',NULL)"
  ).run();
}

const DEBUG = process.env.DEBUG_SINGLE_SESSION === "1";
const log = (...a) => DEBUG && console.log("[single-session]", ...a);

// ====== Healthcheck ======
app.get("/health", (req, res) => res.status(200).send("OK"));
app.get("/salud", (req, res) => res.status(200).send("OK"));

// ====== Raíz ======
app.get("/", (req, res) => {
  const loginFile = path.join(PUBLIC_DIR, "login.html");
  if (fs.existsSync(loginFile)) return res.sendFile(loginFile);
  res.type("html").send(`<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head>
  <body>
    <h1>Login</h1>
    <form method="POST" action="/login">
      <input name="usuario" placeholder="usuario" required>
      <input type="password" name="password" placeholder="password" required>
      <button>Entrar</button>
    </form>
  </body></html>`);
});

// ====== Helper: autenticar ======
function autenticar(username, password) {
  const row = db
    .prepare("SELECT username, password, session_id FROM users WHERE username = ?")
    .get(username);
  if (!row) return null;
  if (row.password && password && row.password !== password) return null;
  return row;
}

// ====== LOGIN ======
app.post("/login", async (req, res) => {
  try {
    const { usuario, username, password } = req.body;
    const userField = usuario || username;
    if (!userField) return res.redirect("/login.html?error=credenciales");

    const user = autenticar(userField, password);
    if (!user) return res.redirect("/login.html?error=credenciales");

    if (user.session_id) {
      await storeDestroy(user.session_id).catch(() => {});
      db.prepare("UPDATE users SET session_id = NULL WHERE username = ?").run(
        user.username
      );
    }

    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => (err ? reject(err) : resolve()));
    });

    const claim = db
      .prepare(
        "UPDATE users SET session_id = ? WHERE username = ? AND session_id IS NULL"
      )
      .run(req.sessionID, user.username);

    if (claim.changes === 0) {
      return res.redirect("/login.html?error=sesion_activa");
    }

    req.session.usuario = user.username;
    log("login OK (reemplazo + claim) para", user.username, "sid:", req.sessionID);
    return res.redirect("/inicio");
  } catch (e) {
    console.error(e);
    return res.redirect("/login.html?error=interno");
  }
});

// ====== Middleware: sesión única ======
async function requiereSesionUnica(req, res, next) {
  try {
    if (!req.session?.usuario) return res.redirect("/login.html");

    const row = db
      .prepare("SELECT session_id FROM users WHERE username = ?")
      .get(req.session.usuario);
    if (!row) return res.redirect("/login.html");

    if (!row.session_id) {
      req.session.destroy(() =>
        res.redirect("/login.html?error=sesion_invalida")
      );
      return;
    }

    if (row.session_id !== req.sessionID) {
      req.session.destroy(() =>
        res.redirect("/login.html?error=conectado_en_otra_maquina")
      );
      return;
    }

    const sess = await storeGet(row.session_id);
    if (!sess) {
      db.prepare("UPDATE users SET session_id = NULL WHERE username = ?").run(
        req.session.usuario
      );
      req.session.destroy(() =>
        res.redirect("/login.html?error=sesion_expirada")
      );
      return;
    }

    next();
  } catch (e) {
    console.error(e);
    res.redirect("/login.html?error=interno");
  }
}

// ====== Rutas protegidas ======
app.get("/inicio", requiereSesionUnica, (req, res) => {
  const inicioFile = path.join(PUBLIC_DIR, "inicio.html");
  if (fs.existsSync(inicioFile)) return res.sendFile(inicioFile);
  res.type("html").send(`<!doctype html><html><head><meta charset="utf-8"><title>Inicio</title></head>
  <body><h1>Inicio</h1><p>Usuario: ${req.session.usuario}</p>
  <form method="POST" action="/logout"><button>Salir</button></form>
  </body></html>`);
});

// ====== Logout ======
app.post("/logout", (req, res) => {
  const usuario = req.session?.usuario;
  const sid = req.sessionID;
  req.session.destroy(async () => {
    if (usuario) {
      const row = db
        .prepare("SELECT session_id FROM users WHERE username = ?")
        .get(usuario);
      if (row?.session_id === sid) {
        db.prepare("UPDATE users SET session_id = NULL WHERE username = ?").run(
          usuario
        );
      }
    }
    res.redirect("/login.html?msg=logout");
  });
});

// ====== RUTA NUEVA: lluvia acumulada del AÑO ACTUAL (WU) ======
app.get("/api/lluvia/total/year", requiereSesionUnica, async (req, res) => {
  try {
    const apiKey = process.env.WU_API_KEY;
    const stationId = process.env.WU_STATION_ID;
    if (!apiKey || !stationId) {
      return res.status(400).json({
        error: "config_missing",
        detalle: "Define WU_API_KEY y WU_STATION_ID en el .env",
      });
    }

    const ahora = new Date();
    const year = ahora.getFullYear();
    const pad = (n) => String(n).padStart(2, "0");
    const startDate = `${year}0101`;
    const endDate = `${year}${pad(ahora.getMonth() + 1)}${pad(
      ahora.getDate()
    )}`;

    const url = `https://api.weather.com/v2/pws/history/daily?stationId=${stationId}&format=json&units=m&startDate=${startDate}&endDate=${endDate}&numericPrecision=decimal&apiKey=${apiKey}`;

    const r = await fetch(url);
    if (!r.ok) throw new Error(`WU HTTP ${r.status}`);
    const data = await r.json();
    const arr = Array.isArray(data?.observations) ? data.observations : [];

    const toNum = (v) => {
      if (v === "T") return 0;
      const n = Number(v);
      return Number.isFinite(n) ? n : null;
    };
    const inchesToMm = (inch) => inch * 25.4;

    const dayMm = (d) => {
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

    const porDia = arr.map((d) => ({
      fecha: d?.obsTimeLocal || d?.obsTimeUtc || null,
      mm: dayMm(d),
      src: {
        m_total: d?.metric?.precipTotal ?? null,
        i_total: d?.imperial?.precipTotal ?? null,
        plain_total: d?.precipTotal ?? null,
      },
    }));

    const totalYear = porDia.reduce(
      (acc, x) => acc + (Number.isFinite(x.mm) ? x.mm : 0),
      0
    );

    if (req.query.debug === "1") {
      return res.json({
        total_mm: Number(totalYear.toFixed(2)),
        year,
        desde: `${year}-01-01`,
        hasta: `${year}-${pad(ahora.getMonth() + 1)}-${pad(ahora.getDate())}`,
        dias_contados: porDia.length,
        muestra: porDia.slice(-10),
      });
    }

    res.json({
      total_mm: Number(totalYear.toFixed(2)),
      year,
      desde: `${year}-01-01`,
      hasta: `${year}-${pad(ahora.getMonth() + 1)}-${pad(ahora.getDate())}`,
      dias_contados: porDia.length,
      origen: "WU history/daily",
    });
  } catch (e) {
    console.error("Error /api/lluvia/total/year:", e);
    res
      .status(500)
      .json({ error: "calc_failed", detalle: String(e.message || e) });
  }
});

// ====== Arranque ======
const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () =>
  console.log(
    `🚀 Servidor iniciado en http://0.0.0.0:${PORT} — Sesión única + lluvia anual activa`
  )
);
