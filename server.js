
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "events.json");
const SEED_FILE = path.join(__dirname, "events.seed.json");
const SESSION_SECRET = process.env.SESSION_SECRET;

let users = [];

try {
  users = JSON.parse(process.env.USERS_JSON || "[]");
} catch {
  console.error("USERS_JSON no contiene JSON válido");
}

if (
  process.env.NODE_ENV === "production" &&
  (
    !SESSION_SECRET ||
    SESSION_SECRET.length < 32 ||
    users.filter(u => u.role === "admin").length < 2
  )
) {
  console.error(
    "Configura SESSION_SECRET (32+ caracteres) y USERS_JSON con las cuentas de los dos administradores."
  );
  process.exit(1);
}

// Preparar el archivo de eventos.
// Si no existe, copiar los 12 eventos iniciales.
// Si ya existe, no sobrescribirlo.
fs.mkdirSync(DATA_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
  if (fs.existsSync(SEED_FILE)) {
    fs.copyFileSync(SEED_FILE, DB_FILE);
    console.log("Agenda inicial copiada al almacenamiento persistente.");
  } else {
    fs.writeFileSync(DB_FILE, "[]", "utf8");
  }
}

app.use(express.json({ limit: "100kb" }));
app.set("trust proxy", 1);

function sign(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return data + "." + crypto
    .createHmac("sha256", SESSION_SECRET || "local-development-secret")
    .update(data)
    .digest("base64url");
}

function verify(token) {
  try {
    const [data, sig] = String(token || "").split(".");
    if (!data || !sig) return null;

    const expected = crypto
      .createHmac("sha256", SESSION_SECRET || "local-development-secret")
      .update(data)
      .digest();

    const got = Buffer.from(sig, "base64url");

    if (
      got.length !== expected.length ||
      !crypto.timingSafeEqual(got, expected)
    ) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString()
    );

    return payload.exp > Date.now() ? payload : null;
  } catch {
    return null;
  }
}

function currentUser(req) {
  const token = (req.headers.cookie || "")
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith("agenda_session="))
    ?.slice("agenda_session=".length);

  const session = verify(token);
  if (!session) return null;

  const user = users.find(u => u.username === session.username);

  return user
    ? {
        username: user.username,
        role: user.role,
        name: user.name || user.username
      }
    : null;
}

function auth(req, res, next) {
  const user = currentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Inicia sesión para continuar."
    });
  }

  req.user = user;
  next();
}

function admin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      error: "Tu cuenta solo tiene permiso de consulta."
    });
  }

  next();
}

// Inicio de sesión
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};

  const user = users.find(u =>
    u.username === username &&
    typeof u.password === "string" &&
    typeof password === "string" &&
    Buffer.byteLength(u.password) === Buffer.byteLength(password) &&
    crypto.timingSafeEqual(Buffer.from(u.password), Buffer.from(password))
  );

  if (!user) {
    return res.status(401).json({
      error: "Usuario o contraseña incorrectos."
    });
  }

  const token = sign({
    username: user.username,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  });

  res.setHeader(
    "Set-Cookie",
    `agenda_session=${token}; HttpOnly; ${
      process.env.NODE_ENV === "production" ? "Secure; " : ""
    }SameSite=Lax; Path=/; Max-Age=604800`
  );

  res.json({
    user: {
      username: user.username,
      name: user.name || user.username,
      role: user.role
    }
  });
});

// Cerrar sesión
app.post("/api/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    `agenda_session=; HttpOnly; ${
      process.env.NODE_ENV === "production" ? "Secure; " : ""
    }SameSite=Lax; Path=/; Max-Age=0`
  );

  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  res.json({ user: req.user });
});

app.use(express.static(path.join(__dirname, "public")));

function readEvents() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch {
    return [];
  }
}

function writeEvents(events) {
  fs.writeFileSync(DB_FILE, JSON.stringify(events, null, 2), "utf8");
}

function validDate(s) {
  return /^\d{4}-\d{2}-\d{2}$/.test(s) &&
    !Number.isNaN(Date.parse(s + "T12:00:00"));
}

function conflict(candidate, events, ignoreId = null) {
  if (candidate.status !== "confirmed") return null;

  return events.find(e =>
    e.id !== ignoreId &&
    e.status === "confirmed" &&
    e.date === candidate.date &&
    e.startTime === candidate.startTime
  );
}

function publicEvent(e) {
  return {
    id: e.id,
    title: e.title,
    date: e.date,
    startTime: e.startTime,
    venue: e.venue,
    city: e.city,
    status: e.status
  };
}

// Consultar eventos
app.get("/api/events", (req, res) => {
  const events = readEvents().sort((a, b) =>
    (a.date + a.startTime).localeCompare(b.date + b.startTime)
  );

  res.json(
    currentUser(req)?.role === "admin"
      ? events
      : events.map(publicEvent)
  );
});

// Crear evento
app.post("/api/events", auth, admin, (req, res) => {
  const b = req.body || {};

  if (!b.title || !validDate(b.date)) {
    return res.status(400).json({
      error: "Ingresa el nombre del evento y una fecha válida."
    });
  }

  if (!["confirmed", "pending", "cancelled"].includes(b.status)) {
    return res.status(400).json({ error: "Estado no válido." });
  }

  const events = readEvents();
  const clash = conflict(b, events);

  if (clash) {
    return res.status(409).json({
      error: `Conflicto: ya existe un show confirmado ese día (${clash.title}). Revisa la fecha antes de cerrar otro.`
    });
  }

  const event = {
    id: "evt_" + Date.now().toString(36) + "_" +
      Math.random().toString(36).slice(2, 7),
    title: String(b.title).trim(),
    date: b.date,
    startTime: b.startTime || "21:00",
    venue: b.venue || "",
    city: b.city || "",
    contact: b.contact || "",
    fee: b.fee || "",
    notes: b.notes || "",
    status: b.status,
    createdAt: new Date().toISOString()
  };

  events.push(event);
  writeEvents(events);
  res.status(201).json(event);
});

// Editar evento
app.put("/api/events/:id", auth, admin, (req, res) => {
  const events = readEvents();
  const idx = events.findIndex(e => e.id === req.params.id);

  if (idx < 0) {
    return res.status(404).json({ error: "Evento no encontrado." });
  }

  const b = req.body || {};

  if (!b.title || !validDate(b.date)) {
    return res.status(400).json({
      error: "Ingresa el nombre del evento y una fecha válida."
    });
  }

  if (!["confirmed", "pending", "cancelled"].includes(b.status)) {
    return res.status(400).json({ error: "Estado no válido." });
  }

  const candidate = { ...events[idx], ...b };
  const clash = conflict(candidate, events, req.params.id);

  if (clash) {
    return res.status(409).json({
      error: `Conflicto: ya existe un show confirmado ese día (${clash.title}).`
    });
  }

  events[idx] = candidate;
  writeEvents(events);
  res.json(candidate);
});

// Eliminar evento
app.delete("/api/events/:id", auth, admin, (req, res) => {
  const events = readEvents();
  const next = events.filter(e => e.id !== req.params.id);

  if (next.length === events.length) {
    return res.status(404).json({ error: "Evento no encontrado." });
  }

  writeEvents(next);
  res.json({ ok: true });
});

// Descargar copia de seguridad: solo administradores
app.get("/api/admin/backup", auth, admin, (req, res) => {
  try {
    const events = readEvents();

    const backup = {
      app: "agenda-corona-boliganga",
      createdAt: new Date().toISOString(),
      count: events.length,
      events
    };

    const stamp = new Date().toISOString().replace(/[:.]/g, "-");

    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=agenda-backup-${stamp}.json`
    );
    res.setHeader("Cache-Control", "no-store");

    res.status(200).send(JSON.stringify(backup, null, 2));
  } catch (err) {
    console.error("No se pudo generar la copia de seguridad", err);

    res.status(500).json({
      error: "No se pudo generar la copia de seguridad."
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Agenda musical activa en http://localhost:${PORT}`);
});

