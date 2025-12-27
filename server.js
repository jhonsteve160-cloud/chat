import express from "express";
import session from "express-session";
import { Server } from "socket.io";
import http from "http";
import pkg from "pg";
import crypto from "crypto";

const { Pool } = pkg;

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "session-secret",
    resave: false,
    saveUninitialized: false,
  })
);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

//
// --- PASSWORD HASHING (no bcrypt, no deps) ---
//

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(":");
  const hashed = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(hashed));
}

//
// --- SAFE AUTO-MIGRATIONS (will not crash) ---
//

async function migrate() {
  try {
    await pool.query(`
      CREATE EXTENSION IF NOT EXISTS "pgcrypto";
      
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        sender_id UUID REFERENCES users(id),
        room TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room);
    `);

    // --- ensure admin exists ---
    const adminPass = process.env.ADMIN_PASSWORD || "admin123";
    const hash = hashPassword(adminPass);

    await pool.query(
      `
      INSERT INTO users (username, password_hash, role)
      VALUES ('admin', $1, 'admin')
      ON CONFLICT (username) DO NOTHING;
    `,
      [hash]
    );

    console.log("DB ready");
  } catch (err) {
    console.log("Migration skipped:", err.message);
  }
}

await migrate();

//
// --- AUTH ---
//

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const { rows } = await pool.query(
    `SELECT * FROM users WHERE username=$1 LIMIT 1`,
    [username]
  );

  if (!rows.length) return res.status(401).json({ error: "Invalid login" });

  const user = rows[0];

  if (!verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: "Invalid login" });
  }

  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role,
  };

  res.json({ ok: true });
});

// 🚫 sign-ups disabled — only admin can add users
app.post("/signup", (_req, res) =>
  res
    .status(403)
    .json({ error: "Accounts may only be created via admin dashboard." })
);

//
// --- ADMIN: CREATE USER ---
//

app.post("/admin/create-user", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).json({ error: "Forbidden" });

  const { username, password } = req.body;
  const hash = hashPassword(password);

  await pool.query(
    `
    INSERT INTO users (username, password_hash, role)
    VALUES ($1,$2,'user')
    ON CONFLICT (username) DO NOTHING;
  `,
    [username, hash]
  );

  res.json({ ok: true });
});

//
// --- SOCKET AUTH ---
//

io.use((socket, next) => {
  const s = socket.request.session;
  if (!s?.user) return next(new Error("unauthorized"));
  socket.user = s.user;
  next();
});

//
// --- CHAT ---
//

io.on("connection", (socket) => {
  const user = socket.user;

  socket.join("global");

  // typing indicator
  socket.on("typing", (room = "global") => {
    socket.to(room).emit("typing", { user: user.username });
  });

  // join dm / room
  socket.on("join", (room) => socket.join(room));

  // send message
  socket.on("message", async ({ content, room = "global", to }) => {
    if (!content?.trim()) return;

    if (to) {
      room = `dm:${[user.username, to].sort().join(":")}`;
      socket.join(room);
    }

    const { rows } = await pool.query(
      `
      INSERT INTO messages (sender_id, room, content)
      VALUES ($1,$2,$3)
      RETURNING id, created_at
    `,
      [user.id, room, content]
    );

    const msg = {
      id: rows[0].id,
      user: user.username,
      content,
      room,
      created_at: rows[0].created_at,
    };

    io.to(room).emit("message", msg);
  });
});

//
// --- HISTORY API ---
//

app.get("/history/:room", async (req, res) => {
  const room = req.params.room || "global";

  const { rows } = await pool.query(
    `
    SELECT m.id, m.content, m.created_at, u.username AS user
    FROM messages m
    JOIN users u ON u.id = m.sender_id
    WHERE room=$1
    ORDER BY created_at ASC
  `,
    [room]
  );

  res.json(rows);
});

//
// --- START ---
//

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log("Running on", PORT));
