import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import { Server } from "socket.io";
import http from "http";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-me",
    resave: false,
    saveUninitialized: false
  })
);

//
// ---------- AUTO DATABASE FIX / MIGRATIONS -----------
//

async function migrate() {
  // enable UUID + crypto helpers where supported
  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";
  `).catch(() => {});

  // USERS TABLE
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // ensure ROLE column exists (prevents crash)
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';
  `);

  // MESSAGES TABLE
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
      room TEXT DEFAULT 'global',
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // indexes
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room);
    CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
  `);

  // seed admin if missing
  const adminUser = "admin";
  const adminPass = process.env.ADMIN_PASSWORD || "change_this_admin_password";

  const hash = await bcrypt.hash(adminPass, 10);

  await pool.query(
    `
    INSERT INTO users (username, password_hash, role)
    VALUES ($1,$2,'admin')
    ON CONFLICT (username) DO NOTHING;
  `,
    [adminUser, hash]
  );

  console.log("Database migrated & admin ensured");
}

await migrate();

//
// ---------- AUTH HELPERS -----------
//

async function getUser(username) {
  const { rows } = await pool.query(
    "SELECT * FROM users WHERE username=$1 LIMIT 1",
    [username]
  );
  return rows[0];
}

//
// ---------- AUTH ROUTES -----------
//

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await getUser(username);
  if (!user) return res.status(401).json({ error: "Invalid login" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid login" });

  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role
  };

  res.json({ ok: true });
});

// 🚫 disable public signup
app.post("/signup", (_req, res) => {
  return res.status(403).json({
    error: "New accounts may only be created via the admin dashboard."
  });
});

//
// ---------- SOCKET AUTH -----------
//

io.engine.use((req, _res, next) => {
  session({
    secret: process.env.SESSION_SECRET || "change-me",
    resave: false,
    saveUninitialized: false
  })(req, {}, next);
});

io.use((socket, next) => {
  const session = socket.request.session;
  if (!session?.user) return next(new Error("unauthorized"));
  socket.user = session.user;
  next();
});

//
// ---------- CHAT / ROOMS / DMS -----------
//

io.on("connection", (socket) => {
  const user = socket.user;

  socket.join("global");

  // typing indicator
  socket.on("typing", (room = "global") => {
    socket.to(room).emit("typing", { user: user.username });
  });

  // join custom room
  socket.on("join", (room) => socket.join(room));

  // send message
  socket.on("message", async ({ content, room = "global", to }) => {
    if (!content?.trim()) return;

    // private DM channel
    if (to) room = `dm:${[user.username, to].sort().join(":")}`;

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
      created_at: rows[0].created_at
    };

    io.to(room).emit("message", msg);
  });
});

//
// ---------- HISTORY ENDPOINT -----------
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
// ---------- START SERVER -----------
//

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log("Server running on", PORT);
});
