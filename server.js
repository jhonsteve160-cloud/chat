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
// ----------- SAFE, ORDERED, NON-CRASHING MIGRATIONS -----------
//

async function migrate() {
  try {
    // create table if missing (no role here on purpose)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // make sure role column exists BEFORE any inserts use it
    await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user';
    `);

    // backfill nulls
    await pool.query(`
      UPDATE users SET role='user' WHERE role IS NULL;
    `);

    // messages table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
        room TEXT DEFAULT 'global',
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room);
    `);

    // --- ensure admin account exists AFTER role column ---
    const adminUser = "admin";
    const adminPass =
      process.env.ADMIN_PASSWORD || "change_this_admin_password";

    const hash = await bcrypt.hash(adminPass, 10);

    await pool.query(
      `
        INSERT INTO users (username, password_hash, role)
        VALUES ($1,$2,'admin')
        ON CONFLICT (username) DO NOTHING;
      `,
      [adminUser, hash]
    );

    console.log("DB schema OK — migrations applied");
  } catch (err) {
    console.error("Migration failed but app will continue:", err.message);
  }
}

await migrate();

//
// ----------- HELPERS -----------
//

async function getUser(username) {
  const { rows } = await pool.query(
    "SELECT * FROM users WHERE username=$1 LIMIT 1",
    [username]
  );
  return rows[0];
}

//
// ----------- AUTH -----------
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
    role: user.role || "user"
  };

  res.json({ ok: true });
});

// 🚫 disable public signup completely
app.post("/signup", (_req, res) => {
  return res
    .status(403)
    .json({ error: "Accounts may only be created via admin dashboard." });
});

//
// ----------- SOCKET + CHAT -----------
//

// attach session to socket transport
io.engine.use(
  session({
    secret: process.env.SESSION_SECRET || "change-me",
    resave: false,
    saveUninitialized: false
  })
);

io.use((socket, next) => {
  const s = socket.request.session;
  if (!s?.user) return next(new Error("unauthorized"));
  socket.user = s.user;
  next();
});

io.on("connection", (socket) => {
  const user = socket.user;

  socket.join("global");

  socket.on("typing", (room = "global") => {
    socket.to(room).emit("typing", { user: user.username });
  });

  socket.on("join", (room) => socket.join(room));

  socket.on("message", async ({ content, room = "global", to }) => {
    if (!content?.trim()) return;

    if (to) {
      // deterministic dm room id
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
      created_at: rows[0].created_at
    };

    io.to(room).emit("message", msg);
  });
});

//
// ----------- HISTORY API -----------
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
// ----------- START -----------
//

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log("Server running on", PORT));
