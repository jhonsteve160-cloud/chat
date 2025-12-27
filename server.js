import express from "express";
import http from "http";
import { Server } from "socket.io";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const MSG_FILE = path.join(DATA_DIR, "messages.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

// ---------- helpers ----------
function loadJSON(file, fallback) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify(fallback, null, 2));
    return fallback;
  }
  return JSON.parse(fs.readFileSync(file));
}

function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

import pg from "pg";
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ---------- DB INIT ----------
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    
    // Create users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user'
      )
    `);

    // Handle existing users table that might have different columns (Railway scenario)
    const tableInfo = await client.query("SELECT column_name FROM information_schema.columns WHERE table_name = 'users'");
    const columns = tableInfo.rows.map(r => r.column_name);
    
    if (!columns.includes('password')) {
      if (columns.includes('password_hash')) {
        await client.query("ALTER TABLE users RENAME COLUMN password_hash TO password");
      } else {
        await client.query("ALTER TABLE users ADD COLUMN password TEXT");
      }
    }
    if (!columns.includes('role')) {
      await client.query("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'");
    }
    if (!columns.includes('id')) {
      await client.query("ALTER TABLE users ADD COLUMN id SERIAL PRIMARY KEY");
    }

    // Create messages table
    await client.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        "from" TEXT NOT NULL,
        room TEXT,
        text TEXT NOT NULL,
        timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Handle existing messages table
    const msgTableInfo = await client.query("SELECT column_name FROM information_schema.columns WHERE table_name = 'messages'");
    const msgColumns = msgTableInfo.rows.map(r => r.column_name);
    if (!msgColumns.includes('from')) {
      await client.query('ALTER TABLE messages ADD COLUMN "from" TEXT');
    }

    // Ensure admin exists
    await client.query(`
      INSERT INTO users (username, password, role)
      VALUES ('admin', 'admin123', 'admin')
      ON CONFLICT (username) DO NOTHING
    `);

    await client.query("COMMIT");
    console.log("Database initialized successfully");
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Database initialization failed:", e);
  } finally {
    client.release();
  }
}
initDB();

// ---------- persistent data ----------
async function getUsers() {
  const res = await pool.query("SELECT * FROM users");
  return res.rows;
}

async function getMessages() {
  const res = await pool.query('SELECT "from", room, text, timestamp FROM messages ORDER BY timestamp ASC');
  return res.rows;
}

// ---------- express / socket ----------
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------- ADMIN AUTH ----------
const ADMIN_USER = "admin";
const ADMIN_PASS = "admin123";

function isAdmin(u, p) {
  return u === ADMIN_USER && p === ADMIN_PASS;
}

// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query("SELECT id, username, role FROM users WHERE username = $1 AND password = $2", [username, password]);
  const user = result.rows[0];

  if (!user)
    return res.status(401).json({ error: "Invalid credentials" });

  return res.status(200).json(user);
});

// ---------- ADMIN: CREATE USER ----------
app.post("/api/admin/users", async (req, res) => {
  const { adminUser, adminPass, username, password } = req.body;

  if (!isAdmin(adminUser, adminPass))
    return res.status(403).json({ error: "Admin auth failed" });

  if (!username || !password)
    return res.status(400).json({ error: "Missing fields" });

  try {
    const result = await pool.query(
      "INSERT INTO users (username, password, role) VALUES ($1, $2, 'user') RETURNING id, username, role",
      [username, password]
    );
    return res.status(201).json({ success: true, user: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "User already exists" });
    throw err;
  }
});

// ---------- LIST USERS (ADMIN) ----------
app.post("/api/admin/list-users", async (req, res) => {
  const { adminUser, adminPass } = req.body;

  if (!isAdmin(adminUser, adminPass))
    return res.status(403).json({ error: "Admin auth failed" });

  const users = await getUsers();
  return res.status(200).json(users.map(u => ({
    id: u.id,
    username: u.username,
    role: u.role
  })));
});

// ---------- MESSAGES API ----------
app.get("/api/messages", async (req, res) => {
  const messages = await getMessages();
  res.status(200).json(messages);
});

// ---------- presence ----------
const onlineUsers = new Map();

// ---------- SOCKET.IO ----------
io.on("connection", socket => {

  socket.on("join", user => {
    socket.data.user = user;
    onlineUsers.set(socket.id, user);

    io.emit("presence", Array.from(onlineUsers.values()));
  });

  socket.on("joinRoom", room => {
    socket.join(room);
  });

  socket.on("typing", (room, user) => {
    socket.to(room).emit("typing", user);
  });

  socket.on("message", async data => {
    const { from, room, text } = data;
    const result = await pool.query(
      'INSERT INTO messages ("from", room, text) VALUES ($1, $2, $3) RETURNING "from", room, text, timestamp',
      [from, room, text]
    );
    const msg = result.rows[0];

    if (data.room)
      io.to(data.room).emit("message", msg);
    else
      io.emit("message", msg);
  });

  socket.on("disconnect", () => {
    onlineUsers.delete(socket.id);
    io.emit("presence", Array.from(onlineUsers.values()));
  });
});

// ---------- STATIC UI ----------
app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// ---------- ADMIN: DELETE USER ----------
app.post("/api/admin/delete-user", async (req, res) => {
  const { adminUser, adminPass, username } = req.body;
  if (!isAdmin(adminUser, adminPass)) return res.status(403).json({ error: "Admin auth failed" });
  if (username === "admin") return res.status(400).json({ error: "Cannot delete admin" });
  
  await pool.query("DELETE FROM users WHERE username = $1", [username]);
  return res.status(200).json({ success: true });
});

// ---------- USER: UPDATE PROFILE ----------
app.post("/api/user/update", async (req, res) => {
  const { currentUsername, newUsername, newPassword } = req.body;
  
  try {
    if (newUsername && newUsername !== currentUsername) {
      await pool.query("UPDATE users SET username = $1 WHERE username = $2", [newUsername, currentUsername]);
    }
    if (newPassword) {
      const usernameToUpdate = newUsername || currentUsername;
      await pool.query("UPDATE users SET password = $1 WHERE username = $2", [newPassword, usernameToUpdate]);
    }
    
    const result = await pool.query("SELECT id, username, role FROM users WHERE username = $1", [newUsername || currentUsername]);
    return res.status(200).json({ success: true, user: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "Username taken" });
    throw err;
  }
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, "0.0.0.0", () =>
  console.log("Server running on port", PORT)
);
