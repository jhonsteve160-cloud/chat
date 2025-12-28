import express from "express";
import http from "http";
import { Server } from "socket.io";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import pg from "pg";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ---------- presence ----------
const onlineUsers = new Map();

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

    // Handle existing users table
    const tableInfo = await client.query("SELECT column_name FROM information_schema.columns WHERE table_name = 'users'");
    const columns = tableInfo.rows.map(r => r.column_name);
    
    if (!columns.includes('id')) {
      await client.query("ALTER TABLE users ADD COLUMN id SERIAL");
    }

    // CRITICAL: Ensure users(id) is the primary key or has a unique constraint
    const pkCheckUsers = await client.query(`
      SELECT count(*) FROM information_schema.table_constraints 
      WHERE table_name='users' AND constraint_type='PRIMARY KEY'
    `);
    if (pkCheckUsers.rows[0].count == 0) {
      await client.query("ALTER TABLE users ADD PRIMARY KEY (id)");
    } else {
      // Check if the PK is actually on 'id'
      const pkColumnCheck = await client.query(`
        SELECT kcu.column_name 
        FROM information_schema.table_constraints tc 
        JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name 
        WHERE tc.table_name = 'users' AND tc.constraint_type = 'PRIMARY KEY'
      `);
      if (pkColumnCheck.rows[0].column_name !== 'id') {
        // If PK is on something else, ensure 'id' is at least unique so it can be referenced
        await client.query("ALTER TABLE users ADD CONSTRAINT users_id_unique UNIQUE (id)");
      }
    }

    // Create friends table
    await client.query(`
      CREATE TABLE IF NOT EXISTS friends (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        friend_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, friend_id)
      )
    `);

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
    
    if (msgColumns.includes('sender')) await client.query("ALTER TABLE messages ALTER COLUMN sender DROP NOT NULL");
    if (msgColumns.includes('receiver')) await client.query("ALTER TABLE messages ALTER COLUMN receiver DROP NOT NULL");
    if (msgColumns.includes('content')) await client.query("ALTER TABLE messages ALTER COLUMN content DROP NOT NULL");

    if (!msgColumns.includes('from')) await client.query('ALTER TABLE messages ADD COLUMN "from" TEXT NOT NULL DEFAULT \'unknown\'');
    if (!msgColumns.includes('text')) await client.query('ALTER TABLE messages ADD COLUMN text TEXT NOT NULL DEFAULT \'\'');
    if (!msgColumns.includes('room')) await client.query('ALTER TABLE messages ADD COLUMN room TEXT');
    if (!msgColumns.includes('timestamp')) await client.query('ALTER TABLE messages ADD COLUMN timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP');
    if (!msgColumns.includes('receiver_id')) {
      await client.query("ALTER TABLE messages ADD COLUMN receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE");
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
  try {
    const { username, password } = req.body;
    const result = await pool.query("SELECT id, username, role FROM users WHERE username = $1 AND password = $2", [username, password]);
    const user = result.rows[0];

    if (!user)
      return res.status(401).json({ error: "Invalid credentials" });

    return res.status(200).json(user);
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- ADMIN: CREATE USER ----------
app.post("/api/admin/users", async (req, res) => {
  const { adminUser, adminPass, username, password } = req.body;
  if (!isAdmin(adminUser, adminPass)) return res.status(403).json({ error: "Admin auth failed" });
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });

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
  if (!isAdmin(adminUser, adminPass)) return res.status(403).json({ error: "Admin auth failed" });
  const users = await getUsers();
  return res.status(200).json(users.map(u => ({ id: u.id, username: u.username, role: u.role })));
});

// ---------- FRIENDS & PRIVATE MESSAGES ----------
app.post("/api/users/search", async (req, res) => {
  const { query, currentUserId } = req.body;
  try {
    const result = await pool.query(
      "SELECT id, username FROM users WHERE username ILIKE $1 AND id != $2 LIMIT 10",
      [`%${query}%`, currentUserId]
    );
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: "Search failed" }); }
});

app.post("/api/friends/add", async (req, res) => {
  const { userId, friendId } = req.body;
  try {
    await pool.query("INSERT INTO friends (user_id, friend_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", [userId, friendId]);
    await pool.query("INSERT INTO friends (user_id, friend_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", [friendId, userId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: "Failed to add friend" }); }
});

app.get("/api/friends/:userId", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT u.id, u.username FROM users u JOIN friends f ON u.id = f.friend_id WHERE f.user_id = $1",
      [req.params.userId]
    );
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: "Failed to load friends" }); }
});

app.get("/api/messages", async (req, res) => {
  const userId = req.query.userId;
  try {
    const result = await pool.query(`
      SELECT m.*, u.id as sender_id, u.username as sender_name 
      FROM messages m 
      LEFT JOIN users u ON m."from" = u.username 
      WHERE m.room IS NOT NULL 
      OR m.receiver_id = $1 
      OR (m.receiver_id IS NOT NULL AND u.id = $1)
      ORDER BY m.timestamp ASC
    `, [userId]);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: "Failed to load messages" }); }
});

// ---------- SOCKET.IO ----------
io.on("connection", socket => {
  socket.on("join", user => {
    socket.data.user = user;
    socket.join(`user_${user.id}`);
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
    try {
      const { from, room, text, receiverId } = data;
      const senderResult = await pool.query("SELECT id FROM users WHERE username = $1", [from]);
      const senderId = senderResult.rows[0]?.id;

      const result = await pool.query(
        'INSERT INTO messages ("from", room, text, receiver_id) VALUES ($1, $2, $3, $4) RETURNING *',
        [from, room, text, receiverId]
      );
      const msg = { ...result.rows[0], sender_id: senderId };

      if (receiverId) {
        io.to(`user_${receiverId}`).emit("message", msg);
        io.to(`user_${senderId}`).emit("message", msg);
      } else if (room) {
        io.to(room).emit("message", msg);
      } else {
        io.emit("message", msg);
      }
    } catch (e) { console.error("Message error:", e); }
  });

  socket.on("disconnect", () => {
    onlineUsers.delete(socket.id);
    io.emit("presence", Array.from(onlineUsers.values()));
  });
});

// ---------- STATIC UI ----------
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => { res.sendFile(path.join(__dirname, "public/index.html")); });

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
server.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT));
