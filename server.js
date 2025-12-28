import express from "express";
import http from "http";
import { Server } from "socket.io";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import pg from "pg";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
    // 1. Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user'
      )
    `);

    // 2. Add columns to users if they don't exist
    const userCols = (await client.query("SELECT column_name FROM information_schema.columns WHERE table_name = 'users'")).rows.map(r => r.column_name);
    if (!userCols.includes('role')) await client.query("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'");
    
    // Ensure 'id' exists and is unique if not PK
    if (!userCols.includes('id')) {
        await client.query("ALTER TABLE users ADD COLUMN id SERIAL");
    }
    
    const pkCheck = await client.query(`
        SELECT count(*) FROM information_schema.table_constraints 
        WHERE table_name='users' AND constraint_type='PRIMARY KEY'
    `);
    if (pkCheck.rows[0].count == 0) {
        await client.query("ALTER TABLE users ADD PRIMARY KEY (id)");
    }

    // 3. Friends table
    await client.query(`
      CREATE TABLE IF NOT EXISTS friends (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        friend_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        status TEXT DEFAULT 'pending',
        UNIQUE(user_id, friend_id)
      )
    `);

    // 4. Ensure status column in friends
    const friendsCols = (await client.query("SELECT column_name FROM information_schema.columns WHERE table_name = 'friends'")).rows.map(r => r.column_name);
    if (!friendsCols.includes('status')) {
      await client.query("ALTER TABLE friends ADD COLUMN status TEXT DEFAULT 'accepted'");
    }

    // 5. Messages table
    await client.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        "from" TEXT NOT NULL,
        room TEXT,
        text TEXT NOT NULL,
        timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // 6. Messages migrations
    const msgCols = (await client.query("SELECT column_name FROM information_schema.columns WHERE table_name = 'messages'")).rows.map(r => r.column_name);
    if (!msgCols.includes('from')) await client.query('ALTER TABLE messages ADD COLUMN "from" TEXT NOT NULL DEFAULT \'unknown\'');
    if (!msgCols.includes('text')) await client.query('ALTER TABLE messages ADD COLUMN text TEXT NOT NULL DEFAULT \'\'');
    if (!msgCols.includes('room')) await client.query('ALTER TABLE messages ADD COLUMN room TEXT');
    if (!msgCols.includes('timestamp')) await client.query('ALTER TABLE messages ADD COLUMN timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP');
    if (!msgCols.includes('receiver_id')) await client.query("ALTER TABLE messages ADD COLUMN receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE");

    // 7. Default admin
    await client.query(`
      INSERT INTO users (username, password, role)
      VALUES ('admin', 'admin123', 'admin')
      ON CONFLICT (username) DO NOTHING
    `);

    console.log("Database initialized successfully");
  } catch (e) {
    console.error("Database initialization failed:", e);
  } finally {
    client.release();
  }
}
initDB();

// ---------- express / socket ----------
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const ADMIN_USER = "admin";
const ADMIN_PASS = "admin123";
function isAdmin(u, p) { return u === ADMIN_USER && p === ADMIN_PASS; }

// ---------- API ----------
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query("SELECT id, username, role FROM users WHERE username = $1 AND password = $2", [username, password]);
    if (!result.rows[0]) return res.status(401).json({ error: "Invalid credentials" });
    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/admin/users", async (req, res) => {
  const { adminUser, adminPass, username, password } = req.body;
  if (!isAdmin(adminUser, adminPass)) return res.status(403).json({ error: "Auth failed" });
  try {
    const result = await pool.query("INSERT INTO users (username, password, role) VALUES ($1, $2, 'user') RETURNING id, username", [username, password]);
    res.status(201).json(result.rows[0]);
  } catch (e) { res.status(409).json({ error: "Exists" }); }
});

app.post("/api/admin/list-users", async (req, res) => {
  const { adminUser, adminPass } = req.body;
  if (!isAdmin(adminUser, adminPass)) return res.status(403).json({ error: "Auth failed" });
  const result = await pool.query("SELECT id, username, role FROM users");
  res.json(result.rows);
});

app.post("/api/users/search", async (req, res) => {
  const { query, currentUserId } = req.body;
  const result = await pool.query("SELECT id, username FROM users WHERE username ILIKE $1 AND id != $2 LIMIT 10", [`%${query}%`, currentUserId]);
  res.json(result.rows);
});

app.post("/api/friends/request", async (req, res) => {
  const { userId, friendId } = req.body;
  try {
    await pool.query("INSERT INTO friends (user_id, friend_id, status) VALUES ($1, $2, 'pending') ON CONFLICT DO NOTHING", [userId, friendId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: "Failed" }); }
});

app.post("/api/friends/accept", async (req, res) => {
  const { userId, friendId } = req.body;
  try {
    await pool.query("UPDATE friends SET status = 'accepted' WHERE user_id = $1 AND friend_id = $2", [friendId, userId]);
    await pool.query("INSERT INTO friends (user_id, friend_id, status) VALUES ($1, $2, 'accepted') ON CONFLICT (user_id, friend_id) DO UPDATE SET status = 'accepted'", [userId, friendId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: "Failed" }); }
});

app.get("/api/friends/requests/:userId", async (req, res) => {
  const result = await pool.query("SELECT u.id, u.username FROM users u JOIN friends f ON u.id = f.user_id WHERE f.friend_id = $1 AND f.status = 'pending'", [req.params.userId]);
  res.json(result.rows);
});

app.get("/api/friends/:userId", async (req, res) => {
  const result = await pool.query("SELECT u.id, u.username FROM users u JOIN friends f ON u.id = f.friend_id WHERE f.user_id = $1 AND f.status = 'accepted'", [req.params.userId]);
  res.json(result.rows);
});

app.get("/api/messages", async (req, res) => {
  const userId = req.query.userId;
  if (!userId) return res.status(400).json({ error: "Missing userId" });
  try {
    const userResult = await pool.query("SELECT id, username, role FROM users WHERE id = $1", [userId]);
    const user = userResult.rows[0];
    if (!user) return res.status(404).json({ error: "User not found" });

    let result;
    if (user.role === 'admin') {
      // Admin needs to see all messages, but they will be filtered by room/receiver on frontend
      result = await pool.query(`
        SELECT m.*, u.id as sender_id, u.username as sender_name 
        FROM messages m 
        LEFT JOIN users u ON m."from" = u.username 
        ORDER BY m.timestamp ASC
      `);
    } else {
      // Regular user sees global and their own private messages
      result = await pool.query(`
        SELECT m.*, u.id as sender_id, u.username as sender_name 
        FROM messages m 
        LEFT JOIN users u ON m."from" = u.username 
        WHERE m.room = 'global'
        OR m.receiver_id = $1 
        OR (m.receiver_id IS NOT NULL AND u.id = $1)
        ORDER BY m.timestamp ASC
      `, [userId]);
    }
    res.json(result.rows);
  } catch (e) { 
    console.error("Load messages error:", e);
    res.status(500).json({ error: "Failed" }); 
  }
});

// ---------- SOCKET ----------
io.on("connection", socket => {
  socket.on("join", user => {
    socket.data.user = user;
    socket.join(`user_${user.id}`);
    onlineUsers.set(socket.id, user);
    io.emit("presence", Array.from(onlineUsers.values()));
  });

  socket.on("typing", (roomName, user) => {
    if (roomName !== 'global' && !isNaN(roomName)) {
      socket.to(`user_${roomName}`).emit("typing", user);
    } else {
      socket.to(roomName).emit("typing", user);
    }
  });

  socket.on("message", async data => {
    try {
      const { from, room, text, receiverId } = data;
      const senderRes = await pool.query("SELECT id FROM users WHERE username = $1", [from]);
      const senderId = senderRes.rows[0]?.id;
      
      // Ensure we don't mix global and private. If receiverId exists, room should be null.
      const dbRoom = receiverId ? null : (room || 'global');
      
      const res = await pool.query('INSERT INTO messages ("from", room, text, receiver_id) VALUES ($1, $2, $3, $4) RETURNING *', [from, dbRoom, text, receiverId]);
      const msg = { ...res.rows[0], sender_id: senderId };
      
      if (receiverId) {
        // Send to receiver and sender for private chats
        io.to(`user_${receiverId}`).emit("message", msg);
        if (senderId !== receiverId) {
          io.to(`user_${senderId}`).emit("message", msg);
        }
      } else {
        // Broadcast global messages
        io.emit("message", msg);
      }
    } catch (e) { console.error("Socket message error:", e); }
  });

  socket.on("disconnect", () => {
    onlineUsers.delete(socket.id);
    io.emit("presence", Array.from(onlineUsers.values()));
  });
});

app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public/index.html")));

const PORT = process.env.PORT || 5000;
server.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT));
