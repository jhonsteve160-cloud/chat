import express from "express";
import session from "express-session";
import path from "path";
import { fileURLToPath } from "url";
import { Pool } from "pg";
import bcrypt from "bcryptjs";
import http from "http";
import { Server } from "socket.io";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

// ---------- DATABASE ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Create tables if missing
await pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user'
  );
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    sender TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
  );
`);

// Ensure admin exists (no credentials shown on site)
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "admin123";

const adminCheck = await pool.query(
  `SELECT * FROM users WHERE username=$1`,
  [ADMIN_USER]
);

if (adminCheck.rowCount === 0) {
  const hash = bcrypt.hashSync(ADMIN_PASS, 10);
  await pool.query(
    `INSERT INTO users (username,password_hash,role)
     VALUES ($1,$2,'admin')`,
    [ADMIN_USER, hash]
  );
  console.log("Admin account created:");
  console.log(`Username: ${ADMIN_USER}`);
  console.log("Password: (value from ADMIN_PASS env)");
}

// ---------- MIDDLEWARE ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(
  session({
    secret: "secure-chat-secret",
    resave: false,
    saveUninitialized: false
  })
);

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).send("Forbidden");
  next();
}

// ---------- ROUTES ----------
app.get("/", (req, res) =>
  res.sendFile(path.join(__dirname, "login.html"))
);

app.get("/chat", requireLogin, (req, res) =>
  res.sendFile(path.join(__dirname, "chat.html"))
);

app.get("/admin", requireAdmin, (req, res) =>
  res.sendFile(path.join(__dirname, "admin.html"))
);

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query(
    `SELECT * FROM users WHERE username=$1`,
    [username]
  );

  if (result.rowCount === 0) return res.status(401).send("Invalid login");

  const user = result.rows[0];

  if (!bcrypt.compareSync(password, user.password_hash))
    return res.status(401).send("Invalid login");

  req.session.user = {
    username: user.username,
    role: user.role
  };

  res.redirect("/chat");
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// Admin create users (ONLY admin)
app.post("/admin/create-user", requireAdmin, async (req, res) => {
  const { username, password } = req.body;

  const hash = bcrypt.hashSync(password, 10);

  await pool.query(
    `INSERT INTO users (username,password_hash,role)
     VALUES ($1,$2,'user')
     ON CONFLICT (username) DO NOTHING`,
    [username, hash]
  );

  res.redirect("/admin");
});

// API to fetch session username (for chat.html)
app.get("/whoami", requireLogin, (req, res) => {
  res.json({ username: req.session.user.username });
});

// ---------- SOCKET.IO ----------
io.on("connection", socket => {
  socket.on("join", async username => {
    socket.username = username;

    // send last 50 messages
    const { rows } = await pool.query(
      `SELECT sender,content,
              to_char(created_at,'HH24:MI') AS time
       FROM messages
       ORDER BY id DESC
       LIMIT 50`
    );

    socket.emit("history", rows.reverse());
  });

  socket.on("message", async msg => {
    if (!socket.username) return;

    await pool.query(
      `INSERT INTO messages (sender,content)
       VALUES ($1,$2)`,
      [socket.username, msg]
    );

    const payload = {
      sender: socket.username,
      content: msg,
      time: new Date().toLocaleTimeString()
    };

    io.emit("message", payload);
  });
});

server.listen(PORT, () =>
  console.log("Server running on port " + PORT)
);
