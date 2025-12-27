const express = require("express");
const session = require("express-session");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// =====================
// CONFIG
// =====================

const ADMIN_USER = "admin";
const ADMIN_PASS = "admin123";

// Optional encryption key (leave empty to disable)
const ENCRYPTION_KEY = process.env.CHAT_KEY || "";

// =====================
// DATABASE
// =====================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender TEXT NOT NULL,
      receiver TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
})();

// =====================
// ENCRYPT / DECRYPT
// =====================

function encrypt(text) {
  if (!ENCRYPTION_KEY) return text;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    ENCRYPTION_KEY.padEnd(32).slice(0, 32),
    iv
  );
  const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

function decrypt(text) {
  if (!ENCRYPTION_KEY) return text;
  const [ivHex, dataHex] = text.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const encrypted = Buffer.from(dataHex, "hex");
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    ENCRYPTION_KEY.padEnd(32).slice(0, 32),
    iv
  );
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);
  return decrypted.toString();
}

// =====================
// MIDDLEWARE
// =====================

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "secure-chat-secret",
    resave: false,
    saveUninitialized: false
  })
);

const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.redirect("/login");
  next();
};

const requireAdmin = (req, res, next) => {
  if (req.session.user !== ADMIN_USER) return res.send("Access denied");
  next();
};

// =====================
// LOGIN
// =====================

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // admin login
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.user = ADMIN_USER;
    return res.redirect("/admin");
  }

  const result = await pool.query(
    "SELECT password_hash FROM users WHERE username=$1",
    [username]
  );

  if (!result.rows.length) return res.send("Invalid credentials");

  const hash = result.rows[0].password_hash;

  if (!bcrypt.compareSync(password, hash))
    return res.send("Invalid credentials");

  req.session.user = username;
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// whoami endpoint for UI
app.get("/whoami", requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

// =====================
// ADMIN PANEL
// =====================

app.get("/admin", requireAdmin, async (req, res) => {
  const users = await pool.query("SELECT username FROM users ORDER BY username");

  res.send(`
    <h2>Admin Panel</h2>

    <h3>Add User</h3>
    <form method="POST" action="/admin/add">
      <input name="username" placeholder="username" />
      <input name="password" placeholder="password" />
      <button type="submit">Add</button>
    </form>

    <h3>Users</h3>
    <ul>
      ${users.rows.map(u => `<li>${u.username}</li>`).join("")}
    </ul>

    <a href="/logout">Logout</a>
  `);
});

app.post("/admin/add", requireAdmin, async (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, 10);

  await pool.query(
    `
      INSERT INTO users (username, password_hash)
      VALUES ($1,$2)
      ON CONFLICT (username)
      DO UPDATE SET password_hash = EXCLUDED.password_hash
    `,
    [username, hash]
  );

  res.redirect("/admin");
});

// =====================
// CHAT UI
// =====================

app.get("/", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "chat.html"));
});

// =====================
// SOCKET — PRIVATE CHAT
// =====================

io.use((socket, next) => {
  const req = socket.request;
  const user = req.session?.user;
  if (!user || user === ADMIN_USER) return next(new Error("Unauthorized"));
  socket.username = user;
  next();
});

io.on("connection", async socket => {
  // load history
  const history = await pool.query(
    `
      SELECT sender, receiver, content, created_at
      FROM messages
      WHERE sender=$1 OR receiver=$1
      ORDER BY id ASC
    `,
    [socket.username]
  );

  socket.emit(
    "chat-history",
    history.rows.map(m => ({
      ...m,
      content: decrypt(m.content)
    }))
  );

  // handle messages
  socket.on("private-message", async ({ to, message }) => {
    const encrypted = encrypt(message);

    await pool.query(
      `
        INSERT INTO messages (sender, receiver, content)
        VALUES ($1,$2,$3)
      `,
      [socket.username, to, encrypted]
    );

    // deliver only to sender + receiver
    io.sockets.sockets.forEach(s => {
      if (s.username === to || s.username === socket.username) {
        s.emit("chat message", {
          from: socket.username,
          to,
          message
        });
      }
    });
  });
});

server.listen(process.env.PORT || 3000, () =>
  console.log("Chat running on port 3000")
);