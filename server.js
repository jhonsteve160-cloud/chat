import express from "express";
import sqlite3 from "sqlite3";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import http from "http";
import { Server } from "socket.io";

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(
  session({
    secret: "supersecret",
    resave: false,
    saveUninitialized: false
  })
);

// DB
const db = new sqlite3.Database("./app.db");

// Create tables
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    message TEXT,
    timestamp TEXT
  )
`);

// Default user
db.get("SELECT * FROM users WHERE username = ?", ["admin"], (err, row) => {
  if (!row) {
    const hash = bcrypt.hashSync("12345", 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [
      "admin",
      hash
    ]);
    console.log("Default user created → admin / 12345");
  }
});

// Auth guard
function requireLogin(req, res, next) {
  if (!req.session.username) return res.redirect("/");
  next();
}

// Pages
app.get("/", (req, res) =>
  res.sendFile(path.join(__dirname, "login.html"))
);

app.get("/signup", (req, res) =>
  res.sendFile(path.join(__dirname, "signup.html"))
);

app.get("/chat", requireLogin, (req, res) =>
  res.sendFile(path.join(__dirname, "chat.html"))
);

// Signup
app.post("/signup", (req, res) => {
  const { username, password } = req.body;

  const hash = bcrypt.hashSync(password, 10);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hash],
    err => {
      if (err) return res.status(400).send("Username already exists");
      req.session.username = username;
      res.redirect("/chat");
    }
  );
});

// Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    (err, user) => {
      if (!user) return res.status(401).send("Invalid credentials");

      const valid = bcrypt.compareSync(password, user.password);
      if (!valid) return res.status(401).send("Invalid credentials");

      req.session.username = username;
      res.redirect("/chat");
    }
  );
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// —— Realtime Chat ——

io.on("connection", socket => {
  console.log("User connected");

  // Load last 50 messages
  db.all(
    "SELECT * FROM messages ORDER BY id DESC LIMIT 50",
    (err, rows) => {
      if (!err) {
        socket.emit("chat_history", rows.reverse());
      }
    }
  );

  // Receive message
  socket.on("send_message", ({ username, message }) => {
    const timestamp = new Date().toISOString();

    db.run(
      "INSERT INTO messages (username, message, timestamp) VALUES (?, ?, ?)",
      [username, message, timestamp]
    );

    io.emit("new_message", { username, message, timestamp });
  });
});

server.listen(PORT, () =>
  console.log(`Server running on port ${PORT}`)
);
