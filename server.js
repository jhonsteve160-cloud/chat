import express from "express";
import sqlite3 from "sqlite3";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const PORT = process.env.PORT || 3000;

// Path helpers
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// SQLite setup
const db = new sqlite3.Database("./users.db");

// Create users table if not exists
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )
`);

// Seed default user (username: admin, password: 12345)
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

// Serve pages
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/chat", (req, res) => res.sendFile(path.join(__dirname, "chat.html")));

// Login endpoint
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (!user) return res.status(401).send("Invalid username or password");

    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) return res.status(401).send("Invalid username or password");

    return res.redirect("/chat");
  });
});

app.listen(PORT, () =>
  console.log(`Server running on port ${PORT}`)
);