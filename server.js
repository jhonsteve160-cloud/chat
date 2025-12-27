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

// ---------- persistent data ----------
let users = loadJSON(USERS_FILE, [
  { id: 1, username: "admin", password: "admin123", role: "admin" }
]);

let messages = loadJSON(MSG_FILE, []);

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
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find(
    u => u.username === username && u.password === password
  );

  if (!user)
    return res.status(401).json({ error: "Invalid credentials" });

  return res.status(200).json({
    id: user.id,
    username: user.username,
    role: user.role
  });
});

// ---------- ADMIN: CREATE USER ----------
app.post("/api/admin/users", (req, res) => {
  const { adminUser, adminPass, username, password } = req.body;

  if (!isAdmin(adminUser, adminPass))
    return res.status(403).json({ error: "Admin auth failed" });

  if (!username || !password)
    return res.status(400).json({ error: "Missing fields" });

  const exists = users.find(u => u.username === username);
  if (exists)
    return res.status(409).json({ error: "User already exists" });

  const id = users.length + 1;

  const newUser = { id, username, password, role: "user" };
  users.push(newUser);
  saveJSON(USERS_FILE, users);

  return res.status(201).json({ success: true, user: newUser });
});

// ---------- LIST USERS (ADMIN) ----------
app.post("/api/admin/list-users", (req, res) => {
  const { adminUser, adminPass } = req.body;

  if (!isAdmin(adminUser, adminPass))
    return res.status(403).json({ error: "Admin auth failed" });

  return res.status(200).json(users.map(u => ({
    id: u.id,
    username: u.username,
    role: u.role
  })));
});

// ---------- MESSAGES API ----------
app.get("/api/messages", (req, res) => {
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

  socket.on("message", data => {
    const msg = {
      ...data,
      timestamp: new Date().toISOString()
    };

    messages.push(msg);
    saveJSON(MSG_FILE, messages);

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
app.post("/api/admin/delete-user", (req, res) => {
  const { adminUser, adminPass, username } = req.body;
  if (!isAdmin(adminUser, adminPass)) return res.status(403).json({ error: "Admin auth failed" });
  if (username === "admin") return res.status(400).json({ error: "Cannot delete admin" });
  users = users.filter(u => u.username !== username);
  saveJSON(USERS_FILE, users);
  return res.status(200).json({ success: true });
});

// ---------- USER: UPDATE PROFILE ----------
app.post("/api/user/update", (req, res) => {
  const { currentUsername, newUsername, newPassword } = req.body;
  const userIndex = users.findIndex(u => u.username === currentUsername);
  if (userIndex === -1) return res.status(404).json({ error: "User not found" });
  
  if (newUsername && newUsername !== currentUsername) {
    if (users.find(u => u.username === newUsername)) return res.status(409).json({ error: "Username taken" });
    users[userIndex].username = newUsername;
  }
  if (newPassword) users[userIndex].password = newPassword;
  
  saveJSON(USERS_FILE, users);
  return res.status(200).json({ success: true, user: users[userIndex] });
});

const PORT = 5000;
server.listen(PORT, "0.0.0.0", () =>
  console.log("Server running on port", PORT)
);
