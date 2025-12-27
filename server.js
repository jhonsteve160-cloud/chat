import express from "express";
import http from "http";
import { Server } from "socket.io";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 🚫 Disable public signup — admin only
const users = [
  { id: 1, username: "admin", password: "admin123", role: "admin" },
];

// In-memory messages (so chat works without DB)
const messages = [];

// 🔐 Simple login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  res.json({ id: user.id, username: user.username, role: user.role });
});

// 🧑‍💼 Admin — create users only here
app.post("/admin/create-user", (req, res) => {
  const { adminUser, adminPass, username, password } = req.body;

  const admin = users.find(
    (u) => u.username === adminUser && u.password === adminPass && u.role === "admin"
  );

  if (!admin) return res.status(403).json({ error: "Admin auth failed" });

  const exists = users.find((u) => u.username === username);
  if (exists) return res.status(400).json({ error: "User exists" });

  const id = users.length + 1;
  users.push({ id, username, password, role: "user" });

  res.json({ success: true, id, username });
});

// 🧾 Messages API
app.get("/messages", (req, res) => {
  res.json(messages);
});

// 🧩 Serve static frontend
app.use(express.static(path.join(__dirname, "public")));

// fallback for SPA
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// 💬 Socket.io Chat
io.on("connection", (socket) => {
  // join room / dm
  socket.on("joinRoom", (room) => {
    socket.join(room);
  });

  // typing indicator
  socket.on("typing", (room, user) => {
    socket.to(room).emit("typing", user);
  });

  // send message
  socket.on("message", (data) => {
    const payload = {
      ...data,
      timestamp: new Date().toISOString(),
    };

    messages.push(payload);

    if (data.room) io.to(data.room).emit("message", payload);
    else io.emit("message", payload);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log("Server running on port", PORT));
