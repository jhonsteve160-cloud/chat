const express = require('express');
const session = require('express-session');
const { createServer } = require('http');
const { Server } = require('socket.io');

const app = express();
const server = createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

const USERS = {
  "7": "9",
  "admin": "1234"
};

app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false
}));

function requireAuth(req, res, next) {
  if (req.session.username) {
    return next();
  }
  res.redirect('/login');
}

app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/login.html');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (USERS[username] === password) {
    req.session.username = username;
    res.redirect('/');
  } else {
    res.send('Invalid credentials. <a href="/login">Try again</a>');
  }
});

app.get('/', requireAuth, (req, res) => {
  res.sendFile(__dirname + '/chat.html');
});

// Socket.io authentication
io.use((socket, next) => {
  const req = socket.request;
  const res = {};
  session({
    secret: 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false
  })(req, res, next);
});

io.on('connection', (socket) => {
  if (!socket.request.session.username) {
    socket.disconnect();
    return;
  }
  socket.on('chat message', (msg) => {
    const username = socket.request.session.username;
    io.emit('chat message', username + ': ' + msg);
  });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});