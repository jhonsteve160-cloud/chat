# Secure Chat

A real-time chat application built with Node.js, Express, and Socket.io.

## Overview

This is a secure chat application that supports:
- User authentication (login with username/password)
- Real-time messaging via WebSockets
- Admin dashboard for user management
- Online presence tracking
- Chat rooms
- Typing indicators

## Project Structure

```
├── server.js          # Main Express/Socket.io server
├── package.json       # Node.js dependencies
├── public/            # Static frontend files
│   ├── index.html     # Main chat interface
│   ├── login.html     # Login page
│   ├── signup.html    # Signup page
│   ├── chat.html      # Alternative chat view
│   └── admin.html     # Admin dashboard
└── data/              # Persistent JSON storage (auto-created)
    ├── users.json     # User accounts
    └── messages.json  # Chat messages
```

## Running the Application

The app runs on port 5000 and binds to 0.0.0.0 for Replit compatibility.

```bash
npm start
```

## Default Admin Account

- Username: `admin`
- Password: `admin123`

## Tech Stack

- Node.js 20
- Express.js - Web framework
- Socket.io - Real-time WebSocket communication
- bcryptjs - Password hashing (available but not currently used)
- File-based JSON storage for users and messages
