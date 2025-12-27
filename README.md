# Secure 2-User Chat Web App

A minimal, production-ready chat application built with Node.js, Express, and Socket.io. Designed for small private use with hard-coded user authentication.

## Features

- Secure username/password login with session-based authentication
- Real-time chat using Socket.io
- Protected routes and WebSocket connections
- No database required; users stored in code
- Simple HTML frontend
- Ready for deployment on Railway with zero configuration

## Installation

1. Clone this repository.
2. Run `npm install` to install dependencies.
3. Run `npm start` to start the server.

## Adding New Users

Edit the `USERS` object in `server.js`:

```javascript
const USERS = {
  "7": "9",
  "admin": "1234",
  "newuser": "newpassword"
};
```

Restart the server after changes.

## Deployment on Railway

1. Sign up for a Railway account at https://railway.app.
2. Connect your GitHub repository to Railway.
3. Deploy the app. Railway will automatically run `npm start`.
4. The app uses the `PORT` environment variable provided by Railway.

## Default Credentials

- Username: `7`, Password: `9`
- Username: `admin`, Password: `1234`

## Security Notes

- Change the session secret in production.
- This app is suitable for small private use only.
- No anonymous access allowed.
- Messages are broadcast only to authenticated users.