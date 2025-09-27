
# Gatorkut - Full Package

This package contains:
- frontend/ : lightweight placeholder and instructions (React app available in original repo)
- backend/ : Node.js + Express + SQLite API with full schema and auth

## Backend quick start

cd backend
npm install
node server.js

- Default: DB file will be created at ./db.sqlite
- Uploads saved to ./uploads (served at /uploads/*)
- JWT secret: set env JWT_SECRET

API highlights:
- POST /auth/register {username,password,displayName}
- POST /auth/login {username,password} -> {token}
- GET /posts
- POST /posts (multipart/form-data) with 'image' and 'text' (Auth)
- POST /posts/:id/meow (Auth)
- POST /posts/:id/comments (Auth)
- GET /communities
- POST /communities (Auth)
- POST /communities/:id/join (Auth)
- POST /friends/request {toUsername} (Auth)
