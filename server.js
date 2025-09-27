
const express = require('express');
const Database = require('better-sqlite3');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const SECRET = process.env.JWT_SECRET || 'change-this-secret';
const DB_FILE = process.env.DB_FILE || './db.sqlite';
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';

if(!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');

// Create tables if not exist
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  displayName TEXT,
  avatar TEXT,
  about TEXT,
  meowPoints INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS friends (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userA INTEGER,
  userB INTEGER,
  status TEXT,
  FOREIGN KEY(userA) REFERENCES users(id),
  FOREIGN KEY(userB) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author INTEGER,
  text TEXT,
  image TEXT,
  time INTEGER,
  likes INTEGER DEFAULT 0,
  meows INTEGER DEFAULT 0,
  FOREIGN KEY(author) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  postId INTEGER,
  author INTEGER,
  text TEXT,
  time INTEGER,
  FOREIGN KEY(postId) REFERENCES posts(id),
  FOREIGN KEY(author) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS communities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  description TEXT,
  owner INTEGER,
  FOREIGN KEY(owner) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS community_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  communityId INTEGER,
  userId INTEGER,
  FOREIGN KEY(communityId) REFERENCES communities(id),
  FOREIGN KEY(userId) REFERENCES users(id)
);
`);

// helper functions
function authMiddleware(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).send({error:'no token'});
  const token = h.split(' ')[1];
  try{
    const data = jwt.verify(token, SECRET);
    req.user = data;
    next();
  }catch(e){
    res.status(401).send({error:'invalid token'});
  }
}

const app = express();
app.use(cors());
app.use(bodyParser.json({limit:'10mb'}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer for handling multipart (file upload)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, Date.now().toString() + '-' + Math.random().toString(36).slice(2,8) + ext);
  }
});
const upload = multer({ storage });

// Auth: register (hash password)
app.post('/auth/register', async (req,res)=>{
  try{
    const {username, password, displayName} = req.body;
    if(!username || !password) return res.status(400).send({error:'username and password required'});
    const hashed = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (username,password,displayName) VALUES (?,?,?)');
    const info = stmt.run(username, hashed, displayName || username);
    const user = db.prepare('SELECT id,username,displayName,about,avatar,meowPoints FROM users WHERE id = ?').get(info.lastInsertRowid);
    res.send({user});
  }catch(e){
    res.status(400).send({error: 'user exists or invalid', detail: e.message});
  }
});

// Auth: login (returns token)
app.post('/auth/login', async (req,res)=>{
  try{
    const {username, password} = req.body;
    if(!username || !password) return res.status(400).send({error:'username and password required'});
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if(!user) return res.status(404).send({error:'user not found'});
    const ok = await bcrypt.compare(password, user.password);
    if(!ok) return res.status(401).send({error:'invalid credentials'});
    const token = jwt.sign({id:user.id,username:user.username}, SECRET, {expiresIn:'7d'});
    res.send({token, user:{id:user.id,username:user.username,displayName:user.displayName,about:user.about,avatar:user.avatar,meowPoints:user.meowPoints}});
  }catch(e){
    res.status(500).send({error:'server error'});
  }
});

// Users list (public)
app.get('/users', (req,res)=>{
  const rows = db.prepare('SELECT id,username,displayName,about,avatar,meowPoints FROM users').all();
  res.send(rows);
});

// Update profile (auth) - can upload avatar via multipart
app.post('/users/me', authMiddleware, upload.single('avatar'), (req,res)=>{
  const {displayName, about} = req.body;
  const avatarFile = req.file;
  const userId = req.user.id;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if(!user) return res.status(404).send({error:'user not found'});
  let avatarPath = user.avatar;
  if(avatarFile){
    avatarPath = '/uploads/' + avatarFile.filename;
  }
  db.prepare('UPDATE users SET displayName = ?, about = ?, avatar = ? WHERE id = ?').run(displayName || user.displayName, about || user.about, avatarPath, userId);
  const updated = db.prepare('SELECT id,username,displayName,about,avatar,meowPoints FROM users WHERE id = ?').get(userId);
  res.send({user:updated});
});

// Create post (auth) - supports multipart upload for image
app.post('/posts', authMiddleware, upload.single('image'), (req,res)=>{
  const authorId = req.user.id;
  const text = req.body.text || '';
  let imagePath = null;
  if(req.file){
    imagePath = '/uploads/' + req.file.filename;
  } else if(req.body.image){ // accept base64 image too
    // save base64 data to file
    const matches = req.body.image.match(/^data:(.+);base64,(.+)$/);
    if(matches){
      const buf = Buffer.from(matches[2], 'base64');
      const fname = Date.now().toString() + '-' + Math.random().toString(36).slice(2,8) + '.png';
      const full = path.join(UPLOAD_DIR, fname);
      fs.writeFileSync(full, buf);
      imagePath = '/uploads/' + fname;
    }
  }
  const time = Date.now();
  const info = db.prepare('INSERT INTO posts (author,text,image,time,likes,meows) VALUES (?,?,?,?,0,0)').run(authorId, text, imagePath, time);
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(info.lastInsertRowid);
  res.send({post});
});

// Get posts (public)
app.get('/posts', (req,res)=>{
  const posts = db.prepare('SELECT p.*, u.username, u.displayName, u.avatar FROM posts p JOIN users u ON p.author = u.id ORDER BY p.time DESC').all();
  res.send(posts);
});

// Like / Meow
app.post('/posts/:id/like', authMiddleware, (req,res)=>{
  const id = req.params.id;
  db.prepare('UPDATE posts SET likes = likes + 1 WHERE id = ?').run(id);
  res.send({ok:true});
});
app.post('/posts/:id/meow', authMiddleware, (req,res)=>{
  const id = req.params.id;
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(id);
  if(!post) return res.status(404).send({error:'post not found'});
  db.prepare('UPDATE posts SET meows = meows + 1 WHERE id = ?').run(id);
  // give meow point to author
  db.prepare('UPDATE users SET meowPoints = meowPoints + 1 WHERE id = ?').run(post.author);
  res.send({ok:true});
});

// Comments
app.post('/posts/:id/comments', authMiddleware, (req,res)=>{
  const postId = req.params.id;
  const {text} = req.body;
  const time = Date.now();
  const info = db.prepare('INSERT INTO comments (postId,author,text,time) VALUES (?,?,?,?)').run(postId, req.user.id, text, time);
  const c = db.prepare('SELECT c.*, u.username, u.displayName FROM comments c JOIN users u ON c.author = u.id WHERE c.id = ?').get(info.lastInsertRowid);
  res.send({comment: c});
});
app.get('/posts/:id/comments', (req,res)=>{
  const postId = req.params.id;
  const rows = db.prepare('SELECT c.*, u.username, u.displayName FROM comments c JOIN users u ON c.author = u.id WHERE c.postId = ? ORDER BY c.time').all(postId);
  res.send(rows);
});

// Communities
app.post('/communities', authMiddleware, (req,res)=>{
  const {name, description} = req.body;
  const owner = req.user.id;
  const info = db.prepare('INSERT INTO communities (name,description,owner) VALUES (?,?,?)').run(name, description, owner);
  const comm = db.prepare('SELECT * FROM communities WHERE id = ?').get(info.lastInsertRowid);
  res.send({community: comm});
});
app.get('/communities', (req,res)=>{
  const rows = db.prepare('SELECT * FROM communities').all();
  res.send(rows);
});
app.post('/communities/:id/join', authMiddleware, (req,res)=>{
  const id = req.params.id; const userId = req.user.id;
  const exists = db.prepare('SELECT * FROM community_members WHERE communityId = ? AND userId = ?').get(id,userId);
  if(!exists) db.prepare('INSERT INTO community_members (communityId,userId) VALUES (?,?)').run(id,userId);
  res.send({ok:true});
});
app.post('/communities/:id/leave', authMiddleware, (req,res)=>{
  const id = req.params.id; const userId = req.user.id;
  db.prepare('DELETE FROM community_members WHERE communityId = ? AND userId = ?').run(id,userId);
  res.send({ok:true});
});

// Friends - simple send/accept flow
app.post('/friends/request', authMiddleware, (req,res)=>{
  const {toUsername} = req.body;
  const to = db.prepare('SELECT * FROM users WHERE username = ?').get(toUsername);
  if(!to) return res.status(404).send({error:'user not found'});
  // check existing
  const existing = db.prepare('SELECT * FROM friends WHERE (userA = ? AND userB = ?) OR (userA = ? AND userB = ?)').get(req.user.id, to.id, to.id, req.user.id);
  if(existing) return res.status(400).send({error:'request exists'});
  db.prepare('INSERT INTO friends (userA,userB,status) VALUES (?,?,?)').run(req.user.id, to.id, 'pending');
  res.send({ok:true});
});
app.post('/friends/:id/accept', authMiddleware, (req,res)=>{
  const fid = req.params.id;
  const f = db.prepare('SELECT * FROM friends WHERE id = ?').get(fid);
  if(!f) return res.status(404).send({error:'friend request not found'});
  if(f.userB !== req.user.id) return res.status(403).send({error:'not allowed'});
  db.prepare('UPDATE friends SET status = ? WHERE id = ?').run('accepted', fid);
  res.send({ok:true});
});
app.get('/friends/requests', authMiddleware, (req,res)=>{
  const rows = db.prepare('SELECT f.id, u.username AS fromUsername, u.displayName FROM friends f JOIN users u ON f.userA = u.id WHERE f.userB = ? AND f.status = ?').all(req.user.id, 'pending');
  res.send(rows);
});

// Serve
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log('Gatorkut API listening on', PORT));
