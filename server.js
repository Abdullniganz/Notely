require("dotenv").config();
const express = require("express");
const http = require("http");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const { Server } = require("socket.io");
const path = require("path");
const fs = require("fs");

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-change-this-secret";
const CORS_ORIGIN = process.env.CORS_ORIGIN || `http://localhost:${PORT}`;

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "notely.sqlite"));
db.pragma("foreign_keys = ON");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  avatar TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS chat_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(sender_id, receiver_id)
);
CREATE TABLE IF NOT EXISTS friendships (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_a INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_b INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_a, user_b)
);
CREATE TABLE IF NOT EXISTS blocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(blocker_id, blocked_id)
);
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  favorite INTEGER NOT NULL DEFAULT 0,
  deleted INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS note_shares (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  note_id INTEGER NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
  sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(note_id, receiver_id)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, receiver_id, id);
CREATE INDEX IF NOT EXISTS idx_requests_receiver ON chat_requests(receiver_id, status);
CREATE INDEX IF NOT EXISTS idx_notes_owner ON notes(owner_id, deleted);
`);

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: CORS_ORIGIN, methods: ["GET","POST"] }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: CORS_ORIGIN === "*" ? true : CORS_ORIGIN }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const clean = (v, max=10000) => String(v ?? "").trim().slice(0,max);
const tokenFor = user => jwt.sign({ id:user.id }, JWT_SECRET, { expiresIn:"7d" });

function userPublic(id) {
  return db.prepare("SELECT id, username, email, display_name, avatar, created_at FROM users WHERE id=?").get(id);
}
function auth(req,res,next) {
  try {
    const h = req.headers.authorization || "";
    if (!h.startsWith("Bearer ")) throw new Error();
    const decoded = jwt.verify(h.slice(7), JWT_SECRET);
    const user = userPublic(decoded.id);
    if (!user) throw new Error();
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error:"Please sign in again." });
  }
}
function pair(a,b){ return a < b ? [a,b] : [b,a]; }
function areFriends(a,b) {
  const [x,y] = pair(a,b);
  return !!db.prepare("SELECT 1 FROM friendships WHERE user_a=? AND user_b=?").get(x,y);
}
function isBlocked(a,b) {
  return !!db.prepare("SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?").get(a,b)
      || !!db.prepare("SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?").get(b,a);
}
function emitUser(id,event,payload){ io.to(`user:${id}`).emit(event,payload); }

app.post("/api/auth/register", async (req,res) => {
  try {
    const username = clean(req.body.username,32).replace(/\s+/g,"").toLowerCase();
    const email = clean(req.body.email,120).toLowerCase();
    const displayName = clean(req.body.displayName || username,60);
    const password = String(req.body.password || "");
    if (!/^[a-z0-9_]{3,32}$/.test(username)) return res.status(400).json({error:"Username must be 3-32 characters: letters, numbers or underscores."});
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:"Enter a valid email."});
    if (password.length < 8) return res.status(400).json({error:"Password must be at least 8 characters."});
    if (db.prepare("SELECT 1 FROM users WHERE username=? OR email=?").get(username,email)) return res.status(409).json({error:"Username or email is already registered."});
    const hash = await bcrypt.hash(password,12);
    const info = db.prepare("INSERT INTO users(username,email,password_hash,display_name) VALUES(?,?,?,?)").run(username,email,hash,displayName);
    const user = userPublic(info.lastInsertRowid);
    res.status(201).json({ token:tokenFor(user), user });
  } catch(e){ res.status(500).json({error:"Could not create account."}); }
});
app.post("/api/auth/login", async (req,res) => {
  const login = clean(req.body.login,120).toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE username=? OR email=?").get(login,login);
  if (!user || !(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({error:"Invalid username/email or password."});
  const pub = userPublic(user.id);
  res.json({token:tokenFor(pub), user:pub});
});
app.get("/api/me", auth, (req,res)=>res.json({user:req.user}));

app.get("/api/users", auth, (req,res)=>{
  const q = clean(req.query.search,60);
  if (!q) return res.json({users:[]});
  const like = `%${q}%`;
  const users = db.prepare(`
    SELECT id,username,display_name,avatar FROM users
    WHERE id != ? AND (username LIKE ? OR display_name LIKE ?)
    ORDER BY display_name LIMIT 30
  `).all(req.user.id,like,like).map(u=>({
    ...u,
    blocked:isBlocked(req.user.id,u.id),
    friends:areFriends(req.user.id,u.id),
    pendingSent:!!db.prepare("SELECT 1 FROM chat_requests WHERE sender_id=? AND receiver_id=? AND status='pending'").get(req.user.id,u.id),
    pendingReceived:!!db.prepare("SELECT 1 FROM chat_requests WHERE sender_id=? AND receiver_id=? AND status='pending'").get(u.id,req.user.id)
  }));
  res.json({users});
});

app.post("/api/requests", auth, (req,res)=>{
  const receiverId = Number(req.body.receiverId);
  if (!receiverId || receiverId===req.user.id) return res.status(400).json({error:"Choose another person."});
  if (!userPublic(receiverId)) return res.status(404).json({error:"User not found."});
  if (isBlocked(req.user.id,receiverId)) return res.status(403).json({error:"You cannot request this person."});
  if (areFriends(req.user.id,receiverId)) return res.status(400).json({error:"You are already connected."});
  const existing = db.prepare("SELECT * FROM chat_requests WHERE sender_id=? AND receiver_id=?").get(req.user.id,receiverId);
  if (existing && existing.status==="pending") return res.status(400).json({error:"Request already sent."});
  if (existing) db.prepare("UPDATE chat_requests SET status='pending', created_at=CURRENT_TIMESTAMP WHERE id=?").run(existing.id);
  else db.prepare("INSERT INTO chat_requests(sender_id,receiver_id) VALUES(?,?)").run(req.user.id,receiverId);
  emitUser(receiverId,"chat:request",{from:req.user});
  res.json({ok:true});
});
app.get("/api/requests", auth, (req,res)=>{
  const incoming = db.prepare(`
    SELECT r.id,r.created_at,u.id user_id,u.username,u.display_name,u.avatar
    FROM chat_requests r JOIN users u ON u.id=r.sender_id
    WHERE r.receiver_id=? AND r.status='pending' ORDER BY r.id DESC
  `).all(req.user.id);
  const outgoing = db.prepare(`
    SELECT r.id,r.created_at,u.id user_id,u.username,u.display_name,u.avatar
    FROM chat_requests r JOIN users u ON u.id=r.receiver_id
    WHERE r.sender_id=? AND r.status='pending' ORDER BY r.id DESC
  `).all(req.user.id);
  res.json({incoming,outgoing});
});
app.post("/api/requests/:id/accept", auth, (req,res)=>{
  const id=Number(req.params.id);
  const r=db.prepare("SELECT * FROM chat_requests WHERE id=? AND receiver_id=? AND status='pending'").get(id,req.user.id);
  if(!r) return res.status(404).json({error:"Request not found."});
  const tx=db.transaction(()=>{
    db.prepare("UPDATE chat_requests SET status='accepted' WHERE id=?").run(id);
    const [a,b]=pair(r.sender_id,r.receiver_id);
    db.prepare("INSERT OR IGNORE INTO friendships(user_a,user_b) VALUES(?,?)").run(a,b);
  });
  tx();
  emitUser(r.sender_id,"chat:accepted",{user:req.user});
  res.json({ok:true});
});
app.post("/api/requests/:id/decline", auth, (req,res)=>{
  const r=db.prepare("SELECT * FROM chat_requests WHERE id=? AND receiver_id=? AND status='pending'").get(Number(req.params.id),req.user.id);
  if(!r) return res.status(404).json({error:"Request not found."});
  db.prepare("UPDATE chat_requests SET status='declined' WHERE id=?").run(r.id);
  emitUser(r.sender_id,"chat:declined",{user:req.user});
  res.json({ok:true});
});

app.get("/api/friends", auth, (req,res)=>{
  const rows=db.prepare(`
    SELECT u.id,u.username,u.display_name,u.avatar FROM friendships f
    JOIN users u ON u.id=CASE WHEN f.user_a=? THEN f.user_b ELSE f.user_a END
    WHERE f.user_a=? OR f.user_b=? ORDER BY u.display_name
  `).all(req.user.id,req.user.id,req.user.id);
  res.json({friends:rows});
});

app.post("/api/blocks/:userId", auth, (req,res)=>{
  const id=Number(req.params.userId);
  if (!userPublic(id) || id===req.user.id) return res.status(400).json({error:"Invalid person."});
  const tx=db.transaction(()=>{
    db.prepare("INSERT OR IGNORE INTO blocks(blocker_id,blocked_id) VALUES(?,?)").run(req.user.id,id);
    const [a,b]=pair(req.user.id,id);
    db.prepare("DELETE FROM friendships WHERE user_a=? AND user_b=?").run(a,b);
  });
  tx();
  emitUser(id,"blocked",{by:req.user.id});
  res.json({ok:true});
});
app.delete("/api/blocks/:userId", auth, (req,res)=>{
  db.prepare("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?").run(req.user.id,Number(req.params.userId));
  res.json({ok:true});
});
app.get("/api/blocks", auth, (req,res)=>{
  res.json({blocked:db.prepare(`
    SELECT u.id,u.username,u.display_name,u.avatar FROM blocks b JOIN users u ON u.id=b.blocked_id WHERE b.blocker_id=? ORDER BY u.display_name
  `).all(req.user.id)});
});

app.get("/api/notes", auth, (req,res)=>{
  const mode=clean(req.query.mode,20)||"active";
  if(mode==="shared") {
    return res.json({notes:db.prepare(`
      SELECT n.id,n.title,n.body,n.favorite,n.created_at,n.updated_at,u.display_name sender_name,u.username sender_username
      FROM note_shares s JOIN notes n ON n.id=s.note_id JOIN users u ON u.id=s.sender_id
      WHERE s.receiver_id=? ORDER BY s.id DESC
    `).all(req.user.id)});
  }
  const deleted=mode==="trash"?1:0;
  res.json({notes:db.prepare("SELECT id,title,body,favorite,created_at,updated_at FROM notes WHERE owner_id=? AND deleted=? ORDER BY favorite DESC, updated_at DESC").all(req.user.id,deleted)});
});
app.post("/api/notes", auth, (req,res)=>{
  const title=clean(req.body.title,120)||"Untitled note";
  const body=clean(req.body.body,20000);
  const info=db.prepare("INSERT INTO notes(owner_id,title,body) VALUES(?,?,?)").run(req.user.id,title,body);
  res.status(201).json({note:db.prepare("SELECT * FROM notes WHERE id=?").get(info.lastInsertRowid)});
});
app.put("/api/notes/:id", auth, (req,res)=>{
  const id=Number(req.params.id), n=db.prepare("SELECT * FROM notes WHERE id=? AND owner_id=?").get(id,req.user.id);
  if(!n) return res.status(404).json({error:"Note not found."});
  db.prepare("UPDATE notes SET title=?,body=?,favorite=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(clean(req.body.title,120)||"Untitled note",clean(req.body.body,20000),req.body.favorite?1:0,id);
  res.json({note:db.prepare("SELECT * FROM notes WHERE id=?").get(id)});
});
app.delete("/api/notes/:id", auth, (req,res)=>{
  const n=db.prepare("SELECT * FROM notes WHERE id=? AND owner_id=?").get(Number(req.params.id),req.user.id);
  if(!n) return res.status(404).json({error:"Note not found."});
  db.prepare("UPDATE notes SET deleted=1,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(n.id);
  res.json({ok:true});
});
app.post("/api/notes/:id/restore", auth, (req,res)=>{
  db.prepare("UPDATE notes SET deleted=0,updated_at=CURRENT_TIMESTAMP WHERE id=? AND owner_id=?").run(Number(req.params.id),req.user.id);
  res.json({ok:true});
});
app.post("/api/notes/:id/share", auth, (req,res)=>{
  const id=Number(req.params.id), receiverId=Number(req.body.receiverId);
  const n=db.prepare("SELECT * FROM notes WHERE id=? AND owner_id=? AND deleted=0").get(id,req.user.id);
  if(!n || !areFriends(req.user.id,receiverId) || isBlocked(req.user.id,receiverId)) return res.status(403).json({error:"You can only share active notes with accepted connections."});
  db.prepare("INSERT OR IGNORE INTO note_shares(note_id,sender_id,receiver_id) VALUES(?,?,?)").run(id,req.user.id,receiverId);
  emitUser(receiverId,"note:shared",{from:req.user,title:n.title});
  res.json({ok:true});
});

app.get("/api/messages/:friendId", auth, (req,res)=>{
  const friendId=Number(req.params.friendId);
  if(!areFriends(req.user.id,friendId) || isBlocked(req.user.id,friendId)) return res.status(403).json({error:"You are not connected to this person."});
  res.json({messages:db.prepare(`
    SELECT id,sender_id,receiver_id,body,created_at FROM messages
    WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
    ORDER BY id ASC LIMIT 500
  `).all(req.user.id,friendId,friendId,req.user.id)});
});
app.post("/api/messages", auth, (req,res)=>{
  const receiverId=Number(req.body.receiverId), body=clean(req.body.body,4000);
  if(!body) return res.status(400).json({error:"Message is empty."});
  if(!areFriends(req.user.id,receiverId) || isBlocked(req.user.id,receiverId)) return res.status(403).json({error:"You must be connected before chatting."});
  const info=db.prepare("INSERT INTO messages(sender_id,receiver_id,body) VALUES(?,?,?)").run(req.user.id,receiverId,body);
  const msg=db.prepare("SELECT * FROM messages WHERE id=?").get(info.lastInsertRowid);
  emitUser(receiverId,"message:new",msg);
  res.status(201).json({message:msg});
});

const online=new Map();
io.use((socket,next)=>{
  try {
    const token=socket.handshake.auth?.token;
    socket.user=jwt.verify(token,JWT_SECRET);
    next();
  } catch { next(new Error("Unauthorized")); }
});
io.on("connection",socket=>{
  const uid=socket.user.id;
  socket.join(`user:${uid}`);
  online.set(uid,(online.get(uid)||0)+1);
  emitUser(uid,"presence",{online:true});
  socket.on("typing",({to,isTyping})=>{ if(areFriends(uid,Number(to)) && !isBlocked(uid,Number(to))) emitUser(Number(to),"typing",{from:uid,isTyping:!!isTyping}); });
  socket.on("call:offer",({to,offer,kind})=>{ const t=Number(to); if(areFriends(uid,t)&&!isBlocked(uid,t)) emitUser(t,"call:offer",{from:uid,offer,kind}); });
  socket.on("call:answer",({to,answer})=>{ const t=Number(to); if(areFriends(uid,t)&&!isBlocked(uid,t)) emitUser(t,"call:answer",{from:uid,answer}); });
  socket.on("call:ice",({to,candidate})=>{ const t=Number(to); if(areFriends(uid,t)&&!isBlocked(uid,t)) emitUser(t,"call:ice",{from:uid,candidate}); });
  socket.on("call:reject",({to})=>emitUser(Number(to),"call:rejected",{from:uid}));
  socket.on("call:end",({to})=>emitUser(Number(to),"call:end",{from:uid}));
  socket.on("disconnect",()=>{ const count=Math.max(0,(online.get(uid)||1)-1); if(count) online.set(uid,count); else {online.delete(uid); emitUser(uid,"presence",{online:false});} });
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
server.listen(PORT,()=>console.log(`Notely running on http://localhost:${PORT}`));
