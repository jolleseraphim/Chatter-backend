const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST", "PATCH", "DELETE"] }
});

app.use(cors());
app.use(express.json({ limit: "5mb" }));

// CONFIGURATION
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!JWT_SECRET || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.error("Missing environment variables.");
  process.exit(1);
}

// DATABASE
const db = new Database("chatter.db");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  blocked INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL,
  receiver_id INTEGER NOT NULL,
  text TEXT,
  image TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS support_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  message TEXT NOT NULL,
  reply TEXT,
  status TEXT DEFAULT 'open',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  replied_at TEXT
);

CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_id INTEGER NOT NULL,
  reported_user_id INTEGER NOT NULL,
  reason TEXT NOT NULL,
  details TEXT,
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

try {
  db.exec("ALTER TABLE users ADD COLUMN blocked INTEGER DEFAULT 0");
} catch (e) {}

const onlineUsers = new Set();

// TOKEN FUNCTIONS
function createToken(data) {
  return jwt.sign(data, JWT_SECRET, { expiresIn: "7d" });
}

function requireAdmin(req, res, next) {
  if (!req.auth || req.auth.role !== "admin") {
    return res.status(403).json({ error: "Admin access required." });
  }
  next();
}

// AUTHENTICATION
function authenticate(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Login required." });
  }

  try {
    req.auth = jwt.verify(header.substring(7), JWT_SECRET);

    if (req.auth.role === "admin") return next();

    const user = db.prepare(
      "SELECT id, blocked FROM users WHERE id = ?"
    ).get(req.auth.id);

    if (!user || user.blocked) {
      return res.status(403).json({ error: "Account unavailable." });
    }

    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid login." });
  }
}

// HEALTH CHECK
app.get("/", (req, res) => {
  res.json({
    app: "Chatter",
    status: "online",
    message: "Chatter backend is running!"
  });
});

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Complete all fields." });
    }

    const cleanName = String(name).trim();
    const cleanEmail = String(email).trim().toLowerCase();

    if (cleanName.length < 2 || cleanName.length > 50) {
      return res.status(400).json({ error: "Invalid name." });
    }

    if (String(password).length < 8) {
      return res.status(400).json({
        error: "Password must contain at least 8 characters."
      });
    }

    const existing = db.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).get(cleanEmail);

    if (existing) {
      return res.status(409).json({ error: "Email already registered." });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (name, email, password_hash)
      VALUES (?, ?, ?)
    `).run(cleanName, cleanEmail, hash);

    res.status(201).json({
      message: "Account created.",
      userId: result.lastInsertRowid
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Registration failed." });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = db.prepare(
      "SELECT * FROM users WHERE email = ?"
    ).get(String(email || "").trim().toLowerCase());

    if (!user || !(await bcrypt.compare(password || "", user.password_hash))) {
      return res.status(401).json({ error: "Incorrect email or password." });
    }

    if (user.blocked) {
      return res.status(403).json({ error: "Your account is blocked." });
    }

    res.json({
      message: "Login successful.",
      token: createToken({ id: user.id, role: "user" }),
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Login failed." });
  }
});

// VIEW USERS
app.get("/api/users", authenticate, (req, res) => {
  const users = db.prepare(`
    SELECT id, name, email
    FROM users
    WHERE id != ?
    ORDER BY name
  `).all(req.auth.id);

  res.json(users);
});

// SEND MESSAGE
app.post("/api/messages", authenticate, (req, res) => {
  try {
    const { receiverId, text, image } = req.body;
    const recipient = Number(receiverId);

    if (!Number.isInteger(recipient) || recipient <= 0) {
      return res.status(400).json({ error: "Invalid recipient." });
    }

    if ((!text || !String(text).trim()) && !image) {
      return res.status(400).json({ error: "Message is empty." });
    }

    if (text && String(text).length > 5000) {
      return res.status(400).json({ error: "Message too long." });
    }

    if (image && (
      typeof image !== "string" ||
      !/^data:image\/(jpeg|png|webp|gif);base64,/.test(image)
    )) {
      return res.status(400).json({ error: "Invalid image." });
    }

    const receiver = db.prepare(
      "SELECT id, blocked FROM users WHERE id = ?"
    ).get(recipient);

    if (!receiver || receiver.blocked) {
      return res.status(404).json({ error: "Recipient not found." });
    }

    const result = db.prepare(`
      INSERT INTO messages (sender_id, receiver_id, text, image)
      VALUES (?, ?, ?, ?)
    `).run(
      req.auth.id,
      recipient,
      text ? String(text).trim() : null,
      image || null
    );

    const message = db.prepare(
      "SELECT * FROM messages WHERE id = ?"
    ).get(result.lastInsertRowid);

    io.to(`user:${recipient}`).emit("new_message", message);
    io.to(`user:${req.auth.id}`).emit("new_message", message);

    res.status(201).json(message);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not send message." });
  }
});

// GET MESSAGES
app.get("/api/messages/:userId", authenticate, (req, res) => {
  const otherId = Number(req.params.userId);

  if (!Number.isInteger(otherId) || otherId <= 0) {
    return res.status(400).json({ error: "Invalid user ID." });
  }

  const messages = db.prepare(`
    SELECT * FROM messages
    WHERE
      (sender_id = ? AND receiver_id = ?)
      OR
      (sender_id = ? AND receiver_id = ?)
    ORDER BY id ASC
  `).all(req.auth.id, otherId, otherId, req.auth.id);

  res.json(messages);
});

// SEND SUPPORT MESSAGE
app.post("/api/support", authenticate, (req, res) => {
  try {
    const { message } = req.body;

    if (!message || !String(message).trim()) {
      return res.status(400).json({ error: "Write a message." });
    }

    if (String(message).length > 5000) {
      return res.status(400).json({ error: "Message too long." });
    }

    const user = db.prepare(
      "SELECT name, email FROM users WHERE id = ?"
    ).get(req.auth.id);

    const result = db.prepare(`
      INSERT INTO support_messages (user_id, name, email, message)
      VALUES (?, ?, ?, ?)
    `).run(req.auth.id, user.name, user.email, String(message).trim());

    const support = db.prepare(
      "SELECT * FROM support_messages WHERE id = ?"
    ).get(result.lastInsertRowid);

    io.to("admins").emit("new_support_message", support);

    res.status(201).json({
      message: "Sent to Chatter Support.",
      supportId: result.lastInsertRowid
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Support message failed." });
  }
});

// VIEW MY SUPPORT MESSAGES
app.get("/api/support", authenticate, (req, res) => {
  const messages = db.prepare(`
    SELECT id, message, reply, status, created_at, replied_at
    FROM support_messages
    WHERE user_id = ?
    ORDER BY id DESC
  `).all(req.auth.id);

  res.json(messages);
});

// ADMIN LOGIN
app.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body;

  if (
    String(email || "").trim().toLowerCase() !== ADMIN_EMAIL.trim().toLowerCase() ||
    password !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({ error: "Incorrect admin credentials." });
  }

  res.json({
    message: "Admin login successful.",
    token: createToken({ id: 0, role: "admin" })
  });
});

// ADMIN VIEW USERS
app.get("/api/admin/users", authenticate, requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT id, name, email, blocked, created_at
    FROM users
    ORDER BY id DESC
  `).all();

  res.json(users);
});

// ADMIN BLOCK USER
app.post("/api/admin/users/:id/block", authenticate, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { blocked } = req.body;

  if (!Number.isInteger(id) || typeof blocked !== "boolean") {
    return res.status(400).json({ error: "Invalid request." });
  }

  const result = db.prepare(
    "UPDATE users SET blocked = ? WHERE id = ?"
  ).run(blocked ? 1 : 0, id);

  if (!result.changes) {
    return res.status(404).json({ error: "User not found." });
  }

  res.json({ message: blocked ? "User blocked." : "User unblocked." });
});

// ADMIN DELETE USER
app.delete("/api/admin/users/:id", authenticate, requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid user ID." });
  }

  const remove = db.transaction(() => {
    db.prepare("DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?").run(id, id);
    db.prepare("DELETE FROM support_messages WHERE user_id = ?").run(id);
    db.prepare("DELETE FROM reports WHERE reporter_id = ? OR reported_user_id = ?").run(id, id);
    db.prepare("DELETE FROM users WHERE id = ?").run(id);
  });

  remove();
  onlineUsers.delete(id);

  res.json({ message: "User deleted." });
});

// ADMIN ONLINE USERS
app.get("/api/admin/online", authenticate, requireAdmin, (req, res) => {
  res.json({
    count: onlineUsers.size,
    users: Array.from(onlineUsers)
  });
});

// ADMIN VIEW SUPPORT
app.get("/api/admin/support", authenticate, requireAdmin, (req, res) => {
  const messages = db.prepare(
    "SELECT * FROM support_messages ORDER BY id DESC"
  ).all();

  res.json(messages);
});

// ADMIN REPLY SUPPORT
app.post("/api/admin/support/:id/reply", authenticate, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { reply } = req.body;

  if (!reply || !String(reply).trim()) {
    return res.status(400).json({ error: "Write a reply." });
  }

  const result = db.prepare(`
    UPDATE support_messages
    SET reply = ?, status = 'answered', replied_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(String(reply).trim(), id);

  if (!result.changes) {
    return res.status(404).json({ error: "Support message not found." });
  }

  const updated = db.prepare(
    "SELECT * FROM support_messages WHERE id = ?"
  ).get(id);

  io.to(`user:${updated.user_id}`).emit("support_reply", updated);

  res.json({
    message: "Reply sent.",
    support: updated
  });
});

// USER REPORTS
app.post("/api/reports", authenticate, (req, res) => {
  try {
    const { reportedUserId, reason, details } = req.body;
    const targetId = Number(reportedUserId);

    const reasons = [
      "Harassment",
      "Scamming",
      "Abusive messages",
      "Inappropriate content",
      "Spam",
      "Other"
    ];

    if (!Number.isInteger(targetId) || !reasons.includes(reason)) {
      return res.status(400).json({ error: "Invalid report." });
    }

    if (targetId === req.auth.id) {
      return res.status(400).json({ error: "Cannot report yourself." });
    }

    if (details && String(details).length > 2000) {
      return res.status(400).json({ error: "Details too long." });
    }

    const target = db.prepare(
      "SELECT id FROM users WHERE id = ?"
    ).get(targetId);

    if (!target) {
      return res.status(404).json({ error: "User not found." });
    }

    const result = db.prepare(`
      INSERT INTO reports (reporter_id, reported_user_id, reason, details)
      VALUES (?, ?, ?, ?)
    `).run(
      req.auth.id,
      targetId,
      reason,
      details ? String(details).trim() : null
    );

    const report = db.prepare(
      "SELECT * FROM reports WHERE id = ?"
    ).get(result.lastInsertRowid);

    io.to("admins").emit("new_report", report);

    res.status(201).json({
      message: "Report submitted.",
      reportId: result.lastInsertRowid
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not submit report." });
  }
});

// ADMIN VIEW REPORTS
app.get("/api/admin/reports", authenticate, requireAdmin, (req, res) => {
  const reports = db.prepare(`
    SELECT
      reports.*,
      reporter.name AS reporter_name,
      reported.name AS reported_name
    FROM reports
    LEFT JOIN users reporter ON reports.reporter_id = reporter.id
    LEFT JOIN users reported ON reports.reported_user_id = reported.id
    ORDER BY reports.id DESC
  `).all();

  res.json(reports);
});

// ADMIN UPDATE REPORT
app.patch("/api/admin/reports/:id", authenticate, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { status } = req.body;

  const statuses = ["pending", "investigating", "resolved", "dismissed"];

  if (!statuses.includes(status)) {
    return res.status(400).json({ error: "Invalid status." });
  }

  const result = db.prepare(
    "UPDATE reports SET status = ? WHERE id = ?"
  ).run(status, id);

  if (!result.changes) {
    return res.status(404).json({ error: "Report not found." });
  }

  res.json({ message: "Report updated." });
});

// SOCKET AUTHENTICATION
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token) return next(new Error("Login required."));

    const user = jwt.verify(token, JWT_SECRET);

    if (user.role !== "admin") {
      const account = db.prepare(
        "SELECT blocked FROM users WHERE id = ?"
      ).get(user.id);

      if (!account || account.blocked) {
        return next(new Error("Account unavailable."));
      }
    }

    socket.user = user;
    next();
  } catch (e) {
    next(new Error("Invalid login."));
  }
});

// SOCKET CONNECTION
io.on("connection", socket => {
  const user = socket.user;

  if (user.role === "admin") {
    socket.join("admins");
  } else {
    socket.join(`user:${user.id}`);
    onlineUsers.add(user.id);

    io.to("admins").emit("online_update", {
      count: onlineUsers.size
    });
  }

  socket.on("disconnect", () => {
    if (user.role !== "admin") {
      const stillConnected = [...io.sockets.sockets.values()].some(s =>
        s.id !== socket.id &&
        s.user &&
        s.user.role === "user" &&
        s.user.id === user.id
      );

      if (!stillConnected) onlineUsers.delete(user.id);

      io.to("admins").emit("online_update", {
        count: onlineUsers.size
      });
    }
  });
});

// START SERVER
server.listen(PORT, () => {
  console.log(`Chatter server running on port ${PORT}`);
});
