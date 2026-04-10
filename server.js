const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const JWT_SECRET = "SUPER_SECRET_KEY_CHANGE_ME";

const app = express();
app.use(cors());
app.use(express.json());

// ====== In-memory users (для демо) ======
/**
 * users: [{
 *   id: string,
 *   username: string,
 *   email: string,
 *   passwordHash: string
 * }]
 */
const users = [];
let nextUserId = 1;

function createToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// ====== Auth endpoints ======

// Регистрация
app.post("/api/auth/register", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: "username, email, password are required" });
  }

  const exists = users.find(
    (u) => u.email === email || u.username === username
  );
  if (exists) {
    return res.status(400).json({ error: "User with this email/username already exists" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: String(nextUserId++),
    username,
    email,
    passwordHash,
  };
  users.push(user);

  const token = createToken(user);
  res.json({
    token,
    user: { id: user.id, username: user.username, email: user.email },
  });
});

// Логин
app.post("/api/auth/login", async (req, res) => {
  const { emailOrUsername, password } = req.body;
  if (!emailOrUsername || !password) {
    return res.status(400).json({ error: "emailOrUsername, password are required" });
  }

  const user = users.find(
    (u) => u.email === emailOrUsername || u.username === emailOrUsername
  );
  if (!user) {
    return res.status(400).json({ error: "User not found" });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(400).json({ error: "Invalid password" });
  }

  const token = createToken(user);
  res.json({
    token,
    user: { id: user.id, username: user.username, email: user.email },
  });
});

// Список пользователей (для выбора собеседника)
app.get("/api/users", (req, res) => {
  const minimized = users.map((u) => ({
    id: u.id,
    username: u.username,
    email: u.email,
  }));
  res.json(minimized);
});

// ====== Socket.IO + JWT auth ======
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

// middleware: авторизация по токену при подключении [web:105][web:113]
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) {
    return next(new Error("No token"));
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = payload; // { id, username, email }
    next();
  } catch (e) {
    next(new Error("Invalid token"));
  }
});

// генерация roomId для приватного чата между двумя юзерами
function getRoomId(userId1, userId2) {
  const sorted = [userId1, userId2].sort();
  return `room:${sorted[0]}:${sorted[1]}`;
}

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id, socket.user);

  // Клиент просит присоединиться к приватной комнате с другим пользователем
  socket.on("join", ({ peerId }) => {
    if (!peerId || !socket.user) return;
    const roomId = getRoomId(socket.user.id, peerId);
    socket.join(roomId);
    socket.emit("joined", { roomId });
  });

  // Отправка сообщения в конкретную комнату
  socket.on("message", ({ roomId, text }) => {
    if (!roomId || !text || !socket.user) return;
    io.to(roomId).emit("message", {
      roomId,
      text,
      from: {
        id: socket.user.id,
        username: socket.user.username,
      },
      createdAt: new Date().toISOString(),
    });
  });

  socket.on("disconnect", () => {
    console.log("Socket disconnected:", socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log("Server listening on", PORT);
});