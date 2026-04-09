const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");

const app = express();
app.use(cors());

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*"
  }
});

io.on("connection", (socket) => {
  console.log("Подключился:", socket.id);

  socket.on("message", (msg) => {
    io.emit("message", {
      text: msg,
      sender: socket.id
    });
  });

  socket.on("disconnect", () => {
    console.log("Отключился:", socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log("Сервер работает на порту", PORT);
});