import express from "express";
import http from "http";
import { Server } from "socket.io";
import cors from "cors";
import { prisma } from "./prisma";
import { comparePassword, createToken, hashPassword } from "./auth";
import cookieParser from "cookie-parser";
import { requireAuth } from "./middleware/auth";
import { authenticateSocket } from "./socketAuth";
import { userConnected, userDisconnected, getOnlineUserIds, onlineUsers } from "./presence";
import type { AuthRequest } from "./middleware/auth";
import path from "path";
import multer from "multer";
import fs from "fs";

const BASE_URL = process.env.BASE_URL || "http://localhost:3001";
const SVELTE_URL = process.env.SVELTE_URL || "http://localhost:5173";
const avatarDir = path.join(__dirname, "../uploads/avatars");
const UPLOADS_BASE_URL = BASE_URL + "/uploads/avatars/";
const AVATAR_UPLOAD_DIR = path.join(__dirname, "../uploads/avatars/");

if (!fs.existsSync(avatarDir)) {
  fs.mkdirSync(avatarDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, avatarDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${req.userId}-${Date.now()}${ext}`);
  },
});

const uploadAvatar = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (_req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      cb(new Error("Only images allowed"));
    } else {
      cb(null, true);
    }
  },
});

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: SVELTE_URL, // SvelteKit dev
    methods: ["GET", "POST"],
  },
});

const PORT = 3001;
server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});

app.use("/uploads", express.static(path.join(__dirname, "../uploads")));
app.use(
  cors({
    origin: SVELTE_URL,
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

app.get("/", (_, res) => {
  res.send("Server is running");
});

app.get("/auth/me", requireAuth, async (req, res) => {
  const userId = (req as any).userId;

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      username: true,
      createdAt: true,
      status: true,
      avatarUrl: true
    },
  });

  if (!user) {
    return res.status(401).send("Unauthorized");
  }

  res.send(user);
});

io.use(authenticateSocket);

io.on("connection", async (socket) => {
  const authSocket = socket as any;
  const userId = authSocket.userId;

  socket.join(userId);
  userConnected(userId, socket.id);

  // 👇 FIX: mark user as ONLINE if they were OFFLINE
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { status: true, avatarUrl: true },
  });

  if (user?.status === "OFFLINE") {

    // notify friends
    const friends = await prisma.friend.findMany({
      where: {
        OR: [{ userAId: userId }, { userBId: userId }],
      },
      select: { userAId: true, userBId: true },
    });

    friends.forEach((f) => {
      const friendId = f.userAId === userId ? f.userBId : f.userAId;

      io.to(friendId).emit("status:update", {
        userId,
        status: user?.status,
      });
    });
  }

  socket.on("disconnect", async () => {
    const userId = authSocket.userId;

    // Check if this was the last socket
    const sockets = onlineUsers.get(userId);
    userDisconnected(userId, socket.id);
    if (sockets && sockets.size > 0) return;

  });

  socket.on("dm:typing", ({ conversationId }) => {
    // broadcast to everyone else in the conversation
    socket.to(conversationId).emit("dm:typing", {
      userId: authSocket.userId,
      conversationId,
    });
  });

});

function deleteAvatarIfExists(avatarUrl: string | null) {
  if (!avatarUrl) return;

  // Only delete avatars uploaded to our server
  if (!avatarUrl.startsWith("/uploads/avatars/")) return;

  const filename = avatarUrl.replace("/uploads/avatars/", "");
  const filePath = path.join(AVATAR_UPLOAD_DIR, filename);
  console.log("Deleting old avatar at path:", filePath);

  if (fs.existsSync(filePath)) {
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error("Failed to delete old avatar:", err);
      }
    });
  }
}

app.post("/auth/login", async (req: AuthRequest, res) => {
  console.log("LOGIN BODY:", req.body);

  const { email, password } = req.body;

  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user) {
    console.log("User not found");
    return res.status(401).send("Invalid credentials");
  }

  const valid = await comparePassword(password, user.password);
  if (!valid) {
    console.log("Invalid password");
    return res.status(401).send("Invalid credentials");
  }

  const token = createToken(user.id);

  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
  });

  console.log("Login success for", user.email);
  res.send({ ok: true });
});

app.post("/auth/register", async (req: AuthRequest, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password) {
    return res.status(400).send("Missing required fields");
  }

  if (password.length < 6) {
    return res.status(400).send("Password must be at least 6 characters");
  }

  const existingEmail = await prisma.user.findUnique({
    where: { email },
  });

  if (existingEmail) {
    return res.status(400).send("Email already in use");
  }

  const existingUsername = await prisma.user.findUnique({
    where: { username },
  });

  if (existingUsername) {
    return res.status(400).send("Username already taken");
  }

  const hashed = await hashPassword(password);

  await prisma.user.create({
    data: {
      email,
      username,
      password: hashed,
    },
  });

  res.send({ ok: true });
});

app.post("/friends/request", requireAuth, async (req: AuthRequest, res) => {
  const fromId = req.userId!;
  const { username } = req.body;

  const toUser = await prisma.user.findUnique({ where: { username } });
  if (!toUser) return res.status(404).send("Username not found");

  if (toUser.id === fromId) {
    return res.status(400).send("Cannot add yourself");
  }

  const existingFriend = await prisma.friend.findFirst({
    where: {
      OR: [
        { userAId: fromId, userBId: toUser.id },
        { userAId: toUser.id, userBId: fromId },
      ],
    },
  });

  if (existingFriend) {
    return res.status(400).send("Already friends");
  }

  // ✅ CREATE and STORE the request
  const request = await prisma.friendRequest.create({
    data: {
      fromId,
      toId: toUser.id,
    },
    include: {
      from: {
        select: { id: true, username: true },
      },
    },
  });

  // 🔔 notify recipient in realtime
  io.to(toUser.id).emit("friend:request", {
    id: request.id,
    from: request.from,
  });

  res.send({ ok: true });
});

app.get("/friends/requests", requireAuth, async (req: AuthRequest, res) => {
  const userId = req.userId!;

  const requests = await prisma.friendRequest.findMany({
    where: { toId: userId },
    include: {
      from: { select: { id: true, username: true } },
    },
  });

  res.send(requests);
});

app.post("/friends/respond", requireAuth, async (req: AuthRequest, res) => {
  const userId = req.userId!;
  const { requestId, accept } = req.body;

  const request = await prisma.friendRequest.findUnique({
    where: { id: requestId },
    include: {
      from: { select: { id: true, username: true } },
      to: { select: { id: true, username: true } },
    },
  });

  if (!request || request.toId !== userId) {
    return res.status(404).send("Request not found");
  }

  if (accept) {
    const friendship = await prisma.friend.create({
      data: {
        userAId: request.fromId,
        userBId: request.toId,
      },
    });

    // 🔔 notify sender (request.fromId)
    io.to(request.fromId).emit("friend:accepted", {
      id: request.to.id,
      username: request.to.username,
    });
  }


  await prisma.friendRequest.delete({
    where: { id: requestId },
  });

  res.send({ ok: true });
});

app.get("/friends", requireAuth, async (req: AuthRequest, res) => {
  const userId = req.userId!;

  const friends = await prisma.friend.findMany({
    where: {
      OR: [{ userAId: userId }, { userBId: userId }],
    },
    select: {
      userAId: true,
      userBId: true,
      userA: {
        select: { id: true, username: true, status: true, avatarUrl: true },
      },
      userB: {
        select: { id: true, username: true, status: true, avatarUrl: true },
      },
    },
  });

  const formatted = friends.map((f) =>
    f.userAId === userId ? f.userB : f.userA
  );

  res.send(formatted);
});

app.post("/friends/delete", requireAuth, async (req: AuthRequest, res) => {
  const userId = req.userId!;
  const { friendId } = req.body;

  const friendship = await prisma.friend.findFirst({
    where: {
      OR: [
        { userAId: userId, userBId: friendId },
        { userAId: friendId, userBId: userId },
      ],
    },
  });

  if (!friendship) {
    return res.status(404).send("Friend not found");
  }

  await prisma.friend.delete({
    where: { id: friendship.id },
  });

  // 🔔 notify the other user
  io.to(friendId).emit("friend:deleted", {
    userId,
  });

  res.send({ ok: true });
});

app.post("/user/status", requireAuth, async (req: AuthRequest, res) => {
  const userId = req.userId!;
  const { status } = req.body;

  if (!["ONLINE", "AWAY", "BUSY", "OFFLINE"].includes(status)) {
    return res.status(400).send("Invalid status");
  }

  await prisma.user.update({
    where: { id: userId },
    data: { status },
  });

  // 🔔 notify friends in realtime
  const friends = await prisma.friend.findMany({
    where: {
      OR: [{ userAId: userId }, { userBId: userId }],
    },
    select: {
      userAId: true,
      userBId: true,
    },
  });

  const friendIds = friends.map((f) =>
    f.userAId === userId ? f.userBId : f.userAId
  );

  friendIds.forEach((fid) => {
    io.to(fid).emit("status:update", {
      userId,
      status,
    });
  });

  res.send({ ok: true });
});

app.get("/presence", requireAuth, async (req: AuthRequest, res) => {
  // Read user table using the getOnlineUserIds to get the Id and get id => status mapping
  const users = await prisma.user.findMany({
    where: {
      id: { in: getOnlineUserIds() },
    },
    select: {
      id: true,
      status: true,
      avatarUrl: true
    },
  });
  // Create a mapping of userId to status
  const statusMap: Record<string, string> = {};
  users.forEach((user) => {
    statusMap[user.id] = user.status;
  });
  res.send({
    onlineUserIds: getOnlineUserIds(),
    statusMap
  });
});

app.post("/dm/conversation", requireAuth, async (req: AuthRequest, res) => {
  const userId = req.userId!;
  const { friendId } = req.body;

  // find existing DM
  const existing = await prisma.conversation.findFirst({
    where: {
      participants: {
        every: {
          userId: { in: [userId, friendId] },
        },
      },
    },
    include: {
      participants: true,
    },
  });

  if (existing) {
    return res.send(existing);
  }

  // create new DM
  const conversation = await prisma.conversation.create({
    data: {
      participants: {
        create: [{ userId }, { userId: friendId }],
      },
    },
  });

  res.send(conversation);
});

app.get("/dm/:conversationId/messages", requireAuth, async (req: AuthRequest, res) => {
    const { conversationId } = req.params;
    const limit = Number(req.query.limit ?? 20);
    const cursor = req.query.cursor as string | undefined;

    const messages = await prisma.message.findMany({
      where: { conversationId },
      orderBy: { createdAt: "desc" },
      take: limit + 1, // fetch one extra to detect "hasMore"
      ...(cursor && {
        cursor: { id: cursor },
        skip: 1,
      }),
      include: {
        sender: {
          select: {
            id: true,
            username: true,
            avatarUrl: true,
          },
        },
      },
    });

    const hasMore = messages.length > limit;
    const items = hasMore ? messages.slice(0, limit) : messages;

    res.json({
      messages: items.reverse(), // oldest → newest
      nextCursor: hasMore ? items[items.length - 1].id : null,
    });
  }
);


app.post("/dm/message", requireAuth, async (req: AuthRequest, res) => {
  const userId = req.userId!;
  const { conversationId, content } = req.body;

  if (!content.trim()) {
    return res.status(400).send("Empty message");
  }

  const message = await prisma.message.create({
    data: {
      conversationId,
      senderId: userId,
      content,
    },
    include: {
      sender: {
        select: { id: true, username: true, avatarUrl: true },
      },
    },
  });

  // emit to all participants
  const participants = await prisma.conversationParticipant.findMany({
    where: { conversationId },
  });

  participants.forEach((p) => {
    io.to(p.userId).emit("dm:message", message);
  });

  res.send(message);
});

app.get("/dm/conversations", requireAuth, async (req: AuthRequest, res) => {
  const userId = req.userId!;

  const conversations = await prisma.conversation.findMany({
    where: {
      participants: {
        some: { userId },
      },
    },
    include: {
      participants: {
        include: {
          user: {
            select: {
              id: true,
              username: true,
              status: true,
              avatarUrl: true
            },
          },
        },
      },
      messages: {
        orderBy: { createdAt: "desc" },
        take: 1,
      },
    },
  });

  // ✅ Sort in JS by last message time
  conversations.sort((a, b) => {
    const aTime = a.messages[0]?.createdAt?.getTime() ?? 0;
    const bTime = b.messages[0]?.createdAt?.getTime() ?? 0;
    return bTime - aTime;
  });

  res.send(conversations);
});

app.post("/dm/read", requireAuth, async (req: AuthRequest, res) => {
  const userId = req.userId!;
  const { conversationId } = req.body;

  // get messages not sent by this user
  const messages = await prisma.message.findMany({
    where: {
      conversationId,
      senderId: { not: userId },
    },
    select: { id: true },
  });

  // mark them as read (ignore duplicates)
  await prisma.messageRead.createMany({
    data: messages.map((m) => ({
      messageId: m.id,
      userId,
    })),
    skipDuplicates: true,
  });

  // notify other participants (read receipt)
  const participants = await prisma.conversationParticipant.findMany({
    where: { conversationId },
  });

  participants
    .filter((p) => p.userId !== userId)
    .forEach((p) => {
      io.to(p.userId).emit("dm:read", {
        conversationId,
        userId,
      });
    });

  res.send({ ok: true });
});

app.get("/dm/:conversationId/reads", requireAuth, async (req: AuthRequest, res) => {
    const { conversationId } = req.params;
    const userId = req.userId!;

    const reads = await prisma.messageRead.findMany({
      where: {
        message: { conversationId },
        userId: { not: userId }, // 👈 only other user
      },
      select: {
        messageId: true,
      },
    });

    res.send(reads.map((r) => r.messageId));
  }
);

app.post("/auth/logout", (_req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    sameSite: "lax",
    secure: false, // true in production (HTTPS)
  });

  res.send({ ok: true });
});

app.post(
  "/profile/avatar",
  requireAuth,
  uploadAvatar.single("avatar"),
  async (req: AuthRequest, res) => {
    if (!req.file) {
      return res.status(400).send("No file uploaded");
    }

    const avatarUrl = `/uploads/avatars/${req.file.filename}`;

    // Fetch current avatar
    const existingUser = await prisma.user.findUnique({
      where: { id: req.userId! },
      select: { avatarUrl: true },
    });

    const user = await prisma.user.update({
      where: { id: req.userId! },
      data: { avatarUrl },
      select: {
        id: true,
        username: true,
        avatarUrl: true,
      },
    });

    // Delete old avatar if needed
    deleteAvatarIfExists(existingUser?.avatarUrl ?? null);

    res.send(user);
  }
);


