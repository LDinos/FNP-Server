import type { Socket } from "socket.io";
import jwt from "jsonwebtoken";

const JWT_SECRET = "dev-secret";

export interface AuthenticatedSocket extends Socket {
  userId?: string;
}

export function authenticateSocket(
  socket: AuthenticatedSocket,
  next: (err?: Error) => void
) {
  try {
    const cookieHeader = socket.handshake.headers.cookie;

    if (!cookieHeader) {
      return next(new Error("No cookies"));
    }

    const tokenMatch = cookieHeader
      .split("; ")
      .find((c) => c.startsWith("token="));

    if (!tokenMatch) {
      return next(new Error("No token"));
    }

    const token = tokenMatch.split("=")[1];

    const payload = jwt.verify(token, JWT_SECRET) as { userId: string };

    socket.userId = payload.userId;
    next();
  } catch (err) {
    next(new Error("Unauthorized"));
  }
}
