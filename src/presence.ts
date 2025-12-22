const onlineUsers = new Map<string, Set<string>>();

export function userConnected(userId: string, socketId: string) {
  if (!onlineUsers.has(userId)) {
    onlineUsers.set(userId, new Set());
  }

  onlineUsers.get(userId)!.add(socketId);
}

export function userDisconnected(userId: string, socketId: string) {
  const sockets = onlineUsers.get(userId);
  if (!sockets) return;

  sockets.delete(socketId);

  if (sockets.size === 0) {
    onlineUsers.delete(userId);
  }
}

export function isUserOnline(userId: string) {
  return onlineUsers.has(userId);
}

export function getOnlineUserIds() {
  return Array.from(onlineUsers.keys());
}

export { onlineUsers };