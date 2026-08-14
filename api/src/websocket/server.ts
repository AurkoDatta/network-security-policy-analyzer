import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { env } from '../config/env';

let io: SocketIOServer | undefined;

export function attachSocketIO(server: http.Server): SocketIOServer {
  io = new SocketIOServer(server, {
    path: '/ws/analyze',
    cors: { origin: `http://localhost:${env.frontendPort}` },
  });

  io.on('connection', (socket) => {
    socket.on('join', (policyId: string) => {
      socket.join(`analyze:${policyId}`);
    });
  });

  return io;
}

export function emitProgress(policyId: string, stage: string, percent: number): void {
  io?.to(`analyze:${policyId}`).emit('progress', { stage, percent });
}
