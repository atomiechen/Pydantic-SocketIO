import { Server } from 'socket.io';
import { Root, Chat, type Answer, type Request } from './generated/client';

const root = new Server<Root.ClientToServerEvents, Root.ServerToClientEvents>();
root.on('connection', socket => {
  socket.on('client_send', (request, ack) => {
    const count: number = request.nested.count;
    const answer: Answer = { ok: true, result: count };
    ack?.(answer);
  });
});

const chat = new Server<Chat.ClientToServerEvents, Chat.ServerToClientEvents>();
chat.of(Chat.path).on('connection', socket => {
  const notice: Request = { nested: { count: 2 } };
  socket.emit('client_event', notice, answer => {
    const ok: boolean = answer.ok;
    void ok;
  });
});

// @ts-expect-error unknown event on TypeScript server
root.emit('missing', { nested: { count: 1 } });
// @ts-expect-error incorrect payload on TypeScript server
chat.of(Chat.path).emit('client_event', { nested: { count: 'wrong' } });
// @ts-expect-error wrong direction: client_send belongs to client-to-server
root.emit('client_send', { nested: { count: 1 } });
