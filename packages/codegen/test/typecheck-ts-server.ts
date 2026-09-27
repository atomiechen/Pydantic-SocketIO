import { Server, type Namespace } from 'socket.io';
import { Root, Chat, type Answer, type Request } from './generated/client';

const server = new Server<Root.ClientToServerEvents, Root.ServerToClientEvents>();
server.on('connection', socket => {
  socket.on('client_send', (request, ack) => {
    const count: number = request.nested.count;
    const answer: Answer = { ok: true, result: count };
    ack?.(answer);
  });
});

const chat: Namespace<Chat.ClientToServerEvents, Chat.ServerToClientEvents> = server.of(Chat.path);
chat.on('connection', socket => {
  const notice: Request = { nested: { count: 2 } };
  socket.emit('client_event', notice, answer => {
    const ok: boolean = answer.ok;
    void ok;
  });
  // @ts-expect-error client_event is sent by the server, not received by it
  socket.on('client_event', () => {});
});

// @ts-expect-error unknown event on TypeScript server
server.emit('missing', { nested: { count: 1 } });
// @ts-expect-error incorrect payload on TypeScript server
chat.emit('client_event', { nested: { count: 'wrong' } });
// @ts-expect-error wrong direction: client_send belongs to client-to-server
server.emit('client_send', { nested: { count: 1 } });
// @ts-expect-error client_send is on the root namespace, not /chat
chat.emit('client_send', { nested: { count: 1 } });
