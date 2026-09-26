import { io, Socket } from 'socket.io-client';
import { Root, Chat } from './generated/client';

const root: Socket<Root.ServerToClientEvents, Root.ClientToServerEvents> = io(Root.path);
root.emit('client_send', { nested: { count: 1 } }, answer => {
  const ok: boolean = answer.ok;
  void ok;
});

const chat: Socket<Chat.ServerToClientEvents, Chat.ClientToServerEvents> = io(Chat.path);
chat.on('client_event', (request, ack) => {
  const count: number = request.nested.count;
  void count;
  ack?.({ ok: true, result: 'done' });
});

// @ts-expect-error client source role still maps outgoing operations to client-to-server events
root.on('client_send', () => {});
// @ts-expect-error client receive handler maps to server-to-client events
chat.emit('client_event', { nested: { count: 1 } });
