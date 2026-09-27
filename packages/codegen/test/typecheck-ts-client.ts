import { io, Socket } from 'socket.io-client';
import { Root, Chat } from './generated/server';

const root: Socket<Root.ServerToClientEvents, Root.ClientToServerEvents> = io(Root.path);
root.emit('ping');
root.emit('ping', () => {});
root.on('fallback', data => { const n: number = data.nested.count; void n; });
root.on('tick', (data, ack) => { const n: number = data; void n; ack?.(); });

const chat: Socket<Chat.ServerToClientEvents, Chat.ClientToServerEvents> = io(Chat.path);
chat.emit('shared', { nested: { count: 1 } }, answer => {
  const value: number | string = answer.result;
  void value;
});
chat.emit('many', { nested: { count: 1 }, label: null }, 2, (n, s) => {
  const number: number = n;
  const text: string = s;
  void number; void text;
});
chat.on('shared', (n, s, ack) => { ack?.(n, s); });
chat.on('fallback', data => { const ok: boolean = data.ok; void ok; });

async function request() {
  const answer = await chat.emitWithAck('shared', { nested: { count: 1 } });
  const ok: boolean = answer.ok;
  void ok;
}
void request;

// @ts-expect-error incorrect event
chat.emit('typo', { nested: { count: 1 } });
// @ts-expect-error incorrect nested payload
chat.emit('shared', { nested: { count: 'wrong' } });
// @ts-expect-error missing second event argument
chat.emit('many', { nested: { count: 1 } });
// @ts-expect-error incorrect ACK result use
chat.emit('shared', { nested: { count: 1 } }, answer => { const n: number = answer.ok; void n; });
// @ts-expect-error incorrect ACK argument types
chat.on('shared', (n, s, ack) => { ack?.('wrong', 1); });
// @ts-expect-error scoped override replaces the unscoped fallback
chat.on('fallback', data => { const n: number = data.nested.count; void n; });
// @ts-expect-error an explicitly empty ACK takes no arguments
root.on('tick', (data, ack) => { ack?.('wrong'); });
