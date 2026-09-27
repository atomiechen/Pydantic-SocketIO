import { io, type Socket } from "socket.io-client";
import { Chat } from "./socketio.generated";

const status = document.querySelector<HTMLParagraphElement>("#status")!;
const form = document.querySelector<HTMLFormElement>("#ask-form")!;
const input = document.querySelector<HTMLInputElement>("#message")!;
const ack = document.querySelector<HTMLParagraphElement>("#ack")!;
const notices = document.querySelector<HTMLUListElement>("#notices")!;

const socket: Socket<Chat.ServerToClientEvents, Chat.ClientToServerEvents> = io(
  `http://127.0.0.1:8000${Chat.path}`,
);

socket.on("connect", () => { status.textContent = "Connected"; });
socket.on("disconnect", () => { status.textContent = "Disconnected"; });
socket.on("connect_error", (error) => { status.textContent = error.message; });
socket.on("notice", (notice) => {
  const item = document.createElement("li");
  item.textContent = notice.text;
  notices.prepend(item);
});

form.addEventListener("submit", (event) => {
  event.preventDefault();
  socket.emit("ask", { text: input.value }, (answer) => {
    ack.textContent = answer.accepted ? "Accepted" : "Empty message";
  });
  input.value = "";
});
