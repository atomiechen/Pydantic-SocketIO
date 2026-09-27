"""One Python Socket.IO contract shared with a typed browser client."""

from fastapi import FastAPI
from pydantic import BaseModel

from pydantic_socketio import ASGIApp, AsyncServer


class Ask(BaseModel):
    text: str


class Answer(BaseModel):
    accepted: bool


class Notice(BaseModel):
    text: str


api = FastAPI()
sio = AsyncServer(async_mode="asgi", cors_allowed_origins=["http://127.0.0.1:5173"])
sio.register_emit("notice", Notice, namespace="/chat")
app = ASGIApp(sio, other_asgi_app=api)


@api.get("/")
async def root():
    return {"message": "Open http://127.0.0.1:5173 for the chat example"}


@sio.on("ask", namespace="/chat")
async def ask(sid: str, request: Ask) -> Answer:
    text = request.text.strip()
    await sio.emit("notice", Notice(text=f"Received: {text}"), to=sid, namespace="/chat")
    return Answer(accepted=bool(text))
