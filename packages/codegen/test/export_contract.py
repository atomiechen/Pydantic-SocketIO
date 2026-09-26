"""Produce real AsyncAPI inputs for the TypeScript consumer test."""

import json
from pathlib import Path
from typing import Optional, Tuple, Union

from pydantic import BaseModel

import pydantic_socketio


class Nested(BaseModel):
    count: int


class Request(BaseModel):
    nested: Nested
    label: Optional[str] = None


class Answer(BaseModel):
    ok: bool
    result: Union[int, str]


server = pydantic_socketio.Server(async_mode="threading")


@server.on("ping")
def ping(sid: str) -> None:
    return None


@server.on("shared", namespace="/chat")
def shared(sid: str, payload: Request) -> Answer:
    return Answer(ok=True, result=payload.nested.count)


@server.on("many", namespace="/chat")
def many(sid: str, first: Request, second: int) -> Tuple[int, str]:
    return second, first.label or ""


server.register_emit("shared", Tuple[int, str], namespace="/chat", ack_type=Tuple[int, str])
server.register_emit("tick", int, namespace="/", ack_type=None)
server.register_emit("fallback", Request)
server.register_emit("fallback", Answer, namespace="/chat")

client = pydantic_socketio.Client()


@client.on("client_event", namespace="/chat")
def client_event(payload: Request) -> Answer:
    return Answer(ok=True, result=payload.nested.count)


client.register_emit("client_send", Request, namespace="/", ack_type=Answer)

destination = Path(__file__).parent / "generated"
destination.mkdir(exist_ok=True)
for name, sio in (("server", server), ("client", client)):
    document = pydantic_socketio.asyncapi_schema(sio, title="Type test", version="1")
    (destination / f"{name}.json").write_text(json.dumps(document, indent=2))
