"""Static contract checked by pyright; this module is not a pytest test."""

from typing import Any, Dict, Tuple, Type, Union

from pydantic import BaseModel
from typing_extensions import assert_type

import pydantic_socketio


class Reply(BaseModel):
    value: int


class Error(BaseModel):
    message: str


def check_registration(client: pydantic_socketio.Client) -> None:
    assert_type(
        pydantic_socketio.asyncapi_schema(client, title="API", version="1.0"),
        Dict[str, Any],
    )
    assert_type(client.register_emit("ask", Reply), Type[Reply])
    client.register_emit("ask", Reply, namespace="/chat", ack_type=Tuple[int, str])
    client.register_emit("empty", Reply, ack_type=None)

    @client.register_emit("decorated", namespace="/chat", ack_type=Reply)
    class Payload(BaseModel):
        value: int

    assert_type(Payload, Type[Payload])
    assert_type(client.call("ask", response_model=Reply), Reply)


def check_sync(
    client: pydantic_socketio.Client, server: pydantic_socketio.Server
) -> None:
    assert_type(client.call("ask", response_model=Reply), Reply)
    assert_type(
        server.call("ask", response_model=Union[Reply, Error]), Union[Reply, Error]
    )


async def check_async(
    client: pydantic_socketio.AsyncClient, server: pydantic_socketio.AsyncServer
) -> None:
    assert_type(await client.call("ask", response_model=Reply), Reply)
    assert_type(
        await server.call("ask", response_model=Union[Reply, Error]),
        Union[Reply, Error],
    )
