"""Static contract checked by pyright; this module is not a pytest test."""

from typing import Union

from pydantic import BaseModel
from typing_extensions import assert_type

import pydantic_socketio


class Reply(BaseModel):
    value: int


class Error(BaseModel):
    message: str


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
