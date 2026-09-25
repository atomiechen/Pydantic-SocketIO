"""AsyncAPI description of locally registered Socket.IO operations."""

from typing import Any, Dict, Union

from socketio import AsyncClient, AsyncServer, Client, Server

from ._asyncapi import generate_asyncapi


def asyncapi_schema(
    sio: Union[Server, AsyncServer, Client, AsyncClient], *, title: str, version: str
) -> Dict[str, Any]:
    """Describe this instance's registered operations as AsyncAPI 3.1.

    The result is a plain dictionary. It does not inspect remote peers or
    infer a stable ACK type from individual ``call(response_model=...)`` uses.
    """
    contracts = getattr(sio, "_operation_contracts", None)
    role = getattr(sio, "_role", None)
    if contracts is None or role not in ("server", "client"):
        raise TypeError("Socket.IO instance has no Pydantic-SocketIO registrations")
    return generate_asyncapi(contracts.values(), title, version, role)
