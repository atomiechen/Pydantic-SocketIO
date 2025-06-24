import functools
import inspect
import logging
from typing import Any, Callable, Dict, List, Literal, Optional, Type, Union

from pydantic import TypeAdapter, validate_call, ValidationError
from pydantic_core import to_jsonable_python
from pydantic_socketio.types import JsonModule
from socketio import (
    AsyncServer as OldAsyncServer,
    Manager,
    Server as OldServer,
    Client as OldClient,
    AsyncClient as OldAsyncClient,
    packet,
)
from socketio.base_server import BaseServer as OldBaseServer
from socketio.base_client import BaseClient as OldBaseClient


# Save the original functions
_old_server_on = OldBaseServer.on

_old_server_init = OldServer.__init__
_old_server_emit = OldServer.emit

_old_server_init_async = OldAsyncServer.__init__
_old_server_emit_async = OldAsyncServer.emit

_old_client_on = OldBaseClient.on

_old_client_init = OldClient.__init__
_old_client_emit = OldClient.emit

_old_client_init_async = OldAsyncClient.__init__
_old_client_emit_async = OldAsyncClient.emit


module_logger = logging.getLogger(__name__)
module_logger.addHandler(logging.NullHandler())


def _wrapper(
    handler: Callable,
    old_on: Callable,
    self,
    event: str,
    *args,
    **kwargs,
):
    """Wrap the handler to validate the input using pydantic"""
    validated_handler = validate_call(handler)
    if event in ["connect", "disconnect"]:
        # For connect and disconnect events, convert ValidationError
        # to TypeError, so that socketio can handle it properly
        if inspect.iscoroutinefunction(validated_handler):

            @functools.wraps(validated_handler)
            async def wrapped_handler(*args, **kwargs):  # type: ignore
                try:
                    return await validated_handler(*args, **kwargs)
                except ValidationError as e:
                    raise TypeError from e
        else:

            @functools.wraps(validated_handler)
            def wrapped_handler(*args, **kwargs):
                try:
                    return validated_handler(*args, **kwargs)
                except ValidationError as e:
                    raise TypeError from e
    else:
        wrapped_handler = validated_handler  # type: ignore

    # Register the wrapped handler
    old_on(self, event, wrapped_handler, *args, **kwargs)
    return wrapped_handler


class PydanticSioToolset:
    """A toolset for pydantic validation and conversion for socketio."""

    def __init__(self, old_on: Callable, role: Literal["server", "client"]):
        self._EMIT_EVENT_TYPES: Dict[str, Type] = {}
        self._old_on = old_on

    def register_emit(self, event: str, payload_type: Optional[Type] = None):
        """Decorator to register the payload type for an event."""

        def decorator(payload_type: Type):
            self._EMIT_EVENT_TYPES[event] = payload_type
            return payload_type

        if payload_type is None:
            # invoked as a decorator
            return decorator
        else:
            # not invoked as a decorator, but as a function
            return decorator(payload_type)

    def validate_emit(self, event: str, data: Any):
        """Validate the emit data type for the given event."""
        expected_type = self._EMIT_EVENT_TYPES.get(event)
        if expected_type is None:
            # If no type is registered, skip validation
            return

        TypeAdapter(expected_type).validate_python(data)

    def on(
        self,
        event: str,
        handler: Optional[Callable] = None,
        namespace: Optional[str] = None,
    ) -> Callable:
        if handler is None:
            # invoked as a decorator
            return functools.partial(
                _wrapper,
                old_on=self._old_on,
                self=self,
                event=event,
                namespace=namespace,
            )
        else:
            # not invoked as a decorator, but as a function
            return _wrapper(
                handler=handler,
                old_on=self._old_on,
                self=self,
                event=event,
                namespace=namespace,
            )

    def schema(self):
        """Return the event schema of the server."""
        # TODO
        pass


class Server(PydanticSioToolset, OldServer):
    """Server with pydantic validation and data conversion."""

    def __init__(
        self,
        client_manager: Optional[Manager] = None,
        logger: bool = False,
        serializer: Union[
            Literal["default", "pickle", "msgpack", "cbor"], packet.Packet
        ] = "default",
        json: Optional[JsonModule] = None,
        async_handlers: bool = True,
        always_connect: bool = False,
        namespaces: Optional[Union[List[str], Literal["*"]]] = None,
        **kwargs,
    ):
        _old_server_init(
            self,
            client_manager=client_manager,
            logger=logger,
            serializer=serializer,  # type: ignore
            json=json,
            async_handlers=async_handlers,
            always_connect=always_connect,
            namespaces=namespaces,
            **kwargs,
        )
        PydanticSioToolset.__init__(self, _old_server_on, "server")

    def emit(
        self,
        event: str,
        data: Any = None,
        to: Optional[Union[str, List[str]]] = None,
        room: Optional[Union[str, List[str]]] = None,
        skip_sid: Optional[Union[str, List[str]]] = None,
        namespace: Optional[str] = None,
        callback: Optional[Callable] = None,
        ignore_queue: bool = False,
    ):
        self.validate_emit(event, data)
        return _old_server_emit(
            self,
            event=event,
            data=to_jsonable_python(data),
            to=to,
            room=room,
            skip_sid=skip_sid,
            namespace=namespace,
            callback=callback,
            ignore_queue=ignore_queue,
        )


class AsyncServer(PydanticSioToolset, OldAsyncServer):
    """AsyncServer with pydantic validation and data conversion."""

    def __init__(
        self,
        client_manager: Optional[Manager] = None,
        logger: bool = False,
        serializer: Union[
            Literal["default", "pickle", "msgpack", "cbor"], packet.Packet
        ] = "default",
        json: Optional[JsonModule] = None,
        async_handlers: bool = True,
        always_connect: bool = False,
        namespaces: Optional[Union[List[str], Literal["*"]]] = None,
        **kwargs,
    ):
        _old_server_init_async(
            self,
            client_manager=client_manager,
            logger=logger,
            serializer=serializer,  # type: ignore
            json=json,
            async_handlers=async_handlers,
            always_connect=always_connect,
            namespaces=namespaces,
            **kwargs,
        )
        PydanticSioToolset.__init__(self, _old_server_on, "server")

    async def emit(
        self,
        event: str,
        data: Any = None,
        to: Optional[Union[str, List[str]]] = None,
        room: Optional[Union[str, List[str]]] = None,
        skip_sid: Optional[Union[str, List[str]]] = None,
        namespace: Optional[str] = None,
        callback: Optional[Callable] = None,
        ignore_queue: bool = False,
    ):
        self.validate_emit(event, data)
        return await _old_server_emit_async(
            self,
            event=event,
            data=to_jsonable_python(data),
            to=to,
            room=room,
            skip_sid=skip_sid,
            namespace=namespace,
            callback=callback,
            ignore_queue=ignore_queue,
        )


class Client(PydanticSioToolset, OldClient):
    """Client with pydantic validation and data conversion."""

    def __init__(
        self,
        reconnection: bool = True,
        reconnection_attempts: int = 0,
        reconnection_delay: int = 1,
        reconnection_delay_max: int = 5,
        randomization_factor: float = 0.5,
        logger: Union[bool, logging.Logger] = False,
        serializer: Union[
            Literal["default", "pickle", "msgpack", "cbor"], packet.Packet
        ] = "default",
        json: Optional[JsonModule] = None,
        handle_sigint: bool = True,
        **kwargs,
    ):
        _old_client_init(
            self,
            reconnection=reconnection,
            reconnection_attempts=reconnection_attempts,
            reconnection_delay=reconnection_delay,
            reconnection_delay_max=reconnection_delay_max,
            randomization_factor=randomization_factor,
            logger=logger,  # type: ignore
            serializer=serializer,  # type: ignore
            json=json,
            handle_sigint=handle_sigint,
            **kwargs,
        )
        PydanticSioToolset.__init__(self, _old_client_on, "client")

    def emit(
        self,
        event: str,
        data: Any = None,
        namespace: Optional[str] = None,
        callback: Optional[Callable] = None,
    ):
        self.validate_emit(event, data)
        return _old_client_emit(
            self,
            event=event,
            data=to_jsonable_python(data),
            namespace=namespace,
            callback=callback,
        )


class AsyncClient(PydanticSioToolset, OldAsyncClient):
    """AsyncClient with pydantic validation and data conversion."""

    def __init__(
        self,
        reconnection: bool = True,
        reconnection_attempts: int = 0,
        reconnection_delay: int = 1,
        reconnection_delay_max: int = 5,
        randomization_factor: float = 0.5,
        logger: Union[bool, logging.Logger] = False,
        serializer: Union[
            Literal["default", "pickle", "msgpack", "cbor"], packet.Packet
        ] = "default",
        json: Optional[JsonModule] = None,
        handle_sigint: bool = True,
        **kwargs,
    ):
        _old_client_init_async(
            self,
            reconnection=reconnection,
            reconnection_attempts=reconnection_attempts,
            reconnection_delay=reconnection_delay,
            reconnection_delay_max=reconnection_delay_max,
            randomization_factor=randomization_factor,
            logger=logger,  # type: ignore
            serializer=serializer,  # type: ignore
            json=json,
            handle_sigint=handle_sigint,
            **kwargs,
        )
        PydanticSioToolset.__init__(self, _old_client_on, "client")

    async def emit(
        self,
        event: str,
        data: Any = None,
        namespace: Optional[str] = None,
        callback: Optional[Callable] = None,
    ):
        self.validate_emit(event, data)
        return await _old_client_emit_async(
            self,
            event=event,
            data=to_jsonable_python(data),
            namespace=namespace,
            callback=callback,
        )


def monkey_patch():
    module_logger.debug("Monkey patching")

    setattr(OldServer, "__init__", Server.__init__)
    setattr(OldServer, "on", Server.on)
    setattr(OldServer, "emit", Server.emit)
    setattr(OldServer, "register_emit", Server.register_emit)
    setattr(OldServer, "validate_emit", Server.validate_emit)
    setattr(OldServer, "schema", Server.schema)

    setattr(OldAsyncServer, "__init__", AsyncServer.__init__)
    setattr(OldAsyncServer, "on", AsyncServer.on)
    setattr(OldAsyncServer, "emit", AsyncServer.emit)
    setattr(OldAsyncServer, "register_emit", AsyncServer.register_emit)
    setattr(OldAsyncServer, "validate_emit", AsyncServer.validate_emit)
    setattr(OldAsyncServer, "schema", AsyncServer.schema)

    setattr(OldClient, "__init__", Client.__init__)
    setattr(OldClient, "on", Client.on)
    setattr(OldClient, "emit", Client.emit)
    setattr(OldClient, "register_emit", Client.register_emit)
    setattr(OldClient, "validate_emit", Client.validate_emit)
    setattr(OldClient, "schema", Client.schema)

    setattr(OldAsyncClient, "__init__", AsyncClient.__init__)
    setattr(OldAsyncClient, "on", AsyncClient.on)
    setattr(OldAsyncClient, "emit", AsyncClient.emit)
    setattr(OldAsyncClient, "register_emit", AsyncClient.register_emit)
    setattr(OldAsyncClient, "validate_emit", AsyncClient.validate_emit)
    setattr(OldAsyncClient, "schema", AsyncClient.schema)

    module_logger.debug("Monkey patched")
