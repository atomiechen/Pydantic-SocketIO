import functools
import inspect
import logging
from typing import Any, Callable, Optional, Union

from pydantic import validate_call, ValidationError
from pydantic_core import to_jsonable_python
from socketio import (
    AsyncServer as OldAsyncServer,
    Server as OldServer,
    Client as OldClient,
    AsyncClient as OldAsyncClient,
)
from socketio.base_server import BaseServer as OldBaseServer
from socketio.base_client import BaseClient as OldBaseClient


# Save the original functions
_old_server_on = OldBaseServer.on
_old_server_emit = OldServer.emit
_old_server_emit_async = OldAsyncServer.emit
_old_client_on = OldBaseClient.on
_old_client_emit = OldClient.emit
_old_client_emit_async = OldAsyncClient.emit


module_logger = logging.getLogger(__name__)
module_logger.addHandler(logging.NullHandler())


def _wrapper(
    handler: Callable,
    old_on: Callable,
    self: Union[OldBaseClient, OldBaseServer],
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


class BaseServer(OldBaseServer):
    """BaseServer with pydantic validation."""

    def on(
        self: OldBaseServer,
        event: str,
        handler: Optional[Callable] = None,
        *args,
        **kwargs,
    ) -> Callable:
        if handler is None:
            # invoked as a decorator
            return functools.partial(
                _wrapper,
                old_on=_old_server_on,
                self=self,
                event=event,
                *args,
                **kwargs,
            )
        else:
            # not invoked as a decorator, but as a function
            return _wrapper(handler, _old_server_on, self, event, *args, **kwargs)


class Server(BaseServer, OldServer):
    """Server with pydantic validation and data conversion."""

    def emit(
        self: OldServer,
        event: str,
        data: Any = None,
        to: Optional[str] = None,
        *args,
        **kwargs,
    ):
        return _old_server_emit(
            self, event=event, data=to_jsonable_python(data), to=to, *args, **kwargs
        )


class AsyncServer(BaseServer, OldAsyncServer):
    """AsyncServer with pydantic validation and data conversion."""

    async def emit(
        self: OldAsyncServer,
        event: str,
        data: Any = None,
        to: Optional[str] = None,
        *args,
        **kwargs,
    ):
        return await _old_server_emit_async(
            self, event=event, data=to_jsonable_python(data), to=to, *args, **kwargs
        )


class BaseClient(OldBaseClient):
    """BaseClient with pydantic validation."""

    def on(
        self: OldBaseClient,
        event: str,
        handler: Optional[Callable] = None,
        *args,
        **kwargs,
    ) -> Callable:
        if handler is None:
            # invoked as a decorator
            return functools.partial(
                _wrapper,
                old_on=_old_client_on,
                self=self,
                event=event,
                *args,
                **kwargs,
            )
        else:
            # not invoked as a decorator, but as a function
            return _wrapper(handler, _old_client_on, self, event, *args, **kwargs)


class Client(BaseClient, OldClient):
    """Client with pydantic validation and data conversion."""

    def emit(self: OldClient, event: str, data: Any = None, *args, **kwargs):
        return _old_client_emit(self, event, to_jsonable_python(data), *args, **kwargs)


class AsyncClient(BaseClient, OldAsyncClient):
    """AsyncClient with pydantic validation and data conversion."""

    async def emit(self: OldAsyncClient, event: str, data: Any = None, *args, **kwargs):
        return await _old_client_emit_async(
            self, event, to_jsonable_python(data), *args, **kwargs
        )


def monkey_patch():
    module_logger.debug("Monkey patching")
    OldBaseServer.on = BaseServer.on
    OldServer.emit = Server.emit
    OldAsyncServer.emit = AsyncServer.emit
    OldBaseClient.on = BaseClient.on
    OldClient.emit = Client.emit
    OldAsyncClient.emit = AsyncClient.emit
    module_logger.debug("Monkey patched")
