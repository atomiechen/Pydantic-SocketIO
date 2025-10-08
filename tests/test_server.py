from pydantic import BaseModel
import socketio
import pydantic_socketio


# pydantic_socketio.monkey_patch()


def test_wsgi():
    # create a Socket.IO server
    # sio = socketio.Server()
    sio = pydantic_socketio.Server(async_mode="threading")

    # wrap with a WSGI application
    app = socketio.WSGIApp(sio)

    class Data(BaseModel):
        value: int
        description: str

    @sio.event
    def connect(sid: str, environ):
        print("==== connect ", sid)

    @sio.on("*")
    def get_event(sid: str, event: str, data):
        print("==== get_event ", sid, event, data)

    @sio.on("disconnect")
    def disconnect(sid: str, reason: str):
        print("==== disconnect ", sid, reason)

    @sio.on("misc")
    def misc(sid: str, data: Data):
        print("==== misc ", sid, type(data), data)
        ret = Data(value=data.value + 1, description="value increased by 1")
        sio.emit("misc", ret)

    return app


if __name__ == "__main__":
    from gunicorn.app.wsgiapp import WSGIApplication

    # ref: https://stackoverflow.com/a/73895674/11854304
    class StandaloneApplication(WSGIApplication):
        def __init__(self, wsgi_app, options=None):
            self.options = options or {}
            super().__init__()
            self.callable = wsgi_app

        def load_config(self):
            config = {
                key: value
                for key, value in self.options.items()
                if key in self.cfg.settings and value is not None  # type: ignore
            }
            for key, value in config.items():
                self.cfg.set(key.lower(), value)  # type: ignore

    app = test_wsgi()
    StandaloneApplication(
        app,
        {
            "bind": "localhost:8000",
        },
    ).run()
