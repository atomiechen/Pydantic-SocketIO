from fastapi import FastAPI
from pydantic import BaseModel
from pydantic_socketio import FastAPISocketIO, SioDep


app = FastAPI()
sio = FastAPISocketIO()
# sio = FastAPISocketIO(app)


class Data(BaseModel):
    value: int
    description: str


@app.get("/")
async def read_root(sio: SioDep):
    print(type(sio))
    await sio.emit("misc", Data(value=666, description="API root called"))
    return {"Hello": "World"}


@sio.on("connect")
def connect(sid: str, environ):
    print("==== connect ", sid)


@sio.on("disconnect")
async def disconnect(sid: str):
    print("==== disconnect ", sid)


@sio.on("misc")
async def misc(sid: str, data: Data):
    print("==== misc ", sid, type(data), data)
    ret = Data(value=data.value + 1, description="value increased by 1")
    await sio.emit("misc", ret)


sio.integrate(app)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, port=8000)
