from pydantic_socketio.asyncapi.models import AsyncAPI, Info


my_asyncapi = AsyncAPI(
    asyncapi="3.0.0",
    info=Info(
        title="My AsyncAPI",
        version="1.0.0",
    ),
)


if __name__ == "__main__":
    import yaml

    # This is just a simple test to ensure that the AsyncAPI object can be created
    print(my_asyncapi.model_dump_json(indent=2))
    # You can also use my_asyncapi.dict() to get a dictionary representation
    api_obj = my_asyncapi.model_dump()
    print(yaml.safe_dump(api_obj))
