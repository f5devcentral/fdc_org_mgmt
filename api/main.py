"""Main module for the API."""
import base64
import hmac
import hashlib
import json
import os
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from starlette.types import Message
from jinja2 import Environment, PackageLoader, select_autoescape
from dotenv import load_dotenv
from msgraph_user import GraphUser


load_dotenv()
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TENANT_ID = os.getenv("TENANT_ID")

env = Environment(
    loader=PackageLoader("main", "templates"),
    autoescape=select_autoescape(),
)

app = FastAPI()

@app.post("/")
async def read_root(request: Request):
    """
    Root endpoint for the API.
    :param request: The request object.
    :return: The response object.
    """

    # determine action
    match request.state.action:
        case 'enroll':
            graph = GraphUser(CLIENT_ID, CLIENT_SECRET, TENANT_ID)
            user = await graph.get_user_by_id(request.state.user_id)
            print(f'User ID: {request.state.user_id}')
            if user is not None:
                template = env.get_template("enrolled.j2")
                return JSONResponse(json.loads(template.render({"user": user})))
            else:
                template = env.get_template("error.j2")
                return JSONResponse(json.loads(template.render({"message": "User not found."})))
        case _:
            template = env.get_template("help.j2")
            return JSONResponse(json.loads(template.render()))

# Handle accessing the body twice in middleware
# https://github.com/tiangolo/fastapi/discussions/8187
async def set_body(request: Request, body: bytes):
    """
    Set the body of the request.
    :param request: The request object.
    :param body: The body of the request.
    :return: None
    """
    async def receive() -> Message:
        return {"type": "http.request", "body": body}
    request._receive = receive

async def get_body(request: Request) -> bytes:
    """
    Get the body of the request.
    :param request: The request object.
    :return: The body of the request.
    """
    body = await request.body()
    await set_body(request, body)
    return body

@app.middleware("http")
async def validate_signature(request: Request, call_next):
    """
    Middleware to validate the signature of the request.
    :param request: The request object.
    :param call_next: The next function to call.
    :return: The response object.
    """
    auth = request.headers['Authorization'][5:]
    # body = await request.body()
    await set_body(request, await request.body())
    digest = hmac.new(base64.b64decode(WEBHOOK_SECRET),
                    # msg=body,
                    msg=await get_body(request),
                    digestmod=hashlib.sha256).digest()
    signature = base64.b64encode(digest).decode('utf-8')
    if hmac.compare_digest(auth, signature):
        response = await call_next(request)
        return response
    else:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content='{ "type": "message", "text": "Error: invalid signature." }')

@app.middleware("http")
async def collect_teams_data(request: Request, call_next):
    """
    Middleware to collect the teams data.
    :param request: The request object.
    :param call_next: The next function to call.
    :return: The response object.
    """
    request.state.teams_request = json.loads(await get_body(request))
    request.state.name = request.state.teams_request['from']['name']
    request.state.user_id = request.state.teams_request['from']['aadObjectId']
    request.state.message = request.state.teams_request['text']
    request.state.action = request.state.message.split(' ')[1].lower().rstrip('\n') \
        if len(request.state.message.split(' ')) > 1 else None
    request.state.argument = request.state.message.split(' ')[2].lower().rstrip('\n') \
        if len(request.state.message.split(' ')) > 2 else None
    response = await call_next(request)
    return response
