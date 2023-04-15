from fastapi import FastAPI, Request
from jinja2 import Environment, PackageLoader, select_autoescape
from dotenv import load_dotenv
import configparser
from msgraph_user import GraphUser
import hmac, hashlib, base64, os, json

load_dotenv()
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
env = Environment(
    loader=PackageLoader("main", "templates"),
    autoescape=select_autoescape(),
)

app = FastAPI()

# Load settings
config = configparser.ConfigParser()
config.read(['config.cfg', 'config.dev.cfg'])
azure_settings = config['azure']

@app.post("/")
async def read_root(request: Request):
    # Read the signature and strip HMAC prefix
    auth = request.headers['Authorization'][5:]
    body = await request.body()
    if validate_signature(auth, body, WEBHOOK_SECRET):
        # get user information
        user = await GraphUser(azure_settings).get_user_by_id(json.loads(body)['from']['aadObjectId'])
        if user is not None:
            template = env.get_template("enrolled.j2")
            return json.loads(template.render({"user": user}))
        else:
            return { "type": "message", "text": "Error: user not found." }
    else:
        return { "type": "message", "text": "Error: invalid signature." }

def validate_signature(auth, payload, secret):
    """
    Validates the signature of a request.
    :param auth: The signature from the request.
    :param payload: The body of the request.
    :param secret: The secret used to sign the request.
    :return: True if the signature is valid, False otherwise.
    """
    digest = hmac.new(base64.b64decode(secret),
                    msg=payload,
                    digestmod=hashlib.sha256).digest()
    signature = base64.b64encode(digest).decode('utf-8')
    return hmac.compare_digest(auth, signature)