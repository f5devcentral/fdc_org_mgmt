import os
import boto3
from util import get_secret

FQDN = os.getenv("FQDN")
if not FQDN:
    raise ValueError(
        "Need to define FQDN environment variable")

AZURE_SCOPE = ["User.ReadBasic.All", "profile", "openid", "User.Read", "email"]
APP_DEBUG = os.getenv("APP_DEBUG")
if not APP_DEBUG:
    APP_DEBUG = 0
REGION = "us-east-1"
SECRET_NAME = os.getenv("SECRET_NAME")
if not SECRET_NAME:
    raise ValueError("Need to define SECRET_NAME environment variable")
USERS_TABLE = os.getenv("USERS_TABLE")
if not USERS_TABLE:
    raise ValueError("Need to define USERS_TABLE environment variable")

# get secrets
SECRETS = get_secret(SECRET_NAME, REGION)
if not SECRETS:
    raise Exception('Unable to load secrets')
