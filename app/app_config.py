import os

USER_MAPPING_FILE_PATH = "./data/user_mapping.json"

# Application (client) ID of app registration
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
if not AZURE_CLIENT_ID:
    raise ValueError(
        "Need to define AZURE_CLIENT_ID environment variable")

AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
if not AZURE_CLIENT_SECRET:
    raise ValueError(
        "Need to define AZURE_CLIENT_SECRET environment variable")

AZURE_SCOPE = ["User.ReadBasic.All", "profile", "openid", "User.Read", "email"]

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
if not GITHUB_CLIENT_ID:
    raise ValueError(
        "Need to define GITHUB_CLIENT_ID environment variable")

GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
if not GITHUB_CLIENT_SECRET:
    raise ValueError(
        "Need to define GITHUB_CLIENT_SECRET environment variable")

GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
if not GITHUB_APP_ID:
    raise ValueError(
        "Need to define GITHUB_APP_ID environment variable")

GITHUB_APP_KEY = os.getenv("GITHUB_APP_KEY")
if not GITHUB_APP_KEY:
    raise ValueError(
        "need to define GITHUB_APP_KEY environment variable")

GITHUB_ORG = os.getenv("GITHUB_ORG")
if not GITHUB_ORG:
    raise ValueError(
        "need to define GITHUB_ORG environment variable")

GITHUB_INSTALLATION_ID = os.getenv("GITHUB_INSTALLATION_ID")
if not GITHUB_INSTALLATION_ID:
    raise ValueError(
        "need to define GITHUB_INSTALLATION_ID environment variable")

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError(
        "Need to define SECRET_KEY environment variable")

DYNAMODB_URL = os.getenv("DYNAMODB_URL")
DYNAMODB_TABLE = "fdc_user_mapping"
REGION = "us-east-1"