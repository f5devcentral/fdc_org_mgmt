import os

# Application (client) ID of app registration
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
if not AZURE_CLIENT_ID:
    raise ValueError("Need to define AZURE_CLIENT_ID environment variable")

AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
if not AZURE_CLIENT_SECRET:
    raise ValueError("Need to define AZURE_CLIENT_SECRET environment variable")

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
if not GITHUB_CLIENT_ID:
    raise ValueError("Need to define GITHUB_CLIENT_ID environment variable")

GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
if not GITHUB_CLIENT_SECRET:
    raise ValueError(
        "Need to define GITHUB_CLIENT_SECRET environment variable")

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError(
        "Need to define SECRET_KEY environment variable")

AZURE_SCOPE = ["User.ReadBasic.All", "profile", "openid", "User.Read", "email"]
