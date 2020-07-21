import os

# Application (client) ID of app registration
CLIENT_ID = os.getenv("CLIENT_ID")

CLIENT_SECRET = os.getenv("CLIENT_SECRET")
if not CLIENT_SECRET:
    raise ValueError("Need to define CLIENT_SECRET environment variable")

SECRET_KEY = os.getenv("SECRET_KEY")

AUTHORITY = "https://login.microsoftonline.com/f5.onmicrosoft.com"  # For multi-tenant app

# You can find more Microsoft Graph API endpoints from Graph Explorer
# https://developer.microsoft.com/en-us/graph/graph-explorer
# This resource requires no admin consent
# ENDPOINT = 'https://graph.microsoft.com/v1.0/users'
ENDPOINT = 'https://graph.microsoft.com/v1.0/me'

# You can find the proper permission names from this document
# https://docs.microsoft.com/en-us/graph/permissions-reference
SCOPE = ["User.ReadBasic.All", "profile", "openid", "User.Read", "email"]

# Specifies the token cache should be stored in server-side session
SESSION_TYPE = "filesystem"
