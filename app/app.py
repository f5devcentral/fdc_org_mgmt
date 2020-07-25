import os
import app_config
from flask import Flask, redirect, url_for
from flask_dance.contrib.azure import make_azure_blueprint, azure
from flask_dance.contrib.github import make_github_blueprint, github
from cryptography.hazmat.backends import default_backend
import jwt
import requests
import time

# Define the Flask app
app = Flask(__name__)
# Load configuration
app.config.from_object(app_config)

# Build JWT header


def create_jwt(app_id):
    time_since_epoch_in_seconds = int(time.time())

    payload = {
        # issued at time
        'iat': time_since_epoch_in_seconds,
        # JWT expiration time
        'exp': time_since_epoch_in_seconds + (10 * 60),
        # GitHub App ID
        'iss': app_config.GITHUB_APP_ID
    }

    return jwt.encode(
        payload, app_config.GITHUB_APP_KEY, algorithm='RS256')


def get_access_token(installation_id, gh_jwt, permissions):
    headers = {
        "Authorization": "Bearer {}".format(gh_jwt.decode()),
        "Accept": "application/vnd.github.machine-man-preview+json"
    }
    resp = requests.post(
        "https://api.github.com/app/installations/{}/access_tokens".format(
            installation_id),
        headers=headers,
        data=permissions)

    return (resp.json()["token"])


# Build Azure OAuth blueprint
azure_bp = make_azure_blueprint(
    client_id=app_config.AZURE_CLIENT_ID,
    client_secret=app_config.AZURE_CLIENT_SECRET,
    scope=app_config.AZURE_SCOPE
)
app.register_blueprint(azure_bp, url_prefix="/login")

# Build GitHub OAuth blueprint
github_bp = make_github_blueprint(
    client_id=app_config.GITHUB_CLIENT_ID,
    client_secret=app_config.GITHUB_CLIENT_SECRET
)
app.register_blueprint(github_bp, url_prefix="/login")


@app.route("/")
def index():
    # Ensure the user is authenticated against Azure and GitHub
    if not azure.authorized:
        return redirect(url_for("azure.login"))
    if not github.authorized:
        return redirect(url_for("github.login"))

    # Get email address
    azure_resp = azure.get("/v1.0/me")
    assert azure_resp.ok
    email = azure_resp.json()["userPrincipalName"]

    # Get GitHub username
    github_resp = github.get("/user")
    assert github_resp.ok
    login = github_resp.json()["login"]

    # Create JWT Token for installation authentication
    gh_jwt = create_jwt(app_config.GITHUB_APP_ID)

    # Get Access Token
    gh_access_token = get_access_token(
        app_config.GITHUB_INSTALLATION_ID, gh_jwt, '{"members": "read"}')

    # Test GitHub API with installation authentication
    headers = {
        "Authorization": "Token {}".format(gh_access_token),
        "Accept": "application/vnd.github.machine-man-preview+json"
    }
    resp = requests.get("https://api.github.com/orgs/{}/outside_collaborators".format(app_config.GITHUB_ORG),
                        headers=headers)
    assert resp.ok

    return "You are {} on Azure AD and {} on GitHub\n {}".format(email, login, resp.json())


if __name__ == "__main__":
    app.run()
