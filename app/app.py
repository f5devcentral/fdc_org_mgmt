import os
import app_config
from flask import Flask, redirect, url_for, render_template, session
from flask_dance.contrib.azure import make_azure_blueprint, azure
from flask_dance.contrib.github import make_github_blueprint, github
from cryptography.hazmat.backends import default_backend
from oauthlib.oauth2 import TokenExpiredError
import jwt
import requests
import time
import json

# Define the Flask app
app = Flask(__name__)
# Load configuration
app.config.from_object(app_config)


def add_org_member(access_token, username):
    """
    Add a user to the GitHub Organization

    Parameters
    ----------
    access_token: string
        GitHub installation access token
    username: string
        GitHub username

    Returns
    -------
    string
        invite state
    """
    headers = {
        "Authorization": "Token {}".format(access_token),
        "Accept": "application/vnd.github.v3+json"
    }
    resp = requests.put("https://api.github.com/orgs/{}/memberships/{}".format(app_config.GITHUB_ORG, username),
                        headers=headers)
    assert resp.ok
    return resp.json()["state"]


def create_jwt(app_id):
    """
    Create a Github App Authentication JSON Web Token

    Parameters
    ----------
    app_id: string
        Application ID assigned to the GitHub Application

    Returns
    -------
    string
        JSON Web Token (JWT) to use while requesting an GitHub Access Token
    """
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


def enroll_user(email, gh_username):
    # Create JWT Token for installation authentication
    gh_jwt = create_jwt(app_config.GITHUB_APP_ID)

    # Get Access Token
    gh_access_token = get_access_token(
        app_config.GITHUB_INSTALLATION_ID, gh_jwt, '{"members": "write"}')

    # State for Jinja2 to change UI
    # valid states are:
    #   - existing
    #   - enrolling
    #   - error
    enrollment_state = None

    # Add user to organization
    if(is_org_member(gh_access_token, gh_username)):
        # User is already a member of the GitHub Org
        enrollment_state = "existing"
    else:
        # User is not a member of the GitHub Org
        resp = add_org_member(gh_access_token, gh_username)

        if(resp == "pending"):
            # Invitation status is pending, so invitation should be available to the user
            # add user mapping
            mapping = store_user_mapping(email, gh_username)
            enrollment_state = "enrolling"
        else:
            # Unknown invitation status
            enrollment_state = "error"

    return enrollment_state


def get_access_token(installation_id, gh_jwt, permissions):
    """
    Obtain a GitHub Access Token for Installation Authentication

    Parameters
    ----------
    installation_id: string
        The installation ID for the application installed in your GitHub organization
    gh_jwt: string
        The GitHub JSON Web Token (JWT)
    permissions: string
        The permissions/scope for the access token

    Returns
    -------
    string
        Access token for Application API calls (not as the authenticated user)
    """
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


def get_azure_user(az):
    """
    Get user data from Azure Active Directory

    Parameters
    ----------
    az: object
        flask-dance Azure object

    Returns
    -------
    string
        Azure AD email address
    """

    azure_resp = azure.get("/v1.0/me")
    assert azure_resp.ok
    return azure_resp.json()["userPrincipalName"]


def get_github_user(gh):
    """
    Get user data from GitHub

    Parameters
    ----------
    gh: object
        flask-dance GitHub object

    Returns
    -------
    string 
        GitHub username
    """
    github_resp = github.get("/user")
    assert github_resp.ok
    return github_resp.json()["login"]


def is_enrolled(email):
    """
    Checks if the user exists in the mapping file

    Parameters
    ----------
    email: string
        Azure AD email address

    Returns
    -------
    boolean
        If the user exists in the mapping file
    """
    with open(app_config.USER_MAPPING_FILE_PATH, "r") as openfile:
        json_object = json.load(openfile)

    user_exists = False
    for user in json_object["users"]:
        if email.lower() in user:
            user_exists = True

    return user_exists


def is_org_member(access_token, username):
    """
    Add a user to the GitHub Organization

    Parameters
    ----------
    access_token: string
        GitHub installation access token
    username: string
        GitHub username

    Returns
    -------
    boolean
        returns if the user is a member of the organization
    """

    headers = {
        "Authorization": "Token {}".format(access_token),
        "Accept": "application/vnd.github.v3+json"
    }
    resp = requests.get("https://api.github.com/orgs/{}/members/{}".format(app_config.GITHUB_ORG, username),
                        headers=headers)

    if resp.status_code != 204:
        return False
    else:
        return True


def store_user_mapping(email, username):
    """
    Store the mapping between the user's Azure AD email address and GitHub username

    Parameters
    ----------
    email: string
        user's email address stored in Azure AD
    username: string
        user's GitHub username

    Returns
    -------
    object
        Python object representing the user
    """

    # Open json file
    with open(app_config.USER_MAPPING_FILE_PATH, "r") as openfile:
        json_object = json.load(openfile)

    user_obj = {email.lower(): {"username": username.lower()}}
    # add the user mapping if not already present
    user_exists = is_enrolled(email)

    if not user_exists:
        json_object["users"].append(user_obj)

    # write the json object back to file
    with open(app_config.USER_MAPPING_FILE_PATH, "w") as openfile:
        openfile.write(json.dumps(json_object, indent=4))

    return user_obj


# Build Azure OAuth blueprint
azure_bp = make_azure_blueprint(
    client_id=app_config.AZURE_CLIENT_ID,
    client_secret=app_config.AZURE_CLIENT_SECRET,
    scope=app_config.AZURE_SCOPE
)
app.register_blueprint(azure_bp, url_prefix="/login")

# Build GitHub OAuth blueprint
# related to flask-dance issue #235
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

    return render_template("index.j2", user_exists=is_enrolled(get_azure_user(azure)), org=app_config.GITHUB_ORG)


if __name__ == "__main__":
    app.run()


@app.route("/enroll")
def enroll():
    # Ensure the user is authenticated against Azure and GitHub
    if not azure.authorized:
        return redirect(url_for("azure.login"))
    if not github.authorized:
        return redirect(url_for("github.login"))

    # Get email address
    try:
        email = get_azure_user(azure)
    except TokenExpiredError:
        return redirect(url_for("azure.login"))

    # check if user is already enrolled
    if is_enrolled(email):
        return render_template("error.j2", msg="User is already enrolled in the {} GitHub Organization".format(app_config.GITHUB_ORG))

    # Get GitHub username
    try:
        gh_username = get_github_user(github)
    except TokenExpiredError:
        return redirect(url_for("github.login"))

    enrollment_state = enroll_user(email, gh_username)

    # return payload
    return render_template("enroll.j2", enrollment_state=enrollment_state, email=email, org=app_config.GITHUB_ORG, login=gh_username)


@app.route("/logout")
def logout():
    session.clear()
    return render_template("logout.j2")
