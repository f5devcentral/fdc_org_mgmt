import app_config
import jwt
import time
import os
import requests
from flask import Flask

# Define the Flask app
app = Flask(__name__)
# Load configuration
app.config.from_object(app_config)


def add_org_member(username):
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
    # Get Access Token
    access_token = get_access_token('{"members": "write"}')

    headers = {
        "Authorization": "Token {}".format(access_token),
        "Accept": "application/vnd.github.v3+json"
    }
    resp = requests.put("https://api.github.com/orgs/{}/memberships/{}".format(app_config.SECRETS['GITHUB_ORG'], username),
                        headers=headers)
    assert resp.ok
    return resp.json()["state"]


def convert_org_member(username):
    """
    Removed a user from the GitHub Organization

    Parameters
    ----------
    access_token: string
        GitHub installation access token
    username: string
        GitHub username 

    Returns
    -------
    boolean
        returns true if the user was removed from the organization
    """
    if app_config.APP_DEBUG:
        print("github.convert_org_member start")

    # Create JWT Token for installation authentication
    access_token = get_access_token('{"members": "write"}')

    headers = {
        "Authorization": "Token {}".format(access_token),
        "Accept": "application/vnd.github.v3+json"
    }
    resp = requests.put("https://api.github.com/orgs/{}/outside_collaborators/{}".format(app_config.SECRETS['GITHUB_ORG'], username),
                        headers=headers)

    if resp.status_code != 204:
        if app_config.APP_DEBUG:
            print("response status code != 204: {}".format(resp))
            print("github.convert_org_member end")
        return False
    else:
        if app_config.APP_DEBUG:
            print("github.convert_org_member end")
        return True


def create_jwt():
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
    app_id = app_config.SECRETS['GITHUB_APP_ID_LOCAL'] if "localhost" in app_config.FQDN else app_config.SECRETS['GITHUB_APP_ID']

    time_since_epoch_in_seconds = int(time.time())

    payload = {
        # issued at time
        'iat': time_since_epoch_in_seconds,
        # JWT expiration time
        'exp': time_since_epoch_in_seconds + (10 * 60),
        # GitHub App ID
        'iss': app_config.SECRETS['GITHUB_APP_ID_LOCAL'] if "localhost" in app_config.FQDN else app_config.SECRETS['GITHUB_APP_ID']
    }

    gh_app_key = "-----BEGIN RSA PRIVATE KEY-----\r\n"
    gh_app_key += app_config.SECRETS['GITHUB_APP_SECRET_LOCAL'] if "localhost" in app_config.FQDN else app_config.SECRETS['GITHUB_APP_SECRET']
    gh_app_key += "\r\n-----END RSA PRIVATE KEY-----"

    if not gh_app_key:
        raise Exception("create_jwt: Github Private Key not loaded")

    return jwt.encode(payload, gh_app_key, algorithm='RS256')


def get_access_token(permissions):
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

    installation_id = app_config.SECRETS['GITHUB_INSTALLATION_ID_LOCAL'] if "localhost" in app_config.FQDN else app_config.SECRETS['GITHUB_INSTALLATION_ID']
    gh_jwt = create_jwt()

    headers = {
        "Authorization": "Bearer {}".format(gh_jwt.decode()),
        "Accept": "application/vnd.github.machine-man-preview+json"
    }
    resp = requests.post(
        "https://api.github.com/app/installations/{}/access_tokens".format(
            installation_id),
        headers=headers,
        data=permissions)

    if "token" not in resp.json():
        raise Exception("get_access_token: no token in the response")
    else:
        return (resp.json()["token"])


def get_github_user(github):
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


def is_org_member(username):
    """
    Check if user is a member of the GitHub Organization

    Parameters
    ----------
    access_token: string
        GitHub installation access token
    username: string
        GitHub username

    Returns
    -------
    boolean
        returns true if the user is a member of the organization
    """
    # Create JWT Token for installation authentication
    access_token = get_access_token('{"members": "read"}')

    headers = {
        "Authorization": "Token {}".format(access_token),
        "Accept": "application/vnd.github.v3+json"
    }
    resp = requests.get("https://api.github.com/orgs/{}/members/{}".format(app_config.SECRETS['GITHUB_ORG'], username),
                        headers=headers)

    if resp.status_code != 204:
        return False
    else:
        return True


def is_org_owner(github):
    """
    Check if user is a owner of the GitHub Organization

    Parameters
    ----------
    github: object
        github connection object from flask_dance

    Returns
    -------
    boolean
        returns true if the user is an owner of the GitHub organization
    """
    github_resp = github.get("/user/memberships/orgs?state=active")
    assert github_resp.ok

    # loop through orgs and find the desired org
    for org in github_resp.json():
        if org['organization']['login'] == app_config.SECRETS['GITHUB_ORG'] and org['role'] == 'admin':
            return True

    return False


def remove_org_member(username):
    """
    Removed a user from the GitHub Organization

    Parameters
    ----------
    access_token: string
        GitHub installation access token
    username: string
        GitHub username 

    Returns
    -------
    boolean
        returns true if the user was removed from the organization
    """
    if app_config.APP_DEBUG:
        print("github.remove_org_member: start")
    # Create JWT Token for installation authentication
    access_token = get_access_token('{"members": "write"}')

    headers = {
        "Authorization": "Token {}".format(access_token),
        "Accept": "application/vnd.github.v3+json"
    }
    resp = requests.delete("https://api.github.com/orgs/{}/members/{}".format(app_config.SECRETS['GITHUB_ORG'], username),
                           headers=headers)

    if resp.status_code == 204:
        if app_config.APP_DEBUG:
            print("github.remove_org_member: end")
        return True
    elif resp.status_code == 404:
        # user not in org, return true to remove from database
        if app_config.APP_DEBUG:
            print("github.remove_org_member: end")
        return True
    else:
        if app_config.APP_DEBUG:
            print(
                "github.remove_org_member: response code != 204 or 404: {}".format(resp))
            print("github.remove_org_member: end")
        return False
