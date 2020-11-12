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
    if app_config.APP_DEBUG:
        print("github.create_jwt: start")

    app_id, app_secret, installation_id = get_gh_app_data()

    if not app_id or not app_secret or not installation_id:
        if app_config.APP_DEBUG:
            print(
                "github.remove_org_member: app_id, app_secret or installation_id not returned")
        raise Exception(
            "github.create_jwt: get_gh_app_data did not return all required variables")

    time_since_epoch_in_seconds = int(time.time())

    payload = {
        # issued at time
        'iat': time_since_epoch_in_seconds,
        # JWT expiration time
        'exp': time_since_epoch_in_seconds + (10 * 60),
        # GitHub App ID
        'iss': app_id
    }

    gh_app_key = "-----BEGIN RSA PRIVATE KEY-----\r\n"
    gh_app_key += app_secret
    gh_app_key += "\r\n-----END RSA PRIVATE KEY-----"

    if not gh_app_key:
        raise Exception("github.create_jwt: Github Private Key not loaded")

    if app_config.APP_DEBUG:
        print("github.remove_org_member: end")

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
    app_id, app_secret, installation_id = get_gh_app_data()

    if not app_id or not app_secret or not installation_id:
        if app_config.APP_DEBUG:
            print(
                "github.remove_org_member: app_id, app_secret or installation_id not returned")
        raise Exception(
            "github.create_jwt: get_gh_app_data did not return all required variables")

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


def get_gh_app_data():
    """
    Get the correct GitHub App ID, App Secret and Installation ID based upon the serverless stage 

    Parameters
    ----------
    stage: string
        serverless stage (prod, dev, local)

    Returns
    -------
    list(string, string, string)
        GitHub Application ID, GitHub Application Secret, Github Installation ID
    """
    append = None
    if "prod" in app_config.STAGE:
        append = ""
    elif "dev" in app_config.STAGE:
        append = "_DEV"
    elif "local" in app_config.STAGE:
        append = "_LOCAL"
    else:
        raise Exception(
            "github.get_gh_app_data: Invalid stage {}".format(stage))

    return app_config.SECRETS['GITHUB_APP_ID'+append], app_config.SECRETS['GITHUB_APP_SECRET'+append], app_config.SECRETS['GITHUB_INSTALLATION_ID'+append]


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


def get_github_users():
    """
    Get org users data from GitHub

    Parameters
    ----------
    gh: object
        flask-dance GitHub object

    Returns
    -------
    list[string] 
        GitHub username
    """
    # Create JWT Token for installation authentication
    access_token = get_access_token('{"members": "read"}')

    headers = {
        "Authorization": "Token {}".format(access_token),
        "Accept": "application/vnd.github.v3+json"
    }

    payload = []
    # GitHub limits the request to 100 users
    # TODO: find way to determine how many pages are left
    for i in range(1, 10):
        resp = requests.get("https://api.github.com/orgs/{}/members?per_page=100&page={}".format(app_config.SECRETS['GITHUB_ORG'], i),
                            headers=headers)
        assert resp.ok
        for user in resp.json():
            payload.append(user['login'].lower())

    return payload


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
