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
import boto3
import base64
from botocore.exceptions import ClientError

# Define the Flask app
app = Flask(__name__)
# Load configuration
app.config.from_object(app_config)

# setup DynamoDB connection
if "localhost" in app_config.FQDN:
    dynamodb = boto3.resource(
        'dynamodb', endpoint_url="http://localhost:8000")
else:
    dynamodb = boto3.resource(
        'dynamodb', region_name=app_config.REGION)


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
    resp = requests.put("https://api.github.com/orgs/{}/memberships/{}".format(secrets['GITHUB_ORG'], username),
                        headers=headers)
    # print(resp)
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
        'iss': secrets['GITHUB_APP_ID_LOCAL'] if "localhost" in app_config.FQDN else secrets['GITHUB_APP_ID']
    }

    # gh_app_key = secrets['GITHUB_APP_SECRET_LOCAL'] if "localhost" in app_config.FQDN else secrets['GITHUB_APP_SECRET']
    gh_app_key = os.getenv("GITHUB_APP_KEY")

    if not gh_app_key:
        raise Exception("create_jwt: Github Private Key not loaded")

    return jwt.encode(payload, gh_app_key, algorithm='RS256')


def enroll_user(email, givenName, surname, gh_username):
    # Create JWT Token for installation authentication
    gh_app_id = secrets['GITHUB_APP_ID_LOCAL'] if "localhost" in app_config.FQDN else secrets['GITHUB_APP_ID']
    gh_jwt = create_jwt(gh_app_id)

    # Get Access Token
    gh_app_install_id = secrets['GITHUB_INSTALLATION_ID_LOCAL'] if "localhost" in app_config.FQDN else secrets['GITHUB_INSTALLATION_ID']
    gh_access_token = get_access_token(
        gh_app_install_id, gh_jwt, '{"members": "write"}')

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

        # check if user mapping exists
        if not is_enrolled(email):
            store_user_mapping(email, givenName, surname, gh_username)

    else:
        # User is not a member of the GitHub Org
        resp = add_org_member(gh_access_token, gh_username)

        if(resp == "pending"):
            # Invitation status is pending, so invitation should be available to the user
            # add user mapping
            mapping = store_user_mapping(
                email, givenName, surname, gh_username)
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

    if "token" not in resp.json():
        raise Exception("get_access_token: no token in the response")
    else:
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
    payload = azure_resp.json()
    # print(payload)
    return payload["userPrincipalName"], payload["givenName"], payload["surname"]


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
    print(github_resp.json())
    return github_resp.json()["login"]


def get_secret():
    """
    Get a secrets from the AWS Secret Manager
    Code is based on AWS examples

    Returns
    -------
    string
        Secret
    """
    secret_name = app_config.SECRET_NAME
    region_name = app_config.REGION

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            return json.loads(get_secret_value_response['SecretString'])
        else:
            return json.loads(base64.b64decode(
                get_secret_value_response['SecretBinary']))


def get_user_mappings():
    """
    Return all user mappings in the DynamoDB database

    Returns
    -------
    List 
        list of all user mappings
    """
    table = dynamodb.Table(app_config.USERS_TABLE)
    response = table.scan()
    if "Items" in response:
        return response["Items"]
    else:
        return None


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
    table = dynamodb.Table(app_config.USERS_TABLE)
    response = table.get_item(
        Key={
            'email': email
        }
    )

    if "Item" in response:
        return True
    else:
        return False


def is_org_member(access_token, username):
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

    headers = {
        "Authorization": "Token {}".format(access_token),
        "Accept": "application/vnd.github.v3+json"
    }
    resp = requests.get("https://api.github.com/orgs/{}/members/{}".format(secrets['GITHUB_ORG'], username),
                        headers=headers)

    if resp.status_code != 204:
        return False
    else:
        return True


def is_org_owner():
    """
    Check if user is a owner of the GitHub Organization

    Parameters
    ----------
    access_token: string
        GitHub installation access token
    username: string
        GitHub username

    Returns
    -------
    boolean
        returns true if the user is an owner of the GitHub organization
    """
    github_resp = github.get("/user/memberships/orgs?state=active")
    assert github_resp.ok

    # loop through orgs and find the desired org
    for org in github_resp.json():
        if org['organization']['login'] == secrets['GITHUB_ORG'] and org['role'] == 'admin':
            return True

    return False


def store_user_mapping(email, givenName, surname, username):
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
    table = dynamodb.Table(app_config.USERS_TABLE)
    response = table.put_item(
        Item={
            'email': email,
            'givenName': givenName,
            'surname': surname,
            'username': username,
            'status': "member"
        }
    )
    return response


# get secrets
secrets = get_secret()
if not secrets:
    raise Exception('Unable to load secrets')
# print(secrets)

# Set Key for Flask Dance
app.secret_key = secrets['SECRET_KEY']

# Build Azure OAuth blueprint
azure_bp = make_azure_blueprint(
    client_id=secrets['AZURE_CLIENT_ID'],
    client_secret=secrets['AZURE_CLIENT_SECRET'],
    scope=app_config.AZURE_SCOPE
)
app.register_blueprint(azure_bp, url_prefix="/login")

# Build GitHub OAuth blueprint
# related to flask-dance issue #235
# check if we're doing local development
if "localhost" in app_config.FQDN:
    gh_client_id = secrets['GITHUB_CLIENT_ID_LOCAL']
    gh_client_secret = secrets['GITHUB_CLIENT_SECRET_LOCAL']
else:
    gh_client_id = secrets['GITHUB_CLIENT_ID']
    gh_client_secret = secrets['GITHUB_CLIENT_SECRET']

github_bp = make_github_blueprint(
    client_id=gh_client_id,
    client_secret=gh_client_secret
)
app.register_blueprint(github_bp, url_prefix="/login")


@app.route("/")
def index():
    # Ensure the user is authenticated against Azure and GitHub
    if not azure.authorized:
        return redirect(url_for("azure.login"))
    if not github.authorized:
        return redirect(url_for("github.login"))

    try:
        email, givenName, surname = get_azure_user(azure)
        response = render_template("index.j2", user_exists=is_enrolled(
            email), org=secrets['GITHUB_ORG'])
        return response
    except TokenExpiredError:
        return redirect("/logout")


@app.route("/enroll")
def enroll():
    # Ensure the user is authenticated against Azure and GitHub
    if not azure.authorized:
        return redirect(url_for("azure.login"))
    if not github.authorized:
        return redirect(url_for("github.login"))

    # Get email address
    try:
        email, givenName, surname = get_azure_user(azure)
    except TokenExpiredError:
        return redirect(url_for("azure.login"))

    # check if user is already enrolled
    if is_enrolled(email):
        return render_template("error.j2", msg="User is already enrolled in the {} GitHub Organization".format(secrets['GITHUB_ORG']))

    # Get GitHub username
    try:
        gh_username = get_github_user(github)
    except TokenExpiredError:
        return redirect(url_for("github.login"))

    enrollment_state = enroll_user(email, givenName, surname, gh_username)

    # return payload
    return render_template("enroll.j2", enrollment_state=enrollment_state, email=email, org=secrets['GITHUB_ORG'], login=gh_username)


@app.route("/users")
def users():
    # Ensure the user is authenticated against Azure and GitHub
    if not azure.authorized:
        return redirect(url_for("azure.login"))
    if not github.authorized:
        return redirect(url_for("github.login"))

    # get scan from DynamoDB
    users = get_user_mappings()

    return render_template("users.j2", users=users, owner=is_org_owner())


@app.route("/logout")
def logout():
    session.clear()
    return render_template("logout.j2")


if __name__ == "__main__":
    app.run()
