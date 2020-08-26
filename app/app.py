import os
import app_config
from flask import Flask, request, redirect, url_for, render_template, session
from flask_dance.contrib.azure import make_azure_blueprint, azure
from flask_dance.contrib.github import make_github_blueprint, github
from cryptography.hazmat.backends import default_backend
from oauthlib.oauth2 import TokenExpiredError
from botocore.exceptions import ClientError
from azure import get_azure_user
from users import add_user, convert_user, enroll_user, get_user, get_users, is_enrolled, remove_user
from github import get_github_user, is_org_owner
import boto3

# Define the Flask app
app = Flask(__name__)
# Load configuration
app.config.from_object(app_config)

# Set Key for Flask Dance
app.secret_key = app_config.SECRETS['SECRET_KEY']

# Build Azure OAuth blueprint
azure_bp = make_azure_blueprint(
    client_id=app_config.SECRETS['AZURE_CLIENT_ID'],
    client_secret=app_config.SECRETS['AZURE_CLIENT_SECRET'],
    tenant=app_config.SECRETS['AZURE_TENANT_ID'],
    scope=app_config.AZURE_SCOPE
)
app.register_blueprint(azure_bp, url_prefix="/login")

# Build GitHub OAuth blueprint
# related to flask-dance issue #235
# check if we're doing local development
if "localhost" in app_config.FQDN:
    gh_client_id = app_config.SECRETS['GITHUB_CLIENT_ID_LOCAL']
    gh_client_secret = app_config.SECRETS['GITHUB_CLIENT_SECRET_LOCAL']
else:
    gh_client_id = app_config.SECRETS['GITHUB_CLIENT_ID']
    gh_client_secret = app_config.SECRETS['GITHUB_CLIENT_SECRET']

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
            email), org=app_config.SECRETS['GITHUB_ORG'])
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

    if app_config.APP_DEBUG:
        print("app.enroll: start")

    # Get email address
    try:
        email, givenName, surname = get_azure_user(azure)
    except TokenExpiredError:
        return redirect(url_for("azure.login"))

    # check if user is already enrolled
    if is_enrolled(email):
        if app_config.APP_DEBUG:
            print("app.enroll: user is already enrolled")
        return render_template("error.j2", msg="User is already mapped to a user in the {} GitHub Organization".format(app_config.SECRETS['GITHUB_ORG']))

    # Get GitHub username
    try:
        gh_username = get_github_user(github)
    except TokenExpiredError:
        return redirect(url_for("github.login"))

    enrollment_state = enroll_user(email, givenName, surname, gh_username)
    if app_config.APP_DEBUG:
        print("app.enroll: enrollment_state: {}".format(enrollment_state))

    if app_config.APP_DEBUG:
        print("app.enroll: end")
    # return payload
    return render_template("enroll.j2", enrollment_state=enrollment_state, email=email, org=app_config.SECRETS['GITHUB_ORG'], login=gh_username)


@app.route("/users", methods=['GET', 'POST'])
def users():
    # Ensure the user is authenticated against Azure and GitHub
    if not azure.authorized:
        return redirect(url_for("azure.login"))
    if not github.authorized:
        return redirect(url_for("github.login"))

    # set default action messasge
    action_message = None
    error_message = None

    # process the POST request and ensure post is by org owner
    if request.method == 'POST' and is_org_owner(github):
        data = request.form

        # ensure we have the required post data
        if not data.get('action') or not data.get('email') or not data.get('user'):
            error_message = "No users or action was supplied"

        action = data.get('action')
        email = data.get('email')
        user = data.get('user')

        # determine the requested action
        if action == "Convert":
            if app_config.APP_DEBUG:
                print("app.users: action == Convert")
            result = convert_user(email, user)
            if result is not True:
                error_message = "Unable to convert user to external contributor"
            else:
                action_message = "User {} converted to external contributor".format(
                    user)

        elif action == "Remove":
            if app_config.APP_DEBUG:
                print("app.users: action == Remove")
            result = remove_user(email, user)
            if result is not True:
                error_message = "Unable to remove user from GitHub Organization"
            else:
                action_message = "User {} removed from GitHub Organization".format(
                    user)

        else:
            error_message = "Unsupported user action"

    # get scan from DynamoDB
    users = get_users()

    return render_template("users.j2", users=users, owner=is_org_owner(github), action_message=action_message, error_message=error_message)


@app.route("/logout")
def logout():
    session.clear()
    return render_template("logout.j2")


if __name__ == "__main__":
    app.run()
