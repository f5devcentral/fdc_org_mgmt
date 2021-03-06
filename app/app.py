import os
import app_config
from flask import Flask, request, redirect, url_for, render_template, session
from flask_dance.contrib.azure import make_azure_blueprint, azure
from flask_dance.contrib.github import make_github_blueprint, github
from cryptography.hazmat.backends import default_backend
from oauthlib.oauth2 import TokenExpiredError
from botocore.exceptions import ClientError
from azure import get_azure_user, get_azure_users
from users import add_user, convert_user, enroll_user, get_user, get_users, is_enrolled, remove_user
from github import get_github_user, get_github_users, is_org_owner
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
print("STAGE: {}".format(app_config.STAGE))
append = None
if "prod" in app_config.STAGE:
    append = ""
elif "dev" in app_config.STAGE:
    append = "_DEV"
elif "local" in app_config.STAGE:
    append = "_LOCAL"
else:
    raise Exception("Invalid stage: {}".format(app_config.STAGE))

gh_client_id = app_config.SECRETS['GITHUB_CLIENT_ID' + append]
gh_client_secret = app_config.SECRETS['GITHUB_CLIENT_SECRET' + append]
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
        # get user data
        email, givenName, surname = get_azure_user(azure)

        # determine if the user is enrolled
        user_exists = is_enrolled(email)
    except TokenExpiredError:
        return redirect(url_for("azure.login"))

    # determine if user is a GitHub org owner
    try:
        owner = is_org_owner(github)
    except TokenExpiredError:
        return redirect(url_for("github.login"))

    response = render_template("index.j2", user_exists=user_exists,
                               owner=owner, org=app_config.SECRETS['GITHUB_ORG'])
    return response


@ app.route("/enroll")
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


@ app.route("/users", methods=['GET', 'POST'])
def users():
    # Ensure the user is authenticated against Azure and GitHub
    if not azure.authorized:
        return redirect(url_for("azure.login"))
    if not github.authorized:
        return redirect(url_for("github.login"))

    # set default action messasge
    action_message = None
    error_message = None

    # determine if user is a GitHub org owner
    try:
        owner = is_org_owner(github)
    except TokenExpiredError:
        return redirect(url_for("github.login"))

    # process the POST request and ensure post is by org owner
    if request.method == 'POST' and owner:
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

    return render_template("users.j2", title="GitHub User Mappings", users=users, owner=owner, action_message=action_message, error_message=error_message)


@ app.route("/users/audit/employee", methods=['GET', 'POST'])
def users_audit_employee():
    # Ensure the user is authenticated against Azure and GitHub
    if not azure.authorized:
        return redirect(url_for("azure.login"))
    if not github.authorized:
        return redirect(url_for("github.login"))

    # set default action messasge
    action_message = None
    error_message = None

    # you need to be an owner to run this task
    # determine if user is a GitHub org owner
    try:
        owner = is_org_owner(github)
    except TokenExpiredError:
        return redirect(url_for("github.login"))

    if not owner:
        error_message = "Your do not have permissions to run this task"
        return render_template("users.j2", title="GitHub User Not Employeed", users=[], owner=owner, action_message=action_message, error_message=error_message)

    # process the POST request and ensure post is by org owner
    if request.method == 'POST' and owner:
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
    # Get email address
    try:
        employees = get_azure_users(azure, users)
    except TokenExpiredError:
        return redirect(url_for("azure.login"))

    not_employee = []
    for user in users:
        if not user['email'].lower() in employees:
            not_employee.append(user)

    return render_template("users.j2", title="GitHub User Not Employeed", users=not_employee, owner=owner, action_message=action_message, error_message=error_message)


@ app.route("/users/audit/github", methods=['GET', 'POST'])
def users_audit_github():
    # Ensure the user is authenticated against Azure and GitHub
    if not azure.authorized:
        return redirect(url_for("azure.login"))
    if not github.authorized:
        return redirect(url_for("github.login"))

    # set default action messasge
    action_message = None
    error_message = None

    # you need to be an owner to run this task
    # determine if user is a GitHub org owner
    try:
        owner = is_org_owner(github)
    except TokenExpiredError:
        return redirect(url_for("github.login"))

    if not owner:
        error_message = "Your do not have permissions to run this task"
        return render_template("gh_users.j2", title="GitHub User Not Employeed", users=[], owner=owner, action_message=action_message, error_message=error_message)

    # process the POST request to add a user
    if request.method == 'POST' and owner:
        data = request.form

        # ensure we have the required post data
        if not data.get('username') or not data.get('email'):
            error_message = "No username or email address provided"
        else:
            email = data.get('email')
            username = data.get('username')

            if app_config.APP_DEBUG:
                print("app.users: adding user: {}".format(username))

            # get Azure AD information for the requested user
            try:
                ad_email, givenName, surname = get_azure_user(azure, email)
            except TokenExpiredError:
                return redirect(url_for("github.login"))

            # ensure a user was returned
            if ad_email is None:
                error_message = "Email address not found"
            # ensure the user is not already enrolled
            elif is_enrolled(ad_email):
                error_message = "User is already enrolled"
            else:
                enrollment_state = enroll_user(
                    ad_email, givenName, surname, username)

                action_message = "User {} has been enrolled as {} {}".format(
                    username, givenName, surname)

    # get scan from DynamoDB
    users = get_users()

    # get github org members
    gh_users = get_github_users()
    for user in users:
        if user['username'].lower() in gh_users:
            gh_users.remove(user['username'].lower())

    return render_template("gh_users.j2", title="GitHub User Not Enrolled", users=gh_users, owner=owner, action_message=action_message, error_message=error_message)


@ app.route("/users/audit/github/mfa")
def users_audit_github_mfa():
    # Ensure the user is authenticated against Azure and GitHub
    if not azure.authorized:
        return redirect(url_for("azure.login"))
    if not github.authorized:
        return redirect(url_for("github.login"))

    # set default action messasge
    action_message = None
    error_message = None

    # you need to be an owner to run this task
    # determine if user is a GitHub org owner
    try:
        owner = is_org_owner(github)
    except TokenExpiredError:
        return redirect(url_for("github.login"))

    if not owner:
        error_message = "Your do not have permissions to run this task"
        return render_template("gh_users.j2", title="GitHub User Not Employeed", users=[], owner=owner, action_message=action_message, error_message=error_message)

    # get scan from DynamoDB
    users = get_users()
    non_mfa_users = []

    # get github org members
    gh_users = get_github_users(mfa_disabled=True)
    for user in users:
        if user['username'].lower() in gh_users:
            non_mfa_users.append(user)

    return render_template("users.j2", title="GitHub User Without MFA", users=non_mfa_users, owner=owner, action_message=action_message, error_message=error_message)


@ app.route("/logout")
def logout():
    session.clear()
    return render_template("logout.j2")


if __name__ == "__main__":
    app.run()
