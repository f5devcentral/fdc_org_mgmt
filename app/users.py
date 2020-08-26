import boto3
import app_config
from flask import Flask
from github import add_org_member, convert_org_member, is_org_member, remove_org_member

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


def add_user(email, givenName, surname, username):
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
            'github_role': "member"
        }
    )
    return response


def convert_user(email, username):
    """
    Convert a GitHub Oranization member to an external contributor

    Parameters
    ----------
    user: string
        GitHub username

    Returns
    -------
    boolean
        Boolean value reflecting if the user was converted or not
    """

    if app_config.APP_DEBUG:
        print("user.convert_user start")

    # convert user
    if not convert_org_member(username):
        if app_config.APP_DEBUG:
            print("user.convert_user github.convert_org_member failed")
        return False

    # remove DynamoDB user record
    table = dynamodb.Table(app_config.USERS_TABLE)
    response = table.delete_item(
        Key={
            'email': email
        }
    )

    if 'ResponseMetadata' not in response or 'HTTPStatusCode' not in response['ResponseMetadata'] or response['ResponseMetadata']['HTTPStatusCode'] != 200:
        if app_config.APP_DEBUG:
            print("user.convert_user response incorrect {}".format(response))
            print('user.convert_user end')
        return False
    else:
        if app_config.APP_DEBUG:
            print('user.convert_user end')
        return True


def enroll_user(email, givenName, surname, gh_username):
    if app_config.APP_DEBUG:
        print("users.enroll_user: start")

    # State for Jinja2 to change UI
    # valid states are:
    #   - active
    #   - pending
    #   - error
    enrollment_state = None

    # Add user to organization
    if(is_org_member(gh_username)):
        if app_config.APP_DEBUG:
            print("users.enroll_user: user is already a GitHub Org member")

        # User is already a member of the GitHub Org
        enrollment_state = "existing"

        # check if user mapping exists
        if not is_enrolled(email):
            add_user(email, givenName, surname, gh_username)

    else:
        # User is not a member of the GitHub Org
        resp = add_org_member(gh_username)
        if app_config.APP_DEBUG:
            print("users.enroll_user: user is not a GitHub Org member")
            print("users.enroll_user: add_org_member response: {}".format(resp))

        if(resp == "pending" or resp == "active"):
            # Invitation status is pending, so invitation should be available to the user
            # add user mapping
            mapping = add_user(
                email, givenName, surname, gh_username)
            enrollment_state = resp
        else:
            # Unknown invitation status
            enrollment_state = "error"

    if app_config.APP_DEBUG:
        print("users.enroll_user: enrollment_state: {}".format(enrollment_state))
        print("users.enroll_user: stop")
    return enrollment_state


def get_user(email):
    """
    Return all user mappings in the DynamoDB database

    Returns
    -------
    List 
        list of all user mappings
    """
    table = dynamodb.Table(app_config.USERS_TABLE)
    response = table.get_item(
        Key={
            'email': email
        }
    )
    if "Item" in response:
        return response["Item"]
    else:
        return None


def get_users():
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
    if app_config.APP_DEBUG:
        print("users.is_enrolled: start")

    user = get_user(email)
    if user is not None:
        if app_config.APP_DEBUG:
            print("users.is_enrolled: user is already mapped to a GitHub username")
            print("users.is_enrolled: end")
        return True
    else:
        if app_config.APP_DEBUG:
            print("users.is_enrolled: user is not not mapped to a GitHub username")
            print("users.is_enrolled: end")
        return False


def remove_user(email, username):
    """
    remove a GitHub Oranization member

    Parameters
    ----------
    user: string
        GitHub username

    Returns
    -------
    boolean
        Boolean value reflecting if the user was removed or not
    """

    # remove user
    if not remove_org_member(username):
        return False

    # remove DynamoDB user record
    table = dynamodb.Table(app_config.USERS_TABLE)
    response = table.delete_item(
        Key={
            'email': email
        }
    )

    if 'ResponseMetadata' not in response or 'HTTPStatusCode' not in response['ResponseMetadata'] or response['ResponseMetadata']['HTTPStatusCode'] != 200:
        return False
    else:
        return True
