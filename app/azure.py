import app_config
from flask import Flask

# Define the Flask app
app = Flask(__name__)
# Load configuration
app.config.from_object(app_config)


def get_azure_user(azure, user="me"):
    """
    Get user data from Azure Active Directory

    Parameters
    ----------
    az: object
        flask-dance Azure object
    user: string
        Azure AD email address

    Returns
    -------
    string
        Azure AD email address
    """
    query_url = "/v1.0/me" if user == "me" else "/v1.0/users/{}".format(user)
    azure_resp = azure.get(query_url)
    # assert azure_resp.ok
    payload = azure_resp.json()
    if "userPrincipalName" in payload:
        return payload["userPrincipalName"], payload["givenName"], payload["surname"]
    else:
        return None


def is_employee(azure, email):
    """
    Check if the user exists in Azure AD

    Parameters
    ----------
    az: object
        flask-dance Azure object
    user: string
        Azure AD email address

    Returns
    -------
    boolean
        If the user exists in Azure AD
    """
    if app_config.APP_DEBUG:
        print("users.is_employee: start")

    if get_azure_user(azure, email):
        if app_config.APP_DEBUG:
            print("users.is_employee: {} is an employee".format(email))
            print("users.is_employee: end")
        return True
    else:
        if app_config.APP_DEBUG:
            print("users.is_employee: {} is not an employee".format(email))
            print("users.is_employee: end")
        return False
