import app_config
from flask import Flask

# Define the Flask app
app = Flask(__name__)
# Load configuration
app.config.from_object(app_config)


def get_azure_user(azure):
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
    return payload["userPrincipalName"], payload["givenName"], payload["surname"]
