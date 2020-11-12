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


def get_azure_users(azure, users):
    """
    Get list of user data from Azure Active Directory

    Parameters
    ----------
    az: object
        flask-dance Azure object
    users: list
        email addresses

    Returns
    -------
    list
        Azure user principal names (should match email)
    """
    employees = []
    # break the user list down, only allowed to have 15 filters
    n = 15
    users_list = [users[i * n:(i + 1) * n]
                  for i in range((len(users) + n - 1) // n)]

    # loop through users and add to query
    for u1 in users_list:
        query_url = "/v1.0/users?$select=userPrincipalName&$filter="
        count = 0
        for u2 in u1:
            if count == 0:
                query_url += "startswith(userPrincipalName,'{}')".format(
                    u2['email'])
            else:
                query_url += " or startswith(userPrincipalName,'{}')".format(
                    u2['email'])
            count += 1

        azure_resp = azure.get(query_url)
        assert azure_resp.ok
        # process the response into a list of employees
        payload = azure_resp.json()

        for user in payload["value"]:
            employees.append(user['userPrincipalName'].lower())

    return employees
