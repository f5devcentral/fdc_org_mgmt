import os
import app_config
from flask import Flask, redirect, url_for
from flask_dance.contrib.azure import make_azure_blueprint, azure
from flask_dance.contrib.github import make_github_blueprint, github

app = Flask(__name__)
app.config.from_object(app_config)

azure_bp = make_azure_blueprint(
    client_id=app_config.AZURE_CLIENT_ID,
    client_secret=app_config.AZURE_CLIENT_SECRET,
    scope=app_config.AZURE_SCOPE
)
app.register_blueprint(azure_bp, url_prefix="/login")

github_bp = make_github_blueprint(
    client_id=app_config.GITHUB_CLIENT_ID,
    client_secret=app_config.GITHUB_CLIENT_SECRET
)
app.register_blueprint(github_bp, url_prefix="/login")


@app.route("/")
def index():
    if not azure.authorized:
        return redirect(url_for("azure.login"))
    if not github.authorized:
        return redirect(url_for("github.login"))
    azure_resp = azure.get("/v1.0/me")
    assert azure_resp.ok
    github_resp = github.get("/user")
    assert github_resp.ok
    email = azure_resp.json()["userPrincipalName"]
    login = github_resp.json()["login"]
    test_resp = github.get("/orgs/f5devcentral/outside_collaborators")
    # assert test_resp.ok
    return "You are {} on Azure AD and {} on GitHub\n {}".format(email, login, test_resp.json())


if __name__ == "__main__":
    app.run()
