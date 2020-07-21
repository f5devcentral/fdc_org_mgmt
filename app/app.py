import os
import app_config
from flask import Flask, redirect, url_for
from flask_dance.contrib.azure import make_azure_blueprint, azure

app = Flask(__name__)
app.config.from_object(app_config)

azure_bp = make_azure_blueprint(
    client_id=app_config.CLIENT_ID,
    client_secret=app_config.CLIENT_SECRET,
    scope=app_config.SCOPE
)
app.register_blueprint(azure_bp, url_prefix="/login")


@app.route("/")
def index():
    if not azure.authorized:
        return redirect(url_for("azure.login"))
    resp = azure.get("/v1.0/me")
    assert resp.ok
    return "You are {mail} on Azure AD".format(mail=resp.json()["userPrincipalName"])


if __name__ == "__main__":
    app.run()
