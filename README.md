# fdc_org_mgmt
Application to help onboard and offboard F5 employees to the F5 DevCentral Organization.

Users will be authenticated against Azure and GitHub for enrollment. 

# Development

## Starting a Flask App

| Variable  | Description |
|-----------|-------------|
| FLASK_APP | The python file containing the flask application|
| FLASK_ENV | Tells flask if the app is in development or production for extra debugging |
| AZURE_CLIENT_ID | Azure Client ID for OAuth authentication |
| AZURE_CLIENT_SECRET | Azure Client Secret for OAuth authentication |
| GITHUB_CLIENT_ID | GitHub Client ID for OAuth authentication |
| GITHUB_CLIENT_SECRET | GitHub Client ID for OAuth authentication |
| GITHUB_APP_ID | Application ID - generated when you create a GitHub application |
| GITHUB_APP_KEY | Private Key associated with the GitHub app. Used to generate the JWT |
| GITHUB_ORG | GitHub Organization Name |
| GITHUB_INSTALLATION_ID | Installation ID for the app in your organization. Obtain via api: `curl -i -H "Authorization: Bearer YOUR_JWT" -H "Accept: application/vnd.github.machine-man-preview+json" https://api.github.com/app/installations/` |
| SECRET_KEY | Secret Key for Flask Dance OAuth authentication against Azure and GitHub |

```bash
cd app
export FLASK_APP=app.py
export FLASK_ENV=development
export AZURE_CLIENT_ID=enter_your_client_id
export AZURE_CLIENT_SECRET=enter_your_client_secret
export GITHUB_CLIENT_ID=enter_your_client_id
export GITHUB_CLIENT_SECRET=enter_your_client_secret
export GITHUB_APP_ID=enter_your_app_id
export GITHUB_APP_KEY=enter_your_app_private_key
export GITHUB_ORG=enter_your_organization_name
export GITHUB_INSTALLATION_ID=enter your app installation id
export SECRET_KEY=enter_your_app_secret_key
flask run --cert=adhoc
```
