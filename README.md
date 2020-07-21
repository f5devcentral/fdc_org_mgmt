# fdc_org_mgmt
Application to help onboard and offboard F5 employees to the F5 DevCentral Organization.

Users will be authenticated against Azure and GitHub for enrollment. 

# Development

## Starting a Flask App
```bash
cd app
export FLASK_APP=app.py
export FLASK_ENV=development
export AZURE_CLIENT_ID=enter_your_client_id
export AZURE_CLIENT_SECRET=enter_your_client_secret
export GITHUB_CLIENT_ID=enter_your_client_id
export GITHUB_CLIENT_SECRET=enter_your_client_secret
export SECRET_KEY=enter_your_app_secret_key
flask run --cert=adhoc
```
