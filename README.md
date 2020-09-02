# F5 DevCentral GitHub User Management
This repository contains a Lambda application to help onboard and offboard F5 employees to the F5 DevCentral GitHub Organization.

While this application is used by F5, the code is abstracted enough to work for any GitHub organization that also uses Azure AD for corporate authentication.


## User Experience
For detailed documentation on the enrollment process, view the [enrollment documentation](/docs/enrollment.md).
### Authentication
The application authenticates the user against both Azure AD and GitHub.  The user will be redirected to https://login.microsftoneline.com to authenticate against the configured Azure AD tenant and approve the requested OAuth scope.  Once Azure AD authentication is successful, the user will be redirected to https://github.com to authenticate and approve the requested OAuth scope.  

### Enrollment
Once the user is successfully authenticated against Azure AD and GitHub, they will see an enroll button on the web page.  Clicking the button will generate a GitHub organization invite that will be sent to the email address associated with the GitHub username.  This email will contain a link allowing the user to accept the GitHub organization invite.  

## Development

### Requirements
This application requires that the developer install the [serverless](https://www.serverless.com/framework/docs/providers/aws/guide/installation/) libraries as well as a [local instance of DynamoDB](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html). 

 * The requirements.txt file contains the required python packages
 * the package.json contains the required packages for serverless

### Environment Variables
The application requires the following environment variables to deploy locally or in AWS:
| Variable  | Description |
|-----------|-------------|
| APP_DEBUG | A 0 or 1 value to enable advanced debugging |
| ROLE_ARN | ARN of the AWS Role to allow lambda access to required resources | 
| GITHUB_APP_KEY | PEM format of the GitHub Application private key for API calls, strip the header and footer so it only contains the base64 encoded payload |
| SECRET_NAME | AWS Secrets Manager Secret Name |
| SECRET_ARN | ARN of the AWS Secret Manager Secret |


### Serverless Deploy Locally
To deploy the application locally:

```bash
export APP_DEBUG=1
export GITHUB_APP_KEY=enter_your_private_key_in_PEM_format
export ROLE_ARN=your_lambda_role_arn
export SECRET_NAME=your_secret_manager_secret_name
export SECRET_ARN=ARN_of_your_secret_manager_secret
sls wsgi serve --ssl --stage local
```

in another terminal, start the local instance of DynamoDB:
```bash
sls dynamodb start --migrate --stage local
```

### Serverless Deploy Development in AWS
To deploy the application in AWS:

```bash
export APP_DEBUG=0
export GITHUB_APP_KEY=enter_your_private_key_in_PEM_format
export ROLE_ARN=your_lambda_role_arn
export SECRET_NAME=your_secret_manager_secret_name
export SECRET_ARN=ARN_of_your_secret_manager_secret
sls deploy --stage dev

### Serverless Deploy in AWS
To deploy the application in AWS:

```bash
export APP_DEBUG=0
export GITHUB_APP_KEY=enter_your_private_key_in_PEM_format
export ROLE_ARN=your_lambda_role_arn
export SECRET_NAME=your_secret_manager_secret_name
export SECRET_ARN=ARN_of_your_secret_manager_secret
sls deploy --stage prod
```

### Serverless Remove from AWS
To remove the application from AWS:

```bash
export APP_DEBUG=0
export GITHUB_APP_KEY=enter_your_private_key_in_PEM_format
export ROLE_ARN=your_lambda_role_arn
export SECRET_NAME=your_secret_manager_secret_name
export SECRET_ARN=ARN_of_your_secret_manager_secret
sls remove
```

## Support
For support, please open a GitHub issue.  Note, the code in this repository is community supported and is not supported by F5 Networks.  For a complete list of supported projects please reference [SUPPORT.md](support.md).

## Community Code of Conduct
Please refer to the [F5 DevCentral Community Code of Conduct](code_of_conduct.md).


## License
[Apache License 2.0](LICENSE)

## Copyright
Copyright 2014-2020 F5 Networks Inc.


### F5 Networks Contributor License Agreement

Before you start contributing to any project sponsored by F5 Networks, Inc. (F5) on GitHub, you will need to sign a Contributor License Agreement (CLA).

If you are signing as an individual, we recommend that you talk to your employer (if applicable) before signing the CLA since some employment agreements may have restrictions on your contributions to other projects.
Otherwise by submitting a CLA you represent that you are legally entitled to grant the licenses recited therein.

If your employer has rights to intellectual property that you create, such as your contributions, you represent that you have received permission to make contributions on behalf of that employer, that your employer has waived such rights for your contributions, or that your employer has executed a separate CLA with F5.

If you are signing on behalf of a company, you represent that you are legally entitled to grant the license recited therein.
You represent further that each employee of the entity that submits contributions is authorized to submit such contributions on behalf of the entity pursuant to the CLA.