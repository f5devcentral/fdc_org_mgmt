# Working with the DynamoDB Local Instance
To work with the local DynamoDB instance we'll need to cover some basics.

## Start DynamoDB Local Instance
```bash
sls dynamodb start --migrate --stage local
```
## Dynamo DB via AWS CLI
To leverage the AWS CLI you'll need to append your dynamodb commands with:
```bash
--endpoint-url http://localhost:8000
```

For example, we'll get a list of tables:
```bash
aws dynamodb list-tables --endpoint-url http://localhost:8000
```

## Load DB with Test Data
```bash
aws dynamodb put-item \
    --table-name fdc-org-mgmt-local \
    --item '{
        "email": {"S": "j.doe@f5.com"},
        "surname": {"S": "Doe"},
        "github_role": {"S": "member"},
        "givenName": {"S": "John"},
        "username": {"S": "johndoef5"}
      }' \
      --endpoint-url http://localhost:8000
```