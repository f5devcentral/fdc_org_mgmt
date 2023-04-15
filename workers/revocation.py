import asyncio
import boto3
import configparser
from botocore.exceptions import ClientError
from msgraph_user import Graph

async def main():
    print('Python Graph App-Only Tutorial\m')

    # Load settings
    config = configparser.ConfigParser()
    config.read(['config.cfg', 'config.dev.cfg'])
    azure_settings = config['azure']

    graph: Graph = Graph(azure_settings)

    users = await get_gh_users()
    users_to_delete = []
    if users is not None:
        for user in users:
            result = await get_user(graph, user['email'])
            if result is not None:
                print(result)
            else:
                print('No user found')
                users_to_delete.append(user['username'])
    print(users_to_delete)
    
async def get_user(graph: Graph, email: str):
    user_page = await graph.get_user(email)
    if user_page is not None and user_page.value is not None and len(user_page.value) > 0:
        user = user_page.value[0]
        print(f'  User: {user.surname} {user.given_name}')
        print(f'  ID: {user.id}')
        print(f'  Email: {user.mail}')
        print(f'  User Principal Name: {user.user_principal_name}')
    return user_page

async def get_gh_users():
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('fdc-org-mgmt-prod')

        response = table.scan(Limit=10)
    except ClientError as e:
        print(e)
    return response['Items']

# Run main
asyncio.run(main())