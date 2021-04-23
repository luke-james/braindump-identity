import os

import boto3
import botocore.exceptions

import hmac
import hashlib
import base64

import json


def get_auth_methods():
    return [
    "username",
    "password",
    "email",
    "name"
]

def get_user_pool_id():
    return os.environ.get('USER_POOL_ID')


def get_client_id():
    return os.environ.get('CLIENT_ID')


def get_client_secret():
    return os.environ.get('CLIENT_SECRET')


def get_secret_hash(username):

    message = username + get_client_id()

    digest = hmac.new(
                    str(get_client_secret()).encode('utf-8'), 
                    msg=str(message).encode('utf-8'),
                    digestmod=hashlib.sha256
                ).digest()
    
    d2 = base64.b64encode(digest).decode()
    
    return d2


def given_all_auth_methods(event):

    for field in get_auth_methods():
        if not event.get(field):
            return True, field

    return False, ''

def get_cognito_client():
    return boto3.client('cognito-idp', region_name='us-east-1')


def lambda_handler(event, context):

    ## This function will create a new user account within Cognito.

    '''
    Check to make sure we have ALL the info needed to sign the user up 
    for a new account.
    '''

    is_missing_field, missing_field = given_all_auth_methods(event)
    
    if is_missing_field:
        return {
            "statusCode": 400,
            "body": json.dumps({
                "error": True,
                "message": f"{ missing_field } is missing"
            })
        }

    cognito_client = get_cognito_client()

    print(cognito_client.describe_user_pool(
        UserPoolId=get_user_pool_id()
    ))

    try:

        cognito_response = cognito_client.sign_up(
            ClientId=get_client_id(),
            SecretHash=get_secret_hash(event['username']),
            Username=event['username'],
            Password="abcdef",
            UserAttributes=[
                {
                    'Name': "name",
                    'Value': event['name']
                },
                {
                    'Name': "email",
                    'Value': event['email']
                }
            ],
            ValidationData=[
                {
                    'Name': "email",
                    'Value': event['email']
                },
                {
                    'Name': "custom:username",
                    'Value': event['username']
                }
            ]
        )

    except cognito_client.exceptions.UsernameExistsException as e:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": True,
                "message": "This username already exists"
            })
        }

    except cognito_client.exceptions.InvalidPasswordException as e:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": True,
                "message": "Password MUST have Caps, Lowercase & > 8 digits"
            })
        }

    except cognito_client.exceptions.UserLambdaValidationException as e:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": True,
                "message": "Email already exists"
            })
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": True,
                "message": str(e),
            })
    }          


    print(cognito_client.admin_get_user(
        UserPoolId=get_user_pool_id(),
        Username=event['username']
    ))

    return {
        "statusCode": 200,
        "body": json.dumps({
            "error": False,
            "message": "Please confirm your signup, check Email for validation code",
        })
    }