import boto3
import botocore.exceptions

import hmac
import hashlib
import base64

import json

USER_POOL_ID = ''
CLIENT_ID = ''
CLIENT_SECRET = ''

AUTH_METHODS = [
    "username",
    "password",
    "email",
    "name"
]

def get_secret_hash(username):

    message = username + CLIENT_ID
    
    digest = hmac.new(
                    str(CLIENT_SECRET).encode('utf-8'), 
                    msg=str(message).encode('utf-8'),
                    digestmod=hashlib.sha256
                ).digest()
    
    d2 = base64.b64encode(digest).decode()
    
    return d2

def given_all_auth_methods(event):

    for field in AUTH_METHODS:
        if not event.get(field):
            return True, field

    return False, ''

def get_cognito_client():
    return boto3.client('cognito-idp')


def lambda_handler(event, context):

    ## This function will create a new user account within Cognito.

    '''
    Check to make sure we have ALL the info needed to sign the user up 
    for a new account.
    '''

    is_missing_field, missing_field = given_all_auth_methods(event)
    
    if is_missing_field:
        return {
            "error": True,
            "statusCode": 400,
            "body": json.dumps({
                "message": f"{ missing_field } is missing"
            }),
            "data": None
        }

    cognito_client = get_cognito_client()

    try:

        cognito_response = cognito_client.sign_up(
            ClientId=CLIENT_SECRET,
            SecretHash=get_secret_hash(event['username']),
            Username=event['username'],
            Password=event['password'],
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
            "error": True,
            "statusCode": 500,
            "body": json.dumps({
                "message": "This username already exists"
            }),
            "data": None
        }

    except cognito_client.exceptions.InvalidPasswordException as e:
        return {
            "error": True,
            "statusCode": 500,
            "body": json.dumps({
                "message": "Password should have Caps, \
                            Special Chars, Numbers"
            }),
            "data": None
        }

    except cognito_client.exceptions.UserLambdaValidationException as e:
        return {
            "error": True,
            "statusCode": 500,
            "body": json.dumps({
                "message": "Email already exists"
            }),
            "data": None
        }

    except Exception as e:
        return {
            "error": True,
            "statusCode": 500,
            "body": json.dumps({
                "message": str(e),
            }),
            "data": None
    }          

    return {
        "error": False,
        "statusCode": 200,
        "body": json.dumps({
        "message": "Please confirm your signup, \
                        check Email for validation code",
        }),
        "data": None
    }