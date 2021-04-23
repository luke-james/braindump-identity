import os

import boto3
import botocore.exceptions

import hmac
import hashlib
import base64

import json

'''

FUNCTION --> 

    CREATE USER ACCOUNT

DESCRIPTION --> 

    This function will communicate with the AWS cognito service and create a new account, using the password
    policy set as part of our Cognito User Pool (created manually in AWS Console).

'''


def get_auth_methods():
    return [
    "username",
    "password",
    "email",
    "name"
]


def get_account_data_from_event_body(raw_event):
    return json.loads(raw_event['body'])


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


def given_all_auth_methods(data):

    for field in get_auth_methods():
        if not data.get(field):
            return True, field

    return False, ''


def get_cognito_client():
    return boto3.client('cognito-idp', region_name='us-east-1')


def lambda_handler(event, context):

    '''

    This is our handler function which will contain the majority of the logic for interfacing with 
    Cognito to create a new account.

    '''

    try:

        new_user_data = get_account_data_from_event_body(event)

    except TypeError as e:

        return {
            "statusCode": 400,
            "body": json.dumps({
                "error": True,
                "message": "Payload body is missing"
            })
        }

    '''
    Check to make sure we have ALL the info needed to sign the user up 
    for a new account (e.g. username, password, email, name etc.).
    '''

    is_missing_field, missing_field = given_all_auth_methods(new_user_data)
    
    if is_missing_field:
        return {
            "statusCode": 400,
            "body": json.dumps({
                "error": True,
                "message": f"{ missing_field } is missing"
            })
        }

    cognito_client = get_cognito_client()

    try:

        cognito_response = cognito_client.sign_up(
            ClientId=get_client_id(),
            SecretHash=get_secret_hash(new_user_data['username']),
            Username=new_user_data['username'],
            Password=new_user_data['password'],
            UserAttributes=[
                {
                    'Name': "name",
                    'Value': new_user_data['name']
                },
                {
                    'Name': "email",
                    'Value': new_user_data['email']
                }
            ],
            ValidationData=[
                {
                    'Name': "email",
                    'Value': new_user_data['email']
                },
                {
                    'Name': "custom:username",
                    'Value': new_user_data['username']
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

    return {
        "statusCode": 200,
        "body": json.dumps({
            "error": False,
            "message": "Please confirm your signup, check Email for validation code",
        })
    }