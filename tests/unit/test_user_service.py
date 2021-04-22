import json

import pytest

import boto3, botocore
from moto import mock_cognitoidp

import uuid

from mock import patch

import create_user_account
from create_user_account import app


@pytest.fixture()
def apigw_event_full():
    """ Generates API GW Event"""

    return {
        "username": "test_user1",
        "email": "test@test.com",
        "password": "password123",
        "name": "Jon Smith",
        "body": '{ "test": "body"}',
        "resource": "/{proxy+}",
        "requestContext": {
            "resourceId": "123456",
            "apiId": "1234567890",
            "resourcePath": "/{proxy+}",
            "httpMethod": "POST",
            "requestId": "c6af9ac6-7b61-11e6-9a41-93e8deadbeef",
            "accountId": "123456789012",
            "identity": {
                "apiKey": "",
                "userArn": "",
                "cognitoAuthenticationType": "",
                "caller": "",
                "userAgent": "Custom User Agent String",
                "user": "",
                "cognitoIdentityPoolId": "",
                "cognitoIdentityId": "",
                "cognitoAuthenticationProvider": "",
                "sourceIp": "127.0.0.1",
                "accountId": "",
            },
            "stage": "prod",
        },
        "queryStringParameters": {"foo": "bar"},
        "headers": {
            "Via": "1.1 08f323deadbeefa7af34d5feb414ce27.cloudfront.net (CloudFront)",
            "Accept-Language": "en-US,en;q=0.8",
            "CloudFront-Is-Desktop-Viewer": "true",
            "CloudFront-Is-SmartTV-Viewer": "false",
            "CloudFront-Is-Mobile-Viewer": "false",
            "X-Forwarded-For": "127.0.0.1, 127.0.0.2",
            "CloudFront-Viewer-Country": "US",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "X-Forwarded-Port": "443",
            "Host": "1234567890.execute-api.us-east-1.amazonaws.com",
            "X-Forwarded-Proto": "https",
            "X-Amz-Cf-Id": "aaaaaaaaaae3VYQb9jd-nvCd-de396Uhbp027Y2JvkCPNLmGJHqlaA==",
            "CloudFront-Is-Tablet-Viewer": "false",
            "Cache-Control": "max-age=0",
            "User-Agent": "Custom User Agent String",
            "CloudFront-Forwarded-Proto": "https",
            "Accept-Encoding": "gzip, deflate, sdch",
        },
        "pathParameters": {"proxy": "/examplepath"},
        "httpMethod": "POST",
        "stageVariables": {"baz": "qux"},
        "path": "/examplepath",
    }


@patch.object(app, 'get_client_id', return_value="fake_client_id")
@patch.object(app, 'get_user_pool_id', return_value="fake_user_pool_id")
@patch.object(app, 'get_client_secret', return_value="fake_client_secret")
@mock_cognitoidp
def test_create_account_success(mock_get_client_secret, mock_user_pool_id, mock_client_id, apigw_event_full, mocker):

    client = boto3.client('cognito-idp')
    
    user_pool = client.create_user_pool(PoolName=str(uuid.uuid4()))

    user_pool_client = client.create_user_pool_client(
        UserPoolId=user_pool["UserPool"]["Id"], 
        ClientName="fake_user_pool_client",
        GenerateSecret=True)

    mock_user_pool_id.return_value = user_pool["UserPool"]["Id"]
    mock_client_id.return_value = user_pool_client["UserPoolClient"]["ClientId"]
    mock_get_client_secret.return_value = user_pool_client["UserPoolClient"]["ClientSecret"]

    ret = app.lambda_handler(apigw_event_full, "")
    data = json.loads(ret["body"])

    #assert ret["statusCode"] == 200
    assert "message" in ret["body"]
    assert data["message"] == "Please confirm your signup, \
                        check Email for validation code"

@pytest.mark.skip(reason="no way of currently testing this")
def test_create_account_username_exists(apigw_event_full, mocker):

    ret = app.lambda_handler(apigw_event_full, "")
    data = json.loads(ret["body"])

    assert ret["statusCode"] == 200
    assert ret["statusCode"] == 200
    assert "message" in ret["body"]
    assert data["message"] == "This username already exists"

@pytest.mark.skip(reason="no way of currently testing this")
def test_create_account_invalid_password(apigw_event_full, mocker):

    ret = app.lambda_handler(apigw_event_full, "")
    data = json.loads(ret["body"])

    assert ret["statusCode"] == 200
    assert ret["statusCode"] == 200
    assert "message" in ret["body"]
    assert data["message"] == "Password should only have Caps,\
                       Special Chars & Numbers"

@pytest.mark.skip(reason="no way of currently testing this")
def test_create_account_email_exists(apigw_event_full, mocker):

    ret = app.lambda_handler(apigw_event_full, "")
    data = json.loads(ret["body"])

    assert ret["statusCode"] == 200
    assert ret["statusCode"] == 200
    assert "message" in ret["body"]
    assert data["message"] == "Email already exists"