import json

def lambda_handler(event, context):

    ## This function will create a new user account within Cognito.

    return {
        "statusCode": 200,
        "body": json.dumps({
        "message": "Please confirm your signup, \
                        check Email for validation code",
        }),
        "data": None
    }