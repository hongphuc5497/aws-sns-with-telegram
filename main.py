import json
import logging
import boto3
import urllib3
from botocore.exceptions import ClientError

# Read from env
import os
SECRET_REGION = os.environ['SECRET_REGION']  # AWS Secret Manager Region
SECRET_NAME = os.environ['SECRET_NAME']  # AWS Secret Manager Name

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_secret():
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=SECRET_REGION
    )

    try:
        get_secret_value_resp = client.get_secret_value(
            SecretId=SECRET_NAME
        )
    except ClientError as e:
        raise e

    secret = get_secret_value_resp['SecretString']
    return secret


def get_secret_value(secret_name):
    secret = get_secret()
    secretValue = json.loads(secret)

    return secretValue[secret_name]


def process_message(input):
    try:
        raw_json = json.loads(input)
        output = json.dumps(raw_json, indent=4)
    except:
        output = input
    return output


def lambda_handler(event, context):
    logger.info("event=")
    logger.info(json.dumps(event))

    TELEGRAM_USER_ID = get_secret_value("TELEGRAM_USER_ID")
    TELEGRAM_TOKEN = get_secret_value("TELEGRAM_TOKEN")
    TELEGRAM_URL = "https://api.telegram.org/bot{}/sendMessage".format(
        TELEGRAM_TOKEN)

    try:
        message = process_message(event['Records'][0]['Sns']['Message'])

        req_hearders = {
            "Content-Type": "application/json"
        }
        encoded_body = json.dumps({
            "text": message,
            "chat_id": int(TELEGRAM_USER_ID)
        })

        logger.info("encoded_body=")
        logger.info(encoded_body)

        http = urllib3.PoolManager()
        request = http.request('POST', TELEGRAM_URL,
                               headers=req_hearders, body=encoded_body)
        logger.info("request=")
        logger.info(request.data)
        logger.info("Message posted to Telegram")
    except Exception as e:
        raise e
