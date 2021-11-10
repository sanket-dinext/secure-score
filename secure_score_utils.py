import pandas as pd
import requests
import hashlib
import hmac
import base64
import logging
import datetime
import configparser
import json
import os
from itertools import islice

configParser = configparser.ConfigParser()
configFilePath = os.path.join('secure-score','credentials.config')
configParser.read(configFilePath)

client_id = configParser.get('API_Auth', 'client_id')
scope = configParser.get('API_Auth', 'scope')
grant_type = configParser.get('API_Auth', 'grant_type')
client_secret = configParser.get('API_Auth','client_secret')
tenant_id = configParser.get('API_Auth','tenant_id')
url_token_1 = configParser.get('API_Auth','url_token_1')
url_token_2 = configParser.get('API_Auth','url_token_2')


def get_header():
    body = {'client_id': client_id, 'scope': scope, 'grant_type': grant_type, 'client_secret': client_secret}
    access_token = requests.post(url_token_1, data=body).json()['access_token']
    headers = {"Authorization": "Bearer " + access_token}
    return headers

def get_secure_scores():
    headers = get_header()
    url_secure_score = 'https://graph.microsoft.com/v1.0/security/secureScores'
    secure_score = requests.get(url_secure_score, headers=headers).json()['value']
    return pd.DataFrame(secure_score)

def get_secure_profiles():
    headers = get_header()
    url_secure_score_profiles = 'https://graph.microsoft.com/v1.0/security/securescorecontrolprofiles'
    secure_profiles = requests.get(url_secure_score_profiles, headers=headers).json()['value']
    return pd.DataFrame(secure_profiles)

def generate_score_profile_dataframe():
    secure_score = get_secure_scores()
    secure_profiles = get_secure_profiles()

    secure_score_explode = secure_score.explode('controlScores')
    expanded_secure_score = secure_score_explode.join(pd.json_normalize(secure_score_explode['controlScores']))
    score_profile_joined = expanded_secure_score.merge(secure_profiles, left_on='controlName', right_on='id',
                                                       how='left')
    required_columns = ['id_x', 'azureTenantId_x', 'activeUserCount', 'createdDateTime',
       'currentScore',  'licensedUserCount', 'maxScore_x',
       'vendorInformation_x', 'averageComparativeScores', 'controlCategory_x', 'controlName', 'description', 'score',
       'implementationStatus' , 'on', 'controlState',
       'lastSynced', 'scoreInPercentage', 'State']

    score_profile_joined = score_profile_joined[required_columns]
    return score_profile_joined


profile_score = generate_score_profile_dataframe()


def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    """Returns authorization header which will be used when sending data into Azure Log Analytics"""

    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, 'UTF-8')
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode(
        'utf-8')
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization


def post_data(customer_id, shared_key, body, log_type):
    """Sends payload to Azure Log Analytics Workspace

    Keyword arguments:
    customer_id -- Workspace ID obtained from Advanced Settings
    shared_key -- Authorization header, created using build_signature
    body -- payload to send to Azure Log Analytics
    log_type -- Azure Log Analytics table name
    """

    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)

    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri, data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        logging.info('Accepted payload:' + body)
    else:
        logging.error("Unable to Write: " + format(response.status_code))