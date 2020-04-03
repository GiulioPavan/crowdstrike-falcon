import json
import requests
import ast
import datetime

# from oauthlib.oauth2 import BackendApplicationClient
# from requests_oauthlib import OAuth2Session
from cred import accessTokenURL, clientID, clientSecret, aidURL, hostURL, deleteURL

delete_log = open("delete_log.txt", "w+")

# to install the libraries """"pip install requests requests_oauthlib, oauth2, requests""""

payload = 'grant_type=client_credentials&client_id={0}&client_secret={1}'.format(clientID, clientSecret)
limit = 50

# this function is created to request an OAUTH2 token which will be used for 1600 seconds (the token expires after 30 mins). This function returns the token as position 1 of this obtain_token list and the expiry_time as expiration time in epoch
def obtain_token(client_id, client_secret, url):
    payload = 'grant_type=client_credentials&client_id={0}&client_secret={1}'.format(client_id, client_secret)
    headers = {
  	'Content-Type': 'application/x-www-form-urlencoded'
	}
    response = requests.request("POST", url, headers=headers, data = payload)
    expiry_time = datetime.datetime.now().timestamp() + 1500
    return [ast.literal_eval(response.text)["access_token"],expiry_time]


## prepares the header for all the requests that will be done afterwards. It uses the result of the obtain_token function called in "access_response"
access_response = obtain_token(clientID, clientSecret, accessTokenURL)
access_token = access_response[0]
expiry_time = access_response[1]

header = {
    'content-type': "application/json",
    'Authorization' : 'Bearer {}'.format(access_token)
    }

for i in open('host_output_small.txt'):
    res = ast.literal_eval(i.replace("\n", ""))
    if len(res) == 0:
        print('no AID')
    elif len(res) > 1:
        getDates = requests.get(hostURL + "?" + "ids="  + "&ids=".join(res), headers=header)
        data = getDates.json()
        new_list = [datetime.datetime.strptime(object['first_seen'], "%Y-%m-%dT%H:%M:%SZ").timestamp() for object in data['resources']]
        del res[new_list.index(max(new_list))]
        for line in res:
            payload = { "action_parameters": [], "ids": [line]}
            removeAIDs = requests.post(deleteURL, headers=header, data=json.dumps(payload))
            removeAIDs = json.loads(removeAIDs.text)
            removeAIDs['ids'] = payload
            delete_log.write('{0}\n'.format(str(removeAIDs)))
    else:
        print("single AID")
