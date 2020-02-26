import json
import requests
import ast
import datetime

# from oauthlib.oauth2 import BackendApplicationClient
# from requests_oauthlib import OAuth2Session
from cred import accessTokenURL, clientID, clientSecret, aidURL, hostURL, hostQueryURL

host_list = open("hosts_list.txt","r+")
host_output = open("host_output.txt", "w+")

## this function prepares the OATH2 session token request that will be used in the next request
def obtain_token(client_id, client_secret, url):
    payload = 'grant_type=client_credentials&client_id={0}&client_secret={1}'.format(client_id, client_secret)
    headers = {
  	'Content-Type': 'application/x-www-form-urlencoded'
	}
    response = requests.request("POST", url, headers=headers, data = payload)
    expiry_time = datetime.datetime.now().timestamp() + 20
    return [ast.literal_eval(response.text)["access_token"],expiry_time]

access_response = obtain_token(clientID, clientSecret, accessTokenURL)
access_token = access_response[0]
expiry_time = access_response[1]

# it formats the header for the request using the previously obtained access token
header = {
    'content-type': "application/json",
    'Authorization' : 'Bearer {}'.format(access_token)
    }

## Iterates through the hostname list for outputting the AgentIDs (AIDs) - in "host_output.txt", that can be used in another script
for i in host_list:
    i = i.replace('\n', '')
    getHostDetails = requests.get("{0}?filter=_all:~'{1}'".format(hostQueryURL,i), headers=header)
    data = getHostDetails.json()
    #it gets the AID value stored inside "resources"
    output = json.dumps(data['resources'])
    #print(json.dumps(data['resources']))
    formatted_output = "{0} \n".format(output)
    host_output.write(formatted_output)

host_output.close()
