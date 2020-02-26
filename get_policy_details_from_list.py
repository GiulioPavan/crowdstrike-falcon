import json
import requests
import ast
import datetime

# from oauthlib.oauth2 import BackendApplicationClient
# from requests_oauthlib import OAuth2Session
from cred import accessTokenURL, clientID, clientSecret, aidURL, hostURL, policyURL

host_list = open("host_output.txt","r+")


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
    expiry_time = datetime.datetime.now().timestamp() + 20
    return [ast.literal_eval(response.text)["access_token"],expiry_time]


## prepares the header for all the requests that will be done afterwards. It uses the result of the obtain_token function called in "access_response"
access_response = obtain_token(clientID, clientSecret, accessTokenURL)
access_token = access_response[0]
expiry_time = access_response[1]

header = {
    'content-type': "application/json",
    'Authorization' : 'Bearer {}'.format(access_token)
    }

## creates the URL for getting the agentIDs with the limit of 5000 (max limit per request)
offset = 0
loop_back = True

## the while loop is set for stopping the script when all the hosts details have been ingested, since there requests are limited to 5000 hosts and several requests will have to be performed

while(loop_back):
    ## it requests the agent IDs (AIDs) by using the original header generated at the beginning (the token lasts for 30 mins)
    getAID = requests.get(aidURL + "?limit=5000&offset={}".format(offset), headers=header)

    ## results gets the entire list of 5000 AIDs which will be broken down in lists of 50 (in listoflists)
    results = json.loads(getAID.text)['resources']
    policy_output = open("policy_application.txt","a+")


    ## it iterates through the list of lists (the value of the variable "limit") of agentIDs received in the previous request and generate new requests for the host details
    for i in host_list:
        i = i.replace('\n', '')
        ## it checks if the expiry time of the token is reached: if so it requests a new token
        if expiry_time < datetime.datetime.now().timestamp():
            access_response = obtain_token(clientID, clientSecret, accessTokenURL)
            access_token = access_response[0]
            expiry_time = access_response[1]
            header = {
                'content-type': "application/json",
                'Authorization' : 'Bearer {}'.format(access_token)
                }
        ## it gets the host details using the AID as part of the request. A JSON object is returned
        getHosts = requests.get('{0}?ids={1}'.format(hostURL,i), headers=header)
        data = getHosts.json()

        ## the for loop iterates through the JSON object and saves the values of different keys in variables, that are then formatted and printed as string in the output file "policy_application.txt"
        for p in data['resources']:
            try:
                output_hostname = json.dumps(p['hostname'])
                output_agentVersion = json.dumps(p['agent_version'])
                output_lastSeen = json.dumps(p['last_seen'])
                output_applied = json.dumps(p['device_policies']['sensor_update']['applied'])
                output_uninstall = json.dumps(p['device_policies']['sensor_update']['uninstall_protection'])
                output_policyId = json.dumps(p['device_policies']['sensor_update']['policy_id']).replace('"', '')
                output_AID = json.dumps(p['device_id'])
                getSensorPolicyName = requests.get('{0}?ids={1}'.format(policyURL,output_policyId), headers=header)
                sensorPolicyData = getSensorPolicyName.json()
                sensorPolicyName = json.dumps(sensorPolicyData['resources'][0]['name'])
                output = "{0}, {1}, {2}, {3}, {4}, {5}, {6}\n".format(output_hostname,output_agentVersion,output_lastSeen,sensorPolicyName,output_applied,output_uninstall, output_AID)
                policy_output.write(output)
            except KeyError:
                print('no device policy applied')
                output_hostname = json.dumps(p['hostname'])
                output_error = ("{} has no policy applied"'\n').format(output_hostname)
                policy_output.write(output_error)
                continue


    ## it checks if the value of "total" is the same as "offset": if it is, it sets the value of look_back as false, so the while loop can be completed
    if json.loads(getAID.text)['meta']['pagination']['offset'] == json.loads(getAID.text)['meta']['pagination']['total']:
        loop_back = False
        continue
    ## it adds 5000 to the value of the variable offset: this will bring the next chunk of 5000 hosts in the following request
    offset += 5000

policy_output.close()
