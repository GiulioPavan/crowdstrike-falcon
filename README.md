# crowdstrike-falcon
Repo containing the python scripts developed by CFC (former GSOC) for gathering details from Crowdstrike Falcon.

These scripts require the creation of a cred.py file that contains the access token and secret, plus these other details:

accessTokenURL = "https://api.crowdstrike.com/oauth2/token"
clientID = ""
clientSecret = ""
aidURL = "https://api.crowdstrike.com/devices/queries/devices/v1"
hostURL = "https://api.crowdstrike.com/devices/entities/devices/v1"
hostQueryURL = "https://api.crowdstrike.com/devices/queries/devices/v1"
policyURL = "https://api.crowdstrike.com/policy/entities/sensor-update/v1"

