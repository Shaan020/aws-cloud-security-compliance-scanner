import boto3

iam = boto3.client('iam')

def check_user_mfa(username):
    response = iam.list_mfa_devices(UserName=username)
    
    if len(response['MFADevices']) == 0:
        return f"{username}: FAIL - no MFA device enabled"
    else:
        return f"{username}: PASS - MFA is enabled"

# Get all IAM users in your account
users_response = iam.list_users()

for user in users_response['Users']:
    username = user['UserName']
    print(check_user_mfa(username))