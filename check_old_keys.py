import boto3
from datetime import datetime, timezone

iam = boto3.client('iam')

MAX_KEY_AGE_DAYS = 90

def check_access_key_age(username):
    response = iam.list_access_keys(UserName=username)
    
    if len(response['AccessKeyMetadata']) == 0:
        print(f"{username}: No access keys found")
        return
    
    for key in response['AccessKeyMetadata']:
        key_id = key['AccessKeyId']
        created_date = key['CreateDate']
        
        age_days = (datetime.now(timezone.utc) - created_date).days
        
        if age_days > MAX_KEY_AGE_DAYS:
            print(f"{username} - {key_id}: FAIL - key is {age_days} days old (limit: {MAX_KEY_AGE_DAYS})")
        else:
            print(f"{username} - {key_id}: PASS - key is {age_days} days old")

users_response = iam.list_users()

for user in users_response['Users']:
    check_access_key_age(user['UserName'])